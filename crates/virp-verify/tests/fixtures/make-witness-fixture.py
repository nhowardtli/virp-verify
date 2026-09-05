#!/usr/bin/env python3
"""Rebuild `witness-bundle/`, the fixture the witness CLI tests run against.

WHY THIS FIXTURE IS SYNTHETIC, when the others are not
------------------------------------------------------
`axis-referenced-bundle` is real Axis footage on a real chain, and it is
better for being real. This one cannot be, and the reason is worth writing
down rather than discovering later.

`witness: VERIFIED` requires the witness leaf's `key_id` to equal the
signing key_id of the session's head — that is the whole binding, and it is
what the node-side submitter arranges by signing its submission with the same
chain key that signed the head. Producing such a leaf therefore requires the
chain's PRIVATE signing key. Every real chain in this project is signed by the
O-Node key that lives on the node, and Docket does not hold private keys and
must not start.

So the fixture is built under the PUBLISHED TEST KEY whose seed is public in
`crates/docket-bundle/tests/vectors/chain-signing-v1.json` — the same key the
witness repository's own golden vectors use as their submitter. Everything
else is real: real Ed25519 over the real domain-tagged canonical bytes, a real
`virp-witness` server, a real submission, a real receipt, a real RFC 9162
audit path served by that log. Nothing here is stubbed and nothing is
hand-written; the only synthetic thing is the identity of the chain.

WHAT IT NEEDS
-------------
  * `~/virp-witness` checked out and buildable (`virp-witness`, and
    `virp-witness-client`).
  * python3 with `cryptography` (this is a fixture generator, not shipped
    code — the exporter it drives is still standard library only).

USAGE
-----
    python3 make-witness-fixture.py [--out <dir>] [--port 8795]

It builds a chain database, starts a witness on localhost, submits three
heads to it, and runs the real `export_bundle.py --witness` against it. The
resulting bundle is what the tests read.
"""

import argparse
import hashlib
import json
import os
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
EXPORTER = os.path.join(REPO, "tools", "export", "export_bundle.py")
WITNESS_REPO = os.path.expanduser("~/virp-witness")

# The published test key. Its seed is public on purpose; it must never be a
# node's chain-signing key, and it is exactly right for a fixture.
SEED_HEX = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f"
PUBLIC_HEX = "29acbae141bccaf0b22e1a94d34d0bc7361e526d0bfe12c89794bc9322966dd7"
KEY_ID = "24f6ed6acbfe1009c030d7ca567c33ca"

ENTRY_SIG_TAG = b"VIRP-CHAIN-ENTRY-SIG-v1\x00"
HEAD_SIG_TAG = b"VIRP-CHAIN-HEAD-SIG-v1\x00"

# Three sessions, so the tree has three leaves and the audit path for the one
# under test is NOT empty. A single-leaf tree would make the `failed` case
# untestable: there would be no node to flip.
MAIN_SESSION = "docket-witness:fixture-1"
FILLER_SESSIONS = ["docket-witness:filler-a", "docket-witness:filler-b"]

SCHEMA = """
CREATE TABLE chain_entries (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  chain_entry_hash TEXT NOT NULL,
  previous_entry_hash TEXT NOT NULL,
  timestamp_ns INTEGER NOT NULL,
  monotonic_ns INTEGER NOT NULL,
  artifact_type TEXT NOT NULL,
  artifact_id TEXT NOT NULL,
  artifact_hash TEXT NOT NULL,
  artifact_hash_alg TEXT NOT NULL DEFAULT 'sha256',
  artifact_schema_version TEXT NOT NULL DEFAULT '1',
  signer_node_id INTEGER NOT NULL,
  signer_org_id TEXT NOT NULL DEFAULT 'local',
  chain_hmac TEXT NOT NULL,
  chain_sig TEXT,
  chain_sig_key_id TEXT,
  UNIQUE(session_id, sequence)
);
CREATE TABLE chain_milestones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  session_id TEXT NOT NULL,
  sequence INTEGER NOT NULL,
  entries_covered INTEGER NOT NULL,
  cumulative_hash TEXT NOT NULL,
  chain_hmac TEXT NOT NULL,
  created_at_ns INTEGER NOT NULL
);
CREATE TABLE chain_heads (
  session_id TEXT PRIMARY KEY,
  last_sequence INTEGER NOT NULL,
  last_entry_hash TEXT NOT NULL,
  head_hmac TEXT NOT NULL,
  updated_at_ns INTEGER NOT NULL,
  head_sig TEXT,
  head_sig_key_id TEXT
);
CREATE TABLE artifacts (
  artifact_id TEXT NOT NULL,
  artifact_hash TEXT NOT NULL,
  artifact_content TEXT NOT NULL,
  PRIMARY KEY (artifact_id, artifact_hash)
);
"""

ENTRY_COLS = [
    "session_id", "sequence", "chain_entry_hash", "previous_entry_hash", "timestamp_ns", "monotonic_ns",
    "artifact_type", "artifact_id", "artifact_hash", "artifact_hash_alg", "artifact_schema_version",
    "signer_node_id", "signer_org_id", "chain_hmac", "chain_sig", "chain_sig_key_id",
]


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def genesis_hash(session_id):
    return sha256_hex(b"VIRP_CHAIN_GENESIS:" + session_id.encode("utf-8"))


def fake_hmac(label):
    """A 64-hex placeholder for an HMAC this generator cannot compute (it
    holds no K_chain). The verifier grades it OPERATOR-ATTESTED, never
    VERIFIED, which is exactly what a real bundle's HMAC rows do here too."""
    return sha256_hex(b"fixture-hmac-not-real:" + label.encode("utf-8"))


def canonical_bytes(f):
    return (
        '{"artifact_hash":"%s","artifact_hash_alg":"%s","artifact_id":"%s",'
        '"artifact_schema_version":"%s","artifact_type":"%s","monotonic_ns":%d,'
        '"previous_entry_hash":"%s","sequence":%d,"session_id":"%s",'
        '"signer_node_id":%d,"signer_org_id":"%s","timestamp_ns":%d}'
        % (
            f["artifact_hash"], f["artifact_hash_alg"], f["artifact_id"], f["artifact_schema_version"],
            f["artifact_type"], f["monotonic_ns"], f["previous_entry_hash"], f["sequence"], f["session_id"],
            f["signer_node_id"], f["signer_org_id"], f["timestamp_ns"],
        )
    ).encode("utf-8")


def head_canonical(session_id, last_sequence, last_entry_hash):
    return (
        '{"last_entry_hash":"%s","last_sequence":%d,"session_id":"%s","v":"VIRP-CHAIN-HEAD-v1"}'
        % (last_entry_hash, last_sequence, session_id)
    ).encode("utf-8")


def build_session(conn, key, session_id, n, base_ns):
    prev = genesis_hash(session_id)
    for i in range(n):
        body = ('{"note":"%s entry %d"}' % (session_id, i)).encode("utf-8")
        f = {
            "artifact_hash": sha256_hex(body),
            "artifact_hash_alg": "sha256",
            "artifact_id": "obs:%s:%04d" % (session_id.split(":")[-1], i),
            "artifact_schema_version": "1",
            "artifact_type": "observation",
            "monotonic_ns": 1_000_000_000 + i * 1000,
            "previous_entry_hash": prev,
            "sequence": i,
            "session_id": session_id,
            "signer_node_id": 1,
            "signer_org_id": "local",
            "timestamp_ns": base_ns + i * 1_000_000_000,
        }
        canonical = canonical_bytes(f)
        h = sha256_hex(canonical)
        row = dict(f)
        row["chain_entry_hash"] = h
        row["chain_hmac"] = fake_hmac("%s-entry-%d" % (session_id, i))
        row["chain_sig"] = key.sign(ENTRY_SIG_TAG + canonical).hex()
        row["chain_sig_key_id"] = KEY_ID
        conn.execute(
            "INSERT INTO chain_entries (%s) VALUES (%s)" % (", ".join(ENTRY_COLS), ", ".join("?" * len(ENTRY_COLS))),
            [row[c] for c in ENTRY_COLS],
        )
        conn.execute(
            "INSERT INTO artifacts (artifact_id, artifact_hash, artifact_content) VALUES (?, ?, ?)",
            (f["artifact_id"], f["artifact_hash"], body.decode("utf-8")),
        )
        prev = h
    hc = head_canonical(session_id, n - 1, prev)
    conn.execute(
        "INSERT INTO chain_heads (session_id, last_sequence, last_entry_hash, head_hmac, updated_at_ns, "
        "head_sig, head_sig_key_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (session_id, n - 1, prev, fake_hmac("%s-head" % session_id), base_ns + n * 1_000_000_000,
         key.sign(HEAD_SIG_TAG + hc).hex(), KEY_ID),
    )
    return {"session_id": session_id, "last_sequence": n - 1, "last_entry_hash": prev}


def wait_for_port(port, seconds=20):
    deadline = time.time() + seconds
    while time.time() < deadline:
        with socket.socket() as s:
            s.settimeout(0.5)
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return True
        time.sleep(0.2)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=os.path.join(HERE, "witness-bundle"))
    ap.add_argument("--work", default=None, help="scratch directory (default: alongside --out)")
    ap.add_argument("--port", type=int, default=8795)
    args = ap.parse_args()

    work = args.work or (args.out + ".work")
    for d in (args.out, work):
        if os.path.exists(d):
            shutil.rmtree(d)
    os.makedirs(os.path.join(work, "heads"))

    key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(SEED_HEX))

    # The submitter key file the client reads: 64 bytes, seed || public,
    # mode 0400. Same key that signs the heads, which is the whole point —
    # it is what makes the leaf's key_id equal the head's signing key_id.
    submitter_key = os.path.join(work, "submitter.key")
    with open(submitter_key, "wb") as f:
        f.write(bytes.fromhex(SEED_HEX) + bytes.fromhex(PUBLIC_HEX))
    os.chmod(submitter_key, 0o400)

    # --- the chain -------------------------------------------------------
    db = os.path.join(work, "fixture.db")
    conn = sqlite3.connect(db)
    conn.executescript(SCHEMA)
    heads = [build_session(conn, key, MAIN_SESSION, 6, 1_787_000_000_000_000_000)]
    for i, sid in enumerate(FILLER_SESSIONS):
        heads.append(build_session(conn, key, sid, 3, 1_787_100_000_000_000_000 + i * 10 ** 12))
    conn.commit()
    conn.close()

    keys_json = os.path.join(work, "keys.json")
    with open(keys_json, "w") as f:
        json.dump({"keys": [{"key_id": KEY_ID, "algorithm": "ed25519", "public_key_hex": PUBLIC_HEX,
                             "comment": "PUBLISHED TEST KEY — seed is public"}]}, f, indent=2)

    # --- the witness -----------------------------------------------------
    target = os.path.join(work, "wtarget")
    env = dict(os.environ, CARGO_TARGET_DIR=target)
    subprocess.run(["cargo", "build", "--release", "-p", "witness-server", "-p", "witness-client"],
                   cwd=WITNESS_REPO, env=env, check=True)
    wbin = os.path.join(target, "release", "virp-witness")
    cbin = os.path.join(target, "release", "virp-witness-client")

    wkey = os.path.join(work, "witness.key")
    out = subprocess.run([wbin, "keygen", "--out", wkey], capture_output=True, text=True, check=True).stdout
    witness_pub = [l.split()[-1] for l in out.splitlines() if "public_key_hex" in l][0]
    with open(os.path.join(args.out + ".witness.pub"), "w") as f:
        f.write(witness_pub + "\n")

    registry = os.path.join(work, "submitters.json")
    with open(registry, "w") as f:
        json.dump({"keys": [{"key_id": KEY_ID, "algorithm": "ed25519", "public_key_hex": PUBLIC_HEX,
                             "comment": "the published chain-signing TEST key"}]}, f, indent=2)

    wenv = dict(os.environ,
                VIRP_WITNESS_KEY=wkey,
                VIRP_WITNESS_REGISTRY=registry,
                VIRP_WITNESS_DB=os.path.join(work, "witness.db"),
                VIRP_WITNESS_BIND="127.0.0.1:%d" % args.port,
                VIRP_WITNESS_SUBMIT_BIND="127.0.0.1:%d" % (args.port + 1))
    log = open(os.path.join(work, "witness.log"), "w")
    proc = subprocess.Popen([wbin, "serve"], env=wenv, stdout=log, stderr=subprocess.STDOUT)
    try:
        if not wait_for_port(args.port):
            raise SystemExit("witness did not come up; see %s" % log.name)

        # Submit the filler heads FIRST, so the session under test is not
        # leaf 0 of a one-leaf tree.
        for h in heads[1:] + heads[:1]:
            hp = os.path.join(work, "heads", "%s-%d.head" % (h["session_id"].replace(":", "_"), h["last_sequence"]))
            with open(hp, "w") as f:
                f.write(head_canonical(h["session_id"], h["last_sequence"], h["last_entry_hash"]).decode("utf-8"))
            r = subprocess.run([cbin, "submit", "--witness", "http://127.0.0.1:%d" % args.port,
                                "--head-file", hp, "--key", submitter_key],
                               capture_output=True, text=True)
            if r.returncode != 0:
                raise SystemExit("submit failed: %s" % (r.stderr or r.stdout))

        subprocess.run([sys.executable, EXPORTER,
                        "--db", db, "--out", args.out,
                        "--all-sessions", "--artifacts",
                        "--keys", keys_json,
                        "--witness", "http://127.0.0.1:%d" % args.port,
                        "--witness-receipts", os.path.join(work, "heads")],
                       check=True)
    finally:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
        log.close()

    print("\nfixture written to %s" % args.out)
    print("witness public key: %s (also in %s.witness.pub)" % (witness_pub, args.out))


if __name__ == "__main__":
    main()
