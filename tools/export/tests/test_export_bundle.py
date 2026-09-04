"""
Tests for tools/export/export_bundle.py.

The gate: export a synthetic sqlite fixture built from the golden Appendix A
vectors, run the REAL `virp-verify` binary on the output, and expect the
operator-attested verdict (exit 3). The exporter is not done until the real
verifier accepts what it writes. Python 3 stdlib only; `cargo` is needed once
to build virp-verify if target/debug/virp-verify is missing.

Run:  python3 -m unittest discover -s tools/export/tests -v
"""

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
EXPORT = os.path.join(REPO, "tools", "export", "export_bundle.py")
VECTORS = os.path.join(REPO, "crates", "docket-bundle", "tests", "vectors")
APPENDIX_A = os.path.join(VECTORS, "fixtures-appendix-a.json")
CHAIN_SIGNING = os.path.join(VECTORS, "chain-signing-v1.json")
REAL_SEAL = os.path.join(VECTORS, "seal-2026-08.json")
REAL_SEAL_SHA256 = "58309407ed41349611205d2ad1efd2c1df3b443e7cba6a89ad502699d4e93479"
# TEST minisign signature over the vector seal by a THROWAWAY key, plus that
# key's public half (vectors/README.md). NOT the operator's signature.
TEST_MINISIG = os.path.join(VECTORS, "seal-2026-08.json.test.minisig")
TEST_MINISIGN_PUB = os.path.join(VECTORS, "minisign-test.pub")
UPSTREAM_SEAL = os.path.expanduser("<upstream-seal>/seal-2026-08.json")

sys.path.insert(0, os.path.join(REPO, "tools", "export"))
import export_bundle  # noqa: E402

# The C schema, verbatim from src/virp_chain.c (D-1 columns added by the
# fixture when a test needs them).
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
  updated_at_ns INTEGER NOT NULL
);
"""

ENTRY_COLS = [
    "session_id", "sequence", "chain_entry_hash", "previous_entry_hash", "timestamp_ns", "monotonic_ns",
    "artifact_type", "artifact_id", "artifact_hash", "artifact_hash_alg", "artifact_schema_version",
    "signer_node_id", "signer_org_id", "chain_hmac",
]

SYNTHETIC_SESSION = "docket-test:synthetic-1"
APPENDIX_A_SESSION = "approval:clab-frr-ospf-frr1"
AUTOPILOT_SESSION = "autopilot:2026-08-22"


# --- test-side canonical encoder (VERIFIED against golden vector A) --------


def canonical_bytes(f):
    """The twelve-field canonical exactly as build_canonical_json writes it:
    fixed order, compact, raw strings, plain decimal integers."""
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


def sha256_hex(b):
    return hashlib.sha256(b).hexdigest()


def genesis_hash(session_id):
    return sha256_hex(b"VIRP_CHAIN_GENESIS:" + session_id.encode("utf-8"))


def fake_hmac(label):
    """A 64-hex placeholder standing in for an HMAC the test cannot compute
    (no K_chain). The verifier must grade it OPERATOR-ATTESTED, never
    VERIFIED — that is the whole point of the symmetric tier."""
    return sha256_hex(b"synthetic-hmac-not-real:" + label.encode("utf-8"))


def parse_canonical(utf8):
    """Fields from a golden canonical_utf8 string (these are plain JSON in
    practice — the golden values contain no quotes or escapes)."""
    return json.loads(utf8)


def load_appendix_a():
    with open(APPENDIX_A) as f:
        return json.load(f)


def synthetic_session(n, bodies=None):
    """A complete n-entry session with correct links/genesis and fake HMACs.

    `bodies` supplies the exact byte string each entry's artifact_hash
    commits to; the default is b"body-<i>". Passing real device output is how
    the redaction tests get entries whose bodies bind correctly AND carry
    credentials."""
    entries = []
    prev = genesis_hash(SYNTHETIC_SESSION)
    for i in range(n):
        body = bodies[i] if bodies else b"body-%d" % i
        f = {
            "artifact_hash": sha256_hex(body),
            "artifact_hash_alg": "sha256",
            "artifact_id": "obs:synthetic:%04d" % i,
            "artifact_schema_version": "1",
            "artifact_type": "observation",
            "monotonic_ns": 1_000_000_000 + i * 1000,
            "previous_entry_hash": prev,
            "sequence": i,
            "session_id": SYNTHETIC_SESSION,
            "signer_node_id": 1,
            "signer_org_id": "local",
            "timestamp_ns": 1_787_000_000_000_000_000 + i * 1000,
        }
        h = sha256_hex(canonical_bytes(f))
        entries.append((f, h, fake_hmac("entry-%d" % i)))
        prev = h
    head = {"session_id": SYNTHETIC_SESSION, "last_sequence": n - 1, "last_entry_hash": prev,
            "head_hmac": fake_hmac("head"), "updated_at_ns": 1_787_000_000_000_001_000}
    return entries, head


# --- fixture database ---------------------------------------------------------


def insert_entry(conn, fields, chain_entry_hash, chain_hmac, extra=None):
    row = dict(fields)
    row["chain_entry_hash"] = chain_entry_hash
    row["chain_hmac"] = chain_hmac
    cols = list(ENTRY_COLS)
    if extra:
        row.update(extra)
        cols += list(extra)
    conn.execute(
        "INSERT INTO chain_entries (%s) VALUES (%s)" % (", ".join(cols), ", ".join("?" * len(cols))),
        [row[c] for c in cols],
    )


def insert_head(conn, head, extra=None):
    cols = ["session_id", "last_sequence", "last_entry_hash", "head_hmac", "updated_at_ns"]
    row = dict(head)
    if extra:
        row.update(extra)
        cols += list(extra)
    conn.execute(
        "INSERT INTO chain_heads (%s) VALUES (%s)" % (", ".join(cols), ", ".join("?" * len(cols))),
        [row[c] for c in cols],
    )


def build_fixture_db(path, d1_columns=False, d1_hmac=""):
    """The synthetic snapshot:

    * Appendix A rows A–E with their REAL hashes and HMACs, plus the REAL head
      row for approval:clab-frr-ospf-frr1 (last_sequence 272). The three
      approval entries (81–83) are therefore a partial chain — on purpose:
      the exporter must ship it as-is and the verifier must FAIL it.
    * autopilot:2026-08-22 = golden entry A alone (sequence 0, real genesis,
      real hash, real HMAC) with a synthetic head row closing it at 0.
    * docket-test:synthetic-1 = a complete 5-entry synthetic session with
      fake HMACs.
    * with d1_columns: the golden inv-lock-1 signed session from
      chain-signing-v1.json in the D-1 columns. d1_hmac fills its HMAC
      cells: "" (the default) exercises the exporter's copy-the-empty-string
      fidelity and FAILS in the verifier; a 64-hex fake grades
      OPERATOR-ATTESTED, letting the signature tier carry the verdict.
    """
    a = load_appendix_a()
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    if d1_columns:
        conn.executescript(
            "ALTER TABLE chain_entries ADD COLUMN chain_sig TEXT;"
            "ALTER TABLE chain_entries ADD COLUMN chain_sig_key_id TEXT;"
            "ALTER TABLE chain_heads ADD COLUMN head_sig TEXT;"
            "ALTER TABLE chain_heads ADD COLUMN head_sig_key_id TEXT;"
        )
    for e in a["entries"].values():
        insert_entry(conn, parse_canonical(e["canonical_utf8"]), e["chain_entry_hash"], e["chain_hmac"])
    h = a["head"]
    insert_head(conn, {k: h[k] for k in ("session_id", "last_sequence", "last_entry_hash", "head_hmac", "updated_at_ns")})

    ea = a["entries"]["A"]
    insert_head(conn, {"session_id": AUTOPILOT_SESSION, "last_sequence": 0, "last_entry_hash": ea["chain_entry_hash"],
                       "head_hmac": fake_hmac("autopilot-head"), "updated_at_ns": 1})

    entries, head = synthetic_session(5)
    for f, hh, mac in entries:
        insert_entry(conn, f, hh, mac)
    insert_head(conn, head)

    if d1_columns:
        with open(CHAIN_SIGNING) as f:
            cs = json.load(f)
        vecs = {v["name"]: v for v in cs["vectors"]}
        key_id = cs["test_key"]["key_id_hex"]
        ent = vecs["inv-lock-entry-0"]
        hd = vecs["inv-lock-head-0"]
        fields = parse_canonical(ent["message_utf8"])
        insert_entry(conn, fields, sha256_hex(canonical_bytes(fields)), d1_hmac,
                     {"chain_sig": ent["signature_hex"], "chain_sig_key_id": key_id})
        hf = json.loads(hd["message_utf8"])
        insert_head(conn, {"session_id": hf["session_id"], "last_sequence": hf["last_sequence"],
                           "last_entry_hash": hf["last_entry_hash"], "head_hmac": d1_hmac, "updated_at_ns": 2},
                    {"head_sig": hd["signature_hex"], "head_sig_key_id": key_id})
    conn.commit()
    conn.close()


# --- test seal (labelled synthetic; same rules as virp-seal/1) -------------


def merkle_root(sessions):
    level = []
    for s in sessions:
        buf = b"\x00" + s["session_id"].encode("utf-8") + b"\x1f" + str(s["entry_count"]).encode() + b"\x1f" + s["head_hash"].encode()
        level.append(hashlib.sha256(buf).digest())
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest())
            else:
                nxt.append(level[i])
        level = nxt
    return level[0].hex()


# Named `make_test_seal`, not `test_seal`: pytest collects any module-level
# `test_*` callable, and this helper takes a `sessions` argument, so it was
# collected and reported as a permanent ERROR ("fixture 'sessions' not
# found") on every run. A test line that is always red trains readers to
# ignore test output.
def make_test_seal(sessions):
    sessions = sorted(sessions, key=lambda s: s["session_id"].encode("utf-8"))
    return {
        "seal_version": "virp-seal/1",
        "created_at": "2026-08-23T00:00:00Z",
        "sealed_by": "docket export tests (SYNTHETIC seal — not the D-0 seal)",
        "seal_public_key": "minisign:SYNTHETIC",
        "sessions": sessions,
        "merkle": {"root": merkle_root(sessions), "leaf_count": len(sessions)},
        "residual_disclosure": "Synthetic test seal. Attests nothing.",
    }


# --- the real verifier -----------------------------------------------------


def find_virp_verify():
    exe = os.path.join(REPO, "target", "debug", "virp-verify")
    if os.path.exists(exe):
        return exe
    cargo = shutil.which("cargo") or os.path.expanduser("~/.cargo/bin/cargo")
    if not os.path.exists(cargo):
        raise RuntimeError("virp-verify binary not built and cargo not found; run `cargo build -p virp-verify` first")
    subprocess.run([cargo, "build", "-q", "-p", "virp-verify"], cwd=REPO, check=True)
    return exe


def verify(bundle_dir, *extra):
    """Run the real verifier (extra flags first). Returns
    (exit_code, text_stdout, json_report)."""
    exe = find_virp_verify()
    text = subprocess.run([exe, *extra, bundle_dir], capture_output=True, text=True)
    js = subprocess.run([exe, "--json", *extra, bundle_dir], capture_output=True, text=True)
    assert text.returncode == js.returncode, (text.returncode, js.returncode, js.stderr)
    report = json.loads(js.stdout) if js.stdout.strip().startswith("{") else None
    return text.returncode, text.stdout, report


def session_report(report, session_id):
    return next(s for s in report["sessions"] if s["session_id"] == session_id)


def prop(sreport, name):
    return next(p for p in sreport["properties"] if p["name"] == name)["status"]


def run_export(*args, env=None):
    full_env = None if env is None else {**os.environ, **env}
    return subprocess.run([sys.executable, EXPORT] + list(args), capture_output=True, text=True, env=full_env)


def sha256_file(path):
    with open(path, "rb") as f:
        return sha256_hex(f.read())


def side_files(db_path):
    d = os.path.dirname(db_path)
    return sorted(n for n in os.listdir(d) if n.startswith(os.path.basename(db_path)) and n != os.path.basename(db_path))


# --- tests ---------------------------------------------------------------------


class EncoderSanity(unittest.TestCase):
    """The test-side encoder must reproduce golden vector A exactly; if it
    did not, every synthetic chain below would be wrong by construction."""

    def test_encoder_reproduces_golden_vector_a(self):
        a = load_appendix_a()
        for name, e in a["entries"].items():
            fields = parse_canonical(e["canonical_utf8"])
            self.assertEqual(canonical_bytes(fields).decode(), e["canonical_utf8"], name)
            self.assertEqual(sha256_hex(canonical_bytes(fields)), e["chain_entry_hash"], name)
        ea = a["entries"]["A"]
        self.assertEqual(parse_canonical(ea["canonical_utf8"])["previous_entry_hash"], genesis_hash(AUTOPILOT_SESSION))

    def test_seal_merkle_rule_reproduces_the_real_seal_root(self):
        with open(REAL_SEAL) as f:
            s = json.load(f)
        self.assertEqual(merkle_root(s["sessions"]), s["merkle"]["root"])


class ExportAndVerify(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="docket-export-test-")
        self.db = os.path.join(self.tmp, "snapshot.db")
        build_fixture_db(self.db)
        self.db_sha = sha256_file(self.db)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def out(self, name):
        return os.path.join(self.tmp, name)

    # ---- THE GATE -------------------------------------------------------------

    def test_gate_export_is_accepted_by_virp_verify_as_operator_attested_exit_3(self):
        out = self.out("bundle")
        r = run_export("--db", self.db, "--out", out, "--sessions", AUTOPILOT_SESSION, SYNTHETIC_SESSION)
        self.assertEqual(r.returncode, 0, r.stderr)

        code, text, report = verify(out)
        self.assertEqual(code, 3, text)
        self.assertIn("OVERALL VERDICT: OPERATOR-ATTESTED", text)
        self.assertEqual(report["verdict"], "operator_attested_unverifiable")
        self.assertEqual(report["key_ids"], [])
        for sid in (AUTOPILOT_SESSION, SYNTHETIC_SESSION):
            s = session_report(report, sid)
            self.assertEqual(s["verdict"], "operator_attested_unverifiable", sid)
            for p in ("entry_hashes", "contiguity", "genesis", "links", "head_commitment"):
                self.assertEqual(prop(s, p), "verified", (sid, p))
            self.assertEqual(prop(s, "entry_hmacs"), "operator_attested", sid)
            self.assertEqual(prop(s, "head_hmac"), "operator_attested", sid)
            self.assertEqual(prop(s, "head_signature"), "absent", sid)

        # Faithful copy: HMACs in the bundle are the DB's bytes, untouched.
        a = load_appendix_a()
        with open(os.path.join(out, "sessions", "autopilot_2026-08-22.json")) as f:
            chain = json.load(f)
        self.assertEqual(chain["entries"][0]["chain_hmac"], a["entries"]["A"]["chain_hmac"])
        self.assertEqual(chain["entries"][0]["chain_entry_hash"], a["entries"]["A"]["chain_entry_hash"])
        self.assertNotIn("canonical_utf8", chain["entries"][0])
        self.assertNotIn("signature", chain["entries"][0])
        self.assertFalse(os.path.exists(os.path.join(out, "keys.json")))

        # Summary output names every file with its sha256.
        with open(os.path.join(out, "manifest.json"), "rb") as f:
            self.assertIn(sha256_hex(f.read()) + "  manifest.json", r.stdout)
        self.assertIn("files written (sha256):", r.stdout)

    # ---- fidelity: the exporter does not judge ------------------------------

    def test_partial_appendix_a_session_is_exported_as_is_and_fails_in_the_verifier(self):
        out = self.out("partial")
        r = run_export("--db", self.db, "--out", out, "--sessions", APPENDIX_A_SESSION)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(out, "sessions", "approval_clab-frr-ospf-frr1.json")) as f:
            chain = json.load(f)
        self.assertEqual([e["sequence"] for e in chain["entries"]], [81, 82, 83])  # not renumbered, not filled
        self.assertEqual(chain["head"]["last_sequence"], 272)  # the real head, untouched
        code, text, report = verify(out)
        self.assertEqual(code, 1, text)
        s = session_report(report, APPENDIX_A_SESSION)
        self.assertEqual(s["verdict"], "failed")
        self.assertEqual(prop(s, "entry_hashes"), "verified")  # the three real rows do hash
        self.assertEqual(prop(s, "contiguity"), "failed")

    # ---- seals ------------------------------------------------------------------

    def test_real_seal_is_copied_verbatim_and_its_consistency_verifies(self):
        self.assertEqual(sha256_file(REAL_SEAL), REAL_SEAL_SHA256)
        if os.path.exists(UPSTREAM_SEAL):
            self.assertEqual(sha256_file(UPSTREAM_SEAL), REAL_SEAL_SHA256, "repo copy of the seal drifted from the upstream VIRP tree")
        out = self.out("sealed-real")
        r = run_export("--db", self.db, "--out", out, "--sessions", AUTOPILOT_SESSION, "--seal", REAL_SEAL)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sha256_file(os.path.join(out, "seal", "seal-2026-08.json")), REAL_SEAL_SHA256)
        with open(os.path.join(out, "manifest.json")) as f:
            self.assertEqual(json.load(f)["seal"], "seal/seal-2026-08.json")

        code, text, report = verify(out)
        self.assertEqual(report["seal"]["consistency"]["status"], "verified")
        self.assertEqual(report["seal"]["session_count"], 350)
        # The real seal attests 5184 entries for autopilot:2026-08-22; this
        # fixture holds only golden entry A. The anchor must FAIL, and the
        # exporter must not have hidden that. (A matching real chain is not
        # reproducible from the public vectors; the anchor-VERIFIED path is
        # proven with a synthetic seal in the next test.)
        s = session_report(report, AUTOPILOT_SESSION)
        self.assertEqual(s["seal_head_match"]["status"], "failed")
        self.assertEqual(report["verdict"], "failed")
        self.assertEqual(code, 1, text)

    def test_seal_head_match_verifies_for_a_session_the_seal_lists(self):
        entries, head = synthetic_session(5)
        a = load_appendix_a()
        seal = make_test_seal([
            {"session_id": SYNTHETIC_SESSION, "entry_count": 5, "head_hash": head["last_entry_hash"]},
            {"session_id": AUTOPILOT_SESSION, "entry_count": 1, "head_hash": a["entries"]["A"]["chain_entry_hash"]},
            {"session_id": "zz-unrelated", "entry_count": 7, "head_hash": "00" * 32},
        ])
        seal_path = os.path.join(self.tmp, "test-seal.json")
        with open(seal_path, "w") as f:
            json.dump(seal, f, indent=1)
        out = self.out("sealed-synthetic")
        r = run_export("--db", self.db, "--out", out, "--sessions", SYNTHETIC_SESSION, AUTOPILOT_SESSION, "--seal", seal_path)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sha256_file(os.path.join(out, "seal", "test-seal.json")), sha256_file(seal_path))

        code, text, report = verify(out)
        self.assertEqual(report["seal"]["consistency"]["status"], "verified")
        for sid in (SYNTHETIC_SESSION, AUTOPILOT_SESSION):
            self.assertEqual(session_report(report, sid)["seal_head_match"]["status"], "verified", sid)
        self.assertEqual(report["verdict"], "operator_attested_unverifiable")
        self.assertEqual(code, 3, text)
        self.assertIn("seal_head_match        VERIFIED", text)

    def test_seal_sig_is_carried_verbatim_and_verifies_under_an_out_of_band_key(self):
        out = self.out("sealed-signed")
        r = run_export("--db", self.db, "--out", out, "--sessions", SYNTHETIC_SESSION,
                       "--seal", REAL_SEAL, "--seal-sig", TEST_MINISIG)
        self.assertEqual(r.returncode, 0, r.stderr)
        carried = os.path.join(out, "seal", "seal-2026-08.json.test.minisig")
        self.assertEqual(sha256_file(carried), sha256_file(TEST_MINISIG))
        with open(os.path.join(out, "manifest.json")) as f:
            self.assertEqual(json.load(f)["seal_signature"], "seal/seal-2026-08.json.test.minisig")

        # Without --seal-key: unchanged, UNVERIFIABLE even with the carried sig.
        code, _, report = verify(out)
        self.assertEqual(report["seal"]["signature"]["status"], "unverifiable")
        self.assertEqual(code, 3)
        # With the key OUT OF BAND: the carried signature verifies.
        code, text, report = verify(out, "--seal-key", TEST_MINISIGN_PUB)
        self.assertEqual(report["seal"]["signature"]["status"], "verified")
        self.assertIn("seal_public_key claim is ignored", report["seal"]["signature_detail"])
        self.assertEqual(code, 3, text)  # seal signature upgrades nothing

    def test_seal_sig_without_seal_is_an_error(self):
        r = run_export("--db", self.db, "--out", self.out("ss"), "--sessions", SYNTHETIC_SESSION,
                       "--seal-sig", TEST_MINISIG)
        self.assertEqual(r.returncode, 2)
        self.assertIn("needs --seal", r.stderr)
        self.assertFalse(os.path.exists(self.out("ss")))

    def test_seal_sig_that_is_not_a_minisig_is_refused(self):
        bad = os.path.join(self.tmp, "not-a-sig.minisig")
        with open(bad, "w") as f:
            f.write("untrusted comment: x\nAAAA\n")
        r = run_export("--db", self.db, "--out", self.out("sb"), "--sessions", SYNTHETIC_SESSION,
                       "--seal", REAL_SEAL, "--seal-sig", bad)
        self.assertEqual(r.returncode, 2)
        self.assertIn("not a minisign signature blob", r.stderr)
        self.assertFalse(os.path.exists(self.out("sb")))

    def test_seal_that_is_not_virp_seal_1_is_refused(self):
        bad = os.path.join(self.tmp, "bad-seal.json")
        with open(bad, "w") as f:
            json.dump({"seal_version": "virp-seal/2"}, f)
        r = run_export("--db", self.db, "--out", self.out("x"), "--sessions", SYNTHETIC_SESSION, "--seal", bad)
        self.assertEqual(r.returncode, 2)
        self.assertIn("expected seal_version 'virp-seal/1'", r.stderr)
        self.assertFalse(os.path.exists(self.out("x")))

    # ---- D-1 columns -------------------------------------------------------------

    def test_d1_signature_columns_export_as_signature_objects(self):
        db = os.path.join(self.tmp, "snapshot-d1.db")
        build_fixture_db(db, d1_columns=True)
        out = self.out("d1")
        r = run_export("--db", db, "--out", out, "--sessions", "inv-lock-1", SYNTHETIC_SESSION)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("D-1 signature columns: present", r.stdout)
        with open(os.path.join(out, "sessions", "inv-lock-1.json")) as f:
            chain = json.load(f)
        sig = chain["entries"][0]["signature"]
        self.assertEqual(sig["signature_scheme"], "ed25519-detached-v1")
        self.assertEqual(sig["signing_key_id"], "24f6ed6acbfe1009c030d7ca567c33ca")
        self.assertEqual(chain["head"]["signature"]["signing_key_id"], "24f6ed6acbfe1009c030d7ca567c33ca")
        # Empty HMAC cells ('' in the fixture) are exported as-is, not dropped.
        self.assertEqual(chain["entries"][0]["chain_hmac"], "")
        # Unsigned synthetic rows (NULL sig cells) carry no signature object.
        with open(os.path.join(out, "sessions", "docket-test_synthetic-1.json")) as f:
            self.assertNotIn("signature", json.load(f)["entries"][0])

        # No keys.json -> signed under a key the verifier was not given ->
        # OPERATOR-ATTESTED, never VERIFIED; the empty HMAC strings are the
        # verifier's to grade (malformed -> FAILED) — exporter did not soften.
        code, text, report = verify(out)
        s = session_report(report, "inv-lock-1")
        self.assertEqual(prop(s, "head_signature"), "unverifiable")
        self.assertEqual(prop(s, "session_key_binding"), "verified")
        self.assertEqual(prop(s, "entry_hmacs"), "failed")
        self.assertEqual(s["verdict"], "failed")
        self.assertEqual(code, 1, text)

    # ---- safety and operator round-trip ---------------------------------------

    def test_database_is_untouched_and_no_side_files_appear(self):
        r = run_export("--db", self.db, "--out", self.out("ro"), "--all-sessions")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(sha256_file(self.db), self.db_sha)
        self.assertEqual(side_files(self.db), [])

    def test_refuses_existing_output_directory(self):
        os.mkdir(self.out("exists"))
        r = run_export("--db", self.db, "--out", self.out("exists"), "--sessions", SYNTHETIC_SESSION)
        self.assertEqual(r.returncode, 2)
        self.assertIn("already exists", r.stderr)
        self.assertEqual(os.listdir(self.out("exists")), [])

    def test_unknown_session_names_itself_and_points_at_list_sessions(self):
        r = run_export("--db", self.db, "--out", self.out("u"), "--sessions", SYNTHETIC_SESSION, "nope:1")
        self.assertEqual(r.returncode, 2)
        self.assertIn("['nope:1']", r.stderr)
        self.assertIn("--list-sessions", r.stderr)
        self.assertFalse(os.path.exists(self.out("u")))
        lst = run_export("--db", self.db, "--list-sessions")
        self.assertEqual(lst.returncode, 0, lst.stderr)
        self.assertIn(SYNTHETIC_SESSION, lst.stdout)
        self.assertIn("NO HEAD", lst.stdout)  # gate-enforce:pbs-lab has entry E but no head row

    def test_schema_drift_error_names_expected_vs_found(self):
        db = os.path.join(self.tmp, "drift.db")
        conn = sqlite3.connect(db)
        conn.executescript(SCHEMA.replace("  chain_hmac TEXT NOT NULL,\n  UNIQUE", "  hmac_sha256 TEXT NOT NULL,\n  UNIQUE"))
        conn.execute("DROP TABLE chain_heads")
        conn.commit()
        conn.close()
        r = run_export("--db", db, "--out", self.out("d"), "--sessions", "x")
        self.assertEqual(r.returncode, 2)
        self.assertIn("schema drift", r.stderr)
        self.assertIn("missing required column(s) ['chain_hmac']", r.stderr)
        self.assertIn("hmac_sha256", r.stderr)  # what WAS found
        self.assertIn("table 'chain_heads': MISSING", r.stderr)
        self.assertFalse(os.path.exists(self.out("d")))

    def test_null_required_cell_is_reported_with_session_and_sequence(self):
        db = os.path.join(self.tmp, "null.db")
        build_fixture_db(db)
        conn = sqlite3.connect(db)
        conn.execute("CREATE TABLE t AS SELECT * FROM chain_entries")  # drop NOT NULL by copying
        conn.execute("DROP TABLE chain_entries")
        conn.execute("ALTER TABLE t RENAME TO chain_entries")
        conn.execute("UPDATE chain_entries SET signer_org_id = NULL WHERE session_id = ? AND sequence = 2", (SYNTHETIC_SESSION,))
        conn.commit()
        conn.close()
        r = run_export("--db", db, "--out", self.out("n"), "--sessions", SYNTHETIC_SESSION)
        self.assertEqual(r.returncode, 2)
        self.assertIn("sequence=2", r.stderr)
        self.assertIn("'signer_org_id' is NULL", r.stderr)

    def test_a_non_empty_wal_is_refused_not_silently_dropped(self):
        """immutable=1 IGNORES the write-ahead log. Measured 2026-09-04: a
        live chain with a 4.2 MB WAL exported fifteen entries instead of
        twenty, and the bundle looked complete — every hash and signature
        verified, and the five missing records left no hole to find."""
        db = self.out("wal.db")
        build_fixture_db(db)
        conn = sqlite3.connect(db)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE scratch (x TEXT)")
        conn.execute("INSERT INTO scratch VALUES ('uncheckpointed')")
        conn.commit()
        self.assertGreater(os.path.getsize(db + "-wal"), 0, "fixture needs a live WAL")
        r = run_export("--db", db, "--out", self.out("from-wal"), "--sessions", SYNTHETIC_SESSION)
        conn.close()
        self.assertEqual(r.returncode, 2)
        self.assertIn("non-empty write-ahead log", r.stderr)
        self.assertIn("IGNORES the WAL", r.stderr)
        # it must say which it did, and it refuses rather than writing to
        # the operator's source database
        self.assertIn("Refusing rather than exporting an undercount", r.stderr)
        self.assertIn("wal_checkpoint(TRUNCATE)", r.stderr)
        self.assertFalse(os.path.exists(self.out("from-wal")))

    def test_a_checkpointed_wal_exports_normally(self):
        db = self.out("ckpt.db")
        build_fixture_db(db)
        conn = sqlite3.connect(db)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("CREATE TABLE scratch (x TEXT)")
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        conn.commit()
        conn.close()
        r = run_export("--db", db, "--out", self.out("from-ckpt"), "--sessions", SYNTHETIC_SESSION)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_stdlib_only(self):
        with open(EXPORT) as f:
            src = f.read()
        imports = {line.split()[1] for line in src.splitlines() if line.startswith(("import ", "from "))}
        self.assertEqual(
            imports,
            {"argparse", "base64", "binascii", "datetime", "glob", "hashlib", "json", "os", "re", "sqlite3",
             "sys", "urllib.parse"},
        )


# --- public keys (--keys) ---------------------------------------------------


def tree_hashes(root):
    """relative path -> sha256 for every file under root."""
    out = {}
    for dirpath, _, files in os.walk(root):
        for n in files:
            p = os.path.join(dirpath, n)
            out[os.path.relpath(p, root)] = sha256_file(p)
    return out


class KeysExport(unittest.TestCase):
    """--keys: keys.json and the manifest pointer are deterministic, key_id
    is derived from the key bytes (never copied from a label), casing is
    normalized on write, secret material is refused, and a --keys export of
    a signed session is CRYPTOGRAPHICALLY-VERIFIED by the real verifier."""

    # A second real Ed25519 point (the public key embedded in the D-0 seal's
    # minisign key), so multi-key exports stay verifier-readable. Its derived
    # sha256-raw-16 id is fixed by the bytes. Used as ARBITRARY key material
    # only: the seal key is NOT a chain-signing key in any real deployment,
    # and nothing about key roles may be inferred from this fixture — the
    # test needed any second valid curve point and this one was on hand.
    SECOND_PUB = "71622502a38314f06dcb28253efd287110502b8b33847459c4509541db64e901"

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="docket-export-keys-")
        self.db = os.path.join(self.tmp, "snapshot-d1.db")
        # Non-empty (fake) HMAC cells: OPERATOR-ATTESTED, so the signature
        # tier decides the verdict instead of a malformed-HMAC failure.
        build_fixture_db(self.db, d1_columns=True, d1_hmac=fake_hmac("d1-signed"))
        with open(CHAIN_SIGNING) as f:
            self.cs = json.load(f)
        self.pub = self.cs["test_key"]["public_key_hex"]
        self.key_id = self.cs["test_key"]["key_id_hex"]

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def out(self, name):
        return os.path.join(self.tmp, name)

    def key_file(self, name, content):
        path = os.path.join(self.tmp, name)
        with open(path, "w") as f:
            if isinstance(content, str):
                f.write(content)
            else:
                json.dump(content, f, indent=1)
        return path

    # ---- THE GATE: the real verifier accepts a --keys export ---------------
    #
    # Since the signer-trust axis, a key travelling INSIDE the bundle checks
    # the signatures but is no examiner-selected trust anchor: the bundle is
    # CRYPTOGRAPHICALLY-CONSISTENT (exit 5) on its own, and earns the full
    # CRYPTOGRAPHICALLY-VERIFIED (exit 0) only when the examiner pins the
    # same key out of band (--pin).

    def test_gate_keys_export_of_signed_session_verifies_and_pins_to_exit_0(self):
        pub_path = self.key_file("chain-signing.pub.json", {"algorithm": "Ed25519", "public_key_hex": self.pub})
        out = self.out("bundle")
        r = run_export("--db", self.db, "--out", out, "--sessions", "inv-lock-1", "--keys", pub_path)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("keys.json: 1 public key(s): " + self.key_id, r.stdout)
        with open(os.path.join(out, "manifest.json")) as f:
            self.assertEqual(json.load(f)["keys"], "keys.json")

        # In-band key only: valid cryptography, unestablished signer.
        code, text, report = verify(out)
        self.assertEqual(code, 5, text)
        self.assertEqual(report["verdict"], "cryptographically_consistent")
        self.assertEqual(report["key_ids"], [self.key_id])
        self.assertEqual(report["bundle_key_ids"], [self.key_id])
        self.assertEqual(report["pinned_key_ids"], [])
        s = session_report(report, "inv-lock-1")
        self.assertEqual(s["verdict"], "cryptographically_consistent")
        for p in ("head_signature", "entry_signatures", "session_key_binding"):
            self.assertEqual(prop(s, p), "verified", p)
        self.assertEqual(s["signer"]["trust"], "unestablished")
        self.assertEqual(s["signer"]["signature_validity"]["status"], "verified")
        self.assertIn("OVERALL VERDICT: CRYPTOGRAPHICALLY-CONSISTENT", text)

        # The exported keys.json doubles as the examiner's pin file: pinned,
        # the same bundle earns the full verdict.
        code, text, report = verify(out, "--pin", os.path.join(out, "keys.json"))
        self.assertEqual(code, 0, text)
        self.assertEqual(report["verdict"], "cryptographically_verified")
        self.assertEqual(report["pinned_key_ids"], [self.key_id])
        s = session_report(report, "inv-lock-1")
        self.assertEqual(s["signer"]["trust"], "pinned")
        self.assertIn("OVERALL VERDICT: CRYPTOGRAPHICALLY-VERIFIED", text)

    # ---- determinism --------------------------------------------------------

    def test_reexport_is_byte_identical_under_source_date_epoch(self):
        key_a = self.key_file("a.pub.json", {"algorithm": "Ed25519", "public_key_hex": self.pub})
        key_b = self.key_file("b.pub", self.SECOND_PUB + "\n")
        env = {"SOURCE_DATE_EPOCH": "0"}
        r1 = run_export("--db", self.db, "--out", self.out("one"), "--sessions", "inv-lock-1", SYNTHETIC_SESSION,
                        "--keys", key_a, key_b, env=env)
        self.assertEqual(r1.returncode, 0, r1.stderr)
        # Same inputs, opposite --keys order: ordering is derived, not given.
        r2 = run_export("--db", self.db, "--out", self.out("two"), "--sessions", "inv-lock-1", SYNTHETIC_SESSION,
                        "--keys", key_b, key_a, env=env)
        self.assertEqual(r2.returncode, 0, r2.stderr)
        one, two = tree_hashes(self.out("one")), tree_hashes(self.out("two"))
        self.assertEqual(one, two)
        with open(os.path.join(self.out("one"), "manifest.json")) as f:
            manifest = json.load(f)
        self.assertEqual(manifest["created_at"], "1970-01-01T00:00:00Z")
        with open(os.path.join(self.out("one"), "keys.json")) as f:
            ids = [k["key_id"] for k in json.load(f)["keys"]]
        self.assertEqual(ids, sorted(ids))
        self.assertEqual(len(ids), 2)
        self.assertIn(self.key_id, ids)

    # ---- key_id is derived, never copied ------------------------------------

    def test_key_id_derives_from_bytes_not_from_filename_or_label(self):
        # A raw-hex key file whose NAME lies about the id, in uppercase hex:
        # the emitted entry must carry the derived id and lowercase bytes.
        lying_name = self.key_file("00000000000000000000000000000000.pub", self.pub.upper() + "\n")
        out = self.out("derived")
        r = run_export("--db", self.db, "--out", out, "--sessions", SYNTHETIC_SESSION, "--keys", lying_name)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(out, "keys.json")) as f:
            entry = json.load(f)["keys"][0]
        self.assertEqual(entry["key_id"], self.key_id)
        self.assertEqual(entry["public_key_hex"], self.pub)

    def test_stated_key_id_that_does_not_rederive_is_an_error(self):
        bad = self.key_file("bad.json", {"public_key_hex": self.pub, "key_id": "00" * 16})
        r = run_export("--db", self.db, "--out", self.out("x"), "--sessions", SYNTHETIC_SESSION, "--keys", bad)
        self.assertEqual(r.returncode, 2)
        self.assertIn("does not re-derive", r.stderr)
        self.assertIn(self.key_id, r.stderr)  # the derived id is named
        self.assertFalse(os.path.exists(self.out("x")))

    def test_relabelled_key_collapses_to_one_entry(self):
        # Same bytes as raw hex and as JSON, different file names: one key.
        raw = self.key_file("k1.pub", self.pub)
        js = self.key_file("k2.json", {"public_key_hex": self.pub.upper(), "key_id": self.key_id.upper()})
        out = self.out("dedup")
        r = run_export("--db", self.db, "--out", out, "--sessions", SYNTHETIC_SESSION, "--keys", raw, js)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(out, "keys.json")) as f:
            keys = json.load(f)["keys"]
        self.assertEqual([k["key_id"] for k in keys], [self.key_id])

    # ---- casing is normalized on write, and pinned --------------------------

    def test_emitted_casing_is_lowercase_even_when_the_api_serves_Ed25519(self):
        pub_path = self.key_file(
            "api.json",
            {"algorithm": "Ed25519", "public_key_hex": self.pub.upper(), "key_id_hex": self.key_id.upper(),
             "comment": "as served"},
        )
        out = self.out("cased")
        r = run_export("--db", self.db, "--out", out, "--sessions", SYNTHETIC_SESSION, "--keys", pub_path)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(out, "keys.json")) as f:
            raw = f.read()
        self.assertIn('"algorithm": "ed25519"', raw)
        self.assertNotIn("Ed25519", raw)
        entry = json.loads(raw)["keys"][0]
        self.assertEqual(entry["public_key_hex"], self.pub)  # lowercase
        self.assertEqual(entry["key_id"], self.key_id)  # lowercase, derived
        self.assertEqual(entry["comment"], "as served")

    def test_algorithm_other_than_ed25519_is_an_error(self):
        bad = self.key_file("rsa.json", {"algorithm": "rsa", "public_key_hex": self.pub})
        r = run_export("--db", self.db, "--out", self.out("alg"), "--sessions", SYNTHETIC_SESSION, "--keys", bad)
        self.assertEqual(r.returncode, 2)
        self.assertIn("'rsa' is not ed25519", r.stderr)
        self.assertFalse(os.path.exists(self.out("alg")))

    # ---- no private key material enters Docket ------------------------------

    def test_key_file_carrying_secret_material_is_refused(self):
        # The chain-signing vector's test_key object holds seed_hex and
        # secret_key_hex_libsodium; handing it to --keys must be refused
        # outright, not quietly stripped to its public half.
        leak = self.key_file("test_key.json", self.cs["test_key"])
        r = run_export("--db", self.db, "--out", self.out("leak"), "--sessions", SYNTHETIC_SESSION, "--keys", leak)
        self.assertEqual(r.returncode, 2)
        self.assertIn("PUBLIC key files only", r.stderr)
        self.assertFalse(os.path.exists(self.out("leak")))

    # ---- one key format on both sides of Docket -----------------------------
    #
    # `virp-verify --pin` used to take only a keys.json and answered "invalid
    # JSON" for the bare-hex public half the exporter's --keys already read.
    # Both sides now read both forms; these tests hold the exporter half.

    def test_keys_json_shape_and_bare_hex_produce_the_same_keys_json(self):
        # The same key, in the two accepted forms, under a pinned clock:
        # byte-identical output, so a round trip through the bundle format is
        # a no-op and neither form is the "real" one.
        env = {"SOURCE_DATE_EPOCH": "0"}
        hex_file = self.key_file("chain.hex", self.pub + "\n")
        json_file = self.key_file(
            "keys.json",
            {"keys": [{"key_id": self.key_id, "algorithm": "ed25519", "public_key_hex": self.pub}]},
        )
        outs = {}
        for label, path in (("from-hex", hex_file), ("from-json", json_file)):
            out = self.out(label)
            r = run_export(
                "--db", self.db, "--out", out, "--sessions", SYNTHETIC_SESSION, "--keys", path, env=env
            )
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(os.path.join(out, "keys.json"), "rb") as f:
                outs[label] = f.read()
        self.assertEqual(outs["from-hex"], outs["from-json"])
        entry = json.loads(outs["from-hex"])["keys"][0]
        self.assertEqual(entry["key_id"], self.key_id)
        self.assertEqual(entry["public_key_hex"], self.pub)

    def test_a_keys_json_carrying_several_keys_exports_all_of_them(self):
        multi = self.key_file(
            "multi.json",
            {
                "keys": [
                    {"public_key_hex": self.pub},
                    {"public_key_hex": self.SECOND_PUB},
                ]
            },
        )
        out = self.out("multi")
        r = run_export("--db", self.db, "--out", out, "--sessions", SYNTHETIC_SESSION, "--keys", multi)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(out, "keys.json")) as f:
            ids = [k["key_id"] for k in json.load(f)["keys"]]
        self.assertEqual(len(ids), 2)
        self.assertIn(self.key_id, ids)

    def test_a_key_id_inside_a_keys_json_is_still_never_taken_on_faith(self):
        lying = self.key_file(
            "lying.json",
            {"keys": [{"key_id": "00" * 16, "algorithm": "ed25519", "public_key_hex": self.pub}]},
        )
        r = run_export("--db", self.db, "--out", self.out("lying"), "--sessions", SYNTHETIC_SESSION, "--keys", lying)
        self.assertEqual(r.returncode, 2)
        self.assertIn("does not re-derive", r.stderr)
        self.assertFalse(os.path.exists(self.out("lying")))

    def test_secret_material_inside_a_keys_json_entry_is_still_refused(self):
        leak = self.key_file("wrapped-leak.json", {"keys": [self.cs["test_key"]]})
        r = run_export("--db", self.db, "--out", self.out("wrapped"), "--sessions", SYNTHETIC_SESSION, "--keys", leak)
        self.assertEqual(r.returncode, 2)
        self.assertIn("PUBLIC key files only", r.stderr)
        self.assertFalse(os.path.exists(self.out("wrapped")))

    def test_raw_binary_key_is_refused_and_the_message_names_both_forms(self):
        path = os.path.join(self.tmp, "raw.bin")
        with open(path, "wb") as f:
            f.write(bytes.fromhex(self.pub))
        r = run_export("--db", self.db, "--out", self.out("raw"), "--sessions", SYNTHETIC_SESSION, "--keys", path)
        self.assertEqual(r.returncode, 2)
        self.assertIn("64 hex characters", r.stderr)
        self.assertIn("keys.json", r.stderr)
        self.assertIn("Raw 32-byte binary is not accepted", r.stderr)
        self.assertFalse(os.path.exists(self.out("raw")))

    def test_an_empty_keys_list_is_refused(self):
        empty = self.key_file("empty.json", {"keys": []})
        r = run_export("--db", self.db, "--out", self.out("empty"), "--sessions", SYNTHETIC_SESSION, "--keys", empty)
        self.assertEqual(r.returncode, 2)
        self.assertIn("at least one key", r.stderr)

    # ---- without --keys, nothing changes ------------------------------------

    def test_without_keys_flag_no_keys_json_and_no_manifest_pointer(self):
        out = self.out("plain")
        r = run_export("--db", self.db, "--out", out, "--sessions", SYNTHETIC_SESSION)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse(os.path.exists(os.path.join(out, "keys.json")))
        with open(os.path.join(out, "manifest.json")) as f:
            self.assertNotIn("keys", json.load(f))
        self.assertIn("keys.json: not produced", r.stdout)


# --- artifact bodies (--artifacts) -----------------------------------------


ARTIFACTS_SCHEMA = """
CREATE TABLE artifacts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  artifact_id TEXT NOT NULL,
  artifact_type TEXT NOT NULL,
  artifact_content TEXT NOT NULL,
  artifact_hash TEXT NOT NULL,
  session_id TEXT NOT NULL,
  created_at_ns INTEGER NOT NULL,
  UNIQUE(artifact_id, artifact_hash)
);
"""


def add_artifact(conn, artifact_id, artifact_hash, content, session_id=SYNTHETIC_SESSION):
    conn.execute(
        "INSERT INTO artifacts (artifact_id, artifact_type, artifact_content, artifact_hash, session_id,"
        " created_at_ns) VALUES (?, 'observation', ?, ?, ?, 1)",
        (artifact_id, content, artifact_hash, session_id),
    )


class ArtifactBodies(unittest.TestCase):
    """--artifacts: bodies are carried as the exact bytes the artifact_hash
    commits to, coverage is honest per entry, and the default (no-flag)
    export is untouched."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="docket-export-artifacts-")
        self.db = os.path.join(self.tmp, "snapshot.db")
        build_fixture_db(self.db)
        # The synthetic session's artifact_hash values are sha256(b"body-<i>"),
        # so real matching bodies exist. Store bodies 0,2,4 as plain TEXT and
        # 1 under the daemon's base64 envelope; leave 3 with no body row.
        conn = sqlite3.connect(self.db)
        conn.executescript(ARTIFACTS_SCHEMA)
        import base64 as b64
        for i in (0, 2, 4):
            add_artifact(conn, "obs:synthetic:%04d" % i, sha256_hex(b"body-%d" % i), "body-%d" % i)
        add_artifact(conn, "obs:synthetic:0001", sha256_hex(b"body-1"),
                     "base64:" + b64.b64encode(b"body-1").decode("ascii"))
        conn.commit()
        conn.close()
        self.db_sha = sha256_file(self.db)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def out(self, name):
        return os.path.join(self.tmp, name)

    def test_gate_bodies_carried_verifier_grades_binding_verdict_unchanged(self):
        out = self.out("bundle")
        r = run_export("--db", self.db, "--out", out, "--sessions", SYNTHETIC_SESSION, "--artifacts")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("bodies: 4/5 entries have carried bodies; hash-only sequences: 3", r.stdout)
        self.assertIn("artifact bodies carried: 4 distinct artifact_hash file(s)", r.stdout)
        self.assertEqual(sha256_file(self.db), self.db_sha)

        # The carried files are the exact preimages, raw bytes on disk —
        # the base64 envelope is unwrapped, never carried.
        for i in (0, 1, 2, 4):
            path = os.path.join(out, "artifacts", sha256_hex(b"body-%d" % i))
            with open(path, "rb") as f:
                self.assertEqual(f.read(), b"body-%d" % i)
        self.assertFalse(os.path.exists(os.path.join(out, "artifacts", sha256_hex(b"body-3"))))

        code, text, report = verify(out)
        self.assertEqual(code, 3, text)  # verdict identical to a hash-only export
        s = session_report(report, SYNTHETIC_SESSION)
        self.assertEqual(s["artifact_binding"]["status"], "verified")
        cov = s["artifact_coverage"]
        self.assertEqual((cov["entry_count"], cov["entries_with_body"]), (5, 4))
        self.assertEqual(cov["hash_only_sequences"], [3])
        self.assertIn("artifact_binding       VERIFIED", text)
        self.assertIn("4/5 entries have carried bodies", text)

    def test_default_export_is_unchanged_no_artifacts_key_no_directory(self):
        out = self.out("plain")
        r = run_export("--db", self.db, "--out", out, "--sessions", SYNTHETIC_SESSION)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(out, "manifest.json")) as f:
            manifest = json.load(f)
        self.assertNotIn("artifacts", manifest)
        self.assertEqual(sorted(os.listdir(out)), ["manifest.json", "sessions"])
        code, _, report = verify(out)
        self.assertEqual(code, 3)
        s = session_report(report, SYNTHETIC_SESSION)
        self.assertNotIn("artifact_binding", s)
        self.assertNotIn("artifact_coverage", s)

    def test_artifacts_flag_without_the_table_is_a_named_error(self):
        db = os.path.join(self.tmp, "notable.db")
        build_fixture_db(db)  # no artifacts table
        r = run_export("--db", db, "--out", self.out("nt"), "--sessions", SYNTHETIC_SESSION, "--artifacts")
        self.assertEqual(r.returncode, 2)
        self.assertIn("'artifacts' does not exist", r.stderr)
        self.assertIn("export without --artifacts", r.stderr)
        self.assertFalse(os.path.exists(self.out("nt")))

    def test_mismatched_stored_body_exports_as_is_and_the_verifier_fails_it(self):
        # The store lies: a body that does not hash to its artifact_hash.
        # The exporter must ship it unchanged; the JUDGE fails the bundle.
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM artifacts WHERE artifact_id = 'obs:synthetic:0000'")
        add_artifact(conn, "obs:synthetic:0000", sha256_hex(b"body-0"), "not what was hashed")
        conn.commit()
        conn.close()
        out = self.out("lying")
        r = run_export("--db", self.db, "--out", out, "--sessions", SYNTHETIC_SESSION, "--artifacts")
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(out, "artifacts", sha256_hex(b"body-0")), "rb") as f:
            self.assertEqual(f.read(), b"not what was hashed")
        code, text, report = verify(out)
        self.assertEqual(code, 1, text)
        s = session_report(report, SYNTHETIC_SESSION)
        self.assertEqual(s["artifact_binding"]["status"], "failed")
        self.assertIn("sequence 0", s["artifact_binding"]["failure"])
        self.assertEqual(report["verdict"], "failed")

    def test_undecodable_base64_envelope_is_an_export_error(self):
        conn = sqlite3.connect(self.db)
        conn.execute("DELETE FROM artifacts WHERE artifact_id = 'obs:synthetic:0001'")
        add_artifact(conn, "obs:synthetic:0001", sha256_hex(b"body-1"), "base64:!!not-base64!!")
        conn.commit()
        conn.close()
        r = run_export("--db", self.db, "--out", self.out("bad"), "--sessions", SYNTHETIC_SESSION, "--artifacts")
        self.assertEqual(r.returncode, 2)
        self.assertIn("claims base64 but does not decode", r.stderr)
        self.assertFalse(os.path.exists(self.out("bad")))


if __name__ == "__main__":
    unittest.main()


# --- redacted export (--redacted) -------------------------------------------


# Real shapes, exactly as a device would emit them. Bodies 0 and 2 carry
# credentials; 1 and 3 do not; 4 is not text at all (rule 3, fail-closed).
REDACTION_BODIES = [
    b"R24#show running-config\n"
    b"enable secret 5 $1$mERr$b0EjM9pUzYnwGl0Wxq4Ha0\n"
    b"snmp-server community s3cr3tRO RO 99\n",
    b"R24#show ip interface brief\nGigabitEthernet0/0  10.2.13.1  YES manual up  up\n",
    b'{"device":"sw-1","api_key":"abc123","status":"ok"}\n',
    b"pve-lab$ qm list\n 100 DC01 stopped\n 313 onode-b running\n",
    bytes([0x00, 0x01, 0xFF, 0xFE]) + b"OK",
]
SECRETS_IN_BODIES = [b"$1$mERr$b0EjM9pUzYnwGl0Wxq4Ha0", b"s3cr3tRO", b"abc123"]
CLEAN_BODY_INDEXES = [1, 3]
WITHHELD_BODY_INDEXES = [0, 2, 4]


def build_redaction_db(path):
    """A snapshot whose synthetic session carries REDACTION_BODIES, each body
    stored so it hashes to its entry's artifact_hash."""
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.executescript(ARTIFACTS_SCHEMA)
    entries, head = synthetic_session(len(REDACTION_BODIES), bodies=REDACTION_BODIES)
    for f, hh, mac in entries:
        insert_entry(conn, f, hh, mac)
    insert_head(conn, head)
    import base64 as b64
    for i, body in enumerate(REDACTION_BODIES):
        try:
            content = body.decode("utf-8")
        except UnicodeDecodeError:
            content = "base64:" + b64.b64encode(body).decode("ascii")
        add_artifact(conn, "obs:synthetic:%04d" % i, sha256_hex(body), content)
    conn.commit()
    conn.close()


class RedactedExport(unittest.TestCase):
    """--redacted: entries whose body matches export hash-only, the bytes
    never leave, and the verifier reaches the same verdicts it reached on the
    unredacted export."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="docket-export-redacted-")
        self.db = os.path.join(self.tmp, "snapshot.db")
        build_redaction_db(self.db)
        self.db_sha = sha256_file(self.db)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def out(self, name):
        return os.path.join(self.tmp, name)

    def export(self, name, *extra):
        out = self.out(name)
        r = run_export("--db", self.db, "--out", out, "--sessions", SYNTHETIC_SESSION, "--artifacts", *extra)
        self.assertEqual(r.returncode, 0, r.stderr)
        return out, r.stdout

    def test_secret_bearing_bodies_are_withheld_and_clean_ones_are_carried(self):
        out, stdout = self.export("redacted", "--redacted")

        for i in CLEAN_BODY_INDEXES:
            path = os.path.join(out, "artifacts", sha256_hex(REDACTION_BODIES[i]))
            self.assertTrue(os.path.exists(path), "a clean body was withheld: %d" % i)
            with open(path, "rb") as f:
                self.assertEqual(f.read(), REDACTION_BODIES[i])
        for i in WITHHELD_BODY_INDEXES:
            path = os.path.join(out, "artifacts", sha256_hex(REDACTION_BODIES[i]))
            self.assertFalse(os.path.exists(path), "a secret-bearing body was exported: %d" % i)

        # Not one secret byte anywhere under --out.
        for root, _dirs, files in os.walk(out):
            for name in files:
                with open(os.path.join(root, name), "rb") as f:
                    blob = f.read()
                for secret in SECRETS_IN_BODIES:
                    self.assertNotIn(secret, blob, "%s leaked %r" % (name, secret))

        self.assertIn("3 of 5 distinct bodies withheld", stdout)
        self.assertEqual(sha256_file(self.db), self.db_sha)

    def test_manifest_records_the_policy_and_every_withheld_entry(self):
        out, _ = self.export("manifest", "--redacted")
        with open(os.path.join(out, "manifest.json")) as f:
            manifest = json.load(f)
        red = manifest["redaction"]
        self.assertEqual(red["policy"], "docket-mask-v1")
        self.assertEqual(red["entries_withheld"], 3)
        self.assertEqual(len(red["withheld"]), 3)
        by_hash = {w["artifact_hash"]: w for w in red["withheld"]}
        for i in WITHHELD_BODY_INDEXES:
            w = by_hash[sha256_hex(REDACTION_BODIES[i])]
            self.assertEqual(w["bytes"], len(REDACTION_BODIES[i]))
        # The non-text body was withheld by the fail-closed rule, not by a
        # recognized secret shape, and the manifest says which.
        self.assertTrue(by_hash[sha256_hex(REDACTION_BODIES[4])]["unclassifiable"])
        self.assertFalse(by_hash[sha256_hex(REDACTION_BODIES[0])]["unclassifiable"])
        # Withheld hashes are NOT listed as carried artifacts.
        carried = {a["artifact_hash"] for a in manifest["artifacts"]}
        for i in WITHHELD_BODY_INDEXES:
            self.assertNotIn(sha256_hex(REDACTION_BODIES[i]), carried)

    def test_gate_the_verifier_reaches_the_same_verdicts_as_the_unredacted_export(self):
        """The gate. Real virp-verify on both exports of the same snapshot:
        the per-session verdicts must be identical. If one moves, that is a
        bug in the exporter, never a reason to touch the verifier."""
        plain, _ = self.export("plain")
        redacted, _ = self.export("gate", "--redacted")

        code_p, text_p, rep_p = verify(plain)
        code_r, text_r, rep_r = verify(redacted)

        self.assertEqual(
            {s["session_id"]: s["verdict"] for s in rep_p["sessions"]},
            {s["session_id"]: s["verdict"] for s in rep_r["sessions"]},
            "a per-session verdict moved under --redacted",
        )
        self.assertEqual(rep_p["verdict"], rep_r["verdict"])
        self.assertEqual(code_p, code_r)

        # Binding still VERIFIED: the bodies that DID travel still hash to
        # their entries, and the withheld ones are simply not carried.
        s_r = session_report(rep_r, SYNTHETIC_SESSION)
        self.assertEqual(s_r["artifact_binding"]["status"], "verified")
        cov = s_r["artifact_coverage"]
        self.assertEqual((cov["entry_count"], cov["entries_with_body"]), (5, 2))
        self.assertEqual(cov["hash_only_sequences"], WITHHELD_BODY_INDEXES)

        # And the examiner is told that hash-only HERE was a choice — with
        # the count RECOMPUTED from the bundle, and the policy name flagged
        # as the unsigned claim it is.
        self.assertIn("redaction: docket-mask-v1 (declared, unsigned), 3 withheld (recomputed)", text_r)
        self.assertIn("policy name above is a CLAIM", text_r)
        self.assertNotIn("INCONSISTENT", text_r)
        self.assertNotIn("redaction:", text_p)

    def test_a_tampered_manifest_count_is_recomputed_and_flagged(self):
        """The redaction block is metadata: nothing hashes it and nothing
        signs it. The verifier must recompute the count from the bundle's own
        hash-only entries and say so when the manifest disagrees — and it
        must not move a verdict either way."""
        out, _ = self.export("tampered", "--redacted")
        mpath = os.path.join(out, "manifest.json")
        with open(mpath) as f:
            manifest = json.load(f)
        honest_code, honest_text, honest_report = verify(out)
        self.assertIn("3 withheld (recomputed)", honest_text)
        self.assertNotIn("INCONSISTENT", honest_text)

        # (a) Inflated count: claim 99 withheld, carry the same bundle.
        manifest["redaction"]["entries_withheld"] = 99
        with open(mpath, "w") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
        code, text, report = verify(out)
        self.assertIn("redaction: docket-mask-v1 (declared, unsigned), 3 withheld (recomputed)", text)
        self.assertIn("INCONSISTENT: the manifest declares 99 withheld; the bundle supports 3", text)
        self.assertIn("recomputed number is the one to trust", text)
        self.assertEqual(code, honest_code, "a tampered manifest count moved the exit code")
        self.assertEqual(report["verdict"], honest_report["verdict"])
        self.assertEqual(
            [s["verdict"] for s in report["sessions"]],
            [s["verdict"] for s in honest_report["sessions"]],
            "a tampered manifest count moved a session verdict",
        )

        # (b) A withheld claim about a body the bundle actually carries.
        carried = manifest["artifacts"][0]["artifact_hash"]
        manifest["redaction"]["entries_withheld"] = 4
        manifest["redaction"]["withheld"].append(
            {"artifact_hash": carried, "bytes": 1, "spans_masked": 1, "unclassifiable": False}
        )
        with open(mpath, "w") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
        code, text, _ = verify(out)
        self.assertIn("3 withheld (recomputed)", text)  # the false claim does NOT count
        self.assertIn("named as withheld but their bodies ARE carried", text)
        self.assertIn(carried, text)
        self.assertEqual(code, honest_code)

        # (c) A withheld claim about a hash no entry in this bundle mentions.
        ghost = "f" * 64
        manifest["redaction"]["withheld"] = [
            {"artifact_hash": ghost, "bytes": 1, "spans_masked": 1, "unclassifiable": False}
        ]
        manifest["redaction"]["entries_withheld"] = 1
        with open(mpath, "w") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
        code, text, _ = verify(out)
        self.assertIn("0 withheld (recomputed)", text)
        self.assertIn("no entry in this bundle references them", text)
        self.assertIn(ghost, text)
        self.assertEqual(code, honest_code)

    def test_the_policy_name_is_repeated_never_verified(self):
        """A manifest can name any policy it likes. The verifier says which
        name was claimed and marks it unsigned; it never asserts the patterns
        that name implies actually ran."""
        out, _ = self.export("claimed", "--redacted")
        mpath = os.path.join(out, "manifest.json")
        with open(mpath) as f:
            manifest = json.load(f)
        manifest["redaction"]["policy"] = "not-a-real-policy-v9"
        with open(mpath, "w") as f:
            json.dump(manifest, f, indent=2, sort_keys=True)
        code, text, _ = verify(out)
        self.assertIn("redaction: not-a-real-policy-v9 (declared, unsigned), 3 withheld (recomputed)", text)
        self.assertIn("nothing in a bundle can prove which patterns ran", text)
        self.assertEqual(code, 3)

    def test_redacted_without_artifacts_is_a_named_error(self):
        r = run_export("--db", self.db, "--out", self.out("noart"), "--sessions", SYNTHETIC_SESSION, "--redacted")
        self.assertEqual(r.returncode, 2)
        self.assertIn("a hash-only bundle is already body-free", r.stderr)
        self.assertFalse(os.path.exists(self.out("noart")))

    def test_a_missing_pattern_table_fails_before_anything_is_written(self):
        r = run_export(
            "--db", self.db, "--out", self.out("nopol"), "--sessions", SYNTHETIC_SESSION,
            "--artifacts", "--redacted",
            env={"DOCKET_MASK_PATTERNS": os.path.join(self.tmp, "no-such-table.json")},
        )
        self.assertEqual(r.returncode, 2)
        self.assertIn("cannot load the masking policy", r.stderr)
        self.assertFalse(os.path.exists(self.out("nopol")))

    def test_default_export_carries_everything_and_has_no_redaction_block(self):
        out, _ = self.export("full")
        with open(os.path.join(out, "manifest.json")) as f:
            manifest = json.load(f)
        self.assertNotIn("redaction", manifest)
        self.assertEqual(len(manifest["artifacts"]), 5)


# --- the reference-bundle gate ---------------------------------------------


# The two reference bundles this session was gated against, with the snapshot
# each was exported from. They live outside the repo (they are evidence, not
# fixtures), so these tests SKIP when the laptop does not have them rather
# than failing on a machine that never had them.
REFERENCE_GATES = [
    ("313-human", os.path.expanduser("<reference-bundles>/case-a/bundle"),
     os.path.expanduser("<reference-bundles>/case-a/snapshot.db")),
    ("fortigate-authority", os.path.expanduser("<reference-bundles>/case-b/bundle"),
     os.path.expanduser("<reference-bundles>/case-b/snapshot.db")),
]


class ReferenceBundleGate(unittest.TestCase):
    """The gate: a --redacted export of a REAL bundle's sessions must reach
    the same verdicts, from the real virp-verify, as the unredacted export of
    the same sessions. If a verdict moves, that is a bug in the exporter and
    never a reason to touch the verifier."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="docket-export-refgate-")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _export(self, name, db, sids, tag, ref, *extra):
        out = os.path.join(self.tmp, "%s-%s" % (name, tag))
        r = run_export("--db", db, "--out", out, "--sessions", *sids, "--artifacts", *extra)
        self.assertEqual(r.returncode, 0, r.stderr)
        # Both exports get the reference bundle's own keys, so the signature
        # tiers are the real ones and the comparison is not made trivial by
        # everything being KEYLESS.
        keys = os.path.join(ref, "keys.json")
        if os.path.exists(keys):
            shutil.copy(keys, os.path.join(out, "keys.json"))
            with open(os.path.join(out, "manifest.json")) as f:
                m = json.load(f)
            m["keys"] = "keys.json"
            with open(os.path.join(out, "manifest.json"), "w") as f:
                json.dump(m, f, indent=2, sort_keys=True)
        return out, r.stdout

    def test_gate_redacted_export_of_the_reference_bundles_moves_no_verdict(self):
        ran = 0
        for name, ref, db in REFERENCE_GATES:
            if not (os.path.isdir(ref) and os.path.exists(db)):
                continue
            ran += 1
            with self.subTest(bundle=name):
                with open(os.path.join(ref, "manifest.json")) as f:
                    sids = [s["session_id"] for s in json.load(f)["sessions"]]
                plain, _ = self._export(name, db, sids, "plain", ref)
                redacted, out = self._export(name, db, sids, "redacted", ref, "--redacted")

                code_p, _, rep_p = verify(plain)
                code_r, text_r, rep_r = verify(redacted)

                self.assertEqual(
                    {s["session_id"]: s["verdict"] for s in rep_p["sessions"]},
                    {s["session_id"]: s["verdict"] for s in rep_r["sessions"]},
                    "a per-session verdict moved under --redacted",
                )
                self.assertEqual(rep_p["verdict"], rep_r["verdict"])
                self.assertEqual(code_p, code_r)

                # Stronger than the gate asks for: no PROPERTY moved either.
                def props(rep):
                    return {(s["session_id"], p["name"]): p["status"] for s in rep["sessions"] for p in s["properties"]}

                self.assertEqual(props(rep_p), props(rep_r), "a property status moved under --redacted")

                # Every withheld body is absent, whole, from the export.
                with open(os.path.join(redacted, "manifest.json")) as f:
                    red = json.load(f)["redaction"]
                bodies = []
                for w in red["withheld"]:
                    self.assertFalse(os.path.exists(os.path.join(redacted, "artifacts", w["artifact_hash"])))
                    with open(os.path.join(plain, "artifacts", w["artifact_hash"]), "rb") as f:
                        bodies.append(f.read())
                for root, _dirs, files in os.walk(redacted):
                    for fn in files:
                        with open(os.path.join(root, fn), "rb") as f:
                            blob = f.read()
                        for b in bodies:
                            self.assertNotIn(b, blob, "a withheld body survived in %s" % fn)

                if red["withheld"]:
                    self.assertIn(
                        "redaction: docket-mask-v1 (declared, unsigned), %d withheld (recomputed)"
                        % len(red["withheld"]),
                        text_r,
                    )
                    self.assertNotIn("INCONSISTENT", text_r)
        if ran == 0:
            self.skipTest("no reference bundle + source snapshot pair present on this machine")


# --- referenced artifacts (--referenced-artifacts) --------------------------
#
# The files a camera record CITES by digest: the segment video, and the
# validator's own output about it. They have never travelled in a bundle, and
# the 2026-09-04 tamper pass measured what that costs — a byte flipped in
# either survived both verifiers with byte-identical output.

REF_CAMERA = "cam-ref"
REF_SESSION = SYNTHETIC_SESSION


def camera_body(seq, video, validation, prev=None, leaf=b""):
    """A camera_segment/5 body citing exactly the two artifacts this feature
    carries. Canonical single-line JSON, the way the driver serializes."""
    body = {
        "byte_len": len(video),
        "camera_id": REF_CAMERA,
        "capture_end_utc_ns": 1_787_000_000_000_000_000 + (seq + 1) * 6_000_000_000,
        "capture_policy": {"jitter_s": 1.5, "max_unexplained_gap_s": 0.0, "nominal_segment_s": 6.0},
        "capture_start_utc_ns": 1_787_000_000_000_000_000 + seq * 6_000_000_000,
        "device": REF_CAMERA,
        "duration_s": 6.0,
        "encoder": "copy",
        "gap": None,
        "mode": "live",
        "prev_segment_sha256": prev,
        "producer_key_id": "0" * 32,
        "schema": "camera_segment/6",
        "segment_seq": seq,
        "segment_sha256": sha256_hex(video),
        "sensor_signature": {
            "asserted_first_frame": "Fri 2026-09-04 00:00:00 GMT",
            "asserted_last_frame": "Fri 2026-09-04 00:00:06 GMT",
            "device_chain": {
                "anchor": "intermediate_pinned",
                "anchor_sha256": sha256_hex(b"anchor"),
                "chain_to_anchor_verified": True,
                "leaf_not_after": "2033-10-22T20:22:29Z",
                "leaf_serial_matches_device": True,
                "leaf_sha256": sha256_hex(leaf),
            },
            "device_firmware": "12.5.68",
            "device_serial": "TESTSERIAL01",
            "gops_invalid": 0,
            "gops_unsigned": 0,
            "gops_valid": 4,
            "gops_valid_with_missing": 0,
            "public_key": "VALID",
            "public_key_pin": "MATCH",
            "sensor_key_sha256": sha256_hex(b"sensor-key"),
            "validator": {"name": "signed-video-framework", "version": "2.3.10"},
            "validator_output_sha256": sha256_hex(validation),
            "vendor": "axis",
            "verdict": "VALID",
        },
        "time_source": "host-clock",
    }
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def build_referenced_db(path, bodies):
    conn = sqlite3.connect(path)
    conn.executescript(SCHEMA)
    conn.executescript(ARTIFACTS_SCHEMA)
    entries, head = synthetic_session(len(bodies), bodies=bodies)
    for f, hh, mac in entries:
        insert_entry(conn, f, hh, mac)
    insert_head(conn, head)
    for i, body in enumerate(bodies):
        add_artifact(conn, "obs:synthetic:%04d" % i, sha256_hex(body), body.decode("utf-8"))
    conn.commit()
    conn.close()


class ReferencedArtifacts(unittest.TestCase):
    """--referenced-artifacts: the cited files are carried under the digest
    the RECORD cites, verbatim and unchecked, and a cited artifact that
    cannot be found is listed present=false rather than omitted."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="docket-export-referenced-")
        self.db = os.path.join(self.tmp, "snapshot.db")
        self.outbox = os.path.join(self.tmp, "outbox")
        os.makedirs(self.outbox)
        self.videos = [b"video-%d" % i + b"\x00" * 32 for i in range(3)]
        self.validations = [b"VIDEO IS VALID!\nsegment %d\n" % i for i in range(3)]
        # One leaf certificate for the whole camera, as in reality: the same
        # device signs every segment, so every record cites the same DER.
        self.leaf = b"\x30\x82DER-leaf-certificate-bytes"
        bodies, prev = [], None
        for i, (v, val) in enumerate(zip(self.videos, self.validations)):
            bodies.append(camera_body(i, v, val, prev, leaf=self.leaf))
            prev = sha256_hex(v)
        build_referenced_db(self.db, bodies)
        self.db_sha = sha256_file(self.db)
        for i, (v, val) in enumerate(zip(self.videos, self.validations)):
            self._write("%s.%06d.%s.mp4" % (REF_CAMERA, i, sha256_hex(v)), v)
            self._write("%s.%06d.%s.validation.txt" % (REF_CAMERA, i, sha256_hex(v)), val)
            self._write("%s.%06d.%s.leaf.der" % (REF_CAMERA, i, sha256_hex(v)), self.leaf)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _write(self, name, data, where=None):
        with open(os.path.join(where or self.outbox, name), "wb") as f:
            f.write(data)

    def _restore(self, path, mode):
        """chmod back, tolerating tearDown having already removed the tree
        (addCleanup runs after tearDown, not before)."""
        self.addCleanup(lambda: os.path.exists(path) and os.chmod(path, mode))

    def out(self, name):
        return os.path.join(self.tmp, name)

    def export(self, name, *extra, dirs=None):
        out = self.out(name)
        args = ["--db", self.db, "--out", out, "--sessions", REF_SESSION, "--artifacts"]
        for d in dirs if dirs is not None else [self.outbox]:
            args += ["--referenced-artifacts", d]
        r = run_export(*args, *extra)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(out, "manifest.json")) as f:
            return out, r.stdout, json.load(f)

    # --- carriage ---------------------------------------------------------

    def test_every_cited_artifact_is_carried_and_listed(self):
        out, stdout, manifest = self.export("bundle")
        ref = manifest["referenced_artifacts"]
        self.assertEqual(len(ref), 7)   # 3 segments + 3 validator outputs + 1 shared leaf
        self.assertTrue(all(r["present"] for r in ref))
        self.assertIn("referenced artifacts: 7 cited by the carried camera records; 7 carried, 0 not found", stdout)
        self.assertEqual(sha256_file(self.db), self.db_sha)
        for v, val in zip(self.videos, self.validations):
            for data in (v, val):
                path = os.path.join(out, "artifacts", sha256_hex(data))
                with open(path, "rb") as f:
                    self.assertEqual(f.read(), data)

    def test_cited_by_names_the_record_and_the_field_path(self):
        _, _, manifest = self.export("bundle")
        by_digest = {r["sha256"]: r for r in manifest["referenced_artifacts"]}
        seg = by_digest[sha256_hex(self.videos[1])]["cited_by"]
        self.assertEqual(seg, [{"session_id": REF_SESSION, "segment_seq": 1, "field": "segment_sha256"}])
        val = by_digest[sha256_hex(self.validations[1])]["cited_by"]
        self.assertEqual(
            val,
            [{"session_id": REF_SESSION, "segment_seq": 1,
              "field": "sensor_signature.validator_output_sha256"}],
        )

    def test_the_content_addressed_layout_is_searched_too(self):
        alt = os.path.join(self.tmp, "cas")
        os.makedirs(alt)
        for v in self.videos:
            self._write("%s.mp4" % sha256_hex(v), v, where=alt)
        for val in self.validations:
            self._write("%s.txt" % sha256_hex(val), val, where=alt)
        self._write("%s.der" % sha256_hex(self.leaf), self.leaf, where=alt)
        _, _, manifest = self.export("cas-bundle", dirs=[alt])
        self.assertTrue(all(r["present"] for r in manifest["referenced_artifacts"]))

    # --- a tampered file is CARRIED, not hidden ---------------------------

    def test_an_altered_file_is_carried_under_the_cited_digest(self):
        """The crux. Naming the file by its OWN hash would file altered bytes
        under a name nobody looks up and turn a tamper into an absence."""
        cited = sha256_hex(self.videos[1])
        target = os.path.join(self.outbox, "%s.%06d.%s.mp4" % (REF_CAMERA, 1, cited))
        altered = bytearray(self.videos[1])
        altered[0] ^= 0x01
        self._write(os.path.basename(target), bytes(altered))

        out, _, manifest = self.export("tampered")
        entry = next(r for r in manifest["referenced_artifacts"] if r["sha256"] == cited)
        self.assertTrue(entry["present"])
        self.assertEqual(entry["path"], "artifacts/" + cited)
        carried = os.path.join(out, "artifacts", cited)
        with open(carried, "rb") as f:
            data = f.read()
        self.assertEqual(data, bytes(altered))
        # named by what the RECORD cites, and it does not hash to it: exactly
        # the case the verifier has to grade FAILED
        self.assertNotEqual(sha256_hex(data), cited)
        self.assertFalse(os.path.exists(os.path.join(out, "artifacts", sha256_hex(bytes(altered)))))

    # --- absent is listed, never omitted ---------------------------------

    def test_a_missing_artifact_is_listed_present_false(self):
        os.remove(os.path.join(
            self.outbox, "%s.%06d.%s.validation.txt" % (REF_CAMERA, 2, sha256_hex(self.videos[2]))))
        out, stdout, manifest = self.export("partial")
        ref = manifest["referenced_artifacts"]
        self.assertEqual(len(ref), 7)                  # still seven: nothing omitted
        missing = [r for r in ref if not r["present"]]
        self.assertEqual(len(missing), 1)
        self.assertEqual(missing[0]["sha256"], sha256_hex(self.validations[2]))
        self.assertNotIn("path", missing[0])
        self.assertIn("6 carried, 1 not found", stdout)
        self.assertIn("NOT FOUND", stdout)
        self.assertFalse(os.path.exists(
            os.path.join(out, "artifacts", sha256_hex(self.validations[2]))))

    def test_an_empty_search_directory_lists_every_citation_absent(self):
        empty = os.path.join(self.tmp, "empty")
        os.makedirs(empty)
        _, stdout, manifest = self.export("none", dirs=[empty])
        ref = manifest["referenced_artifacts"]
        self.assertEqual(len(ref), 7)
        self.assertFalse(any(r["present"] for r in ref))
        self.assertIn("0 carried, 7 not found", stdout)

    # --- inaccessible is not absent --------------------------------------

    def test_an_unreadable_directory_is_eacces_never_not_found(self):
        """chmod 000. glob() cannot tell an unreadable directory from an
        empty one, so the exporter used to write a manifest declaring
        every artifact missing after never being allowed to look."""
        os.chmod(self.outbox, 0o000)
        self._restore(self.outbox, 0o700)
        if os.access(self.outbox, os.R_OK):
            self.skipTest("running as root: chmod 000 does not deny access")
        _, stdout, manifest = self.export("blocked")
        ref = manifest["referenced_artifacts"]
        self.assertTrue(all(not r["present"] for r in ref))
        self.assertTrue(all(r["reason"] == "eacces" for r in ref), ref)
        self.assertIn("INACCESSIBLE", stdout)
        self.assertIn("their absence from this bundle is not evidence", stdout)

    def test_an_unreadable_file_is_eacces_not_not_found(self):
        target = os.path.join(
            self.outbox, "%s.%06d.%s.mp4" % (REF_CAMERA, 1, sha256_hex(self.videos[1])))
        os.chmod(target, 0o000)
        self._restore(target, 0o600)
        if os.access(target, os.R_OK):
            self.skipTest("running as root: chmod 000 does not deny access")
        _, _, manifest = self.export("blocked-file")
        row = next(r for r in manifest["referenced_artifacts"]
                   if r["sha256"] == sha256_hex(self.videos[1]))
        self.assertFalse(row["present"])
        self.assertEqual(row["reason"], "eacces")

    def test_a_genuinely_missing_file_still_reads_not_found(self):
        """The other half: the distinction is only worth having if the
        ordinary absence keeps its own, weaker, word."""
        os.remove(os.path.join(
            self.outbox, "%s.%06d.%s.validation.txt" % (REF_CAMERA, 2, sha256_hex(self.videos[2]))))
        _, stdout, manifest = self.export("plain-missing")
        row = next(r for r in manifest["referenced_artifacts"]
                   if r["sha256"] == sha256_hex(self.validations[2]))
        self.assertEqual(row["reason"], "not_found")
        self.assertIn("NOT FOUND", stdout)
        self.assertIn("0 INACCESSIBLE", stdout)     # counted, none of them
        self.assertNotIn("    INACCESSIBLE", stdout)

    # --- the flag's own edges --------------------------------------------

    def test_default_export_carries_no_referenced_array(self):
        out = self.out("plain")
        r = run_export("--db", self.db, "--out", out, "--sessions", REF_SESSION, "--artifacts")
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(os.path.join(out, "manifest.json")) as f:
            manifest = json.load(f)
        self.assertNotIn("referenced_artifacts", manifest)

    def test_without_artifacts_it_is_a_named_error(self):
        r = run_export("--db", self.db, "--out", self.out("no-bodies"), "--sessions", REF_SESSION,
                       "--referenced-artifacts", self.outbox)
        self.assertEqual(r.returncode, 2)
        self.assertIn("no bodies to read the citations out of", r.stderr)

    def test_a_missing_search_directory_is_a_named_error(self):
        r = run_export("--db", self.db, "--out", self.out("no-dir"), "--sessions", REF_SESSION,
                       "--artifacts", "--referenced-artifacts", os.path.join(self.tmp, "nope"))
        self.assertEqual(r.returncode, 2)
        self.assertIn("not a directory", r.stderr)

    # --- citation extraction ---------------------------------------------

    def test_cited_digests_reads_all_three_fields_and_only_camera_records(self):
        body = json.loads(camera_body(0, self.videos[0], self.validations[0],
                                      leaf=self.leaf))
        cited = export_bundle.cited_digests(body)
        self.assertEqual(
            cited,
            {"segment_sha256": sha256_hex(self.videos[0]),
             "sensor_signature.validator_output_sha256": sha256_hex(self.validations[0]),
             "sensor_signature.device_chain.leaf_sha256": sha256_hex(self.leaf)},
        )
        self.assertEqual(export_bundle.cited_digests({"schema": "observation/1"}), {})
        self.assertEqual(export_bundle.cited_digests({}), {})

    def test_a_record_with_no_device_chain_cites_no_leaf(self):
        """/3 and /4 records, and any camera that presents no chain: the
        leaf citation is absent, not null, and nothing looks for a file."""
        body = json.loads(camera_body(0, self.videos[0], self.validations[0]))
        body["sensor_signature"]["device_chain"] = None
        self.assertNotIn("sensor_signature.device_chain.leaf_sha256",
                         export_bundle.cited_digests(body))

    def test_a_non_hex_citation_is_not_acted_on(self):
        body = json.loads(camera_body(0, self.videos[0], self.validations[0],
                                      leaf=self.leaf))
        body["segment_sha256"] = "../../etc/passwd"
        body["sensor_signature"]["validator_output_sha256"] = "NOT-A-DIGEST"
        body["sensor_signature"]["device_chain"]["leaf_sha256"] = "../../../leaf"
        self.assertEqual(export_bundle.cited_digests(body), {})
