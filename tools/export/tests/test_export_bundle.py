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


def synthetic_session(n):
    """A complete n-entry session with correct links/genesis and fake HMACs."""
    entries = []
    prev = genesis_hash(SYNTHETIC_SESSION)
    for i in range(n):
        f = {
            "artifact_hash": sha256_hex(b"body-%d" % i),
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


def build_fixture_db(path, d1_columns=False):
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
      chain-signing-v1.json in the D-1 columns.
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
        insert_entry(conn, fields, sha256_hex(canonical_bytes(fields)), "",
                     {"chain_sig": ent["signature_hex"], "chain_sig_key_id": key_id})
        hf = json.loads(hd["message_utf8"])
        insert_head(conn, {"session_id": hf["session_id"], "last_sequence": hf["last_sequence"],
                           "last_entry_hash": hf["last_entry_hash"], "head_hmac": "", "updated_at_ns": 2},
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


def verify(bundle_dir):
    """Run the real verifier. Returns (exit_code, text_stdout, json_report)."""
    exe = find_virp_verify()
    text = subprocess.run([exe, bundle_dir], capture_output=True, text=True)
    js = subprocess.run([exe, "--json", bundle_dir], capture_output=True, text=True)
    assert text.returncode == js.returncode, (text.returncode, js.returncode, js.stderr)
    report = json.loads(js.stdout) if js.stdout.strip().startswith("{") else None
    return text.returncode, text.stdout, report


def session_report(report, session_id):
    return next(s for s in report["sessions"] if s["session_id"] == session_id)


def prop(sreport, name):
    return next(p for p in sreport["properties"] if p["name"] == name)["status"]


def run_export(*args):
    return subprocess.run([sys.executable, EXPORT] + list(args), capture_output=True, text=True)


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

    def test_stdlib_only(self):
        with open(EXPORT) as f:
            src = f.read()
        imports = {line.split()[1] for line in src.splitlines() if line.startswith(("import ", "from "))}
        self.assertEqual(
            imports,
            {"argparse", "base64", "binascii", "datetime", "hashlib", "json", "os", "re", "sqlite3", "sys",
             "urllib.parse"},
        )


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
