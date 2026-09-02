#!/usr/bin/env python3
"""
export_bundle.py — export a Docket evidence bundle (directory form) from a
VIRP chain database snapshot.

    python3 export_bundle.py --db <snapshot.db> --out <bundle-dir> \
        --sessions <id> [<id> ...] [--seal <seal-2026-08.json>] [--artifacts] \
        [--keys <pubfile> [<pubfile> ...]] [--seal-sig <file.minisig>]
    python3 export_bundle.py --db <snapshot.db> --out <bundle-dir> --all-sessions
    python3 export_bundle.py --db <snapshot.db> --list-sessions

What this script is
-------------------
An EXPORTER. It copies chain rows out of the database into the bundle format
that `docket-bundle` 0.1 / `virp-verify` read (DESIGN.md §2 in the Docket
repository). It copies hashes, HMACs and (if the D-1 columns exist)
signatures exactly as stored. It renumbers nothing, fills no gaps, lowercases
nothing, recomputes nothing. Every judgement about the chain — hashes, links,
genesis, contiguity, head commitment, signatures, seal anchoring — is
virp-verify's job. If this script "fixed" anything the bundle would be
worthless as evidence.

Structural sanity only: the expected tables and columns exist; every required
cell is present (not NULL) and of the expected type; hash/HMAC/signature
cells are hex. Anything else is exported as-is for the verifier to grade.

Safety
------
* Python 3 standard library only. No third-party imports, no network.
* The database is opened READ-ONLY through a `file:...?mode=ro&immutable=1`
  URI. `immutable=1` additionally tells SQLite the file will not change
  underneath it, so it takes no locks and creates no `-journal`/`-wal`/`-shm`
  files beside the database. This is correct for a snapshot — which is the
  only thing this script should be pointed at — and still write-safe if it
  is pointed at a live database by mistake (reads may be torn; nothing is
  ever written).
* No PRAGMA that changes the database. `PRAGMA table_info` (read) is used for
  schema discovery; `PRAGMA query_only=ON` is set on the connection as a
  belt-and-braces guard (a connection setting, not a database change).
* Writes go ONLY under `--out`, which must not already exist.

Format facts this script relies on (from DESIGN.md and the fixture bundle)
-------------------------------------------------------------------------
manifest.json   docket_bundle_version "docket-bundle/0.1", chain_format "v1",
                producer, created_at, sessions[{session_id, path}], seal?
sessions/*.json {session_id, entries[...], head?}
  entry         the twelve canonical fields as JSON values (integers as
                numbers), chain_entry_hash, chain_hmac?, signature?
  head          session_id, last_sequence, last_entry_hash, head_hmac?,
                signature?
  signature     {signature_scheme: "ed25519-detached-v1", signing_key_id,
                signature_hex}
seal/<file>     the virp-seal/1 document, byte-for-byte.
seal/<file>.minisig  (--seal-sig only) the detached minisign SIGNATURE over
                the seal document, byte-for-byte, named in the manifest as
                "seal_signature". The signature may travel in the bundle —
                it is a claim the verifier grades. The PUBLIC KEY that
                checks it never travels in the bundle: virp-verify takes it
                out of band (--seal-key) or reports UNVERIFIABLE.
artifacts/<hash>  (--artifacts only) raw artifact-body bytes, one file per
                distinct artifact_hash, named in the manifest as
                {"artifact_hash": "...", "path": "artifacts/..."}. The bytes
                are recovered exactly as the producer hashed them: the
                daemon stores bodies in the `artifacts` table either as
                plain TEXT (hashed as UTF-8) or as "base64:<data>" (hashed
                as the decoded bytes). Decoding that envelope is transport
                unwrapping, not re-encoding — and the verifier recomputes
                SHA-256 over the carried bytes against each entry's
                artifact_hash, so a wrong recovery FAILS rather than
                passing. Entries whose (artifact_id, artifact_hash) pair
                has no body row export hash-only and the summary says so;
                a stored body that does not hash to its column value is
                exported AS STORED for the verifier to fail — fixing it
                here would be judging.
keys.json       produced ONLY with --keys, from PUBLIC key files the operator
                supplies in either form virp-verify --pin also reads: 64 hex
                characters (the raw public key), or a docket keys.json
                object. The key_id is derived from the bytes either way.
                supplies (the chain schema has no table of public keys; the
                D-1 public half lives as a file on the daemon host, so there
                is nothing in a database to export). Without --keys nothing
                changes: no keys.json, no manifest pointer, and the bundle
                verifies as OPERATOR-ATTESTED — the expected outcome for
                every pre-D-1 (Era 2) session. With --keys, entries are
                written deterministically (sorted by key_id, normalized
                encoding) so the same inputs give byte-identical output;
                key_id is DERIVED from the key bytes (sha256-raw-16), never
                copied from a filename or label, and a stated id that does
                not re-derive is an error. A key file containing secret or
                seed material is refused: no private key material enters
                Docket, ever.

Reproducibility: SOURCE_DATE_EPOCH (unix seconds, the reproducible-builds
convention) pins the manifest's created_at so two exports of the same inputs
are byte-identical. Unset, created_at is the wall clock, as before.
canonical_utf8  NOT produced. The database does not store canonical bytes;
                the verifier rebuilds them from the twelve fields. Emitting a
                rebuilt copy would be computing, not exporting.
"""

import argparse
import base64
import binascii
import datetime
import hashlib
import json
import os
import re
import sqlite3
import sys
import urllib.parse

VERSION = "0.1"
BUNDLE_VERSION = "docket-bundle/0.1"
CHAIN_FORMAT = "v1"
SIGNATURE_SCHEME = "ed25519-detached-v1"
SEAL_VERSION = "virp-seal/1"

# --- schema expectations (from src/virp_chain.c in the VIRP tree) ----------

# The twelve canonical fields, in canonical order, with the JSON type each
# must carry in the bundle ("str" or "int").
CANONICAL_FIELDS = [
    ("artifact_hash", "str"),
    ("artifact_hash_alg", "str"),
    ("artifact_id", "str"),
    ("artifact_schema_version", "str"),
    ("artifact_type", "str"),
    ("monotonic_ns", "int"),
    ("previous_entry_hash", "str"),
    ("sequence", "int"),
    ("session_id", "str"),
    ("signer_node_id", "int"),
    ("signer_org_id", "str"),
    ("timestamp_ns", "int"),
]

ENTRIES_TABLE = "chain_entries"
ENTRIES_REQUIRED = [name for name, _ in CANONICAL_FIELDS] + ["chain_entry_hash", "chain_hmac"]
ENTRIES_OPTIONAL = ["chain_sig", "chain_sig_key_id"]  # D-1; absent pre-cut-over

HEADS_TABLE = "chain_heads"
HEADS_REQUIRED = ["session_id", "last_sequence", "last_entry_hash", "head_hmac"]
HEADS_OPTIONAL = ["head_sig", "head_sig_key_id"]  # D-1; absent pre-cut-over

# Only consulted with --artifacts. The table is the daemon's body store;
# a database without it simply cannot carry bodies.
ARTIFACTS_TABLE = "artifacts"
ARTIFACTS_REQUIRED = ["artifact_id", "artifact_hash", "artifact_content"]

# The daemon's binary-body envelope in artifacts.artifact_content.
BASE64_PREFIX = "base64:"

# Cells that must be hex when present. Lengths are NOT enforced and case is
# NOT normalised: well-formedness beyond "is hex" is the verifier's call.
HEX_CELLS = {
    "chain_entry_hash",
    "previous_entry_hash",
    "chain_hmac",
    "last_entry_hash",
    "head_hmac",
    "chain_sig",
    "chain_sig_key_id",
    "head_sig",
    "head_sig_key_id",
}
HEX_RE = re.compile(r"^[0-9A-Fa-f]+$")


class ExportError(Exception):
    """A condition that stops the export. The message is the operator's
    round-trip: it names what was expected and what was found."""


# --- database ---------------------------------------------------------------


def open_readonly(db_path):
    """Open the database read-only and immutable. Never creates the file."""
    if not os.path.isfile(db_path):
        raise ExportError(f"database not found: {db_path}")
    abs_path = os.path.abspath(db_path)
    uri = "file:" + urllib.parse.quote(abs_path, safe="/") + "?mode=ro&immutable=1"
    try:
        conn = sqlite3.connect(uri, uri=True)
        conn.execute("PRAGMA query_only = ON")
        # Touch the schema so an unreadable / non-SQLite file fails here,
        # with the path in the message, rather than deep in the export.
        conn.execute("SELECT name FROM sqlite_master LIMIT 1").fetchall()
    except sqlite3.Error as e:
        raise ExportError(f"cannot open {db_path} read-only: {e}") from e
    return conn


def table_columns(conn, table):
    """Column names of `table`, or None if the table does not exist."""
    rows = conn.execute(f"PRAGMA table_info({table})").fetchall()
    if not rows:
        return None
    return [r[1] for r in rows]


def discover_schema(conn):
    """Confirm the tables/columns this exporter needs. Returns a dict of
    which optional (D-1) columns are present. Raises ExportError naming
    expected vs found on any shortfall."""
    found_tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
    problems = []
    present = {}
    for table, required, optional in (
        (ENTRIES_TABLE, ENTRIES_REQUIRED, ENTRIES_OPTIONAL),
        (HEADS_TABLE, HEADS_REQUIRED, HEADS_OPTIONAL),
    ):
        cols = table_columns(conn, table)
        if cols is None:
            problems.append(f"  table {table!r}: MISSING\n    tables found: {found_tables}")
            continue
        missing = [c for c in required if c not in cols]
        if missing:
            problems.append(
                f"  table {table!r}: missing required column(s) {missing}\n"
                f"    expected: {required}\n"
                f"    found:    {cols}"
            )
        for c in optional:
            present[c] = c in cols
    if problems:
        raise ExportError("schema drift — the snapshot does not match what this exporter expects:\n" + "\n".join(problems))
    # D-1 columns come in pairs; half a pair is drift, not a feature.
    for a, b in (("chain_sig", "chain_sig_key_id"), ("head_sig", "head_sig_key_id")):
        if present[a] != present[b]:
            raise ExportError(f"schema drift — found only one of the D-1 column pair {a!r}/{b!r}")
    return present


def list_sessions(conn):
    """(session_id, entry_count, has_head) for every session, by id."""
    entries = {
        r[0]: r[1]
        for r in conn.execute(f"SELECT session_id, COUNT(*) FROM {ENTRIES_TABLE} GROUP BY session_id")
    }
    heads = {r[0] for r in conn.execute(f"SELECT session_id FROM {HEADS_TABLE}")}
    ids = sorted(set(entries) | heads)
    return [(sid, entries.get(sid, 0), sid in heads) for sid in ids]


# --- cell checks (structural sanity only) ---------------------------------


def check_cell(where, name, value, kind):
    """`kind` is "str", "int" or "hex". Returns the value unchanged."""
    if value is None:
        raise ExportError(f"{where}: column {name!r} is NULL; the bundle format requires a value")
    if kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ExportError(f"{where}: column {name!r} expected INTEGER, found {type(value).__name__} {value!r}")
    else:
        if isinstance(value, bytes):
            raise ExportError(f"{where}: column {name!r} is a BLOB; expected TEXT")
        if not isinstance(value, str):
            raise ExportError(f"{where}: column {name!r} expected TEXT, found {type(value).__name__} {value!r}")
        if kind == "hex" and not HEX_RE.match(value):
            raise ExportError(f"{where}: column {name!r} is not hex: {value!r}")
    return value


def optional_hmac(where, name, value):
    """HMAC columns: NULL means absent (the bundle omits the key). An EMPTY
    string is exported as-is — turning it into "absent" would change the
    verifier's grade from FAILED (malformed) to "nothing attests", which is
    exactly the kind of fix this exporter must not make."""
    if value is None:
        return None
    if value == "":
        return value
    return check_cell(where, name, value, "hex")


def optional_sig(where, name, value):
    """D-1 signature columns: NULL or empty string means unsigned — that is
    the producer's own convention (`head_sig[0] != '\\0'` in virp_chain.c)."""
    if value is None or value == "":
        return None
    return check_cell(where, name, value, "hex")


# --- export -----------------------------------------------------------------


def export_session(conn, session_id, present):
    """Read one session's rows and shape them as a SessionChain object."""
    entry_cols = ENTRIES_REQUIRED + [c for c in ENTRIES_OPTIONAL if present[c]]
    sql = f"SELECT {', '.join(entry_cols)} FROM {ENTRIES_TABLE} WHERE session_id = ? ORDER BY sequence ASC"
    entries = []
    for row in conn.execute(sql, (session_id,)):
        r = dict(zip(entry_cols, row))
        where = f"{ENTRIES_TABLE} session={session_id!r} sequence={r.get('sequence')!r}"
        entry = {}
        for name, kind in CANONICAL_FIELDS:
            entry[name] = check_cell(where, name, r[name], "hex" if name in HEX_CELLS else kind)
        entry["chain_entry_hash"] = check_cell(where, "chain_entry_hash", r["chain_entry_hash"], "hex")
        hmac = optional_hmac(where, "chain_hmac", r["chain_hmac"])
        if hmac is not None:
            entry["chain_hmac"] = hmac
        if present["chain_sig"]:
            sig = optional_sig(where, "chain_sig", r["chain_sig"])
            kid = optional_sig(where, "chain_sig_key_id", r["chain_sig_key_id"])
            if (sig is None) != (kid is None):
                raise ExportError(f"{where}: chain_sig and chain_sig_key_id must both be present or both absent")
            if sig is not None:
                entry["signature"] = {
                    "signature_scheme": SIGNATURE_SCHEME,
                    "signing_key_id": kid,
                    "signature_hex": sig,
                }
        entries.append(entry)

    head_cols = HEADS_REQUIRED + [c for c in HEADS_OPTIONAL if present[c]]
    sql = f"SELECT {', '.join(head_cols)} FROM {HEADS_TABLE} WHERE session_id = ?"
    rows = conn.execute(sql, (session_id,)).fetchall()
    head = None
    if len(rows) > 1:
        raise ExportError(f"{HEADS_TABLE}: {len(rows)} head rows for session {session_id!r}; expected at most 1")
    if rows:
        r = dict(zip(head_cols, rows[0]))
        where = f"{HEADS_TABLE} session={session_id!r}"
        head = {
            "session_id": check_cell(where, "session_id", r["session_id"], "str"),
            "last_sequence": check_cell(where, "last_sequence", r["last_sequence"], "int"),
            "last_entry_hash": check_cell(where, "last_entry_hash", r["last_entry_hash"], "hex"),
        }
        hmac = optional_hmac(where, "head_hmac", r["head_hmac"])
        if hmac is not None:
            head["head_hmac"] = hmac
        if present["head_sig"]:
            sig = optional_sig(where, "head_sig", r["head_sig"])
            kid = optional_sig(where, "head_sig_key_id", r["head_sig_key_id"])
            if (sig is None) != (kid is None):
                raise ExportError(f"{where}: head_sig and head_sig_key_id must both be present or both absent")
            if sig is not None:
                head["signature"] = {
                    "signature_scheme": SIGNATURE_SCHEME,
                    "signing_key_id": kid,
                    "signature_hex": sig,
                }

    if not entries and head is None:
        raise ExportError(f"session {session_id!r}: no entries and no head in the database (use --list-sessions)")

    chain = {"session_id": session_id, "entries": entries}
    if head is not None:
        chain["head"] = head
    return chain


def discover_artifacts_schema(conn):
    """Confirm the artifacts table exists with the columns --artifacts needs."""
    cols = table_columns(conn, ARTIFACTS_TABLE)
    if cols is None:
        found_tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
        raise ExportError(
            f"--artifacts: table {ARTIFACTS_TABLE!r} does not exist in this database, so it carries no bodies\n"
            f"  tables found: {found_tables}\n"
            f"  export without --artifacts for a hash-only bundle"
        )
    missing = [c for c in ARTIFACTS_REQUIRED if c not in cols]
    if missing:
        raise ExportError(
            f"--artifacts: table {ARTIFACTS_TABLE!r} is missing required column(s) {missing}\n"
            f"  expected: {ARTIFACTS_REQUIRED}\n"
            f"  found:    {cols}"
        )


def body_bytes(where, content):
    """The exact bytes the producer hashed into artifact_hash.

    Plain TEXT is hashed as its UTF-8 encoding; "base64:<data>" is hashed as
    the decoded bytes. Unwrapping that envelope recovers bytes, it does not
    re-encode content — and the verifier recomputes SHA-256 over what is
    carried, so a wrong recovery is FAILED there, never silently accepted."""
    if content is None:
        raise ExportError(f"{where}: artifact_content is NULL; the body store cannot hold an absent body")
    if isinstance(content, bytes):
        return content
    if not isinstance(content, str):
        raise ExportError(f"{where}: artifact_content expected TEXT, found {type(content).__name__}")
    if content.startswith(BASE64_PREFIX):
        try:
            return base64.b64decode(content[len(BASE64_PREFIX):], validate=True)
        except (binascii.Error, ValueError) as e:
            raise ExportError(f"{where}: artifact_content claims base64 but does not decode: {e}") from e
    return content.encode("utf-8")


def fetch_artifact_bodies(conn, chains):
    """Bodies for every entry of every selected chain.

    Returns (store, coverage): store maps artifact_hash -> bytes (exactly as
    stored, decoded from the envelope only); coverage maps session_id ->
    (entries_with_body, [hash-only sequences]). An entry with no
    (artifact_id, artifact_hash) row is hash-only — recorded, never faked.
    Two rows disagreeing on the bytes for one artifact_hash is a store
    conflict this exporter refuses to paper over."""
    store = {}
    coverage = {}
    sql = f"SELECT artifact_content FROM {ARTIFACTS_TABLE} WHERE artifact_id = ? AND artifact_hash = ?"
    for chain in chains:
        with_body = 0
        hash_only = []
        for entry in chain["entries"]:
            aid, ahash, seq = entry["artifact_id"], entry["artifact_hash"], entry["sequence"]
            rows = conn.execute(sql, (aid, ahash)).fetchall()
            if not rows:
                hash_only.append(seq)
                continue
            # UNIQUE(artifact_id, artifact_hash) means at most one row.
            where = f"{ARTIFACTS_TABLE} artifact_id={aid!r}"
            data = body_bytes(where, rows[0][0])
            if ahash in store and store[ahash] != data:
                raise ExportError(
                    f"{where}: the store holds two different bodies for artifact_hash {ahash}; "
                    f"refusing to choose one"
                )
            store[ahash] = data
            with_body += 1
        coverage[chain["session_id"]] = (with_body, hash_only)
    return store, coverage


SAFE_NAME_RE = re.compile(r"[^A-Za-z0-9._-]")


def session_file_name(session_id, taken):
    """A filesystem- and tar-safe file name for a session. Session ids
    contain ':' and other characters; the manifest maps id -> path, so the
    name only has to be unique and safe, not reversible."""
    base = SAFE_NAME_RE.sub("_", session_id).strip("._") or "session"
    name = base + ".json"
    if name in taken:
        tag = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:8]
        name = f"{base}-{tag}.json"
    taken.add(name)
    return name


def read_seal(seal_path):
    """Read the seal bytes verbatim. Sanity: parses as JSON and says it is a
    virp-seal/1 document. Nothing is altered."""
    try:
        with open(seal_path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise ExportError(f"cannot read seal {seal_path}: {e}") from e
    try:
        doc = json.loads(data)
    except ValueError as e:
        raise ExportError(f"seal {seal_path} is not valid JSON: {e}") from e
    if not isinstance(doc, dict) or doc.get("seal_version") != SEAL_VERSION:
        raise ExportError(
            f"seal {seal_path}: expected seal_version {SEAL_VERSION!r}, found "
            f"{doc.get('seal_version') if isinstance(doc, dict) else type(doc).__name__!r}"
        )
    return data


def read_seal_sig(seal_sig_path):
    """Read the detached minisign signature verbatim. Sanity only: the file
    must look like a .minisig (a base64 payload line decoding to 74 bytes
    whose algorithm tag is minisign's Ed or ED). Whether it VERIFIES is
    virp-verify's call, under a --seal-key supplied out of band."""
    try:
        with open(seal_sig_path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise ExportError(f"cannot read seal signature {seal_sig_path}: {e}") from e
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ExportError(f"seal signature {seal_sig_path} is not UTF-8 text (a .minisig is)") from e
    payload = [
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith(("untrusted comment:", "trusted comment:"))
    ]
    if not payload:
        raise ExportError(f"seal signature {seal_sig_path}: no base64 payload line found")
    try:
        blob = base64.b64decode(payload[0], validate=True)
    except (binascii.Error, ValueError) as e:
        raise ExportError(f"seal signature {seal_sig_path}: payload line is not base64: {e}") from e
    if len(blob) != 74 or blob[:2] not in (b"Ed", b"ED"):
        raise ExportError(
            f"seal signature {seal_sig_path}: payload is not a minisign signature blob "
            f"(74 bytes starting Ed/ED; found {len(blob)} bytes)"
        )
    return data


# --- public keys (--keys) ---------------------------------------------------

# key_id is sha256-raw-16: hex(SHA-256(raw 32 public-key bytes)[0:16]).
KEY_ID_HEX_LEN = 32
PUBLIC_KEY_HEX_LEN = 64

# Top-level JSON field names that mean the file holds more than a public key.
# Matched case-insensitively as substrings: no private key material enters
# Docket, ever — refusing the whole file beats quietly copying out the public
# half of something the operator should not be handing around.
SECRET_FIELD_WORDS = ("secret", "seed", "private")


def derive_key_id(public_key_hex):
    """sha256-raw-16 over the raw key bytes. Derived, never copied: a
    relabelled key file cannot change the id, and a stated id that does not
    re-derive is caught by the caller."""
    return hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest()[:KEY_ID_HEX_LEN]


# The two forms `virp-verify --pin` accepts, named in every rejection so an
# operator holding the wrong shape is told what the right ones are.
KEY_FILE_FORMS = (
    f"A key file is either {PUBLIC_KEY_HEX_LEN} hex characters — the raw Ed25519 PUBLIC key as it lives "
    'on the daemon host, trailing newline allowed — or a docket keys.json object '
    '{"keys": [{"key_id", "algorithm", "public_key_hex"}]}. Raw 32-byte binary is not accepted by '
    "either side of Docket: hex it first (xxd -p -c 64)"
)


def read_public_key_file(path):
    """One chain-signing PUBLIC key file -> normalized keys.json entries.

    Accepted forms, the same set `virp-verify --pin` reads, so one file works
    on both sides of the tool:
      * raw hex: the file is exactly 64 hex characters (plus whitespace) —
        the D-1 public half as it lives on the daemon host;
      * a docket keys.json object: {"keys": [ <key object>, ... ]};
      * a bare key object: {"public_key_hex": "64 hex"} with optional
        "algorithm" (any casing of ed25519 — the API serves "Ed25519", the
        bundle format wants lowercase), optional stated "key_id"/"key_id_hex"
        (checked against the derived id, never trusted), optional "comment".
        This is the exporter's original single-key form; it is kept because
        operators have files in it.

    Normalization on write: algorithm lowercase "ed25519", hex lowercase,
    key_id always derived. Whether the bytes are a valid curve point is the
    verifier's call, as with every other cell this exporter copies.
    """
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as e:
        raise ExportError(f"cannot read key file {path}: {e}") from e
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as e:
        raise ExportError(f"key file {path} is not UTF-8 text. {KEY_FILE_FORMS}: {e}") from e

    stripped = text.strip()
    if HEX_RE.match(stripped) and len(stripped) == PUBLIC_KEY_HEX_LEN:
        docs = [{"public_key_hex": stripped}]
    else:
        try:
            doc = json.loads(stripped)
        except ValueError as e:
            raise ExportError(
                f"key file {path} is neither {PUBLIC_KEY_HEX_LEN} hex characters nor valid JSON. "
                f"{KEY_FILE_FORMS}: {e}"
            ) from e
        if not isinstance(doc, dict):
            raise ExportError(
                f"key file {path}: JSON form must be an object, found {type(doc).__name__}. {KEY_FILE_FORMS}"
            )
        if "keys" in doc:
            # The keys.json shape, exactly as this exporter emits it and as
            # --pin reads it: a round trip through the bundle format works.
            if not isinstance(doc["keys"], list):
                raise ExportError(f"key file {path}: 'keys' must be a list, found {type(doc['keys']).__name__}")
            if not doc["keys"]:
                raise ExportError(f"key file {path}: 'keys' is empty; a key file must carry at least one key")
            for k in doc["keys"]:
                if not isinstance(k, dict):
                    raise ExportError(f"key file {path}: every entry in 'keys' must be an object")
            docs = doc["keys"]
        else:
            docs = [doc]
    return [read_public_key_doc(path, d) for d in docs]


def read_public_key_doc(path, doc):
    """One key object -> a normalized keys.json entry."""
    for name in doc:
        if any(w in name.lower() for w in SECRET_FIELD_WORDS):
            raise ExportError(
                f"key file {path} carries field {name!r}, which names secret key material; "
                f"--keys takes PUBLIC key files only and no private key material enters Docket"
            )

    pub = doc.get("public_key_hex")
    if pub is None:
        raise ExportError(f"key file {path}: no 'public_key_hex' field (and the file is not raw hex)")
    if not isinstance(pub, str) or not HEX_RE.match(pub) or len(pub) != PUBLIC_KEY_HEX_LEN:
        raise ExportError(
            f"key file {path}: public_key_hex must be {PUBLIC_KEY_HEX_LEN} hex characters, found {pub!r}"
        )
    pub = pub.lower()

    algorithm = doc.get("algorithm")
    if algorithm is not None:
        if not isinstance(algorithm, str) or algorithm.lower() != "ed25519":
            raise ExportError(f"key file {path}: algorithm {algorithm!r} is not ed25519 (any casing accepted)")

    key_id = derive_key_id(pub)
    stated = doc.get("key_id", doc.get("key_id_hex"))
    if stated is not None:
        if not isinstance(stated, str) or stated.lower() != key_id:
            raise ExportError(
                f"key file {path}: stated key_id {stated!r} does not re-derive from the key bytes "
                f"(derived {key_id}); the id is sha256-raw-16 over the raw public key and is never taken on faith"
            )

    entry = {"key_id": key_id, "algorithm": "ed25519", "public_key_hex": pub}
    comment = doc.get("comment")
    if comment is not None:
        if not isinstance(comment, str):
            raise ExportError(f"key file {path}: comment must be a string, found {type(comment).__name__}")
        entry["comment"] = comment
    return entry


def read_public_keys(paths):
    """All --keys files -> deterministic keys.json entries, sorted by key_id.
    The same key supplied twice collapses to one entry; twice with differing
    comments is a conflict this exporter refuses to resolve."""
    by_id = {}
    origin = {}
    for path in paths:
        for entry in read_public_key_file(path):
            kid = entry["key_id"]
            if kid in by_id:
                if by_id[kid] != entry:
                    raise ExportError(
                        f"key files {origin[kid]} and {path} supply key_id {kid} with different metadata; "
                        f"refusing to choose"
                    )
                continue
            by_id[kid] = entry
            origin[kid] = path
    return [by_id[kid] for kid in sorted(by_id)]


def created_at_utc():
    """The manifest's created_at. SOURCE_DATE_EPOCH (unix seconds) pins it so
    a re-export is byte-identical; unset, the wall clock, as before."""
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch is None:
        now = datetime.datetime.now(datetime.timezone.utc)
    else:
        try:
            now = datetime.datetime.fromtimestamp(int(epoch), datetime.timezone.utc)
        except (ValueError, OverflowError, OSError) as e:
            raise ExportError(f"SOURCE_DATE_EPOCH={epoch!r} is not a unix timestamp in seconds: {e}") from e
    return now.strftime("%Y-%m-%dT%H:%M:%SZ")


def write_json(path, obj):
    data = json.dumps(obj, indent=2, ensure_ascii=True).encode("utf-8") + b"\n"
    with open(path, "xb") as f:
        f.write(data)
    return hashlib.sha256(data).hexdigest()


def write_bytes(path, data):
    with open(path, "xb") as f:
        f.write(data)
    return hashlib.sha256(data).hexdigest()


def run_export(db_path, out_dir, session_ids, seal_path, all_sessions, artifacts=False, key_paths=None, seal_sig_path=None):
    if os.path.lexists(out_dir):
        raise ExportError(f"output directory already exists: {out_dir} (refusing to overwrite; choose a new --out)")
    if seal_sig_path and not seal_path:
        raise ExportError("--seal-sig is a signature over the seal document; it needs --seal")
    if seal_sig_path and os.path.basename(seal_sig_path) == os.path.basename(seal_path):
        raise ExportError(
            f"--seal and --seal-sig share the file name {os.path.basename(seal_path)!r}; "
            f"both land in seal/ and would collide"
        )

    # Key files, the seal signature and created_at are resolved before the
    # output directory exists, like every other input: a bad file leaves
    # nothing on disk.
    key_entries = read_public_keys(key_paths) if key_paths else None
    seal_sig_bytes = read_seal_sig(seal_sig_path) if seal_sig_path else None
    created_at = created_at_utc()

    conn = open_readonly(db_path)
    try:
        present = discover_schema(conn)
        if artifacts:
            discover_artifacts_schema(conn)
        available = list_sessions(conn)
        available_ids = [s[0] for s in available]

        if all_sessions:
            selected = available_ids
        else:
            unknown = [s for s in session_ids if s not in available_ids]
            if unknown:
                raise ExportError(
                    f"session id(s) not in the database: {unknown}\n"
                    f"  the database holds {len(available_ids)} session(s); run --list-sessions to see them"
                )
            # Preserve the operator's order, drop duplicates.
            selected = list(dict.fromkeys(session_ids))
        if not selected:
            raise ExportError("no sessions selected")

        seal_bytes = read_seal(seal_path) if seal_path else None

        # Read everything BEFORE creating the output directory, so a sanity
        # failure leaves nothing on disk.
        chains = [export_session(conn, sid, present) for sid in selected]
        body_store, body_coverage = fetch_artifact_bodies(conn, chains) if artifacts else ({}, {})
    finally:
        conn.close()

    written = []  # (relative path, sha256)
    os.makedirs(os.path.join(out_dir, "sessions"), exist_ok=False)
    taken = set()
    manifest_sessions = []
    for chain in chains:
        name = session_file_name(chain["session_id"], taken)
        rel = "sessions/" + name
        digest = write_json(os.path.join(out_dir, rel), chain)
        written.append((rel, digest))
        manifest_sessions.append({"session_id": chain["session_id"], "path": rel})

    manifest = {
        "docket_bundle_version": BUNDLE_VERSION,
        "chain_format": CHAIN_FORMAT,
        "producer": f"docket export_bundle.py {VERSION} (db={os.path.basename(db_path)})",
        "created_at": created_at,
        "sessions": manifest_sessions,
    }
    if key_entries is not None:
        digest = write_json(os.path.join(out_dir, "keys.json"), {"keys": key_entries})
        written.append(("keys.json", digest))
        manifest["keys"] = "keys.json"
    if seal_bytes is not None:
        os.makedirs(os.path.join(out_dir, "seal"), exist_ok=False)
        rel = "seal/" + os.path.basename(seal_path)
        digest = write_bytes(os.path.join(out_dir, rel), seal_bytes)
        written.append((rel, digest))
        manifest["seal"] = rel
        if seal_sig_bytes is not None:
            rel = "seal/" + os.path.basename(seal_sig_path)
            digest = write_bytes(os.path.join(out_dir, rel), seal_sig_bytes)
            written.append((rel, digest))
            manifest["seal_signature"] = rel
    if artifacts:
        os.makedirs(os.path.join(out_dir, "artifacts"), exist_ok=False)
        manifest["artifacts"] = []
        for ahash in sorted(body_store):
            rel = "artifacts/" + ahash
            digest = write_bytes(os.path.join(out_dir, rel), body_store[ahash])
            written.append((rel, digest))
            manifest["artifacts"].append({"artifact_hash": ahash, "path": rel})
    digest = write_json(os.path.join(out_dir, "manifest.json"), manifest)
    written.insert(0, ("manifest.json", digest))

    # Summary.
    print(f"exported {len(chains)} session(s) from {db_path} -> {out_dir}")
    d1 = "present" if present["chain_sig"] else "absent"
    if key_entries is None:
        print(f"  D-1 signature columns: {d1}; keys.json: not produced (no public keys live in the database)")
    else:
        ids = ", ".join(e["key_id"] for e in key_entries)
        print(f"  D-1 signature columns: {d1}; keys.json: {len(key_entries)} public key(s): {ids}")
    for chain in chains:
        head = chain.get("head")
        head_txt = f"head last_sequence={head['last_sequence']}" if head else "NO HEAD ROW"
        signed = sum(1 for e in chain["entries"] if "signature" in e)
        hmacs = sum(1 for e in chain["entries"] if "chain_hmac" in e)
        print(
            f"  {chain['session_id']}: {len(chain['entries'])} entries "
            f"({hmacs} with chain_hmac, {signed} with signature), {head_txt}"
        )
        if artifacts:
            with_body, hash_only = body_coverage[chain["session_id"]]
            line = f"    bodies: {with_body}/{len(chain['entries'])} entries have carried bodies"
            if hash_only:
                line += f"; hash-only sequences: {', '.join(str(s) for s in hash_only)}"
            print(line)
    if artifacts:
        print(f"  artifact bodies carried: {len(body_store)} distinct artifact_hash file(s) under artifacts/")
    print("files written (sha256):")
    for rel, digest in written:
        print(f"  {digest}  {rel}")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(
        prog="export_bundle.py",
        description="Export a Docket evidence bundle (directory) from a VIRP chain database snapshot. "
        "Exports only; virp-verify judges.",
    )
    p.add_argument("--db", required=True, help="path to the chain database SNAPSHOT (opened read-only, immutable)")
    p.add_argument("--out", help="bundle directory to create (must not exist)")
    p.add_argument("--sessions", nargs="+", metavar="ID", help="session id(s) to export")
    p.add_argument("--all-sessions", action="store_true", help="export every session in the database")
    p.add_argument("--seal", help="path to a virp-seal/1 JSON document to copy into the bundle verbatim")
    p.add_argument(
        "--seal-sig",
        help="detached minisign signature (.minisig) over the --seal document, copied into the bundle "
        "verbatim; the signature may travel in-band, the seal PUBLIC key never does (virp-verify "
        "takes it out of band via --seal-key)",
    )
    p.add_argument(
        "--keys",
        nargs="+",
        metavar="PUBFILE",
        help="chain-signing PUBLIC key file(s) (raw 64-hex, or JSON with public_key_hex) to write into "
        "keys.json; key_id is derived from the key bytes (sha256-raw-16), output is deterministic, and "
        "a file carrying secret/seed material is refused",
    )
    p.add_argument(
        "--artifacts",
        action="store_true",
        help="also carry artifact BODIES (raw bytes from the artifacts table) so the verifier can grade "
        "artifact binding and a reader can see what happened; without it the bundle is hash-only, as before",
    )
    p.add_argument("--list-sessions", action="store_true", help="list session ids in the database and exit")
    args = p.parse_args(argv)

    try:
        if args.list_sessions:
            conn = open_readonly(args.db)
            try:
                discover_schema(conn)
                rows = list_sessions(conn)
            finally:
                conn.close()
            print(f"{len(rows)} session(s) in {args.db}:")
            for sid, n, has_head in rows:
                print(f"  {n:>7} entries  {'head' if has_head else 'NO HEAD':>7}  {sid}")
            return 0
        if not args.out:
            p.error("--out is required (unless --list-sessions)")
        if bool(args.sessions) == bool(args.all_sessions):
            p.error("give exactly one of --sessions <id>... or --all-sessions")
        return run_export(
            args.db, args.out, args.sessions or [], args.seal, args.all_sessions, args.artifacts, args.keys,
            args.seal_sig,
        )
    except ExportError as e:
        print(f"export_bundle.py: error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
