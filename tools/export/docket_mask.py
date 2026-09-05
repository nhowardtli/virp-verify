"""
docket_mask — the Python half of Docket's masking layer.

Masking at render, omission at export. This module never modifies chained
bytes and never computes a hash: it takes bytes and returns the same bytes
with secret-shaped spans replaced by a visible marker.

THE ONE PATTERN TABLE
---------------------
Every pattern lives in `docket-mask-v1.json`, beside this module. This module
carries no pattern of its own, and neither does the Rust matcher in Docket's
private `docket-redact`, which embeds a byte-identical copy of that same file
at compile time. The shared fixture corpus (`tests/corpus/cases.json`) gives
one `expected` output per fixture, and BOTH matchers are asserted against it
— here in `tests/test_docket_mask.py` and there in `tests/fixtures.rs`. Two
matchers cannot disagree on a fixture without one of the two suites failing.

This tree is the source for both. The table and the corpus are published here
so that a reader who is handed a `--redacted` bundle can check the policy it
was produced under, rather than being told what it was.

REGEX DIALECT
-------------
Patterns are restricted to the intersection of Rust `regex` 1.x and Python
`re`: no lookaround, no backreferences, ASCII classes written out rather than
\\d / \\w. Patterns are matched against ONE line with its terminator already
removed — that is what makes `$` mean the same thing in both engines, since
Python's `$` would otherwise also match before a trailing newline.

THE HONESTY LIMIT
-----------------
Inherited from the C scrubber this table was seeded from
(`virp/include/virp_scrub.h`): this masks secrets in RECOGNIZED FORMATS. An
unlabelled plaintext password or a bare hex token with no adjacent label is
NOT caught. Say "secrets in recognized formats are masked"; never say "no
secret can leave here".

DEPLOYMENT
----------
`export_bundle.py` imports this module ONLY for `--redacted`. Every other
export path still needs nothing but the Python standard library and the one
script. For `--redacted` on another host, three files travel together:
`export_bundle.py`, `docket_mask.py`, and `docket-mask-v1.json` (put the
table beside this module, or point `DOCKET_MASK_PATTERNS` at it).
"""

import base64
import json
import os
import re

__all__ = [
    "Masked",
    "mask_body",
    "mask_text",
    "is_sensitive",
    "policy",
    "policy_name",
    "categories",
    "MASK_MAX_BODY_BYTES",
    "DISPLAY_CAP_REFERENCE",
    "PatternTableMissing",
]

# Rule 3's size cap: a body larger than this is masked in full rather than
# scanned. Deliberately LARGER than the display cap below — the display cap
# answers "how much do we show", this one answers "is this thing something we
# are willing to classify at all". Authoritative value comes from the table;
# this mirrors it so the constant is readable here too.
MASK_MAX_BODY_BYTES = 1048576

# The display cap the two readers apply AFTER masking. Recorded so the
# relationship between the two numbers is written down on this side as well.
DISPLAY_CAP_REFERENCE = 65536

PATTERN_FILE_NAME = "docket-mask-v1.json"


class PatternTableMissing(Exception):
    """The pattern table could not be found. Never falls back to no rules."""


def _table_path():
    """Where the table is, in the order a deployment would have put it."""
    env = os.environ.get("DOCKET_MASK_PATTERNS")
    if env:
        return env
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        # Beside this module: both where it lives in this tree, and how the
        # exporter travels to another host. There is no second location, so
        # there is no way to load a table other than the one shipped here.
        os.path.join(here, PATTERN_FILE_NAME),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return os.path.normpath(c)
    raise PatternTableMissing(
        "cannot find %s. Looked at: %s. Set DOCKET_MASK_PATTERNS to its path, or copy it beside "
        "docket_mask.py." % (PATTERN_FILE_NAME, ", ".join(os.path.normpath(c) for c in candidates))
    )


_POLICY = None


def policy():
    """The compiled pattern table, loaded once."""
    global _POLICY
    if _POLICY is None:
        with open(_table_path(), "r", encoding="utf-8") as f:
            raw = json.load(f)
        _POLICY = _compile(raw)
    return _POLICY


def _compile(raw):
    rules = []
    for r in raw["rules"]:
        redacts = r.get("action") != "keep"
        mode = r["mode"]
        if mode not in ("sweep", "line-first"):
            raise ValueError("rule %s: unknown mode %r" % (r["id"], mode))
        if redacts and "group" not in r:
            raise ValueError("rule %s: a redacting rule needs a capture group" % r["id"])
        rules.append(
            {
                "id": r["id"],
                "category": r["category"],
                "redacts": redacts,
                "sweep": mode == "sweep",
                "re": re.compile(r["regex"]),
                # The prefilter: lowercased substrings, at least one of which
                # the line must contain before the pattern is tried. Every
                # one is REQUIRED by the pattern, so this can only skip
                # attempts that would have failed. It exists for cost, not
                # semantics — Python's `re` backtracks where Rust's `regex`
                # does not, and without it a megabyte-long line with no
                # separators costs the two matchers wildly different amounts
                # of time for the same answer.
                "literals": [l.lower() for l in r.get("literals", [])],
                # Tested against capture group 1 (the label and its
                # separator) after the pattern matches; a hit SKIPS that
                # occurrence. This is how a label vocabulary says "key"
                # without also saying "key_id", in a dialect with no
                # lookaround.
                "exclude_label": re.compile(r["exclude_label"]) if "exclude_label" in r else None,
                "group": r.get("group", 0),
            }
        )
    return {
        "policy": raw["policy"],
        "marker_prefix": raw["marker_prefix"],
        "marker_suffix": raw["marker_suffix"],
        "unclassifiable_reason": raw["unclassifiable_reason"],
        "already_redacted": list(raw["already_redacted"]),
        "max_body_bytes": raw["unclassifiable_max_bytes"],
        "blocks": [
            {
                "category": b["category"],
                "open_contains": list(b["open_contains"]),
                "close_contains": list(b["close_contains"]),
            }
            for b in raw["blocks"]
        ],
        "rules": rules,
    }


def policy_name():
    """The policy name recorded in a redacted export's manifest."""
    return policy()["policy"]


def categories():
    """Every category this table can emit, sorted."""
    p = policy()
    out = {r["category"] for r in p["rules"] if r["redacts"]}
    out.update(b["category"] for b in p["blocks"])
    out.add(p["unclassifiable_reason"])
    return sorted(out)


class Masked(object):
    """A masked body, with the metadata a reader is owed."""

    __slots__ = ("text", "redactions", "withheld_bytes", "whole_body")

    def __init__(self, text, redactions, withheld_bytes, whole_body):
        self.text = text
        self.redactions = redactions
        self.withheld_bytes = withheld_bytes
        self.whole_body = whole_body

    def is_clean(self):
        return self.redactions == 0

    def __repr__(self):
        return "Masked(redactions=%d, withheld_bytes=%d, whole_body=%r)" % (
            self.redactions,
            self.withheld_bytes,
            self.whole_body,
        )


def _marker(p, reason):
    return p["marker_prefix"] + reason + p["marker_suffix"]


def _already_redacted_at(p, rest):
    """The C scrubber's guard: what stands here is already a marker — this
    layer's `[REDACTED: `, or a driver scrub's `<removed>`."""
    return any(rest.startswith(s) for s in p["already_redacted"])


def _whole_body(p, total, why):
    return Masked(_marker(p, "%s: %s" % (p["unclassifiable_reason"], why)), 1, total, True)


def mask_body(raw):
    """Mask a body: rule 3 (unclassifiable) first, then blocks and rules.

    `raw` is bytes — anything whose content came off a device. Use
    `mask_text` for a string that is already structure (a command, a camera
    id, a gap reason)."""
    p = policy()
    total = len(raw)
    if total > p["max_body_bytes"]:
        return _whole_body(p, total, "oversize")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return _whole_body(p, total, "not-utf8")
    for ch in text:
        # `str.isprintable()` is not the test: it calls '\n' unprintable and
        # would send every ordinary multi-line body to rule 3.
        if ch in "\n\t\r":
            continue
        if ord(ch) < 0x20 or ord(ch) == 0x7F or (0x80 <= ord(ch) <= 0x9F):
            return _whole_body(p, total, "control-bytes")
    return mask_text(text)


def mask_text(s):
    """Mask a string already known to be text.

    Rule 3 does not apply — the caller has already decided this is structure
    worth showing. Rules 1 and 2 do: a `set password …` command loses its
    argument and keeps its verb, because the rules keep the recognisable
    prefix by construction."""
    p = policy()
    out = []
    redactions = 0
    withheld = 0
    in_block = None
    block_marked = False

    for content, terminator in _lines(s):
        if in_block is not None:
            b = p["blocks"][in_block]
            if _contains_all(content, b["close_contains"]):
                out.append(content)
                out.append(terminator)
                in_block = None
                block_marked = False
                continue
            if _already_redacted_at(p, content):
                # Already a marker: this body has been masked before (or
                # scrubbed upstream). Pass it through and count nothing, so a
                # second pass reports a clean body.
                out.append(content)
                out.append(terminator)
                block_marked = True
                continue
            withheld += len(content)
            if not block_marked:
                redactions += 1
                block_marked = True
                out.append(_marker(p, b["category"]))
                out.append(terminator)
            continue

        opened = None
        for i, b in enumerate(p["blocks"]):
            if _contains_all(content, b["open_contains"]):
                opened = i
                break
        if opened is not None:
            out.append(content)
            out.append(terminator)
            in_block = opened
            block_marked = False
            continue

        masked, n, w = _mask_line(p, content)
        redactions += n
        withheld += w
        out.append(masked)
        out.append(terminator)

    return Masked("".join(out), redactions, withheld, False)


def is_sensitive(raw):
    """True when the input carries anything this policy would mask — the
    exporter's gate for withholding a body."""
    return not mask_body(raw).is_clean()


def _contains_all(hay, needles):
    return all(n in hay for n in needles)


def _lines(s):
    """(content-without-terminator, terminator) pairs, so a rule's `$` means
    the same thing in both engines and the output reassembles byte for
    byte."""
    out = []
    start = 0
    for i, ch in enumerate(s):
        if ch == "\n":
            end = i
            if end > start and s[end - 1] == "\r":
                end -= 1
            out.append((s[start:end], s[end : i + 1]))
            start = i + 1
    if start < len(s):
        out.append((s[start:], ""))
    return out


def _can_match(r, lowered):
    return not r["literals"] or any(l in lowered for l in r["literals"])


def _label_excluded(r, m):
    """True when this occurrence's label is one the rule explicitly does not
    claim. See the table's `exclusions` note."""
    if r["exclude_label"] is None or m.lastindex is None or m.lastindex < 1:
        return False
    label = m.group(1)
    return label is not None and bool(r["exclude_label"].search(label))


def _mask_line(p, line, prefilter=True):
    """One line through the two passes. Returns (masked, redactions, withheld).

    `prefilter` is always on in production; the suite runs it both ways to
    prove the filter cannot change an answer."""
    cur = line
    redactions = 0
    withheld = 0
    lowered = cur.lower()

    # Pass 1 — line-first: table order, the first rule that matches wins.
    for r in p["rules"]:
        if r["sweep"]:
            continue
        if prefilter and not _can_match(r, lowered):
            continue
        m = r["re"].search(cur)
        if not m:
            continue
        if _label_excluded(r, m):
            continue  # this rule does not claim that label
        if not r["redacts"]:
            break  # a keep-rule: this line is structure, not payload
        span = m.span(r["group"])
        if span[0] < 0:
            continue
        if _already_redacted_at(p, cur[span[0] :]):
            # Already scrubbed at this position. Stop the pass rather than
            # fall through: a BROADER rule further down the table would
            # otherwise re-redact a span that already begins with a marker,
            # and masking would stop being idempotent.
            break
        marker = _marker(p, r["category"])
        withheld += span[1] - span[0]
        redactions += 1
        cur = cur[: span[0]] + marker + cur[span[1] :]
        lowered = cur.lower()
        break

    # Pass 2 — sweep: every generic rule, every match. Runs whether or not
    # pass 1 fired: one compact JSON body is a single line and can carry
    # several secrets of different kinds.
    for r in p["rules"]:
        if not (r["sweep"] and r["redacts"]):
            continue
        if prefilter and not _can_match(r, lowered):
            continue
        while True:
            hit = None
            for m in r["re"].finditer(cur):
                if _label_excluded(r, m):
                    continue  # this rule does not claim that label
                span = m.span(r["group"])
                if span[0] < 0 or span[0] == span[1]:
                    continue
                if _already_redacted_at(p, cur[span[0] :]):
                    continue
                hit = span
                break
            if hit is None:
                break
            marker = _marker(p, r["category"])
            withheld += hit[1] - hit[0]
            redactions += 1
            cur = cur[: hit[0]] + marker + cur[hit[1] :]
            lowered = cur.lower()

    return cur, redactions, withheld


def _b64(data):
    return base64.b64encode(data).decode("ascii")
