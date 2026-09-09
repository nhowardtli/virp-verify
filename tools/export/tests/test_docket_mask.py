# SPDX-License-Identifier: LicenseRef-Proprietary
"""
The Python half of the shared corpus contract.

`tests/corpus/cases.json` holds one `expected` output per fixture. This suite
asserts the Python matcher produces it; `tests/fixtures.rs` in Docket's private
`docket-redact` asserts the Rust matcher produces the same one. Neither matcher
can drift from the other without failing its own suite — there is one
`expected`, and both have to land on it.
"""

import base64
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import docket_mask  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
EXPORT = os.path.dirname(HERE)
CORPUS = os.path.join(HERE, "corpus", "cases.json")
TABLE = os.path.join(EXPORT, "docket-mask-v1.json")


def load_cases():
    with open(CORPUS, "r", encoding="utf-8") as f:
        return json.load(f)["cases"]


def case_bytes(c):
    if "input" in c:
        assert "input_b64" not in c, "%s: exactly one of input / input_b64" % c["id"]
        return c["input"].encode("utf-8")
    return base64.b64decode(c["input_b64"])


CASES = load_cases()
IDS = [c["id"] for c in CASES]


def test_the_table_this_matcher_reads_is_the_one_the_rust_matcher_embeds():
    """Not a copy — the same file. A second copy would be a second source of
    truth and would drift."""
    assert os.path.samefile(docket_mask._table_path(), TABLE)


def test_the_corpus_is_not_empty_and_covers_both_kinds():
    kinds = {c["kind"] for c in CASES}
    assert kinds == {"positive", "negative"}
    assert len(CASES) > 40


@pytest.mark.parametrize("c", CASES, ids=IDS)
def test_every_fixture_masks_to_its_expected_output(c):
    m = docket_mask.mask_body(case_bytes(c))
    assert m.text == c["expected"], "%s: masked text" % c["id"]
    assert m.redactions == c["redactions"], "%s: redaction count" % c["id"]
    assert m.withheld_bytes == c["withheld_bytes"], "%s: withheld bytes" % c["id"]
    assert m.whole_body == c["whole_body"], "%s: whole-body flag" % c["id"]


@pytest.mark.parametrize("c", [c for c in CASES if c["kind"] == "negative"], ids=[c["id"] for c in CASES if c["kind"] == "negative"])
def test_negative_fixtures_are_never_masked(c):
    raw = case_bytes(c)
    m = docket_mask.mask_body(raw)
    assert m.redactions == 0, "%s was masked: %r" % (c["id"], m.text)
    assert m.text.encode("utf-8") == raw


@pytest.mark.parametrize("c", [c for c in CASES if c["kind"] == "positive"], ids=[c["id"] for c in CASES if c["kind"] == "positive"])
def test_positive_fixtures_fire_and_name_their_category(c):
    m = docket_mask.mask_body(case_bytes(c))
    assert m.redactions > 0, "%s did not fire" % c["id"]
    assert m.withheld_bytes > 0
    if c["category"] != "none":
        assert "[REDACTED: %s" % c["category"] in m.text


def test_every_category_has_a_positive_and_a_negative_fixture():
    positives = {c["category"] for c in CASES if c["kind"] == "positive"}
    negatives = {c["category"] for c in CASES if c["kind"] == "negative"}
    for cat in docket_mask.categories():
        assert cat in positives, "category %s has no positive fixture" % cat
        assert cat in negatives, "category %s has no negative fixture" % cat


@pytest.mark.parametrize("c", CASES, ids=IDS)
def test_masking_is_idempotent(c):
    once = docket_mask.mask_body(case_bytes(c))
    twice = docket_mask.mask_body(once.text.encode("utf-8"))
    assert twice.text == once.text, "%s is not idempotent" % c["id"]
    assert twice.redactions == 0, "%s re-redacted on a second pass" % c["id"]


def test_a_virp_scrubbed_body_passes_through_unchanged():
    """Both C markers survive: `[REDACTED: …]` from virp_scrub.c and
    `<removed>` from the cisco and ASA driver scrubs."""
    body = (
        "enable secret [REDACTED: enable-secret]\n"
        "username admin password <removed>\n"
        "snmp-server community <removed> RO 99\n"
        "crypto isakmp key <removed> address 203.0.113.7\n"
    )
    m = docket_mask.mask_body(body.encode("utf-8"))
    assert m.text == body
    assert m.redactions == 0


def test_the_rule_three_cap_is_exact_and_above_the_display_cap():
    assert docket_mask.MASK_MAX_BODY_BYTES > docket_mask.DISPLAY_CAP_REFERENCE
    assert docket_mask.policy()["max_body_bytes"] == docket_mask.MASK_MAX_BODY_BYTES
    at = b"A" * docket_mask.MASK_MAX_BODY_BYTES
    assert not docket_mask.mask_body(at).whole_body
    over = b"A" * (docket_mask.MASK_MAX_BODY_BYTES + 1)
    m = docket_mask.mask_body(over)
    assert m.whole_body
    assert m.text == "[REDACTED: unclassifiable: oversize]"
    assert m.withheld_bytes == docket_mask.MASK_MAX_BODY_BYTES + 1


def test_mask_text_keeps_the_verb_and_takes_the_argument():
    assert docket_mask.mask_text("set password ENC SH2VGx1lPTBSc0Q").text == "set password ENC [REDACTED: fortigate-secret]"
    for cmd in ("show running-config", "show ip bgp summary", "pct list", "show version"):
        assert docket_mask.mask_text(cmd).text == cmd
        assert docket_mask.mask_text(cmd).is_clean()


def test_is_sensitive_answers_the_exporters_question():
    assert docket_mask.is_sensitive(b"enable secret 5 $1$abc\n")
    assert docket_mask.is_sensitive(b"\xff\xfe")
    assert not docket_mask.is_sensitive(b"interface Gi0/0\n no shutdown\n")


def test_a_missing_pattern_table_is_an_error_and_never_an_empty_ruleset():
    """A masking layer that silently degrades to "no rules" is worse than one
    that refuses to start."""
    saved = os.environ.get("DOCKET_MASK_PATTERNS")
    docket_mask._POLICY = None
    os.environ["DOCKET_MASK_PATTERNS"] = os.path.join(HERE, "no", "such", "table.json")
    try:
        with pytest.raises(Exception):
            docket_mask.policy()
    finally:
        if saved is None:
            del os.environ["DOCKET_MASK_PATTERNS"]
        else:
            os.environ["DOCKET_MASK_PATTERNS"] = saved
        docket_mask._POLICY = None


def _fixture_lines():
    lines = []
    for c in CASES:
        raw = case_bytes(c)
        if len(raw) > 4096:
            continue  # the oversize fixtures never reach the line rules
        try:
            lines.extend(raw.decode("utf-8").splitlines())
        except UnicodeDecodeError:
            continue
    # Shapes the corpus does not carry: a rule's literal present but the
    # pattern failing, and a line with no literal at all.
    lines.extend(
        [
            "the password-encryption service is enabled",
            "a line about a key and a secret and a token, with no separators",
            "AKIA",
            "eyJ",
            "md5",
            "",
            "   ",
            "set",
        ]
    )
    return lines


def test_the_literal_prefilter_cannot_change_an_answer():
    """The prefilter is a cost optimisation and must never be a semantic one.
    It exists because this engine backtracks and Rust's does not; the Rust
    suite runs the same check on its side."""
    p = docket_mask.policy()
    for line in _fixture_lines():
        with_filter = docket_mask._mask_line(p, line, prefilter=True)[0]
        without = docket_mask._mask_line(p, line, prefilter=False)[0]
        assert with_filter == without, "the prefilter changed the answer for %r" % line
