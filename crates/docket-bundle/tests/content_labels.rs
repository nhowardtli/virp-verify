use docket_bundle::{content::labels, sha256_hex};
#[test]
fn labels_require_exact_binding_and_never_echo_unbound_claims() {
    let body = br#"{"content_tier":"observed","mode":"tap"}"#;
    assert_eq!(labels(Some(body), &sha256_hex(body)), ("observed".into(), "tap".into()));
    assert_eq!(
        labels(Some(body), &"0".repeat(64)),
        ("unverified".into(), "unverified".into())
    );
    assert_eq!(
        labels(None, &sha256_hex(body)),
        ("unverified".into(), "unverified".into())
    );
    let bad = b"not json";
    assert_eq!(
        labels(Some(bad), &sha256_hex(bad)),
        ("unverified".into(), "unverified".into())
    );
}
#[test]
fn absent_unknown_and_self_reported_are_distinct() {
    for (body, tier, mode) in [
        (r#"{}"#, "absent", "absent"),
        (
            r#"{"content_tier":"self-reported","mode":"witness"}"#,
            "self-reported",
            "witness",
        ),
        (r#"{"content_tier":"VERIFIED\nforged","mode":42}"#, "unknown", "unknown"),
    ] {
        assert_eq!(
            labels(Some(body.as_bytes()), &sha256_hex(body.as_bytes())),
            (tier.into(), mode.into())
        );
    }
}
