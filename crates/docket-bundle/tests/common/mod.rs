//! Shared fixture loading for the golden-vector tests.
#![allow(dead_code)]

use serde_json::Value;
use std::path::PathBuf;

pub fn vectors_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
}

pub fn load_json(name: &str) -> Value {
    let path = vectors_dir().join(name);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    serde_json::from_slice(&bytes).unwrap_or_else(|e| panic!("parse {}: {e}", path.display()))
}

pub fn load_bytes(name: &str) -> Vec<u8> {
    let path = vectors_dir().join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()))
}

pub fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("fixture missing string field {key:?}"))
}

pub fn i64_of(v: &Value, key: &str) -> i64 {
    v.get(key)
        .and_then(Value::as_i64)
        .unwrap_or_else(|| panic!("fixture missing integer field {key:?}"))
}

pub fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap_or_else(|e| panic!("bad hex in fixture: {e}"))
}

/// Appendix A fixtures: the seal file records this file's SHA-256, so the
/// copy we carry is anchored to the seal.
pub const FIXTURES_APPENDIX_A_SHA256: &str = "cd022ae2f7b9b5efda2d0f46bb8c14c356d1918feb4b80bf52c043d14c30b8ab";
