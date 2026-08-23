//! The minimal Docket evidence bundle: a directory.
//!
//! ```text
//! <bundle>/
//!   manifest.json            required — see [`Manifest`]
//!   keys.json                optional — key_id → public key (see [`KeyFile`])
//!   sessions/<name>.json     one [`SessionChain`] per session, paths named in the manifest
//!   seal/<name>.json         optional D-0 seal anchor, path named in the manifest
//! ```
//!
//! Every path in the manifest is relative to the bundle root and may not
//! escape it. The reader is strict: unknown manifest versions, missing
//! files, a key whose bytes do not derive its claimed `key_id`, or a session
//! file whose `session_id` disagrees with the manifest are all hard errors —
//! a bundle that cannot be read is never reported as anything but unreadable.

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::seal::Seal;
use crate::sig::PublicKey;
use crate::verify::{verify_session, Keyring, SessionChain, SessionReport, Status, Verdict};

pub const BUNDLE_VERSION: &str = "docket-bundle/0.1";
pub const CHAIN_FORMAT: &str = "v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestSession {
    pub session_id: String,
    /// Relative path to the session JSON.
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// Must be `docket-bundle/0.1`.
    pub docket_bundle_version: String,
    /// Must be `v1` — the VIRP canonical format. Signed entries are
    /// distinguished by the presence of their `signature` object, not by a
    /// format bump (DRAFT07-NOTES §2).
    pub chain_format: String,
    #[serde(default)]
    pub producer: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    pub sessions: Vec<ManifestSession>,
    /// Relative path to `keys.json`.
    #[serde(default)]
    pub keys: Option<String>,
    /// Relative path to the seal JSON.
    #[serde(default)]
    pub seal: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyEntry {
    /// Claimed `sha256-raw-16` id — checked against the bytes, never trusted.
    pub key_id: String,
    pub algorithm: String,
    pub public_key_hex: String,
    #[serde(default)]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyFile {
    pub keys: Vec<KeyEntry>,
}

/// Why a bundle could not be read. None of these is a verification
/// outcome; they mean the verifier never got to look.
#[derive(Debug)]
pub enum BundleError {
    Io { path: PathBuf, source: std::io::Error },
    Json { path: PathBuf, source: serde_json::Error },
    UnsupportedVersion(String),
    UnsupportedChainFormat(String),
    UnsafePath(String),
    KeyIdMismatch { claimed: String, derived: String },
    UnsupportedKeyAlgorithm(String),
    InvalidKey(String),
    SessionIdMismatch { manifest: String, file: String },
    Seal(crate::seal::SealError),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Json { path, source } => write!(f, "{}: invalid JSON: {source}", path.display()),
            Self::UnsupportedVersion(v) => write!(f, "unsupported docket_bundle_version {v:?} (want {BUNDLE_VERSION})"),
            Self::UnsupportedChainFormat(v) => write!(f, "unsupported chain_format {v:?} (want {CHAIN_FORMAT})"),
            Self::UnsafePath(p) => write!(f, "manifest path {p:?} is absolute or escapes the bundle"),
            Self::KeyIdMismatch { claimed, derived } => {
                write!(
                    f,
                    "keys.json claims key_id {claimed} but the key bytes derive {derived}"
                )
            }
            Self::UnsupportedKeyAlgorithm(a) => write!(f, "unsupported key algorithm {a:?} (want ed25519)"),
            Self::InvalidKey(k) => write!(f, "public key {k} is not a valid Ed25519 key"),
            Self::SessionIdMismatch { manifest, file } => {
                write!(f, "manifest names session {manifest:?} but the file says {file:?}")
            }
            Self::Seal(e) => write!(f, "seal: {e}"),
        }
    }
}

impl std::error::Error for BundleError {}

/// A fully read bundle.
#[derive(Debug)]
pub struct Bundle {
    pub root: PathBuf,
    pub manifest: Manifest,
    pub keyring: Keyring,
    pub sessions: Vec<SessionChain>,
    pub seal: Option<Seal>,
}

fn safe_join(root: &Path, rel: &str) -> Result<PathBuf, BundleError> {
    let p = Path::new(rel);
    if p.is_absolute() || p.components().any(|c| !matches!(c, Component::Normal(_))) {
        return Err(BundleError::UnsafePath(rel.to_owned()));
    }
    Ok(root.join(p))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, BundleError> {
    let bytes = std::fs::read(path).map_err(|source| BundleError::Io {
        path: path.to_owned(),
        source,
    })?;
    serde_json::from_slice(&bytes).map_err(|source| BundleError::Json {
        path: path.to_owned(),
        source,
    })
}

impl Bundle {
    /// Read a bundle directory. Strict; see the module docs.
    pub fn read_dir(root: &Path) -> Result<Bundle, BundleError> {
        let manifest: Manifest = read_json(&root.join("manifest.json"))?;
        if manifest.docket_bundle_version != BUNDLE_VERSION {
            return Err(BundleError::UnsupportedVersion(manifest.docket_bundle_version));
        }
        if manifest.chain_format != CHAIN_FORMAT {
            return Err(BundleError::UnsupportedChainFormat(manifest.chain_format));
        }

        let mut keyring = Keyring::new();
        if let Some(rel) = &manifest.keys {
            let kf: KeyFile = read_json(&safe_join(root, rel)?)?;
            for k in kf.keys {
                if k.algorithm != "ed25519" {
                    return Err(BundleError::UnsupportedKeyAlgorithm(k.algorithm));
                }
                let pk = PublicKey::from_hex(&k.public_key_hex)
                    .map_err(|_| BundleError::InvalidKey(k.public_key_hex.clone()))?;
                if pk.key_id() != k.key_id {
                    return Err(BundleError::KeyIdMismatch {
                        claimed: k.key_id,
                        derived: pk.key_id().to_owned(),
                    });
                }
                keyring.insert(pk);
            }
        }

        let mut sessions = Vec::with_capacity(manifest.sessions.len());
        for ms in &manifest.sessions {
            let chain: SessionChain = read_json(&safe_join(root, &ms.path)?)?;
            if chain.session_id != ms.session_id {
                return Err(BundleError::SessionIdMismatch {
                    manifest: ms.session_id.clone(),
                    file: chain.session_id,
                });
            }
            sessions.push(chain);
        }

        let seal = match &manifest.seal {
            None => None,
            Some(rel) => {
                let path = safe_join(root, rel)?;
                let bytes = std::fs::read(&path).map_err(|source| BundleError::Io {
                    path: path.clone(),
                    source,
                })?;
                Some(Seal::from_slice(&bytes).map_err(BundleError::Seal)?)
            }
        };

        Ok(Bundle {
            root: root.to_owned(),
            manifest,
            keyring,
            sessions,
            seal,
        })
    }

    /// Verify every session and grade the seal.
    pub fn verify(&self) -> BundleReport {
        let mut sessions = Vec::with_capacity(self.sessions.len());
        for chain in &self.sessions {
            let report = verify_session(chain, &self.keyring);
            let seal_anchor = match (&self.seal, &chain.head) {
                (None, _) => None,
                (Some(_), None) => Some(Status::unverifiable("no head to anchor")),
                (Some(seal), Some(head)) => {
                    // Only anchor a head the walk has verified as committing
                    // to the entries; otherwise the anchor would be
                    // anchoring a claim, not a verified fact.
                    let head_ok = report.status(crate::verify::property::HEAD_COMMITMENT) == Some(&Status::Verified);
                    if head_ok {
                        Some(seal.anchor(
                            &chain.session_id,
                            head.fields.last_sequence,
                            &head.fields.last_entry_hash,
                        ))
                    } else {
                        Some(Status::unverifiable("head commitment did not verify; not anchoring"))
                    }
                }
            };
            sessions.push(SessionOutcome { report, seal_anchor });
        }

        let seal = self.seal.as_ref().map(|s| SealOutcome {
            seal_version: s.seal_version.clone(),
            created_at: s.created_at.clone(),
            sealed_by: s.sealed_by.clone(),
            session_count: s.sessions.len(),
            consistency: s.consistency(),
            signature: Status::unverifiable("minisign signature not checked by this verifier (not implemented)"),
            residual_disclosure: s.residual_disclosure.clone(),
        });

        let verdict = overall_verdict(&sessions, seal.as_ref());
        BundleReport {
            bundle_version: self.manifest.docket_bundle_version.clone(),
            chain_format: self.manifest.chain_format.clone(),
            key_ids: self.keyring.key_ids().map(str::to_owned).collect(),
            sessions,
            seal,
            verdict,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionOutcome {
    #[serde(flatten)]
    pub report: SessionReport,
    /// Present only when the bundle carries a seal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal_anchor: Option<Status>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealOutcome {
    pub seal_version: String,
    pub created_at: String,
    pub sealed_by: String,
    pub session_count: usize,
    /// Merkle root recomputed from the listed sessions.
    pub consistency: Status,
    /// The seal's own signature — not checked by Docket today.
    pub signature: Status,
    pub residual_disclosure: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleReport {
    pub bundle_version: String,
    pub chain_format: String,
    pub key_ids: Vec<String>,
    pub sessions: Vec<SessionOutcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seal: Option<SealOutcome>,
    /// The weakest session verdict; Failed if anything failed.
    pub verdict: Verdict,
}

/// Weakest-link: any failure (including a failed seal anchor or an
/// inconsistent seal) is FAILED; otherwise the least-authenticated session
/// verdict. An empty bundle has nothing verified and is FAILED.
fn overall_verdict(sessions: &[SessionOutcome], seal: Option<&SealOutcome>) -> Verdict {
    if sessions.is_empty() {
        return Verdict::Failed;
    }
    let seal_failed = seal.is_some_and(|s| s.consistency.is_failed());
    let any_failed = sessions
        .iter()
        .any(|s| s.report.verdict == Verdict::Failed || s.seal_anchor.as_ref().is_some_and(Status::is_failed));
    if any_failed || seal_failed {
        return Verdict::Failed;
    }
    let rank = |v: Verdict| match v {
        Verdict::Failed => 0,
        Verdict::ConsistentUnauthenticated => 1,
        Verdict::OperatorAttestedUnverifiable => 2,
        Verdict::CryptographicallyVerified => 3,
    };
    sessions
        .iter()
        .map(|s| s.report.verdict)
        .min_by_key(|v| rank(*v))
        .unwrap_or(Verdict::Failed)
}
