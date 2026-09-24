//! Approval-gated deletes (lane B3 / P0-2): signed delete token verification.
//!
//! Token format (shared with implementations/storage/deletion_approval.py):
//!   v1|bucket|key|version_id|approval_id|expiry_epoch|jti|hmac_sha256_hex
//!
//! The token proves a dual-control approval exists (issued only after a
//! requester != approver sign-off, enforced where the token is minted).
//! Verification here enforces: signature, expiry, bucket/key binding and
//! single-use (jti replay cache, optionally persisted to disk).

use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::collections::HashSet;
use std::sync::Mutex;

use crate::config::AppConfig;
use crate::error::StorageError;

type HmacSha256 = Hmac<Sha256>;

pub struct DeleteTokenVerifier {
    key: Vec<u8>,
    used_jtis: Mutex<HashSet<String>>,
    jti_path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteTokenClaims {
    pub bucket: String,
    pub key: String,
    pub version_id: Option<String>,
    pub approval_id: String,
    pub expiry: u64,
    pub jti: String,
}

impl DeleteTokenVerifier {
    pub fn from_config(config: &AppConfig) -> anyhow::Result<Self> {
        let raw = config.delete_token_key.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "DELETE_TOKEN_KEY or DELETE_TOKEN_KEY_URI must be configured; deletes fail closed"
            )
        })?;
        let key_material = if let Some(path) = raw.strip_prefix("file://") {
            std::fs::read(path)?.into_iter().collect::<Vec<u8>>()
        } else if raw.len() == 64 && raw.chars().all(|c| c.is_ascii_hexdigit()) {
            hex::decode(raw)?
        } else {
            raw.into_bytes()
        };
        let jti_path = std::env::var("DELETE_TOKEN_JTI_PATH").ok();
        Ok(Self {
            key: key_material,
            used_jtis: Mutex::new(HashSet::new()),
            jti_path,
        })
    }

    /// Test constructor (also used by the dual-control approval API when it
    /// is added to the gateway binary).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn new_for_test(key: &[u8]) -> Self {
        Self { key: key.to_vec(), used_jtis: Mutex::new(HashSet::new()), jti_path: None }
    }

    fn sign(&self, payload: &str) -> String {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.key).expect("HMAC any length");
        mac.update(payload.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// Mint a token (used by the dual-control approval API and in tests).
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn issue(
        &self,
        bucket: &str,
        key: &str,
        version_id: Option<&str>,
        approval_id: &str,
        ttl_seconds: u64,
    ) -> String {
        let expiry = now_epoch() + ttl_seconds;
        let jti = uuid::Uuid::new_v4().to_string();
        let payload = format!(
            "v1|{}|{}|{}|{}|{}|{}",
            bucket,
            key,
            version_id.unwrap_or(""),
            approval_id,
            expiry,
            jti
        );
        format!("{}|{}", payload, self.sign(&payload))
    }

    pub fn verify(&self, token: &str, bucket: &str, key: &str) -> Result<DeleteTokenClaims, StorageError> {
        let parts: Vec<&str> = token.split('|').collect();
        if parts.len() != 8 || parts[0] != "v1" {
            return Err(StorageError::Forbidden("malformed delete token".into()));
        }
        let (t_bucket, t_key, t_version, approval_id, expiry_text, jti, signature) =
            (parts[1], parts[2], parts[3], parts[4], parts[5], parts[6], parts[7]);

        let payload = parts[..7].join("|");
        let expected = self.sign(&payload);
        if !constant_time_eq(expected.as_bytes(), signature.as_bytes()) {
            return Err(StorageError::Forbidden("delete token signature invalid".into()));
        }
        if t_bucket != bucket || t_key != key {
            return Err(StorageError::Forbidden(format!(
                "delete token bound to {t_bucket}/{t_key}, not {bucket}/{key}"
            )));
        }
        let expiry: u64 = expiry_text
            .parse()
            .map_err(|_| StorageError::Forbidden("delete token expiry malformed".into()))?;
        if expiry < now_epoch() {
            return Err(StorageError::Forbidden("delete token expired".into()));
        }
        {
            let used = self.used_jtis.lock().expect("jti set poisoned");
            if used.contains(jti) || self.jti_seen_on_disk(jti) {
                return Err(StorageError::Forbidden(
                    "delete token already used (single-use)".into(),
                ));
            }
        }
        Ok(DeleteTokenClaims {
            bucket: t_bucket.to_string(),
            key: t_key.to_string(),
            version_id: if t_version.is_empty() { None } else { Some(t_version.to_string()) },
            approval_id: approval_id.to_string(),
            expiry,
            jti: jti.to_string(),
        })
    }

    /// Consume after a successful delete (single-use).
    pub fn consume(&self, claims: &DeleteTokenClaims) {
        let mut used = self.used_jtis.lock().expect("jti set poisoned");
        used.insert(claims.jti.clone());
        if let Some(path) = &self.jti_path {
            use std::io::Write;
            if let Some(parent) = std::path::Path::new(path).parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
                let _ = writeln!(f, "{}", claims.jti);
            }
        }
    }

    fn jti_seen_on_disk(&self, jti: &str) -> bool {
        match &self.jti_path {
            Some(path) => std::fs::read_to_string(path)
                .map(|body| body.lines().any(|l| l.trim() == jti))
                .unwrap_or(false),
            None => false,
        }
    }
}

fn now_epoch() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_verify() {
        let v = DeleteTokenVerifier::new_for_test(b"test-key");
        let token = v.issue("evidence", "kyc/a.pdf", Some("ver1"), "approval-1", 300);
        let claims = v.verify(&token, "evidence", "kyc/a.pdf").unwrap();
        assert_eq!(claims.approval_id, "approval-1");
        assert_eq!(claims.version_id.as_deref(), Some("ver1"));
    }

    #[test]
    fn rejects_tampered_signature() {
        let v = DeleteTokenVerifier::new_for_test(b"test-key");
        let token = v.issue("evidence", "k", None, "a1", 300);
        let mut parts: Vec<&str> = token.split('|').collect();
        parts[4] = "forged-approval";
        let forged = parts.join("|");
        assert!(v.verify(&forged, "evidence", "k").is_err());
    }

    #[test]
    fn rejects_wrong_target() {
        let v = DeleteTokenVerifier::new_for_test(b"test-key");
        let token = v.issue("evidence", "k", None, "a1", 300);
        assert!(v.verify(&token, "evidence", "other-key").is_err());
        assert!(v.verify(&token, "other-bucket", "k").is_err());
    }

    #[test]
    fn rejects_expired() {
        let v = DeleteTokenVerifier::new_for_test(b"test-key");
        // craft an already-expired token with a valid signature
        let expiry = now_epoch() - 10;
        let payload = format!("v1|b|k||a1|{}|j1", expiry);
        let mut mac = <HmacSha256 as Mac>::new_from_slice(b"test-key").unwrap();
        mac.update(payload.as_bytes());
        let token = format!("{}|{}", payload, hex::encode(mac.finalize().into_bytes()));
        assert!(v.verify(&token, "b", "k").is_err());
    }

    #[test]
    fn rejects_replay() {
        let v = DeleteTokenVerifier::new_for_test(b"test-key");
        let token = v.issue("b", "k", None, "a1", 300);
        let claims = v.verify(&token, "b", "k").unwrap();
        v.consume(&claims);
        let err = v.verify(&token, "b", "k").unwrap_err();
        assert!(err.to_string().contains("single-use"));
    }

    #[test]
    fn python_token_format_compatible() {
        // Cross-implementation vector produced by Python:
        //   hmac.new(b"rust-compat-key",
        //            b"v1|evidence|doc.pdf||appr-7|1893456000|jti-fixed",
        //            hashlib.sha256).hexdigest()
        // (same construction as implementations/storage/deletion_approval.py)
        let v = DeleteTokenVerifier::new_for_test(b"rust-compat-key");
        let token = "v1|evidence|doc.pdf||appr-7|1893456000|jti-fixed|\
                     05194f237118af8abf1d6e3a7f917408072d165c0367140c0a65a977e1950037"
            .replace(" ", "");
        let claims = v.verify(&token, "evidence", "doc.pdf").unwrap();
        assert_eq!(claims.approval_id, "appr-7");
        assert_eq!(claims.version_id, None);
    }
}
