//! WORM / immutability enforcement (lane B3 / P0-1).
//!
//! - Boot-time (fail closed): asserts bucket versioning + object lock on all
//!   regulated buckets when `WORM_ENFORCE_ON_BOOT=true`.
//! - Request-time: `assert_can_hard_delete` enforces retention before any
//!   physical delete; `is_read_only` implements the ransomware lockdown check.

use chrono::{DateTime, Duration, Utc};
use serde::Deserialize;

use crate::config::AppConfig;
use crate::error::StorageError;
use crate::storage::StorageClient;

/// Whether a bucket is covered by the WORM policy. An empty WORM_BUCKETS list
/// means the policy applies to every bucket (safest default).
pub fn bucket_is_regulated(config: &AppConfig, bucket: &str) -> bool {
    config.worm_buckets.is_empty() || config.worm_buckets.iter().any(|b| b == bucket)
}

/// Boot-time assertion: versioning must be Enabled on every regulated bucket
/// (and a default object-lock rule attached when OBJECT_LOCK_MODE != OFF).
/// Fails closed: any assertion failure aborts startup.
pub async fn enforce_on_boot(storage: &StorageClient, config: &AppConfig) -> anyhow::Result<()> {
    if !config.worm_enforce_on_boot {
        tracing::warn!("WORM_ENFORCE_ON_BOOT=false — immutability boot checks skipped");
        return Ok(());
    }

    let buckets = storage.list_buckets().await?;
    let targets: Vec<String> = if config.worm_buckets.is_empty() {
        buckets.iter().map(|b| b.name.clone()).collect()
    } else {
        config.worm_buckets.clone()
    };

    for bucket in &targets {
        if config.enable_versioning {
            let status = storage.get_bucket_versioning(bucket).await?;
            if status != "Enabled" {
                tracing::warn!(bucket, status, "bucket versioning not enabled; enabling");
                storage.enable_bucket_versioning(bucket).await?;
                let status = storage.get_bucket_versioning(bucket).await?;
                anyhow::ensure!(
                    status == "Enabled",
                    "bucket {bucket} versioning could not be enabled (status {status}); refusing to serve (fail closed)"
                );
            }
        }
        if config.object_lock_mode != "OFF" {
            match storage
                .put_object_lock_configuration(bucket, &config.object_lock_mode, config.object_lock_retention_days)
                .await
            {
                Ok(()) => tracing::info!(bucket, mode = %config.object_lock_mode, days = config.object_lock_retention_days, "object lock asserted"),
                Err(e) => {
                    // RustFS/minio variants without object-lock support: fail
                    // closed only for COMPLIANCE; GOVERNANCE degrades to
                    // gateway-level retention checks.
                    if config.object_lock_mode == "COMPLIANCE" {
                        return Err(anyhow::anyhow!(
                            "bucket {bucket} object lock assertion failed: {e}; refusing to serve COMPLIANCE data on an unlocked bucket"
                        ));
                    }
                    tracing::error!(bucket, error = %e, "object lock unavailable; gateway-level governance retention still enforced");
                }
            }
        }
    }
    Ok(())
}

/// Attach protection to a newly created bucket (called from create_bucket).
pub async fn protect_new_bucket(storage: &StorageClient, config: &AppConfig, bucket: &str) -> Result<(), StorageError> {
    if config.enable_versioning {
        storage.enable_bucket_versioning(bucket).await?;
    }
    if config.object_lock_mode != "OFF" && bucket_is_regulated(config, bucket) {
        storage
            .put_object_lock_configuration(bucket, &config.object_lock_mode, config.object_lock_retention_days)
            .await
            .map_err(|e| {
                if config.object_lock_mode == "COMPLIANCE" {
                    StorageError::WormViolation(format!(
                        "bucket {bucket} cannot serve COMPLIANCE data without object lock: {e}"
                    ))
                } else {
                    tracing::error!(bucket, error = %e, "object lock unavailable on new bucket");
                    StorageError::StorageBackend(format!("object lock setup: {e}"))
                }
            })?;
    }
    Ok(())
}

/// Request-time retention gate for physical deletes.
///
/// COMPLIANCE: refuse while within retention — absolutely.
/// GOVERNANCE: refuse within retention (soft-delete remains available).
/// OFF: no retention block.
pub fn assert_can_hard_delete(
    config: &AppConfig,
    bucket: &str,
    key: &str,
    last_modified: Option<DateTime<Utc>>,
) -> Result<(), StorageError> {
    if config.object_lock_mode == "OFF" || !bucket_is_regulated(config, bucket) {
        return Ok(());
    }
    let Some(modified) = last_modified else {
        // Unknown age -> fail closed.
        return Err(StorageError::WormViolation(format!(
            "{bucket}/{key}: object age unknown; hard delete refused (fail closed)"
        )));
    };
    let retention_until = modified + Duration::days(config.object_lock_retention_days as i64);
    if Utc::now() < retention_until {
        return Err(StorageError::WormViolation(format!(
            "{bucket}/{key}: {} retention active until {}; hard delete blocked",
            config.object_lock_mode,
            retention_until.to_rfc3339()
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Ransomware lockdown (read-only switch shared with ransomware_guard)
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct LockdownFile {
    read_only: bool,
}

/// STORAGE_READ_ONLY env (fast path, process-local) OR the shared lockdown
/// state file written by services/python/ransomware_guard.
pub fn is_read_only(config: &AppConfig) -> bool {
    if std::env::var("STORAGE_READ_ONLY")
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "1" | "true" | "yes"))
        .unwrap_or(false)
    {
        return true;
    }
    match std::fs::read_to_string(&config.lockdown_state_path) {
        Ok(body) => serde_json::from_str::<LockdownFile>(&body)
            .map(|f| f.read_only)
            .unwrap_or(false),
        Err(_) => false,
    }
}

pub fn assert_writable(config: &AppConfig) -> Result<(), StorageError> {
    if is_read_only(config) {
        return Err(StorageError::Lockdown(
            "storage is in READ-ONLY ransomware lockdown; writes/deletes rejected".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config(mode: &str, retention_days: u32) -> AppConfig {
        AppConfig {
            host: "127.0.0.1".into(),
            port: 8080,
            rustfs_endpoint: "https://rustfs.local".into(),
            rustfs_access_key: "ak".into(),
            rustfs_secret_key: "sk".into(),
            rustfs_region: "us-east-1".into(),
            keycloak_url: "https://kc.local".into(),
            keycloak_realm: "r".into(),
            keycloak_client_id: "c".into(),
            keycloak_client_secret: "s".into(),
            keycloak_required_roles: vec!["storage_user".into()],
            cors_allowed_origins: vec!["https://app.local".into()],
            enable_validation: true,
            max_file_size: 1024,
            enable_audit_log: true,
            cache_ttl_seconds: 60,
            cache_max_size_mb: 16,
            enable_versioning: true,
            object_lock_mode: mode.into(),
            object_lock_retention_days: retention_days,
            worm_enforce_on_boot: false,
            worm_buckets: vec![],
            keycloak_delete_role: "storage_admin".into(),
            delete_token_ttl_seconds: 300,
            delete_token_key: Some("0123456789abcdef".repeat(4)),
            soft_delete_tombstone_retention_days: 90,
            dual_control_required: true,
            lockdown_state_path: "/nonexistent/lockdown.json".into(),
        }
    }

    #[test]
    fn compliance_blocks_recent_object() {
        let cfg = test_config("COMPLIANCE", 2555);
        let recent = Utc::now() - Duration::days(30);
        let err = assert_can_hard_delete(&cfg, "evidence", "kyc/a.pdf", Some(recent)).unwrap_err();
        assert!(matches!(err, StorageError::WormViolation(_)));
    }

    #[test]
    fn compliance_allows_expired_retention() {
        let cfg = test_config("COMPLIANCE", 2555);
        let old = Utc::now() - Duration::days(3000);
        assert!(assert_can_hard_delete(&cfg, "evidence", "kyc/a.pdf", Some(old)).is_ok());
    }

    #[test]
    fn unknown_age_fails_closed() {
        let cfg = test_config("GOVERNANCE", 2555);
        assert!(assert_can_hard_delete(&cfg, "evidence", "k", None).is_err());
    }

    #[test]
    fn off_mode_allows() {
        let cfg = test_config("OFF", 2555);
        assert!(assert_can_hard_delete(&cfg, "evidence", "k", None).is_ok());
    }

    #[test]
    fn unlisted_bucket_not_regulated() {
        let mut cfg = test_config("COMPLIANCE", 2555);
        cfg.worm_buckets = vec!["evidence".into()];
        assert!(bucket_is_regulated(&cfg, "evidence"));
        assert!(!bucket_is_regulated(&cfg, "tmp"));
        assert!(assert_can_hard_delete(&cfg, "tmp", "k", None).is_ok());
    }

    #[test]
    fn lockdown_env_flips_read_only() {
        let cfg = test_config("COMPLIANCE", 2555);
        assert!(!is_read_only(&cfg));
        std::env::set_var("STORAGE_READ_ONLY", "true");
        assert!(is_read_only(&cfg));
        assert!(matches!(assert_writable(&cfg), Err(StorageError::Lockdown(_))));
        std::env::remove_var("STORAGE_READ_ONLY");
    }
}
