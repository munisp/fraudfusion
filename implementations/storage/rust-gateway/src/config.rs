use serde::Deserialize;
use std::env;

/// Application configuration loaded from explicit environment variables.
#[derive(Debug, Clone, Deserialize)]
pub struct AppConfig {
    pub host: String,
    pub port: u16,

    pub rustfs_endpoint: String,
    pub rustfs_access_key: String,
    pub rustfs_secret_key: String,
    pub rustfs_region: String,

    pub keycloak_url: String,
    pub keycloak_realm: String,
    pub keycloak_client_id: String,
    pub keycloak_client_secret: String,
    pub keycloak_required_roles: Vec<String>,
    pub cors_allowed_origins: Vec<String>,

    pub enable_validation: bool,
    pub max_file_size: u64,
    pub enable_audit_log: bool,
    pub cache_ttl_seconds: u64,
    pub cache_max_size_mb: u64,

    // --- anti-wipe / WORM policy (lane B3) ---
    pub enable_versioning: bool,
    pub object_lock_mode: String,
    pub object_lock_retention_days: u32,
    pub worm_enforce_on_boot: bool,
    pub worm_buckets: Vec<String>,
    pub keycloak_delete_role: String,
    pub delete_token_ttl_seconds: u64,
    pub delete_token_key: Option<String>,
    pub soft_delete_tombstone_retention_days: u64,
    pub dual_control_required: bool,
    pub lockdown_state_path: String,
}

impl AppConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let rustfs_endpoint = required("RUSTFS_ENDPOINT").or_else(|_| required("S3_ENDPOINT"))?;
        let allow_insecure = bool_env("RUSTFS_ALLOW_INSECURE_HTTP", false)?;
        if !allow_insecure && !rustfs_endpoint.starts_with("https://") {
            anyhow::bail!("RUSTFS_ENDPOINT must use https:// unless RUSTFS_ALLOW_INSECURE_HTTP=true is explicitly set for local development")
        }
        let keycloak_url = required("KEYCLOAK_URL")?;
        if !keycloak_url.starts_with("https://") {
            anyhow::bail!("KEYCLOAK_URL must use https://")
        }
        let cors_allowed_origins = csv_required("CORS_ALLOWED_ORIGINS")?;
        for origin in &cors_allowed_origins {
            if origin == "*" || !(origin.starts_with("https://") || origin.starts_with("http://localhost:")) {
                anyhow::bail!("CORS_ALLOWED_ORIGINS must contain explicit HTTPS origins; localhost is allowed only for development")
            }
        }

        Ok(Self {
            host: env::var("GATEWAY_HOST").unwrap_or_else(|_| "0.0.0.0".to_string()),
            port: env::var("GATEWAY_PORT").unwrap_or_else(|_| "8080".to_string()).parse()?,
            rustfs_endpoint,
            rustfs_access_key: required("RUSTFS_ACCESS_KEY").or_else(|_| required("S3_ACCESS_KEY"))?,
            rustfs_secret_key: required("RUSTFS_SECRET_KEY").or_else(|_| required("S3_SECRET_KEY"))?,
            rustfs_region: env::var("RUSTFS_REGION").or_else(|_| env::var("AWS_REGION")).unwrap_or_else(|_| "us-east-1".to_string()),
            keycloak_url,
            keycloak_realm: required("KEYCLOAK_REALM")?,
            keycloak_client_id: required("KEYCLOAK_CLIENT_ID")?,
            keycloak_client_secret: required("KEYCLOAK_CLIENT_SECRET")?,
            keycloak_required_roles: csv_required("KEYCLOAK_REQUIRED_ROLES")?,
            cors_allowed_origins,
            enable_validation: bool_env("ENABLE_VALIDATION", true)?,
            max_file_size: env::var("MAX_FILE_SIZE").unwrap_or_else(|_| "104857600".to_string()).parse()?,
            enable_audit_log: bool_env("ENABLE_AUDIT_LOG", true)?,
            cache_ttl_seconds: env::var("CACHE_TTL_SECONDS").unwrap_or_else(|_| "300".to_string()).parse()?,
            cache_max_size_mb: env::var("CACHE_MAX_SIZE_MB").unwrap_or_else(|_| "512".to_string()).parse()?,
            enable_versioning: bool_env("RUSTFS_ENABLE_VERSIONING", true)?,
            object_lock_mode: {
                let mode = env::var("OBJECT_LOCK_MODE").unwrap_or_else(|_| "COMPLIANCE".to_string()).to_uppercase();
                if mode != "COMPLIANCE" && mode != "GOVERNANCE" && mode != "OFF" {
                    anyhow::bail!("OBJECT_LOCK_MODE must be COMPLIANCE, GOVERNANCE or OFF")
                }
                mode
            },
            object_lock_retention_days: env::var("OBJECT_LOCK_RETENTION_DAYS").unwrap_or_else(|_| "2555".to_string()).parse()?,
            worm_enforce_on_boot: bool_env("WORM_ENFORCE_ON_BOOT", true)?,
            worm_buckets: env::var("WORM_BUCKETS").unwrap_or_default()
                .split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect(),
            keycloak_delete_role: env::var("KEYCLOAK_DELETE_ROLE").unwrap_or_else(|_| "storage_admin".to_string()),
            delete_token_ttl_seconds: env::var("DELETE_TOKEN_TTL_SECONDS").unwrap_or_else(|_| "300".to_string()).parse()?,
            delete_token_key: env::var("DELETE_TOKEN_KEY").ok().filter(|v| !v.trim().is_empty())
                .or_else(|| env::var("DELETE_TOKEN_KEY_URI").ok().filter(|v| !v.trim().is_empty())),
            soft_delete_tombstone_retention_days: env::var("SOFT_DELETE_TOMBSTONE_RETENTION_DAYS").unwrap_or_else(|_| "90".to_string()).parse()?,
            dual_control_required: bool_env("DUAL_CONTROL_REQUIRED", true)?,
            lockdown_state_path: env::var("STORAGE_LOCKDOWN_STATE").unwrap_or_else(|_| "/var/lib/fraudfusion/storage/lockdown.json".to_string()),
        })
    }
}

fn required(name: &str) -> anyhow::Result<String> {
    let value = env::var(name).map_err(|_| anyhow::anyhow!("{name} must be configured"))?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        anyhow::bail!("{name} must not be empty")
    }
    Ok(trimmed.to_string())
}

fn csv_required(name: &str) -> anyhow::Result<Vec<String>> {
    let values = required(name)?
        .split(',')
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    if values.is_empty() {
        anyhow::bail!("{name} must contain at least one value")
    }
    Ok(values)
}

fn bool_env(name: &str, default: bool) -> anyhow::Result<bool> {
    match env::var(name) {
        Ok(value) => value.parse::<bool>().map_err(|error| anyhow::anyhow!("{name} must be true or false: {error}")),
        Err(_) => Ok(default),
    }
}
