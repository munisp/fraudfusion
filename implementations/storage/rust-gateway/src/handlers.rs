//! HTTP handlers for the Storage Gateway API

use axum::{
    body::Bytes,
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use chrono::{DateTime, Utc};

use crate::auth::AuthContext;
use crate::error::StorageError;
use crate::models::{
    AuditEntry, BucketInfo, CreateBucketRequest, HealthResponse, BackendHealth,
    ListObjectsResponse, PresignedUrlResponse, StorageOperation, UploadResult,
};
use crate::{deletion, worm, AppState};

const DELETE_TOKEN_HEADER: &str = "x-delete-token";
const HARD_DELETE_HEADER: &str = "x-hard-delete";

fn record(state: &AppState, operation: StorageOperation, bucket: &str, key: &str,
          subject: Option<&str>, success: bool, error: Option<String>) {
    state.storage.record_audit(AuditEntry {
        timestamp: Utc::now(),
        operation,
        bucket: bucket.to_string(),
        key: key.to_string(),
        subject: subject.map(|s| s.to_string()),
        success,
        error_message: error,
        metadata: Default::default(),
    });
}

/// Health check endpoint
pub async fn health_check(State(state): State<Arc<AppState>>) -> Json<HealthResponse> {
    let (healthy, latency) = state.storage.health_check().await.unwrap_or((false, None));

    Json(HealthResponse {
        status: if healthy { "healthy" } else { "unhealthy" }.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        backend: BackendHealth {
            status: if healthy { "healthy" } else { "unhealthy" }.to_string(),
            endpoint: state.config.rustfs_endpoint.clone(),
            latency_ms: latency,
        },
        uptime_seconds: 0, // TODO: Track actual uptime
    })
}

/// Readiness check endpoint
pub async fn readiness_check(State(state): State<Arc<AppState>>) -> Result<StatusCode, StorageError> {
    let (healthy, _) = state.storage.health_check().await?;

    if healthy {
        Ok(StatusCode::OK)
    } else {
        Err(StorageError::StorageBackend("Backend not ready".to_string()))
    }
}

/// Metrics endpoint (Prometheus format)
pub async fn metrics(State(state): State<Arc<AppState>>) -> String {
    let (cache_entries, cache_size) = state.storage.cache_stats();
    let audit_log = state.storage.get_audit_log().await;

    let uploads = audit_log.iter().filter(|e| e.operation == crate::models::StorageOperation::Upload).count();
    let downloads = audit_log.iter().filter(|e| e.operation == crate::models::StorageOperation::Download).count();
    let deletes = audit_log.iter().filter(|e| e.operation == crate::models::StorageOperation::Delete).count();
    let errors = audit_log.iter().filter(|e| !e.success).count();
    let lockdown = if worm::is_read_only(&state.config) { 1 } else { 0 };

    format!(
        r#"# HELP storage_gateway_cache_entries Number of entries in cache
# TYPE storage_gateway_cache_entries gauge
storage_gateway_cache_entries {}

# HELP storage_gateway_cache_size_bytes Size of cache in bytes
# TYPE storage_gateway_cache_size_bytes gauge
storage_gateway_cache_size_bytes {}

# HELP storage_gateway_uploads_total Total number of uploads
# TYPE storage_gateway_uploads_total counter
storage_gateway_uploads_total {}

# HELP storage_gateway_downloads_total Total number of downloads
# TYPE storage_gateway_downloads_total counter
storage_gateway_downloads_total {}

# HELP storage_gateway_errors_total Total number of errors
# TYPE storage_gateway_errors_total counter
storage_gateway_errors_total {}

# HELP storage_gateway_deletes_total Total number of delete (tombstone) operations
# TYPE storage_gateway_deletes_total counter
storage_gateway_deletes_total {}

# HELP storage_lockdown_active Whether the gateway is in ransomware read-only lockdown
# TYPE storage_lockdown_active gauge
storage_lockdown_active {}
"#,
        cache_entries, cache_size, uploads, downloads, errors, deletes, lockdown
    )
}

/// List all buckets
pub async fn list_buckets(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<BucketInfo>>, StorageError> {
    let buckets = state.storage.list_buckets().await?;
    Ok(Json(buckets))
}

/// Create a new bucket (versioning + object lock attached immediately)
pub async fn create_bucket(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateBucketRequest>,
) -> Result<StatusCode, StorageError> {
    worm::assert_writable(&state.config)?;
    state.storage.create_bucket(&request.name).await?;
    worm::protect_new_bucket(&state.storage, &state.config, &request.name).await?;
    record(&state, StorageOperation::List, &request.name, "", None, true, None);
    Ok(StatusCode::CREATED)
}

/// Query parameters for list objects
#[derive(Debug, Deserialize)]
pub struct ListObjectsQuery {
    prefix: Option<String>,
    max_keys: Option<i32>,
    continuation_token: Option<String>,
}

/// List objects in a bucket
pub async fn list_objects(
    State(state): State<Arc<AppState>>,
    Path(bucket): Path<String>,
    Query(query): Query<ListObjectsQuery>,
) -> Result<Json<ListObjectsResponse>, StorageError> {
    let response = state
        .storage
        .list_objects(
            &bucket,
            query.prefix.as_deref(),
            query.max_keys,
            query.continuation_token.as_deref(),
        )
        .await?;

    Ok(Json(response))
}

/// Get object data (tombstoned objects read as 404)
pub async fn get_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
) -> Result<Bytes, StorageError> {
    if state.storage.is_tombstoned(&bucket, &key).await {
        record(&state, StorageOperation::Download, &bucket, &key, None, false,
               Some("tombstoned".into()));
        return Err(StorageError::NotFound(format!(
            "{bucket}/{key} has been soft-deleted (tombstoned)"
        )));
    }
    let data = state.storage.get_object(&bucket, &key).await?;
    Ok(Bytes::from(data))
}

/// Put object data. Bucket versioning is enforced (fail closed) so a PUT on
/// an existing key creates a new version instead of silently destroying the
/// previous content; the returned version_id identifies it.
pub async fn put_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<UploadResult>, StorageError> {
    worm::assert_writable(&state.config)?;
    ensure_versioned(&state, &bucket).await?;

    let overwriting = state.storage.object_exists(&bucket, &key).await;

    let content_type = mime_guess::from_path(&key)
        .first()
        .map(|m| m.to_string());

    let metadata = vec![
        ("upload-timestamp".to_string(), Utc::now().to_rfc3339()),
        ("overwrite".to_string(), overwriting.to_string()),
    ];

    let result = state
        .storage
        .put_object(&bucket, &key, body.to_vec(), content_type.as_deref(), Some(metadata))
        .await?;

    record(&state, StorageOperation::Upload, &bucket, &key, None, true, None);
    if overwriting {
        tracing::warn!(bucket, key, "PUT overwrote existing key (new version created)");
    }
    Ok(Json(result))
}

async fn ensure_versioned(state: &AppState, bucket: &str) -> Result<(), StorageError> {
    if !state.config.enable_versioning {
        return Ok(());
    }
    let status = state.storage.get_bucket_versioning(bucket).await?;
    if status != "Enabled" {
        state.storage.enable_bucket_versioning(bucket).await?;
        let status = state.storage.get_bucket_versioning(bucket).await?;
        if status != "Enabled" {
            return Err(StorageError::WormViolation(format!(
                "bucket {bucket} versioning could not be enabled; refusing overwrite-capable write (fail closed)"
            )));
        }
    }
    Ok(())
}

/// Delete object.
///
/// Default path is a SOFT delete: a tombstone marker object is written and the
/// original object (all versions) is retained. Physical deletion requires:
///   1. caller role == KEYCLOAK_DELETE_ROLE (default `storage_admin`)
///   2. a valid, unexpired, single-use signed delete token (X-Delete-Token)
///      minted only after a dual-control approval
///   3. WORM retention expiry for regulated buckets
///   4. tombstone grace window (SOFT_DELETE_TOMBSTONE_RETENTION_DAYS)
pub async fn delete_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: axum::http::HeaderMap,
    auth: Option<axum::extract::Extension<AuthContext>>,
) -> Result<StatusCode, StorageError> {
    worm::assert_writable(&state.config)?;

    let auth = auth.map(|axum::extract::Extension(ctx)| ctx);
    let subject = auth.as_ref().map(|c| c.subject.clone());

    let hard_delete = headers
        .get(HARD_DELETE_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);

    if !hard_delete {
        // Soft delete (tombstone). Still requires an authenticated caller.
        state.storage.soft_delete_object(
            &bucket,
            &key,
            subject.as_deref().unwrap_or("unknown"),
            "api-delete",
            None,
        ).await?;
        record(&state, StorageOperation::Delete, &bucket, &key, subject.as_deref(), true, None);
        return Ok(StatusCode::NO_CONTENT);
    }

    // --- hard delete path: every barrier fails closed -------------------
    let ctx = auth.ok_or_else(|| StorageError::Forbidden("authentication context missing".into()))?;
    if !ctx.has_role(&state.config.keycloak_delete_role) {
        record(&state, StorageOperation::Delete, &bucket, &key, Some(&ctx.subject), false,
               Some("missing delete role".into()));
        return Err(StorageError::Forbidden(format!(
            "hard delete requires the '{}' role", state.config.keycloak_delete_role
        )));
    }

    let verifier = deletion::DeleteTokenVerifier::from_config(&state.config)
        .map_err(|e| StorageError::Forbidden(format!("delete token verifier unavailable: {e}")))?;
    let token = headers
        .get(DELETE_TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| StorageError::Forbidden("X-Delete-Token header required for hard delete".into()))?;
    let claims = verifier.verify(token, &bucket, &key)?;

    // WORM retention gate
    let (_, last_modified, _) = state.storage.head_object(&bucket, &key).await.ok()
        .unwrap_or((0, None, None));
    let last_modified_dt = last_modified
        .as_deref()
        .and_then(|s| DateTime::parse_from_rfc2822(s).ok().map(|d| d.with_timezone(&Utc)))
        .or_else(|| last_modified.as_deref().and_then(|s| DateTime::parse_from_rfc3339(s).ok().map(|d| d.with_timezone(&Utc))));
    worm::assert_can_hard_delete(&state.config, &bucket, &key, last_modified_dt)?;

    state.storage.delete_object(&bucket, &key).await?;
    // remove the tombstone too if present
    if state.storage.is_tombstoned(&bucket, &key).await {
        let _ = state.storage.delete_object(&bucket, &format!("{key}.tombstone")).await;
    }
    verifier.consume(&claims);
    record(&state, StorageOperation::Delete, &bucket, &key, Some(&ctx.subject), true,
           Some(format!("hard_delete approval_id={}", claims.approval_id)));
    tracing::warn!(bucket, key, approval_id = %claims.approval_id, subject = %ctx.subject,
                   "hard delete executed under dual-control token");
    Ok(StatusCode::NO_CONTENT)
}

/// Query parameters for presigned URL
#[derive(Debug, Deserialize)]
pub struct PresignQuery {
    expires_in: Option<u64>,
}

/// Generate presigned URL
pub async fn presign_url(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(query): Query<PresignQuery>,
) -> Result<Json<PresignedUrlResponse>, StorageError> {
    let expires_in = query.expires_in.unwrap_or(3600);
    let response = state.storage.presign_url(&bucket, &key, expires_in).await?;
    Ok(Json(response))
}

/// Upload via multipart form
pub async fn upload_multipart(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<Vec<UploadResult>>, StorageError> {
    worm::assert_writable(&state.config)?;
    let mut results = Vec::new();
    let mut bucket = String::new();

    while let Some(field) = multipart.next_field().await.map_err(|e| {
        StorageError::InvalidRequest(format!("Failed to read multipart field: {}", e))
    })? {
        let name = field.name().unwrap_or("").to_string();

        if name == "bucket" {
            bucket = field.text().await.map_err(|e| {
                StorageError::InvalidRequest(format!("Failed to read bucket name: {}", e))
            })?;
            continue;
        }

        if name == "file" {
            let filename = field
                .file_name()
                .map(|s| s.to_string())
                .unwrap_or_else(|| format!("upload_{}", uuid::Uuid::new_v4()));

            let content_type = field
                .content_type()
                .map(|s| s.to_string());

            let data = field.bytes().await.map_err(|e| {
                StorageError::InvalidRequest(format!("Failed to read file data: {}", e))
            })?;

            if bucket.is_empty() {
                return Err(StorageError::InvalidRequest(
                    "Bucket name must be provided before file".to_string(),
                ));
            }

            ensure_versioned(&state, &bucket).await?;
            let metadata = vec![
                ("upload-timestamp".to_string(), Utc::now().to_rfc3339()),
            ];
            let result = state
                .storage
                .put_object(&bucket, &filename, data.to_vec(), content_type.as_deref(), Some(metadata))
                .await?;
            record(&state, StorageOperation::Upload, &bucket, &filename, None, true, None);

            results.push(result);
        }
    }

    Ok(Json(results))
}
