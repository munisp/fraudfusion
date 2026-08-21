//! HTTP handlers for the Storage Gateway API

use axum::{
    body::Bytes,
    extract::{Multipart, Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::Deserialize;
use std::sync::Arc;

use crate::error::StorageError;
use crate::models::{
    BucketInfo, CreateBucketRequest, HealthResponse, BackendHealth,
    ListObjectsResponse, ObjectMetadata, PresignedUrlResponse, UploadResult,
};
use crate::AppState;

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
    let errors = audit_log.iter().filter(|e| !e.success).count();

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
"#,
        cache_entries, cache_size, uploads, downloads, errors
    )
}

/// List all buckets
pub async fn list_buckets(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<BucketInfo>>, StorageError> {
    let buckets = state.storage.list_buckets().await?;
    Ok(Json(buckets))
}

/// Create a new bucket
pub async fn create_bucket(
    State(state): State<Arc<AppState>>,
    Json(request): Json<CreateBucketRequest>,
) -> Result<StatusCode, StorageError> {
    state.storage.create_bucket(&request.name).await?;
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

/// Get object data
pub async fn get_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
) -> Result<Bytes, StorageError> {
    let data = state.storage.get_object(&bucket, &key).await?;
    Ok(Bytes::from(data))
}

/// Put object data
pub async fn put_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
    body: Bytes,
) -> Result<Json<UploadResult>, StorageError> {
    let content_type = mime_guess::from_path(&key)
        .first()
        .map(|m| m.to_string());

    let result = state
        .storage
        .put_object(&bucket, &key, body.to_vec(), content_type.as_deref(), None)
        .await?;

    Ok(Json(result))
}

/// Delete object
pub async fn delete_object(
    State(state): State<Arc<AppState>>,
    Path((bucket, key)): Path<(String, String)>,
) -> Result<StatusCode, StorageError> {
    state.storage.delete_object(&bucket, &key).await?;
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

            let result = state
                .storage
                .put_object(&bucket, &filename, data.to_vec(), content_type.as_deref(), None)
                .await?;

            results.push(result);
        }
    }

    Ok(Json(results))
}
