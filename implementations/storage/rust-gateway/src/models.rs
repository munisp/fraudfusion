//! Data models for the Storage Gateway API

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Storage operation types (audit)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StorageOperation {
    Upload,
    Download,
    Delete,
    List,
    Copy,
    Presign,
}

/// Append-only in-memory audit entry mirror. The authoritative sink is the
/// HMAC-chained audit ledger; this ring backs /metrics and debugging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub timestamp: DateTime<Utc>,
    pub operation: StorageOperation,
    pub bucket: String,
    pub key: String,
    pub subject: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

/// Bucket listing entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BucketInfo {
    pub name: String,
    pub creation_date: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CreateBucketRequest {
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub backend: BackendHealth,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct BackendHealth {
    pub status: String,
    pub endpoint: String,
    pub latency_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectMetadata {
    pub key: String,
    pub size: u64,
    pub etag: String,
    pub last_modified: Option<String>,
    pub content_type: Option<String>,
    pub version_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ListObjectsResponse {
    pub objects: Vec<ObjectMetadata>,
    pub key_count: usize,
    pub is_truncated: bool,
    pub next_continuation_token: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PresignedUrlResponse {
    pub url: String,
    pub expires_in: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct UploadResult {
    pub bucket: String,
    pub key: String,
    pub etag: String,
    pub size: u64,
    pub version_id: Option<String>,
    pub content_type: Option<String>,
}

/// Tombstone metadata written on soft-delete.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TombstoneMetadata {
    pub deleted_by: String,
    pub deleted_at: String,
    pub reason: String,
    pub approval_id: Option<String>,
}

pub const TOMBSTONE_SUFFIX: &str = ".tombstone";
pub const TOMBSTONE_CONTENT_TYPE: &str = "application/x-tombstone";
