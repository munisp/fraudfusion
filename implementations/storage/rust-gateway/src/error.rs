//! Error types for the Storage Gateway

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};

/// Gateway error type mapped to HTTP responses.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// Upstream storage backend failure (RustFS/S3) — 502
    #[error("storage backend error: {0}")]
    StorageBackend(String),

    /// Malformed client request — 400
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Object or bucket not found — 404
    #[error("not found: {0}")]
    NotFound(String),

    /// Authenticated but not authorized (role/token) — 403
    #[error("forbidden: {0}")]
    Forbidden(String),

    /// Storage is in read-only ransomware lockdown — 503
    #[error("storage lockdown active: {0}")]
    Lockdown(String),

    /// WORM/retention policy refuses the destructive operation — 403
    #[error("worm policy violation: {0}")]
    WormViolation(String),
}

impl StorageError {
    fn status(&self) -> StatusCode {
        match self {
            StorageError::StorageBackend(_) => StatusCode::BAD_GATEWAY,
            StorageError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
            StorageError::NotFound(_) => StatusCode::NOT_FOUND,
            StorageError::Forbidden(_) | StorageError::WormViolation(_) => StatusCode::FORBIDDEN,
            StorageError::Lockdown(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

impl IntoResponse for StorageError {
    fn into_response(self) -> Response {
        let status = self.status();
        let body = Json(serde_json::json!({
            "error": self.to_string(),
            "kind": match self {
                StorageError::StorageBackend(_) => "storage_backend",
                StorageError::InvalidRequest(_) => "invalid_request",
                StorageError::NotFound(_) => "not_found",
                StorageError::Forbidden(_) => "forbidden",
                StorageError::Lockdown(_) => "lockdown",
                StorageError::WormViolation(_) => "worm_violation",
            },
        }));
        (status, body).into_response()
    }
}
