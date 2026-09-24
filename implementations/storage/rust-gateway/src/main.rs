//! FraudFusion Storage Gateway
//!
//! High-performance storage gateway service built in Rust for the FraudFusion Platform.
//! Provides a unified API for object storage operations using RustFS as the backend.
//!
//! Features:
//! - S3-compatible storage operations via RustFS
//! - Content validation and virus scanning integration
//! - Audit logging for all operations
//! - Moka cache for frequently accessed objects
//! - Prometheus metrics
//! - Health checks

mod auth;
mod config;
mod deletion;
mod error;
mod handlers;
mod models;
mod storage;
mod worm;

use axum::{
    http::{header::{AUTHORIZATION, CONTENT_TYPE}, HeaderValue, Method},
    middleware,
    routing::{delete, get, post},
    Router,
};
use std::sync::Arc;
use tower_http::{
    cors::{AllowOrigin, CorsLayer},
    trace::TraceLayer,
    compression::CompressionLayer,
};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::auth::KeycloakClient;
use crate::config::AppConfig;
use crate::storage::StorageClient;

/// Application state shared across handlers
pub struct AppState {
    pub storage: StorageClient,
    pub config: AppConfig,
    pub auth: KeycloakClient,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "storage_gateway=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = AppConfig::from_env()?;
    tracing::info!("Starting FraudFusion Storage Gateway v{}", env!("CARGO_PKG_VERSION"));
    tracing::info!("RustFS endpoint: {}", config.rustfs_endpoint);

    let storage = StorageClient::new(&config).await?;

    // Anti-wipe boot assertion (fail closed): versioning + object lock on all
    // regulated buckets before serving traffic.
    worm::enforce_on_boot(&storage, &config).await?;

    let auth = KeycloakClient::from_config(&config)?;
    let state = Arc::new(AppState { storage, config: config.clone(), auth });
    let allowed_origins = config
        .cors_allowed_origins
        .iter()
        .map(|origin| origin.parse::<HeaderValue>())
        .collect::<Result<Vec<_>, _>>()?;

    let protected_routes = Router::new()
        .route("/api/v1/buckets", get(handlers::list_buckets))
        .route("/api/v1/buckets", post(handlers::create_bucket))
        .route("/api/v1/buckets/:bucket/objects", get(handlers::list_objects))
        .route("/api/v1/buckets/:bucket/objects/*key", get(handlers::get_object))
        .route("/api/v1/buckets/:bucket/objects/*key", post(handlers::put_object))
        .route("/api/v1/buckets/:bucket/objects/*key", delete(handlers::delete_object))
        .route("/api/v1/buckets/:bucket/presign/*key", get(handlers::presign_url))
        .route("/api/v1/upload", post(handlers::upload_multipart))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::require_auth));

    let app = Router::new()
        .route("/health", get(handlers::health_check))
        .route("/ready", get(handlers::readiness_check))
        .route("/metrics", get(handlers::metrics))
        .merge(protected_routes)
        .with_state(state)
        .layer(TraceLayer::new_for_http())
        .layer(CompressionLayer::new())
        .layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(allowed_origins))
                .allow_methods([Method::GET, Method::POST, Method::DELETE])
                .allow_headers([AUTHORIZATION, CONTENT_TYPE]),
        );

    let addr = format!("{}:{}", config.host, config.port);
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
