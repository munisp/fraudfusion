use axum::{
    extract::State,
    http::{header::AUTHORIZATION, Request, StatusCode},
    middleware::Next,
    response::Response,
};
use serde::Deserialize;
use std::{collections::HashSet, sync::Arc, time::Duration};

use crate::AppState;

#[derive(Clone)]
pub struct KeycloakClient {
    endpoint: String,
    client_id: String,
    client_secret: String,
    allowed_roles: HashSet<String>,
    http_client: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct IntrospectionResponse {
    active: bool,
    sub: Option<String>,
    roles: Option<Vec<String>>,
    realm_access: Option<RealmAccess>,
}

#[derive(Debug, Deserialize)]
struct RealmAccess {
    roles: Option<Vec<String>>,
}

/// Authenticated caller context stored in request extensions.
#[derive(Debug, Clone)]
pub struct AuthContext {
    pub subject: String,
    pub roles: std::collections::HashSet<String>,
}

impl AuthContext {
    pub fn has_role(&self, role: &str) -> bool {
        self.roles.contains(role)
    }
}

impl KeycloakClient {
    pub fn from_config(config: &crate::config::AppConfig) -> anyhow::Result<Self> {
        let endpoint = format!(
            "{}/realms/{}/protocol/openid-connect/token/introspect",
            config.keycloak_url.trim_end_matches('/'),
            config.keycloak_realm
        );
        let allowed_roles = config
            .keycloak_required_roles
            .iter()
            .map(|role| role.trim().to_string())
            .filter(|role| !role.is_empty())
            .collect::<HashSet<_>>();
        if allowed_roles.is_empty() {
            anyhow::bail!("KEYCLOAK_REQUIRED_ROLES must contain at least one role")
        }
        Ok(Self {
            endpoint,
            client_id: config.keycloak_client_id.clone(),
            client_secret: config.keycloak_client_secret.clone(),
            allowed_roles,
            http_client: reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?,
        })
    }

    async fn authorize(&self, bearer_token: &str) -> anyhow::Result<AuthContext> {
        if bearer_token.trim().is_empty() {
            anyhow::bail!("access token is empty")
        }
        let response = self
            .http_client
            .post(&self.endpoint)
            .form(&[
                ("token", bearer_token),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
            ])
            .send()
            .await?
            .error_for_status()?;
        let claims: IntrospectionResponse = response.json().await?;
        if !claims.active {
            anyhow::bail!("Keycloak reports token inactive")
        }
        let mut roles = claims.roles.unwrap_or_default();
        if let Some(realm_access) = claims.realm_access {
            roles.extend(realm_access.roles.unwrap_or_default());
        }
        if !roles.iter().any(|role| self.allowed_roles.contains(role)) {
            anyhow::bail!("token has no permitted storage role")
        }
        let subject = claims.sub.filter(|subject| !subject.is_empty()).ok_or_else(|| anyhow::anyhow!("Keycloak response has no subject"))?;
        Ok(AuthContext { subject, roles: roles.into_iter().collect() })
    }
}

pub async fn require_auth(
    State(state): State<Arc<AppState>>,
    mut request: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    let header = request.headers().get(AUTHORIZATION).and_then(|value| value.to_str().ok()).ok_or(StatusCode::UNAUTHORIZED)?;
    let token = header.strip_prefix("Bearer ").ok_or(StatusCode::UNAUTHORIZED)?;
    let context = state.auth.authorize(token).await.map_err(|error| {
        tracing::warn!(error = %error, "storage gateway authentication denied");
        StatusCode::FORBIDDEN
    })?;
    request.extensions_mut().insert(context);
    Ok(next.run(request).await)
}
