use agentpin::wba;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::{header, HeaderMap};
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::state::AppState;

/// Serialize `doc` as a JSON response, or answer 500 instead of a 200 with
/// an empty body when serialization fails (AP-23).
fn json_response<T: serde::Serialize>(doc: &T, cache_control: &'static str) -> Response {
    match serde_json::to_string_pretty(doc) {
        Ok(json) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, cache_control),
            ],
            json,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn discovery(State(state): State<AppState>) -> Response {
    let doc = state.discovery.read().await;
    json_response(&*doc, "public, max-age=3600")
}

pub async fn revocations(State(state): State<AppState>) -> Response {
    let rev = state.revocation.read().await;
    match &*rev {
        Some(doc) => json_response(doc, "public, max-age=300"),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Web Bot Auth key directory, signed per request (Appendix B.1). The
/// signature covers the request's authority, so only configured hosts are
/// answered.
pub async fn wba_directory(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let Some(dir) = state.wba.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(host) = headers
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .map(|h| h.trim().to_ascii_lowercase())
    else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    if !dir.authorities.contains(&host) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let signed = match wba::sign_directory_response(
        &dir.body,
        &host,
        &dir.keys,
        chrono::Utc::now().timestamp(),
        wba::MAX_VALIDITY_SECS,
    ) {
        Ok(h) => h,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, wba::DIRECTORY_MEDIA_TYPE)
        .header(header::CACHE_CONTROL, "public, max-age=3600");
    for (name, value) in signed {
        builder = builder.header(name, value);
    }
    builder
        .body(axum::body::Body::from(dir.body.clone()))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

pub async fn health() -> Response {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"}))).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AppState;
    use agentpin::types::discovery::{
        AgentDeclaration, AgentStatus, DiscoveryDocument, EntityType,
    };
    use agentpin::types::revocation::RevocationDocument;
    use axum::body::Body;
    use axum::http::Request;
    use axum::Router;
    use std::sync::Arc;
    use tokio::sync::RwLock;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        let discovery = DiscoveryDocument {
            agentpin_version: "0.1".to_string(),
            entity: "test.com".to_string(),
            entity_type: EntityType::Maker,
            public_keys: vec![],
            agents: vec![AgentDeclaration {
                agent_id: "urn:agentpin:test.com:agent".to_string(),
                agent_type: None,
                name: "Test Agent".to_string(),
                description: None,
                version: None,
                capabilities: vec![],
                constraints: None,
                maker_attestation: None,
                credential_ttl_max: None,
                status: AgentStatus::Active,
                directory_listing: None,
            }],
            revocation_endpoint: None,
            policy_url: None,
            schemapin_endpoint: None,
            a2a_endpoint: None,
            web_bot_auth: None,
            max_delegation_depth: 2,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };

        AppState {
            discovery: Arc::new(RwLock::new(discovery)),
            revocation: Arc::new(RwLock::new(None)),
            wba: None,
        }
    }

    fn app(state: AppState) -> Router {
        Router::new()
            .route(
                "/.well-known/agent-identity.json",
                axum::routing::get(discovery),
            )
            .route(
                "/.well-known/agent-identity-revocations.json",
                axum::routing::get(revocations),
            )
            .route(
                "/.well-known/http-message-signatures-directory",
                axum::routing::get(wba_directory),
            )
            .route("/health", axum::routing::get(health))
            .with_state(state)
    }

    fn wba_state(key: &ed25519_dalek::SigningKey) -> AppState {
        let mut state = test_state();
        state.wba = Some(Arc::new(crate::state::WbaDirectory {
            keys: vec![key.clone().into()],
            body: wba::Directory::from_keys([&key.verifying_key().into()])
                .to_json()
                .unwrap(),
            authorities: vec!["test.com".to_string()],
        }));
        state
    }

    async fn get_directory(state: AppState, host: Option<&str>) -> Response {
        let mut req = Request::builder().uri("/.well-known/http-message-signatures-directory");
        if let Some(h) = host {
            req = req.header(header::HOST, h);
        }
        app(state)
            .oneshot(req.body(Body::empty()).unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn test_wba_directory_is_signed() {
        let key = wba::generate_signing_key();
        let resp = get_directory(wba_state(&key), Some("Test.com")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            wba::DIRECTORY_MEDIA_TYPE
        );
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_str().unwrap().to_string()))
            .collect();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let proven = wba::verify_directory_response(
            &body,
            &headers,
            "test.com",
            chrono::Utc::now().timestamp(),
            60,
        )
        .unwrap();
        assert_eq!(proven.keys.len(), 1);
        assert_eq!(
            proven.keys[0].thumbprint().unwrap(),
            wba::thumbprint(&key.verifying_key().into())
        );
    }

    #[tokio::test]
    async fn test_wba_directory_refuses_foreign_host() {
        let key = wba::generate_signing_key();
        let resp = get_directory(wba_state(&key), Some("evil.example")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let resp = get_directory(wba_state(&key), None).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let resp = get_directory(test_state(), Some("test.com")).await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_discovery_endpoint() {
        let state = test_state();
        let app = app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/agent-identity.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=3600"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let doc: DiscoveryDocument = serde_json::from_slice(&body).unwrap();
        assert_eq!(doc.entity, "test.com");
    }

    #[tokio::test]
    async fn test_revocations_not_found() {
        let state = test_state();
        let app = app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/agent-identity-revocations.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_revocations_found() {
        let state = test_state();
        let rev_doc = RevocationDocument {
            agentpin_version: "0.1".to_string(),
            entity: "test.com".to_string(),
            revoked_credentials: vec![],
            revoked_agents: vec![],
            revoked_keys: vec![],
            updated_at: "2026-01-01T00:00:00Z".to_string(),
            kid: None,
            signature: None,
        };
        *state.revocation.write().await = Some(rev_doc);

        let app = app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/.well-known/agent-identity-revocations.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=300"
        );
    }

    /// AP-23: HSTS is opt-in because the listener is plaintext.
    #[test]
    fn hsts_is_opt_in() {
        assert_eq!(crate::middleware::security_headers(false).len(), 3);
        assert_eq!(crate::middleware::security_headers(true).len(), 4);
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let state = test_state();
        let app = app(state);

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
    }
}
