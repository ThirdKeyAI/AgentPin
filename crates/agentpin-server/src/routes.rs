use axum::extract::State;
use axum::http::header;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

use crate::state::AppState;

pub async fn discovery(State(state): State<AppState>) -> Response {
    let doc = state.discovery.read().await;
    let json = serde_json::to_string_pretty(&*doc).unwrap_or_default();
    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        json,
    )
        .into_response()
}

pub async fn revocations(State(state): State<AppState>) -> Response {
    let rev = state.revocation.read().await;
    match &*rev {
        Some(doc) => {
            let json = serde_json::to_string_pretty(doc).unwrap_or_default();
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, "application/json"),
                    (header::CACHE_CONTROL, "public, max-age=300"),
                ],
                json,
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
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
            max_delegation_depth: 2,
            updated_at: "2026-01-01T00:00:00Z".to_string(),
        };

        AppState {
            discovery: Arc::new(RwLock::new(discovery)),
            revocation: Arc::new(RwLock::new(None)),
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
            .route("/health", axum::routing::get(health))
            .with_state(state)
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
