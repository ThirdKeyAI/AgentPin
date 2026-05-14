//! Reference: AgentPin credential extraction as an Axum extractor.
//!
//! This example shows how to integrate AgentPin verification into an Axum HTTP server.
//! It is not a published crate — copy and adapt for your own server.
//!
//! Usage:
//!   cargo run --example axum_middleware --features fetch
//!
//! Dependencies needed in your Cargo.toml:
//!   axum = "0.7"
//!   tokio = { version = "1", features = ["full"] }
//!   agentpin = { version = "0.2", features = ["fetch"] }

use axum::{
    async_trait,
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};

/// Extractor that pulls an AgentPin credential from the Authorization header.
pub struct AgentPinCredential(pub String);

#[async_trait]
impl<S: Send + Sync> FromRequestParts<S> for AgentPinCredential {
    type Rejection = (StatusCode, String);

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let header = parts
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or((StatusCode::UNAUTHORIZED, "Missing Authorization header".to_string()))?;

        let jwt = agentpin::transport::http::extract_credential(header)
            .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

        // In production, you would verify the JWT here:
        //   let resolver = agentpin::resolver::ChainResolver::new(vec![...]);
        //   let result = agentpin::verification::verify_credential(&jwt, &resolver, &config).await?;

        Ok(AgentPinCredential(jwt))
    }
}

async fn protected_handler(AgentPinCredential(jwt): AgentPinCredential) -> impl IntoResponse {
    format!("Authenticated with credential: {}...", &jwt[..20.min(jwt.len())])
}

async fn health() -> &'static str {
    "ok"
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/protected", get(protected_handler))
        .route("/health", get(health));

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    println!("Listening on http://127.0.0.1:3000");
    axum::serve(listener, app).await.unwrap();
}
