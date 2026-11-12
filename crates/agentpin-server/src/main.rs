mod config;
mod middleware;
mod routes;
mod state;

use std::sync::Arc;

use agentpin::types::discovery::DiscoveryDocument;
use agentpin::types::revocation::RevocationDocument;
use axum::Router;
use config::ServerConfig;
use state::AppState;
use tokio::sync::RwLock;
use tower_http::trace::TraceLayer;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("info".parse()?))
        .init();

    let config = ServerConfig::parse_args();

    // Load discovery document
    let discovery_json = std::fs::read_to_string(&config.discovery)?;
    let discovery: DiscoveryDocument = serde_json::from_str(&discovery_json)?;
    tracing::info!(entity = %discovery.entity, "Loaded discovery document");

    // Load optional revocation document
    let revocation: Option<RevocationDocument> = match &config.revocation {
        Some(path) => {
            let json = std::fs::read_to_string(path)?;
            let doc: RevocationDocument = serde_json::from_str(&json)?;
            tracing::info!(entity = %doc.entity, "Loaded revocation document");
            Some(doc)
        }
        None => None,
    };

    // Optional Web Bot Auth key directory
    let wba = if config.wba_keys.is_empty() {
        None
    } else {
        let keys = config
            .wba_keys
            .iter()
            .map(|path| {
                let pem = zeroize::Zeroizing::new(std::fs::read_to_string(path)?);
                agentpin::wba::load_signing_key(&pem)
                    .map_err(|e| anyhow::anyhow!("{}: {}", path, e))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        let public: Vec<_> = keys.iter().map(|k| k.public_key()).collect();
        let body = agentpin::wba::Directory::from_keys(&public).to_json()?;
        let mut authorities = vec![discovery.entity.to_ascii_lowercase()];
        authorities.extend(
            config
                .wba_authorities
                .iter()
                .map(|a| a.to_ascii_lowercase()),
        );
        tracing::info!(keys = keys.len(), "Serving Web Bot Auth key directory");
        Some(Arc::new(state::WbaDirectory {
            keys,
            body,
            authorities,
        }))
    };

    let state = AppState {
        discovery: Arc::new(RwLock::new(discovery)),
        revocation: Arc::new(RwLock::new(revocation)),
        wba,
    };

    // Build router with security headers
    let security = middleware::security_headers(config.hsts);
    let mut app = Router::new()
        .route(
            "/.well-known/agent-identity.json",
            axum::routing::get(routes::discovery),
        )
        .route(
            "/.well-known/agent-identity-revocations.json",
            axum::routing::get(routes::revocations),
        )
        .route(
            "/.well-known/http-message-signatures-directory",
            axum::routing::get(routes::wba_directory),
        )
        .route("/health", axum::routing::get(routes::health))
        .with_state(state)
        .layer(TraceLayer::new_for_http());

    for layer in security {
        app = app.layer(layer);
    }

    let addr = format!("{}:{}", config.bind, config.port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("Listening on {}", addr);

    axum::serve(listener, app).await?;
    Ok(())
}
