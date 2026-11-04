use std::sync::Arc;

use agentpin::types::discovery::DiscoveryDocument;
use agentpin::types::revocation::RevocationDocument;
use ed25519_dalek::SigningKey;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState {
    pub discovery: Arc<RwLock<DiscoveryDocument>>,
    pub revocation: Arc<RwLock<Option<RevocationDocument>>>,
    pub wba: Option<Arc<WbaDirectory>>,
}

/// Web Bot Auth key directory served by this instance.
pub struct WbaDirectory {
    pub keys: Vec<SigningKey>,
    /// Serialized JWK Set, signed as served.
    pub body: Vec<u8>,
    /// Lowercase hosts (with non-default port) the directory is served for.
    pub authorities: Vec<String>,
}
