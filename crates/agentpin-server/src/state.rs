use std::sync::Arc;

use agentpin::types::discovery::DiscoveryDocument;
use agentpin::types::revocation::RevocationDocument;
use agentpin::wba::PrivateKey;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState {
    pub discovery: Arc<RwLock<DiscoveryDocument>>,
    pub revocation: Arc<RwLock<Option<RevocationDocument>>>,
    pub wba: Option<Arc<WbaDirectory>>,
}

/// Web Bot Auth key directory served by this instance.
pub struct WbaDirectory {
    pub keys: Vec<PrivateKey>,
    /// Serialized JWK Set, signed as served.
    pub body: Vec<u8>,
    /// Lowercase hosts (with non-default port) the directory is served for.
    pub authorities: Vec<String>,
}
