use std::sync::Arc;

use agentpin::types::discovery::DiscoveryDocument;
use agentpin::types::revocation::RevocationDocument;
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct AppState {
    pub discovery: Arc<RwLock<DiscoveryDocument>>,
    pub revocation: Arc<RwLock<Option<RevocationDocument>>>,
}
