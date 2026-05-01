pub mod crypto;
pub mod error;
pub mod jwk;
pub mod jwt;
pub mod resolver;
pub mod types;

pub mod credential;
pub mod delegation;
pub mod discovery;
pub mod mutual;
pub mod nonce;
pub mod pinning;
pub mod revocation;
pub mod rotation;
pub mod transport;
pub mod verification;

// v0.3.0: A2A AgentCard signing + verification, plus two new resolvers
// (LocalAgentCardStore always available; A2aAgentCardResolver behind `fetch`).
pub mod a2a;
#[cfg(feature = "fetch")]
pub mod resolver_a2a;
pub mod resolver_local;
