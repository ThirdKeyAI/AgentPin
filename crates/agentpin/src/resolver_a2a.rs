//! [`A2aAgentCardResolver`] — fetches A2A AgentCards over HTTPS (v0.3.0).
//!
//! Implements [`crate::resolver::AsyncDiscoveryResolver`] (gated on the
//! `fetch` feature). Performs:
//!
//! 1. `GET https://{domain}/.well-known/agent-card.json`
//! 2. JSON-decode into [`A2aAgentCard`]
//! 3. Verify the AgentPin extension signature against its embedded JWK
//! 4. Derive a [`DiscoveryDocument`] from the card so the rest of the
//!    AgentPin verification stack can run unchanged
//!
//! The resulting AgentCard is also exposed via [`A2aAgentCardResolver::last_card`]
//! for callers who want to inspect the original A2A representation alongside
//! the derived discovery doc.

#![cfg(feature = "fetch")]

use std::sync::Mutex;
use std::time::Duration;

use crate::a2a::verify_agentpin_extension;
use crate::error::Error;
use crate::resolver::AsyncDiscoveryResolver;
use crate::resolver_local::{card_endpoint_host, derive_discovery_from_card};
use crate::types::a2a::A2aAgentCard;
use crate::types::discovery::DiscoveryDocument;
use crate::types::revocation::RevocationDocument;

const AGENT_CARD_PATH: &str = "/.well-known/agent-card.json";
const DEFAULT_TIMEOUT_SECS: u64 = 10;

/// HTTPS resolver for A2A AgentCards published at `.well-known/agent-card.json`.
pub struct A2aAgentCardResolver {
    timeout: Duration,
    last_card: Mutex<Option<(String, A2aAgentCard)>>,
}

impl A2aAgentCardResolver {
    /// Construct with the default 10s timeout.
    pub fn new() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            last_card: Mutex::new(None),
        }
    }

    /// Construct with a custom HTTP request timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            timeout,
            last_card: Mutex::new(None),
        }
    }

    /// Return the last successfully resolved AgentCard, if any.
    ///
    /// Useful for callers that want to inspect the A2A card's URL,
    /// capabilities, or skill list after `resolve_discovery` has converted
    /// it into a [`DiscoveryDocument`].
    pub fn last_card(&self, domain: &str) -> Option<A2aAgentCard> {
        self.last_card.lock().ok().and_then(|guard| {
            guard
                .as_ref()
                .and_then(|(d, c)| if d == domain { Some(c.clone()) } else { None })
        })
    }
}

impl Default for A2aAgentCardResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AsyncDiscoveryResolver for A2aAgentCardResolver {
    async fn resolve_discovery(&self, domain: &str) -> Result<DiscoveryDocument, Error> {
        let url = format!("https://{}{}", domain, AGENT_CARD_PATH);
        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .build()
            .map_err(|e| Error::Discovery(format!("HTTP client init failed: {e}")))?;
        let response = client
            .get(&url)
            .send()
            .await
            .map_err(|e| Error::Discovery(format!("Failed to fetch {}: {}", url, e)))?;
        if !response.status().is_success() {
            return Err(Error::Discovery(format!(
                "Failed to fetch {}: HTTP {}",
                url,
                response.status()
            )));
        }
        let card: A2aAgentCard = response.json().await.map_err(|e| {
            Error::Discovery(format!("Failed to parse AgentCard at {}: {}", url, e))
        })?;

        // Verify the extension signature before trusting any field.
        verify_agentpin_extension(&card)?;

        // Cross-check that the agentpin endpoint inside the card matches the
        // domain we just fetched from — defends against a card that points at
        // some other domain's AgentPin discovery.
        let endpoint_host = card_endpoint_host(&card)?;
        if endpoint_host != domain {
            return Err(Error::Discovery(format!(
                "AgentCard at {} declares agentpin endpoint host {} (mismatch)",
                domain, endpoint_host
            )));
        }

        let discovery = derive_discovery_from_card(&card)?;

        // Cache the original card for callers that want to inspect it.
        if let Ok(mut guard) = self.last_card.lock() {
            *guard = Some((domain.to_string(), card));
        }

        Ok(discovery)
    }

    async fn resolve_revocation(
        &self,
        _domain: &str,
        _discovery: &DiscoveryDocument,
    ) -> Result<Option<RevocationDocument>, Error> {
        // A2A AgentCards do not carry revocation data. Fall back to a separate
        // revocation resolver via ChainResolver if revocation is required.
        Ok(None)
    }
}
