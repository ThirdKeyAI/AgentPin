//! Discovery resolver abstraction.
//!
//! Provides pluggable discovery mechanisms beyond the standard
//! `https://{domain}/.well-known/agent-identity.json` endpoint.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::Error;
use crate::types::bundle::TrustBundle;
use crate::types::discovery::DiscoveryDocument;
use crate::types::revocation::RevocationDocument;

// ---------------------------------------------------------------------------
// Sync resolver trait (always available)
// ---------------------------------------------------------------------------

/// Resolve discovery and revocation documents for a given domain.
///
/// Implementations can fetch from `.well-known` URLs, the local filesystem,
/// an in-memory trust bundle, or any other source.
pub trait DiscoveryResolver: Send + Sync {
    /// Return the discovery document for `domain`.
    fn resolve_discovery(&self, domain: &str) -> Result<DiscoveryDocument, Error>;

    /// Return the revocation document for `domain`, if available.
    ///
    /// The default implementation returns `Ok(None)`.
    fn resolve_revocation(
        &self,
        domain: &str,
        _discovery: &DiscoveryDocument,
    ) -> Result<Option<RevocationDocument>, Error> {
        let _ = domain;
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Async resolver trait (fetch-gated)
// ---------------------------------------------------------------------------

#[cfg(feature = "fetch")]
/// Async equivalent of [`DiscoveryResolver`].
///
/// Gated behind the `fetch` feature because it brings in `async-trait`.
#[async_trait::async_trait]
pub trait AsyncDiscoveryResolver: Send + Sync {
    async fn resolve_discovery(&self, domain: &str) -> Result<DiscoveryDocument, Error>;

    async fn resolve_revocation(
        &self,
        domain: &str,
        _discovery: &DiscoveryDocument,
    ) -> Result<Option<RevocationDocument>, Error> {
        let _ = domain;
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// WellKnownResolver (fetch-gated — wraps existing HTTP fetchers)
// ---------------------------------------------------------------------------

#[cfg(feature = "fetch")]
/// Fetches documents from the standard `.well-known` HTTPS endpoint.
pub struct WellKnownResolver;

#[cfg(feature = "fetch")]
#[async_trait::async_trait]
impl AsyncDiscoveryResolver for WellKnownResolver {
    async fn resolve_discovery(&self, domain: &str) -> Result<DiscoveryDocument, Error> {
        crate::discovery::fetch_discovery_document(domain).await
    }

    async fn resolve_revocation(
        &self,
        _domain: &str,
        discovery: &DiscoveryDocument,
    ) -> Result<Option<RevocationDocument>, Error> {
        if let Some(ref endpoint) = discovery.revocation_endpoint {
            let doc = crate::revocation::fetch_revocation_document(endpoint).await?;
            Ok(Some(doc))
        } else {
            Ok(None)
        }
    }
}

// ---------------------------------------------------------------------------
// LocalFileResolver (sync — reads from filesystem)
// ---------------------------------------------------------------------------

/// Reads discovery documents from a local directory.
///
/// Expects files named `{domain}.json` under `discovery_dir`.  Optionally
/// reads revocation documents from `{domain}.revocations.json` in the same
/// directory (or a separate `revocation_dir`).
pub struct LocalFileResolver {
    discovery_dir: PathBuf,
    revocation_dir: Option<PathBuf>,
}

impl LocalFileResolver {
    pub fn new(discovery_dir: &Path, revocation_dir: Option<&Path>) -> Self {
        Self {
            discovery_dir: discovery_dir.to_path_buf(),
            revocation_dir: revocation_dir.map(|p| p.to_path_buf()),
        }
    }
}

impl DiscoveryResolver for LocalFileResolver {
    fn resolve_discovery(&self, domain: &str) -> Result<DiscoveryDocument, Error> {
        let path = self.discovery_dir.join(format!("{}.json", domain));
        let data = std::fs::read_to_string(&path)
            .map_err(|e| Error::Discovery(format!("Cannot read {}: {}", path.display(), e)))?;
        let doc: DiscoveryDocument = serde_json::from_str(&data)?;
        Ok(doc)
    }

    fn resolve_revocation(
        &self,
        domain: &str,
        _discovery: &DiscoveryDocument,
    ) -> Result<Option<RevocationDocument>, Error> {
        let dir = self.revocation_dir.as_ref().unwrap_or(&self.discovery_dir);
        let path = dir.join(format!("{}.revocations.json", domain));
        if !path.exists() {
            return Ok(None);
        }
        let data = std::fs::read_to_string(&path)
            .map_err(|e| Error::Discovery(format!("Cannot read {}: {}", path.display(), e)))?;
        let doc: RevocationDocument = serde_json::from_str(&data)?;
        Ok(Some(doc))
    }
}

// ---------------------------------------------------------------------------
// TrustBundleResolver (sync — in-memory lookup)
// ---------------------------------------------------------------------------

/// Resolves documents from a pre-loaded [`TrustBundle`].
pub struct TrustBundleResolver {
    discovery: HashMap<String, DiscoveryDocument>,
    revocations: HashMap<String, RevocationDocument>,
}

impl TrustBundleResolver {
    /// Build from a [`TrustBundle`].
    pub fn new(bundle: &TrustBundle) -> Self {
        let mut discovery = HashMap::new();
        for doc in &bundle.documents {
            discovery.insert(doc.entity.clone(), doc.clone());
        }
        let mut revocations = HashMap::new();
        for doc in &bundle.revocations {
            revocations.insert(doc.entity.clone(), doc.clone());
        }
        Self {
            discovery,
            revocations,
        }
    }

    /// Build from a JSON string representing a [`TrustBundle`].
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let bundle: TrustBundle = serde_json::from_str(json)?;
        Ok(Self::new(&bundle))
    }
}

impl DiscoveryResolver for TrustBundleResolver {
    fn resolve_discovery(&self, domain: &str) -> Result<DiscoveryDocument, Error> {
        self.discovery
            .get(domain)
            .cloned()
            .ok_or_else(|| Error::Discovery(format!("Domain '{}' not in trust bundle", domain)))
    }

    fn resolve_revocation(
        &self,
        domain: &str,
        _discovery: &DiscoveryDocument,
    ) -> Result<Option<RevocationDocument>, Error> {
        Ok(self.revocations.get(domain).cloned())
    }
}

// ---------------------------------------------------------------------------
// ChainResolver (sync — tries resolvers in order)
// ---------------------------------------------------------------------------

/// Composite resolver that tries a sequence of resolvers in order until one
/// succeeds.
pub struct ChainResolver {
    resolvers: Vec<Box<dyn DiscoveryResolver>>,
}

impl ChainResolver {
    pub fn new(resolvers: Vec<Box<dyn DiscoveryResolver>>) -> Self {
        Self { resolvers }
    }
}

impl DiscoveryResolver for ChainResolver {
    fn resolve_discovery(&self, domain: &str) -> Result<DiscoveryDocument, Error> {
        let mut last_err = Error::Discovery("No resolvers configured".to_string());
        for resolver in &self.resolvers {
            match resolver.resolve_discovery(domain) {
                Ok(doc) => return Ok(doc),
                Err(e) => last_err = e,
            }
        }
        Err(last_err)
    }

    fn resolve_revocation(
        &self,
        domain: &str,
        discovery: &DiscoveryDocument,
    ) -> Result<Option<RevocationDocument>, Error> {
        for resolver in &self.resolvers {
            match resolver.resolve_revocation(domain, discovery) {
                Ok(Some(doc)) => return Ok(Some(doc)),
                Ok(None) => continue,
                Err(_) => continue,
            }
        }
        Ok(None)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::build_discovery_document;
    use crate::revocation::build_revocation_document;
    use crate::types::discovery::EntityType;

    fn make_discovery(domain: &str) -> DiscoveryDocument {
        build_discovery_document(
            domain,
            EntityType::Maker,
            vec![crate::jwk::Jwk {
                kid: "test-key".to_string(),
                kty: "EC".to_string(),
                crv: "P-256".to_string(),
                x: "x".to_string(),
                y: "y".to_string(),
                use_: "sig".to_string(),
                key_ops: None,
                exp: None,
            }],
            vec![],
            2,
            "2026-01-15T00:00:00Z",
        )
    }

    // -- TrustBundleResolver -------------------------------------------------

    #[test]
    fn test_trust_bundle_resolver_hit() {
        let bundle = TrustBundle {
            agentpin_bundle_version: "0.1".to_string(),
            created_at: "2026-02-10T00:00:00Z".to_string(),
            documents: vec![make_discovery("example.com")],
            revocations: vec![],
        };
        let resolver = TrustBundleResolver::new(&bundle);
        let doc = resolver.resolve_discovery("example.com").unwrap();
        assert_eq!(doc.entity, "example.com");
    }

    #[test]
    fn test_trust_bundle_resolver_miss() {
        let bundle = TrustBundle::new("2026-02-10T00:00:00Z");
        let resolver = TrustBundleResolver::new(&bundle);
        assert!(resolver.resolve_discovery("missing.com").is_err());
    }

    #[test]
    fn test_trust_bundle_resolver_revocation() {
        let rev = build_revocation_document("example.com");
        let bundle = TrustBundle {
            agentpin_bundle_version: "0.1".to_string(),
            created_at: "2026-02-10T00:00:00Z".to_string(),
            documents: vec![make_discovery("example.com")],
            revocations: vec![rev],
        };
        let resolver = TrustBundleResolver::new(&bundle);
        let disc = resolver.resolve_discovery("example.com").unwrap();
        let rev = resolver.resolve_revocation("example.com", &disc).unwrap();
        assert!(rev.is_some());
    }

    #[test]
    fn test_trust_bundle_resolver_from_json() {
        let bundle = TrustBundle {
            agentpin_bundle_version: "0.1".to_string(),
            created_at: "2026-02-10T00:00:00Z".to_string(),
            documents: vec![make_discovery("example.com")],
            revocations: vec![],
        };
        let json = serde_json::to_string(&bundle).unwrap();
        let resolver = TrustBundleResolver::from_json(&json).unwrap();
        assert!(resolver.resolve_discovery("example.com").is_ok());
    }

    // -- LocalFileResolver ---------------------------------------------------

    #[test]
    fn test_local_file_resolver() {
        let dir = tempfile::tempdir().unwrap();
        let doc = make_discovery("local.example.com");
        let path = dir.path().join("local.example.com.json");
        std::fs::write(&path, serde_json::to_string_pretty(&doc).unwrap()).unwrap();

        let resolver = LocalFileResolver::new(dir.path(), None);
        let resolved = resolver.resolve_discovery("local.example.com").unwrap();
        assert_eq!(resolved.entity, "local.example.com");
    }

    #[test]
    fn test_local_file_resolver_missing() {
        let dir = tempfile::tempdir().unwrap();
        let resolver = LocalFileResolver::new(dir.path(), None);
        assert!(resolver.resolve_discovery("missing.com").is_err());
    }

    #[test]
    fn test_local_file_resolver_revocation() {
        let dir = tempfile::tempdir().unwrap();
        let doc = make_discovery("local.example.com");
        let rev = build_revocation_document("local.example.com");
        std::fs::write(
            dir.path().join("local.example.com.json"),
            serde_json::to_string(&doc).unwrap(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("local.example.com.revocations.json"),
            serde_json::to_string(&rev).unwrap(),
        )
        .unwrap();

        let resolver = LocalFileResolver::new(dir.path(), None);
        let resolved = resolver
            .resolve_revocation("local.example.com", &doc)
            .unwrap();
        assert!(resolved.is_some());
    }

    // -- ChainResolver -------------------------------------------------------

    #[test]
    fn test_chain_resolver_first_wins() {
        let bundle_a = TrustBundle {
            agentpin_bundle_version: "0.1".to_string(),
            created_at: "2026-02-10T00:00:00Z".to_string(),
            documents: vec![make_discovery("a.com")],
            revocations: vec![],
        };
        let bundle_b = TrustBundle {
            agentpin_bundle_version: "0.1".to_string(),
            created_at: "2026-02-10T00:00:00Z".to_string(),
            documents: vec![make_discovery("b.com")],
            revocations: vec![],
        };

        let chain = ChainResolver::new(vec![
            Box::new(TrustBundleResolver::new(&bundle_a)),
            Box::new(TrustBundleResolver::new(&bundle_b)),
        ]);

        assert!(chain.resolve_discovery("a.com").is_ok());
        assert!(chain.resolve_discovery("b.com").is_ok());
        assert!(chain.resolve_discovery("c.com").is_err());
    }

    #[test]
    fn test_chain_resolver_fallthrough() {
        let empty = TrustBundle::new("2026-02-10T00:00:00Z");
        let has_doc = TrustBundle {
            agentpin_bundle_version: "0.1".to_string(),
            created_at: "2026-02-10T00:00:00Z".to_string(),
            documents: vec![make_discovery("example.com")],
            revocations: vec![],
        };

        let chain = ChainResolver::new(vec![
            Box::new(TrustBundleResolver::new(&empty)),
            Box::new(TrustBundleResolver::new(&has_doc)),
        ]);

        let doc = chain.resolve_discovery("example.com").unwrap();
        assert_eq!(doc.entity, "example.com");
    }
}
