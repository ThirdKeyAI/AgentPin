//! Discovery resolver abstraction.
//!
//! Provides pluggable discovery mechanisms beyond the standard
//! `https://{domain}/.well-known/agent-identity.json` endpoint.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::domain::normalize_domain;
#[cfg(feature = "fetch")]
use crate::domain::validate_https_url_for_domain;
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
#[allow(clippy::double_must_use)]
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
        domain: &str,
        discovery: &DiscoveryDocument,
    ) -> Result<Option<RevocationDocument>, Error> {
        if let Some(ref endpoint) = discovery.revocation_endpoint {
            // The endpoint is attacker-publishable; never fetch anything but
            // https on the issuer's own host (AP-12). An explicitly declared
            // endpoint fails closed on any error, including 404.
            validate_https_url_for_domain(endpoint, domain)?;
            let doc = crate::revocation::fetch_revocation_document(endpoint).await?;
            Ok(Some(doc))
        } else {
            // Spec §8.1: assume the default endpoint when none is declared.
            // A 404 there means the issuer publishes no revocations; any
            // other failure still fails closed (design issue 3).
            let domain = crate::domain::normalize_domain(domain)?;
            let url = crate::domain::default_revocation_endpoint(&domain);
            crate::revocation::fetch_revocation_document_if_present(&url).await
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

impl LocalFileResolver {
    /// Resolve `{domain}{suffix}` inside `dir`, refusing anything that is
    /// not a normalized hostname and anything whose canonical path escapes
    /// `dir` (AP-10). Returns `Ok(None)` when the file does not exist and a
    /// generic error (no OS error text, no path) on any other failure.
    fn read_contained(dir: &Path, domain: &str, suffix: &str) -> Result<Option<String>, Error> {
        let domain = normalize_domain(domain)?;
        let path = dir.join(format!("{}{}", domain, suffix));
        if !path.exists() {
            return Ok(None);
        }
        let base = dir
            .canonicalize()
            .map_err(|_| Error::Discovery("Discovery directory is not accessible".to_string()))?;
        let canonical = path.canonicalize().map_err(|_| {
            Error::Discovery(format!("Cannot read document for domain '{}'", domain))
        })?;
        if !canonical.starts_with(&base) {
            return Err(Error::Discovery(format!(
                "Document path for domain '{}' escapes the discovery directory",
                domain
            )));
        }
        let data = std::fs::read_to_string(&canonical).map_err(|_| {
            Error::Discovery(format!("Cannot read document for domain '{}'", domain))
        })?;
        Ok(Some(data))
    }
}

impl DiscoveryResolver for LocalFileResolver {
    fn resolve_discovery(&self, domain: &str) -> Result<DiscoveryDocument, Error> {
        let data =
            Self::read_contained(&self.discovery_dir, domain, ".json")?.ok_or_else(|| {
                Error::Discovery(format!("No discovery document for domain '{}'", domain))
            })?;
        let doc: DiscoveryDocument = serde_json::from_str(&data)?;
        Ok(doc)
    }

    fn resolve_revocation(
        &self,
        domain: &str,
        _discovery: &DiscoveryDocument,
    ) -> Result<Option<RevocationDocument>, Error> {
        let dir = self.revocation_dir.as_ref().unwrap_or(&self.discovery_dir);
        match Self::read_contained(dir, domain, ".revocations.json")? {
            None => Ok(None),
            Some(data) => {
                let doc: RevocationDocument = serde_json::from_str(&data)?;
                Ok(Some(doc))
            }
        }
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
            discovery.insert(bundle_key(&doc.entity), doc.clone());
        }
        let mut revocations = HashMap::new();
        for doc in &bundle.revocations {
            revocations.insert(bundle_key(&doc.entity), doc.clone());
        }
        Self {
            discovery,
            revocations,
        }
    }

    /// Build from a JSON string representing a [`TrustBundle`]. The bundle
    /// is rejected when its `expires_at` has passed; its signature, if any,
    /// is not checked — use [`from_signed_json`](Self::from_signed_json) for
    /// that.
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let bundle: TrustBundle = serde_json::from_str(json)?;
        crate::bundle::check_bundle_expiry(&bundle)?;
        Ok(Self::new(&bundle))
    }

    /// Build from a signed [`TrustBundle`] JSON string, requiring a valid
    /// signature under `verifying_key` and an unexpired `expires_at`
    /// (design issue 5).
    pub fn from_signed_json(
        json: &str,
        verifying_key: &p256::ecdsa::VerifyingKey,
    ) -> Result<Self, Error> {
        let bundle: TrustBundle = serde_json::from_str(json)?;
        crate::bundle::verify_trust_bundle(&bundle, verifying_key)?;
        Ok(Self::new(&bundle))
    }
}

/// Lookup key for bundle entries: the normalized domain when the entity is
/// a valid hostname, the raw string otherwise (such entries can never match
/// a normalized `iss`).
fn bundle_key(entity: &str) -> String {
    normalize_domain(entity).unwrap_or_else(|_| entity.to_string())
}

impl DiscoveryResolver for TrustBundleResolver {
    fn resolve_discovery(&self, domain: &str) -> Result<DiscoveryDocument, Error> {
        self.discovery
            .get(&bundle_key(domain))
            .cloned()
            .ok_or_else(|| Error::Discovery(format!("Domain '{}' not in trust bundle", domain)))
    }

    fn resolve_revocation(
        &self,
        domain: &str,
        _discovery: &DiscoveryDocument,
    ) -> Result<Option<RevocationDocument>, Error> {
        Ok(self.revocations.get(&bundle_key(domain)).cloned())
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

    /// Try each resolver in order. `Ok(None)` ("no data here") moves on to
    /// the next resolver; an `Err` is remembered and only surfaces when no
    /// later resolver produces a document, so a failing source can never
    /// turn into "nothing to check" (AP-11, spec §8.4 fail-closed).
    fn resolve_revocation(
        &self,
        domain: &str,
        discovery: &DiscoveryDocument,
    ) -> Result<Option<RevocationDocument>, Error> {
        let mut last_err: Option<Error> = None;
        for resolver in &self.resolvers {
            match resolver.resolve_revocation(domain, discovery) {
                Ok(Some(doc)) => return Ok(Some(doc)),
                Ok(None) => continue,
                Err(e) => last_err = Some(e),
            }
        }
        match last_err {
            Some(e) => Err(e),
            None => Ok(None),
        }
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
            expires_at: None,
            kid: None,
            signature: None,
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
            expires_at: None,
            kid: None,
            signature: None,
        };
        let resolver = TrustBundleResolver::new(&bundle);
        let disc = resolver.resolve_discovery("example.com").unwrap();
        let rev = resolver.resolve_revocation("example.com", &disc).unwrap();
        assert!(rev.is_some());
    }

    /// Design issue 5: a signed bundle must verify and must not be expired.
    #[test]
    fn test_trust_bundle_resolver_from_signed_json() {
        let kp = crate::crypto::generate_key_pair().unwrap();
        let sk = crate::crypto::load_signing_key(&kp.private_key_pem).unwrap();
        let vk = crate::crypto::load_verifying_key(&kp.public_key_pem).unwrap();
        let mut bundle = TrustBundle::new("2026-02-10T00:00:00Z");
        bundle.documents.push(make_discovery("example.com"));
        let unsigned = serde_json::to_string(&bundle).unwrap();
        assert!(TrustBundleResolver::from_signed_json(&unsigned, &vk).is_err());
        crate::bundle::sign_trust_bundle(&mut bundle, &sk, "ops").unwrap();
        let signed = serde_json::to_string(&bundle).unwrap();
        assert!(TrustBundleResolver::from_signed_json(&signed, &vk).is_ok());
        let mut expired = bundle.clone();
        expired.expires_at = Some("2000-01-01T00:00:00Z".to_string());
        crate::bundle::sign_trust_bundle(&mut expired, &sk, "ops").unwrap();
        let expired_json = serde_json::to_string(&expired).unwrap();
        assert!(TrustBundleResolver::from_signed_json(&expired_json, &vk).is_err());
        assert!(TrustBundleResolver::from_json(&expired_json).is_err());
    }

    #[test]
    fn test_trust_bundle_resolver_from_json() {
        let bundle = TrustBundle {
            agentpin_bundle_version: "0.1".to_string(),
            created_at: "2026-02-10T00:00:00Z".to_string(),
            documents: vec![make_discovery("example.com")],
            revocations: vec![],
            expires_at: None,
            kid: None,
            signature: None,
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

    /// AP-10: an untrusted domain string can never escape the discovery
    /// directory, and errors never echo OS error text or paths.
    #[test]
    fn test_local_file_resolver_rejects_traversal() {
        let dir = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let doc = make_discovery("evil.example");
        std::fs::write(
            outside.path().join("x.json"),
            serde_json::to_string(&doc).unwrap(),
        )
        .unwrap();
        let resolver = LocalFileResolver::new(dir.path(), None);
        let abs = outside.path().join("x").to_string_lossy().to_string();
        let rel = format!(
            "../{}/x",
            outside.path().file_name().unwrap().to_string_lossy()
        );
        for bad in [
            abs.as_str(),
            rel.as_str(),
            "..",
            "../x",
            "a/../../x",
            r"x\..\y",
        ] {
            let err = resolver.resolve_discovery(bad).unwrap_err().to_string();
            assert!(!err.contains("No such file"), "OS error leaked: {}", err);
            assert!(
                !err.contains(dir.path().to_str().unwrap()),
                "path leaked: {}",
                err
            );
        }
        // Missing-document errors are generic too.
        let err = resolver
            .resolve_discovery("missing.com")
            .unwrap_err()
            .to_string();
        assert!(!err.contains(dir.path().to_str().unwrap()));
        assert!(!err.contains("os error"));
    }

    /// AP-3: file lookups use the normalized domain.
    #[test]
    fn test_local_file_resolver_case_insensitive() {
        let dir = tempfile::tempdir().unwrap();
        let doc = make_discovery("local.example.com");
        std::fs::write(
            dir.path().join("local.example.com.json"),
            serde_json::to_string(&doc).unwrap(),
        )
        .unwrap();
        let resolver = LocalFileResolver::new(dir.path(), None);
        assert!(resolver.resolve_discovery("LOCAL.Example.COM.").is_ok());
    }

    /// AP-3: trust bundle lookups use the normalized domain.
    #[test]
    fn test_trust_bundle_resolver_normalized_lookup() {
        let bundle = TrustBundle {
            agentpin_bundle_version: "0.1".to_string(),
            created_at: "2026-02-10T00:00:00Z".to_string(),
            documents: vec![make_discovery("Example.COM")],
            revocations: vec![],
            expires_at: None,
            kid: None,
            signature: None,
        };
        let resolver = TrustBundleResolver::new(&bundle);
        assert!(resolver.resolve_discovery("example.com").is_ok());
        assert!(resolver.resolve_discovery("EXAMPLE.COM.").is_ok());
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
            expires_at: None,
            kid: None,
            signature: None,
        };
        let bundle_b = TrustBundle {
            agentpin_bundle_version: "0.1".to_string(),
            created_at: "2026-02-10T00:00:00Z".to_string(),
            documents: vec![make_discovery("b.com")],
            revocations: vec![],
            expires_at: None,
            kid: None,
            signature: None,
        };

        let chain = ChainResolver::new(vec![
            Box::new(TrustBundleResolver::new(&bundle_a)),
            Box::new(TrustBundleResolver::new(&bundle_b)),
        ]);

        assert!(chain.resolve_discovery("a.com").is_ok());
        assert!(chain.resolve_discovery("b.com").is_ok());
        assert!(chain.resolve_discovery("c.com").is_err());
    }

    /// A resolver whose revocation lookup always fails.
    struct FailingRevocation;
    impl DiscoveryResolver for FailingRevocation {
        fn resolve_discovery(&self, domain: &str) -> Result<DiscoveryDocument, Error> {
            Err(Error::Discovery(format!("no discovery for {}", domain)))
        }
        fn resolve_revocation(
            &self,
            _domain: &str,
            _discovery: &DiscoveryDocument,
        ) -> Result<Option<RevocationDocument>, Error> {
            Err(Error::Revocation(
                "revocation source unreachable".to_string(),
            ))
        }
    }

    /// AP-11: a failing revocation source inside a chain fails closed unless
    /// a later resolver actually produces a document.
    #[test]
    fn test_chain_resolver_revocation_fail_closed() {
        let doc = make_discovery("example.com");
        let no_data = TrustBundleResolver::new(&TrustBundle::new("2026-02-10T00:00:00Z"));
        let chain = ChainResolver::new(vec![Box::new(FailingRevocation), Box::new(no_data)]);
        assert!(chain.resolve_revocation("example.com", &doc).is_err());

        let rev = build_revocation_document("example.com");
        let has_rev = TrustBundleResolver::new(&TrustBundle {
            agentpin_bundle_version: "0.1".to_string(),
            created_at: "2026-02-10T00:00:00Z".to_string(),
            documents: vec![make_discovery("example.com")],
            revocations: vec![rev],
            expires_at: None,
            kid: None,
            signature: None,
        });
        let chain = ChainResolver::new(vec![Box::new(FailingRevocation), Box::new(has_rev)]);
        assert!(chain
            .resolve_revocation("example.com", &doc)
            .unwrap()
            .is_some());

        // No failures and no data is still "nothing to check".
        let empty = TrustBundleResolver::new(&TrustBundle::new("2026-02-10T00:00:00Z"));
        let chain = ChainResolver::new(vec![Box::new(empty)]);
        assert!(chain
            .resolve_revocation("example.com", &doc)
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_chain_resolver_fallthrough() {
        let empty = TrustBundle::new("2026-02-10T00:00:00Z");
        let has_doc = TrustBundle {
            agentpin_bundle_version: "0.1".to_string(),
            created_at: "2026-02-10T00:00:00Z".to_string(),
            documents: vec![make_discovery("example.com")],
            revocations: vec![],
            expires_at: None,
            kid: None,
            signature: None,
        };

        let chain = ChainResolver::new(vec![
            Box::new(TrustBundleResolver::new(&empty)),
            Box::new(TrustBundleResolver::new(&has_doc)),
        ]);

        let doc = chain.resolve_discovery("example.com").unwrap();
        assert_eq!(doc.entity, "example.com");
    }
}
