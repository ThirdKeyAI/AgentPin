//! DNS TXT cross-verification at `_agentpin.{domain}` (v0.3.0).
//!
//! AgentPin's [`crate::types::discovery::DiscoveryDocument`] is published over
//! HTTPS at `.well-known/agent-identity.json`. v0.3.0 adds an OPTIONAL
//! second-channel verification: a DNS `TXT` record at `_agentpin.{domain}`
//! whose `fp=` field carries the JWK thumbprint of one of the discovery
//! document's public keys. DNS is administered through a separate credential
//! chain (registrar account, DNS provider, optionally DNSSEC) — compromising
//! one channel doesn't automatically give an attacker the other.
//!
//! The wire format mirrors SchemaPin's `_schemapin.{domain}` record exactly,
//! with the version tag changed:
//!
//! ```text
//! _agentpin.example.com.  3600  IN  TXT  "v=agentpin1; kid=acme-2026-04; fp=sha256:a1b2c3..."
//! ```
//!
//! ## Verifier semantics
//!
//! - **Absent record** — no effect (DNS TXT is purely additive)
//! - **Present and matching** — verification succeeds; absence of mismatch is
//!   the trust signal
//! - **Present and mismatching** — hard failure ([`Error::Discovery`])
//! - **Present and malformed** — hard failure ([`Error::Discovery`])
//!
//! The mismatch case is fail-closed because a publisher who *intentionally*
//! published a TXT record has signaled that DNS is part of their trust chain
//! — a divergence between DNS and `.well-known` indicates compromise of one
//! of the two channels, and there's no way for the verifier to tell which is
//! authentic. Better to refuse than to guess.

use crate::error::Error;
use crate::jwk::jwk_thumbprint;
use crate::types::discovery::DiscoveryDocument;

/// Parsed `_agentpin.{domain}` TXT record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsTxtRecord {
    pub version: String,
    pub kid: Option<String>,
    /// Lowercase fingerprint string, including the `sha256:` prefix.
    pub fingerprint: String,
}

/// Parse a raw TXT record value (e.g. `"v=agentpin1; kid=acme-2026-04; fp=sha256:..."`).
///
/// Whitespace around `;` and `=` is tolerated. Field order is not significant.
/// Returns an error if the record is missing the required `v` or `fp` fields,
/// or if the version isn't `agentpin1`. Unknown fields are ignored for forward
/// compatibility.
pub fn parse_txt_record(value: &str) -> Result<DnsTxtRecord, Error> {
    let mut version: Option<String> = None;
    let mut kid: Option<String> = None;
    let mut fp: Option<String> = None;

    for raw_part in value.split(';') {
        let part = raw_part.trim();
        if part.is_empty() {
            continue;
        }
        let (k, v) = part
            .split_once('=')
            .ok_or_else(|| Error::Discovery(format!("DNS TXT field missing '=': {}", part)))?;
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        match k.as_str() {
            "v" => version = Some(v.to_string()),
            "kid" => kid = Some(v.to_string()),
            "fp" => fp = Some(v.to_ascii_lowercase()),
            // Forward-compat: ignore unknown fields rather than reject.
            _ => {}
        }
    }

    let version = version
        .ok_or_else(|| Error::Discovery("DNS TXT record missing required 'v' field".to_string()))?;
    if version != "agentpin1" {
        return Err(Error::Discovery(format!(
            "DNS TXT unsupported version: {}",
            version
        )));
    }
    let fingerprint = fp.ok_or_else(|| {
        Error::Discovery("DNS TXT record missing required 'fp' field".to_string())
    })?;
    if !fingerprint.starts_with("sha256:") {
        return Err(Error::Discovery(format!(
            "DNS TXT 'fp' must be sha256:<hex>: {}",
            fingerprint
        )));
    }

    Ok(DnsTxtRecord {
        version,
        kid,
        fingerprint,
    })
}

/// Cross-check the DNS TXT record's fingerprint against the discovery document.
///
/// Returns `Ok(())` when the TXT `fp` matches the JWK thumbprint of *any* key
/// in `discovery.public_keys`. AgentPin discovery docs may carry multiple
/// keys (for rotation); a published TXT record need only match one of them.
///
/// When the TXT carries a `kid`, the matching key MUST also carry the same
/// `kid` — defends against the case where two of the publisher's keys share
/// a fingerprint (vanishingly unlikely with SHA-256 but cheap to enforce).
pub fn verify_dns_match(discovery: &DiscoveryDocument, txt: &DnsTxtRecord) -> Result<(), Error> {
    let target_fp = txt.fingerprint.to_ascii_lowercase();
    for jwk in &discovery.public_keys {
        let computed = jwk_thumbprint(jwk).to_ascii_lowercase();
        let normalized = if computed.starts_with("sha256:") {
            computed
        } else {
            format!("sha256:{}", computed)
        };
        if normalized != target_fp {
            continue;
        }
        // If the TXT specifies a kid, require it to match.
        if let Some(ref txt_kid) = txt.kid {
            if &jwk.kid != txt_kid {
                continue;
            }
        }
        return Ok(());
    }
    Err(Error::Discovery(format!(
        "DNS TXT fingerprint {} does not match any key in the discovery document",
        target_fp
    )))
}

/// Construct the DNS lookup name for a given AgentPin domain.
///
/// Strips a trailing dot if present so callers can pass either `example.com`
/// or `example.com.`.
pub fn txt_record_name(domain: &str) -> String {
    format!("_agentpin.{}", domain.trim_end_matches('.'))
}

/// Fetch and parse the `_agentpin.{domain}` TXT record. Behind the `dns` feature.
///
/// Returns:
/// - `Ok(Some(record))` — record present and parseable
/// - `Ok(None)` — no `_agentpin` TXT record exists for the domain
/// - `Err(_)` — DNS resolution error or the record exists but is malformed
///
/// Multiple matching TXT chunks are joined per RFC 1464 (concatenation in
/// emit order). When several separate TXT records exist at the same name,
/// the first one whose value contains `v=agentpin1` is used.
#[cfg(feature = "dns")]
pub async fn fetch_dns_txt(domain: &str) -> Result<Option<DnsTxtRecord>, Error> {
    use hickory_resolver::error::ResolveErrorKind;
    use hickory_resolver::TokioAsyncResolver;

    let name = txt_record_name(domain);
    let resolver = TokioAsyncResolver::tokio(Default::default(), Default::default());
    let lookup = match resolver.txt_lookup(&name).await {
        Ok(l) => l,
        Err(e) => {
            if matches!(e.kind(), ResolveErrorKind::NoRecordsFound { .. }) {
                return Ok(None);
            }
            return Err(Error::Discovery(format!(
                "DNS TXT lookup failed for {}: {}",
                name, e
            )));
        }
    };

    for record in lookup.iter() {
        // hickory yields TxtData as Vec<Box<[u8]>>; concatenate chunks per RFC 1464.
        let joined: String = record
            .iter()
            .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<_>>()
            .join("");
        if joined.contains("v=agentpin1") {
            return parse_txt_record(&joined).map(Some);
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_key_pair;
    use crate::jwk::pem_to_jwk;
    use crate::types::discovery::EntityType;

    fn make_discovery(jwks: Vec<crate::jwk::Jwk>) -> DiscoveryDocument {
        DiscoveryDocument {
            agentpin_version: "0.3".to_string(),
            entity: "example.com".to_string(),
            entity_type: EntityType::Maker,
            public_keys: jwks,
            agents: vec![],
            revocation_endpoint: None,
            policy_url: None,
            schemapin_endpoint: None,
            a2a_endpoint: None,
            max_delegation_depth: 0,
            updated_at: "2026-05-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn parse_full_record() {
        let r = parse_txt_record("v=agentpin1; kid=acme-2026-04; fp=sha256:abcd1234").unwrap();
        assert_eq!(r.version, "agentpin1");
        assert_eq!(r.kid.as_deref(), Some("acme-2026-04"));
        assert_eq!(r.fingerprint, "sha256:abcd1234");
    }

    #[test]
    fn parse_minimal_record() {
        let r = parse_txt_record("v=agentpin1;fp=sha256:abc").unwrap();
        assert_eq!(r.version, "agentpin1");
        assert_eq!(r.kid, None);
        assert_eq!(r.fingerprint, "sha256:abc");
    }

    #[test]
    fn parse_lowercases_fingerprint() {
        let r = parse_txt_record("v=agentpin1; fp=SHA256:ABCDEF").unwrap();
        assert_eq!(r.fingerprint, "sha256:abcdef");
    }

    #[test]
    fn parse_tolerates_whitespace_and_order() {
        let r = parse_txt_record("  fp = sha256:beef ;  v = agentpin1  ").unwrap();
        assert_eq!(r.version, "agentpin1");
        assert_eq!(r.fingerprint, "sha256:beef");
    }

    #[test]
    fn parse_ignores_unknown_fields() {
        let r = parse_txt_record("v=agentpin1; fp=sha256:abc; future=ignoreme").unwrap();
        assert_eq!(r.fingerprint, "sha256:abc");
    }

    #[test]
    fn parse_missing_v_fails() {
        assert!(parse_txt_record("fp=sha256:abc").is_err());
    }

    #[test]
    fn parse_missing_fp_fails() {
        assert!(parse_txt_record("v=agentpin1").is_err());
    }

    #[test]
    fn parse_unsupported_version_fails() {
        assert!(parse_txt_record("v=agentpin99; fp=sha256:abc").is_err());
    }

    #[test]
    fn parse_fp_without_sha256_prefix_fails() {
        assert!(parse_txt_record("v=agentpin1; fp=abc").is_err());
    }

    #[test]
    fn parse_field_without_equals_fails() {
        assert!(parse_txt_record("v=agentpin1; broken").is_err());
    }

    #[test]
    fn schemapin_record_rejected_under_agentpin_parser() {
        // Sanity: must reject SchemaPin's TXT format so a misconfigured DNS
        // entry doesn't accidentally validate.
        assert!(parse_txt_record("v=schemapin1; fp=sha256:abc").is_err());
    }

    #[test]
    fn verify_match_against_single_key() {
        let kp = generate_key_pair().unwrap();
        let jwk = pem_to_jwk(&kp.public_key_pem, "kid-1").unwrap();
        let raw_fp = jwk_thumbprint(&jwk);
        let normalized_fp = if raw_fp.starts_with("sha256:") {
            raw_fp.clone()
        } else {
            format!("sha256:{}", raw_fp)
        };

        let discovery = make_discovery(vec![jwk]);
        let txt = DnsTxtRecord {
            version: "agentpin1".to_string(),
            kid: None,
            fingerprint: normalized_fp,
        };
        verify_dns_match(&discovery, &txt).unwrap();
    }

    #[test]
    fn verify_match_against_one_of_multiple_keys() {
        let kp_a = generate_key_pair().unwrap();
        let kp_b = generate_key_pair().unwrap();
        let jwk_a = pem_to_jwk(&kp_a.public_key_pem, "kid-a").unwrap();
        let jwk_b = pem_to_jwk(&kp_b.public_key_pem, "kid-b").unwrap();
        let raw_fp_b = jwk_thumbprint(&jwk_b);
        let normalized_fp_b = if raw_fp_b.starts_with("sha256:") {
            raw_fp_b
        } else {
            format!("sha256:{}", raw_fp_b)
        };

        let discovery = make_discovery(vec![jwk_a, jwk_b]);
        let txt = DnsTxtRecord {
            version: "agentpin1".to_string(),
            kid: Some("kid-b".to_string()),
            fingerprint: normalized_fp_b,
        };
        verify_dns_match(&discovery, &txt).unwrap();
    }

    #[test]
    fn verify_kid_mismatch_fails_even_when_fp_matches() {
        let kp = generate_key_pair().unwrap();
        let jwk = pem_to_jwk(&kp.public_key_pem, "kid-real").unwrap();
        let raw_fp = jwk_thumbprint(&jwk);
        let normalized_fp = if raw_fp.starts_with("sha256:") {
            raw_fp
        } else {
            format!("sha256:{}", raw_fp)
        };

        let discovery = make_discovery(vec![jwk]);
        let txt = DnsTxtRecord {
            version: "agentpin1".to_string(),
            kid: Some("kid-different".to_string()),
            fingerprint: normalized_fp,
        };
        let err = verify_dns_match(&discovery, &txt).unwrap_err();
        assert!(matches!(err, Error::Discovery(_)));
    }

    #[test]
    fn verify_mismatch_returns_discovery_error() {
        let kp = generate_key_pair().unwrap();
        let jwk = pem_to_jwk(&kp.public_key_pem, "kid-1").unwrap();
        let discovery = make_discovery(vec![jwk]);
        let txt = DnsTxtRecord {
            version: "agentpin1".to_string(),
            kid: None,
            fingerprint: "sha256:0000000000000000000000000000000000000000000000000000000000000000"
                .to_string(),
        };
        let err = verify_dns_match(&discovery, &txt).unwrap_err();
        assert!(matches!(err, Error::Discovery(_)));
    }

    #[test]
    fn txt_record_name_strips_trailing_dot() {
        assert_eq!(txt_record_name("example.com"), "_agentpin.example.com");
        assert_eq!(txt_record_name("example.com."), "_agentpin.example.com");
    }
}
