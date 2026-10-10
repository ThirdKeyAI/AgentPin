//! Domain-name normalization and validation.
//!
//! DNS, TLS hostname matching and the HTTP `Host` header are all
//! case-insensitive, but the TOFU pin store, the discovery URL and the
//! `entity == iss` comparison used to operate on the literal `iss` string.
//! `EXAMPLE.COM`, `example.com.` and the U-label/A-label forms of an IDN were
//! therefore distinct identities with independent pins (AP-3), and an `iss`
//! containing a path, port or userinfo was interpolated unescaped into file
//! paths and URLs (AP-10, AP-12).
//!
//! [`normalize_domain`] is the single choke point: every verifier applies it
//! to `iss`, every resolver applies it to its lookup key, and discovery
//! validation applies it to `entity` before comparison.

use url::{Host, Url};

use crate::error::Error;

/// Maximum length of a normalized hostname.
const MAX_HOSTNAME_LEN: usize = 253;
/// Maximum length of a single DNS label.
const MAX_LABEL_LEN: usize = 63;

fn invalid(reason: &str) -> Error {
    Error::Discovery(format!("Invalid domain: {}", reason))
}

/// Normalize a domain name to its canonical lowercase A-label form.
///
/// Rules:
/// - leading/trailing whitespace is rejected (not trimmed);
/// - exactly one trailing dot is removed;
/// - the name is lowercased and IDNA/UTS-46 mapped to A-labels;
/// - anything that is not a bare hostname is rejected: scheme, userinfo,
///   port, path, query, fragment, whitespace, control characters, IPv4 and
///   IPv6 literals, empty labels, labels longer than 63 octets, names longer
///   than 253 octets and labels with a leading or trailing hyphen.
///
/// The result is safe to use as a pin-store key, a file name component and
/// a URL host.
pub fn normalize_domain(input: &str) -> Result<String, Error> {
    if input.is_empty() {
        return Err(invalid("empty"));
    }
    if input.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(invalid("contains whitespace or control characters"));
    }
    if input
        .chars()
        .any(|c| matches!(c, '/' | '\\' | '?' | '#' | '@' | ':' | '[' | ']' | '%'))
    {
        return Err(invalid("not a bare hostname"));
    }

    let trimmed = input.strip_suffix('.').unwrap_or(input);
    if trimmed.is_empty() || trimmed.ends_with('.') {
        return Err(invalid("empty label"));
    }

    // Let the URL parser perform IDNA mapping and lowercasing, then insist
    // that nothing but a domain host came out of it.
    let parsed = Url::parse(&format!("https://{}/", trimmed)).map_err(|_| invalid("unparsable"))?;
    let host = match parsed.host() {
        Some(Host::Domain(d)) => d.to_string(),
        Some(Host::Ipv4(_)) | Some(Host::Ipv6(_)) => {
            return Err(invalid("IP literals are not allowed"))
        }
        None => return Err(invalid("no host")),
    };
    if parsed.port().is_some()
        || parsed.path() != "/"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(invalid("not a bare hostname"));
    }

    validate_ascii_hostname(&host)?;
    Ok(host)
}

/// Validate an already-ASCII hostname against RFC 1123 label rules.
fn validate_ascii_hostname(host: &str) -> Result<(), Error> {
    if host.len() > MAX_HOSTNAME_LEN {
        return Err(invalid("hostname too long"));
    }
    if looks_like_ipv4(host) {
        return Err(invalid("IP literals are not allowed"));
    }
    for label in host.split('.') {
        if label.is_empty() {
            return Err(invalid("empty label"));
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(invalid("label too long"));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(invalid("label starts or ends with a hyphen"));
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
            return Err(invalid("label contains characters outside [a-z0-9-]"));
        }
    }
    Ok(())
}

fn looks_like_ipv4(host: &str) -> bool {
    let parts: Vec<&str> = host.split('.').collect();
    parts.len() == 4
        && parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Validate that `url` is an `https://` URL whose host is exactly `domain`
/// (after normalization), with no userinfo, port or fragment.
///
/// Used for `revocation_endpoint`, `a2a_endpoint` and the AgentCard
/// `agentpin_endpoint`, all of which are attacker-publishable strings that a
/// verifier would otherwise fetch verbatim (AP-12).
pub fn validate_https_url_for_domain(url: &str, domain: &str) -> Result<(), Error> {
    let expected = normalize_domain(domain)?;
    let host = https_url_host(url)?;
    if host != expected {
        return Err(Error::Discovery(format!(
            "URL host '{}' does not match domain '{}'",
            host, expected
        )));
    }
    Ok(())
}

/// Parse `url`, require the `https` scheme, no userinfo, no explicit port
/// and no fragment, and return its normalized domain host (IP literals are
/// rejected).
pub fn https_url_host(url: &str) -> Result<String, Error> {
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return Err(Error::Discovery(
            "Invalid URL: contains whitespace".to_string(),
        ));
    }
    let parsed = Url::parse(url).map_err(|_| Error::Discovery("Invalid URL".to_string()))?;
    if parsed.scheme() != "https" {
        return Err(Error::Discovery("URL must use https".to_string()));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(Error::Discovery(
            "URL must not contain userinfo".to_string(),
        ));
    }
    if parsed.port().is_some() {
        return Err(Error::Discovery("URL must not specify a port".to_string()));
    }
    if parsed.fragment().is_some() {
        return Err(Error::Discovery(
            "URL must not contain a fragment".to_string(),
        ));
    }
    match parsed.host() {
        Some(Host::Domain(d)) => normalize_domain(d),
        _ => Err(Error::Discovery(
            "URL host must be a domain name".to_string(),
        )),
    }
}

/// The default revocation endpoint for `domain` (spec §8.1).
pub fn default_revocation_endpoint(domain: &str) -> String {
    format!(
        "https://{}/.well-known/agent-identity-revocations.json",
        domain
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_trailing_dot_and_idn() {
        assert_eq!(normalize_domain("example.com").unwrap(), "example.com");
        assert_eq!(normalize_domain("EXAMPLE.COM").unwrap(), "example.com");
        assert_eq!(normalize_domain("Example.Com.").unwrap(), "example.com");
        assert_eq!(
            normalize_domain("bücher.example").unwrap(),
            "xn--bcher-kva.example"
        );
        assert_eq!(
            normalize_domain("XN--BCHER-KVA.example").unwrap(),
            "xn--bcher-kva.example"
        );
        assert_eq!(normalize_domain("localhost").unwrap(), "localhost");
        assert_eq!(
            normalize_domain("a-b.c1.example").unwrap(),
            "a-b.c1.example"
        );
    }

    #[test]
    fn rejects_non_hostnames() {
        for bad in [
            "",
            ".",
            "..",
            "../../tmp/x",
            "/srv/uploads/x",
            "example.com/path",
            "example.com\\evil",
            "https://example.com",
            "user@example.com",
            "example.com:8443",
            "127.0.0.1",
            "127.0.0.1:8443",
            "[::1]",
            "::1",
            "example.com?x=1",
            "example.com#frag",
            " example.com",
            "example.com ",
            "exa mple.com",
            "example..com",
            ".example.com",
            "-example.com",
            "example-.com",
            "exam_ple.com",
            "example.com..",
            "a%2eb",
            "\u{0}example.com",
        ] {
            assert!(
                normalize_domain(bad).is_err(),
                "expected rejection of {:?}",
                bad
            );
        }
        let long_label = format!("{}.example", "a".repeat(64));
        assert!(normalize_domain(&long_label).is_err());
        let long_name = format!("{}.example", vec!["abcdefghij"; 26].join("."));
        assert!(normalize_domain(&long_name).is_err());
    }

    #[test]
    fn validates_https_url_for_domain() {
        assert!(validate_https_url_for_domain(
            "https://example.com/.well-known/agent-identity-revocations.json",
            "example.com"
        )
        .is_ok());
        assert!(validate_https_url_for_domain(
            "https://EXAMPLE.com/.well-known/agent-identity-revocations.json",
            "example.com."
        )
        .is_ok());
        for bad in [
            "http://example.com/x",
            "https://other.com/x",
            "https://example.com:8443/x",
            "https://user@example.com/x",
            "https://169.254.169.254/latest/meta-data/",
            "https://[::1]/x",
            "https://example.com/x#frag",
            "ftp://example.com/x",
            "not a url",
        ] {
            assert!(
                validate_https_url_for_domain(bad, "example.com").is_err(),
                "expected rejection of {:?}",
                bad
            );
        }
    }
}
