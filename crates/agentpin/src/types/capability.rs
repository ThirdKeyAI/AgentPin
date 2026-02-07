use serde::{Deserialize, Serialize};

use crate::crypto;

/// A capability in `action:resource` format.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Capability(pub String);

impl Capability {
    pub fn new(action: &str, resource: &str) -> Self {
        Capability(format!("{}:{}", action, resource))
    }

    pub fn parse(s: &str) -> Option<(&str, &str)> {
        s.split_once(':')
    }

    pub fn action(&self) -> Option<&str> {
        Self::parse(&self.0).map(|(a, _)| a)
    }

    pub fn resource(&self) -> Option<&str> {
        Self::parse(&self.0).map(|(_, r)| r)
    }

    /// Check if this capability (from a discovery document) matches a requested capability.
    /// Wildcard resources (`*`) match any resource with the same action.
    /// Scoped resources match if the requested resource starts with the declared resource.
    pub fn matches(&self, requested: &Capability) -> bool {
        let (self_action, self_resource) = match Self::parse(&self.0) {
            Some(parts) => parts,
            None => return false,
        };
        let (req_action, req_resource) = match Self::parse(&requested.0) {
            Some(parts) => parts,
            None => return false,
        };

        if self_action != req_action {
            return false;
        }

        if self_resource == "*" {
            return true;
        }

        if self_resource == req_resource {
            return true;
        }

        // Scoped matching: "read:codebase" matches "read:codebase.github.com/org/repo"
        if req_resource.starts_with(self_resource)
            && req_resource[self_resource.len()..].starts_with('.')
        {
            return true;
        }

        false
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for Capability {
    fn from(s: &str) -> Self {
        Capability(s.to_string())
    }
}

impl From<String> for Capability {
    fn from(s: String) -> Self {
        Capability(s)
    }
}

/// Check that all requested capabilities are covered by declared capabilities.
pub fn capabilities_subset(declared: &[Capability], requested: &[Capability]) -> bool {
    requested
        .iter()
        .all(|req| declared.iter().any(|decl| decl.matches(req)))
}

/// Hash capabilities for delegation attestation: SHA-256 of sorted JSON array.
pub fn capabilities_hash(capabilities: &[Capability]) -> String {
    let mut sorted: Vec<&str> = capabilities.iter().map(|c| c.0.as_str()).collect();
    sorted.sort();
    let json = serde_json::to_string(&sorted).expect("capabilities serialize");
    crypto::sha256_hex(json.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_capability_parse() {
        let c = Capability::from("read:codebase");
        assert_eq!(c.action(), Some("read"));
        assert_eq!(c.resource(), Some("codebase"));
    }

    #[test]
    fn test_wildcard_match() {
        let wild = Capability::from("read:*");
        assert!(wild.matches(&Capability::from("read:codebase")));
        assert!(wild.matches(&Capability::from("read:database")));
        assert!(!wild.matches(&Capability::from("write:codebase")));
    }

    #[test]
    fn test_exact_match() {
        let cap = Capability::from("write:report");
        assert!(cap.matches(&Capability::from("write:report")));
        assert!(!cap.matches(&Capability::from("write:text")));
    }

    #[test]
    fn test_scoped_match() {
        let cap = Capability::from("read:codebase");
        assert!(cap.matches(&Capability::from("read:codebase.github.com/org/repo")));
        assert!(!cap.matches(&Capability::from("read:codebase_other")));
    }

    #[test]
    fn test_capabilities_subset() {
        let declared = vec![Capability::from("read:*"), Capability::from("write:report")];
        let requested = vec![
            Capability::from("read:codebase"),
            Capability::from("write:report"),
        ];
        assert!(capabilities_subset(&declared, &requested));

        let bad_request = vec![Capability::from("delete:database")];
        assert!(!capabilities_subset(&declared, &bad_request));
    }

    #[test]
    fn test_capabilities_hash_deterministic() {
        let caps = vec![
            Capability::from("write:report"),
            Capability::from("read:codebase"),
        ];
        let h1 = capabilities_hash(&caps);
        let h2 = capabilities_hash(&caps);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_capabilities_hash_order_independent() {
        let caps1 = vec![
            Capability::from("read:codebase"),
            Capability::from("write:report"),
        ];
        let caps2 = vec![
            Capability::from("write:report"),
            Capability::from("read:codebase"),
        ];
        assert_eq!(capabilities_hash(&caps1), capabilities_hash(&caps2));
    }
}
