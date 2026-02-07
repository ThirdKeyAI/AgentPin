use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Constraints {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_domains: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denied_domains: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_classification_max: Option<DataClassification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_allowlist: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub valid_hours: Option<ValidHours>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ValidHours {
    pub start: String,
    pub end: String,
    pub timezone: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DataClassification {
    Public,
    Internal,
    Confidential,
    Restricted,
}

/// Check that credential constraints are equal to or more restrictive than discovery defaults.
/// Returns true if `credential` is a valid subset/restriction of `discovery`.
pub fn constraints_subset_of(
    discovery: &Option<Constraints>,
    credential: &Option<Constraints>,
) -> bool {
    let disc = match discovery {
        Some(d) => d,
        None => return true, // No discovery constraints means anything is valid
    };

    let cred = match credential {
        Some(c) => c,
        None => return true, // No credential constraints is fine (defaults apply)
    };

    // Data classification: credential max must be ≤ discovery max
    if let (Some(disc_max), Some(cred_max)) =
        (&disc.data_classification_max, &cred.data_classification_max)
    {
        if cred_max > disc_max {
            return false;
        }
    }

    // Rate limit: credential rate must be ≤ discovery rate
    if let (Some(disc_rate), Some(cred_rate)) = (&disc.rate_limit, &cred.rate_limit) {
        if let (Some(disc_count), Some(cred_count)) =
            (parse_rate_limit(disc_rate), parse_rate_limit(cred_rate))
        {
            if cred_count > disc_count {
                return false;
            }
        }
    }

    // Allowed domains: credential allowed domains should be a subset of discovery allowed domains
    if let (Some(disc_domains), Some(cred_domains)) = (&disc.allowed_domains, &cred.allowed_domains)
    {
        for cred_domain in cred_domains {
            if !disc_domains
                .iter()
                .any(|d| domain_pattern_matches(d, cred_domain))
            {
                return false;
            }
        }
    }

    true
}

/// Parse a rate limit string like "100/hour" into requests per hour.
fn parse_rate_limit(rate: &str) -> Option<u64> {
    let parts: Vec<&str> = rate.split('/').collect();
    if parts.len() != 2 {
        return None;
    }
    let count: u64 = parts[0].parse().ok()?;
    let per_hour = match parts[1] {
        "second" => count * 3600,
        "minute" => count * 60,
        "hour" => count,
        _ => return None,
    };
    Some(per_hour)
}

/// Check if a domain pattern matches a domain.
/// Supports `*` wildcard prefix for subdomain matching.
fn domain_pattern_matches(pattern: &str, domain: &str) -> bool {
    if pattern == domain {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        return domain.ends_with(suffix)
            && (domain.len() > suffix.len())
            && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.';
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_data_classification_ordering() {
        assert!(DataClassification::Public < DataClassification::Internal);
        assert!(DataClassification::Internal < DataClassification::Confidential);
        assert!(DataClassification::Confidential < DataClassification::Restricted);
    }

    #[test]
    fn test_parse_rate_limit() {
        assert_eq!(parse_rate_limit("100/hour"), Some(100));
        assert_eq!(parse_rate_limit("10/minute"), Some(600));
        assert_eq!(parse_rate_limit("1/second"), Some(3600));
    }

    #[test]
    fn test_domain_pattern_matches() {
        assert!(domain_pattern_matches("example.com", "example.com"));
        assert!(domain_pattern_matches("*.example.com", "sub.example.com"));
        assert!(!domain_pattern_matches("*.example.com", "example.com"));
        assert!(!domain_pattern_matches("other.com", "example.com"));
    }

    #[test]
    fn test_constraints_subset() {
        let disc = Some(Constraints {
            data_classification_max: Some(DataClassification::Confidential),
            rate_limit: Some("100/hour".to_string()),
            ..Default::default()
        });
        let cred_ok = Some(Constraints {
            data_classification_max: Some(DataClassification::Internal),
            rate_limit: Some("50/hour".to_string()),
            ..Default::default()
        });
        assert!(constraints_subset_of(&disc, &cred_ok));

        let cred_bad = Some(Constraints {
            data_classification_max: Some(DataClassification::Restricted),
            ..Default::default()
        });
        assert!(!constraints_subset_of(&disc, &cred_bad));
    }

    #[test]
    fn test_constraints_serde_roundtrip() {
        let c = Constraints {
            allowed_domains: Some(vec!["*.example.com".to_string()]),
            rate_limit: Some("50/hour".to_string()),
            data_classification_max: Some(DataClassification::Internal),
            ..Default::default()
        };
        let json = serde_json::to_string(&c).unwrap();
        let c2: Constraints = serde_json::from_str(&json).unwrap();
        assert_eq!(c, c2);
    }
}
