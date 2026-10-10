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
    merge_constraints(discovery.as_ref(), credential.as_ref()).is_ok()
}

/// Compute the effective constraints of a credential: the discovery
/// declaration's defaults narrowed by whatever the credential declares.
///
/// Every field is compared (AP-15): the credential may only narrow, never
/// widen, and the merged value is what a consumer must enforce. Omitting a
/// field in the credential therefore inherits the discovery default instead
/// of silently dropping it. An unparsable `rate_limit` on either side is a
/// violation.
///
/// Returns `Ok(None)` when neither side declares constraints, `Ok(Some)`
/// with the merged constraints otherwise, and `Err(reason)` when the
/// credential tries to widen a discovery constraint.
pub fn merge_constraints(
    discovery: Option<&Constraints>,
    credential: Option<&Constraints>,
) -> Result<Option<Constraints>, String> {
    let (disc, cred) = match (discovery, credential) {
        (None, None) => return Ok(None),
        (Some(d), None) => return Ok(Some(d.clone())),
        (None, Some(c)) => {
            validate_rate_limit_field(&c.rate_limit)?;
            return Ok(Some(c.clone()));
        }
        (Some(d), Some(c)) => (d, c),
    };
    let mut merged = disc.clone();

    // Data classification: credential max must be <= discovery max.
    if let Some(cred_max) = cred.data_classification_max {
        if let Some(disc_max) = disc.data_classification_max {
            if cred_max > disc_max {
                return Err(format!(
                    "data_classification_max {:?} exceeds discovery maximum {:?}",
                    cred_max, disc_max
                ));
            }
        }
        merged.data_classification_max = Some(cred_max);
    }

    // Rate limit: credential rate must be <= discovery rate; unparsable is a
    // violation.
    validate_rate_limit_field(&disc.rate_limit)?;
    validate_rate_limit_field(&cred.rate_limit)?;
    if let Some(ref cred_rate) = cred.rate_limit {
        if let Some(ref disc_rate) = disc.rate_limit {
            let cred_count = parse_rate_limit(cred_rate).ok_or("unparsable rate_limit")?;
            let disc_count = parse_rate_limit(disc_rate).ok_or("unparsable rate_limit")?;
            if cred_count > disc_count {
                return Err(format!(
                    "rate_limit {} exceeds discovery limit {}",
                    cred_rate, disc_rate
                ));
            }
        }
        merged.rate_limit = Some(cred_rate.clone());
    }

    // Allowed domains: every credential entry must be covered by a discovery
    // pattern.
    if let Some(ref cred_domains) = cred.allowed_domains {
        if let Some(ref disc_domains) = disc.allowed_domains {
            for cd in cred_domains {
                if !disc_domains.iter().any(|d| domain_pattern_matches(d, cd)) {
                    return Err(format!(
                        "allowed_domains entry '{}' is not covered by discovery allowed_domains",
                        cd
                    ));
                }
            }
        }
        merged.allowed_domains = Some(cred_domains.clone());
    }

    // Denied domains: the credential may only add denials; the effective
    // list is the union.
    if let Some(ref cred_denied) = cred.denied_domains {
        let mut union = disc.denied_domains.clone().unwrap_or_default();
        for d in cred_denied {
            if !union.contains(d) {
                union.push(d.clone());
            }
        }
        merged.denied_domains = Some(union);
    }

    // IP allowlist: credential entries must be a subset of the discovery
    // entries (compared as strings; no CIDR arithmetic).
    if let Some(ref cred_ips) = cred.ip_allowlist {
        if let Some(ref disc_ips) = disc.ip_allowlist {
            for ip in cred_ips {
                if !disc_ips.contains(ip) {
                    return Err(format!(
                        "ip_allowlist entry '{}' is not in discovery ip_allowlist",
                        ip
                    ));
                }
            }
        }
        merged.ip_allowlist = Some(cred_ips.clone());
    }

    // Valid hours: the credential window must lie within the discovery
    // window in the same timezone.
    if let Some(ref cred_hours) = cred.valid_hours {
        if let Some(ref disc_hours) = disc.valid_hours {
            if cred_hours.timezone != disc_hours.timezone
                || cred_hours.start < disc_hours.start
                || cred_hours.end > disc_hours.end
            {
                return Err("valid_hours widens the discovery window".to_string());
            }
        }
        merged.valid_hours = Some(cred_hours.clone());
    }

    Ok(Some(merged))
}

fn validate_rate_limit_field(rate: &Option<String>) -> Result<(), String> {
    match rate {
        Some(r) if parse_rate_limit(r).is_none() => Err(format!("unparsable rate_limit '{}'", r)),
        _ => Ok(()),
    }
}

/// Parse a rate limit string like "100/hour" into requests per hour.
/// Returns `None` for malformed strings or values that would overflow.
pub fn parse_rate_limit(rate: &str) -> Option<u64> {
    let (count, period) = rate.split_once('/')?;
    if count.is_empty() || !count.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let count: u64 = count.parse().ok()?;
    match period {
        "second" => count.checked_mul(3600),
        "minute" => count.checked_mul(60),
        "hour" => Some(count),
        _ => None,
    }
}

/// Check if a domain pattern matches a domain.
/// Supports `*` wildcard prefix for subdomain matching.
pub fn domain_pattern_matches(pattern: &str, domain: &str) -> bool {
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
        // AP-15: overflow and junk are None, never a wrapped number.
        assert_eq!(parse_rate_limit("18446744073709551615/second"), None);
        assert_eq!(parse_rate_limit("unlimited/hour"), None);
        assert_eq!(parse_rate_limit("-5/hour"), None);
        assert_eq!(parse_rate_limit("5/day"), None);
    }

    /// AP-15: omitted credential fields inherit the discovery defaults, every
    /// field is compared, unparsable rate limits are violations.
    #[test]
    fn test_merge_constraints() {
        let disc = Constraints {
            allowed_domains: Some(vec!["*.client-corp.com".to_string()]),
            denied_domains: Some(vec!["internal.client-corp.com".to_string()]),
            rate_limit: Some("100/hour".to_string()),
            data_classification_max: Some(DataClassification::Confidential),
            ip_allowlist: Some(vec![
                "203.0.113.0/24".to_string(),
                "198.51.100.0/24".to_string(),
            ]),
            valid_hours: Some(ValidHours {
                start: "08:00".to_string(),
                end: "18:00".to_string(),
                timezone: "UTC".to_string(),
            }),
        };

        // Credential omits constraints entirely: discovery defaults apply.
        let merged = merge_constraints(Some(&disc), None).unwrap().unwrap();
        assert_eq!(merged, disc);

        // Credential omits allowed_domains but narrows the rest: allowed
        // domains are inherited, not dropped.
        let cred = Constraints {
            rate_limit: Some("1/minute".to_string()),
            data_classification_max: Some(DataClassification::Internal),
            denied_domains: Some(vec!["staging.client-corp.com".to_string()]),
            ..Default::default()
        };
        let merged = merge_constraints(Some(&disc), Some(&cred))
            .unwrap()
            .unwrap();
        assert_eq!(merged.allowed_domains, disc.allowed_domains);
        assert_eq!(merged.rate_limit.as_deref(), Some("1/minute"));
        assert_eq!(
            merged.data_classification_max,
            Some(DataClassification::Internal)
        );
        assert_eq!(
            merged.denied_domains.unwrap(),
            vec![
                "internal.client-corp.com".to_string(),
                "staging.client-corp.com".to_string()
            ]
        );
        assert_eq!(merged.ip_allowlist, disc.ip_allowlist);
        assert_eq!(merged.valid_hours, disc.valid_hours);

        // Widening attempts on each field are violations.
        let widen = |c: Constraints| merge_constraints(Some(&disc), Some(&c)).is_err();
        assert!(widen(Constraints {
            allowed_domains: Some(vec!["evil.com".to_string()]),
            ..Default::default()
        }));
        assert!(widen(Constraints {
            rate_limit: Some("1000/hour".to_string()),
            ..Default::default()
        }));
        assert!(widen(Constraints {
            rate_limit: Some("unlimited/hour".to_string()),
            ..Default::default()
        }));
        assert!(widen(Constraints {
            data_classification_max: Some(DataClassification::Restricted),
            ..Default::default()
        }));
        assert!(widen(Constraints {
            ip_allowlist: Some(vec!["0.0.0.0/0".to_string()]),
            ..Default::default()
        }));
        assert!(widen(Constraints {
            valid_hours: Some(ValidHours {
                start: "07:00".to_string(),
                end: "18:00".to_string(),
                timezone: "UTC".to_string()
            }),
            ..Default::default()
        }));
        assert!(widen(Constraints {
            valid_hours: Some(ValidHours {
                start: "09:00".to_string(),
                end: "17:00".to_string(),
                timezone: "America/New_York".to_string()
            }),
            ..Default::default()
        }));

        // Narrowing on each field is accepted and reflected in the merge.
        let narrow = Constraints {
            allowed_domains: Some(vec!["api.client-corp.com".to_string()]),
            ip_allowlist: Some(vec!["203.0.113.0/24".to_string()]),
            valid_hours: Some(ValidHours {
                start: "09:00".to_string(),
                end: "17:00".to_string(),
                timezone: "UTC".to_string(),
            }),
            ..Default::default()
        };
        let merged = merge_constraints(Some(&disc), Some(&narrow))
            .unwrap()
            .unwrap();
        assert_eq!(merged.allowed_domains, narrow.allowed_domains);
        assert_eq!(merged.ip_allowlist, narrow.ip_allowlist);
        assert_eq!(merged.valid_hours, narrow.valid_hours);
        assert_eq!(merged.rate_limit, disc.rate_limit);

        // No discovery constraints: the credential's own are returned, but an
        // unparsable rate limit is still a violation.
        assert!(merge_constraints(
            None,
            Some(&Constraints {
                rate_limit: Some("x/hour".to_string()),
                ..Default::default()
            })
        )
        .is_err());
        assert_eq!(merge_constraints(None, None).unwrap(), None);
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
