/**
 * Constraint validation for AgentPin.
 */

import { DATA_CLASSIFICATION_ORDER } from './types.js';

/**
 * Parse a rate limit string like "100/hour" into requests per hour.
 * Returns null for malformed strings or values that are not safe integers.
 * @param {string} rate
 * @returns {number|null}
 */
export function parseRateLimit(rate) {
    if (typeof rate !== 'string') return null;
    const parts = rate.split('/');
    if (parts.length !== 2 || !/^[0-9]+$/.test(parts[0])) return null;

    const count = Number(parts[0]);
    if (!Number.isSafeInteger(count)) return null;

    let perHour;
    switch (parts[1]) {
    case 'second':
        perHour = count * 3600;
        break;
    case 'minute':
        perHour = count * 60;
        break;
    case 'hour':
        perHour = count;
        break;
    default:
        return null;
    }
    return Number.isSafeInteger(perHour) ? perHour : null;
}

/**
 * Check if a domain pattern matches a domain.
 * Supports `*.` wildcard prefix for subdomain matching.
 * @param {string} pattern
 * @param {string} domain
 * @returns {boolean}
 */
export function domainPatternMatches(pattern, domain) {
    if (pattern === domain) return true;

    if (typeof pattern === 'string' && pattern.startsWith('*.')) {
        const suffix = pattern.substring(2);
        return typeof domain === 'string' && domain.endsWith(suffix) &&
               domain.length > suffix.length &&
               domain.charAt(domain.length - suffix.length - 1) === '.';
    }

    return false;
}

/**
 * Check that credential constraints are equal to or more restrictive than discovery defaults.
 * @param {object|null|undefined} discoveryConstraints
 * @param {object|null|undefined} credentialConstraints
 * @returns {boolean}
 */
export function constraintsSubsetOf(discoveryConstraints, credentialConstraints) {
    try {
        mergeConstraints(discoveryConstraints, credentialConstraints);
        return true;
    } catch {
        return false;
    }
}

function present(v) {
    return v !== undefined && v !== null;
}

function validateRateLimitField(rate) {
    if (present(rate) && parseRateLimit(rate) === null) {
        throw new Error(`unparsable rate_limit '${rate}'`);
    }
}

/**
 * Compute the effective constraints of a credential: the discovery
 * declaration's defaults narrowed by whatever the credential declares
 * (AP-15). Every field is compared; the credential may only narrow, never
 * widen, and omitting a field inherits the discovery default instead of
 * silently dropping it. An unparsable rate_limit on either side throws.
 *
 * @param {object|null|undefined} discovery
 * @param {object|null|undefined} credential
 * @returns {object|null} merged constraints, or null when neither side declares any
 * @throws {Error} when the credential widens a discovery constraint
 */
export function mergeConstraints(discovery, credential) {
    if (!discovery && !credential) return null;
    if (!credential) return { ...discovery };
    if (!discovery) {
        validateRateLimitField(credential.rate_limit);
        return { ...credential };
    }
    const merged = { ...discovery };

    if (present(credential.data_classification_max)) {
        if (present(discovery.data_classification_max)) {
            const discOrder = DATA_CLASSIFICATION_ORDER[discovery.data_classification_max];
            const credOrder = DATA_CLASSIFICATION_ORDER[credential.data_classification_max];
            if (discOrder === undefined || credOrder === undefined || credOrder > discOrder) {
                throw new Error(`data_classification_max ${credential.data_classification_max} exceeds discovery maximum ${discovery.data_classification_max}`);
            }
        }
        merged.data_classification_max = credential.data_classification_max;
    }

    validateRateLimitField(discovery.rate_limit);
    validateRateLimitField(credential.rate_limit);
    if (present(credential.rate_limit)) {
        if (present(discovery.rate_limit) && parseRateLimit(credential.rate_limit) > parseRateLimit(discovery.rate_limit)) {
            throw new Error(`rate_limit ${credential.rate_limit} exceeds discovery limit ${discovery.rate_limit}`);
        }
        merged.rate_limit = credential.rate_limit;
    }

    if (present(credential.allowed_domains)) {
        if (!Array.isArray(credential.allowed_domains)) throw new Error('allowed_domains must be an array');
        if (present(discovery.allowed_domains)) {
            for (const cd of credential.allowed_domains) {
                if (!discovery.allowed_domains.some((d) => domainPatternMatches(d, cd))) {
                    throw new Error(`allowed_domains entry '${cd}' is not covered by discovery allowed_domains`);
                }
            }
        }
        merged.allowed_domains = [...credential.allowed_domains];
    }

    if (present(credential.denied_domains)) {
        if (!Array.isArray(credential.denied_domains)) throw new Error('denied_domains must be an array');
        const union = [...(discovery.denied_domains || [])];
        for (const d of credential.denied_domains) {
            if (!union.includes(d)) union.push(d);
        }
        merged.denied_domains = union;
    }

    if (present(credential.ip_allowlist)) {
        if (!Array.isArray(credential.ip_allowlist)) throw new Error('ip_allowlist must be an array');
        if (present(discovery.ip_allowlist)) {
            for (const ip of credential.ip_allowlist) {
                if (!discovery.ip_allowlist.includes(ip)) {
                    throw new Error(`ip_allowlist entry '${ip}' is not in discovery ip_allowlist`);
                }
            }
        }
        merged.ip_allowlist = [...credential.ip_allowlist];
    }

    if (present(credential.valid_hours)) {
        const c = credential.valid_hours;
        if (present(discovery.valid_hours)) {
            const d = discovery.valid_hours;
            if (c.timezone !== d.timezone || c.start < d.start || c.end > d.end) {
                throw new Error('valid_hours widens the discovery window');
            }
        }
        merged.valid_hours = { ...c };
    }

    return merged;
}
