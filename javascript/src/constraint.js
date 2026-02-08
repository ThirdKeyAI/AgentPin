/**
 * Constraint validation for AgentPin.
 */

import { DATA_CLASSIFICATION_ORDER } from './types.js';

/**
 * Parse a rate limit string like "100/hour" into requests per hour.
 * @param {string} rate
 * @returns {number|null}
 */
export function parseRateLimit(rate) {
    const parts = rate.split('/');
    if (parts.length !== 2) return null;

    const count = parseInt(parts[0], 10);
    if (isNaN(count)) return null;

    switch (parts[1]) {
    case 'second':
        return count * 3600;
    case 'minute':
        return count * 60;
    case 'hour':
        return count;
    default:
        return null;
    }
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

    if (pattern.startsWith('*.')) {
        const suffix = pattern.substring(2);
        return domain.endsWith(suffix) &&
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
    if (!discoveryConstraints) return true;
    if (!credentialConstraints) return true;

    // Data classification: credential max must be <= discovery max
    if (discoveryConstraints.data_classification_max && credentialConstraints.data_classification_max) {
        const discOrder = DATA_CLASSIFICATION_ORDER[discoveryConstraints.data_classification_max];
        const credOrder = DATA_CLASSIFICATION_ORDER[credentialConstraints.data_classification_max];
        if (discOrder !== undefined && credOrder !== undefined && credOrder > discOrder) {
            return false;
        }
    }

    // Rate limit: credential rate must be <= discovery rate
    if (discoveryConstraints.rate_limit && credentialConstraints.rate_limit) {
        const discCount = parseRateLimit(discoveryConstraints.rate_limit);
        const credCount = parseRateLimit(credentialConstraints.rate_limit);
        if (discCount !== null && credCount !== null && credCount > discCount) {
            return false;
        }
    }

    // Allowed domains: credential allowed domains should be a subset of discovery allowed domains
    if (discoveryConstraints.allowed_domains && credentialConstraints.allowed_domains) {
        for (const credDomain of credentialConstraints.allowed_domains) {
            if (!discoveryConstraints.allowed_domains.some(d => domainPatternMatches(d, credDomain))) {
                return false;
            }
        }
    }

    return true;
}
