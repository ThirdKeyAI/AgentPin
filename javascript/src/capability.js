/**
 * Capability parsing, matching, and validation for AgentPin.
 */

import { sha256Hex } from './crypto.js';

/**
 * A capability in `action:resource` format.
 */
export class Capability {
    /**
     * @param {string} value - Full capability string in `action:resource` format
     */
    constructor(value) {
        this.value = value;
    }

    /**
     * Create a new capability from action and resource.
     * @param {string} action
     * @param {string} resource
     * @returns {Capability}
     */
    static create(action, resource) {
        return new Capability(`${action}:${resource}`);
    }

    /**
     * Parse a capability string into [action, resource].
     * @param {string} s
     * @returns {[string, string] | null}
     */
    static parse(s) {
        const idx = s.indexOf(':');
        if (idx === -1) return null;
        return [s.substring(0, idx), s.substring(idx + 1)];
    }

    /** @returns {string|null} */
    get action() {
        const parsed = Capability.parse(this.value);
        return parsed ? parsed[0] : null;
    }

    /** @returns {string|null} */
    get resource() {
        const parsed = Capability.parse(this.value);
        return parsed ? parsed[1] : null;
    }

    /**
     * Check if this capability (from a discovery document) matches a requested capability.
     * Wildcard resources (`*`) match any resource with the same action.
     * Scoped resources match if the requested resource starts with the declared resource + '.'.
     * @param {Capability} requested
     * @returns {boolean}
     */
    matches(requested) {
        const selfParsed = Capability.parse(this.value);
        const reqParsed = Capability.parse(requested.value);
        if (!selfParsed || !reqParsed) return false;

        const [selfAction, selfResource] = selfParsed;
        const [reqAction, reqResource] = reqParsed;

        if (selfAction !== reqAction) return false;
        if (selfResource === '*') return true;
        if (selfResource === reqResource) return true;

        // Scoped matching: "read:codebase" matches "read:codebase.github.com/org/repo"
        if (reqResource.startsWith(selfResource) &&
            reqResource.charAt(selfResource.length) === '.') {
            return true;
        }

        return false;
    }

    toString() {
        return this.value;
    }

    toJSON() {
        return this.value;
    }
}

/**
 * Check that all requested capabilities are covered by declared capabilities.
 * @param {Capability[]} declared
 * @param {Capability[]} requested
 * @returns {boolean}
 */
export function capabilitiesSubset(declared, requested) {
    return requested.every(req =>
        declared.some(decl => decl.matches(req))
    );
}

/**
 * Hash capabilities for delegation attestation: SHA-256 of sorted JSON array.
 * @param {Capability[]} capabilities
 * @returns {string} Hex-encoded SHA-256 hash
 */
export function capabilitiesHash(capabilities) {
    const sorted = capabilities.map(c => c.value).sort();
    const json = JSON.stringify(sorted);
    return sha256Hex(json);
}
