/**
 * TOFU (Trust On First Use) key pinning store for AgentPin.
 */

import { jwkThumbprint } from './jwk.js';
import { AgentPinError, ErrorCode, TrustLevel } from './types.js';

/** Pinning result enum values. */
export const PinningResult = Object.freeze({
    FIRST_USE: 'first_use',
    MATCHED: 'matched',
    CHANGED: 'changed',
});

/**
 * In-memory TOFU key pinning store.
 */
export class KeyPinStore {
    constructor() {
        /** @type {Map<string, { domain: string, pinned_keys: object[] }>} */
        this.domains = new Map();
    }

    /**
     * Check a key against the pin store. If this is the first time seeing
     * the domain, the key is pinned (TOFU).
     * @param {string} domain
     * @param {object} jwk
     * @returns {string} One of PinningResult values
     */
    checkAndPin(domain, jwk) {
        const keyHash = jwkThumbprint(jwk);
        const now = new Date().toISOString();

        const pinned = this.domains.get(domain);
        if (pinned) {
            const existing = pinned.pinned_keys.find(pk => pk.public_key_hash === keyHash);
            if (existing) {
                existing.last_seen = now;
                return PinningResult.MATCHED;
            }
            return PinningResult.CHANGED;
        }

        // First time seeing this domain — TOFU pin
        this.domains.set(domain, {
            domain,
            pinned_keys: [{
                kid: jwk.kid,
                public_key_hash: keyHash,
                first_seen: now,
                last_seen: now,
                trust_level: TrustLevel.TOFU,
            }],
        });
        return PinningResult.FIRST_USE;
    }

    /**
     * Add a key to an existing domain's pin set (e.g., during key rotation).
     * @param {string} domain
     * @param {object} jwk
     */
    addKey(domain, jwk) {
        const keyHash = jwkThumbprint(jwk);
        const now = new Date().toISOString();

        let pinned = this.domains.get(domain);
        if (!pinned) {
            pinned = { domain, pinned_keys: [] };
            this.domains.set(domain, pinned);
        }

        if (!pinned.pinned_keys.some(pk => pk.public_key_hash === keyHash)) {
            pinned.pinned_keys.push({
                kid: jwk.kid,
                public_key_hash: keyHash,
                first_seen: now,
                last_seen: now,
                trust_level: TrustLevel.TOFU,
            });
        }
    }

    /**
     * Get pinned domain info.
     * @param {string} domain
     * @returns {object|null}
     */
    getDomain(domain) {
        return this.domains.get(domain) || null;
    }

    /**
     * Serialize the store to JSON.
     * @returns {string}
     */
    toJson() {
        return JSON.stringify(Array.from(this.domains.values()), null, 2);
    }

    /**
     * Deserialize the store from JSON.
     * @param {string} json
     * @returns {KeyPinStore}
     */
    static fromJson(json) {
        const store = new KeyPinStore();
        const domains = JSON.parse(json);
        for (const d of domains) {
            store.domains.set(d.domain, d);
        }
        return store;
    }
}

/**
 * Check pinning and throw an error if key has changed.
 * @param {KeyPinStore} store
 * @param {string} domain
 * @param {object} jwk
 * @returns {string} PinningResult value
 * @throws {AgentPinError}
 */
export function checkPinning(store, domain, jwk) {
    const result = store.checkAndPin(domain, jwk);
    if (result === PinningResult.CHANGED) {
        throw new AgentPinError(
            ErrorCode.KEY_PIN_MISMATCH,
            `Key for domain '${domain}' has changed since last pinned (kid: '${jwk.kid}')`
        );
    }
    return result;
}
