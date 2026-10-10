/**
 * TOFU (Trust On First Use) key pinning store for AgentPin.
 */

import { jwkThumbprint } from './jwk.js';
import { normalizeDomain } from './domain.js';
import { AgentPinError, ErrorCode, TrustLevel } from './types.js';

/** Pin-store key: the normalized hostname when valid, the raw string otherwise (AP-3). */
function pinKey(domain) {
    try {
        return normalizeDomain(domain);
    } catch {
        return String(domain);
    }
}

/** Pinning result enum values. */
export const PinningResult = Object.freeze({
    FIRST_USE: 'first_use',
    MATCHED: 'matched',
    CHANGED: 'changed',
    /** Not pinned, but published next to an already-pinned key: pinned as a rotation (spec §7.2). */
    ROTATED: 'rotated',
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
     * Check a single key against the pin store. If this is the first time
     * seeing the domain, the key is pinned (TOFU). Prefer checkAndPinSet when
     * the full validated discovery document is available.
     * @param {string} domain
     * @param {object} jwk
     * @returns {string} One of PinningResult values
     */
    checkAndPin(domain, jwk) {
        return this.checkAndPinSet(domain, jwk, [jwk]);
    }

    /**
     * Check `jwk` against the pin store using the key set of a validated
     * discovery document (spec §7.3 "pins the public key(s)").
     *
     * - First use: every key in `documentKeys` (plus `jwk`) is pinned.
     * - Known domain, `jwk` pinned: MATCHED.
     * - Known domain, `jwk` not pinned, but another key in `documentKeys` is
     *   already pinned: `jwk` is pinned and ROTATED is returned.
     * - Otherwise CHANGED; nothing is modified.
     * @param {string} domain
     * @param {object} jwk
     * @param {object[]} documentKeys
     * @returns {string} One of PinningResult values
     */
    checkAndPinSet(domain, jwk, documentKeys) {
        domain = pinKey(domain);
        const keyHash = jwkThumbprint(jwk);
        const now = new Date().toISOString();

        const pinned = this.domains.get(domain);
        if (!pinned) {
            this.domains.set(domain, { domain, pinned_keys: [] });
            this.addKey(domain, jwk);
            for (const k of documentKeys || []) this.addKey(domain, k);
            return PinningResult.FIRST_USE;
        }

        const existing = pinned.pinned_keys.find(pk => pk.public_key_hash === keyHash);
        if (existing) {
            existing.last_seen = now;
            return PinningResult.MATCHED;
        }

        const continuity = (documentKeys || []).some((k) => {
            const h = jwkThumbprint(k);
            return h !== keyHash && pinned.pinned_keys.some(pk => pk.public_key_hash === h);
        });
        if (continuity) {
            this.addKey(domain, jwk);
            return PinningResult.ROTATED;
        }
        return PinningResult.CHANGED;
    }

    /**
     * Add a key to an existing domain's pin set (e.g., during key rotation).
     * @param {string} domain
     * @param {object} jwk
     */
    addKey(domain, jwk) {
        domain = pinKey(domain);
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
        return this.domains.get(pinKey(domain)) || null;
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
            const key = pinKey(d.domain);
            const existing = store.domains.get(key);
            if (existing) {
                // Merge entries that differ only by case into one pin set.
                for (const pk of d.pinned_keys || []) {
                    if (!existing.pinned_keys.some((e) => e.public_key_hash === pk.public_key_hash)) {
                        existing.pinned_keys.push(pk);
                    }
                }
            } else {
                store.domains.set(key, { ...d, domain: key, pinned_keys: [...(d.pinned_keys || [])] });
            }
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
    return checkPinningSet(store, domain, jwk, [jwk]);
}

/**
 * checkPinning over a validated document's key set; see KeyPinStore.checkAndPinSet.
 * @param {KeyPinStore} store
 * @param {string} domain
 * @param {object} jwk
 * @param {object[]} documentKeys
 * @returns {string} PinningResult value
 * @throws {AgentPinError}
 */
export function checkPinningSet(store, domain, jwk, documentKeys) {
    const result = store.checkAndPinSet(domain, jwk, documentKeys);
    if (result === PinningResult.CHANGED) {
        throw new AgentPinError(
            ErrorCode.KEY_PIN_MISMATCH,
            `Key for domain '${domain}' has changed since last pinned (kid: '${jwk.kid}')`
        );
    }
    return result;
}
