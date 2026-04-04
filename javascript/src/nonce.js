/**
 * Nonce deduplication for replay attack prevention.
 */

/**
 * In-memory nonce store that tracks seen nonces with TTL-based expiry.
 */
export class InMemoryNonceStore {
    constructor() {
        /** @type {Map<string, number>} nonce -> expiry timestamp (ms) */
        this._entries = new Map();
    }

    /**
     * Check if nonce is fresh. Returns true if fresh, false if replay.
     * @param {string} nonce
     * @param {number} ttlMs - TTL in milliseconds
     * @returns {boolean}
     */
    checkAndRecord(nonce, ttlMs) {
        const now = Date.now();
        // Lazy cleanup
        for (const [key, expiry] of this._entries) {
            if (expiry <= now) this._entries.delete(key);
        }
        if (this._entries.has(nonce)) return false;
        this._entries.set(nonce, now + ttlMs);
        return true;
    }
}
