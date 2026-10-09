/**
 * LocalAgentCardStore (v0.3.0) — in-memory A2A AgentCard store.
 *
 * Mirrors the Rust `agentpin::resolver_local` module. For agents that don't
 * serve HTTP themselves (CLI tools, daemon processes, external agents pushed
 * into a coordinator at registration time), the coordinator can keep their
 * AgentCards in memory and look them up by domain without making network
 * calls — supporting Symbiont's push-based external-agent registration flow.
 */

import { verifyAgentpinExtension, extensionKeyThumbprint } from './a2a.js';
import { jwkThumbprint } from './jwk.js';
import { AllowedDomains } from './discovery.js';
import { httpsUrlHost, normalizeDomain } from './domain.js';
import { AgentStatus, EntityType, AgentPinError, ErrorCode } from './types.js';

/** Store key: the normalized domain when valid, the raw string otherwise. */
function storeKey(domain) {
    try {
        return normalizeDomain(domain);
    } catch {
        return String(domain);
    }
}

/**
 * Derive the host portion of an AgentCard's agentpin endpoint URL.
 *
 * `https://example.com/.well-known/agent-identity.json` -> `example.com`.
 *
 * @param {object} card
 * @returns {string}
 */
export function cardEndpointHost(card) {
    const ext = card && card.agentpin;
    if (!ext) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            'AgentCard has no agentpin extension'
        );
    }
    // The endpoint must be https with a domain host and no userinfo, port
    // or fragment; the returned host is normalized (AP-3, AP-12).
    try {
        return httpsUrlHost(ext.agentpin_endpoint);
    } catch (err) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            `Invalid agentpin_endpoint URL: ${err.message || err}`
        );
    }
}

function slug(input) {
    return input
        .split('')
        .map((c) => (/[A-Za-z0-9]/.test(c) ? c.toLowerCase() : '-'))
        .join('')
        .replace(/^-+|-+$/g, '');
}

/**
 * Derive a minimal `DiscoveryDocument` from a signed A2A AgentCard.
 *
 * Mirrors `derive_discovery_from_card` in the Rust SDK — the card's
 * public-key JWK becomes the sole `public_keys` entry; the card's
 * name/description/version/skills become a single `AgentDeclaration` so the
 * rest of the AgentPin verification stack (TOFU pinning, revocation,
 * capability validation) runs against AgentCards unchanged.
 *
 * @param {object} card
 * @returns {object}
 */
export function deriveDiscoveryFromCard(card) {
    const ext = card.agentpin;
    if (!ext) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            'AgentCard has no agentpin extension'
        );
    }
    const domain = cardEndpointHost(card);

    const capabilities = (card.skills || []).map((s) => s.id);
    const allowedDomains = card.capabilities ? card.capabilities.allowed_domains : undefined;
    const constraints = AllowedDomains.isUnrestricted(allowedDomains)
        ? null
        : { allowed_domains: [...allowedDomains] };

    const agentId = `urn:agentpin:${domain}:${slug(card.name)}`;
    const agent = {
        agent_id: agentId,
        name: card.name,
        capabilities,
        status: AgentStatus.ACTIVE,
    };
    if (card.description !== undefined && card.description !== null) {
        agent.description = card.description;
    }
    if (card.version !== undefined && card.version !== null) {
        agent.version = card.version;
    }
    if (constraints) {
        agent.constraints = constraints;
    }

    return {
        agentpin_version: '0.1',
        entity: domain,
        entity_type: EntityType.BOTH,
        public_keys: [ext.public_key_jwk],
        agents: [agent],
        a2a_endpoint: ext.agentpin_endpoint,
        max_delegation_depth: 0,
        updated_at: new Date().toISOString(),
    };
}

/**
 * `true` when the card's extension key appears, by RFC 7638 thumbprint, in
 * `doc.public_keys` (spec §4.10.4 step 5).
 * @param {object} doc
 * @param {object} card
 * @returns {boolean}
 */
export function cardKeyPublishedIn(doc, card) {
    const ext = card && card.agentpin;
    if (!ext || !doc || !Array.isArray(doc.public_keys)) return false;
    const tp = extensionKeyThumbprint(ext);
    return doc.public_keys.some((k) => jwkThumbprint(k) === tp);
}

/**
 * In-memory store of pre-registered A2A AgentCards keyed by their AgentPin
 * discovery domain.
 *
 * Cards are added via `register(card)` (after the extension signature is
 * verified and the trust anchor accepts the key) and looked up via
 * `resolveDiscovery(domain)`. Pair with a `ChainResolver` (or wrap manually)
 * to fall back to HTTP for unregistered domains.
 *
 * Trust anchor (spec §4.10.4 step 5, AP-4, design issue 9): an AgentCard is
 * self-certifying, so verifying its signature proves nothing about which
 * domain it speaks for. The constructor therefore takes one of:
 *
 * - `{ trustedThumbprints: [...] }` — allowlist of JWK thumbprints the
 *   operator verified out of band (the default is an empty allowlist, which
 *   refuses every registration until `trustThumbprint` is called);
 * - `{ resolver }` — the card key must be published, by thumbprint, in the
 *   endpoint domain's discovery document as returned by
 *   `resolver.resolveDiscovery(domain)`;
 * - `{ unanchored: true }` — explicit opt-out for callers whose registration
 *   channel already authenticates the registrant for the domain it claims
 *   (the "documented substitute provenance check" the spec allows).
 */
export class LocalAgentCardStore {
    /**
     * @param {object} [options]
     * @param {string[]} [options.trustedThumbprints]
     * @param {{ resolveDiscovery: Function }} [options.resolver]
     * @param {boolean} [options.unanchored]
     */
    constructor(options = {}) {
        this._cards = new Map();
        this._docs = new Map();
        this._unanchored = !!options.unanchored;
        this._resolver = options.resolver || null;
        this._trusted = (this._unanchored || this._resolver)
            ? null
            : new Set(options.trustedThumbprints || []);
    }

    /**
     * Add a trusted key thumbprint. Only meaningful for allowlist-anchored
     * stores.
     * @param {string} thumbprint
     */
    trustThumbprint(thumbprint) {
        if (!this._trusted) {
            throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'LocalAgentCardStore is not anchored on a thumbprint allowlist');
        }
        this._trusted.add(thumbprint);
    }

    _checkAnchor(card, domain) {
        const tp = extensionKeyThumbprint(card.agentpin);
        if (this._unanchored) return;
        if (this._resolver) {
            const doc = this._resolver.resolveDiscovery(domain);
            if (doc && typeof doc.then === 'function') {
                throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'LocalAgentCardStore requires a synchronous resolver');
            }
            if (!cardKeyPublishedIn(doc, card)) {
                throw new AgentPinError(
                    ErrorCode.DISCOVERY_INVALID,
                    `AgentCard key ${tp} is not published in the discovery document for '${domain}'`
                );
            }
            return;
        }
        if (!this._trusted.has(tp)) {
            throw new AgentPinError(
                ErrorCode.DISCOVERY_INVALID,
                `AgentCard key ${tp} is not a trusted thumbprint for domain '${domain}'`
            );
        }
    }

    /**
     * Register an AgentCard. Verifies the extension signature, requires the
     * trust anchor to accept the card key for the endpoint's domain, then
     * stores it. Re-registering an existing domain replaces the prior entry —
     * useful for handling key rotations.
     *
     * @param {object} card
     */
    register(card) {
        verifyAgentpinExtension(card);
        const domain = cardEndpointHost(card);
        this._checkAnchor(card, domain);
        const discovery = deriveDiscoveryFromCard(card);
        this._cards.set(domain, card);
        this._docs.set(domain, discovery);
    }

    /**
     * `register`, additionally requiring the card's endpoint host to equal
     * `expectedDomain` (normalized).
     * @param {object} card
     * @param {string} expectedDomain
     */
    registerForDomain(card, expectedDomain) {
        const expected = normalizeDomain(expectedDomain);
        const host = cardEndpointHost(card);
        if (host !== expected) {
            throw new AgentPinError(
                ErrorCode.DOMAIN_MISMATCH,
                `AgentCard agentpin_endpoint host '${host}' does not match expected domain '${expected}'`
            );
        }
        this.register(card);
    }

    /** Number of registered AgentCards. */
    get size() {
        return this._cards.size;
    }

    /** `true` when no AgentCards are registered. */
    isEmpty() {
        return this._cards.size === 0;
    }

    /**
     * Return the raw AgentCard for a domain, or `null` when none registered.
     * @param {string} domain
     * @returns {object|null}
     */
    resolveCard(domain) {
        return this._cards.get(storeKey(domain)) || null;
    }

    /**
     * Resolve the derived discovery document for a domain.
     *
     * Throws `AgentPinError(DISCOVERY_INVALID)` when the domain isn't
     * registered.
     *
     * @param {string} domain
     * @returns {object}
     */
    resolveDiscovery(domain) {
        const doc = this._docs.get(storeKey(domain));
        if (!doc) {
            throw new AgentPinError(
                ErrorCode.DISCOVERY_INVALID,
                `Domain '${domain}' not in LocalAgentCardStore`
            );
        }
        return doc;
    }

    /**
     * The store doesn't carry revocation data — pair with an HTTP or file
     * resolver for revocation. Always returns `null`.
     */
    resolveRevocation(_domain, _discovery) {
        return null;
    }

    /**
     * Drop a registered AgentCard. Returns `true` when one was removed.
     * @param {string} domain
     */
    remove(domain) {
        const key = storeKey(domain);
        const had = this._cards.delete(key);
        this._docs.delete(key);
        return had;
    }
}
