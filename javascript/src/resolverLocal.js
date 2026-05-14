/**
 * LocalAgentCardStore (v0.3.0) — in-memory A2A AgentCard store.
 *
 * Mirrors the Rust `agentpin::resolver_local` module. For agents that don't
 * serve HTTP themselves (CLI tools, daemon processes, external agents pushed
 * into a coordinator at registration time), the coordinator can keep their
 * AgentCards in memory and look them up by domain without making network
 * calls — supporting Symbiont's push-based external-agent registration flow.
 */

import { verifyAgentpinExtension } from './a2a.js';
import { AllowedDomains } from './discovery.js';
import { AgentStatus, EntityType, AgentPinError, ErrorCode } from './types.js';

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
    let url;
    try {
        url = new URL(ext.agentpin_endpoint);
    } catch (err) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            `Invalid agentpin_endpoint URL: ${err.message || err}`
        );
    }
    if (!url.hostname) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            'agentpin_endpoint URL has no host'
        );
    }
    return url.hostname;
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
    const allowedDomains = (card.capabilities && card.capabilities.allowed_domains) || [];
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
        agentpin_version: '0.3',
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
 * In-memory store of pre-registered A2A AgentCards keyed by their AgentPin
 * discovery domain.
 *
 * Cards are added via `register(card)` (after the extension signature is
 * verified) and looked up via `resolveDiscovery(domain)`. Pair with a
 * `ChainResolver` (or wrap manually) to fall back to HTTP for unregistered
 * domains.
 */
export class LocalAgentCardStore {
    constructor() {
        this._cards = new Map();
        this._docs = new Map();
    }

    /**
     * Register an AgentCard. Verifies the extension signature before storing.
     * Re-registering an existing domain replaces the prior entry — useful for
     * handling key rotations.
     *
     * @param {object} card
     */
    register(card) {
        verifyAgentpinExtension(card);
        const domain = cardEndpointHost(card);
        const discovery = deriveDiscoveryFromCard(card);
        this._cards.set(domain, card);
        this._docs.set(domain, discovery);
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
        return this._cards.get(domain) || null;
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
        const doc = this._docs.get(domain);
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
        const had = this._cards.delete(domain);
        this._docs.delete(domain);
        return had;
    }
}
