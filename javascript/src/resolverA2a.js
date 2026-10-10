/**
 * A2aAgentCardResolver (v0.3.0) — fetches A2A AgentCards over HTTPS.
 *
 * Mirrors the Rust `agentpin::resolver_a2a` module:
 *   1. GET https://{domain}/.well-known/agent-card.json
 *   2. Verify the AgentPin extension signature against its embedded JWK
 *   3. Cross-check that the agentpin endpoint inside the card matches the
 *      fetched domain (defends against a card pointing at someone else's
 *      AgentPin discovery)
 *   4. Derive a DiscoveryDocument so the rest of the AgentPin stack runs
 *      unchanged
 */

import { verifyAgentpinExtension } from './a2a.js';
import { cardEndpointHost, deriveDiscoveryFromCard, cardKeyPublishedIn } from './resolverLocal.js';
import { fetchDiscoveryDocument } from './discovery.js';
import { normalizeDomain } from './domain.js';
import { fetchJsonBounded } from './net.js';
import { AgentPinError, ErrorCode } from './types.js';

const AGENT_CARD_PATH = '/.well-known/agent-card.json';
const DEFAULT_TIMEOUT_MS = 10000;

/**
 * Resolver that fetches an A2A AgentCard from a domain over HTTPS and
 * exposes both the original card and the derived discovery document.
 */
export class A2aAgentCardResolver {
    /**
     * @param {object} [options]
     * @param {number} [options.timeoutMs]
     * @param {Function} [options.fetchImpl]
     * @param {boolean} [options.requireDiscoveryBinding=true] - spec §4.10.4
     *   step 5: after the card signature verifies, fetch the domain's
     *   `.well-known/agent-identity.json` and require the card key to be
     *   published there by thumbprint (AP-4). Disable only when another
     *   channel establishes the card's provenance.
     */
    constructor({ timeoutMs = DEFAULT_TIMEOUT_MS, fetchImpl, requireDiscoveryBinding = true } = {}) {
        this.timeoutMs = timeoutMs;
        this._fetch = fetchImpl || globalThis.fetch;
        this.requireDiscoveryBinding = requireDiscoveryBinding;
        this._lastCard = null;
        this._lastDomain = null;
    }

    /**
     * Return the last successfully resolved AgentCard for a domain, or
     * `null` when no card has been resolved for that domain yet.
     */
    lastCard(domain) {
        if (this._lastDomain !== domain) return null;
        return this._lastCard;
    }

    /**
     * Fetch + verify the AgentCard at `https://{domain}/.well-known/agent-card.json`
     * and return the derived discovery document.
     *
     * @param {string} domain
     * @returns {Promise<object>}
     */
    async resolveDiscovery(domain) {
        domain = normalizeDomain(domain);
        const url = `https://${domain}${AGENT_CARD_PATH}`;
        // No redirects (spec §4.8.5), bounded timeout and body size (AP-7, AP-13).
        const card = await fetchJsonBounded(url, {
            fetchImpl: this._fetch,
            timeoutMs: this.timeoutMs,
        });
        if (card === null) {
            throw new AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED, `Failed to fetch ${url}: HTTP 404`);
        }

        verifyAgentpinExtension(card);

        const endpointHost = cardEndpointHost(card);
        if (endpointHost !== domain) {
            throw new AgentPinError(
                ErrorCode.DOMAIN_MISMATCH,
                `AgentCard at ${domain} declares agentpin endpoint host ${endpointHost} (mismatch)`
            );
        }

        // Spec §4.10.4 step 5 (AP-4): bind the card to the AgentPin identity
        // by requiring its key in the authoritative discovery document.
        if (this.requireDiscoveryBinding) {
            const authoritative = await fetchDiscoveryDocument(domain, { fetchImpl: this._fetch, timeoutMs: this.timeoutMs });
            if (!cardKeyPublishedIn(authoritative, card)) {
                throw new AgentPinError(
                    ErrorCode.DISCOVERY_INVALID,
                    `AgentCard key for ${domain} is not published in the domain's discovery document`
                );
            }
        }

        const discovery = deriveDiscoveryFromCard(card);
        this._lastCard = card;
        this._lastDomain = domain;
        return discovery;
    }

    /**
     * A2A AgentCards don't carry revocation data. Pair with a separate
     * revocation resolver if revocation is required. Always returns `null`.
     */
    async resolveRevocation(_domain, _discovery) {
        return null;
    }
}
