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
import { cardEndpointHost, deriveDiscoveryFromCard } from './resolverLocal.js';
import { AgentPinError, ErrorCode } from './types.js';

const AGENT_CARD_PATH = '/.well-known/agent-card.json';
const DEFAULT_TIMEOUT_MS = 10000;

/**
 * Resolver that fetches an A2A AgentCard from a domain over HTTPS and
 * exposes both the original card and the derived discovery document.
 */
export class A2aAgentCardResolver {
    constructor({ timeoutMs = DEFAULT_TIMEOUT_MS, fetchImpl } = {}) {
        this.timeoutMs = timeoutMs;
        this._fetch = fetchImpl || globalThis.fetch;
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
        if (!this._fetch) {
            throw new AgentPinError(
                ErrorCode.DISCOVERY_FETCH_FAILED,
                'No fetch implementation available — pass `fetchImpl` or run on Node >= 18'
            );
        }
        const url = `https://${domain}${AGENT_CARD_PATH}`;
        const controller = typeof AbortController === 'function' ? new AbortController() : null;
        const timer = controller
            ? setTimeout(() => controller.abort(), this.timeoutMs)
            : null;

        let response;
        try {
            response = await this._fetch(url, {
                redirect: 'error',
                headers: { Accept: 'application/json' },
                signal: controller ? controller.signal : undefined,
            });
        } catch (err) {
            throw new AgentPinError(
                ErrorCode.DISCOVERY_FETCH_FAILED,
                `Failed to fetch ${url}: ${err.message || err}`
            );
        } finally {
            if (timer) clearTimeout(timer);
        }

        if (!response.ok) {
            throw new AgentPinError(
                ErrorCode.DISCOVERY_FETCH_FAILED,
                `Failed to fetch ${url}: HTTP ${response.status}`
            );
        }

        let card;
        try {
            card = await response.json();
        } catch (err) {
            throw new AgentPinError(
                ErrorCode.DISCOVERY_INVALID,
                `Failed to parse AgentCard at ${url}: ${err.message || err}`
            );
        }

        verifyAgentpinExtension(card);

        const endpointHost = cardEndpointHost(card);
        if (endpointHost !== domain) {
            throw new AgentPinError(
                ErrorCode.DOMAIN_MISMATCH,
                `AgentCard at ${domain} declares agentpin endpoint host ${endpointHost} (mismatch)`
            );
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
