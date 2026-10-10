/**
 * A2A AgentCard signing and verification (v0.3.0).
 *
 * Mirrors the Rust `agentpin::a2a` module. AgentPin extends the
 * Google A2A AgentCard format with cryptographic identity verification.
 * The `agentpin` extension carries the AgentPin endpoint URL, the entity's
 * public key in JWK form, and a detached ECDSA P-256 signature over the
 * canonical bytes of the rest of the AgentCard.
 *
 * Canonicalization: the signing input is the AgentCard with its `agentpin`
 * field replaced by `{ agentpin_endpoint, public_key_jwk }` (signature
 * cleared), serialized as sorted-key compact JSON and wrapped in the
 * `agentpin-agentcard-v1` signing context. The endpoint and key are
 * therefore covered by the signature (AP-4) and card signatures are disjoint
 * from every other AgentPin signature (AP-1).
 */

import { createPublicKey } from 'crypto';
import { signData, verifySignature, domainSeparatedInput, CTX_AGENTCARD } from './crypto.js';
import { pemToJwk, jwkToPem, jwkThumbprint } from './jwk.js';
import { AllowedDomains } from './discovery.js';
import { AgentPinError, ErrorCode } from './types.js';

/**
 * Map an AgentPin capability string (or `{ id }` Capability object) to a
 * minimal A2A AgentSkill.
 * @param {string|{id:string}} cap
 * @returns {{ id: string, name: string, description?: string }}
 */
export function capabilityToSkill(cap) {
    const id = typeof cap === 'string' ? cap : (cap && cap.id) || String(cap);
    return { id, name: id };
}

/**
 * Build an unsigned A2A AgentCard from an AgentPin `AgentDeclaration`.
 *
 * The capability list is mapped 1:1 to skills via `capabilityToSkill`; the
 * `allowed_domains` constraint is copied into `capabilities.allowed_domains`
 * (omitted entirely when unrestricted, matching the Rust serde behaviour).
 *
 * @param {string} url - Public URL where the agent receives A2A traffic.
 * @param {object} declaration - AgentPin AgentDeclaration.
 * @param {object} [opts]
 * @param {Array} [opts.skills] - Override the auto-mapped skill list.
 * @param {boolean} [opts.streaming]
 * @param {boolean} [opts.pushNotifications]
 * @returns {object} Unsigned A2A AgentCard (no `agentpin` extension).
 */
export function buildUnsignedAgentCard(url, declaration, opts = {}) {
    const skills = (opts.skills && opts.skills.length > 0)
        ? opts.skills.map((s) => ({ ...s }))
        : (declaration.capabilities || []).map(capabilityToSkill);

    const allowedDomains = declaration.constraints
        ? AllowedDomains.fromConstraints(declaration.constraints)
        : AllowedDomains.unrestricted();

    const capabilities = {
        streaming: !!opts.streaming,
        pushNotifications: !!opts.pushNotifications,
    };
    if (!AllowedDomains.isUnrestricted(allowedDomains)) {
        capabilities.allowed_domains = allowedDomains;
    }

    const card = {
        name: declaration.name,
        url,
        capabilities,
        skills,
    };
    if (declaration.description !== undefined && declaration.description !== null) {
        card.description = declaration.description;
    }
    if (declaration.version !== undefined && declaration.version !== null) {
        card.version = declaration.version;
    }
    return card;
}

/**
 * Sign an A2A AgentCard with an ECDSA P-256 private key.
 *
 * @param {object} unsignedCard - Card produced by `buildUnsignedAgentCard`.
 * @param {string} privateKeyPem
 * @param {string} kid
 * @param {string} agentpinEndpoint - URL of the entity's AgentPin discovery
 *   document (`.well-known/agent-identity.json`).
 * @returns {object} Signed A2A AgentCard with `agentpin` extension populated.
 */
export function signAgentCard(unsignedCard, privateKeyPem, kid, agentpinEndpoint) {
    if (!agentpinEndpoint) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            'signAgentCard requires agentpinEndpoint'
        );
    }
    const publicKeyPem = createPublicKey(privateKeyPem)
        .export({ type: 'spki', format: 'pem' });
    const publicKeyJwk = pemToJwk(publicKeyPem, kid);

    const input = agentCardSigningInputFor(unsignedCard, agentpinEndpoint, publicKeyJwk);
    const signature = signData(privateKeyPem, input);

    return {
        ...unsignedCard,
        agentpin: {
            agentpin_endpoint: agentpinEndpoint,
            public_key_jwk: publicKeyJwk,
            signature,
        },
    };
}

/**
 * One-shot helper: build + sign in a single call.
 *
 * @param {string} url
 * @param {object} declaration
 * @param {string} privateKeyPem
 * @param {string} kid
 * @param {string} agentpinEndpoint
 * @param {object} [opts] - Forwarded to `buildUnsignedAgentCard`.
 * @returns {object} Signed A2A AgentCard.
 */
export function buildAndSignAgentCard(url, declaration, privateKeyPem, kid, agentpinEndpoint, opts = {}) {
    const unsigned = buildUnsignedAgentCard(url, declaration, opts);
    return signAgentCard(unsigned, privateKeyPem, kid, agentpinEndpoint);
}

/**
 * Verify the `agentpin` extension on an A2A AgentCard.
 *
 * Returns nothing on success; throws `AgentPinError(DISCOVERY_INVALID)` on
 * any failure (extension missing, malformed JWK, signature mismatch).
 *
 * This proves only that the card has not been tampered with relative to the
 * key inside its own extension. The caller still has to verify the JWK
 * chains back to a trusted AgentPin discovery document — pair this with
 * `A2aAgentCardResolver` for the full chain.
 *
 * @param {object} card - A2A AgentCard.
 */
export function verifyAgentpinExtension(card) {
    const ext = card && card.agentpin;
    if (!ext) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            'AgentCard has no agentpin extension'
        );
    }
    const input = agentCardSigningInput(card);
    const publicKeyPem = jwkToPem(ext.public_key_jwk);
    const ok = verifySignature(publicKeyPem, input, ext.signature);
    if (!ok) {
        throw new AgentPinError(
            ErrorCode.DISCOVERY_INVALID,
            'A2A AgentCard signature did not verify against extension JWK'
        );
    }
}

/**
 * Compute the JWK thumbprint of the public key carried in a card's
 * `agentpin` extension. Convenience wrapper used by resolvers when matching
 * the card's key against a discovery document.
 *
 * @param {object} extension - Card's `agentpin` extension.
 * @returns {string} Hex thumbprint (no `sha256:` prefix).
 */
export function extensionKeyThumbprint(extension) {
    return jwkThumbprint(extension.public_key_jwk);
}

// ---------------------------------------------------------------------------
// Canonicalization
// ---------------------------------------------------------------------------

/**
 * The domain-separated bytes that `card.agentpin.signature` must verify
 * against, using the endpoint and JWK from the card's own extension.
 * @param {object} card
 * @returns {Buffer}
 */
export function agentCardSigningInput(card) {
    const ext = card && card.agentpin;
    if (!ext) {
        throw new AgentPinError(ErrorCode.DISCOVERY_INVALID, 'AgentCard has no agentpin extension');
    }
    return agentCardSigningInputFor(card, ext.agentpin_endpoint, ext.public_key_jwk);
}

function agentCardSigningInputFor(card, agentpinEndpoint, publicKeyJwk) {
    const forSigning = {
        ...card,
        agentpin: { agentpin_endpoint: agentpinEndpoint, public_key_jwk: publicKeyJwk },
    };
    const canonical = canonicalizeForSigning(forSigning);
    return domainSeparatedInput(CTX_AGENTCARD, [Buffer.from(canonical, 'utf8')]);
}

/**
 * Canonicalise a JSON-able value with object keys sorted alphabetically and
 * `undefined` properties dropped — matches `serde_json::to_value` + sorted
 * `BTreeMap` re-serialisation in the Rust SDK so signatures verify across
 * languages.
 *
 * @param {*} value
 * @returns {string} Canonical JSON string.
 */
export function canonicalizeForSigning(value) {
    return JSON.stringify(sortedCanonical(value));
}

function sortedCanonical(value) {
    if (value === null || value === undefined) return null;
    if (Array.isArray(value)) return value.map(sortedCanonical);
    if (typeof value === 'object') {
        const out = {};
        for (const key of Object.keys(value).sort()) {
            const v = value[key];
            if (v === undefined) continue;
            out[key] = sortedCanonical(v);
        }
        return out;
    }
    return value;
}
