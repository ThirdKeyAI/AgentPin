/**
 * Web Bot Auth (WBA) profile of RFC 9421 HTTP Message Signatures.
 *
 * Implements draft-ietf-webbotauth-httpsig-protocol: agents sign requests
 * with Ed25519 or RSASSA-PSS, name the HTTPS key directory that publishes
 * the key in the `Signature-Agent` field, and verifiers resolve that
 * directory and check the signature. This module also binds a WBA signature
 * to an AgentPin identity (spec §18): the ES256 credential confirms the WBA
 * key with `cnf.jkt`, and the issuer's discovery document vouches for the
 * `Signature-Agent` URL.
 *
 * WBA uses its own keys. The ES256 credential profile is unchanged, and
 * credential keys are never used to sign HTTP messages.
 */

import { createHash, randomBytes } from 'node:crypto';
import { AgentPinError, ErrorCode } from './types.js';
import {
    Component, PrivateKey, PublicKey, ALG_ED25519, ALG_RSA_PSS_SHA512,
    combinedField, parseDictionaryField, parseSignatures, sign, verify,
    contentDigest, contentDigestMatches, httpRequest, toBytes, withHeaders,
} from './httpsig.js';
import { parseItem, serializeItem, serializeDictionary, sfItem, sfString, isInnerList } from './sf.js';
import { base64urlEncode, base64urlDecode, decodeJwtUnverified } from './jwt.js';
import { httpExtractCredential } from './transport.js';
import { normalizeDomain } from './domain.js';
import { verifyCredentialOffline } from './verification.js';

export { PrivateKey, PublicKey, ALG_ED25519, ALG_RSA_PSS_SHA512 } from './httpsig.js';

/** `tag` value of a Web Bot Auth request signature. */
export const TAG = 'web-bot-auth';
/** `tag` value of a directory response signature. */
export const DIRECTORY_TAG = 'http-message-signatures-directory';
/** Well-known path of a key directory. */
export const DIRECTORY_PATH = '/.well-known/http-message-signatures-directory';
/** Media type a well-known key directory is served with. */
export const DIRECTORY_MEDIA_TYPE = 'application/http-message-signatures-directory+json';
/** Most keys accepted from one directory. */
export const MAX_DIRECTORY_KEYS = 64;
/** Longest accepted `expires - created` window (24 hours). */
export const MAX_VALIDITY_SECS = 86400;

function wbaErr(message) {
    return new AgentPinError(ErrorCode.HTTP_SIGNATURE_INVALID, message);
}

const nowSecs = () => Math.floor(Date.now() / 1000);

// ---------------------------------------------------------------------------
// Keys and JWKs
// ---------------------------------------------------------------------------

/** Generate a new Ed25519 signing key. @returns {PrivateKey} */
export function generateSigningKey() {
    return PrivateKey.generateEd25519();
}

/** Load a signing key from PEM: Ed25519 or RSA (PKCS#8 or PKCS#1). @returns {PrivateKey} */
export function loadSigningKey(pem) {
    return PrivateKey.fromPem(pem);
}

/** Encode a signing key as a PKCS#8 PEM. */
export function signingKeyToPem(key) {
    return key.toPem();
}

/**
 * JWK SHA-256 thumbprint, base64url without padding: RFC 8037 for Ed25519,
 * RFC 7638 for RSA. This is the WBA `keyid`.
 * @param {PublicKey} key
 * @returns {string}
 */
export function thumbprint(key) {
    const canonical = key.type === 'ed25519'
        ? `{"crv":"Ed25519","kty":"OKP","x":"${base64urlEncode(key.x)}"}`
        : `{"e":"${base64urlEncode(key.e)}","kty":"RSA","n":"${base64urlEncode(key.n)}"}`;
    return base64urlEncode(createHash('sha256').update(canonical).digest());
}

/** JWK for `key`, with `kid` set to its thumbprint and `use` "sig". */
export function jwkFromPublicKey(key) {
    return key.type === 'ed25519'
        ? { kty: 'OKP', crv: 'Ed25519', kid: thumbprint(key), x: base64urlEncode(key.x), use: 'sig' }
        : { kty: 'RSA', kid: thumbprint(key), n: base64urlEncode(key.n), e: base64urlEncode(key.e), use: 'sig' };
}

/**
 * Decode a JWK's public key. Accepts Ed25519 OKP keys and RSA keys of 2048
 * to 8192 bits with minimal encodings; rejects everything else.
 * @returns {PublicKey}
 * @throws {AgentPinError} INVALID_KEY_FORMAT
 */
export function publicKeyFromJwk(jwk) {
    const bad = () => new AgentPinError(ErrorCode.INVALID_KEY_FORMAT, 'unsupported or malformed JWK');
    const b64 = (v) => {
        if (typeof v !== 'string') throw bad();
        try {
            return base64urlDecode(v);
        } catch {
            throw bad();
        }
    };
    if (!jwk || typeof jwk !== 'object') throw bad();
    if (jwk.kty === 'OKP' && jwk.crv === 'Ed25519') {
        const x = b64(jwk.x);
        if (x.length !== 32) throw bad();
        try {
            return PublicKey.ed25519(x);
        } catch {
            throw bad();
        }
    }
    if (jwk.kty === 'RSA') {
        const n = b64(jwk.n);
        const e = b64(jwk.e);
        // Minimal encodings only (RFC 7518 §6.3.1), so the thumbprint is well defined.
        const minimal = (v) => v.length > 0 && v[0] !== 0;
        const bits = n.length === 0 ? 0 : (n.length - 1) * 8 + (32 - Math.clz32(n[0]));
        if (!minimal(n) || !minimal(e) || e.length > 4 || bits < 2048 || bits > 8192) throw bad();
        return PublicKey.rsa(n, e);
    }
    throw bad();
}

/** Thumbprint computed from the JWK's key material (never from `kid`); null if unusable. */
export function jwkThumbprint(jwk) {
    try {
        return thumbprint(publicKeyFromJwk(jwk));
    } catch {
        return null;
    }
}

function usableAt(jwk, now, skew) {
    return (jwk.nbf === undefined || now + skew >= jwk.nbf)
        && (jwk.exp === undefined || now - skew < jwk.exp);
}

const JWK_STRING_FIELDS = ['kty', 'crv', 'kid', 'x', 'n', 'e', 'use', 'alg'];

/** Rebuild a JWK with only the known fields, in canonical order; null if mistyped. */
function cleanJwk(raw) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
    if (typeof raw.kty !== 'string') return null;
    const out = {};
    for (const f of JWK_STRING_FIELDS) {
        const v = raw[f];
        if (v === undefined || v === null) continue;
        if (typeof v !== 'string') return null;
        out[f] = v;
    }
    for (const f of ['nbf', 'exp']) {
        const v = raw[f];
        if (v === undefined || v === null) continue;
        if (!Number.isSafeInteger(v)) return null;
        out[f] = v;
    }
    return out;
}

/** Directory publishing the given public keys. @returns {{ keys: object[] }} */
export function directoryFromKeys(keys) {
    return { keys: keys.map(jwkFromPublicKey) };
}

/**
 * Parse a JWK Set. Entries that are not well-formed Ed25519 or RSA keys (EC,
 * short RSA, bad values) are skipped; more than `MAX_DIRECTORY_KEYS` entries
 * is an error.
 * @param {string|Buffer|Uint8Array} json
 * @returns {{ keys: object[] }}
 */
export function parseDirectory(json) {
    let raw;
    try {
        raw = JSON.parse(toBytes(json).toString('utf8'));
    } catch {
        throw wbaErr('key directory is not a JWK Set');
    }
    if (!raw || typeof raw !== 'object' || Array.isArray(raw) || !Array.isArray(raw.keys)) {
        throw wbaErr('key directory is not a JWK Set');
    }
    if (raw.keys.length > MAX_DIRECTORY_KEYS) throw wbaErr('key directory has too many keys');
    const keys = [];
    for (const entry of raw.keys) {
        const jwk = cleanJwk(entry);
        if (jwk && jwkThumbprint(jwk) !== null) keys.push(jwk);
    }
    return { keys };
}

/** Compact JSON body, as served. */
export function directoryToJson(directory) {
    return JSON.stringify({ keys: directory.keys.map((k) => cleanJwk(k) || k) });
}

/**
 * Find `keyid` in `directory` by computed thumbprint, honoring `nbf`/`exp`.
 * @returns {PublicKey|null}
 */
export function findKey(directory, keyid, now, skew) {
    for (const jwk of directory.keys) {
        if (!usableAt(jwk, now, skew)) continue;
        let key;
        try {
            key = publicKeyFromJwk(jwk);
        } catch {
            continue;
        }
        if (thumbprint(key) === keyid) return key;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Signature-Agent
// ---------------------------------------------------------------------------

/** The well-known directory URL for `domain`. */
export function wellKnownDirectory(domain) {
    return `https://${domain}${DIRECTORY_PATH}`;
}

/**
 * Normalize a Signature-Agent URL into the identifier form the draft
 * compares (§5.5): absolute `https` URL with a host, query and fragment
 * dropped, scheme/host case and default port normalized.
 * @param {string} url
 * @returns {string}
 */
export function normalizeSignatureAgent(url) {
    let u;
    try {
        u = new URL(String(url));
    } catch {
        throw wbaErr('Signature-Agent is not an absolute URL');
    }
    if (u.protocol !== 'https:' || !u.hostname) throw wbaErr('Signature-Agent must be an https URL with a host');
    if (u.username !== '' || u.password !== '') throw wbaErr('Signature-Agent must not carry credentials');
    u.search = '';
    u.hash = '';
    return u.href;
}

/**
 * Resolve the Signature-Agent member keyed `label`. `legacy` is set when the
 * signature covers the bare `"signature-agent"` component, which is only
 * valid for the old sf-string form of the field. Throws a reason string.
 */
function signatureAgentMember(headers, label, legacy) {
    const raw = combinedField(headers, 'signature-agent');
    if (raw === null) throw 'request has no Signature-Agent field';
    let item;
    if (legacy) {
        if (!raw.startsWith('"')) throw 'Signature-Agent is a Dictionary; cover it with ;key';
        try {
            item = parseItem(raw);
        } catch {
            throw 'Signature-Agent is not a valid String';
        }
    } else {
        let dict;
        try {
            dict = parseDictionaryField(headers, 'signature-agent');
        } catch (e) {
            throw e.message;
        }
        const entry = dict.get(label);
        if (entry === undefined) throw `Signature-Agent has no member '${label}'`;
        if (isInnerList(entry)) throw 'Signature-Agent member is not an Item';
        item = entry;
    }
    if (item.params.size > 0) throw 'Signature-Agent member carries parameters';
    if (item.value.type !== 'string') throw 'Signature-Agent member is not a String';
    try {
        return normalizeSignatureAgent(item.value.value);
    } catch (e) {
        throw e.message;
    }
}

// ---------------------------------------------------------------------------
// Signing requests
// ---------------------------------------------------------------------------

/** Components covered by default besides `@authority` and the Signature-Agent member. */
export const DEFAULT_SIGN_COMPONENTS = Object.freeze(['@method', '@path']);

/**
 * Sign `req` as a Web Bot Auth agent whose key directory is `signatureAgent`
 * (an https URL). Returns the fields to append; `req` is not modified. Any
 * header named in `opts.components` must already be on `req`.
 *
 * @param {{ method: string, url: string, headers: Array }} req
 * @param {PrivateKey} signingKey
 * @param {string} signatureAgent
 * @param {object} [opts]
 * @param {string} [opts.label='sig1'] - Signature label; also the Signature-Agent member key
 * @param {number} [opts.validitySecs=300] - `expires - created` (1 to 86400)
 * @param {Array<Component|string>} [opts.components] - Covered in addition to
 *   `@authority` and the Signature-Agent member (default `@method`, `@path`).
 *   Add `authorization` to bind an AgentPin credential.
 * @param {boolean} [opts.nonce=true] - Add a random 64-byte `nonce`
 * @param {number|null} [opts.created] - `created` timestamp; default now
 * @param {boolean} [opts.legacySignatureAgent=false] - Send the legacy
 *   bare-String Signature-Agent and cover the bare `"signature-agent"`
 *   component (draft Appendix E.1.2)
 * @returns {{ signatureAgent: string, signatureInput: string, signature: string,
 *   headers: Array<[string, string]>, apply: Function }}
 */
export function signRequest(req, signingKey, signatureAgent, opts = {}) {
    const label = opts.label ?? 'sig1';
    const validitySecs = opts.validitySecs ?? 300;
    const extra = (opts.components ?? DEFAULT_SIGN_COMPONENTS).map(Component.from);
    const useNonce = opts.nonce ?? true;

    let agentUrl;
    try {
        agentUrl = new URL(String(signatureAgent));
    } catch {
        agentUrl = null;
    }
    if (!agentUrl || agentUrl.protocol !== 'https:' || !agentUrl.hostname) {
        throw wbaErr('signatureAgent must be an https URL with a host');
    }
    if (!Number.isInteger(validitySecs) || validitySecs < 1 || validitySecs > MAX_VALIDITY_SECS) {
        throw wbaErr('validitySecs must be between 1 and 86400');
    }

    let field;
    let agentComponent;
    if (opts.legacySignatureAgent) {
        if (combinedField(req.headers, 'signature-agent') !== null) {
            throw wbaErr('legacy Signature-Agent cannot be combined with an existing one');
        }
        field = serializeItem(sfItem(sfString(agentUrl.href)));
        agentComponent = new Component('signature-agent');
    } else {
        const existing = parseDictionaryField(req.headers, 'signature-agent');
        if (existing.has(label)) throw wbaErr(`Signature-Agent already has a member '${label}'`);
        field = serializeDictionary([[label, sfItem(sfString(agentUrl.href))]]);
        agentComponent = Component.keyed('signature-agent', label);
    }
    const toSign = withHeaders(req, [['Signature-Agent', field]]);

    const components = [new Component('@authority'), agentComponent];
    for (const c of extra) {
        if (!components.some((x) => x.equals(c))) components.push(c);
    }

    const created = opts.created ?? nowSecs();
    const params = [
        ['created', created],
        ['keyid', thumbprint(signingKey.publicKey())],
        ['alg', signingKey.alg],
        ['expires', created + validitySecs],
    ];
    if (useNonce) {
        // 64 bytes, as in the draft's vectors; some verifiers reject other lengths.
        params.push(['nonce', randomBytes(64).toString('base64')]);
    }
    params.push(['tag', TAG]);

    const f = sign(toSign, label, components, params, signingKey);
    const headers = [
        ['Signature-Agent', field],
        ['Signature-Input', f.signatureInput],
        ['Signature', f.signature],
    ];
    return {
        signatureAgent: field,
        signatureInput: f.signatureInput,
        signature: f.signature,
        headers,
        /** Copy of `r` with the three fields appended. */
        apply: (r) => withHeaders(r, headers),
    };
}

// ---------------------------------------------------------------------------
// Verifying requests
// ---------------------------------------------------------------------------

/** The three verifier outcomes the draft distinguishes (Appendix C.1). */
export const WbaOutcome = Object.freeze({
    /** The signature and key material validate. */
    VERIFIED: 'verified',
    /** The signature, covered components, key or freshness checks fail. */
    INVALID: 'invalid',
    /** Not enough information: no WBA signature, discovery failed, or the directory lacks the key. */
    UNVERIFIED: 'unverified',
});

const invalid = (reason) => ({ outcome: WbaOutcome.INVALID, reason });
const unverified = (reason) => ({ outcome: WbaOutcome.UNVERIFIED, reason });

/** A request signature that verified against a key its Signature-Agent directory provides. */
export class VerifiedAgent {
    constructor({ label, signatureAgent, keyid, created, expires, nonce, components }) {
        this.label = label;
        /** Normalized Signature-Agent URL: the agent's identifier. */
        this.signatureAgent = signatureAgent;
        /** JWK thumbprint of the signing key. */
        this.keyid = keyid;
        this.created = created;
        this.expires = expires;
        this.nonce = nonce;
        /** @type {Component[]} */
        this.components = components;
    }

    /** `true` if the signature covers `component` (a Component or a name). */
    covers(component) {
        return this.components.some((c) => c.equals(component));
    }
}

/**
 * In-memory key store built from directories the verifier resolved itself.
 * Lookup is keyed on the `(Signature-Agent URL, keyid)` pair, never on the
 * keyid alone (§5.4).
 */
export class DirectoryKeyStore {
    constructor() {
        this._directories = new Map();
        this.clockSkewSecs = 60;
    }

    /** Record (or replace) the directory resolved from `signatureAgent`. */
    insert(signatureAgent, directory) {
        this._directories.set(normalizeSignatureAgent(signatureAgent), directory);
    }

    /**
     * @returns {PublicKey|null} the key, or null when the directory resolved without it
     * @throws when the directory is not resolved
     */
    lookup(signatureAgent, keyid) {
        const dir = this._directories.get(signatureAgent);
        if (!dir) throw wbaErr('directory not resolved');
        return findKey(dir, keyid, nowSecs(), this.clockSkewSecs);
    }
}

function verifyDefaults(opts) {
    return {
        now: opts.now ?? null,
        clockSkewSecs: opts.clockSkewSecs ?? 60,
        maxValiditySecs: opts.maxValiditySecs ?? MAX_VALIDITY_SECS,
        acceptLegacySignatureAgent: opts.acceptLegacySignatureAgent ?? true,
        requiredComponents: (opts.requiredComponents ?? []).map(Component.from),
        nonceStore: opts.nonceStore ?? null,
    };
}

/** Protocol checks on one signature (§5.2, §5.2.1). Throws the reason it is invalid. */
function checkSignature(req, sig, opts, now) {
    const p = sig.params;
    if (p.created === null) throw 'signature has no created parameter';
    if (p.expires === null) throw 'signature has no expires parameter';
    if (p.keyid === null) throw 'signature has no keyid parameter';
    if (p.alg !== null && p.alg !== ALG_ED25519 && p.alg !== ALG_RSA_PSS_SHA512) {
        throw `unsupported alg '${p.alg}'`;
    }
    if (p.created > now + opts.clockSkewSecs) throw 'signature created in the future';
    if (p.expires <= p.created) throw 'expires is not after created';
    if (now - opts.clockSkewSecs > p.expires) throw 'signature expired';
    if (p.expires - p.created > opts.maxValiditySecs) throw 'signature validity window too long';
    if (!sig.covers('@authority') && !sig.covers('@target-uri')) {
        throw 'signature covers neither @authority nor @target-uri';
    }
    for (const c of opts.requiredComponents) {
        if (!sig.covers(c)) throw `signature does not cover required '${c.name}'`;
    }
    // The covered member, not the signature label, names the agent: labels
    // may be rewritten by intermediaries, member keys may not (§6.6.1).
    const members = sig.components
        .filter((c) => c.name === 'signature-agent' && !c.req && c.key !== null)
        .map((c) => c.key);
    let signatureAgent;
    if (members.length === 1) {
        signatureAgent = signatureAgentMember(req.headers, members[0], false);
    } else if (members.length === 0 && opts.acceptLegacySignatureAgent && sig.covers('signature-agent')) {
        signatureAgent = signatureAgentMember(req.headers, sig.label, true);
    } else if (members.length === 0) {
        throw 'signature does not cover a Signature-Agent member';
    } else {
        throw 'signature covers more than one Signature-Agent member';
    }
    return { sig, signatureAgent, keyid: p.keyid };
}

function reasonOf(e) {
    return typeof e === 'string' ? e : (e && e.message) || String(e);
}

async function checkNonce(c, opts, now) {
    if (!opts.nonceStore) return null;
    const nonce = c.sig.params.nonce;
    if (nonce === null) return 'signature has no nonce and replay protection is on';
    // Keep the nonce until the signature can no longer pass the expiry check.
    const ttlSecs = Math.max(c.sig.params.expires + opts.clockSkewSecs - now, 1);
    let fresh;
    try {
        fresh = await opts.nonceStore.checkAndRecord(`${c.keyid} ${nonce}`, ttlSecs * 1000);
    } catch (e) {
        return `nonce store failed: ${reasonOf(e)}`;
    }
    return fresh ? null : 'nonce replayed';
}

/**
 * Verify the Web Bot Auth signatures on `req`. Returns the first signature
 * that verifies; otherwise `invalid` if any signature failed a check, else
 * `unverified`.
 *
 * `keys.lookup(signatureAgent, keyid)` (sync or async) returns the
 * `PublicKey` the directory at the normalized `signatureAgent` URL provides
 * for `keyid`, `null` when the directory resolved without it, and throws
 * when the directory could not be resolved.
 *
 * @param {{ method: string, url: string, headers: Array }} req
 * @param {{ lookup: Function }} keys - e.g. `DirectoryKeyStore` or `CachingDirectoryResolver`
 * @param {object} [opts]
 * @param {number} [opts.now] - Verification time (Unix seconds); default now
 * @param {number} [opts.clockSkewSecs=60]
 * @param {number} [opts.maxValiditySecs=86400] - Longest accepted `expires - created`
 * @param {boolean} [opts.acceptLegacySignatureAgent=true]
 * @param {Array<Component|string>} [opts.requiredComponents] - Components every accepted signature must cover
 * @param {{ checkAndRecord: Function }} [opts.nonceStore] - Replay protection: a
 *   verified signature's nonce is recorded per keyid until it expires and a
 *   repeat is invalid; signatures without a nonce are invalid. Checked only
 *   after the signature verifies, so forged requests cannot fill it.
 * @returns {Promise<{ outcome: string, agent?: VerifiedAgent, reason?: string }>}
 */
export async function verifyRequest(req, keys, opts = {}) {
    const o = verifyDefaults(opts);
    const now = o.now ?? nowSecs();
    let sigs;
    try {
        sigs = parseSignatures(req.headers);
    } catch (e) {
        return invalid(reasonOf(e));
    }
    const candidates = [];
    let result = null;
    let seen = false;
    for (const sig of sigs) {
        if (sig.params.tag !== TAG) continue;
        seen = true;
        try {
            candidates.push(checkSignature(req, sig, o, now));
        } catch (e) {
            result = invalid(reasonOf(e));
        }
    }
    if (!seen) return unverified('request carries no Web Bot Auth signature');

    for (const c of candidates) {
        let key;
        let failure;
        try {
            key = await keys.lookup(c.signatureAgent, c.keyid);
        } catch (e) {
            key = undefined;
            failure = unverified(`key directory ${c.signatureAgent} unavailable: ${reasonOf(e)}`);
        }
        if (!failure && !key) {
            failure = unverified(`key directory ${c.signatureAgent} does not provide keyid ${c.keyid}`);
        }
        if (!failure) {
            try {
                verify(req, c.sig, key);
            } catch {
                failure = invalid('signature verification failed');
            }
        }
        if (!failure) {
            const reason = await checkNonce(c, o, now);
            if (reason) {
                failure = invalid(reason);
            } else {
                return {
                    outcome: WbaOutcome.VERIFIED,
                    agent: new VerifiedAgent({
                        label: c.sig.label,
                        signatureAgent: c.signatureAgent,
                        keyid: c.keyid,
                        created: c.sig.params.created,
                        expires: c.sig.params.expires,
                        nonce: c.sig.params.nonce,
                        components: c.sig.components,
                    }),
                };
            }
        }
        // Keep the more decisive failure: invalid beats unverified.
        if (!(result && result.outcome === WbaOutcome.INVALID)) result = failure;
    }
    return result ?? unverified('no usable signature');
}

// ---------------------------------------------------------------------------
// Directory responses
// ---------------------------------------------------------------------------

function directoryRequest(authority) {
    return httpRequest('GET', `https://${authority}${DIRECTORY_PATH}`);
}

/**
 * Response fields for a signed key directory (Appendix B.1):
 * `Content-Digest` plus one `Signature-Input`/`Signature` per key (labels
 * `binding0`, `binding1`, ...), each covering `"@authority";req` and
 * `content-digest`. `authority` is the host (and non-default port) the
 * directory was requested on.
 * @param {string|Buffer} body
 * @param {string} authority
 * @param {PrivateKey[]} keys
 * @param {number} created
 * @param {number} validitySecs
 * @returns {Array<[string, string]>}
 */
export function signDirectoryResponse(body, authority, keys, created, validitySecs) {
    if (!Number.isInteger(validitySecs) || validitySecs < 1 || validitySecs > MAX_VALIDITY_SECS) {
        throw wbaErr('validitySecs must be between 1 and 86400');
    }
    const request = directoryRequest(authority);
    const digest = contentDigest(body);
    const msg = { status: 200, headers: [['Content-Digest', digest]], request };
    const components = [Component.ofRequest('@authority'), new Component('content-digest')];
    const out = [['Content-Digest', digest]];
    keys.forEach((key, i) => {
        const params = [
            ['created', created],
            ['expires', created + validitySecs],
            ['keyid', thumbprint(key.publicKey())],
            ['tag', DIRECTORY_TAG],
        ];
        const f = sign(msg, `binding${i}`, components, params, key);
        out.push(['Signature-Input', f.signatureInput]);
        out.push(['Signature', f.signature]);
    });
    return out;
}

/**
 * Check a directory response's possession proofs (Appendix B.1) and return
 * only the keys that carry a valid one. The `Content-Digest` must match
 * `body`; a proof must use the key it names, cover `"@authority";req` and
 * `content-digest`, and be neither future-dated nor expired.
 * @returns {{ keys: object[] }}
 */
export function verifyDirectoryResponse(body, responseHeaders, authority, now, clockSkewSecs) {
    const directory = parseDirectory(body);
    if (!contentDigestMatches(responseHeaders, body)) {
        throw wbaErr('directory Content-Digest does not match the body');
    }
    const request = directoryRequest(authority);
    const msg = { status: 200, headers: responseHeaders, request };
    const sigs = parseSignatures(responseHeaders);
    const authorityReq = Component.ofRequest('@authority');
    const proven = directory.keys.filter((jwk) => {
        let pk;
        try {
            pk = publicKeyFromJwk(jwk);
        } catch {
            return false;
        }
        const tp = thumbprint(pk);
        return sigs.some((s) => {
            const p = s.params;
            if (p.tag !== DIRECTORY_TAG || p.keyid !== tp) return false;
            if (p.created === null || p.created > now + clockSkewSecs) return false;
            if (p.expires === null || now - clockSkewSecs > p.expires) return false;
            if (!s.covers(authorityReq) || !s.covers('content-digest')) return false;
            try {
                verify(msg, s, pk);
                return true;
            } catch {
                return false;
            }
        });
    });
    return { keys: proven };
}

// ---------------------------------------------------------------------------
// AgentPin identity binding (spec §18)
// ---------------------------------------------------------------------------

/**
 * The AgentPin credential JWT carried in the request's
 * `Authorization: AgentPin <jwt>` field.
 * @returns {string}
 */
export function requestCredential(req) {
    const auth = combinedField(req.headers, 'authorization');
    if (auth === null) throw wbaErr('request has no Authorization field');
    return httpExtractCredential(auth);
}

/**
 * Check that a verified WBA signature and a verified AgentPin credential
 * describe the same agent:
 *
 * 1. the credential verified, and the signature covers `authorization`, so
 *    the credential is bound to this signed request;
 * 2. the credential's `cnf.jkt` equals the signature's `keyid`;
 * 3. `discovery` is the issuer's document, and it vouches for the
 *    Signature-Agent URL: listed in `web_bot_auth.signature_agents`, or,
 *    when that field is absent, the issuer's well-known directory.
 *
 * @param {VerifiedAgent} agent
 * @param {object} req
 * @param {object} credential - VerificationResult of the request's credential
 * @param {object} discovery - The issuer's discovery document
 * @throws {AgentPinError} HTTP_SIGNATURE_INVALID with the reason
 */
export function checkBinding(agent, req, credential, discovery) {
    const fail = (reason) => wbaErr(reason);
    if (!credential || !credential.valid) throw fail('AgentPin credential did not verify');
    if (!agent.covers('authorization')) {
        throw fail('Web Bot Auth signature does not cover the Authorization field');
    }
    let payload;
    try {
        ({ payload } = decodeJwtUnverified(requestCredential(req)));
    } catch (e) {
        throw fail(reasonOf(e));
    }
    const jkt = payload.cnf && payload.cnf.jkt;
    if (typeof jkt !== 'string') throw fail('credential has no cnf.jkt key confirmation');
    if (jkt !== agent.keyid) throw fail('credential cnf.jkt does not match the signature keyid');
    let issuer;
    let entity;
    try {
        issuer = normalizeDomain(payload.iss);
    } catch (e) {
        throw fail(reasonOf(e));
    }
    let resultIssuer = null;
    try {
        resultIssuer = credential.issuer ? normalizeDomain(credential.issuer) : null;
    } catch {
        resultIssuer = null;
    }
    if (resultIssuer !== issuer || credential.agent_id !== payload.sub) {
        throw fail('credential result does not belong to this request');
    }
    try {
        entity = normalizeDomain(discovery.entity);
    } catch (e) {
        throw fail(reasonOf(e));
    }
    if (issuer !== entity) throw fail('discovery document is not the credential issuer\'s');
    const normalized = (u) => {
        try {
            return normalizeSignatureAgent(u);
        } catch {
            return null;
        }
    };
    const wba = discovery.web_bot_auth;
    const allowed = wba !== undefined && wba !== null
        ? (Array.isArray(wba.signature_agents) ? wba.signature_agents : [])
            .some((u) => normalized(u) === agent.signatureAgent)
        : normalized(wellKnownDirectory(entity)) === agent.signatureAgent;
    if (!allowed) throw fail(`${entity} does not vouch for Signature-Agent ${agent.signatureAgent}`);
}

/** Why `verifyBoundRequest` rejected a request. */
export const BindingFailure = Object.freeze({
    /** The WBA signature did not verify (`outcome` holds the WBA result). */
    WBA: 'wba',
    /** The AgentPin credential did not verify (`credential` holds the result). */
    CREDENTIAL: 'credential',
    /** Both verified but they are not bound to each other. */
    BINDING: 'binding',
});

function credentialFailure(code, message) {
    return {
        valid: false, agent_id: null, issuer: null, capabilities: null, constraints: null,
        delegation_verified: null, delegation_chain: null, key_pinning: null,
        error_code: code, error_message: message, warnings: [],
    };
}

/**
 * Verify a request's WBA signature, its AgentPin credential, and the binding
 * between them (`checkBinding`).
 *
 * `resolver.resolveDiscovery(domain)` (sync or async) returns the issuer's
 * discovery document; an optional `resolver.resolveRevocation(domain,
 * discovery)` returns its revocation document (a failure there is
 * fail-closed). Delegation chains are verified only with a synchronous
 * `resolveDiscovery`.
 *
 * @param {object} req
 * @param {{ lookup: Function }} keys
 * @param {{ resolveDiscovery: Function, resolveRevocation?: Function }} resolver
 * @param {import('./pinning.js').KeyPinStore} pinStore
 * @param {string|null} audience
 * @param {object} [wbaOpts] - Options for `verifyRequest`
 * @param {object} [config] - Verifier config for the credential
 * @returns {Promise<{ ok: true, agent: VerifiedAgent, credential: object } |
 *   { ok: false, failure: string, reason: string, outcome?: object, credential?: object }>}
 */
export async function verifyBoundRequest(req, keys, resolver, pinStore, audience, wbaOpts = {}, config = {}) {
    const wbaResult = await verifyRequest(req, keys, wbaOpts);
    if (wbaResult.outcome !== WbaOutcome.VERIFIED) {
        return { ok: false, failure: BindingFailure.WBA, outcome: wbaResult, reason: wbaResult.reason };
    }
    const agent = wbaResult.agent;
    const binding = (reason) => ({ ok: false, failure: BindingFailure.BINDING, reason });
    const credFail = (credential) => ({
        ok: false, failure: BindingFailure.CREDENTIAL, credential, reason: credential.error_message,
    });

    let jwt;
    try {
        jwt = requestCredential(req);
    } catch (e) {
        return binding(reasonOf(e));
    }
    let payload;
    try {
        ({ payload } = decodeJwtUnverified(jwt));
    } catch {
        // Let the credential verifier produce the precise failure.
        return credFail(verifyCredentialOffline(jwt, null, null, pinStore, audience, config));
    }
    let issuer;
    try {
        issuer = normalizeDomain(payload.iss);
    } catch (e) {
        return credFail(credentialFailure(ErrorCode.DISCOVERY_INVALID, `Invalid issuer domain: ${reasonOf(e)}`));
    }
    let discovery;
    try {
        discovery = await resolver.resolveDiscovery(issuer);
    } catch (e) {
        return credFail(credentialFailure(ErrorCode.DISCOVERY_FETCH_FAILED,
            `Failed to resolve discovery document: ${reasonOf(e)}`));
    }
    let revocation = null;
    if (typeof resolver.resolveRevocation === 'function') {
        try {
            revocation = (await resolver.resolveRevocation(issuer, discovery)) ?? null;
        } catch {
            return credFail(credentialFailure(ErrorCode.DISCOVERY_FETCH_FAILED,
                'Revocation document unreachable (fail-closed)'));
        }
    }
    const chainResolver = {
        resolveDiscovery(domain) {
            const doc = resolver.resolveDiscovery(domain);
            if (doc && typeof doc.then === 'function') {
                throw new AgentPinError(ErrorCode.DISCOVERY_FETCH_FAILED,
                    'asynchronous resolver cannot verify delegation chains');
            }
            return doc;
        },
    };
    const credential = verifyCredentialOffline(jwt, discovery, revocation, pinStore, audience, config, chainResolver);
    if (!credential.valid) return credFail(credential);
    try {
        checkBinding(agent, req, credential, discovery);
    } catch (e) {
        return binding(reasonOf(e));
    }
    return { ok: true, agent, credential };
}
