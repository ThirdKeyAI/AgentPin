/**
 * RFC 9421 HTTP Message Signatures.
 *
 * Builds signature bases, reads and writes the `Signature-Input` and
 * `Signature` fields, and signs and verifies with Ed25519 (`alg="ed25519"`)
 * and RSASSA-PSS SHA-512 (`alg="rsa-pss-sha512"`). This is the layer Web Bot
 * Auth (`wba.js`) is built on.
 *
 * Supported component identifiers: `@method`, `@target-uri`, `@authority`,
 * `@scheme`, `@request-target`, `@path`, `@query`, `@query-param` (with
 * `name`), `@status`, and HTTP fields, with the `key` (Dictionary member)
 * and `req` (related request) parameters. Identifiers carrying any other
 * parameter (`sf`, `bs`, `tr`) are rejected rather than silently
 * mis-serialized.
 *
 * Messages are plain objects:
 * - request: `{ method, url, headers }`;
 * - response: `{ status, headers, request? }`, where `request` is the
 *   related request used by components with the `req` parameter.
 * `headers` is an array of `[name, value]` pairs (names matched
 * case-insensitively), a plain object, or anything with `entries()`.
 */

import {
    createHash, createPrivateKey, createPublicKey, generateKeyPairSync,
    sign as cryptoSign, verify as cryptoVerify, constants as cryptoConstants,
} from 'node:crypto';
import { AgentPinError, ErrorCode } from './types.js';
import {
    parseDictionary, sfString, sfInteger, sfBoolean, sfItem, sfInnerList, isInnerList,
    serializeItem, serializeInnerList, serializeListEntry, serializeDictionary, isSfString,
} from './sf.js';
import { base64urlEncode, base64urlDecode } from './jwt.js';

export {
    parseDictionary, parseItem, parseList, serializeDictionary, serializeItem, serializeList,
} from './sf.js';

/** `alg` value for Ed25519. */
export const ALG_ED25519 = 'ed25519';
/** `alg` value for RSASSA-PSS with SHA-512. */
export const ALG_RSA_PSS_SHA512 = 'rsa-pss-sha512';

function err(message) {
    return new AgentPinError(ErrorCode.HTTP_SIGNATURE_INVALID, message);
}

function signatureInvalid() {
    return new AgentPinError(ErrorCode.SIGNATURE_INVALID, 'HTTP message signature verification failed');
}

function keyFormat(message = 'unsupported or malformed key') {
    return new AgentPinError(ErrorCode.INVALID_KEY_FORMAT, message);
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/**
 * Normalize a header collection to an array of `[name, value]` strings.
 * @param {Array|object|Headers|undefined} headers
 * @returns {Array<[string, string]>}
 */
export function headerList(headers) {
    if (!headers) return [];
    let entries;
    if (Array.isArray(headers)) entries = headers;
    else if (typeof headers.entries === 'function' && !(headers.constructor === Object)) entries = [...headers.entries()];
    else entries = Object.entries(headers);
    return entries.map(([n, v]) => [String(n), String(v)]);
}

/**
 * Build a request message from a method and an absolute URL.
 * @param {string} method
 * @param {string|URL} url
 * @param {Array|object} [headers]
 * @returns {{ method: string, url: string, headers: Array<[string, string]> }}
 */
export function httpRequest(method, url, headers) {
    const u = parseUrl(url);
    return { method: String(method), url: u.href, headers: headerList(headers) };
}

/** Copy of `req` with extra header fields appended. */
export function withHeaders(req, extra) {
    return { ...req, headers: [...headerList(req.headers), ...headerList(extra)] };
}

function parseUrl(url) {
    let u;
    try {
        u = new URL(String(url));
    } catch {
        throw err('request URL is not an absolute URL');
    }
    if (!u.hostname) throw err('request URL has no host');
    return u;
}

function isResponse(msg) {
    return msg && typeof msg === 'object' && msg.status !== undefined && msg.method === undefined;
}

/**
 * Combined value of every `name` field: each value trimmed, joined with
 * `", "` (RFC 9421 §2.1). `null` when the field is absent.
 * @param {Array|object} headers
 * @param {string} name
 * @returns {string|null}
 */
export function combinedField(headers, name) {
    const lower = name.toLowerCase();
    const values = headerList(headers)
        .filter(([n]) => n.toLowerCase() === lower)
        .map(([, v]) => v.trim());
    return values.length === 0 ? null : values.join(', ');
}

/**
 * Parse the combined `name` field as a Structured Field Dictionary; an
 * absent field is an empty Dictionary.
 * @returns {Map}
 */
export function parseDictionaryField(headers, name) {
    const v = combinedField(headers, name);
    if (v === null) return new Map();
    try {
        return parseDictionary(v);
    } catch {
        throw err(`${name} is not a valid Dictionary`);
    }
}

// ---------------------------------------------------------------------------
// Component identifiers
// ---------------------------------------------------------------------------

/**
 * "Percent-encode after encoding" with the application/x-www-form-urlencoded
 * set, spaces as `%20` (RFC 9421 §2.2.8 and its examples).
 */
function encodeQueryPart(s) {
    let out = '';
    for (const b of Buffer.from(s, 'utf8')) {
        const c = String.fromCharCode(b);
        if (/[A-Za-z0-9*\-._]/.test(c)) out += c;
        else out += `%${b.toString(16).toUpperCase().padStart(2, '0')}`;
    }
    return out;
}

/** A covered component identifier. */
export class Component {
    /**
     * @param {string} name - Lowercase field name or derived component name (`@authority`)
     * @param {object} [opts]
     * @param {string|null} [opts.key] - Cover one member of a Dictionary field
     * @param {boolean} [opts.req] - Resolve against the related request
     * @param {string|null} [opts.queryName] - Encoded `name` parameter of `@query-param`
     */
    constructor(name, { key = null, req = false, queryName = null } = {}) {
        this.name = name;
        this.key = key;
        this.req = req;
        this.queryName = queryName;
    }

    /** A Dictionary field member, e.g. `"signature-agent";key="sig1"`. */
    static keyed(name, key) {
        return new Component(name, { key });
    }

    /** A component of the related request, e.g. `"@authority";req`. */
    static ofRequest(name) {
        return new Component(name, { req: true });
    }

    /** One named query parameter; `name` is percent-encoded per RFC 9421 §2.2.8. */
    static queryParam(name) {
        return new Component('@query-param', { queryName: encodeQueryPart(name) });
    }

    /** Accept a Component or a bare component name. */
    static from(c) {
        return c instanceof Component ? c : new Component(String(c));
    }

    equals(other) {
        const o = Component.from(other);
        return this.name === o.name && this.key === o.key && this.req === o.req && this.queryName === o.queryName;
    }

    toItem() {
        const params = [];
        if (this.queryName !== null) params.push(['name', sfString(this.queryName)]);
        if (this.key !== null) params.push(['key', sfString(this.key)]);
        if (this.req) params.push(['req', sfBoolean(true)]);
        return sfItem(sfString(this.name), params);
    }

    /** Serialized identifier, e.g. `"@query-param";name="q"`. */
    identifier() {
        return serializeItem(this.toItem());
    }

    static fromItem(item) {
        if (item.value.type !== 'string') throw err('component identifier is not a String');
        const name = item.value.value;
        if (name.length === 0 || name !== name.toLowerCase()) {
            throw err(`component name '${name}' must be lowercase`);
        }
        if (name === '@signature-params') throw err('@signature-params cannot be covered');
        const c = new Component(name);
        for (const [k, v] of item.params) {
            if (k === 'key') {
                if (v.type !== 'string') throw err('key parameter must be a String');
                if (name.startsWith('@')) throw err('key parameter on a derived component');
                c.key = v.value;
            } else if (k === 'req') {
                if (!(v.type === 'boolean' && v.value === true)) throw err('req parameter must be true');
                c.req = true;
            } else if (k === 'name' && name === '@query-param') {
                if (v.type !== 'string') throw err('name parameter must be a String');
                c.queryName = v.value;
            } else {
                throw err(`unsupported component parameter '${k}' on '${name}'`);
            }
        }
        if ((name === '@query-param') !== (c.queryName !== null)) {
            throw err('@query-param needs exactly one name parameter');
        }
        return c;
    }
}

function rawQuery(u) {
    const noHash = u.href.split('#')[0];
    const i = noHash.indexOf('?');
    return i < 0 ? null : noHash.slice(i + 1);
}

function queryParamValue(u, name) {
    const found = [];
    for (const [n, v] of new URLSearchParams(rawQuery(u) || '')) {
        if (encodeQueryPart(n) === name) found.push(encodeQueryPart(v));
    }
    if (found.length === 0) throw err(`query parameter '${name}' is missing`);
    if (found.length > 1) throw err(`query parameter '${name}' occurs more than once`);
    return found[0];
}

function componentValue(msg, c) {
    if (c.req) {
        if (!isResponse(msg) || !msg.request) throw err('req parameter needs a response with its request');
        msg = msg.request;
    }
    if (c.name.startsWith('@')) {
        const derived = c.name.slice(1);
        if (derived === 'status') {
            if (!isResponse(msg)) throw err('@status is only valid on a response');
            return String(msg.status);
        }
        if (isResponse(msg)) throw err(`${c.name} needs a request`);
        const u = parseUrl(msg.url);
        const q = rawQuery(u);
        switch (derived) {
        case 'method': return String(msg.method);
        case 'target-uri': return u.href;
        case 'authority': return u.host.toLowerCase();
        case 'scheme': return u.protocol.slice(0, -1).toLowerCase();
        case 'request-target': return q === null ? u.pathname : `${u.pathname}?${q}`;
        case 'path': return u.pathname === '' ? '/' : u.pathname;
        case 'query': return `?${q || ''}`;
        case 'query-param': return queryParamValue(u, c.queryName || '');
        default: throw err(`unsupported derived component ${c.name}`);
        }
    }
    if (c.key === null) {
        const v = combinedField(msg.headers, c.name);
        if (v === null) throw err(`covered field '${c.name}' is missing`);
        return v;
    }
    const dict = parseDictionaryField(msg.headers, c.name);
    if (!dict.has(c.key)) throw err(`'${c.name}' has no member '${c.key}'`);
    return serializeListEntry(dict.get(c.key));
}

// ---------------------------------------------------------------------------
// Signature parameters
// ---------------------------------------------------------------------------

const INTEGER_PARAMS = new Set(['created', 'expires']);
const STRING_PARAMS = new Set(['keyid', 'alg', 'nonce', 'tag']);

/**
 * Build the `@signature-params` inner list. `params` is an ordered array of
 * `[name, value]` pairs: `created`/`expires` (integers), `keyid`, `alg`,
 * `nonce`, `tag` (strings). Parameters are written in the order given.
 */
function buildInnerList(components, params) {
    const p = new Map();
    for (const [k, v] of params || []) {
        let bare;
        if (INTEGER_PARAMS.has(k)) bare = sfInteger(v);
        else if (STRING_PARAMS.has(k)) {
            if (!isSfString(v)) throw err('value is not a valid sf-string');
            bare = sfString(v);
        } else throw err(`unsupported signature parameter '${k}'`);
        if (p.has(k)) throw err(`duplicate signature parameter '${k}'`);
        p.set(k, bare);
    }
    return sfInnerList(components.map((c) => c.toItem()), p);
}

function readParams(params) {
    const out = { created: null, expires: null, keyid: null, alg: null, nonce: null, tag: null };
    for (const [k, v] of params) {
        if (INTEGER_PARAMS.has(k)) {
            if (v.type !== 'integer') throw err(`${k} must be an Integer`);
            out[k] = v.value;
        } else if (STRING_PARAMS.has(k)) {
            if (v.type !== 'string') throw err(`${k} must be a String`);
            out[k] = v.value;
        }
        // Unknown parameters are covered by the signature; ignore them.
    }
    return out;
}

// ---------------------------------------------------------------------------
// Signature base, parsing
// ---------------------------------------------------------------------------

function signatureBase(msg, components, inner) {
    let base = '';
    for (const c of components) {
        const value = componentValue(msg, c);
        if (value.includes('\n') || value.includes('\r')) throw err('component value contains a line break');
        base += `${c.identifier()}: ${value}\n`;
    }
    return `${base}"@signature-params": ${serializeInnerList(inner)}`;
}

/** One signature read from `Signature-Input` and `Signature`. */
export class ParsedSignature {
    constructor(label, components, params, signature, inner) {
        this.label = label;
        /** @type {Component[]} */
        this.components = components;
        /** @type {{created: number|null, expires: number|null, keyid: string|null, alg: string|null, nonce: string|null, tag: string|null}} */
        this.params = params;
        /** @type {Buffer} */
        this.signature = signature;
        this._inner = inner;
    }

    /** `true` if the signature covers `component` (a Component or a name). */
    covers(component) {
        return this.components.some((c) => c.equals(component));
    }

    /** The exact signature base this signature claims to cover. */
    signatureBase(msg) {
        return signatureBase(msg, this.components, this._inner);
    }
}

/**
 * Parse every signature carried in `headers`. A `Signature-Input` member
 * without a matching `Signature` member, or a repeated component, is an
 * error.
 * @returns {ParsedSignature[]}
 */
export function parseSignatures(headers) {
    const inputs = parseDictionaryField(headers, 'signature-input');
    const sigs = parseDictionaryField(headers, 'signature');
    const out = [];
    for (const [label, entry] of inputs) {
        if (!isInnerList(entry)) throw err(`Signature-Input '${label}' is not an Inner List`);
        const sigEntry = sigs.get(label);
        if (!sigEntry || isInnerList(sigEntry)) throw err(`no Signature for label '${label}'`);
        if (sigEntry.value.type !== 'bytes') throw err(`Signature '${label}' is not a Byte Sequence`);
        const components = [];
        for (const item of entry.items) {
            const c = Component.fromItem(item);
            if (components.some((x) => x.equals(c))) throw err(`component '${c.name}' is covered twice`);
            components.push(c);
        }
        out.push(new ParsedSignature(label, components, readParams(entry.params), Buffer.from(sigEntry.value.value), entry));
    }
    return out;
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

const P = (1n << 255n) - 19n;
const D = ((P - 121665n) * modPow(121666n, P - 2n, P)) % P;

function modPow(b, e, m) {
    let r = 1n;
    b %= m;
    while (e > 0n) {
        if (e & 1n) r = (r * b) % m;
        b = (b * b) % m;
        e >>= 1n;
    }
    return r;
}

function leToBigInt(bytes) {
    let n = 0n;
    for (let i = bytes.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(bytes[i]);
    return n;
}

function edY(bytes) {
    const b = Buffer.from(bytes);
    b[31] &= 0x7f;
    return leToBigInt(b) % P;
}

/** `true` when 32 bytes decompress to a point on the Ed25519 curve. */
function isEd25519Point(bytes) {
    if (bytes.length !== 32) return false;
    const y = edY(bytes);
    const yy = (y * y) % P;
    const u = (yy - 1n + P) % P;
    const v = (D * yy + 1n) % P;
    const w = (u * modPow(v, P - 2n, P)) % P;
    return w === 0n || modPow(w, (P - 1n) / 2n, P) === 1n;
}

// y coordinates of the eight small-order points (orders 1, 2, 4 and 8).
const Y8 = leToBigInt(Buffer.from('c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a', 'hex'));
const SMALL_ORDER_Y = new Set([0n, 1n, P - 1n, Y8, P - Y8]);

function isSmallOrder(bytes) {
    return SMALL_ORDER_Y.has(edY(bytes));
}

/** A public key that verifies HTTP message signatures. */
export class PublicKey {
    /**
     * @param {'ed25519'|'rsa'} type
     * @param {object} material - `{ x }` for Ed25519, `{ n, e }` (big-endian, no leading zeros) for RSA
     */
    constructor(type, material) {
        this.type = type;
        if (type === 'ed25519') {
            this.x = Buffer.from(material.x);
        } else if (type === 'rsa') {
            this.n = Buffer.from(material.n);
            this.e = Buffer.from(material.e);
        } else {
            throw keyFormat();
        }
        this._keyObject = null;
    }

    /** Ed25519 key from its 32-byte encoding; rejects invalid points. */
    static ed25519(x) {
        const b = Buffer.from(x);
        if (!isEd25519Point(b)) throw keyFormat('invalid Ed25519 public key');
        return new PublicKey('ed25519', { x: b });
    }

    /** RSA key from modulus and exponent (minimal big-endian). */
    static rsa(n, e) {
        return new PublicKey('rsa', { n, e });
    }

    /** The RFC 9421 `alg` this key signs with. */
    get alg() {
        return this.type === 'ed25519' ? ALG_ED25519 : ALG_RSA_PSS_SHA512;
    }

    equals(other) {
        if (!(other instanceof PublicKey) || other.type !== this.type) return false;
        return this.type === 'ed25519'
            ? this.x.equals(other.x)
            : this.n.equals(other.n) && this.e.equals(other.e);
    }

    keyObject() {
        if (!this._keyObject) {
            const jwk = this.type === 'ed25519'
                ? { kty: 'OKP', crv: 'Ed25519', x: base64urlEncode(this.x) }
                : { kty: 'RSA', n: base64urlEncode(this.n), e: base64urlEncode(this.e) };
            this._keyObject = createPublicKey({ key: jwk, format: 'jwk' });
        }
        return this._keyObject;
    }

    /**
     * Verify `sig` over `data`. Ed25519 verification is strict (rejects
     * small-order keys and R values, and non-canonical S); RSA keys must be
     * 2048 to 8192 bits and signatures exactly the modulus length.
     * @throws {AgentPinError} SIGNATURE_INVALID
     */
    verify(data, sig) {
        sig = Buffer.from(sig);
        let ok = false;
        try {
            if (this.type === 'ed25519') {
                ok = sig.length === 64
                    && !isSmallOrder(this.x)
                    && !isSmallOrder(sig.subarray(0, 32))
                    && cryptoVerify(null, Buffer.from(data), this.keyObject(), sig);
            } else {
                const bits = bitLength(this.n);
                const e = this.e;
                ok = bits >= 2048 && bits <= 8192
                    && (this.n[this.n.length - 1] & 1) === 1
                    && e.length > 0 && e.length <= 4 && (e[e.length - 1] & 1) === 1
                    && !(e.length === 1 && e[0] < 3)
                    && sig.length === this.n.length
                    && cryptoVerify('sha512', Buffer.from(data), {
                        key: this.keyObject(),
                        padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
                        saltLength: 64,
                    }, sig);
            }
        } catch {
            ok = false;
        }
        if (!ok) throw signatureInvalid();
    }
}

function bitLength(n) {
    if (n.length === 0) return 0;
    return (n.length - 1) * 8 + (32 - Math.clz32(n[0]));
}

/** A private key that signs HTTP messages. */
export class PrivateKey {
    constructor(keyObject) {
        const type = keyObject.asymmetricKeyType;
        if (type === 'ed25519') {
            this.type = 'ed25519';
        } else if (type === 'rsa') {
            const bits = keyObject.asymmetricKeyDetails?.modulusLength ?? 0;
            const bytes = Math.ceil(bits / 8);
            if (bytes < 256 || bytes > 1024) throw keyFormat('RSA keys must be 2048 to 8192 bits');
            this.type = 'rsa';
        } else {
            throw keyFormat();
        }
        this._keyObject = keyObject;
        this._public = null;
    }

    /**
     * Load a PEM key: PKCS#8 (`PRIVATE KEY`) Ed25519 or RSA, or PKCS#1
     * (`RSA PRIVATE KEY`). RSA keys must be 2048 to 8192 bits; keys with
     * the RSASSA-PSS algorithm identifier are rejected.
     */
    static fromPem(pem) {
        const m = /-----BEGIN ([A-Z ]+)-----/.exec(String(pem));
        if (!m || (m[1] !== 'PRIVATE KEY' && m[1] !== 'RSA PRIVATE KEY')) throw keyFormat();
        let ko;
        try {
            ko = createPrivateKey({ key: String(pem), format: 'pem' });
        } catch {
            throw keyFormat();
        }
        if (m[1] === 'RSA PRIVATE KEY' && ko.asymmetricKeyType !== 'rsa') throw keyFormat();
        return new PrivateKey(ko);
    }

    /** Generate a new Ed25519 key. */
    static generateEd25519() {
        return new PrivateKey(generateKeyPairSync('ed25519').privateKey);
    }

    get alg() {
        return this.type === 'ed25519' ? ALG_ED25519 : ALG_RSA_PSS_SHA512;
    }

    /** @returns {PublicKey} */
    publicKey() {
        if (!this._public) {
            const jwk = createPublicKey(this._keyObject).export({ format: 'jwk' });
            this._public = this.type === 'ed25519'
                ? new PublicKey('ed25519', { x: base64urlDecode(jwk.x) })
                : new PublicKey('rsa', { n: base64urlDecode(jwk.n), e: base64urlDecode(jwk.e) });
        }
        return this._public;
    }

    /** PKCS#8 PEM encoding. */
    toPem() {
        return this._keyObject.export({ type: 'pkcs8', format: 'pem' });
    }

    /** @returns {Buffer} */
    sign(data) {
        if (this.type === 'ed25519') return cryptoSign(null, Buffer.from(data), this._keyObject);
        return cryptoSign('sha512', Buffer.from(data), {
            key: this._keyObject,
            padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
            saltLength: 64,
        });
    }
}

// ---------------------------------------------------------------------------
// Signing and verifying
// ---------------------------------------------------------------------------

/**
 * Sign `msg` over `components` under `label`.
 * @param {object} msg - Request or response message
 * @param {string} label
 * @param {Array<Component|string>} components
 * @param {Array<[string, string|number]>} params - Ordered signature parameters
 * @param {PrivateKey} key
 * @returns {{ signatureInput: string, signature: string }} `Signature-Input` and
 *   `Signature` member strings, each a valid field value on its own
 */
export function sign(msg, label, components, params, key) {
    const comps = components.map(Component.from);
    comps.forEach((c, i) => {
        if (comps.slice(0, i).some((x) => x.equals(c))) throw err(`component '${c.name}' is covered twice`);
    });
    const inner = buildInnerList(comps, params);
    const base = signatureBase(msg, comps, inner);
    const sig = key.sign(Buffer.from(base, 'utf8'));
    return {
        signatureInput: serializeDictionary([[label, inner]]),
        signature: serializeDictionary([[label, sfItem({ type: 'bytes', value: sig })]]),
    };
}

/**
 * Verify `sig` over `msg`. A present `alg` parameter must match the key.
 * @param {object} msg
 * @param {ParsedSignature} sig
 * @param {PublicKey} key
 * @throws {AgentPinError}
 */
export function verify(msg, sig, key) {
    if (sig.params.alg !== null && sig.params.alg !== key.alg) throw signatureInvalid();
    const base = sig.signatureBase(msg);
    key.verify(Buffer.from(base, 'utf8'), sig.signature);
}

/** `Content-Digest` value for `body` using SHA-256 (RFC 9530). */
export function contentDigest(body) {
    return `sha-256=:${createHash('sha256').update(toBytes(body)).digest('base64')}:`;
}

/**
 * `true` when the `Content-Digest` field in `headers` carries a `sha-256`
 * member matching `body`.
 */
export function contentDigestMatches(headers, body) {
    let dict;
    try {
        dict = parseDictionaryField(headers, 'content-digest');
    } catch {
        return false;
    }
    const entry = dict.get('sha-256');
    if (!entry || isInnerList(entry) || entry.value.type !== 'bytes') return false;
    return entry.value.value.equals(createHash('sha256').update(toBytes(body)).digest());
}

/** @returns {Buffer} */
export function toBytes(body) {
    return typeof body === 'string' ? Buffer.from(body, 'utf8') : Buffer.from(body);
}
