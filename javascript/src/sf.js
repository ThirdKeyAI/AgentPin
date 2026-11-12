/**
 * Minimal, strict Structured Field Values (RFC 8941 / RFC 9651) parser and
 * serializer, covering what HTTP Message Signatures need: Dictionaries,
 * Items, Inner Lists and Parameters, with Integer, Decimal, String, Token,
 * Byte Sequence, Boolean, Date and Display String bare items.
 *
 * Representation:
 * - bare item: `{ type, value }` with `type` one of `integer`, `decimal`,
 *   `string`, `token`, `bytes` (value is a Buffer), `boolean`, `date`,
 *   `displaystring`;
 * - item: `{ value: BareItem, params: Map<string, BareItem> }`;
 * - inner list: `{ items: Item[], params: Map<string, BareItem> }`;
 * - dictionary: `Map<string, Item | InnerList>`, in member order.
 *
 * A repeated Dictionary or Parameter key keeps its first position and takes
 * the last value, as the RFC's ordered-map semantics require.
 */

import { AgentPinError, ErrorCode } from './types.js';

function sfError(message) {
    return new AgentPinError(ErrorCode.HTTP_SIGNATURE_INVALID, message);
}

const MAX_INTEGER = 999999999999999;

const isDigit = (c) => c >= '0' && c <= '9';
const isLcAlpha = (c) => c >= 'a' && c <= 'z';
const isAlpha = (c) => isLcAlpha(c) || (c >= 'A' && c <= 'Z');
const TCHAR_EXTRA = '!#$%&\'*+-.^_`|~';
const isTchar = (c) => isAlpha(c) || isDigit(c) || (c !== '' && TCHAR_EXTRA.includes(c));
const isKeyStart = (c) => isLcAlpha(c) || c === '*';
const isKeyChar = (c) => isLcAlpha(c) || isDigit(c) || c === '_' || c === '-' || c === '*' || c === '.';
const isTokenStart = (c) => isAlpha(c) || c === '*';
const isTokenChar = (c) => isTchar(c) || c === ':' || c === '/';

// ---------------------------------------------------------------------------
// Constructors
// ---------------------------------------------------------------------------

/** @returns {{type: 'string', value: string}} */
export const sfString = (value) => ({ type: 'string', value });
/** @returns {{type: 'integer', value: number}} */
export const sfInteger = (value) => ({ type: 'integer', value });
/** @returns {{type: 'decimal', value: number}} */
export const sfDecimal = (value) => ({ type: 'decimal', value });
/** @returns {{type: 'token', value: string}} */
export const sfToken = (value) => ({ type: 'token', value });
/** @returns {{type: 'bytes', value: Buffer}} */
export const sfBytes = (value) => ({ type: 'bytes', value: Buffer.from(value) });
/** @returns {{type: 'boolean', value: boolean}} */
export const sfBoolean = (value) => ({ type: 'boolean', value });

/** An Item with optional parameters (a Map or an array of [key, bareItem]). */
export function sfItem(value, params) {
    return { value, params: new Map(params || []) };
}

/** An Inner List of Items with optional parameters. */
export function sfInnerList(items, params) {
    return { items, params: new Map(params || []) };
}

/** `true` when a Dictionary member or List entry is an Inner List. */
export function isInnerList(entry) {
    return entry !== null && typeof entry === 'object' && Array.isArray(entry.items);
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

class Parser {
    constructor(input) {
        if (typeof input !== 'string') throw sfError('structured field input must be a string');
        this.s = input;
        this.i = 0;
    }

    peek() {
        return this.i < this.s.length ? this.s[this.i] : '';
    }

    done() {
        return this.i >= this.s.length;
    }

    fail(what) {
        return sfError(`invalid structured field: ${what} at offset ${this.i}`);
    }

    sp() {
        while (this.peek() === ' ') this.i++;
    }

    ows() {
        while (this.peek() === ' ' || this.peek() === '\t') this.i++;
    }

    top(fn) {
        this.sp();
        const v = fn();
        this.sp();
        if (!this.done()) throw this.fail('trailing characters');
        return v;
    }

    commaSeparated(member) {
        while (!this.done()) {
            member();
            this.ows();
            if (this.done()) return;
            if (this.peek() !== ',') throw this.fail('expected comma');
            this.i++;
            this.ows();
            if (this.done()) throw this.fail('trailing comma');
        }
    }

    dictionary() {
        const dict = new Map();
        this.commaSeparated(() => {
            const key = this.key();
            if (this.peek() === '=') {
                this.i++;
                dict.set(key, this.listEntry());
            } else {
                dict.set(key, { value: sfBoolean(true), params: this.parameters() });
            }
        });
        return dict;
    }

    list() {
        const out = [];
        this.commaSeparated(() => out.push(this.listEntry()));
        return out;
    }

    listEntry() {
        return this.peek() === '(' ? this.innerList() : this.item();
    }

    innerList() {
        if (this.peek() !== '(') throw this.fail('expected inner list');
        this.i++;
        const items = [];
        while (!this.done()) {
            this.sp();
            if (this.peek() === ')') {
                this.i++;
                return { items, params: this.parameters() };
            }
            items.push(this.item());
            const c = this.peek();
            if (c !== '' && c !== ' ' && c !== ')') throw this.fail('expected inner list delimiter');
        }
        throw this.fail('unterminated inner list');
    }

    item() {
        const value = this.bareItem();
        return { value, params: this.parameters() };
    }

    parameters() {
        const params = new Map();
        while (this.peek() === ';') {
            this.i++;
            this.sp();
            const key = this.key();
            let value = sfBoolean(true);
            if (this.peek() === '=') {
                this.i++;
                value = this.bareItem();
            }
            params.set(key, value);
        }
        return params;
    }

    key() {
        const start = this.i;
        if (!isKeyStart(this.peek())) throw this.fail('expected key');
        this.i++;
        while (isKeyChar(this.peek())) this.i++;
        return this.s.slice(start, this.i);
    }

    bareItem() {
        const c = this.peek();
        if (c === '-' || isDigit(c)) return this.number();
        if (c === '"') return { type: 'string', value: this.string() };
        if (c === ':') return { type: 'bytes', value: this.bytes() };
        if (c === '?') return { type: 'boolean', value: this.boolean() };
        if (c === '@') return this.date();
        if (c === '%') return { type: 'displaystring', value: this.displayString() };
        if (isTokenStart(c)) return { type: 'token', value: this.token() };
        throw this.fail('expected bare item');
    }

    number() {
        let sign = 1;
        if (this.peek() === '-') {
            sign = -1;
            this.i++;
        }
        if (!isDigit(this.peek())) throw this.fail('expected digit');
        let intPart = '';
        while (isDigit(this.peek())) {
            intPart += this.peek();
            this.i++;
            if (intPart.length > 15) throw this.fail('too many digits');
        }
        if (this.peek() !== '.') {
            return { type: 'integer', value: sign * Number(intPart) };
        }
        if (intPart.length > 12) throw this.fail('too many digits before decimal point');
        this.i++;
        let frac = '';
        while (isDigit(this.peek())) {
            if (frac.length === 3) throw this.fail('too many digits after decimal point');
            frac += this.peek();
            this.i++;
        }
        if (frac.length === 0) throw this.fail('trailing decimal point');
        const scaled = Number(intPart) * 1000 + Number(frac.padEnd(3, '0'));
        return { type: 'decimal', value: (sign * scaled) / 1000 };
    }

    string() {
        this.i++; // opening quote
        let out = '';
        while (!this.done()) {
            const c = this.peek();
            const code = c.charCodeAt(0);
            this.i++;
            if (c === '"') return out;
            if (code < 0x20 || code > 0x7e) throw this.fail('invalid string character');
            if (c === '\\') {
                const n = this.peek();
                if (n === '') throw this.fail('unterminated escape');
                if (n !== '\\' && n !== '"') throw this.fail('invalid escape');
                out += n;
                this.i++;
            } else {
                out += c;
            }
        }
        throw this.fail('unterminated string');
    }

    token() {
        const start = this.i;
        this.i++;
        while (isTokenChar(this.peek())) this.i++;
        return this.s.slice(start, this.i);
    }

    bytes() {
        this.i++; // opening colon
        const end = this.s.indexOf(':', this.i);
        if (end < 0) throw this.fail('unterminated byte sequence');
        const b64 = this.s.slice(this.i, end);
        this.i = end + 1;
        const value = decodeBase64Lenient(b64);
        if (value === null) throw this.fail('invalid byte sequence');
        return value;
    }

    boolean() {
        this.i++;
        const c = this.peek();
        if (c === '0' || c === '1') {
            this.i++;
            return c === '1';
        }
        throw this.fail('expected boolean');
    }

    date() {
        this.i++;
        const n = this.number();
        if (n.type !== 'integer') throw this.fail('non-integer date');
        return { type: 'date', value: n.value };
    }

    displayString() {
        this.i++;
        if (this.peek() !== '"') throw this.fail('expected quote');
        this.i++;
        const bytes = [];
        while (!this.done()) {
            const c = this.peek();
            const code = c.charCodeAt(0);
            this.i++;
            if (c === '"') {
                try {
                    return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(bytes));
                } catch {
                    throw this.fail('invalid UTF-8 in display string');
                }
            }
            if (code < 0x20 || code > 0x7e) throw this.fail('invalid display string character');
            if (c === '%') {
                const hex = this.s.slice(this.i, this.i + 2);
                if (!/^[0-9a-f]{2}$/.test(hex)) throw this.fail('invalid escape');
                bytes.push(parseInt(hex, 16));
                this.i += 2;
            } else {
                bytes.push(code);
            }
        }
        throw this.fail('unterminated display string');
    }
}

/**
 * Standard-alphabet base64, padding optional but correct when present,
 * trailing bits ignored. Returns null when malformed.
 */
function decodeBase64Lenient(s) {
    const m = /^([A-Za-z0-9+/]*)(={0,2})$/.exec(s);
    if (!m) return null;
    const data = m[1];
    const pad = m[2].length;
    const rem = data.length % 4;
    if (rem === 1) return null;
    if (pad > 0 && (rem === 0 || rem + pad !== 4)) return null;
    return Buffer.from(data, 'base64');
}

/** Parse a Dictionary field value. @returns {Map} */
export function parseDictionary(input) {
    const p = new Parser(input);
    return p.top(() => p.dictionary());
}

/** Parse a List field value. @returns {Array} */
export function parseList(input) {
    const p = new Parser(input);
    return p.top(() => p.list());
}

/** Parse an Item field value. */
export function parseItem(input) {
    const p = new Parser(input);
    return p.top(() => p.item());
}

// ---------------------------------------------------------------------------
// Serializer
// ---------------------------------------------------------------------------

function serializeKey(key) {
    if (typeof key !== 'string' || key.length === 0 || !isKeyStart(key[0]) || ![...key].every(isKeyChar)) {
        throw sfError(`invalid structured field key '${key}'`);
    }
    return key;
}

function serializeIntegerValue(v) {
    if (!Number.isInteger(v) || Math.abs(v) > MAX_INTEGER) throw sfError('integer out of range');
    return String(v);
}

function serializeDecimalValue(v) {
    if (typeof v !== 'number' || !Number.isFinite(v)) throw sfError('decimal out of range');
    const scaled = Math.round(v * 1000);
    const abs = Math.abs(scaled);
    const intPart = Math.floor(abs / 1000);
    if (String(intPart).length > 12) throw sfError('decimal out of range');
    if (scaled === 0) return '0.0';
    const sign = scaled < 0 ? '-' : '';
    const f = abs % 1000;
    let frac;
    if (f % 100 === 0) frac = String(f / 100);
    else if (f % 10 === 0) frac = String(f / 10).padStart(2, '0');
    else frac = String(f).padStart(3, '0');
    return `${sign}${intPart}.${frac}`;
}

/** `true` when `s` is a valid sf-string (printable ASCII). */
export function isSfString(s) {
    return typeof s === 'string' && /^[\x20-\x7e]*$/.test(s);
}

function serializeStringValue(s) {
    if (!isSfString(s)) throw sfError('value is not a valid sf-string');
    return `"${s.replace(/[\\"]/g, (c) => `\\${c}`)}"`;
}

function serializeTokenValue(s) {
    if (typeof s !== 'string' || s.length === 0 || !isTokenStart(s[0]) || ![...s].every(isTokenChar)) {
        throw sfError(`invalid token '${s}'`);
    }
    return s;
}

function serializeDisplayStringValue(s) {
    let out = '%"';
    for (const b of Buffer.from(String(s), 'utf8')) {
        if (b === 0x25 || b === 0x22 || b < 0x20 || b > 0x7e) {
            out += `%${b.toString(16).padStart(2, '0')}`;
        } else {
            out += String.fromCharCode(b);
        }
    }
    return `${out}"`;
}

/** Serialize a bare item. */
export function serializeBareItem(bare) {
    if (!bare || typeof bare !== 'object') throw sfError('invalid bare item');
    switch (bare.type) {
    case 'integer': return serializeIntegerValue(bare.value);
    case 'decimal': return serializeDecimalValue(bare.value);
    case 'string': return serializeStringValue(bare.value);
    case 'token': return serializeTokenValue(bare.value);
    case 'bytes': return `:${Buffer.from(bare.value).toString('base64')}:`;
    case 'boolean': return bare.value ? '?1' : '?0';
    case 'date': return `@${serializeIntegerValue(bare.value)}`;
    case 'displaystring': return serializeDisplayStringValue(bare.value);
    default: throw sfError(`unknown bare item type '${bare.type}'`);
    }
}

/** Serialize Parameters (a Map or array of [key, bareItem]). */
export function serializeParams(params) {
    let out = '';
    for (const [k, v] of params || []) {
        out += `;${serializeKey(k)}`;
        if (!(v.type === 'boolean' && v.value === true)) out += `=${serializeBareItem(v)}`;
    }
    return out;
}

/** Serialize an Item (bare item plus parameters). */
export function serializeItem(item) {
    return serializeBareItem(item.value) + serializeParams(item.params);
}

/** Serialize an Inner List. */
export function serializeInnerList(inner) {
    return `(${inner.items.map(serializeItem).join(' ')})${serializeParams(inner.params)}`;
}

/** Serialize one List entry (Item or Inner List). */
export function serializeListEntry(entry) {
    return isInnerList(entry) ? serializeInnerList(entry) : serializeItem(entry);
}

/** Serialize a List. */
export function serializeList(entries) {
    return entries.map(serializeListEntry).join(', ');
}

/** Serialize a Dictionary (a Map or array of [key, entry]). */
export function serializeDictionary(dict) {
    const parts = [];
    for (const [k, entry] of dict) {
        const key = serializeKey(k);
        if (!isInnerList(entry) && entry.value.type === 'boolean' && entry.value.value === true) {
            parts.push(key + serializeParams(entry.params));
        } else {
            parts.push(`${key}=${serializeListEntry(entry)}`);
        }
    }
    return parts.join(', ');
}
