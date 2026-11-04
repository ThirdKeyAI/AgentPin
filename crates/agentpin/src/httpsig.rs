//! RFC 9421 HTTP Message Signatures.
//!
//! Builds signature bases, reads and writes the `Signature-Input` and
//! `Signature` fields, and signs and verifies with Ed25519
//! (`alg="ed25519"`). This is the layer Web Bot Auth ([`crate::wba`]) is
//! built on.
//!
//! Supported component identifiers: `@method`, `@target-uri`, `@authority`,
//! `@scheme`, `@request-target`, `@path`, `@query`, `@status`, and HTTP
//! fields, with the `key` (Dictionary member) and `req` (related request)
//! parameters. Identifiers carrying any other parameter (`sf`, `bs`, `tr`,
//! `name`) are rejected rather than silently mis-serialized.

use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use ring::signature::{self as rsig, RsaKeyPair, RsaPublicKeyComponents};
use sfv::{BareItem, Dictionary, FieldType, InnerList, Item, Key, ListEntry, Parameters, Parser};
use url::Url;

use crate::error::Error;

fn err(msg: impl Into<String>) -> Error {
    Error::HttpSignature(msg.into())
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

/// The parts of an HTTP request a signature can cover.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: Url,
    /// Header fields in order; names are matched case-insensitively.
    pub headers: Vec<(String, String)>,
}

impl HttpRequest {
    /// Build a request from a method and an absolute URL.
    pub fn new(method: &str, url: &str) -> Result<Self, Error> {
        let url = Url::parse(url).map_err(|_| err("request URL is not an absolute URL"))?;
        if url.host_str().is_none() {
            return Err(err("request URL has no host"));
        }
        Ok(Self {
            method: method.to_string(),
            url,
            headers: Vec::new(),
        })
    }

    /// Append a header field.
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

/// The parts of an HTTP response a signature can cover.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
}

/// The message a signature is computed over. A response may carry the
/// request that produced it, for components with the `req` parameter.
#[derive(Debug, Clone, Copy)]
pub enum Message<'a> {
    Request(&'a HttpRequest),
    Response {
        response: &'a HttpResponse,
        request: Option<&'a HttpRequest>,
    },
}

impl Message<'_> {
    fn headers(&self) -> &[(String, String)] {
        match self {
            Message::Request(r) => &r.headers,
            Message::Response { response, .. } => &response.headers,
        }
    }
}

/// Combined value of every `name` field: each value trimmed, joined with
/// `", "` (RFC 9421 §2.1). `None` when the field is absent.
pub fn combined_field(headers: &[(String, String)], name: &str) -> Option<String> {
    let values: Vec<&str> = headers
        .iter()
        .filter(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.trim())
        .collect();
    if values.is_empty() {
        None
    } else {
        Some(values.join(", "))
    }
}

/// Parse the combined `name` field as a Structured Field Dictionary; an
/// absent field is an empty Dictionary.
pub fn parse_dictionary_field(
    headers: &[(String, String)],
    name: &str,
) -> Result<Dictionary, Error> {
    match combined_field(headers, name) {
        None => Ok(Dictionary::new()),
        Some(v) => Parser::new(&v)
            .parse::<Dictionary>()
            .map_err(|_| err(format!("{} is not a valid Dictionary", name))),
    }
}

/// Serialize one Dictionary member's value (item or inner list, with its
/// parameters) the way RFC 9421 §2.1.2 covers it.
fn serialize_member(entry: &ListEntry) -> String {
    vec![entry.clone()].serialize().unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Component identifiers
// ---------------------------------------------------------------------------

/// A covered component identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Component {
    /// Lowercase field name or derived component name (`@authority`).
    pub name: String,
    /// `key` parameter: cover one member of a Dictionary field.
    pub key: Option<String>,
    /// `req` parameter: resolve against the related request.
    pub req: bool,
    /// `name` parameter of `@query-param`: the encoded parameter name.
    pub query_name: Option<String>,
}

impl Component {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            key: None,
            req: false,
            query_name: None,
        }
    }

    /// A Dictionary field member, e.g. `"signature-agent";key="sig1"`.
    pub fn keyed(name: &str, key: &str) -> Self {
        Self {
            key: Some(key.to_string()),
            ..Self::new(name)
        }
    }

    /// A component of the related request, e.g. `"@authority";req`.
    pub fn of_request(name: &str) -> Self {
        Self {
            req: true,
            ..Self::new(name)
        }
    }

    /// One named query parameter, e.g. `"@query-param";name="q"`. `name`
    /// is percent-encoded as RFC 9421 §2.2.8 requires.
    pub fn query_param(name: &str) -> Self {
        Self {
            query_name: Some(encode_query_part(name)),
            ..Self::new("@query-param")
        }
    }

    fn to_item(&self) -> Result<Item, Error> {
        let mut params = Parameters::new();
        if let Some(ref n) = self.query_name {
            params.insert(key_of("name")?, BareItem::String(sf_string(n)?));
        }
        if let Some(ref k) = self.key {
            params.insert(key_of("key")?, BareItem::String(sf_string(k)?));
        }
        if self.req {
            params.insert(key_of("req")?, BareItem::Boolean(true));
        }
        Ok(Item::with_params(
            BareItem::String(sf_string(&self.name)?),
            params,
        ))
    }

    fn from_item(item: &Item) -> Result<Self, Error> {
        let name = item
            .bare_item
            .as_string()
            .ok_or_else(|| err("component identifier is not a String"))?
            .as_str()
            .to_string();
        if name.is_empty() || name != name.to_ascii_lowercase() {
            return Err(err(format!("component name '{}' must be lowercase", name)));
        }
        if name == "@signature-params" {
            return Err(err("@signature-params cannot be covered"));
        }
        let mut c = Component::new(&name);
        for (k, v) in &item.params {
            match k.as_str() {
                "key" => {
                    let s = v
                        .as_string()
                        .ok_or_else(|| err("key parameter must be a String"))?;
                    if name.starts_with('@') {
                        return Err(err("key parameter on a derived component"));
                    }
                    c.key = Some(s.as_str().to_string());
                }
                "req" => {
                    if v.as_boolean() != Some(true) {
                        return Err(err("req parameter must be true"));
                    }
                    c.req = true;
                }
                "name" if name == "@query-param" => {
                    let s = v
                        .as_string()
                        .ok_or_else(|| err("name parameter must be a String"))?;
                    c.query_name = Some(s.as_str().to_string());
                }
                other => {
                    return Err(err(format!(
                        "unsupported component parameter '{}' on '{}'",
                        other, name
                    )))
                }
            }
        }
        if (name == "@query-param") != c.query_name.is_some() {
            return Err(err("@query-param needs exactly one name parameter"));
        }
        Ok(c)
    }

    fn identifier(&self) -> Result<String, Error> {
        Ok(self.to_item()?.serialize())
    }
}

fn key_of(s: &str) -> Result<Key, Error> {
    Key::from_string(s.to_string()).map_err(|_| err(format!("invalid key '{}'", s)))
}

fn sf_string(s: &str) -> Result<sfv::String, Error> {
    sfv::String::from_string(s.to_string()).map_err(|_| err("value is not a valid sf-string"))
}

/// "Percent-encode after encoding" with the application/x-www-form-urlencoded
/// set, spaces as `%20` (RFC 9421 §2.2.8 and its examples).
fn encode_query_part(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'*' | b'-' | b'.' | b'_') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{:02X}", b));
        }
    }
    out
}

/// `@query-param` value: the single parameter whose encoded name is
/// `name`. Absent or repeated parameters are errors.
fn query_param_value(url: &Url, name: &str) -> Result<String, Error> {
    let mut found = url
        .query_pairs()
        .filter(|(n, _)| encode_query_part(n) == name)
        .map(|(_, v)| encode_query_part(&v));
    match (found.next(), found.next()) {
        (Some(v), None) => Ok(v),
        (None, _) => Err(err(format!("query parameter '{}' is missing", name))),
        _ => Err(err(format!(
            "query parameter '{}' occurs more than once",
            name
        ))),
    }
}

fn authority(url: &Url) -> Result<String, Error> {
    let host = url
        .host_str()
        .ok_or_else(|| err("URL has no host"))?
        .to_ascii_lowercase();
    Ok(match url.port() {
        Some(p) => format!("{}:{}", host, p),
        None => host,
    })
}

fn component_value(msg: Message<'_>, c: &Component) -> Result<String, Error> {
    let msg = if c.req {
        match msg {
            Message::Response {
                request: Some(r), ..
            } => Message::Request(r),
            _ => return Err(err("req parameter needs a response with its request")),
        }
    } else {
        msg
    };

    if let Some(derived) = c.name.strip_prefix('@') {
        if derived == "status" {
            return match msg {
                Message::Response { response, .. } => Ok(response.status.to_string()),
                Message::Request(_) => Err(err("@status is only valid on a response")),
            };
        }
        let Message::Request(req) = msg else {
            return Err(err(format!("{} needs a request", c.name)));
        };
        let url = &req.url;
        return match derived {
            "method" => Ok(req.method.clone()),
            "target-uri" => Ok(url.as_str().to_string()),
            "authority" => authority(url),
            "scheme" => Ok(url.scheme().to_ascii_lowercase()),
            "request-target" => Ok(match url.query() {
                Some(q) => format!("{}?{}", url.path(), q),
                None => url.path().to_string(),
            }),
            "path" => Ok(if url.path().is_empty() {
                "/".to_string()
            } else {
                url.path().to_string()
            }),
            "query" => Ok(format!("?{}", url.query().unwrap_or(""))),
            "query-param" => query_param_value(url, c.query_name.as_deref().unwrap_or_default()),
            _ => Err(err(format!("unsupported derived component {}", c.name))),
        };
    }

    match c.key {
        None => combined_field(msg.headers(), &c.name)
            .ok_or_else(|| err(format!("covered field '{}' is missing", c.name))),
        Some(ref k) => {
            let dict = parse_dictionary_field(msg.headers(), &c.name)?;
            let entry = dict
                .get(k.as_str())
                .ok_or_else(|| err(format!("'{}' has no member '{}'", c.name, k)))?;
            Ok(serialize_member(entry))
        }
    }
}

// ---------------------------------------------------------------------------
// Signature parameters
// ---------------------------------------------------------------------------

/// One `@signature-params` parameter, for signing. Parameters are written
/// in the order given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Param {
    Created(i64),
    Expires(i64),
    KeyId(String),
    Alg(String),
    Nonce(String),
    Tag(String),
}

/// Signature parameters as received.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SignatureParams {
    pub created: Option<i64>,
    pub expires: Option<i64>,
    pub keyid: Option<String>,
    pub alg: Option<String>,
    pub nonce: Option<String>,
    pub tag: Option<String>,
}

fn sf_integer(v: i64) -> Result<BareItem, Error> {
    sfv::Integer::try_from(v)
        .map(BareItem::Integer)
        .map_err(|_| err("integer out of range"))
}

fn build_inner_list(components: &[Component], params: &[Param]) -> Result<InnerList, Error> {
    let items = components
        .iter()
        .map(Component::to_item)
        .collect::<Result<Vec<_>, _>>()?;
    let mut p = Parameters::new();
    for param in params {
        let (k, v) = match param {
            Param::Created(t) => ("created", sf_integer(*t)?),
            Param::Expires(t) => ("expires", sf_integer(*t)?),
            Param::KeyId(s) => ("keyid", BareItem::String(sf_string(s)?)),
            Param::Alg(s) => ("alg", BareItem::String(sf_string(s)?)),
            Param::Nonce(s) => ("nonce", BareItem::String(sf_string(s)?)),
            Param::Tag(s) => ("tag", BareItem::String(sf_string(s)?)),
        };
        if p.insert(key_of(k)?, v).is_some() {
            return Err(err(format!("duplicate signature parameter '{}'", k)));
        }
    }
    Ok(InnerList::with_params(items, p))
}

fn read_params(params: &Parameters) -> Result<SignatureParams, Error> {
    let int = |v: &BareItem, k: &str| {
        v.as_integer()
            .map(i64::from)
            .ok_or_else(|| err(format!("{} must be an Integer", k)))
    };
    let string = |v: &BareItem, k: &str| {
        v.as_string()
            .map(|s| s.as_str().to_string())
            .ok_or_else(|| err(format!("{} must be a String", k)))
    };
    let mut out = SignatureParams::default();
    for (k, v) in params {
        match k.as_str() {
            "created" => out.created = Some(int(v, "created")?),
            "expires" => out.expires = Some(int(v, "expires")?),
            "keyid" => out.keyid = Some(string(v, "keyid")?),
            "alg" => out.alg = Some(string(v, "alg")?),
            "nonce" => out.nonce = Some(string(v, "nonce")?),
            "tag" => out.tag = Some(string(v, "tag")?),
            // Unknown parameters are covered by the signature; ignore them.
            _ => {}
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Signature base, parsing, signing, verifying
// ---------------------------------------------------------------------------

/// Build the signature base (RFC 9421 §2.5) for `components` and the
/// serialized `@signature-params` inner list.
fn signature_base(
    msg: Message<'_>,
    components: &[Component],
    inner: &InnerList,
) -> Result<String, Error> {
    let mut base = String::new();
    for c in components {
        let value = component_value(msg, c)?;
        if value.contains('\n') || value.contains('\r') {
            return Err(err("component value contains a line break"));
        }
        base.push_str(&c.identifier()?);
        base.push_str(": ");
        base.push_str(&value);
        base.push('\n');
    }
    let params = vec![ListEntry::InnerList(inner.clone())]
        .serialize()
        .unwrap_or_default();
    base.push_str("\"@signature-params\": ");
    base.push_str(&params);
    Ok(base)
}

/// One signature read from `Signature-Input` and `Signature`.
#[derive(Debug, Clone)]
pub struct ParsedSignature {
    pub label: String,
    pub components: Vec<Component>,
    pub params: SignatureParams,
    pub signature: Vec<u8>,
    inner: InnerList,
}

impl ParsedSignature {
    /// `true` if the signature covers `component`.
    pub fn covers(&self, component: &Component) -> bool {
        self.components.contains(component)
    }

    /// The exact signature base this signature claims to cover.
    pub fn signature_base(&self, msg: Message<'_>) -> Result<String, Error> {
        signature_base(msg, &self.components, &self.inner)
    }
}

/// Parse every signature carried in `headers`. A `Signature-Input` member
/// without a matching `Signature` member, or a repeated component, is an
/// error.
pub fn parse_signatures(headers: &[(String, String)]) -> Result<Vec<ParsedSignature>, Error> {
    let inputs = parse_dictionary_field(headers, "signature-input")?;
    let sigs = parse_dictionary_field(headers, "signature")?;
    let mut out = Vec::with_capacity(inputs.len());
    for (label, entry) in &inputs {
        let ListEntry::InnerList(inner) = entry else {
            return Err(err(format!(
                "Signature-Input '{}' is not an Inner List",
                label
            )));
        };
        let signature = match sigs.get(label.as_str()) {
            Some(ListEntry::Item(item)) => item
                .bare_item
                .as_byte_sequence()
                .ok_or_else(|| err(format!("Signature '{}' is not a Byte Sequence", label)))?
                .to_vec(),
            _ => return Err(err(format!("no Signature for label '{}'", label))),
        };
        let mut components = Vec::with_capacity(inner.items.len());
        for item in &inner.items {
            let c = Component::from_item(item)?;
            if components.contains(&c) {
                return Err(err(format!("component '{}' is covered twice", c.name)));
            }
            components.push(c);
        }
        out.push(ParsedSignature {
            label: label.as_str().to_string(),
            components,
            params: read_params(&inner.params)?,
            signature,
            inner: inner.clone(),
        });
    }
    Ok(out)
}

/// `Signature-Input` and `Signature` member strings for one signature,
/// e.g. `sig1=("@authority");created=1` and `sig1=:...:`. Each is a valid
/// field value on its own, and can be appended as an extra field line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureFields {
    pub signature_input: String,
    pub signature: String,
}

/// `alg` value for Ed25519.
pub const ALG_ED25519: &str = "ed25519";
/// `alg` value for RSASSA-PSS with SHA-512.
pub const ALG_RSA_PSS_SHA512: &str = "rsa-pss-sha512";

/// A public key that verifies HTTP message signatures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKey {
    Ed25519(VerifyingKey),
    /// RSA modulus and exponent, big-endian without leading zeros.
    RsaPss {
        n: Vec<u8>,
        e: Vec<u8>,
    },
}

impl PublicKey {
    /// The RFC 9421 `alg` this key signs with.
    pub fn alg(&self) -> &'static str {
        match self {
            PublicKey::Ed25519(_) => ALG_ED25519,
            PublicKey::RsaPss { .. } => ALG_RSA_PSS_SHA512,
        }
    }

    /// Verify `sig` over `data`. Ed25519 uses strict verification (rejects
    /// non-canonical and small-order encodings); RSA keys must be 2048 to
    /// 8192 bits.
    pub fn verify(&self, data: &[u8], sig: &[u8]) -> Result<(), Error> {
        match self {
            PublicKey::Ed25519(k) => {
                let bytes: [u8; 64] = sig.try_into().map_err(|_| Error::SignatureInvalid)?;
                k.verify_strict(data, &Signature::from_bytes(&bytes))
                    .map_err(|_| Error::SignatureInvalid)
            }
            PublicKey::RsaPss { n, e } => RsaPublicKeyComponents { n, e }
                .verify(&rsig::RSA_PSS_2048_8192_SHA512, data, sig)
                .map_err(|_| Error::SignatureInvalid),
        }
    }
}

impl From<VerifyingKey> for PublicKey {
    fn from(k: VerifyingKey) -> Self {
        PublicKey::Ed25519(k)
    }
}

/// A private key that signs HTTP messages.
#[derive(Debug)]
pub enum PrivateKey {
    Ed25519(Box<SigningKey>),
    RsaPss(Box<RsaKeyPair>),
}

impl PrivateKey {
    /// Load a PEM key: PKCS#8 (`PRIVATE KEY`) Ed25519 or RSA, or PKCS#1
    /// (`RSA PRIVATE KEY`). RSA keys must be 2048 to 8192 bits.
    pub fn from_pem(pem: &str) -> Result<Self, Error> {
        use ed25519_dalek::pkcs8::{spki::der::pem, DecodePrivateKey};
        if let Ok(k) = SigningKey::from_pkcs8_pem(pem) {
            return Ok(PrivateKey::Ed25519(Box::new(k)));
        }
        let (label, der) =
            pem::decode_vec(pem.trim().as_bytes()).map_err(|_| Error::InvalidKeyFormat)?;
        let der = zeroize::Zeroizing::new(der);
        let der: &[u8] = &der;
        let kp = match label {
            "PRIVATE KEY" => RsaKeyPair::from_pkcs8(der),
            "RSA PRIVATE KEY" => RsaKeyPair::from_der(der),
            _ => return Err(Error::InvalidKeyFormat),
        }
        .map_err(|_| Error::InvalidKeyFormat)?;
        if !(256..=1024).contains(&kp.public().modulus_len()) {
            return Err(Error::InvalidKeyFormat);
        }
        Ok(PrivateKey::RsaPss(Box::new(kp)))
    }

    pub fn alg(&self) -> &'static str {
        self.public_key().alg()
    }

    pub fn public_key(&self) -> PublicKey {
        match self {
            PrivateKey::Ed25519(k) => PublicKey::Ed25519(k.verifying_key()),
            PrivateKey::RsaPss(kp) => {
                let c = RsaPublicKeyComponents::<Vec<u8>>::from(kp.public());
                PublicKey::RsaPss { n: c.n, e: c.e }
            }
        }
    }

    pub fn sign(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        match self {
            PrivateKey::Ed25519(k) => Ok(k.sign(data).to_bytes().to_vec()),
            PrivateKey::RsaPss(kp) => {
                let mut sig = vec![0u8; kp.public().modulus_len()];
                kp.sign(
                    &rsig::RSA_PSS_SHA512,
                    &ring::rand::SystemRandom::new(),
                    data,
                    &mut sig,
                )
                .map_err(|_| err("RSA signing failed"))?;
                Ok(sig)
            }
        }
    }
}

impl From<SigningKey> for PrivateKey {
    fn from(k: SigningKey) -> Self {
        PrivateKey::Ed25519(Box::new(k))
    }
}

/// Sign `msg` over `components` under `label`.
pub fn sign(
    msg: Message<'_>,
    label: &str,
    components: &[Component],
    params: &[Param],
    key: &PrivateKey,
) -> Result<SignatureFields, Error> {
    for (i, c) in components.iter().enumerate() {
        if components[..i].contains(c) {
            return Err(err(format!("component '{}' is covered twice", c.name)));
        }
    }
    let inner = build_inner_list(components, params)?;
    let base = signature_base(msg, components, &inner)?;
    let sig = key.sign(base.as_bytes())?;

    let label_key = key_of(label)?;
    let mut input = Dictionary::new();
    input.insert(label_key.clone(), ListEntry::InnerList(inner));
    let mut signature = Dictionary::new();
    signature.insert(
        label_key,
        ListEntry::Item(Item::new(BareItem::ByteSequence(sig))),
    );
    Ok(SignatureFields {
        signature_input: input.serialize().unwrap_or_default(),
        signature: signature.serialize().unwrap_or_default(),
    })
}

/// Verify `sig` over `msg`. A present `alg` parameter must match the key.
pub fn verify(msg: Message<'_>, sig: &ParsedSignature, key: &PublicKey) -> Result<(), Error> {
    if sig.params.alg.as_deref().is_some_and(|a| a != key.alg()) {
        return Err(Error::SignatureInvalid);
    }
    let base = sig.signature_base(msg)?;
    key.verify(base.as_bytes(), &sig.signature)
}

/// [`sign`] with an Ed25519 key.
pub fn sign_ed25519(
    msg: Message<'_>,
    label: &str,
    components: &[Component],
    params: &[Param],
    signing_key: &SigningKey,
) -> Result<SignatureFields, Error> {
    sign(msg, label, components, params, &signing_key.clone().into())
}

/// [`verify`] with an Ed25519 key.
pub fn verify_ed25519(
    msg: Message<'_>,
    sig: &ParsedSignature,
    verifying_key: &VerifyingKey,
) -> Result<(), Error> {
    verify(msg, sig, &PublicKey::Ed25519(*verifying_key))
}

/// `Content-Digest` value for `body` using SHA-256 (RFC 9530).
pub fn content_digest(body: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("sha-256=:{}:", BASE64.encode(Sha256::digest(body)))
}

/// `true` when the `Content-Digest` field in `headers` carries a `sha-256`
/// member matching `body`.
pub fn content_digest_matches(headers: &[(String, String)], body: &[u8]) -> bool {
    use sha2::{Digest, Sha256};
    let Ok(dict) = parse_dictionary_field(headers, "content-digest") else {
        return false;
    };
    match dict.get("sha-256") {
        Some(ListEntry::Item(item)) => {
            item.bare_item.as_byte_sequence() == Some(&Sha256::digest(body)[..])
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::pkcs8::DecodePrivateKey;

    /// RFC 9421 Appendix B.1.4 test key (test-key-ed25519).
    pub(crate) const RFC_ED25519_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n\
        -----END PRIVATE KEY-----\n";

    fn rfc_key() -> SigningKey {
        SigningKey::from_pkcs8_pem(RFC_ED25519_PEM).unwrap()
    }

    /// RFC 9421 Appendix B.2.6: Ed25519 over the RFC test request.
    #[test]
    fn rfc9421_b26_ed25519_vector() {
        let req = HttpRequest::new("POST", "https://example.com/foo?param=Value&Pet=dog")
            .unwrap()
            .header("Host", "example.com")
            .header("Date", "Tue, 20 Apr 2021 02:07:55 GMT")
            .header("Content-Type", "application/json")
            .header("Content-Length", "18");
        let components = [
            Component::new("date"),
            Component::new("@method"),
            Component::new("@path"),
            Component::new("@authority"),
            Component::new("content-type"),
            Component::new("content-length"),
        ];
        let params = [
            Param::Created(1618884473),
            Param::KeyId("test-key-ed25519".into()),
        ];
        let fields = sign_ed25519(
            Message::Request(&req),
            "sig-b26",
            &components,
            &params,
            &rfc_key(),
        )
        .unwrap();
        assert_eq!(
            fields.signature,
            "sig-b26=:wqcAqbmYJ2ji2glfAMaRy4gruYYnx2nEFN2HN6jrnDnQCK1u02Gb04v9EDgwUPiu4A0w6vuQv5lIp5WPpBKRCw==:"
        );
        assert_eq!(
            fields.signature_input,
            "sig-b26=(\"date\" \"@method\" \"@path\" \"@authority\" \"content-type\" \"content-length\");created=1618884473;keyid=\"test-key-ed25519\""
        );

        let signed = req
            .header("Signature-Input", &fields.signature_input)
            .header("Signature", &fields.signature);
        let parsed = parse_signatures(&signed.headers).unwrap();
        assert_eq!(parsed.len(), 1);
        verify_ed25519(
            Message::Request(&signed),
            &parsed[0],
            &rfc_key().verifying_key(),
        )
        .unwrap();
    }

    #[test]
    fn tampered_component_fails() {
        let req = HttpRequest::new("GET", "https://example.com/a").unwrap();
        let fields = sign_ed25519(
            Message::Request(&req),
            "s",
            &[Component::new("@authority"), Component::new("@path")],
            &[Param::Created(1)],
            &rfc_key(),
        )
        .unwrap();
        let mut moved = HttpRequest::new("GET", "https://example.com/b").unwrap();
        moved.headers = vec![
            ("Signature-Input".into(), fields.signature_input),
            ("Signature".into(), fields.signature),
        ];
        let parsed = parse_signatures(&moved.headers).unwrap();
        assert!(matches!(
            verify_ed25519(
                Message::Request(&moved),
                &parsed[0],
                &rfc_key().verifying_key()
            ),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn derived_components() {
        let req = HttpRequest::new("GET", "https://Example.COM:8443/p/q?x=1").unwrap();
        let m = Message::Request(&req);
        let v = |n: &str| component_value(m, &Component::new(n)).unwrap();
        assert_eq!(v("@authority"), "example.com:8443");
        assert_eq!(v("@scheme"), "https");
        assert_eq!(v("@path"), "/p/q");
        assert_eq!(v("@query"), "?x=1");
        assert_eq!(v("@request-target"), "/p/q?x=1");
        let plain = HttpRequest::new("GET", "https://example.com").unwrap();
        let v = |n: &str| component_value(Message::Request(&plain), &Component::new(n)).unwrap();
        assert_eq!(v("@authority"), "example.com");
        assert_eq!(v("@path"), "/");
        assert_eq!(v("@query"), "?");
        assert!(component_value(Message::Request(&plain), &Component::new("@status")).is_err());
    }

    #[test]
    fn combined_fields_and_dictionary_members() {
        let req = HttpRequest::new("GET", "https://example.com")
            .unwrap()
            .header("X-A", " one ")
            .header("x-a", "two")
            .header("Sig-Agent", "a=\"https://a.test\", b=\"https://b.test\"");
        let m = Message::Request(&req);
        assert_eq!(
            component_value(m, &Component::new("x-a")).unwrap(),
            "one, two"
        );
        assert_eq!(
            component_value(m, &Component::keyed("sig-agent", "b")).unwrap(),
            "\"https://b.test\""
        );
        assert!(component_value(m, &Component::keyed("sig-agent", "c")).is_err());
        assert!(component_value(m, &Component::new("missing")).is_err());
    }

    #[test]
    fn rejects_bad_identifiers() {
        for input in [
            "s=(\"Date\");created=1",
            "s=(\"date\";sf);created=1",
            "s=(\"@signature-params\");created=1",
            "s=(\"date\" \"date\");created=1",
            "s=(\"@method\";key=\"x\");created=1",
        ] {
            let h = vec![
                ("Signature-Input".to_string(), input.to_string()),
                ("Signature".to_string(), "s=:AAAA:".to_string()),
            ];
            assert!(parse_signatures(&h).is_err(), "{}", input);
        }
        let missing_sig = vec![(
            "Signature-Input".to_string(),
            "s=(\"date\");created=1".to_string(),
        )];
        assert!(parse_signatures(&missing_sig).is_err());
    }

    #[test]
    fn content_digest_roundtrip() {
        let body = b"{\"hello\": \"world\"}\n";
        // RFC 9530 Appendix B.1 example value.
        assert_eq!(
            content_digest(body),
            "sha-256=:RK/0qy18MlBSVnWgjwz6lZEWjP/lF5HF9bvEF8FabDg=:"
        );
        let h = vec![("Content-Digest".to_string(), content_digest(body))];
        assert!(content_digest_matches(&h, body));
        assert!(!content_digest_matches(&h, b"other"));
        assert!(!content_digest_matches(&[], body));
    }

    /// RFC 9421 §2.2.8 examples.
    #[test]
    fn query_param_values() {
        let req = HttpRequest::new(
            "GET",
            "https://www.example.com/parameters?var=this%20is%20a%20big%0Amultiline%20value&bar=with+plus+whitespace&fa%C3%A7ade%22%3A%20=something&dup=1&dup=2&qux=",
        )
        .unwrap();
        let m = Message::Request(&req);
        let v = |n: &str| component_value(m, &Component::query_param(n));
        assert_eq!(v("var").unwrap(), "this%20is%20a%20big%0Amultiline%20value");
        assert_eq!(v("bar").unwrap(), "with%20plus%20whitespace");
        assert_eq!(v("façade\": ").unwrap(), "something");
        assert_eq!(v("qux").unwrap(), "");
        assert!(v("dup").is_err());
        assert!(v("missing").is_err());
        assert_eq!(
            Component::query_param("façade\": ").identifier().unwrap(),
            "\"@query-param\";name=\"fa%C3%A7ade%22%3A%20\""
        );

        // Round trip through Signature-Input.
        let fields = sign_ed25519(
            m,
            "s",
            &[Component::query_param("var"), Component::new("@authority")],
            &[Param::Created(1)],
            &rfc_key(),
        )
        .unwrap();
        let signed = req
            .clone()
            .header("Signature-Input", &fields.signature_input)
            .header("Signature", &fields.signature);
        let parsed = parse_signatures(&signed.headers).unwrap();
        assert!(parsed[0].covers(&Component::query_param("var")));
        verify_ed25519(
            Message::Request(&signed),
            &parsed[0],
            &rfc_key().verifying_key(),
        )
        .unwrap();

        for bad in [
            "s=(\"@query-param\");created=1",
            "s=(\"@method\";name=\"x\");created=1",
        ] {
            let h = vec![
                ("Signature-Input".to_string(), bad.to_string()),
                ("Signature".to_string(), "s=:AAAA:".to_string()),
            ];
            assert!(parse_signatures(&h).is_err(), "{}", bad);
        }
    }

    #[test]
    fn alg_parameter_must_match_key() {
        let req = HttpRequest::new("GET", "https://example.com/").unwrap();
        let fields = sign_ed25519(
            Message::Request(&req),
            "s",
            &[Component::new("@authority")],
            &[Param::Alg(ALG_RSA_PSS_SHA512.into())],
            &rfc_key(),
        )
        .unwrap();
        let signed = req
            .header("Signature-Input", &fields.signature_input)
            .header("Signature", &fields.signature);
        let parsed = parse_signatures(&signed.headers).unwrap();
        assert!(verify_ed25519(
            Message::Request(&signed),
            &parsed[0],
            &rfc_key().verifying_key()
        )
        .is_err());
    }
}
