//! Web Bot Auth (WBA) profile of RFC 9421 HTTP Message Signatures.
//!
//! Implements draft-ietf-webbotauth-httpsig-protocol: agents sign requests
//! with Ed25519 or RSASSA-PSS, name the HTTPS key directory that publishes the key in the
//! `Signature-Agent` field, and verifiers resolve that directory and check
//! the signature. This module also binds a WBA signature to an AgentPin
//! identity (spec §18): the ES256 credential confirms the WBA key with
//! `cnf.jkt`, and the issuer's discovery document vouches for the
//! `Signature-Agent` URL.
//!
//! WBA uses its own keys. The ES256 credential profile is
//! unchanged, and credential keys are never used to sign HTTP messages.

use std::collections::HashMap;

use base64::{
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD as BASE64URL},
    Engine,
};
use chrono::Utc;
use ed25519_dalek::pkcs8::{spki::der::pem::LineEnding, EncodePrivateKey};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sfv::{FieldType, Item, ListEntry, Parser};
use url::Url;
use zeroize::Zeroizing;

use crate::domain::normalize_domain;
use crate::error::Error;
use crate::httpsig::{self, Component, HttpRequest, HttpResponse, Message, Param, ParsedSignature};
pub use crate::httpsig::{PrivateKey, PublicKey, ALG_ED25519, ALG_RSA_PSS_SHA512};
use crate::nonce::NonceStore;
use crate::pinning::KeyPinStore;
use crate::resolver::DiscoveryResolver;
use crate::types::discovery::DiscoveryDocument;
use crate::verification::{verify_credential_with_resolver, VerificationResult, VerifierConfig};

/// `tag` value of a Web Bot Auth request signature.
pub const TAG: &str = "web-bot-auth";
/// `tag` value of a directory response signature.
pub const DIRECTORY_TAG: &str = "http-message-signatures-directory";
/// Well-known path of a key directory.
pub const DIRECTORY_PATH: &str = "/.well-known/http-message-signatures-directory";
/// Media type a well-known key directory is served with.
pub const DIRECTORY_MEDIA_TYPE: &str = "application/http-message-signatures-directory+json";
/// Most keys accepted from one directory.
pub const MAX_DIRECTORY_KEYS: usize = 64;
/// Longest accepted `expires - created` window (24 hours, the draft's
/// recommended ceiling).
pub const MAX_VALIDITY_SECS: i64 = 86_400;

fn wba_err(msg: impl Into<String>) -> Error {
    Error::HttpSignature(msg.into())
}

// ---------------------------------------------------------------------------
// Keys and JWKs
// ---------------------------------------------------------------------------

/// Generate a new Ed25519 signing key from OS randomness.
pub fn generate_signing_key() -> SigningKey {
    SigningKey::generate(&mut rand_core::OsRng)
}

/// Load a signing key from PEM: Ed25519 or RSA (PKCS#8 or PKCS#1).
pub fn load_signing_key(pem: &str) -> Result<PrivateKey, Error> {
    PrivateKey::from_pem(pem)
}

/// Encode an Ed25519 signing key as a PKCS#8 PEM.
pub fn signing_key_to_pem(key: &SigningKey) -> Result<Zeroizing<String>, Error> {
    key.to_pkcs8_pem(LineEnding::LF)
        .map_err(|e| Error::Pkcs8(e.to_string()))
}

/// JWK SHA-256 thumbprint, base64url without padding: RFC 8037 for
/// Ed25519, RFC 7638 for RSA. This is the WBA `keyid`.
pub fn thumbprint(key: &PublicKey) -> String {
    use sha2::{Digest, Sha256};
    let canonical = match key {
        PublicKey::Ed25519(k) => format!(
            r#"{{"crv":"Ed25519","kty":"OKP","x":"{}"}}"#,
            BASE64URL.encode(k.as_bytes())
        ),
        PublicKey::RsaPss { n, e } => format!(
            r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
            BASE64URL.encode(e),
            BASE64URL.encode(n)
        ),
    };
    BASE64URL.encode(Sha256::digest(canonical.as_bytes()))
}

/// A directory public key as a JWK: OKP/Ed25519 (RFC 8037) or RSA
/// (RFC 7517).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    /// Not valid before (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Not valid after (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
}

impl Jwk {
    /// JWK for `key`, with `kid` set to its thumbprint.
    pub fn from_public_key(key: &PublicKey) -> Self {
        let mut jwk = Self {
            kty: String::new(),
            crv: None,
            kid: Some(thumbprint(key)),
            x: None,
            n: None,
            e: None,
            use_: Some("sig".to_string()),
            alg: None,
            nbf: None,
            exp: None,
        };
        match key {
            PublicKey::Ed25519(k) => {
                jwk.kty = "OKP".to_string();
                jwk.crv = Some("Ed25519".to_string());
                jwk.x = Some(BASE64URL.encode(k.as_bytes()));
            }
            PublicKey::RsaPss { n, e } => {
                jwk.kty = "RSA".to_string();
                jwk.n = Some(BASE64URL.encode(n));
                jwk.e = Some(BASE64URL.encode(e));
            }
        }
        jwk
    }

    /// Decode the public key. Accepts Ed25519 OKP keys and RSA keys of
    /// 2048 to 8192 bits; rejects everything else and malformed values.
    pub fn public_key(&self) -> Result<PublicKey, Error> {
        let b64 = |v: &Option<String>| {
            v.as_deref()
                .and_then(|s| BASE64URL.decode(s).ok())
                .ok_or(Error::InvalidKeyFormat)
        };
        match (self.kty.as_str(), self.crv.as_deref()) {
            ("OKP", Some("Ed25519")) => {
                let bytes: [u8; 32] = b64(&self.x)?
                    .try_into()
                    .map_err(|_| Error::InvalidKeyFormat)?;
                VerifyingKey::from_bytes(&bytes)
                    .map(PublicKey::Ed25519)
                    .map_err(|_| Error::InvalidKeyFormat)
            }
            ("RSA", _) => {
                let (n, e) = (b64(&self.n)?, b64(&self.e)?);
                // Minimal encodings only (RFC 7518 §6.3.1), so the
                // thumbprint is well defined.
                let minimal = |v: &[u8]| v.first().is_some_and(|b| *b != 0);
                let bits = n.len() * 8 - n.first().map_or(8, |b| b.leading_zeros() as usize);
                if !minimal(&n) || !minimal(&e) || e.len() > 4 || !(2048..=8192).contains(&bits) {
                    return Err(Error::InvalidKeyFormat);
                }
                Ok(PublicKey::RsaPss { n, e })
            }
            _ => Err(Error::InvalidKeyFormat),
        }
    }

    /// Thumbprint computed from the key material (never taken from `kid`).
    /// `None` for keys [`Jwk::public_key`] rejects.
    pub fn thumbprint(&self) -> Option<String> {
        self.public_key().ok().map(|k| thumbprint(&k))
    }

    fn usable_at(&self, now: i64, skew: i64) -> bool {
        self.nbf.is_none_or(|nbf| now + skew >= nbf) && self.exp.is_none_or(|exp| now - skew < exp)
    }
}

/// A key directory: a JWK Set of signing keys.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Directory {
    pub keys: Vec<Jwk>,
}

impl Directory {
    /// Directory publishing the given keys.
    pub fn from_keys<'a>(keys: impl IntoIterator<Item = &'a PublicKey>) -> Self {
        Self {
            keys: keys.into_iter().map(Jwk::from_public_key).collect(),
        }
    }

    /// Parse a JWK Set. Entries that are not well-formed Ed25519 or RSA
    /// keys (EC, short RSA, bad values) are skipped; more than [`MAX_DIRECTORY_KEYS`]
    /// entries is an error.
    pub fn parse(json: &[u8]) -> Result<Self, Error> {
        #[derive(Deserialize)]
        struct RawSet {
            keys: Vec<serde_json::Value>,
        }
        let raw: RawSet =
            serde_json::from_slice(json).map_err(|_| wba_err("key directory is not a JWK Set"))?;
        if raw.keys.len() > MAX_DIRECTORY_KEYS {
            return Err(wba_err("key directory has too many keys"));
        }
        let keys = raw
            .keys
            .into_iter()
            .filter_map(|v| serde_json::from_value::<Jwk>(v).ok())
            .filter(|k| k.public_key().is_ok())
            .collect();
        Ok(Self { keys })
    }

    /// Compact JSON body, as served.
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        Ok(serde_json::to_vec(self)?)
    }
}

// ---------------------------------------------------------------------------
// Signature-Agent
// ---------------------------------------------------------------------------

/// The well-known directory URL for `domain`.
pub fn well_known_directory(domain: &str) -> String {
    format!("https://{}{}", domain, DIRECTORY_PATH)
}

/// Normalize a Signature-Agent URL into the identifier form the draft
/// compares (§5.5): absolute `https` URL with a host, query and fragment
/// dropped, scheme/host case and default port normalized.
pub fn normalize_signature_agent(url: &str) -> Result<String, Error> {
    let mut u = Url::parse(url).map_err(|_| wba_err("Signature-Agent is not an absolute URL"))?;
    if u.scheme() != "https" || u.host_str().is_none() {
        return Err(wba_err("Signature-Agent must be an https URL with a host"));
    }
    if !u.username().is_empty() || u.password().is_some() {
        return Err(wba_err("Signature-Agent must not carry credentials"));
    }
    u.set_query(None);
    u.set_fragment(None);
    Ok(u.to_string())
}

/// Resolve the Signature-Agent member keyed `label`. `legacy` is set
/// when the signature covers the bare `"signature-agent"` component, which
/// is only valid for the old sf-string form of the field.
fn signature_agent_member(
    headers: &[(String, String)],
    label: &str,
    legacy: bool,
) -> Result<String, String> {
    let raw = httpsig::combined_field(headers, "signature-agent")
        .ok_or("request has no Signature-Agent field")?;
    let item: Item = if legacy {
        if !raw.starts_with('"') {
            return Err("Signature-Agent is a Dictionary; cover it with ;key".into());
        }
        Parser::new(&raw)
            .parse::<Item>()
            .map_err(|_| "Signature-Agent is not a valid String")?
    } else {
        let dict = httpsig::parse_dictionary_field(headers, "signature-agent")
            .map_err(|e| e.to_string())?;
        match dict.get(label) {
            Some(ListEntry::Item(item)) => item.clone(),
            Some(_) => return Err("Signature-Agent member is not an Item".into()),
            None => return Err(format!("Signature-Agent has no member '{}'", label)),
        }
    };
    if !item.params.is_empty() {
        return Err("Signature-Agent member carries parameters".into());
    }
    let url = item
        .bare_item
        .as_string()
        .ok_or("Signature-Agent member is not a String")?
        .as_str();
    normalize_signature_agent(url).map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Signing requests
// ---------------------------------------------------------------------------

/// Options for [`sign_request`].
#[derive(Debug, Clone)]
pub struct SignOptions {
    /// Signature label; also the Signature-Agent member key.
    pub label: String,
    /// `expires - created`, in seconds (1 to [`MAX_VALIDITY_SECS`]).
    pub validity_secs: i64,
    /// Components covered in addition to `@authority` and the
    /// Signature-Agent member. Defaults to `@method` and `@path`, which
    /// narrow a captured signature to one method and resource (§5.2).
    /// Add `authorization` to bind an AgentPin credential.
    pub components: Vec<Component>,
    /// Add a random 64-byte `nonce` parameter.
    pub nonce: bool,
    /// `created` timestamp; `None` uses the current time.
    pub created: Option<i64>,
    /// Send `Signature-Agent` in the legacy bare-String form and cover the
    /// bare `"signature-agent"` component (draft Appendix E.1.2). Only for
    /// verifiers that predate the Dictionary form; the draft requires
    /// signers to send the Dictionary form.
    pub legacy_signature_agent: bool,
}

impl Default for SignOptions {
    fn default() -> Self {
        Self {
            label: "sig1".to_string(),
            validity_secs: 300,
            components: vec![Component::new("@method"), Component::new("@path")],
            nonce: true,
            created: None,
            legacy_signature_agent: false,
        }
    }
}

/// Header fields that carry one WBA signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedHeaders {
    pub signature_agent: String,
    pub signature_input: String,
    pub signature: String,
}

impl SignedHeaders {
    /// `(name, value)` pairs to append to the request.
    pub fn to_vec(&self) -> Vec<(String, String)> {
        vec![
            ("Signature-Agent".to_string(), self.signature_agent.clone()),
            ("Signature-Input".to_string(), self.signature_input.clone()),
            ("Signature".to_string(), self.signature.clone()),
        ]
    }

    /// Append the three fields to `req`.
    pub fn apply(&self, req: &mut HttpRequest) {
        req.headers.extend(self.to_vec());
    }
}

/// Sign `req` as a Web Bot Auth agent whose key directory is
/// `signature_agent` (an https URL). Returns the fields to append; the
/// request itself is not modified. Any header named in
/// `opts.components` must already be on `req`.
pub fn sign_request(
    req: &HttpRequest,
    signing_key: &PrivateKey,
    signature_agent: &str,
    opts: &SignOptions,
) -> Result<SignedHeaders, Error> {
    let agent_url = Url::parse(signature_agent)
        .ok()
        .filter(|u| u.scheme() == "https" && u.host_str().is_some())
        .ok_or_else(|| wba_err("signature_agent must be an https URL with a host"))?;
    if !(1..=MAX_VALIDITY_SECS).contains(&opts.validity_secs) {
        return Err(wba_err("validity_secs must be between 1 and 86400"));
    }
    let (signature_agent_field, agent_component) = if opts.legacy_signature_agent {
        if httpsig::combined_field(&req.headers, "signature-agent").is_some() {
            return Err(wba_err(
                "legacy Signature-Agent cannot be combined with an existing one",
            ));
        }
        let item = Item::new(sfv::BareItem::String(
            sfv::String::from_string(agent_url.to_string())
                .map_err(|_| wba_err("invalid Signature-Agent URL"))?,
        ));
        (item.serialize(), Component::new("signature-agent"))
    } else {
        let existing = httpsig::parse_dictionary_field(&req.headers, "signature-agent")?;
        if existing.contains_key(opts.label.as_str()) {
            return Err(wba_err(format!(
                "Signature-Agent already has a member '{}'",
                opts.label
            )));
        }
        let mut member = sfv::Dictionary::new();
        member.insert(
            sfv::Key::from_string(opts.label.clone()).map_err(|_| wba_err("invalid label"))?,
            ListEntry::Item(Item::new(sfv::BareItem::String(
                sfv::String::from_string(agent_url.to_string())
                    .map_err(|_| wba_err("invalid Signature-Agent URL"))?,
            ))),
        );
        (
            member.serialize().unwrap_or_default(),
            Component::keyed("signature-agent", &opts.label),
        )
    };
    let mut to_sign = req.clone();
    to_sign
        .headers
        .push(("Signature-Agent".to_string(), signature_agent_field.clone()));

    let mut components = vec![Component::new("@authority"), agent_component];
    for c in &opts.components {
        if !components.contains(c) {
            components.push(c.clone());
        }
    }

    let created = opts.created.unwrap_or_else(|| Utc::now().timestamp());
    let mut params = vec![
        Param::Created(created),
        Param::KeyId(thumbprint(&signing_key.public_key())),
        Param::Alg(signing_key.alg().to_string()),
        Param::Expires(created + opts.validity_secs),
    ];
    if opts.nonce {
        // 64 bytes, as in the draft's vectors; Cloudflare's verifier
        // rejects other lengths.
        let mut bytes = [0u8; 64];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut bytes);
        params.push(Param::Nonce(BASE64.encode(bytes)));
    }
    params.push(Param::Tag(TAG.to_string()));

    let fields = httpsig::sign(
        Message::Request(&to_sign),
        &opts.label,
        &components,
        &params,
        signing_key,
    )?;
    Ok(SignedHeaders {
        signature_agent: signature_agent_field,
        signature_input: fields.signature_input,
        signature: fields.signature,
    })
}

// ---------------------------------------------------------------------------
// Verifying requests
// ---------------------------------------------------------------------------

/// Options for [`verify_request`].
#[derive(Clone)]
pub struct VerifyOptions {
    /// Verification time; `None` uses the current time.
    pub now: Option<i64>,
    /// Clock skew tolerance in seconds.
    pub clock_skew_secs: i64,
    /// Longest accepted `expires - created` window.
    pub max_validity_secs: i64,
    /// Accept the legacy bare-String `Signature-Agent` form (§5.2.1).
    pub accept_legacy_signature_agent: bool,
    /// Components every accepted signature must cover, in addition to the
    /// protocol's own requirements.
    pub required_components: Vec<Component>,
    /// Replay protection: when set, a verified signature's `nonce` is
    /// recorded per keyid until the signature expires, and a repeat is
    /// invalid. Signatures without a nonce are invalid too. Checked only
    /// after the signature verifies, so forged requests cannot fill it.
    pub nonce_store: Option<std::sync::Arc<dyn NonceStore>>,
}

impl std::fmt::Debug for VerifyOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifyOptions")
            .field("now", &self.now)
            .field("clock_skew_secs", &self.clock_skew_secs)
            .field("max_validity_secs", &self.max_validity_secs)
            .field(
                "accept_legacy_signature_agent",
                &self.accept_legacy_signature_agent,
            )
            .field("required_components", &self.required_components)
            .field("nonce_store", &self.nonce_store.is_some())
            .finish()
    }
}

impl Default for VerifyOptions {
    fn default() -> Self {
        Self {
            now: None,
            clock_skew_secs: 60,
            max_validity_secs: MAX_VALIDITY_SECS,
            accept_legacy_signature_agent: true,
            required_components: Vec::new(),
            nonce_store: None,
        }
    }
}

/// A request signature that verified against a key its Signature-Agent
/// directory provides.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAgent {
    pub label: String,
    /// Normalized Signature-Agent URL: the agent's identifier.
    pub signature_agent: String,
    /// JWK thumbprint of the signing key.
    pub keyid: String,
    pub created: i64,
    pub expires: i64,
    pub nonce: Option<String>,
    pub components: Vec<Component>,
}

impl VerifiedAgent {
    /// `true` if the signature covers `component`.
    pub fn covers(&self, component: &Component) -> bool {
        self.components.contains(component)
    }
}

/// The three verifier outcomes the draft distinguishes (Appendix C.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WbaOutcome {
    /// The signature and key material validate.
    Verified(Box<VerifiedAgent>),
    /// The signature, covered components, key or freshness checks fail.
    Invalid(String),
    /// Not enough information to decide: no WBA signature, discovery
    /// failed, or the resolved directory lacks the key.
    Unverified(String),
}

/// Key lookup keyed on the `(Signature-Agent URL, keyid)` pair, never on
/// the keyid alone (§5.4).
pub trait KeyLookup {
    /// `Ok(Some)` when the directory at `signature_agent` provides
    /// `keyid`; `Ok(None)` when the directory resolved without it; `Err`
    /// when it could not be resolved.
    fn lookup(&self, signature_agent: &str, keyid: &str) -> Result<Option<PublicKey>, Error>;
}

/// In-memory key store built from directories the verifier resolved
/// itself.
#[derive(Debug, Clone)]
pub struct DirectoryKeyStore {
    directories: HashMap<String, Directory>,
    clock_skew_secs: i64,
}

impl Default for DirectoryKeyStore {
    fn default() -> Self {
        Self::new()
    }
}

impl DirectoryKeyStore {
    pub fn new() -> Self {
        Self {
            directories: HashMap::new(),
            clock_skew_secs: 60,
        }
    }

    /// Record (or replace) the directory resolved from `signature_agent`.
    pub fn insert(&mut self, signature_agent: &str, directory: Directory) -> Result<(), Error> {
        self.directories
            .insert(normalize_signature_agent(signature_agent)?, directory);
        Ok(())
    }
}

/// Find `keyid` in `directory` by computed thumbprint, honoring `nbf`/`exp`.
pub fn find_key(directory: &Directory, keyid: &str, now: i64, skew: i64) -> Option<PublicKey> {
    directory
        .keys
        .iter()
        .filter(|k| k.usable_at(now, skew))
        .filter_map(|k| k.public_key().ok())
        .find(|k| thumbprint(k) == keyid)
}

impl KeyLookup for DirectoryKeyStore {
    fn lookup(&self, signature_agent: &str, keyid: &str) -> Result<Option<PublicKey>, Error> {
        let dir = self
            .directories
            .get(signature_agent)
            .ok_or_else(|| wba_err("directory not resolved"))?;
        Ok(find_key(
            dir,
            keyid,
            Utc::now().timestamp(),
            self.clock_skew_secs,
        ))
    }
}

/// A WBA signature that passed every check except the cryptographic one,
/// with the Signature-Agent URL it names.
pub(crate) struct Candidate {
    sig: ParsedSignature,
    signature_agent: String,
    keyid: String,
}

impl Candidate {
    pub(crate) fn signature_agent(&self) -> &str {
        &self.signature_agent
    }

    pub(crate) fn keyid(&self) -> &str {
        &self.keyid
    }
}

/// Protocol checks on one signature (§5.2, §5.2.1). `Err` is the reason
/// it is invalid.
fn check_signature(
    req: &HttpRequest,
    sig: ParsedSignature,
    opts: &VerifyOptions,
    now: i64,
) -> Result<Candidate, String> {
    let p = &sig.params;
    let created = p.created.ok_or("signature has no created parameter")?;
    let expires = p.expires.ok_or("signature has no expires parameter")?;
    let keyid = p.keyid.clone().ok_or("signature has no keyid parameter")?;
    if let Some(ref alg) = p.alg {
        if alg != ALG_ED25519 && alg != ALG_RSA_PSS_SHA512 {
            return Err(format!("unsupported alg '{}'", alg));
        }
    }
    if created > now + opts.clock_skew_secs {
        return Err("signature created in the future".into());
    }
    if expires <= created {
        return Err("expires is not after created".into());
    }
    if now - opts.clock_skew_secs > expires {
        return Err("signature expired".into());
    }
    if expires - created > opts.max_validity_secs {
        return Err("signature validity window too long".into());
    }
    if !sig.covers(&Component::new("@authority")) && !sig.covers(&Component::new("@target-uri")) {
        return Err("signature covers neither @authority nor @target-uri".into());
    }
    for c in &opts.required_components {
        if !sig.covers(c) {
            return Err(format!("signature does not cover required '{}'", c.name));
        }
    }
    // The covered member, not the signature label, names the agent: labels
    // may be rewritten by intermediaries, member keys may not (§6.6.1).
    let members: Vec<&str> = sig
        .components
        .iter()
        .filter(|c| c.name == "signature-agent" && !c.req)
        .filter_map(|c| c.key.as_deref())
        .collect();
    let signature_agent = match members.as_slice() {
        [member] => signature_agent_member(&req.headers, member, false)?,
        [] if opts.accept_legacy_signature_agent
            && sig.covers(&Component::new("signature-agent")) =>
        {
            signature_agent_member(&req.headers, &sig.label, true)?
        }
        [] => return Err("signature does not cover a Signature-Agent member".into()),
        _ => return Err("signature covers more than one Signature-Agent member".into()),
    };
    Ok(Candidate {
        sig,
        signature_agent,
        keyid,
    })
}

/// Parse and check every WBA-tagged signature. Returns candidates and the
/// reason for the last invalid one.
pub(crate) fn candidates(
    req: &HttpRequest,
    opts: &VerifyOptions,
    now: i64,
) -> Result<(Vec<Candidate>, Option<String>), WbaOutcome> {
    let sigs =
        httpsig::parse_signatures(&req.headers).map_err(|e| WbaOutcome::Invalid(e.to_string()))?;
    let mut out = Vec::new();
    let mut invalid = None;
    let mut seen = false;
    for sig in sigs
        .into_iter()
        .filter(|s| s.params.tag.as_deref() == Some(TAG))
    {
        seen = true;
        match check_signature(req, sig, opts, now) {
            Ok(c) => out.push(c),
            Err(reason) => invalid = Some(reason),
        }
    }
    if !seen {
        return Err(WbaOutcome::Unverified(
            "request carries no Web Bot Auth signature".into(),
        ));
    }
    Ok((out, invalid))
}

pub(crate) fn finish(
    req: &HttpRequest,
    c: Candidate,
    key: Result<Option<PublicKey>, Error>,
    opts: &VerifyOptions,
    now: i64,
) -> WbaOutcome {
    match key {
        Err(e) => WbaOutcome::Unverified(format!(
            "key directory {} unavailable: {}",
            c.signature_agent, e
        )),
        Ok(None) => WbaOutcome::Unverified(format!(
            "key directory {} does not provide keyid {}",
            c.signature_agent, c.keyid
        )),
        Ok(Some(key)) => match httpsig::verify(Message::Request(req), &c.sig, &key) {
            Ok(()) => {
                if let Err(reason) = check_nonce(&c, opts, now) {
                    return WbaOutcome::Invalid(reason);
                }
                WbaOutcome::Verified(Box::new(VerifiedAgent {
                    label: c.sig.label,
                    signature_agent: c.signature_agent,
                    keyid: c.keyid,
                    created: c.sig.params.created.unwrap_or_default(),
                    expires: c.sig.params.expires.unwrap_or_default(),
                    nonce: c.sig.params.nonce,
                    components: c.sig.components,
                }))
            }
            Err(_) => WbaOutcome::Invalid("signature verification failed".into()),
        },
    }
}

/// Record the nonce of a verified signature in `opts.nonce_store`.
fn check_nonce(c: &Candidate, opts: &VerifyOptions, now: i64) -> Result<(), String> {
    let Some(store) = &opts.nonce_store else {
        return Ok(());
    };
    let nonce = c
        .sig
        .params
        .nonce
        .as_deref()
        .ok_or("signature has no nonce and replay protection is on")?;
    // Keep the nonce until the signature can no longer pass the expiry check.
    let expires = c.sig.params.expires.unwrap_or(now);
    let ttl = (expires + opts.clock_skew_secs - now).max(1) as u64;
    let fresh = store
        .check_and_record(
            &format!("{} {}", c.keyid, nonce),
            std::time::Duration::from_secs(ttl),
        )
        .map_err(|e| format!("nonce store failed: {}", e))?;
    if fresh {
        Ok(())
    } else {
        Err("nonce replayed".into())
    }
}

/// Keep the more decisive of two failures: invalid beats unverified.
pub(crate) fn worse(current: Option<WbaOutcome>, next: WbaOutcome) -> Option<WbaOutcome> {
    match (&current, &next) {
        (Some(WbaOutcome::Invalid(_)), _) => current,
        _ => Some(next),
    }
}

/// Verify the Web Bot Auth signatures on `req`. Returns the first
/// signature that verifies; otherwise `Invalid` if any signature failed a
/// check, else `Unverified`. Set [`VerifyOptions::nonce_store`] to reject
/// replays (§5.2.3).
pub fn verify_request(req: &HttpRequest, keys: &dyn KeyLookup, opts: &VerifyOptions) -> WbaOutcome {
    let now = opts.now.unwrap_or_else(|| Utc::now().timestamp());
    let (candidates, invalid) = match candidates(req, opts, now) {
        Ok(v) => v,
        Err(outcome) => return outcome,
    };
    let mut result = invalid.map(WbaOutcome::Invalid);
    for c in candidates {
        let key = keys.lookup(c.signature_agent(), c.keyid());
        match finish(req, c, key, opts, now) {
            v @ WbaOutcome::Verified(_) => return v,
            failure => result = worse(result, failure),
        }
    }
    result.unwrap_or_else(|| WbaOutcome::Unverified("no usable signature".into()))
}

// ---------------------------------------------------------------------------
// Directory responses
// ---------------------------------------------------------------------------

/// Response fields for a signed key directory (Appendix B.1):
/// `Content-Digest` plus one `Signature-Input`/`Signature` per key, each
/// covering `"@authority";req` and `content-digest`. `authority` is the
/// host (and non-default port) the directory was requested on.
pub fn sign_directory_response(
    body: &[u8],
    authority: &str,
    keys: &[PrivateKey],
    created: i64,
    validity_secs: i64,
) -> Result<Vec<(String, String)>, Error> {
    if !(1..=MAX_VALIDITY_SECS).contains(&validity_secs) {
        return Err(wba_err("validity_secs must be between 1 and 86400"));
    }
    let request = HttpRequest::new("GET", &format!("https://{}{}", authority, DIRECTORY_PATH))?;
    let digest = httpsig::content_digest(body);
    let response = HttpResponse {
        status: 200,
        headers: vec![("Content-Digest".to_string(), digest.clone())],
    };
    let msg = Message::Response {
        response: &response,
        request: Some(&request),
    };
    let components = [
        Component::of_request("@authority"),
        Component::new("content-digest"),
    ];
    let mut out = vec![("Content-Digest".to_string(), digest)];
    for (i, key) in keys.iter().enumerate() {
        let params = [
            Param::Created(created),
            Param::Expires(created + validity_secs),
            Param::KeyId(thumbprint(&key.public_key())),
            Param::Tag(DIRECTORY_TAG.to_string()),
        ];
        let f = httpsig::sign(msg, &format!("binding{}", i), &components, &params, key)?;
        out.push(("Signature-Input".to_string(), f.signature_input));
        out.push(("Signature".to_string(), f.signature));
    }
    Ok(out)
}

/// Check a directory response's possession proofs (Appendix B.1) and
/// return only the keys that carry a valid one. The `Content-Digest` must
/// match `body`; a proof must use the key it names, cover
/// `"@authority";req` and `content-digest`, and be neither future-dated nor
/// expired.
pub fn verify_directory_response(
    body: &[u8],
    response_headers: &[(String, String)],
    authority: &str,
    now: i64,
    clock_skew_secs: i64,
) -> Result<Directory, Error> {
    let directory = Directory::parse(body)?;
    if !httpsig::content_digest_matches(response_headers, body) {
        return Err(wba_err("directory Content-Digest does not match the body"));
    }
    let request = HttpRequest::new("GET", &format!("https://{}{}", authority, DIRECTORY_PATH))?;
    let response = HttpResponse {
        status: 200,
        headers: response_headers.to_vec(),
    };
    let msg = Message::Response {
        response: &response,
        request: Some(&request),
    };
    let sigs = httpsig::parse_signatures(response_headers)?;
    let proven = directory
        .keys
        .into_iter()
        .filter(|jwk| {
            let Ok(pk) = jwk.public_key() else {
                return false;
            };
            let tp = thumbprint(&pk);
            sigs.iter().any(|s| {
                let p = &s.params;
                p.tag.as_deref() == Some(DIRECTORY_TAG)
                    && p.keyid.as_deref() == Some(tp.as_str())
                    && p.created.is_some_and(|c| c <= now + clock_skew_secs)
                    && p.expires.is_some_and(|e| now - clock_skew_secs <= e)
                    && s.covers(&Component::of_request("@authority"))
                    && s.covers(&Component::new("content-digest"))
                    && httpsig::verify(msg, s, &pk).is_ok()
            })
        })
        .collect();
    Ok(Directory { keys: proven })
}

// ---------------------------------------------------------------------------
// AgentPin identity binding (spec §18)
// ---------------------------------------------------------------------------

/// The AgentPin credential JWT carried in the request's
/// `Authorization: AgentPin <jwt>` field.
pub fn request_credential(req: &HttpRequest) -> Result<String, Error> {
    let auth = httpsig::combined_field(&req.headers, "authorization")
        .ok_or_else(|| wba_err("request has no Authorization field"))?;
    crate::transport::http::extract_credential(&auth)
}

/// Check that a verified WBA signature and a verified AgentPin credential
/// describe the same agent:
///
/// 1. the credential verified, and the signature covers `authorization`,
///    so the credential is bound to this signed request;
/// 2. the credential's `cnf.jkt` equals the signature's `keyid`;
/// 3. `discovery` is the issuer's document, and it vouches for the
///    Signature-Agent URL: listed in `web_bot_auth.signature_agents`, or,
///    when that field is absent, the issuer's well-known directory.
pub fn check_binding(
    agent: &VerifiedAgent,
    req: &HttpRequest,
    credential: &VerificationResult,
    discovery: &DiscoveryDocument,
) -> Result<(), String> {
    if !credential.valid {
        return Err("AgentPin credential did not verify".into());
    }
    if !agent.covers(&Component::new("authorization")) {
        return Err("Web Bot Auth signature does not cover the Authorization field".into());
    }
    let jwt = request_credential(req).map_err(|e| e.to_string())?;
    let (_, payload, _) = crate::jwt::decode_jwt_unverified(&jwt).map_err(|e| e.to_string())?;
    let jkt = payload
        .cnf
        .as_ref()
        .map(|c| c.jkt.as_str())
        .ok_or("credential has no cnf.jkt key confirmation")?;
    if jkt != agent.keyid {
        return Err("credential cnf.jkt does not match the signature keyid".into());
    }
    let issuer = normalize_domain(&payload.iss).map_err(|e| e.to_string())?;
    let result_issuer = credential.issuer.as_deref().map(normalize_domain);
    if !matches!(result_issuer, Some(Ok(ref d)) if *d == issuer)
        || credential.agent_id.as_deref() != Some(payload.sub.as_str())
    {
        return Err("credential result does not belong to this request".into());
    }
    let entity = normalize_domain(&discovery.entity).map_err(|e| e.to_string())?;
    if issuer != entity {
        return Err("discovery document is not the credential issuer's".into());
    }
    let allowed = match &discovery.web_bot_auth {
        Some(wba) => wba
            .signature_agents
            .iter()
            .filter_map(|u| normalize_signature_agent(u).ok())
            .any(|u| u == agent.signature_agent),
        None => normalize_signature_agent(&well_known_directory(&entity))
            .is_ok_and(|u| u == agent.signature_agent),
    };
    if !allowed {
        return Err(format!(
            "{} does not vouch for Signature-Agent {}",
            entity, agent.signature_agent
        ));
    }
    Ok(())
}

/// A request whose WBA signature and AgentPin credential verified and are
/// bound to each other.
#[derive(Debug, Clone)]
pub struct BoundAgent {
    pub agent: VerifiedAgent,
    pub credential: VerificationResult,
}

/// Why [`verify_bound_request`] rejected a request.
#[derive(Debug, Clone)]
pub enum BindingFailure {
    /// The WBA signature did not verify.
    Wba(WbaOutcome),
    /// The AgentPin credential did not verify.
    Credential(Box<VerificationResult>),
    /// Both verified but they are not bound to each other.
    Binding(String),
}

/// Verify a request's WBA signature, its AgentPin credential, and the
/// binding between them ([`check_binding`]).
pub fn verify_bound_request(
    req: &HttpRequest,
    keys: &dyn KeyLookup,
    resolver: &dyn DiscoveryResolver,
    pin_store: &mut KeyPinStore,
    audience: Option<&str>,
    wba_opts: &VerifyOptions,
    config: &VerifierConfig,
) -> Result<BoundAgent, BindingFailure> {
    let agent = match verify_request(req, keys, wba_opts) {
        WbaOutcome::Verified(a) => *a,
        other => return Err(BindingFailure::Wba(other)),
    };
    let jwt = request_credential(req).map_err(|e| BindingFailure::Binding(e.to_string()))?;
    let credential = verify_credential_with_resolver(&jwt, resolver, pin_store, audience, config);
    if !credential.valid {
        return Err(BindingFailure::Credential(Box::new(credential)));
    }
    let issuer = credential.issuer.clone().unwrap_or_default();
    let discovery = resolver
        .resolve_discovery(&issuer)
        .map_err(|e| BindingFailure::Binding(e.to_string()))?;
    check_binding(&agent, req, &credential, &discovery).map_err(BindingFailure::Binding)?;
    Ok(BoundAgent { agent, credential })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::httpsig::parse_signatures;

    const RFC_ED25519_PEM: &str = "-----BEGIN PRIVATE KEY-----\n\
        MC4CAQAwBQYDK2VwBCIEIJ+DYvh6SEqVTm50DFtMDoQikTmiCqirVv9mWG9qfSnF\n\
        -----END PRIVATE KEY-----\n";
    const RFC_KEYID: &str = "poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U";
    const RFC_X: &str = "JrQLj5P_89iXES9-vFgrIy29clF9CC_oPPsw3c5D0bs";
    const AGENT: &str = "https://signature-agent.test";

    fn rfc_key() -> PrivateKey {
        load_signing_key(RFC_ED25519_PEM).unwrap()
    }

    fn gen() -> PrivateKey {
        generate_signing_key().into()
    }

    #[test]
    fn thumbprint_matches_draft_vector() {
        let key = rfc_key().public_key();
        assert_eq!(thumbprint(&key), RFC_KEYID);
        let jwk = Jwk::from_public_key(&key);
        assert_eq!(jwk.x.as_deref(), Some(RFC_X));
        assert_eq!(jwk.kid.as_deref(), Some(RFC_KEYID));
        assert_eq!(jwk.public_key().unwrap(), key);
    }

    /// draft-ietf-webbotauth-httpsig-protocol Appendix E.2.1: our signer
    /// reproduces the vector byte for byte, and our verifier accepts it.
    #[test]
    fn draft_e21_dictionary_signature_agent() {
        let req = HttpRequest::new("GET", "https://example.com/")
            .unwrap()
            .header("Signature-Agent", "agent2=\"https://signature-agent.test\"");
        let components = [
            Component::new("@authority"),
            Component::keyed("signature-agent", "agent2"),
        ];
        let params = [
            Param::Created(1735689600),
            Param::KeyId(RFC_KEYID.into()),
            Param::Alg("ed25519".into()),
            Param::Expires(4889289600),
            Param::Nonce("n9p433xm+NJ3ph3upfBIGmsuwHw387YV7Q/F+6BSpGCVjYCqQw6rznNA8PVVLySrAWsv0hQtFioQb6E1YsauiA==".into()),
            Param::Tag(TAG.into()),
        ];
        let f = httpsig::sign(
            Message::Request(&req),
            "sig2",
            &components,
            &params,
            &rfc_key(),
        )
        .unwrap();
        assert_eq!(f.signature, "sig2=:RdNFx5Bj6au3YgAMQL/RzmUlZE8QZLIaXGRpw985hWnwPfMxT228NMk6ehRS1PSl4e8PhbNZACSanGdhEwYCCg==:");

        let signed = req
            .header("Signature-Input", &f.signature_input)
            .header("Signature", &f.signature);
        let mut store = DirectoryKeyStore::new();
        store
            .insert(AGENT, Directory::from_keys([&rfc_key().public_key()]))
            .unwrap();
        let opts = VerifyOptions {
            now: Some(1735689700),
            max_validity_secs: i64::MAX,
            ..Default::default()
        };
        match verify_request(&signed, &store, &opts) {
            WbaOutcome::Verified(a) => {
                assert_eq!(a.signature_agent, "https://signature-agent.test/");
                assert_eq!(a.keyid, RFC_KEYID);
                assert_eq!(a.label, "sig2");
            }
            other => panic!("{:?}", other),
        }
        // The default 24 h ceiling rejects the vector's long window.
        let strict = VerifyOptions {
            now: Some(1735689700),
            ..Default::default()
        };
        assert!(matches!(
            verify_request(&signed, &store, &strict),
            WbaOutcome::Invalid(_)
        ));
    }

    /// Appendix E.2.2: legacy bare-String Signature-Agent.
    #[test]
    fn draft_e22_legacy_signature_agent() {
        let req = HttpRequest::new("GET", "https://example.com/")
            .unwrap()
            .header("Signature-Agent", "\"https://signature-agent.test\"")
            .header("Signature-Input", "sig2=(\"@authority\" \"signature-agent\");created=1735689600;keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";alg=\"ed25519\";expires=1735693200;nonce=\"e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk4lAZYadIX6wW25MwG7DCT9RUKAJ0qVkU0mEeLElW1qg==\";tag=\"web-bot-auth\"")
            .header("Signature", "sig2=:jdq0SqOwHdyHr9+r5jw3iYZH6aNGKijYp/EstF4RQTQdi5N5YYKrD+mCT1HA1nZDsi6nJKuHxUi/5Syp3rLWBA==:");
        let mut store = DirectoryKeyStore::new();
        store
            .insert(AGENT, Directory::from_keys([&rfc_key().public_key()]))
            .unwrap();
        let opts = VerifyOptions {
            now: Some(1735689700),
            ..Default::default()
        };
        assert!(matches!(
            verify_request(&req, &store, &opts),
            WbaOutcome::Verified(_)
        ));
        let no_legacy = VerifyOptions {
            accept_legacy_signature_agent: false,
            ..opts
        };
        assert!(matches!(
            verify_request(&req, &store, &no_legacy),
            WbaOutcome::Invalid(_)
        ));
    }

    /// Appendix E.2.3: signed directory response, reproduced and verified.
    #[test]
    fn draft_e23_directory_response() {
        let body = format!(
            r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","kid":"{}","x":"{}","use":"sig"}}]}}"#,
            RFC_KEYID, RFC_X
        );
        let dir = Directory::from_keys([&rfc_key().public_key()]);
        assert_eq!(dir.to_json().unwrap(), body.as_bytes());

        let headers = sign_directory_response(
            body.as_bytes(),
            "signature-agent.test",
            &[rfc_key()],
            1735689600,
            MAX_VALIDITY_SECS,
        )
        .unwrap();
        assert_eq!(
            headers[0].1,
            "sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:"
        );

        let vector = vec![
            ("Content-Digest".to_string(), "sha-256=:CADMT2aBdV/rqQr/NIru64ERQkCobVvllA4V0fLFDu0=:".to_string()),
            ("Signature-Input".to_string(), "binding=(\"@authority\";req \"content-digest\");created=1735689600;expires=4889289600;keyid=\"poqkLGiymh_W0uP6PZFw-dvez3QJT5SolqXBCW38r0U\";tag=\"http-message-signatures-directory\"".to_string()),
            ("Signature".to_string(), "binding=:l6P8R67tm3kujAxbHWio7ll01qrEZ0dKD/WWlGhNYEmTnFZM8Wt0VQ9zqGfvo7T/UMkBxsigzChM1Gpz7gOVBg==:".to_string()),
        ];
        let proven = verify_directory_response(
            body.as_bytes(),
            &vector,
            "signature-agent.test",
            1735689700,
            60,
        )
        .unwrap();
        assert_eq!(proven.keys.len(), 1);

        // Re-served under another authority: the proof does not carry over.
        let moved =
            verify_directory_response(body.as_bytes(), &vector, "evil.test", 1735689700, 60)
                .unwrap();
        assert!(moved.keys.is_empty());
        // Swapped body: digest mismatch.
        assert!(verify_directory_response(
            b"{\"keys\":[]}",
            &vector,
            "signature-agent.test",
            1735689700,
            60
        )
        .is_err());
        // Our own signing round-trips.
        let ours = verify_directory_response(
            body.as_bytes(),
            &headers,
            "signature-agent.test",
            1735689700,
            60,
        )
        .unwrap();
        assert_eq!(ours.keys.len(), 1);
        // Future-dated proofs are rejected.
        assert!(verify_directory_response(
            body.as_bytes(),
            &headers,
            "signature-agent.test",
            1735680000,
            60
        )
        .unwrap()
        .keys
        .is_empty());
    }

    fn signed_request(key: &PrivateKey, opts: &SignOptions) -> HttpRequest {
        let mut req = HttpRequest::new("GET", "https://origin.example/path?q=1").unwrap();
        sign_request(&req, key, AGENT, opts)
            .unwrap()
            .apply(&mut req);
        req
    }

    fn store_with(key: &PrivateKey) -> DirectoryKeyStore {
        let mut store = DirectoryKeyStore::new();
        store
            .insert(AGENT, Directory::from_keys([&key.public_key()]))
            .unwrap();
        store
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let key = gen();
        let req = signed_request(&key, &SignOptions::default());
        let sigs = parse_signatures(&req.headers).unwrap();
        assert_eq!(sigs[0].params.tag.as_deref(), Some(TAG));
        assert!(sigs[0].params.nonce.is_some());
        httpsig::verify(Message::Request(&req), &sigs[0], &key.public_key()).unwrap();
        match verify_request(&req, &store_with(&key), &VerifyOptions::default()) {
            WbaOutcome::Verified(a) => {
                assert!(a.covers(&Component::new("@method")));
                assert!(a.covers(&Component::new("@path")));
                assert_eq!(a.expires - a.created, 300);
            }
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn outcomes_distinguish_invalid_and_unverified() {
        let key = gen();
        let req = signed_request(&key, &SignOptions::default());

        // Unknown directory: unverified.
        assert!(matches!(
            verify_request(&req, &DirectoryKeyStore::new(), &VerifyOptions::default()),
            WbaOutcome::Unverified(_)
        ));
        // Directory resolved without the key: unverified.
        assert!(matches!(
            verify_request(&req, &store_with(&gen()), &VerifyOptions::default()),
            WbaOutcome::Unverified(_)
        ));
        // Unsigned request: unverified.
        let unsigned = HttpRequest::new("GET", "https://origin.example/").unwrap();
        assert!(matches!(
            verify_request(&unsigned, &store_with(&key), &VerifyOptions::default()),
            WbaOutcome::Unverified(_)
        ));
        // Expired: invalid.
        let old = signed_request(
            &key,
            &SignOptions {
                created: Some(Utc::now().timestamp() - 10_000),
                ..Default::default()
            },
        );
        assert!(matches!(
            verify_request(&old, &store_with(&key), &VerifyOptions::default()),
            WbaOutcome::Invalid(_)
        ));
        // Path changed after signing: invalid.
        let mut moved = req.clone();
        moved.url = Url::parse("https://origin.example/other").unwrap();
        assert!(matches!(
            verify_request(&moved, &store_with(&key), &VerifyOptions::default()),
            WbaOutcome::Invalid(_)
        ));
    }

    /// Key lookup is per (URL, keyid): a key published by one directory
    /// does not verify a request that names another (§5.4).
    #[test]
    fn key_is_bound_to_its_directory() {
        let key = gen();
        let mut req = HttpRequest::new("GET", "https://origin.example/").unwrap();
        sign_request(
            &req,
            &key,
            "https://victim.example/.well-known/http-message-signatures-directory",
            &SignOptions::default(),
        )
        .unwrap()
        .apply(&mut req);
        // The verifier learned this key from AGENT, not from victim.example.
        assert!(matches!(
            verify_request(&req, &store_with(&key), &VerifyOptions::default()),
            WbaOutcome::Unverified(_)
        ));
    }

    #[test]
    fn rejects_signature_agent_problems() {
        let key = gen();
        let store = store_with(&key);
        let opts = VerifyOptions::default();

        // Member swapped after signing: the covered value changed. Lookup
        // happens under the new URL, so with no directory there the request
        // is unverified, and with the same key there it is invalid.
        let mut req = signed_request(&key, &SignOptions::default());
        for h in req.headers.iter_mut() {
            if h.0 == "Signature-Agent" {
                h.1 = "sig1=\"https://other.test\"".into();
            }
        }
        assert!(matches!(
            verify_request(&req, &store, &opts),
            WbaOutcome::Unverified(_)
        ));
        let mut both = store.clone();
        both.insert(
            "https://other.test",
            Directory::from_keys([&key.public_key()]),
        )
        .unwrap();
        assert!(matches!(
            verify_request(&req, &both, &opts),
            WbaOutcome::Invalid(_)
        ));

        // Two covered members: ambiguous attribution.
        let two = HttpRequest::new("GET", "https://origin.example/")
            .unwrap()
            .header(
                "Signature-Agent",
                "a=\"https://a.test\", b=\"https://b.test\"",
            );
        let f = httpsig::sign(
            Message::Request(&two),
            "a",
            &[
                Component::new("@authority"),
                Component::keyed("signature-agent", "a"),
                Component::keyed("signature-agent", "b"),
            ],
            &[
                Param::Created(Utc::now().timestamp()),
                Param::Expires(Utc::now().timestamp() + 60),
                Param::KeyId(thumbprint(&key.public_key())),
                Param::Tag(TAG.into()),
            ],
            &key,
        )
        .unwrap();
        let two = two
            .header("Signature-Input", &f.signature_input)
            .header("Signature", &f.signature);
        assert!(matches!(
            verify_request(&two, &store, &opts),
            WbaOutcome::Invalid(_)
        ));

        // Non-https Signature-Agent is refused at signing time.
        let plain = HttpRequest::new("GET", "https://origin.example/").unwrap();
        assert!(sign_request(
            &plain,
            &key,
            "http://insecure.test",
            &SignOptions::default()
        )
        .is_err());
        // Validity above 24 h is refused at signing time.
        assert!(sign_request(
            &plain,
            &key,
            AGENT,
            &SignOptions {
                validity_secs: MAX_VALIDITY_SECS + 1,
                ..Default::default()
            }
        )
        .is_err());
        // Label collision with an existing Signature-Agent member.
        let dup = plain
            .clone()
            .header("Signature-Agent", "sig1=\"https://a.test\"");
        assert!(sign_request(&dup, &key, AGENT, &SignOptions::default()).is_err());
    }

    #[test]
    fn legacy_signing_roundtrip() {
        let key = gen();
        let opts = SignOptions {
            legacy_signature_agent: true,
            ..Default::default()
        };
        let req = signed_request(&key, &opts);
        assert!(httpsig::combined_field(&req.headers, "signature-agent")
            .unwrap()
            .starts_with('"'));
        assert!(matches!(
            verify_request(&req, &store_with(&key), &VerifyOptions::default()),
            WbaOutcome::Verified(_)
        ));
        let strict = VerifyOptions {
            accept_legacy_signature_agent: false,
            ..Default::default()
        };
        assert!(matches!(
            verify_request(&req, &store_with(&key), &strict),
            WbaOutcome::Invalid(_)
        ));
        let existing = HttpRequest::new("GET", "https://origin.example/")
            .unwrap()
            .header("Signature-Agent", "a=\"https://a.test\"");
        assert!(sign_request(&existing, &key, AGENT, &opts).is_err());
    }

    #[test]
    fn member_with_parameters_is_ignored() {
        let headers = vec![(
            "Signature-Agent".to_string(),
            "sig1=\"https://a.test\";type=jwks_uri".to_string(),
        )];
        assert!(signature_agent_member(&headers, "sig1", false).is_err());
    }

    #[test]
    fn normalizes_identifiers() {
        assert_eq!(
            normalize_signature_agent("HTTPS://Agent.Example:443/dir?x=1#f").unwrap(),
            "https://agent.example/dir"
        );
        assert!(normalize_signature_agent("http://agent.example").is_err());
        assert!(normalize_signature_agent("https://u:p@agent.example").is_err());
        assert!(normalize_signature_agent("/relative").is_err());
    }

    #[test]
    fn directory_parse_skips_foreign_keys_and_honors_validity() {
        let key = gen();
        let jwk = Jwk {
            nbf: Some(100),
            exp: Some(200),
            ..Jwk::from_public_key(&key.public_key())
        };
        let json = serde_json::json!({"keys": [
            {"kty": "EC", "crv": "P-256", "x": "a", "y": "b"},
            {"kty": "OKP", "crv": "Ed25519", "x": "short"},
            jwk,
        ]});
        let dir = Directory::parse(json.to_string().as_bytes()).unwrap();
        assert_eq!(dir.keys.len(), 1);
        let tp = thumbprint(&key.public_key());
        assert!(find_key(&dir, &tp, 150, 0).is_some());
        assert!(find_key(&dir, &tp, 50, 0).is_none());
        assert!(find_key(&dir, &tp, 250, 0).is_none());

        let many = serde_json::json!({"keys": vec![serde_json::json!({}); MAX_DIRECTORY_KEYS + 1]});
        assert!(Directory::parse(many.to_string().as_bytes()).is_err());
    }

    #[test]
    fn pem_roundtrip() {
        let key = generate_signing_key();
        let pem = signing_key_to_pem(&key).unwrap();
        assert_eq!(
            load_signing_key(&pem).unwrap().public_key(),
            PublicKey::Ed25519(key.verifying_key())
        );
        assert!(load_signing_key("not a key").is_err());
    }

    #[test]
    fn nonce_store_rejects_replays() {
        let key = gen();
        let store = store_with(&key);
        let opts = VerifyOptions {
            nonce_store: Some(std::sync::Arc::new(crate::nonce::InMemoryNonceStore::new())),
            ..Default::default()
        };
        let req = signed_request(&key, &SignOptions::default());
        assert!(matches!(
            verify_request(&req, &store, &opts),
            WbaOutcome::Verified(_)
        ));
        assert_eq!(
            verify_request(&req, &store, &opts),
            WbaOutcome::Invalid("nonce replayed".into())
        );
        // A fresh signature is fine; one without a nonce is not.
        let again = signed_request(&key, &SignOptions::default());
        assert!(matches!(
            verify_request(&again, &store, &opts),
            WbaOutcome::Verified(_)
        ));
        let no_nonce = signed_request(
            &key,
            &SignOptions {
                nonce: false,
                ..Default::default()
            },
        );
        assert!(matches!(
            verify_request(&no_nonce, &store, &opts),
            WbaOutcome::Invalid(_)
        ));
        // Forged signatures never reach the store.
        let mut forged = signed_request(&key, &SignOptions::default());
        forged.url = Url::parse("https://origin.example/elsewhere").unwrap();
        assert!(matches!(
            verify_request(&forged, &store, &opts),
            WbaOutcome::Invalid(r) if r == "signature verification failed"
        ));
    }
}
