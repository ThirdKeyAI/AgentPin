use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use p256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    SecretKey,
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};

use crate::error::Error;

/// A freshly generated key pair.
///
/// The private PEM is zeroized when the value is dropped and is redacted
/// from `Debug` output, so an incidental `{:?}` or log line never leaks key
/// material (AP-23).
#[derive(Clone)]
pub struct KeyPair {
    pub private_key_pem: String,
    pub public_key_pem: String,
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("private_key_pem", &"<redacted>")
            .field("public_key_pem", &self.public_key_pem)
            .finish()
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private_key_pem.zeroize();
    }
}

/// Generate a new ECDSA P-256 keypair.
pub fn generate_key_pair() -> Result<KeyPair, Error> {
    let secret_key = SecretKey::random(&mut OsRng);
    let signing_key = SigningKey::from(&secret_key);
    let verifying_key = signing_key.verifying_key();

    let private_key_pem = secret_key
        .to_pkcs8_pem(p256::pkcs8::LineEnding::LF)?
        .to_string();
    let public_key_pem = verifying_key.to_public_key_pem(p256::pkcs8::LineEnding::LF)?;

    Ok(KeyPair {
        private_key_pem,
        public_key_pem,
    })
}

/// Sign data with a PEM-encoded private key. Returns base64-encoded signature.
pub fn sign_data(private_key_pem: &str, data: &[u8]) -> Result<String, Error> {
    let signing_key =
        SigningKey::from_pkcs8_pem(private_key_pem).map_err(|e| Error::Ecdsa(e.to_string()))?;
    let signature: Signature = signing_key.sign(data);
    Ok(BASE64.encode(signature.to_der()))
}

/// Verify a signature against data using a PEM-encoded public key.
pub fn verify_signature(
    public_key_pem: &str,
    data: &[u8],
    signature_b64: &str,
) -> Result<bool, Error> {
    let verifying_key = VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|e| Error::Ecdsa(e.to_string()))?;
    let sig_bytes = BASE64.decode(signature_b64)?;
    let signature = Signature::from_der(&sig_bytes).map_err(|e| Error::Ecdsa(e.to_string()))?;
    match verifying_key.verify(data, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

// ---------------------------------------------------------------------------
// Domain-separated signing (protocol v0.4)
// ---------------------------------------------------------------------------
//
// Every object AgentPin signs other than the credential JWT itself goes
// through `domain_separated_input`, which prefixes a fixed context label and
// length-prefixes each field. The JWT keeps the RFC 7515 `header.payload`
// signing input, whose alphabet (base64url plus `.`) can never contain the
// NUL byte that terminates every context label, so no signature produced for
// one object type can be replayed as another. In particular a challenge
// response can no longer be turned into a credential signature (AP-1).

/// Context label for mutual-authentication challenge responses.
pub const CTX_RESPONSE: &str = "agentpin-response-v1";
/// Context label for delegation attestations.
pub const CTX_ATTESTATION: &str = "agentpin-attestation-v1";
/// Context label for A2A AgentCard signatures.
pub const CTX_AGENTCARD: &str = "agentpin-agentcard-v1";
/// Context label for signed revocation documents.
pub const CTX_REVOCATION: &str = "agentpin-revocation-v1";
/// Context label for signed trust bundles.
pub const CTX_BUNDLE: &str = "agentpin-bundle-v1";

/// Build the domain-separated signing input for `context` over `fields`.
///
/// Layout: `context || 0x00 || (u32_be(len(field)) || field)*`. Every
/// field is length-prefixed so the encoding is unambiguous regardless of
/// field content; the NUL after the context keeps the input disjoint from
/// the JWT signing-input alphabet.
pub fn domain_separated_input(context: &str, fields: &[&[u8]]) -> Vec<u8> {
    let total: usize = context.len() + 1 + fields.iter().map(|f| 4 + f.len()).sum::<usize>();
    let mut out = Vec::with_capacity(total);
    out.extend_from_slice(context.as_bytes());
    out.push(0);
    for field in fields {
        let len = u32::try_from(field.len()).expect("field longer than u32::MAX");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// Sign `fields` under `context` with a SigningKey. Returns base64-encoded
/// DER signature.
pub fn sign_with_context(signing_key: &SigningKey, context: &str, fields: &[&[u8]]) -> String {
    let input = domain_separated_input(context, fields);
    sign_bytes(signing_key, &input)
}

/// Verify a signature produced by [`sign_with_context`].
pub fn verify_with_context(
    verifying_key: &VerifyingKey,
    context: &str,
    fields: &[&[u8]],
    signature_b64: &str,
) -> Result<bool, Error> {
    let input = domain_separated_input(context, fields);
    verify_bytes(verifying_key, &input, signature_b64)
}

/// Sign raw bytes with a SigningKey. Returns base64-encoded DER signature.
///
/// This is a low-level primitive. Protocol objects MUST be signed through
/// [`sign_with_context`] (or the JWT encoder) so that signatures over
/// different object types can never be confused; never pass caller-supplied
/// bytes to this function directly.
pub fn sign_bytes(signing_key: &SigningKey, data: &[u8]) -> String {
    let signature: Signature = signing_key.sign(data);
    BASE64.encode(signature.to_der())
}

/// Verify a signature with a VerifyingKey.
pub fn verify_bytes(
    verifying_key: &VerifyingKey,
    data: &[u8],
    signature_b64: &str,
) -> Result<bool, Error> {
    let sig_bytes = BASE64.decode(signature_b64)?;
    let signature = Signature::from_der(&sig_bytes).map_err(|e| Error::Ecdsa(e.to_string()))?;
    match verifying_key.verify(data, &signature) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Generate a key ID from a public key PEM: SHA-256 hash of the DER bytes, hex-encoded.
pub fn generate_key_id(public_key_pem: &str) -> Result<String, Error> {
    let verifying_key = VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|e| Error::Ecdsa(e.to_string()))?;
    let der_bytes = verifying_key.to_public_key_der()?;
    let hash = sha256_hash(der_bytes.as_bytes());
    Ok(hex::encode(hash))
}

/// SHA-256 hash of arbitrary bytes.
pub fn sha256_hash(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

/// SHA-256 hash, hex-encoded.
pub fn sha256_hex(data: &[u8]) -> String {
    hex::encode(sha256_hash(data))
}

/// Load a SigningKey from PEM.
pub fn load_signing_key(pem: &str) -> Result<SigningKey, Error> {
    SigningKey::from_pkcs8_pem(pem).map_err(|e| Error::Ecdsa(e.to_string()))
}

/// Load a VerifyingKey from PEM.
pub fn load_verifying_key(pem: &str) -> Result<VerifyingKey, Error> {
    VerifyingKey::from_public_key_pem(pem).map_err(|e| Error::Ecdsa(e.to_string()))
}

/// Export a VerifyingKey to PEM.
pub fn verifying_key_to_pem(key: &VerifyingKey) -> Result<String, Error> {
    Ok(key.to_public_key_pem(p256::pkcs8::LineEnding::LF)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_pair() {
        let kp = generate_key_pair().unwrap();
        assert!(kp
            .private_key_pem
            .starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(kp.public_key_pem.starts_with("-----BEGIN PUBLIC KEY-----"));
    }

    /// AP-23: Debug output never contains the private key.
    #[test]
    fn test_keypair_debug_redacts_private_key() {
        let kp = generate_key_pair().unwrap();
        let dbg = format!("{:?}", kp);
        assert!(dbg.contains("<redacted>"));
        assert!(!dbg.contains("PRIVATE KEY"));
        assert!(dbg.contains("PUBLIC KEY"));
    }

    #[test]
    fn test_sign_and_verify() {
        let kp = generate_key_pair().unwrap();
        let data = b"hello agentpin";
        let sig = sign_data(&kp.private_key_pem, data).unwrap();
        assert!(verify_signature(&kp.public_key_pem, data, &sig).unwrap());
        assert!(!verify_signature(&kp.public_key_pem, b"wrong data", &sig).unwrap());
    }

    #[test]
    fn test_wrong_key_rejection() {
        let kp1 = generate_key_pair().unwrap();
        let kp2 = generate_key_pair().unwrap();
        let data = b"test data";
        let sig = sign_data(&kp1.private_key_pem, data).unwrap();
        assert!(!verify_signature(&kp2.public_key_pem, data, &sig).unwrap());
    }

    #[test]
    fn test_generate_key_id() {
        let kp = generate_key_pair().unwrap();
        let kid = generate_key_id(&kp.public_key_pem).unwrap();
        assert_eq!(kid.len(), 64); // 32 bytes = 64 hex chars
                                   // Deterministic
        let kid2 = generate_key_id(&kp.public_key_pem).unwrap();
        assert_eq!(kid, kid2);
    }

    #[test]
    fn test_sha256_hash() {
        let hash = sha256_hex(b"test");
        assert_eq!(hash.len(), 64);
        // Known SHA-256 of "test"
        assert_eq!(
            hash,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
    }

    #[test]
    fn test_domain_separated_input_layout() {
        let input = domain_separated_input("agentpin-response-v1", &[b"abc", b"", b"xyz"]);
        let mut expected = b"agentpin-response-v1\0".to_vec();
        expected.extend_from_slice(&[0, 0, 0, 3]);
        expected.extend_from_slice(b"abc");
        expected.extend_from_slice(&[0, 0, 0, 0]);
        expected.extend_from_slice(&[0, 0, 0, 3]);
        expected.extend_from_slice(b"xyz");
        assert_eq!(input, expected);
    }

    #[test]
    fn test_context_signature_does_not_verify_under_other_context() {
        let kp = generate_key_pair().unwrap();
        let sk = load_signing_key(&kp.private_key_pem).unwrap();
        let vk = load_verifying_key(&kp.public_key_pem).unwrap();
        let sig = sign_with_context(&sk, CTX_RESPONSE, &[b"nonce"]);
        assert!(verify_with_context(&vk, CTX_RESPONSE, &[b"nonce"], &sig).unwrap());
        assert!(!verify_with_context(&vk, CTX_ATTESTATION, &[b"nonce"], &sig).unwrap());
        // And it is not a signature over the bare bytes either.
        assert!(!verify_bytes(&vk, b"nonce", &sig).unwrap());
    }

    #[test]
    fn test_sign_verify_bytes() {
        let kp = generate_key_pair().unwrap();
        let sk = load_signing_key(&kp.private_key_pem).unwrap();
        let vk = load_verifying_key(&kp.public_key_pem).unwrap();
        let data = b"raw bytes test";
        let sig = sign_bytes(&sk, data);
        assert!(verify_bytes(&vk, data, &sig).unwrap());
    }
}
