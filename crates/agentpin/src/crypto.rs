use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use p256::{
    ecdsa::{signature::Signer, signature::Verifier, Signature, SigningKey, VerifyingKey},
    pkcs8::{DecodePrivateKey, DecodePublicKey, EncodePrivateKey, EncodePublicKey},
    SecretKey,
};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::error::Error;

#[derive(Debug, Clone)]
pub struct KeyPair {
    pub private_key_pem: String,
    pub public_key_pem: String,
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

/// Sign raw bytes with a SigningKey. Returns base64-encoded DER signature.
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
    fn test_sign_verify_bytes() {
        let kp = generate_key_pair().unwrap();
        let sk = load_signing_key(&kp.private_key_pem).unwrap();
        let vk = load_verifying_key(&kp.public_key_pem).unwrap();
        let data = b"raw bytes test";
        let sig = sign_bytes(&sk, data);
        assert!(verify_bytes(&vk, data, &sig).unwrap());
    }
}
