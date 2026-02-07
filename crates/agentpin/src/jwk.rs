use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
use p256::{
    ecdsa::VerifyingKey,
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::{DecodePublicKey, EncodePublicKey},
    PublicKey,
};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Jwk {
    pub kid: String,
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    #[serde(rename = "use")]
    pub use_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<String>,
}

/// Convert a VerifyingKey to a JWK with the given key ID.
pub fn verifying_key_to_jwk(key: &VerifyingKey, kid: &str) -> Jwk {
    let public_key = PublicKey::from(key);
    let point = public_key.to_encoded_point(false);
    let x = BASE64URL.encode(point.x().expect("x coordinate"));
    let y = BASE64URL.encode(point.y().expect("y coordinate"));

    Jwk {
        kid: kid.to_string(),
        kty: "EC".to_string(),
        crv: "P-256".to_string(),
        x,
        y,
        use_: "sig".to_string(),
        key_ops: Some(vec!["verify".to_string()]),
        exp: None,
    }
}

/// Convert a JWK to a VerifyingKey.
pub fn jwk_to_verifying_key(jwk: &Jwk) -> Result<VerifyingKey, Error> {
    if jwk.kty != "EC" || jwk.crv != "P-256" {
        return Err(Error::InvalidKeyFormat);
    }

    let x_bytes = BASE64URL
        .decode(&jwk.x)
        .map_err(|_| Error::InvalidKeyFormat)?;
    let y_bytes = BASE64URL
        .decode(&jwk.y)
        .map_err(|_| Error::InvalidKeyFormat)?;

    if x_bytes.len() != 32 || y_bytes.len() != 32 {
        return Err(Error::InvalidKeyFormat);
    }

    // Build uncompressed SEC1 point: 0x04 || x || y
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(&x_bytes);
    sec1.extend_from_slice(&y_bytes);

    let public_key = PublicKey::from_sec1_bytes(&sec1).map_err(|_| Error::InvalidKeyFormat)?;
    Ok(VerifyingKey::from(&public_key))
}

/// Convert a PEM public key to a JWK.
pub fn pem_to_jwk(public_key_pem: &str, kid: &str) -> Result<Jwk, Error> {
    let vk = VerifyingKey::from_public_key_pem(public_key_pem)
        .map_err(|e| Error::Ecdsa(e.to_string()))?;
    Ok(verifying_key_to_jwk(&vk, kid))
}

/// Convert a JWK to a PEM public key.
pub fn jwk_to_pem(jwk: &Jwk) -> Result<String, Error> {
    let vk = jwk_to_verifying_key(jwk)?;
    Ok(vk.to_public_key_pem(p256::pkcs8::LineEnding::LF)?)
}

/// Compute JWK thumbprint (RFC 7638): SHA-256 of canonical JWK JSON.
/// Canonical form uses alphabetically sorted required members: crv, kty, x, y.
pub fn jwk_thumbprint(jwk: &Jwk) -> String {
    let canonical = format!(
        r#"{{"crv":"{}","kty":"{}","x":"{}","y":"{}"}}"#,
        jwk.crv, jwk.kty, jwk.x, jwk.y
    );
    crypto::sha256_hex(canonical.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::generate_key_pair;

    #[test]
    fn test_jwk_roundtrip() {
        let kp = generate_key_pair().unwrap();
        let jwk = pem_to_jwk(&kp.public_key_pem, "test-key-01").unwrap();

        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert_eq!(jwk.kid, "test-key-01");
        assert_eq!(jwk.use_, "sig");

        let pem_back = jwk_to_pem(&jwk).unwrap();
        assert_eq!(pem_back, kp.public_key_pem);
    }

    #[test]
    fn test_jwk_to_verifying_key_roundtrip() {
        let kp = generate_key_pair().unwrap();
        let vk = crypto::load_verifying_key(&kp.public_key_pem).unwrap();
        let jwk = verifying_key_to_jwk(&vk, "kid-1");
        let vk2 = jwk_to_verifying_key(&jwk).unwrap();
        assert_eq!(
            vk.to_public_key_pem(p256::pkcs8::LineEnding::LF).unwrap(),
            vk2.to_public_key_pem(p256::pkcs8::LineEnding::LF).unwrap()
        );
    }

    #[test]
    fn test_jwk_thumbprint_deterministic() {
        let kp = generate_key_pair().unwrap();
        let jwk = pem_to_jwk(&kp.public_key_pem, "kid-1").unwrap();
        let t1 = jwk_thumbprint(&jwk);
        let t2 = jwk_thumbprint(&jwk);
        assert_eq!(t1, t2);
        assert_eq!(t1.len(), 64);
    }

    #[test]
    fn test_invalid_jwk_rejected() {
        let jwk = Jwk {
            kid: "bad".to_string(),
            kty: "RSA".to_string(),
            crv: "P-256".to_string(),
            x: "AAAA".to_string(),
            y: "BBBB".to_string(),
            use_: "sig".to_string(),
            key_ops: None,
            exp: None,
        };
        assert!(jwk_to_verifying_key(&jwk).is_err());
    }
}
