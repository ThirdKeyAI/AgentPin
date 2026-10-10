use base64::{engine::general_purpose::URL_SAFE_NO_PAD as BASE64URL, Engine};
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};

use crate::error::Error;
use crate::types::credential::{JwtHeader, JwtPayload};

const REQUIRED_ALG: &str = "ES256";
const REQUIRED_TYP: &str = "agentpin-credential+jwt";

/// Base64url encode bytes.
pub fn base64url_encode(data: &[u8]) -> String {
    BASE64URL.encode(data)
}

/// Base64url decode a string.
pub fn base64url_decode(s: &str) -> Result<Vec<u8>, Error> {
    Ok(BASE64URL.decode(s)?)
}

/// Encode a JWT from header + payload + signing key. Returns the compact JWT string.
pub fn encode_jwt(
    header: &JwtHeader,
    payload: &JwtPayload,
    signing_key: &SigningKey,
) -> Result<String, Error> {
    let header_json = serde_json::to_string(header)?;
    let payload_json = serde_json::to_string(payload)?;

    let header_b64 = base64url_encode(header_json.as_bytes());
    let payload_b64 = base64url_encode(payload_json.as_bytes());

    let signing_input = format!("{}.{}", header_b64, payload_b64);
    let signature: Signature = signing_key.sign(signing_input.as_bytes());
    let sig_b64 = base64url_encode(signature.to_der().as_bytes());

    Ok(format!("{}.{}", signing_input, sig_b64))
}

/// Decode a JWT without verifying the signature. Returns (header, payload, signature_bytes).
pub fn decode_jwt_unverified(jwt: &str) -> Result<(JwtHeader, JwtPayload, String), Error> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(Error::Jwt("JWT must have 3 parts".to_string()));
    }

    let header_bytes = base64url_decode(parts[0])?;
    let payload_bytes = base64url_decode(parts[1])?;

    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| Error::Jwt(format!("Invalid JWT header: {}", e)))?;

    // Critical: reject non-ES256 algorithms
    if header.alg != REQUIRED_ALG {
        return Err(Error::Jwt(format!(
            "Algorithm '{}' rejected, must be '{}'",
            header.alg, REQUIRED_ALG
        )));
    }

    // Critical: reject wrong token type
    if header.typ != REQUIRED_TYP {
        return Err(Error::Jwt(format!(
            "Token type '{}' rejected, must be '{}'",
            header.typ, REQUIRED_TYP
        )));
    }

    // Payload shape: must be a JSON object whose claims have the right
    // types; anything else is a malformed credential (AP-5, AP-18).
    let payload_value: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| Error::Jwt(format!("Invalid JWT payload: {}", e)))?;
    if !payload_value.is_object() {
        return Err(Error::MalformedCredential(
            "JWT payload is not a JSON object".to_string(),
        ));
    }
    let payload: JwtPayload = serde_json::from_value(payload_value)
        .map_err(|e| Error::MalformedCredential(format!("Invalid JWT payload: {}", e)))?;
    validate_claims(&payload)?;

    Ok((header, payload, parts[2].to_string()))
}

/// Protocol version a credential's `agentpin_version` claim must carry.
pub const CREDENTIAL_VERSION: &str = "0.1";

/// Validate claim values that serde cannot express: non-empty identifiers,
/// non-negative timestamps, `exp > iat`, a supported protocol version
/// (AP-5, AP-14, AP-18).
pub fn validate_claims(payload: &JwtPayload) -> Result<(), Error> {
    if payload.iss.is_empty() {
        return Err(Error::MalformedCredential("iss is empty".to_string()));
    }
    if payload.sub.is_empty() {
        return Err(Error::MalformedCredential("sub is empty".to_string()));
    }
    if payload.jti.is_empty() {
        return Err(Error::MalformedCredential("jti is empty".to_string()));
    }
    if payload.iat < 0 || payload.exp < 0 {
        return Err(Error::MalformedCredential(
            "iat and exp must be non-negative".to_string(),
        ));
    }
    if payload.exp <= payload.iat {
        return Err(Error::MalformedCredential(
            "exp must be greater than iat".to_string(),
        ));
    }
    if let Some(nbf) = payload.nbf {
        if nbf < 0 {
            return Err(Error::MalformedCredential(
                "nbf must be non-negative".to_string(),
            ));
        }
    }
    if payload.agentpin_version != CREDENTIAL_VERSION {
        return Err(Error::MalformedCredential(format!(
            "Unsupported agentpin_version '{}'",
            payload.agentpin_version
        )));
    }
    Ok(())
}

/// Verify a JWT signature using a VerifyingKey. Returns (header, payload) on success.
pub fn verify_jwt(
    jwt: &str,
    verifying_key: &VerifyingKey,
) -> Result<(JwtHeader, JwtPayload), Error> {
    let (header, payload, _sig_b64) = decode_jwt_unverified(jwt)?;

    // Reconstruct signing input
    let parts: Vec<&str> = jwt.split('.').collect();
    let signing_input = format!("{}.{}", parts[0], parts[1]);

    // Decode and verify signature
    let sig_bytes = base64url_decode(parts[2])?;
    let signature = Signature::from_der(&sig_bytes)
        .map_err(|e| Error::Jwt(format!("Invalid signature encoding: {}", e)))?;

    use p256::ecdsa::signature::Verifier;
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|_| Error::SignatureInvalid)?;

    Ok((header, payload))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use crate::types::capability::Capability;

    fn make_test_jwt(signing_key: &SigningKey, kid: &str) -> (String, JwtHeader, JwtPayload) {
        let header = JwtHeader {
            alg: "ES256".to_string(),
            typ: "agentpin-credential+jwt".to_string(),
            kid: kid.to_string(),
        };
        let payload = JwtPayload {
            iss: "example.com".to_string(),
            sub: "urn:agentpin:example.com:agent".to_string(),
            aud: Some("verifier.com".to_string()),
            iat: 1738300800,
            exp: 1738304400,
            nbf: None,
            jti: "test-jti-001".to_string(),
            agentpin_version: "0.1".to_string(),
            capabilities: vec![Capability::from("read:data")],
            constraints: None,
            delegation_chain: None,
            nonce: None,
        };
        let jwt = encode_jwt(&header, &payload, signing_key).unwrap();
        (jwt, header, payload)
    }

    #[test]
    fn test_jwt_encode_decode_roundtrip() {
        let kp = crypto::generate_key_pair().unwrap();
        let sk = crypto::load_signing_key(&kp.private_key_pem).unwrap();
        let vk = crypto::load_verifying_key(&kp.public_key_pem).unwrap();

        let (jwt, orig_header, orig_payload) = make_test_jwt(&sk, "test-key");

        // Verify
        let (header, payload) = verify_jwt(&jwt, &vk).unwrap();
        assert_eq!(header, orig_header);
        assert_eq!(payload, orig_payload);
    }

    #[test]
    fn test_jwt_wrong_key_rejected() {
        let kp1 = crypto::generate_key_pair().unwrap();
        let kp2 = crypto::generate_key_pair().unwrap();
        let sk1 = crypto::load_signing_key(&kp1.private_key_pem).unwrap();
        let vk2 = crypto::load_verifying_key(&kp2.public_key_pem).unwrap();

        let (jwt, _, _) = make_test_jwt(&sk1, "key1");
        assert!(verify_jwt(&jwt, &vk2).is_err());
    }

    #[test]
    fn test_jwt_algorithm_rejection() {
        let kp = crypto::generate_key_pair().unwrap();
        let sk = crypto::load_signing_key(&kp.private_key_pem).unwrap();

        let header = JwtHeader {
            alg: "none".to_string(),
            typ: "agentpin-credential+jwt".to_string(),
            kid: "test".to_string(),
        };
        let payload = JwtPayload {
            iss: "example.com".to_string(),
            sub: "urn:agentpin:example.com:agent".to_string(),
            aud: None,
            iat: 1738300800,
            exp: 1738304400,
            nbf: None,
            jti: "jti".to_string(),
            agentpin_version: "0.1".to_string(),
            capabilities: vec![],
            constraints: None,
            delegation_chain: None,
            nonce: None,
        };
        let jwt = encode_jwt(&header, &payload, &sk).unwrap();

        let vk = crypto::load_verifying_key(&kp.public_key_pem).unwrap();
        let result = verify_jwt(&jwt, &vk);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("rejected"));
    }

    #[test]
    fn test_jwt_wrong_type_rejected() {
        let kp = crypto::generate_key_pair().unwrap();
        let sk = crypto::load_signing_key(&kp.private_key_pem).unwrap();

        let header = JwtHeader {
            alg: "ES256".to_string(),
            typ: "JWT".to_string(),
            kid: "test".to_string(),
        };
        let payload = JwtPayload {
            iss: "example.com".to_string(),
            sub: "urn:agentpin:example.com:agent".to_string(),
            aud: None,
            iat: 1738300800,
            exp: 1738304400,
            nbf: None,
            jti: "jti".to_string(),
            agentpin_version: "0.1".to_string(),
            capabilities: vec![],
            constraints: None,
            delegation_chain: None,
            nonce: None,
        };
        let jwt = encode_jwt(&header, &payload, &sk).unwrap();

        let vk = crypto::load_verifying_key(&kp.public_key_pem).unwrap();
        assert!(verify_jwt(&jwt, &vk).is_err());
    }

    #[test]
    fn test_jwt_malformed_rejected() {
        assert!(decode_jwt_unverified("not.a.jwt.token").is_err());
        assert!(decode_jwt_unverified("only-one-part").is_err());
    }

    fn raw_jwt(payload_json: &str) -> String {
        let header =
            base64url_encode(br#"{"alg":"ES256","typ":"agentpin-credential+jwt","kid":"k"}"#);
        format!(
            "{}.{}.sig",
            header,
            base64url_encode(payload_json.as_bytes())
        )
    }

    /// AP-5 / AP-14 / AP-18: missing, mistyped, negative or inconsistent
    /// claims are MalformedCredential errors, not parse errors or panics.
    #[test]
    fn test_claim_validation() {
        let base = r#""iss":"example.com","sub":"urn:agentpin:example.com:a","jti":"j","agentpin_version":"0.1","capabilities":[]"#;
        let cases = [
            format!("{{{},\"iat\":1}}", base),                                  // missing exp
            format!("{{{},\"iat\":1,\"exp\":\"never\"}}", base),              // string exp
            format!("{{{},\"iat\":1,\"exp\":{{}}}}", base),                     // object exp
            format!("{{{},\"iat\":-9223372036854775808,\"exp\":4102444800}}", base), // i64::MIN iat
            format!("{{{},\"iat\":10,\"exp\":10}}", base),                      // exp == iat
            format!("{{{},\"iat\":10,\"exp\":5}}", base),                       // exp < iat
            format!("{{{},\"iat\":1,\"exp\":2,\"nbf\":-1}}", base),           // negative nbf
            r#"{"iss":"","sub":"s","jti":"j","agentpin_version":"0.1","capabilities":[],"iat":1,"exp":2}"#.to_string(),
            r#"{"iss":"example.com","sub":"s","jti":"j","agentpin_version":"0.2","capabilities":[],"iat":1,"exp":2}"#.to_string(),
            r#"{"iss":"example.com","sub":"s","jti":"j","agentpin_version":"0.1","capabilities":"read:*","iat":1,"exp":2}"#.to_string(),
            "null".to_string(),
            "[]".to_string(),
        ];
        for payload in cases {
            let err = decode_jwt_unverified(&raw_jwt(&payload)).unwrap_err();
            assert!(
                matches!(err, Error::MalformedCredential(_)),
                "payload {} gave {:?}",
                payload,
                err
            );
        }
        let ok = format!("{{{},\"iat\":1,\"exp\":2}}", base);
        assert!(decode_jwt_unverified(&raw_jwt(&ok)).is_ok());
    }
}
