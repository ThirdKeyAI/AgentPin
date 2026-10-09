#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(jwk) = serde_json::from_slice::<agentpin::jwk::Jwk>(data) {
        let _ = agentpin::jwk::jwk_to_verifying_key(&jwk);
        let _ = agentpin::jwk::jwk_thumbprint(&jwk);
    }
});
