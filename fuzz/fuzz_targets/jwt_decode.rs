#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok((_, payload, _)) = agentpin::jwt::decode_jwt_unverified(s) {
            let _ = agentpin::jwt::validate_claims(&payload);
        }
    }
});
