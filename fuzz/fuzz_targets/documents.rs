#![no_main]
use agentpin::types::discovery::DiscoveryDocument;
use agentpin::types::revocation::RevocationDocument;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(doc) = serde_json::from_slice::<DiscoveryDocument>(data) {
        let entity = doc.entity.clone();
        let _ = agentpin::discovery::validate_discovery_document(&doc, &entity);
        let _ = agentpin::domain::normalize_domain(&entity);
    }
    if let Ok(rev) = serde_json::from_slice::<RevocationDocument>(data) {
        let _ = agentpin::revocation::revocation_signing_input(&rev);
    }
});
