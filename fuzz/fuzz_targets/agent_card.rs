#![no_main]
use agentpin::types::a2a::A2aAgentCard;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(card) = serde_json::from_slice::<A2aAgentCard>(data) {
        // Canonicalization must be deterministic across a serde round trip.
        if let Ok(first) = agentpin::a2a::agent_card_signing_input(&card) {
            let json = serde_json::to_vec(&card).unwrap();
            let again: A2aAgentCard = serde_json::from_slice(&json).unwrap();
            assert_eq!(first, agentpin::a2a::agent_card_signing_input(&again).unwrap());
        }
        let _ = agentpin::a2a::verify_agentpin_extension(&card);
    }
});
