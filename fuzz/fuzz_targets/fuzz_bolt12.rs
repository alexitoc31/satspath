#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. Direct byte-level TLV and BlindedPath decoding
    let _ = satspath_router::bolt12::decode_tlv_stream(data);
    if let Ok(path) = satspath_router::bolt12::BlindedPath::decode_bytes(data) {
        assert!(path.blinded_hops.len() <= satspath_router::bolt12::MAX_BLINDED_PATH_HOPS);
    }

    // 2. String-level offer and invoice parsing
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(offer) = satspath_router::bolt12::parse_bolt12_offer(s) {
            let _ = offer.has_blinded_paths();
            let _ = offer.primary_blinded_path();
            let _ = offer.is_expired(1_700_000_000);
            let _ = offer.is_amount_valid(50_000);
            let _ = offer.offer_id();
        }
        let _ = satspath_router::bolt12::parse_bolt12_invoice_request(s);
        let _ = satspath_router::bolt12::parse_bolt12_invoice(s);
        let _ = satspath_core::validation::validate_bolt12_offer(s);
    }
});
