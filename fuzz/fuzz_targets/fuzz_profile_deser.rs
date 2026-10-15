#![no_main]

use libfuzzer_sys::fuzz_target;
use satspath_core::crypto::{canonical_profile_bytes, verify_signed_profile};
use satspath_core::profile::{Invite, PaymentProfile, PaymentRequest, SignedPaymentProfile};
use satspath_core::validation::validate_public_profile;

fuzz_target!(|data: &[u8]| {
    if let Ok(profile) = serde_json::from_slice::<PaymentProfile>(data) {
        let _ = validate_public_profile(&profile);
        if let Ok(bytes1) = canonical_profile_bytes(&profile) {
            let bytes2 = canonical_profile_bytes(&profile).unwrap();
            assert_eq!(
                bytes1, bytes2,
                "canonical_profile_bytes must be deterministic"
            );
        }
    }

    if let Ok(signed) = serde_json::from_slice::<SignedPaymentProfile>(data) {
        let _ = validate_public_profile(&signed.profile);
        let _ = verify_signed_profile(&signed);
    }

    let _ = serde_json::from_slice::<PaymentRequest>(data);
    let _ = serde_json::from_slice::<Invite>(data);
});
