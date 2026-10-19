#![no_main]

use libfuzzer_sys::fuzz_target;
use satspath_core::crypto::{sign_profile, verify_signed_profile};
use satspath_core::profile::PaymentProfile;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

fuzz_target!(|data: &[u8]| {
    if let Ok(mut profile) = serde_json::from_slice::<PaymentProfile>(data) {
        let key = SecretKey::from_slice(&[1; 32]).unwrap();
        profile.identity_pubkey = PublicKey::from_secret_key(&Secp256k1::new(), &key).to_string();
        if profile.pqc_required || profile.hybrid_pubkey.is_some() {
            // Classical-only signing cannot satisfy a PQC-demanding profile.
            if let Ok(signed) = sign_profile(profile, &key) {
                assert!(!verify_signed_profile(&signed).unwrap_or(false));
            }
            return;
        }
        if let Ok(signed) = sign_profile(profile, &key) {
            assert!(verify_signed_profile(&signed).unwrap());
            if !signed.profile.methods.is_empty() {
                let mut changed_methods = signed.clone();
                changed_methods.profile.methods.clear();
                assert!(!verify_signed_profile(&changed_methods).unwrap_or(false));
            }
            let mut changed_alias = signed.clone();
            changed_alias.profile.alias.push('x');
            assert!(!verify_signed_profile(&changed_alias).unwrap_or(false));
            let mut changed_sig = signed;
            changed_sig.signature = "00".repeat(64);
            assert!(!verify_signed_profile(&changed_sig).unwrap_or(false));
        }
    }
});
