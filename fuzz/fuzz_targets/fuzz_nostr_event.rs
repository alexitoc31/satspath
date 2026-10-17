#![no_main]

use libfuzzer_sys::fuzz_target;
use satspath_core::resolvers::nostr::signed_profile_from_event;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

fuzz_target!(|data: &[u8]| {
    if let Ok(raw) = std::str::from_utf8(data) {
        // The parser must never accept a relay frame without a matching
        // subscription ID, author, d-tag, valid profile signature and expiry.
        let expected = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        if let Ok(Some(signed)) =
            signed_profile_from_event(raw, "sub", expected, "alice@example.com")
        {
            assert_eq!(
                satspath_core::canonical_identifier(&signed.profile.alias),
                "alice@example.com"
            );
            assert!(satspath_core::verify_signed_profile(&signed).unwrap_or(false));
            assert!(!signed.profile.revoked);
        }
    }
    if let Ok(mut profile) = serde_json::from_slice::<satspath_core::PaymentProfile>(data) {
        let key = SecretKey::from_slice(&[1; 32]).unwrap();
        let public = PublicKey::from_secret_key(&Secp256k1::new(), &key);
        profile.alias = "alice@example.com".into();
        profile.identity_pubkey = public.to_string();
        profile.expires_at = None;
        profile.pqc_required = false;
        profile.hybrid_pubkey = None;
        let signed = satspath_core::sign_profile(profile, &key).unwrap();
        let frame = serde_json::json!(["EVENT", "sub", {
            "kind": 30078,
            "pubkey": public.x_only_public_key().0.to_string(),
            "tags": [["d", "satspath-profile:alice@example.com"]],
            "content": serde_json::to_string(&signed).unwrap()
        }]);
        let resolved = signed_profile_from_event(
            &frame.to_string(),
            "sub",
            &public.x_only_public_key().0.to_string(),
            "alice@example.com",
        );
        if signed.profile.revoked {
            assert!(matches!(
                resolved,
                Err(satspath_core::SatsPathError::RegistryError(_))
            ));
        } else {
            assert!(resolved.unwrap().is_some());
        }
        for changed in [
            {
                let mut value = frame.clone();
                value[1] = serde_json::json!("wrong-subscription");
                value
            },
            {
                let mut value = frame.clone();
                value[2]["pubkey"] = serde_json::json!("wrong-author");
                value
            },
            {
                let mut value = frame.clone();
                value[2]["tags"][0][1] = serde_json::json!("satspath-profile:bob@example.com");
                value
            },
        ] {
            assert!(signed_profile_from_event(
                &changed.to_string(),
                "sub",
                &public.x_only_public_key().0.to_string(),
                "alice@example.com"
            )
            .unwrap()
            .is_none());
        }
    }
});
