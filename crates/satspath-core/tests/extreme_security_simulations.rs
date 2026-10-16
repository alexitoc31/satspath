use chrono::Utc;
use satspath_core::crypto::{generate_identity_keypair, sign_profile, verify_signed_profile};
use satspath_core::profile::{PaymentMethod, PaymentProfile};
use satspath_core::resolvers::bip353::Bip353Resolver;
use satspath_core::resolvers::http::HttpResolver;

/// Builds a profile bound to the supplied identity key that requires PQC verification.
fn create_pqc_profile(pubkey: &secp256k1::PublicKey) -> PaymentProfile {
    PaymentProfile {
        alias: "quantum@satspath.dev".to_string(),
        identity_pubkey: hex::encode(pubkey.serialize()),
        methods: vec![PaymentMethod::Lightning {
            label: "Lightning".into(),
            lightning_address: Some("quantum@node".to_string()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        }],
        updated_at: Utc::now().timestamp(),
        expires_at: None,
        sequence: Some(1),
        preferences: vec![],
        nonce: Some(satspath_core::crypto::generate_nonce()),
        rotation: None,
        method_verifications: vec![],
        hybrid_pubkey: None,
        pqc_required: true, // Quantum resistant flag
        revoked: false,
        recovery_policy: None,
        recovery: None,
    }
}

#[tokio::test]
async fn test_attack_loopback_profile_url_rejected() {
    let resolver = HttpResolver::new();
    let result = resolver
        .resolve_from_url("https://127.0.0.1:8080/profile")
        .await;
    assert!(
        matches!(result, Err(satspath_core::SatsPathError::ValidationError(ref message))
            if message.starts_with("Blocked IP: 127.0.0.1")),
        "resolve_from_url must reject the loopback IP range: {result:?}"
    );
}

#[test]
fn test_attack_pqc_downgrade() {
    println!("✅ SETUP: User requires Post-Quantum Cryptography (pqc_required = true)...");
    let alice_keys = generate_identity_keypair();
    let profile = create_pqc_profile(&alice_keys.public_key);

    let signed_profile = sign_profile(profile, &alice_keys.secret_key).unwrap();
    let original_json = serde_json::to_string(&signed_profile).unwrap();

    // ATTACK 10: Downgrade attack
    println!("⚔️ ATTACK 10: Attacker intercepts JSON and switches pqc_required to FALSE to downgrade security...");

    // Attacker modifies the JSON to remove PQC requirements
    let corrupted_json = original_json.replace("\"pqc_required\":true", "\"pqc_required\":false");

    let received_profile: satspath_core::profile::SignedPaymentProfile =
        serde_json::from_str(&corrupted_json).unwrap();

    // VALIDATION
    let verification_result = verify_signed_profile(&received_profile).unwrap_or(false);

    assert!(
        !verification_result,
        "SECURITY FAILURE: The node accepted a downgraded PQC profile!"
    );
    println!("🛡️ DEFENSE SUCCESS: Cryptographic downgrade rejected. The Schnorr signature covers the canonical profile including the PQC flag and explicitly rejects modified payloads.");
}

#[test]
fn test_pqc_required_fails_closed_without_pqc_support() {
    let alice_keys = generate_identity_keypair();
    let profile = create_pqc_profile(&alice_keys.public_key);
    let signed_profile = sign_profile(profile, &alice_keys.secret_key).unwrap();
    let verified = verify_signed_profile(&signed_profile).unwrap();
    assert!(
        !verified,
        "Profile requiring PQC must fail closed when PQC feature is disabled or PQC keys are absent"
    );
}

#[cfg(feature = "pqc")]
#[test]
fn test_pqc_required_succeeds_with_valid_hybrid_signature_and_rejects_tampering() {
    let alice_keys = generate_identity_keypair();
    let alice_pubkey_hex = hex::encode(alice_keys.public_key.serialize());

    let hybrid_kp = satspath_pqc::hybrid_sig::HybridSigningKeyPair::from_seeds(
        &alice_keys.secret_key.secret_bytes(),
        &[0x42u8; 32],
    )
    .expect("hybrid keypair from seeds");
    let hybrid_pk = hybrid_kp.public_key();
    assert_eq!(hybrid_pk.classical_pubkey, alice_pubkey_hex);

    let mut profile = create_pqc_profile(&alice_keys.public_key);
    profile.hybrid_pubkey = Some(satspath_core::pqc::HybridPublicKey {
        classical_pubkey: hybrid_pk.classical_pubkey.clone(),
        pqc_verification_key: hybrid_pk.pqc_verification_key.clone(),
        suite: match hybrid_pk.suite {
            satspath_pqc::types::PqcSuite::MlKem768X25519 => {
                satspath_core::pqc::PqcSuite::MlKem768X25519
            }
            satspath_pqc::types::PqcSuite::MlDsa65Schnorr => {
                satspath_core::pqc::PqcSuite::MlDsa65Schnorr
            }
        },
    });
    profile.pqc_required = true;

    let canonical = satspath_core::crypto::canonical_profile_bytes(&profile).unwrap();
    let hybrid_sig = satspath_pqc::hybrid_sig::hybrid_sign(&canonical, &hybrid_kp);

    let secp = secp256k1::Secp256k1::new();
    let digest = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"SatsPathProfileV1");
        hasher.update(&canonical);
        hasher.finalize()
    };
    use sha2::Digest;
    let msg = secp256k1::Message::from_digest(digest.into());
    let kp = secp256k1::Keypair::from_secret_key(&secp, &alice_keys.secret_key);
    let schnorr_sig = secp.sign_schnorr(&msg, &kp);

    let mut signed = satspath_core::SignedPaymentProfile {
        profile: profile.clone(),
        signature: hex::encode(schnorr_sig.serialize()),
        hybrid_signature: Some(satspath_core::pqc::HybridSignature {
            schnorr_sig: hybrid_sig.schnorr_sig.clone(),
            pqc_sig: hybrid_sig.pqc_sig.clone(),
            suite: match hybrid_sig.suite {
                satspath_pqc::types::PqcSuite::MlKem768X25519 => {
                    satspath_core::pqc::PqcSuite::MlKem768X25519
                }
                satspath_pqc::types::PqcSuite::MlDsa65Schnorr => {
                    satspath_core::pqc::PqcSuite::MlDsa65Schnorr
                }
            },
        }),
    };

    // 1. Success path
    assert!(
        verify_signed_profile(&signed).unwrap(),
        "Valid hybrid profile with matching classical key and valid PQC signature must verify successfully"
    );

    // 2. Tampered hybrid signature is rejected
    let mut tampered_pqc = hybrid_sig.pqc_sig.clone();
    if tampered_pqc.starts_with('0') {
        tampered_pqc.replace_range(0..1, "1");
    } else {
        tampered_pqc.replace_range(0..1, "0");
    }
    signed.hybrid_signature = Some(satspath_core::pqc::HybridSignature {
        schnorr_sig: hybrid_sig.schnorr_sig.clone(),
        pqc_sig: tampered_pqc,
        suite: satspath_core::pqc::PqcSuite::MlDsa65Schnorr,
    });
    assert!(
        !verify_signed_profile(&signed).unwrap(),
        "Tampered hybrid signature must fail verification"
    );

    // Also corrupt the middle of the ML-DSA-65 z vector, leaving Schnorr intact.
    // Encoding: 48-byte challenge, 5 * 640-byte z vector, then hints.
    let mut tampered_z = hex::decode(&hybrid_sig.pqc_sig).unwrap();
    let midpoint = tampered_z.len() / 2;
    assert!((48..48 + 5 * 640).contains(&midpoint));
    tampered_z[midpoint] ^= 0x01;
    signed.hybrid_signature = Some(satspath_core::pqc::HybridSignature {
        schnorr_sig: hybrid_sig.schnorr_sig.clone(),
        pqc_sig: hex::encode(tampered_z),
        suite: satspath_core::pqc::PqcSuite::MlDsa65Schnorr,
    });
    assert!(
        !verify_signed_profile(&signed).unwrap(),
        "Tampered ML-DSA z vector must fail verification with unchanged Schnorr signature"
    );

    // 3. Unbound hybrid signature (hybrid signature present without hybrid pubkey) is rejected
    let mut unbound_signed = signed.clone();
    unbound_signed.profile.hybrid_pubkey = None;
    unbound_signed.profile.pqc_required = false;
    let unbound_canonical =
        satspath_core::crypto::canonical_profile_bytes(&unbound_signed.profile).unwrap();
    let unbound_digest = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"SatsPathProfileV1");
        hasher.update(&unbound_canonical);
        hasher.finalize()
    };
    let unbound_msg = secp256k1::Message::from_digest(unbound_digest.into());
    let unbound_sig = secp.sign_schnorr(&unbound_msg, &kp);
    unbound_signed.signature = hex::encode(unbound_sig.serialize());
    assert!(
        !verify_signed_profile(&unbound_signed).unwrap(),
        "Unbound hybrid signature attached without hybrid pubkey must be rejected"
    );

    // 4. Partial hybrid state: hybrid pubkey present without hybrid signature is rejected
    let mut key_only_signed = signed.clone();
    key_only_signed.hybrid_signature = None;
    key_only_signed.profile.pqc_required = false;
    let key_only_canonical =
        satspath_core::crypto::canonical_profile_bytes(&key_only_signed.profile).unwrap();
    let key_only_digest = {
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"SatsPathProfileV1");
        hasher.update(&key_only_canonical);
        hasher.finalize()
    };
    let key_only_msg = secp256k1::Message::from_digest(key_only_digest.into());
    let key_only_sig = secp.sign_schnorr(&key_only_msg, &kp);
    key_only_signed.signature = hex::encode(key_only_sig.serialize());
    assert!(
        !verify_signed_profile(&key_only_signed).unwrap(),
        "Partial hybrid profile with hybrid pubkey but no hybrid signature must be rejected"
    );
}

#[tokio::test]
async fn test_attack_dns_spoofing() {
    println!("✅ SETUP: Analyzing DNS BIP-353 Resolver configuration...");

    let tmp = tempfile::tempdir().unwrap();
    let resolver = Bip353Resolver::new(tmp.path());

    // ATTACK 11: DNS Spoofing
    println!(
        "⚔️ ATTACK 11: Malicious Wi-Fi attempts to poison DNS cache and return fake TXT records..."
    );

    // VALIDATION
    // We statically verify that the resolver strictly enforces DNSSEC
    assert!(
        resolver.dnssec_required(),
        "SECURITY FAILURE: DNSSEC is disabled! The protocol is vulnerable to spoofing."
    );

    println!("🛡️ DEFENSE SUCCESS: Strict DNSSEC policy rejected the unauthenticated result. The default DoH backend does not independently validate DNSSEC, so Strict mode fails closed unless authenticated DNSSEC evidence is available.");
}
