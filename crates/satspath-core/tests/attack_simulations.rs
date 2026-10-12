use satspath_core::crypto::{generate_identity_keypair, sign_profile, verify_signed_profile};
use satspath_core::profile::{PaymentMethod, PaymentProfile};
use satspath_core::rotation::KeyRotation;

// Helper function to create a basic profile for a given pubkey
fn create_test_profile(alias: &str, pubkey_hex: &str, ln_address: &str) -> PaymentProfile {
    PaymentProfile {
        alias: alias.to_string(),
        identity_pubkey: pubkey_hex.to_string(),
        methods: vec![PaymentMethod::Lightning {
            label: "Lightning".into(),
            lightning_address: Some(ln_address.to_string()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
            // Since PaymentMethod doesn't have other required fields in the main enum variant we are using
        }],
        updated_at: chrono::Utc::now().timestamp(),
        expires_at: None,
        sequence: Some(1),
        preferences: vec![],
        nonce: Some(satspath_core::crypto::generate_nonce()),
        rotation: None,
        method_verifications: vec![],
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
        recovery_policy: None,
        recovery: None,
    }
}

#[test]
fn test_attack_payload_tampering() {
    // SETUP: Generate a new user (Alice)
    let alice_keys = generate_identity_keypair();
    let alice_pubkey_hex = hex::encode(alice_keys.public_key.serialize());

    // Alice creates her valid profile and signs it
    let alice_profile = create_test_profile(
        "alice@satspath.dev",
        &alice_pubkey_hex,
        "alice_real@lightning.node",
    );
    let mut signed_profile =
        sign_profile(alice_profile, &alice_keys.secret_key).expect("Failed to sign profile");

    // Validate that Alice's profile is initially valid
    assert!(
        verify_signed_profile(&signed_profile).expect("Verification failed"),
        "Alice's original profile should be valid"
    );

    println!("✅ SETUP: Alice's profile generated and signed successfully.");

    // ATTACK: A malicious server intercepts the signed profile and modifies the Lightning address
    println!("⚔️ ATTACK 1: Malicious server attempts to replace Lightning address...");
    if let Some(PaymentMethod::Lightning {
        ref mut lightning_address,
        ..
    }) = signed_profile.profile.methods.get_mut(0)
    {
        *lightning_address = Some("hacker_evil@lightning.node".to_string());
    }

    // VALIDATION: The receiver downloads this tampered profile and attempts to verify it.
    // The signature should fail because the payload was modified.
    let is_valid = verify_signed_profile(&signed_profile).unwrap_or(false);

    assert!(
        !is_valid,
        "SECURITY FAILURE: The tampered profile was accepted as valid!"
    );
    println!("🛡️ DEFENSE SUCCESS: The cryptographic signature rejected the tampered profile.");
}

#[test]
fn test_attack_unauthorized_key_rotation() {
    // SETUP: Generate a new user (Bob)
    let bob_keys = generate_identity_keypair();
    let bob_pubkey_hex = hex::encode(bob_keys.public_key.serialize());

    // Bob has an existing signed profile
    let bob_profile =
        create_test_profile("bob@satspath.dev", &bob_pubkey_hex, "bob@lightning.node");
    let _signed_bob_profile =
        sign_profile(bob_profile.clone(), &bob_keys.secret_key).expect("Failed to sign profile");

    println!("✅ SETUP: Bob's profile generated and signed successfully.");

    // ATTACK: Attacker generates a new keypair and tries to hijack Bob's alias via key rotation
    println!("⚔️ ATTACK 2: Attacker attempts an unauthorized key rotation...");
    let hacker_keys = generate_identity_keypair();
    let hacker_pubkey_hex = hex::encode(hacker_keys.public_key.serialize());

    // The attacker crafts a KeyRotation object but signs it with THEIR own private key,
    // because they don't have Bob's private key.
    let malicious_rotation = KeyRotation::create(
        satspath_core::privacy::identifier_hash("bob@satspath.dev"),
        bob_pubkey_hex.clone(),
        &hacker_keys.secret_key, // <-- Attacker signs with their key
        hacker_pubkey_hex.clone(),
        &hacker_keys.secret_key,
        "previous-event".into(),
        2,
    )
    .expect("Failed to create malicious rotation");

    // Attacker injects this rotation into a new version of Bob's profile
    let mut hijacked_profile = bob_profile.clone();
    hijacked_profile.identity_pubkey = hacker_pubkey_hex.clone();
    hijacked_profile.rotation = Some(malicious_rotation.clone());
    hijacked_profile.sequence = Some(2); // Bump sequence to make it look like an update

    // Attacker signs this new hijacked profile with their own key
    let signed_hijacked_profile = sign_profile(hijacked_profile, &hacker_keys.secret_key)
        .expect("Failed to sign hijacked profile");

    // VALIDATION: The protocol must check if the rotation is valid.
    // `is_rotation_valid` checks if the rotation was signed by the PREVIOUS pubkey (Bob's).
    let is_rotation_valid =
        satspath_core::rotation::is_rotation_valid(&signed_hijacked_profile).unwrap_or(false);

    assert!(
        !is_rotation_valid,
        "SECURITY FAILURE: The unauthorized key rotation was accepted!"
    );
    println!("🛡️ DEFENSE SUCCESS: The rotation was rejected because it was not signed by Bob's original key.");
}

#[test]
fn test_attack_rotation_proof_substitution() {
    let bob_keys = generate_identity_keypair();
    let bob_pubkey_hex = hex::encode(bob_keys.public_key.serialize());
    let bob_profile =
        create_test_profile("bob@satspath.dev", &bob_pubkey_hex, "bob@lightning.node");
    let signed_bob_profile =
        sign_profile(bob_profile.clone(), &bob_keys.secret_key).expect("Failed to sign profile");

    // Attacker generates two keypairs and creates an internally valid rotation proof between them
    let attacker_key1 = generate_identity_keypair();
    let attacker_pk1 = hex::encode(attacker_key1.public_key.serialize());
    let attacker_key2 = generate_identity_keypair();
    let attacker_pk2 = hex::encode(attacker_key2.public_key.serialize());

    let attacker_rotation = KeyRotation::create(
        satspath_core::privacy::identifier_hash("attacker@satspath.dev"),
        attacker_pk1.clone(),
        &attacker_key1.secret_key,
        attacker_pk2.clone(),
        &attacker_key2.secret_key,
        "prev-event".into(),
        2,
    )
    .expect("Valid attacker rotation");

    // Attacker rotation verifies on its own
    assert!(attacker_rotation.verify().unwrap());

    // ATTACK: Attacker injects their valid rotation proof into Bob's profile
    let mut hijacked_profile = signed_bob_profile.clone();
    hijacked_profile.profile.rotation = Some(attacker_rotation.clone());

    // Defense 1: is_rotation_valid MUST reject the foreign rotation proof
    let is_valid = satspath_core::rotation::is_rotation_valid(&hijacked_profile).unwrap();
    assert!(
        !is_valid,
        "SECURITY FAILURE: Foreign rotation proof accepted for Bob's profile!"
    );

    // Defense 2: get_effective_identity_pubkey MUST NOT switch to attacker's pubkey
    let effective_key =
        satspath_core::rotation::get_effective_identity_pubkey(&hijacked_profile).unwrap();
    assert_eq!(
        effective_key, bob_pubkey_hex,
        "SECURITY FAILURE: Effective pubkey hijacked by foreign rotation!"
    );

    // Defense 3: apply_key_rotation MUST fail
    let apply_res = satspath_core::rotation::apply_key_rotation(&hijacked_profile, &attacker_pk2);
    assert!(
        apply_res.is_err(),
        "SECURITY FAILURE: apply_key_rotation accepted foreign rotation proof!"
    );
}

#[tokio::test]
async fn test_attack_revoked_profile_rejection() {
    let alice_keys = generate_identity_keypair();
    let alice_pubkey_hex = hex::encode(alice_keys.public_key.serialize());
    let mut alice_profile = create_test_profile(
        "alice@satspath.dev",
        &alice_pubkey_hex,
        "alice@lightning.node",
    );
    alice_profile.revoked = true;
    let signed_revoked = sign_profile(alice_profile, &alice_keys.secret_key).unwrap();

    // 1. Registry::register_profile_for must reject registering an already-revoked profile
    let tmp = tempfile::tempdir().unwrap();
    let mut registry = satspath_core::registry::Registry::open(tmp.path()).unwrap();
    let reg_res = registry.register_profile(signed_revoked.clone());
    assert!(
        reg_res.is_err(),
        "Registry must reject registering a revoked profile"
    );

    // 2. ChainResolver must reject revoked profiles
    struct MockRevokedResolver {
        profile: satspath_core::SignedPaymentProfile,
    }
    #[async_trait::async_trait]
    impl satspath_core::resolver::ProfileResolver for MockRevokedResolver {
        async fn resolve_alias(
            &self,
            _alias: &str,
        ) -> satspath_core::Result<satspath_core::SignedPaymentProfile> {
            Ok(self.profile.clone())
        }
    }
    use satspath_core::resolver::ProfileResolver;
    let chain = satspath_core::resolver::ChainResolver::new().push(MockRevokedResolver {
        profile: signed_revoked,
    });
    let chain_res = chain.resolve_alias("alice@satspath.dev").await;
    assert!(
        chain_res.is_err(),
        "ChainResolver must reject revoked profiles"
    );
}

#[test]
fn test_attack_hybrid_pubkey_classical_mismatch() {
    let alice_keys = generate_identity_keypair();
    let alice_pubkey_hex = hex::encode(alice_keys.public_key.serialize());
    let rogue_keys = generate_identity_keypair();
    let rogue_pubkey_hex = hex::encode(rogue_keys.public_key.serialize());

    let hybrid_kp = satspath_pqc::hybrid_sig::generate_hybrid_keypair();
    let mut hybrid_pk = hybrid_kp.public_key();
    // Rogue substitution: classical_pubkey does not match Alice's identity pubkey
    hybrid_pk.classical_pubkey = rogue_pubkey_hex;

    let mut profile = create_test_profile(
        "alice@satspath.dev",
        &alice_pubkey_hex,
        "alice@lightning.node",
    );
    profile.hybrid_pubkey = Some(hybrid_pk);
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

    let signed = satspath_core::SignedPaymentProfile {
        profile,
        signature: hex::encode(schnorr_sig.serialize()),
        hybrid_signature: Some(hybrid_sig),
    };

    assert!(
        !verify_signed_profile(&signed).unwrap(),
        "verify_signed_profile must reject hybrid_pubkey whose classical key does not match identity_pubkey"
    );
}
