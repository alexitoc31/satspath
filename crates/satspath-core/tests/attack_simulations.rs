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
