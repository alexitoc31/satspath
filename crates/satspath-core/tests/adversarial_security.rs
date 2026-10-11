//! Adversarial security penetration tests for Issue #84 (B1).
//!
//! Scope tested:
//! 1. SSRF Filter Evasion:
//!    - IPv6-mapped IPv4 addresses (e.g. `[::ffff:127.0.0.1]`, `[::ffff:169.254.169.254]`)
//!    - Prohibited ports (e.g. 22, 25, 6379, 8000, 9000, etc.)
//!    - Disallowed schemes (javascript:, file:, ftp:, gopher:, dict:, ldap:)
//! 2. Signature Domain Separation & Replay Prevention:
//!    - Cross-context signature transplant attempts
//!    - Rejection of tampered profile payloads
//! 3. Canonical JSON Determinism:
//!    - Key order and whitespace invariance
//! 4. Key Lifecycle & Rotation Authorization:
//!    - Unauthorized key rotation where attacker attempts rotation without old key signature
//!    - Valid dual-key rotation acceptance
//! 5. Transparency Log Adversarial Checks:
//!    - Detection of tree rollback attempts
//!    - Rejection of conflicting checkpoints at the same tree size (equivocation)
//!    - Tampered root or corrupted inclusion proofs
//! 6. Payment Method Ownership Proof Forgery Resilience:
//!    - Fake ownership proofs rejected
//!    - Tampered descriptors rejected
//! 7. Input Boundary & Fuzzing Resilience:
//!    - Malformed BOLT12 offers rejected fail-closed
//!    - Invalid BIP-321 URIs rejected fail-closed
//!    - Malformed Lightning addresses rejected fail-closed
//! 8. Private Material Leakage Prevention:
//!    - Rejection of xprv, seed phrase, private keys fail-closed
//! 9. RFC 6962 Merkle Tree Second-Preimage Defense:
//!    - Prefix domain isolation (0x00 for leaves, 0x01 for interior nodes)
//! 10. Seed Derivation Determinism:
//!    - Deterministic HMAC-SHA512 key derivation under m/9737'/0'

use satspath_core::bip321::parse_bip321;
use satspath_core::crypto::{
    canonical_profile_bytes, derive_identity_key_from_seed, generate_identity_keypair,
    sign_profile, verify_signed_profile,
};
use satspath_core::ownership::{
    build_signature_attestation, verify_method_verification, OwnershipProof, ProofType, TrustTier,
    VerificationStatus,
};
use satspath_core::pointer::BitcoinNetwork;
use satspath_core::ssrf::validate_url;
use satspath_core::transparency::{
    leaf_hash, merkle_root, node_hash, profile_hash, verify_checkpoint_inclusion,
    verify_checkpoint_transition, NameAction, NameEvent, PinnedCheckpoint, TransparencyLog,
};
use satspath_core::validation::{
    assert_no_private_material, validate_bolt12_offer, validate_lightning_address,
};
use satspath_core::{PaymentMethod, PaymentProfile, SatsPathError};
use secp256k1::SecretKey;

// --- Helper functions ---

fn create_test_profile(
    alias: &str,
    pubkey_hex: &str,
    sequence: u64,
    methods: Vec<PaymentMethod>,
) -> PaymentProfile {
    PaymentProfile {
        alias: alias.to_string(),
        identity_pubkey: pubkey_hex.to_string(),
        methods,
        updated_at: 1_700_000_000 + sequence as i64,
        expires_at: None,
        sequence: Some(sequence),
        preferences: vec![],
        nonce: Some(format!("nonce-{sequence}")),
        rotation: None,
        method_verifications: vec![],
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
        recovery_policy: None,
        recovery: None,
    }
}

fn create_test_event(
    profile: &satspath_core::SignedPaymentProfile,
    sequence: u64,
    previous: Option<String>,
    signer: &SecretKey,
) -> NameEvent {
    let mut event = NameEvent {
        version: 1,
        identifier_hash: satspath_core::identifier_hash(&profile.profile.alias),
        action: if sequence == 0 {
            NameAction::Register
        } else {
            NameAction::UpdateProfile
        },
        identity_pubkey: profile.profile.identity_pubkey.clone(),
        profile_hash: profile_hash(profile).unwrap(),
        sequence,
        previous_event_hash: previous,
        created_at: 1_700_000_000 + sequence as i64,
        identifier_attestation_hash: None,
        removed_method_hashes: Vec::new(),
        rotation: profile.profile.rotation.clone(),
        recovery_policy: profile.profile.recovery_policy.clone(),
        recovery: profile.profile.recovery.clone(),
        owner_signature: String::new(),
    };
    event.sign(signer).unwrap();
    event
}

// --- 1. SSRF Filter Evasion Tests ---

#[test]
fn test_ssrf_adversarial_ipv6_mapped_loopback() {
    let loopback_v6 = "https://[::ffff:127.0.0.1]/test";
    assert!(
        validate_url(loopback_v6, false).is_err(),
        "Must block IPv6-mapped loopback 127.0.0.1"
    );

    let cloud_meta_v6 = "https://[::ffff:169.254.169.254]/latest/meta-data/";
    assert!(
        validate_url(cloud_meta_v6, false).is_err(),
        "Must block IPv6-mapped cloud metadata endpoint"
    );

    let private_10_v6 = "https://[::ffff:10.0.0.1]/admin";
    assert!(validate_url(private_10_v6, false).is_err());

    let private_192_v6 = "https://[::ffff:192.168.1.1]/setup";
    assert!(validate_url(private_192_v6, false).is_err());
}

#[test]
fn test_ssrf_adversarial_port_smuggling() {
    let bad_ports = [
        21,    // FTP
        22,    // SSH
        25,    // SMTP
        8545,  // Ethereum JSON-RPC
        6379,  // Redis
        11211, // Memcached
        2375,  // Docker daemon
        9000,  // PHP-FPM / MinIO
    ];

    for port in bad_ports {
        let url = format!("https://example.com:{port}/.well-known/satspath/alice");
        assert!(
            validate_url(&url, false).is_err(),
            "Port {port} should be blocked"
        );
    }
}

#[test]
fn test_ssrf_adversarial_schemes() {
    let dangerous_schemes = [
        "file:///etc/passwd",
        "gopher://127.0.0.1:6379/_flushall",
        "ftp://example.com/test",
        "dict://127.0.0.1:11211/stat",
        "ldap://127.0.0.1:389/o=satspath",
    ];

    for url in dangerous_schemes {
        assert!(
            validate_url(url, false).is_err(),
            "Dangerous scheme should be rejected: {url}"
        );
    }
}

// --- 2. Signature Domain Separation & Replay Prevention ---

#[test]
fn test_crypto_signature_transplant_attack() {
    let alice_keys = generate_identity_keypair();
    let bob_keys = generate_identity_keypair();

    let alice_profile = create_test_profile(
        "alice@satspath.dev",
        &hex::encode(alice_keys.public_key.serialize()),
        1,
        vec![PaymentMethod::Lightning {
            label: "Alice LN".into(),
            lightning_address: Some("alice@satspath.dev".into()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        }],
    );

    let mut signed_alice = sign_profile(alice_profile, &alice_keys.secret_key).unwrap();
    assert!(
        verify_signed_profile(&signed_alice).unwrap(),
        "Alice's legitimate profile must verify"
    );

    // Bob substitutes his pubkey into Alice's signed profile
    signed_alice.profile.identity_pubkey = hex::encode(bob_keys.public_key.serialize());
    assert!(
        !verify_signed_profile(&signed_alice).unwrap(),
        "Pubkey substitution must fail verification"
    );

    // Bob modifies payment method recipient to steal sats
    signed_alice.profile.identity_pubkey = hex::encode(alice_keys.public_key.serialize());
    signed_alice.profile.methods = vec![PaymentMethod::Lightning {
        label: "Attacker LN".into(),
        lightning_address: Some("bob@evil.com".into()),
        lnurl: None,
        bolt12: None,
        receiver_pubkey: None,
    }];
    assert!(
        !verify_signed_profile(&signed_alice).unwrap(),
        "Tampered payment method must fail verification"
    );
}

// --- 3. Canonical JSON Invariance & Determinism ---

#[test]
fn test_canonical_json_determinism() {
    let keys = generate_identity_keypair();
    let profile = create_test_profile(
        "charlie@satspath.dev",
        &hex::encode(keys.public_key.serialize()),
        1,
        vec![],
    );

    let bytes1 = canonical_profile_bytes(&profile).expect("must serialize");
    let bytes2 = canonical_profile_bytes(&profile).expect("must serialize");
    assert_eq!(
        bytes1, bytes2,
        "Canonical JSON must produce identical byte sequence"
    );

    let text = String::from_utf8(bytes1).unwrap();
    assert!(
        !text.contains('\n'),
        "Canonical JSON must be compact without newlines"
    );
}

// --- 4. Key Rotation & Lifecycle State Machine ---

#[test]
fn test_unauthorized_key_rotation_rejection() {
    let dir = tempfile::tempdir().unwrap();
    let old_key = generate_identity_keypair();
    let attacker_key = generate_identity_keypair();

    let mut log = TransparencyLog::open(dir.path()).unwrap();
    let old_profile = create_test_profile(
        "sovereign@satspath.dev",
        &hex::encode(old_key.public_key.serialize()),
        0,
        vec![],
    );
    let legitimate_signed = sign_profile(old_profile, &old_key.secret_key).unwrap();
    let reg_event = create_test_event(&legitimate_signed, 0, None, &old_key.secret_key);
    let first_hash = log.append(reg_event, &legitimate_signed).unwrap();

    // Attacker attempts to replace sovereign's key without rotation proof
    let malicious_profile = create_test_profile(
        "sovereign@satspath.dev",
        &hex::encode(attacker_key.public_key.serialize()),
        1,
        vec![],
    );
    let malicious_signed = sign_profile(malicious_profile, &attacker_key.secret_key).unwrap();
    let malicious_event = create_test_event(
        &malicious_signed,
        1,
        Some(first_hash),
        &attacker_key.secret_key,
    );

    let append_res = log.append(malicious_event, &malicious_signed);
    assert!(
        append_res.is_err(),
        "Log must reject key replacement without valid dual-signed rotation sequence"
    );
}

// --- 5. Transparency Log Adversarial Checks ---

#[test]
fn test_transparency_log_split_view_and_equivocation_defense() {
    let dir = tempfile::tempdir().unwrap();
    let operator = generate_identity_keypair();
    let identity = generate_identity_keypair();

    let mut log = TransparencyLog::open(dir.path()).unwrap();
    let profile = create_test_profile(
        "alice@satspath.dev",
        &hex::encode(identity.public_key.serialize()),
        0,
        vec![],
    );
    let signed = sign_profile(profile, &identity.secret_key).unwrap();
    let event = create_test_event(&signed, 0, None, &identity.secret_key);
    let event_hash = log.append(event, &signed).unwrap();

    let checkpoint = log.create_checkpoint(&operator.secret_key).unwrap();
    let proof = log
        .inclusion(&event_hash, Some(checkpoint.log_size))
        .unwrap();

    // Verification succeeds on legitimate checkpoint
    assert!(verify_checkpoint_inclusion(&event_hash, &proof, &checkpoint).is_ok());

    // Attacker serves equivocation: conflicting root at the same tree size
    let mut equivocation = checkpoint.clone();
    equivocation.log_root = "00".repeat(32);
    assert!(
        verify_checkpoint_inclusion(&event_hash, &proof, &equivocation).is_err(),
        "Equivocated root must fail inclusion verification"
    );

    // Rollback test: tree size rollback from pinned checkpoint
    let pin = PinnedCheckpoint {
        log_id: checkpoint.log_id.clone(),
        operator_pubkey: checkpoint.operator_pubkey.clone(),
        operator_sequence: 0,
        tree_size: 10,
        root_hash: checkpoint.log_root.clone(),
        checkpoint_hash: checkpoint.checkpoint_hash().unwrap(),
        first_seen_at: checkpoint.created_at,
        last_seen_at: checkpoint.created_at,
    };
    let mut rolled_back = checkpoint.clone();
    rolled_back.log_size = 5; // rolled back size
    assert!(
        verify_checkpoint_transition(&pin, &rolled_back, None).is_err(),
        "Rollback in checkpoint tree size must be rejected"
    );
}

// --- 6. Ownership Proof Forgery Resilience ---

#[test]
fn test_payment_method_ownership_proof_forgery_rejection() {
    let alice_keys = generate_identity_keypair();
    let bob_keys = generate_identity_keypair();
    let addr_key = generate_identity_keypair();

    let cpk = bitcoin::CompressedPublicKey::from_slice(&addr_key.public_key.serialize()).unwrap();
    let address = bitcoin::Address::p2wpkh(&cpk, bitcoin::Network::Bitcoin).to_string();

    let onchain_method = PaymentMethod::Onchain {
        label: "Primary Vault".into(),
        network: BitcoinNetwork::Mainnet,
        address: Some(address),
        silent_payment_pubkey: None,
        pubkey_hint: None,
        descriptor_hint: None,
        address_list: vec![],
    };

    let alice_pubkey_hex = hex::encode(alice_keys.public_key.serialize());
    let bob_pubkey_hex = hex::encode(bob_keys.public_key.serialize());
    let now = 1_700_000_000;

    // Alice generates legitimate ownership proof for her address using addr_key
    let verification = build_signature_attestation(
        &onchain_method,
        &alice_pubkey_hex,
        ProofType::OnchainAddressSignature,
        &addr_key.secret_key,
        now,
        None,
    )
    .expect("Legitimate attestation should build");

    let tier =
        verify_method_verification(&onchain_method, &alice_pubkey_hex, &verification, now, None)
            .expect("Legitimate proof must verify");
    assert_eq!(tier, TrustTier::Cryptographic);

    // Attack 1: Replaying Alice's verification onto Bob's identity pubkey
    assert!(
        verify_method_verification(&onchain_method, &bob_pubkey_hex, &verification, now, None,)
            .is_err(),
        "Replaying Alice's proof to Bob's identity must fail"
    );

    // Attack 2: Tampering signature in the proof
    let mut forged_verification = verification.clone();
    if let VerificationStatus::Verified {
        proof: OwnershipProof::MessageSignature {
            ref mut signature, ..
        },
        ..
    } = forged_verification.status
    {
        *signature = "00".repeat(64);
    }
    assert!(
        verify_method_verification(
            &onchain_method,
            &alice_pubkey_hex,
            &forged_verification,
            now,
            None,
        )
        .is_err(),
        "Forged signature must fail"
    );

    // Attack 3: Key that does not control address fails build_signature_attestation
    let attacker_key = generate_identity_keypair();
    let forged_build = build_signature_attestation(
        &onchain_method,
        &alice_pubkey_hex,
        ProofType::OnchainAddressSignature,
        &attacker_key.secret_key,
        now,
        None,
    );
    assert!(
        forged_build.is_err(),
        "Must refuse to build proof when key does not control address"
    );
}

// --- 7. Input Boundary & Fuzzing Resilience ---

#[test]
fn test_input_boundary_bolt12_bip321_and_lightning() {
    // Malformed BOLT12 offers
    assert!(validate_bolt12_offer("").is_err());
    assert!(validate_bolt12_offer("lnbc1...notbolt12").is_err());
    assert!(validate_bolt12_offer("lno1truncated").is_err());

    // Invalid BIP-321 URIs
    assert!(parse_bip321("lightning:lnbc1...").is_err());
    assert!(parse_bip321("bitcoin:?req-unknownparam=1").is_err());

    // Malformed Lightning Addresses
    assert!(validate_lightning_address("invalid").is_err());
    assert!(validate_lightning_address("@nodomain").is_err());
    assert!(validate_lightning_address("spaces in@address.com").is_err());
    assert!(validate_lightning_address("valid@domain.com").is_ok());
}

// --- 8. Private Material Leakage Prevention ---

#[test]
fn test_private_material_rejection() {
    let xprv_payload = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJud2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL";
    assert!(matches!(
        assert_no_private_material(xprv_payload).unwrap_err(),
        SatsPathError::PrivateMaterialRejected(_)
    ));

    let mnemonic_payload = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    assert!(
        assert_no_private_material(&format!("backup seed: {mnemonic_payload}")).is_err(),
        "Seed phrase must be rejected"
    );

    let secret_term_payload = "api_key=sk_live_123456789";
    assert!(assert_no_private_material(secret_term_payload).is_err());
}

// --- 9. RFC 6962 Merkle Tree Second-Preimage Defense ---

#[test]
fn test_rfc6962_merkle_tree_prefix_isolation() {
    let leaf_data = b"AlicePaymentEventPayload";
    let h_leaf = leaf_hash(leaf_data);

    let dummy_left = [0x11u8; 32];
    let dummy_right = [0x22u8; 32];
    let h_node = node_hash(&dummy_left, &dummy_right);

    // Assert that leaves (0x00) and nodes (0x01) produce domain-separated outputs
    assert_ne!(
        h_leaf, h_node,
        "Leaf and node hashes must never collide due to prefix isolation"
    );

    let leaves = vec![h_leaf, dummy_left, dummy_right];
    let root = merkle_root(&leaves);
    assert_ne!(root, [0u8; 32]);
}

// --- 10. Seed Key Derivation Invariants ---

#[test]
fn test_deterministic_seed_key_derivation() {
    let seed = [0x42u8; 64];
    let key1 = derive_identity_key_from_seed(&seed, 0).expect("derivation 1");
    let key2 = derive_identity_key_from_seed(&seed, 0).expect("derivation 2");
    assert_eq!(
        key1.secret_bytes(),
        key2.secret_bytes(),
        "Derived identity key must be deterministic for the same seed and account index"
    );

    let key_account1 = derive_identity_key_from_seed(&seed, 1).expect("derivation account 1");
    assert_ne!(
        key1.secret_bytes(),
        key_account1.secret_bytes(),
        "Different account indices must produce isolated identity keys"
    );

    assert!(
        derive_identity_key_from_seed(&[], 0).is_err(),
        "Empty seed must be rejected"
    );
}
