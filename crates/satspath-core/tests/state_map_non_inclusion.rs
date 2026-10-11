use satspath_core::crypto::{generate_identity_keypair, sign_profile};
use satspath_core::transparency::{
    empty_hash, profile_hash, verify_checkpoint, verify_checkpoint_state_binding,
    verify_state_map_proof, IdentifierStatus, NameAction, NameEvent, SparseMerkleTree,
    StateMapValue, TransparencyCheckpoint, TransparencyLog,
};
use satspath_core::PaymentProfile;
use secp256k1::Secp256k1;
use tempfile::tempdir;

#[test]
fn test_empty_state_map_non_inclusion_proof() {
    let tree = SparseMerkleTree::new();
    let root = tree.root_hex();
    assert_eq!(root, hex::encode(empty_hash(0)));

    let nonexistent_key = [0x42u8; 32];
    let proof = tree.prove(&nonexistent_key);

    assert!(proof.value.is_none());
    assert_eq!(proof.audit_path.len(), 256);
    assert_eq!(proof.key_hash, hex::encode(nonexistent_key));

    // Non-inclusion proof verifies successfully against empty root
    assert!(proof.verify(&root).expect("verify non-inclusion"));
    assert!(verify_state_map_proof(&proof, &root).expect("verify helper"));

    // Fails against wrong root
    let wrong_root = "1111111111111111111111111111111111111111111111111111111111111111";
    assert!(!proof.verify(wrong_root).expect("verify wrong root"));
}

#[test]
fn test_multi_identifier_population_updates_and_non_inclusion() {
    let mut tree = SparseMerkleTree::new();

    let alice_key = [0x01u8; 32];
    let bob_key = [0x02u8; 32];
    let charlie_key = [0x03u8; 32];
    let unregistered_key = [0x99u8; 32];

    // 1. Register alice and bob
    tree.insert(
        alice_key,
        StateMapValue {
            latest_event_hash: "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"
                .into(),
            sequence: 0,
            status: IdentifierStatus::Registered,
        },
    );
    tree.insert(
        bob_key,
        StateMapValue {
            latest_event_hash: "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222"
                .into(),
            sequence: 0,
            status: IdentifierStatus::Registered,
        },
    );

    let root_v1 = tree.root_hex();

    // 2. Alice has valid inclusion proof
    let alice_proof_v1 = tree.prove(&alice_key);
    assert!(alice_proof_v1.value.is_some());
    assert_eq!(alice_proof_v1.value.as_ref().unwrap().sequence, 0);
    assert!(alice_proof_v1.verify(&root_v1).expect("alice v1"));

    // 3. Charlie is unregistered: non-inclusion proof passes
    let charlie_proof_v1 = tree.prove(&charlie_key);
    assert!(charlie_proof_v1.value.is_none());
    assert!(charlie_proof_v1
        .verify(&root_v1)
        .expect("charlie non-inc v1"));

    // 4. Update Alice to sequence 1 and register Charlie
    tree.insert(
        alice_key,
        StateMapValue {
            latest_event_hash: "aaaa3333aaaa3333aaaa3333aaaa3333aaaa3333aaaa3333aaaa3333aaaa3333"
                .into(),
            sequence: 1,
            status: IdentifierStatus::Registered,
        },
    );
    tree.insert(
        charlie_key,
        StateMapValue {
            latest_event_hash: "cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333cccc3333"
                .into(),
            sequence: 0,
            status: IdentifierStatus::Registered,
        },
    );

    // 5. Revoke Bob
    tree.insert(
        bob_key,
        StateMapValue {
            latest_event_hash: "bbbb4444bbbb4444bbbb4444bbbb4444bbbb4444bbbb4444bbbb4444bbbb4444"
                .into(),
            sequence: 1,
            status: IdentifierStatus::Revoked,
        },
    );

    let root_v2 = tree.root_hex();
    assert_ne!(root_v1, root_v2);

    // Alice v2 inclusion proof
    let alice_proof_v2 = tree.prove(&alice_key);
    assert_eq!(alice_proof_v2.value.as_ref().unwrap().sequence, 1);
    assert!(alice_proof_v2.verify(&root_v2).expect("alice v2"));

    // Old Alice v1 proof does NOT verify against root_v2
    assert!(!alice_proof_v1
        .verify(&root_v2)
        .expect("alice v1 against v2"));

    // Bob revoked inclusion proof
    let bob_proof_v2 = tree.prove(&bob_key);
    assert_eq!(
        bob_proof_v2.value.as_ref().unwrap().status,
        IdentifierStatus::Revoked
    );
    assert!(bob_proof_v2.verify(&root_v2).expect("bob revoked v2"));

    // Charlie is now registered: inclusion proof passes
    let charlie_proof_v2 = tree.prove(&charlie_key);
    assert!(charlie_proof_v2.value.is_some());
    assert!(charlie_proof_v2.verify(&root_v2).expect("charlie inc v2"));

    // Unregistered key non-inclusion proof passes
    let unreg_proof = tree.prove(&unregistered_key);
    assert!(unreg_proof.value.is_none());
    assert!(unreg_proof.verify(&root_v2).expect("unregistered non-inc"));

    // Attempting to forge inclusion for unregistered key fails
    let mut fake_inc = unreg_proof.clone();
    fake_inc.value = Some(StateMapValue {
        latest_event_hash: "9999999999999999999999999999999999999999999999999999999999999999"
            .into(),
        sequence: 0,
        status: IdentifierStatus::Registered,
    });
    assert!(!fake_inc.verify(&root_v2).expect("fake inc"));
}

#[test]
fn test_checkpoint_map_root_binding_and_backward_compatibility() {
    let secp = Secp256k1::new();
    let (operator_sk, _) = secp.generate_keypair(&mut rand::thread_rng());

    let dir = tempdir().expect("tempdir");
    let mut log = TransparencyLog::open(dir.path()).expect("open log");

    // Add a registration event
    let key = generate_identity_keypair();
    let signed = sign_profile(
        PaymentProfile {
            alias: "alice@example.com".into(),
            identity_pubkey: hex::encode(key.public_key.serialize()),
            methods: vec![],
            updated_at: 1_700_000_000,
            expires_at: None,
            sequence: Some(0),
            preferences: vec![],
            nonce: Some("nonce-0".into()),
            rotation: None,
            method_verifications: vec![],
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
            recovery_policy: None,
            recovery: None,
        },
        &key.secret_key,
    )
    .expect("sign profile");

    let mut event = NameEvent {
        version: 1,
        identifier_hash: satspath_core::privacy::identifier_hash(&signed.profile.alias),
        action: NameAction::Register,
        identity_pubkey: signed.profile.identity_pubkey.clone(),
        profile_hash: profile_hash(&signed).expect("profile hash"),
        sequence: 0,
        previous_event_hash: None,
        created_at: 1_700_000_000,
        identifier_attestation_hash: None,
        removed_method_hashes: Vec::new(),
        rotation: None,
        recovery_policy: None,
        recovery: None,
        owner_signature: String::new(),
    };
    event.sign(&key.secret_key).expect("sign event");
    log.append(event.clone(), &signed).expect("append event");

    // Create checkpoint with map_root populated
    let checkpoint = log
        .create_checkpoint(&operator_sk)
        .expect("create checkpoint");
    assert!(checkpoint.map_root.is_some());
    let map_root = checkpoint.map_root.as_ref().unwrap();
    assert_eq!(map_root.len(), 64);

    // Checkpoint signature verifies
    assert!(verify_checkpoint(&checkpoint).expect("verify checkpoint"));

    // State proof for registered identifier binds to checkpoint map_root
    let reg_proof = log
        .prove_state(&event.identifier_hash)
        .expect("prove registered");
    assert!(reg_proof.value.is_some());
    assert!(verify_checkpoint_state_binding(&reg_proof, &checkpoint).is_ok());

    // Non-inclusion proof for unregistered identifier binds to checkpoint map_root
    let unreg_hash = "3333333333333333333333333333333333333333333333333333333333333333";
    let unreg_proof = log.prove_state(unreg_hash).expect("prove unregistered");
    assert!(unreg_proof.value.is_none());
    assert!(verify_checkpoint_state_binding(&unreg_proof, &checkpoint).is_ok());

    // Tampering with map_root invalidates checkpoint signature
    let mut tampered_checkpoint = checkpoint.clone();
    tampered_checkpoint.map_root =
        Some("4444444444444444444444444444444444444444444444444444444444444444".into());
    assert!(!verify_checkpoint(&tampered_checkpoint).expect("tampered verify"));

    // Backward compatibility: checkpoint with map_root = None verifies cleanly
    let mut legacy_checkpoint = TransparencyCheckpoint {
        version: 1,
        log_id: log.log_id().to_string(),
        log_size: 1,
        log_root: checkpoint.log_root.clone(),
        map_root: None,
        previous_checkpoint_hash: None,
        created_at: 1000,
        operator_pubkey: checkpoint.operator_pubkey.clone(),
        operator_sequence: 0,
        operator_rotation: None,
        operator_signature: String::new(),
        bitcoin_anchor: None,
    };
    legacy_checkpoint.sign(&operator_sk).expect("sign legacy");
    assert!(verify_checkpoint(&legacy_checkpoint).expect("verify legacy checkpoint"));
}
