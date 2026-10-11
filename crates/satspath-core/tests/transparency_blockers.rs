use satspath_core::crypto::{generate_identity_keypair, sign_profile};
use satspath_core::registry::Registry;
use satspath_core::transparency::{
    profile_hash, verify_attestation_binding, verify_checkpoint_inclusion,
    verify_checkpoint_transition, IdentifierAttestation, IdentifierVerificationMethod, NameAction,
    NameEvent, PinnedCheckpoint, TransparencyError, TransparencyLog, TrustedVerifier,
};
use satspath_core::{
    verify_payment_method_states, PaymentMethod, PaymentProfile, SatsPathError,
    TransactionalTransparencyStore,
};

fn signed_profile(
    alias: &str,
    key: &satspath_core::IdentityKeypair,
    sequence: u64,
    methods: Vec<PaymentMethod>,
) -> satspath_core::SignedPaymentProfile {
    sign_profile(
        PaymentProfile {
            alias: alias.into(),
            identity_pubkey: hex::encode(key.public_key.serialize()),
            methods,
            updated_at: 1_800_000_000 + sequence as i64,
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
        },
        &key.secret_key,
    )
    .unwrap()
}

fn lightning(alias: &str) -> PaymentMethod {
    PaymentMethod::Lightning {
        label: "LN".into(),
        lightning_address: Some(alias.into()),
        lnurl: None,
        bolt12: None,
        receiver_pubkey: None,
    }
}

fn event(
    profile: &satspath_core::SignedPaymentProfile,
    sequence: u64,
    previous: Option<String>,
    signer: &secp256k1::SecretKey,
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
        created_at: 1_800_000_000 + sequence as i64,
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

#[test]
fn merkle_leaf_commits_to_complete_owner_signature() {
    let key = generate_identity_keypair();
    let profile = signed_profile(
        "alice@example.com",
        &key,
        0,
        vec![lightning("alice@example.com")],
    );
    let original = event(&profile, 0, None, &key.secret_key);
    let mut changed = original.clone();
    let first_two = &original.owner_signature[0..2];
    let new_prefix = if first_two == "00" { "ff" } else { "00" };
    changed.owner_signature.replace_range(0..2, new_prefix);
    assert_eq!(
        original.signing_payload_hash().unwrap(),
        changed.signing_payload_hash().unwrap()
    );
    assert_ne!(
        original.signed_event_hash().unwrap(),
        changed.signed_event_hash().unwrap()
    );
}

#[test]
fn checkpoint_inclusion_requires_exact_root_size_and_event_leaf() {
    let dir = tempfile::tempdir().unwrap();
    let identity = generate_identity_keypair();
    let operator = generate_identity_keypair();
    let profile = signed_profile(
        "alice@example.com",
        &identity,
        0,
        vec![lightning("alice@example.com")],
    );
    let mut log = TransparencyLog::open(dir.path()).unwrap();
    let hash = log
        .append(event(&profile, 0, None, &identity.secret_key), &profile)
        .unwrap();
    let checkpoint = log.create_checkpoint(&operator.secret_key).unwrap();
    let proof = log.inclusion(&hash, Some(checkpoint.log_size)).unwrap();
    verify_checkpoint_inclusion(&hash, &proof, &checkpoint).unwrap();

    let mut wrong_root = checkpoint.clone();
    wrong_root.log_root = "00".repeat(32);
    assert!(matches!(
        verify_checkpoint_inclusion(&hash, &proof, &wrong_root).unwrap_err(),
        SatsPathError::Transparency(TransparencyError::CheckpointInclusionMismatch)
    ));
    let mut wrong_size = checkpoint.clone();
    wrong_size.log_size += 1;
    assert!(verify_checkpoint_inclusion(&hash, &proof, &wrong_size).is_err());
    assert!(verify_checkpoint_inclusion(&"11".repeat(32), &proof, &checkpoint).is_err());
}

#[test]
fn oversized_inclusion_tree_size_returns_error_not_panic() {
    let dir = tempfile::tempdir().unwrap();
    let identity = generate_identity_keypair();
    let profile = signed_profile(
        "alice@example.com",
        &identity,
        0,
        vec![lightning("alice@example.com")],
    );
    let mut log = TransparencyLog::open(dir.path()).unwrap();
    let hash = log
        .append(event(&profile, 0, None, &identity.secret_key), &profile)
        .unwrap();
    assert!(log.inclusion(&hash, Some(0)).is_err());
    assert!(log.inclusion(&hash, Some(u64::MAX)).is_err());
}

#[test]
fn unexpected_operator_key_is_rejected_and_valid_rotation_is_accepted() {
    let dir = tempfile::tempdir().unwrap();
    let identity = generate_identity_keypair();
    let old_operator = generate_identity_keypair();
    let new_operator = generate_identity_keypair();
    let first_profile = signed_profile(
        "alice@example.com",
        &identity,
        0,
        vec![lightning("alice@example.com")],
    );
    let mut log = TransparencyLog::open(dir.path()).unwrap();
    let first_hash = log
        .append(
            event(&first_profile, 0, None, &identity.secret_key),
            &first_profile,
        )
        .unwrap();
    let first_checkpoint = log.create_checkpoint(&old_operator.secret_key).unwrap();
    let pin = PinnedCheckpoint {
        log_id: first_checkpoint.log_id.clone(),
        operator_pubkey: first_checkpoint.operator_pubkey.clone(),
        operator_sequence: 0,
        tree_size: first_checkpoint.log_size,
        root_hash: first_checkpoint.log_root.clone(),
        checkpoint_hash: first_checkpoint.checkpoint_hash().unwrap(),
        first_seen_at: first_checkpoint.created_at,
        last_seen_at: first_checkpoint.created_at,
    };
    let second_profile = signed_profile(
        "alice@example.com",
        &identity,
        1,
        vec![lightning("alice@example.com")],
    );
    log.append(
        event(&second_profile, 1, Some(first_hash), &identity.secret_key),
        &second_profile,
    )
    .unwrap();
    let mut unexpected = log.prepare_checkpoint(&new_operator.secret_key).unwrap();
    unexpected.operator_sequence = 0;
    unexpected.sign(&new_operator.secret_key).unwrap();
    assert!(matches!(
        verify_checkpoint_transition(&pin, &unexpected, Some(&log.consistency(1, 2).unwrap()))
            .unwrap_err(),
        SatsPathError::Transparency(TransparencyError::UnexpectedOperatorKey)
    ));

    let rotated = log
        .prepare_operator_rotation_checkpoint(&old_operator.secret_key, &new_operator.secret_key)
        .unwrap();
    verify_checkpoint_transition(&pin, &rotated, Some(&log.consistency(1, 2).unwrap())).unwrap();
}

#[test]
fn transaction_rejects_checkpoint_failure_without_appending_profile_or_event() {
    let dir = tempfile::tempdir().unwrap();
    let identity = generate_identity_keypair();
    let operator = generate_identity_keypair();
    let store = TransactionalTransparencyStore::open(dir.path()).unwrap();
    let profile = signed_profile(
        "alice@example.com",
        &identity,
        0,
        vec![lightning("alice@example.com")],
    );
    let log = store.load_log().unwrap();
    let event = event(&profile, 0, None, &identity.secret_key);
    let candidate = log.prepare_append(event.clone(), &profile).unwrap();
    let mut checkpoint = candidate.prepare_checkpoint(&operator.secret_key).unwrap();
    checkpoint.log_root = "00".repeat(32);
    checkpoint.sign(&operator.secret_key).unwrap();
    assert!(store
        .commit_profile_event_checkpoint("alice@example.com", &profile, &event, &checkpoint)
        .is_err());
    assert!(store.profile("alice@example.com").unwrap().is_none());
    assert!(store.load_log().unwrap().events().is_empty());
}

#[test]
fn registry_failure_does_not_append_event() {
    let dir = tempfile::tempdir().unwrap();
    let identity = generate_identity_keypair();
    let operator = generate_identity_keypair();
    let store = TransactionalTransparencyStore::open(dir.path()).unwrap();
    let profile = signed_profile(
        "alice@example.com",
        &identity,
        0,
        vec![lightning("alice@example.com")],
    );
    let log = store.load_log().unwrap();
    let event = event(&profile, 0, None, &identity.secret_key);
    let checkpoint = log
        .prepare_append(event.clone(), &profile)
        .unwrap()
        .prepare_checkpoint(&operator.secret_key)
        .unwrap();
    assert!(store
        .commit_profile_event_checkpoint("mallory@example.com", &profile, &event, &checkpoint)
        .is_err());
    assert!(store.load_log().unwrap().events().is_empty());
}

#[test]
fn profile_event_checkpoint_binding_and_sequence_alignment_are_required() {
    let dir = tempfile::tempdir().unwrap();
    let identity = generate_identity_keypair();
    let profile = signed_profile(
        "alice@example.com",
        &identity,
        0,
        vec![lightning("alice@example.com")],
    );
    let log = TransparencyLog::open(dir.path()).unwrap();
    let mut wrong_sequence = event(&profile, 0, None, &identity.secret_key);
    wrong_sequence.sequence = 1;
    wrong_sequence.sign(&identity.secret_key).unwrap();
    assert!(log.prepare_append(wrong_sequence, &profile).is_err());

    let mut wrong_profile = profile.clone();
    wrong_profile.profile.updated_at += 1;
    assert!(log
        .prepare_append(
            event(&profile, 0, None, &identity.secret_key),
            &wrong_profile
        )
        .is_err());
}

#[test]
fn invalid_and_duplicate_method_proofs_are_not_verified() {
    let identity = generate_identity_keypair();
    let mut profile = signed_profile(
        "alice@example.com",
        &identity,
        0,
        vec![lightning("alice@example.com")],
    )
    .profile;
    let descriptor = profile.methods[0].ownership_descriptor();
    let invalid = satspath_core::MethodVerification {
        method_descriptor: descriptor,
        status: satspath_core::VerificationStatus::Unverified,
    };
    profile.method_verifications = vec![invalid.clone(), invalid];
    let states = verify_payment_method_states(&profile, 1_800_000_001);
    assert_eq!(states.len(), 1);
    assert!(!states[0].verified);
    assert!(states[0].reason.contains("duplicate"));

    profile.method_verifications = vec![satspath_core::MethodVerification {
        method_descriptor: "ln-address:mallory@example.com".into(),
        status: satspath_core::VerificationStatus::Unverified,
    }];
    let wrong_descriptor = verify_payment_method_states(&profile, 1_800_000_001);
    assert!(!wrong_descriptor[0].verified);
    assert!(wrong_descriptor[0].reason.contains("missing"));
}

#[test]
fn identifier_attestation_requires_exact_binding_and_trusted_verifier() {
    let identity = generate_identity_keypair();
    let verifier = generate_identity_keypair();
    let profile = signed_profile(
        "alice@example.com",
        &identity,
        0,
        vec![lightning("alice@example.com")],
    );
    let mut event = event(&profile, 0, None, &identity.secret_key);
    let mut attestation = IdentifierAttestation {
        version: 1,
        identifier_hash: event.identifier_hash.clone(),
        identity_pubkey: event.identity_pubkey.clone(),
        profile_hash: event.profile_hash.clone(),
        nonce: "ab".repeat(16),
        issued_at: 1_800_000_000,
        expires_at: 1_800_001_000,
        method: IdentifierVerificationMethod::Email,
        verifier_pubkey: hex::encode(verifier.public_key.serialize()),
        verifier_signature: String::new(),
    };
    attestation.sign(&verifier.secret_key).unwrap();
    event.identifier_attestation_hash = Some(attestation.attestation_hash().unwrap());
    event.sign(&identity.secret_key).unwrap();
    assert!(!verify_attestation_binding(&attestation, &event, &[], 1_800_000_001).unwrap());
    let trusted = [TrustedVerifier {
        verifier_id: "test-email-verifier".into(),
        public_key: attestation.verifier_pubkey.clone(),
        allowed_methods: vec![IdentifierVerificationMethod::Email],
    }];
    assert!(verify_attestation_binding(&attestation, &event, &trusted, 1_800_000_001).unwrap());
    let mut wrong_profile = attestation;
    wrong_profile.profile_hash = "00".repeat(32);
    assert!(!verify_attestation_binding(&wrong_profile, &event, &trusted, 1_800_000_001).unwrap());
}

#[test]
fn authorized_owner_can_remove_compromised_payment_method() {
    let dir = tempfile::tempdir().unwrap();
    let identity = generate_identity_keypair();
    let mut registry = Registry::open(dir.path()).unwrap();
    let first = signed_profile(
        "alice@example.com",
        &identity,
        0,
        vec![
            lightning("alice@example.com"),
            lightning("backup@example.com"),
        ],
    );
    registry.register_profile(first).unwrap();
    let second = signed_profile(
        "alice@example.com",
        &identity,
        1,
        vec![lightning("alice@example.com")],
    );
    registry.update_profile(second).unwrap();
    assert_eq!(
        registry
            .resolve_alias("alice@example.com")
            .unwrap()
            .profile
            .methods
            .len(),
        1
    );
}

fn two_checkpoint_log(
    dir: &std::path::Path,
) -> (
    secp256k1::SecretKey,
    Vec<satspath_core::TransparencyCheckpoint>,
) {
    let identity = generate_identity_keypair();
    let operator = generate_identity_keypair();
    let mut log = TransparencyLog::open(dir).unwrap();
    let first = signed_profile(
        "alice@example.com",
        &identity,
        0,
        vec![lightning("alice@example.com")],
    );
    let first_hash = log
        .append(event(&first, 0, None, &identity.secret_key), &first)
        .unwrap();
    log.create_checkpoint(&operator.secret_key).unwrap();
    let second = signed_profile(
        "alice@example.com",
        &identity,
        1,
        vec![lightning("alice@example.com")],
    );
    log.append(
        event(&second, 1, Some(first_hash), &identity.secret_key),
        &second,
    )
    .unwrap();
    log.create_checkpoint(&operator.secret_key).unwrap();
    (operator.secret_key, log.checkpoints().to_vec())
}

fn write_checkpoints(dir: &std::path::Path, checkpoints: &[satspath_core::TransparencyCheckpoint]) {
    std::fs::write(
        dir.join("transparency-checkpoints-v1.json"),
        serde_json::to_vec_pretty(checkpoints).unwrap(),
    )
    .unwrap();
}

#[test]
fn tampered_checkpoint_signature_fails_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let (_, mut checkpoints) = two_checkpoint_log(dir.path());
    let first_two = &checkpoints[1].operator_signature[0..2];
    let new_prefix = if first_two == "00" { "ff" } else { "00" };
    checkpoints[1]
        .operator_signature
        .replace_range(0..2, new_prefix);
    write_checkpoints(dir.path(), &checkpoints);
    assert!(TransparencyLog::open(dir.path()).is_err());
}

#[test]
fn tampered_checkpoint_root_fails_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let (operator, mut checkpoints) = two_checkpoint_log(dir.path());
    checkpoints[1].log_root = "00".repeat(32);
    checkpoints[1].sign(&operator).unwrap();
    write_checkpoints(dir.path(), &checkpoints);
    assert!(TransparencyLog::open(dir.path()).is_err());
}

#[test]
fn tampered_previous_checkpoint_hash_fails_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let (operator, mut checkpoints) = two_checkpoint_log(dir.path());
    checkpoints[1].previous_checkpoint_hash = Some("11".repeat(32));
    checkpoints[1].sign(&operator).unwrap();
    write_checkpoints(dir.path(), &checkpoints);
    assert!(TransparencyLog::open(dir.path()).is_err());
}

#[test]
fn conflicting_checkpoint_same_size_fails_on_open() {
    let dir = tempfile::tempdir().unwrap();
    let (operator, mut checkpoints) = two_checkpoint_log(dir.path());
    let mut conflict = checkpoints[1].clone();
    conflict.previous_checkpoint_hash = Some(checkpoints[1].checkpoint_hash().unwrap());
    conflict.created_at += 1;
    conflict.sign(&operator).unwrap();
    checkpoints.push(conflict);
    write_checkpoints(dir.path(), &checkpoints);
    assert!(TransparencyLog::open(dir.path()).is_err());
}
