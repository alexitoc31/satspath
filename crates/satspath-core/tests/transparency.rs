use satspath_core::crypto::{generate_identity_keypair, sign_profile};
use satspath_core::transparency::{
    profile_hash, verify_checkpoint, verify_checkpoint_transition, verify_consistency_proof,
    verify_event_transition, verify_identifier_history, verify_inclusion_proof, CheckpointStore,
    NameAction, NameEvent, PinnedCheckpoint, TransparencyError, TransparencyLog,
};
use satspath_core::{KeyRotation, PaymentMethod, PaymentProfile, SatsPathError};

fn profile(
    alias: &str,
    key: &satspath_core::IdentityKeypair,
    sequence: u64,
) -> satspath_core::SignedPaymentProfile {
    sign_profile(
        PaymentProfile {
            alias: alias.into(),
            identity_pubkey: hex::encode(key.public_key.serialize()),
            methods: vec![PaymentMethod::Lightning {
                label: "LN".into(),
                lightning_address: Some(alias.into()),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: None,
            }],
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
        },
        &key.secret_key,
    )
    .unwrap()
}

fn event(
    signed: &satspath_core::SignedPaymentProfile,
    action: NameAction,
    sequence: u64,
    previous: Option<String>,
    signer: &secp256k1::SecretKey,
) -> NameEvent {
    let mut event = NameEvent {
        version: 1,
        identifier_hash: satspath_core::privacy::identifier_hash(&signed.profile.alias),
        action,
        identity_pubkey: signed.profile.identity_pubkey.clone(),
        profile_hash: profile_hash(signed).unwrap(),
        sequence,
        previous_event_hash: previous,
        created_at: 1_700_000_000 + sequence as i64,
        identifier_attestation_hash: None,
        removed_method_hashes: Vec::new(),
        rotation: signed.profile.rotation.clone(),
        recovery_policy: signed.profile.recovery_policy.clone(),
        recovery: signed.profile.recovery.clone(),
        owner_signature: String::new(),
    };
    event.sign(signer).unwrap();
    event
}

#[test]
fn deterministic_event_hash_and_canonicalization() {
    let key = generate_identity_keypair();
    let signed = profile("alice@example.com", &key, 0);
    let event = event(&signed, NameAction::Register, 0, None, &key.secret_key);
    assert_eq!(event.event_hash().unwrap(), event.event_hash().unwrap());
    assert!(
        !String::from_utf8(event.unsigned_canonical_bytes().unwrap())
            .unwrap()
            .contains("alice@example.com")
    );
}

#[test]
fn inclusion_and_consistency_cover_arbitrary_sizes_and_reject_mutation() {
    for size in 1..=32 {
        let dir = tempfile::tempdir().unwrap();
        let key = generate_identity_keypair();
        let mut log = TransparencyLog::open(dir.path()).unwrap();
        let mut previous = None;
        for sequence in 0..size {
            let signed = profile("alice@example.com", &key, sequence as u64);
            let e = event(
                &signed,
                if sequence == 0 {
                    NameAction::Register
                } else {
                    NameAction::UpdateProfile
                },
                sequence as u64,
                previous,
                &key.secret_key,
            );
            previous = Some(log.append(e, &signed).unwrap());
        }
        for index in 0..size {
            let hash = log.events()[index].event_hash().unwrap();
            let proof = log.inclusion(&hash, None).unwrap();
            assert!(
                verify_inclusion_proof(&proof).unwrap(),
                "size={size} index={index}"
            );
            let mut modified = proof.clone();
            let replacement = if modified.root_hash.starts_with("00") {
                "01"
            } else {
                "00"
            };
            modified.root_hash.replace_range(0..2, replacement);
            assert!(!verify_inclusion_proof(&modified).unwrap());
            if !proof.audit_path.is_empty() {
                let mut truncated = proof.clone();
                truncated.audit_path.pop();
                assert!(!verify_inclusion_proof(&truncated).unwrap());
            }
        }
        if size > 1 {
            let proof = log.consistency(1, size as u64).unwrap();
            assert_eq!(proof.version, 2);
            assert!(verify_consistency_proof(&proof).unwrap());
            if proof.audit_path.len() >= 2 {
                let mut reordered = proof.clone();
                reordered.audit_path.swap(0, 1);
                assert!(!verify_consistency_proof(&reordered).unwrap());
            }

            // Test invalid roots
            let mut bad_root = proof.clone();
            bad_root.old_root = bad_root.new_root.clone();
            assert!(!verify_consistency_proof(&bad_root).unwrap());
        }
    }
}

#[test]
fn test_rfc6962_compact_consistency_verification_logic() {
    // Manually construct leaves to verify the compact V2 verifier
    use satspath_core::transparency::{
        consistency_proof, leaf_hash, merkle_root, verify_consistency,
    };
    let leaves: Vec<[u8; 32]> = (0..8).map(|i| leaf_hash(&[i])).collect();

    for old_size in 1..=8 {
        for new_size in old_size..=8 {
            let old_root = merkle_root(&leaves[..old_size]);
            let new_root = merkle_root(&leaves[..new_size]);
            let proof = consistency_proof(&leaves[..new_size], old_size).unwrap();

            // Should be valid
            assert!(verify_consistency(
                old_size as u64,
                new_size as u64,
                &old_root,
                &new_root,
                &proof
            )
            .unwrap());

            // Should fail with corrupted proof
            if !proof.is_empty() {
                let mut corrupted = proof.clone();
                corrupted[0][0] ^= 1;
                assert!(!verify_consistency(
                    old_size as u64,
                    new_size as u64,
                    &old_root,
                    &new_root,
                    &corrupted
                )
                .unwrap());
            }
        }
    }
}

#[test]
fn rotation_requires_old_authorization_and_new_acceptance() {
    let old = generate_identity_keypair();
    let new = generate_identity_keypair();
    let first_profile = profile("alice@example.com", &old, 0);
    let first = event(
        &first_profile,
        NameAction::Register,
        0,
        None,
        &old.secret_key,
    );
    let previous = first.event_hash().unwrap();
    let mut rotated_profile = profile("alice@example.com", &new, 1);
    let rotation = KeyRotation::create(
        satspath_core::privacy::identifier_hash("alice@example.com"),
        first_profile.profile.identity_pubkey.clone(),
        &old.secret_key,
        rotated_profile.profile.identity_pubkey.clone(),
        &new.secret_key,
        previous.clone(),
        1,
    )
    .unwrap();
    rotated_profile.profile.rotation = Some(rotation);
    rotated_profile = sign_profile(rotated_profile.profile, &new.secret_key).unwrap();
    let rotated = event(
        &rotated_profile,
        NameAction::RotateKey,
        1,
        Some(previous),
        &old.secret_key,
    );
    assert!(verify_identifier_history(&[first.clone(), rotated.clone()]).is_ok());

    let mut no_acceptance = rotated.clone();
    no_acceptance
        .rotation
        .as_mut()
        .unwrap()
        .acceptance_signature
        .clear();
    no_acceptance.sign(&old.secret_key).unwrap();
    assert!(matches!(
        verify_identifier_history(&[first, no_acceptance]).unwrap_err(),
        SatsPathError::Transparency(TransparencyError::InvalidRotation(_))
    ));
}

#[test]
fn checkpoint_signature_pinning_rollback_and_equivocation() {
    let dir = tempfile::tempdir().unwrap();
    let owner = generate_identity_keypair();
    let operator = generate_identity_keypair();
    let signed = profile("alice@example.com", &owner, 0);
    let mut log = TransparencyLog::open(dir.path()).unwrap();
    log.append(
        event(&signed, NameAction::Register, 0, None, &owner.secret_key),
        &signed,
    )
    .unwrap();
    let checkpoint = log.create_checkpoint(&operator.secret_key).unwrap();
    assert!(verify_checkpoint(&checkpoint).unwrap());
    let pin = CheckpointStore::new(dir.path()).pin(&checkpoint).unwrap();

    let mut conflict = checkpoint.clone();
    conflict.log_root = "00".repeat(32);
    conflict.sign(&operator.secret_key).unwrap();
    assert!(matches!(
        verify_checkpoint_transition(&pin, &conflict, None).unwrap_err(),
        SatsPathError::Transparency(TransparencyError::ConflictingCheckpoint)
    ));
    let rollback = PinnedCheckpoint {
        tree_size: 2,
        ..pin
    };
    assert!(matches!(
        verify_checkpoint_transition(&rollback, &checkpoint, None).unwrap_err(),
        SatsPathError::Transparency(TransparencyError::CheckpointRollback)
    ));
}

#[test]
fn recovery_is_disabled_and_updates_after_revocation_fail() {
    let key = generate_identity_keypair();
    let signed = profile("alice@example.com", &key, 0);
    let register = event(&signed, NameAction::Register, 0, None, &key.secret_key);
    let revoke = event(
        &signed,
        NameAction::Revoke,
        1,
        Some(register.event_hash().unwrap()),
        &key.secret_key,
    );
    let update = event(
        &signed,
        NameAction::UpdateProfile,
        2,
        Some(revoke.event_hash().unwrap()),
        &key.secret_key,
    );
    assert!(matches!(
        verify_identifier_history(&[register, revoke, update]).unwrap_err(),
        SatsPathError::Transparency(TransparencyError::IdentifierRevoked)
    ));
}

#[test]
fn recovery_without_policy_fails_with_recovery_disabled() {
    let key = generate_identity_keypair();
    let signed = profile("alice@example.com", &key, 0);
    let register = event(&signed, NameAction::Register, 0, None, &key.secret_key);

    let new_key = generate_identity_keypair();
    let mut recover_event = event(
        &signed,
        NameAction::RecoverKey,
        1,
        Some(register.event_hash().unwrap()),
        &new_key.secret_key,
    );
    recover_event.identity_pubkey = hex::encode(new_key.public_key.serialize());

    assert!(matches!(
        verify_identifier_history(&[register, recover_event]).unwrap_err(),
        SatsPathError::Transparency(TransparencyError::RecoveryDisabled)
    ));
}

#[test]
fn recovery_with_valid_policy_and_proof_succeeds() {
    use satspath_core::recovery::{sign_guardian_authorization, KeyRecoveryProof, RecoveryPolicy};

    let key = generate_identity_keypair();
    let g1 = generate_identity_keypair();
    let g2 = generate_identity_keypair();

    let policy = RecoveryPolicy::new(
        2,
        vec![
            hex::encode(g1.public_key.serialize()),
            hex::encode(g2.public_key.serialize()),
        ],
    )
    .unwrap();

    let mut reg_profile = profile("alice@example.com", &key, 0);
    reg_profile.profile.recovery_policy = Some(policy.clone());
    let signed_reg = sign_profile(reg_profile.profile, &key.secret_key).unwrap();

    let mut register = event(&signed_reg, NameAction::Register, 0, None, &key.secret_key);
    register.recovery_policy = Some(policy.clone());
    register.sign(&key.secret_key).unwrap();

    let new_key = generate_identity_keypair();
    let id_hash = satspath_core::privacy::identifier_hash("alice@example.com");
    let prev_pk = hex::encode(key.public_key.serialize());
    let new_pk = hex::encode(new_key.public_key.serialize());
    let prev_event_hash = register.event_hash().unwrap();
    let now_ts = 1_700_000_100;

    let s1 = sign_guardian_authorization(
        &id_hash,
        &prev_pk,
        &new_pk,
        &prev_event_hash,
        1,
        now_ts,
        &g1.secret_key,
    );
    let s2 = sign_guardian_authorization(
        &id_hash,
        &prev_pk,
        &new_pk,
        &prev_event_hash,
        1,
        now_ts,
        &g2.secret_key,
    );

    let proof = KeyRecoveryProof::create(
        id_hash.clone(),
        prev_pk.clone(),
        new_pk.clone(),
        &new_key.secret_key,
        prev_event_hash.clone(),
        1,
        now_ts,
        vec![s1, s2],
    )
    .unwrap();

    let mut rec_profile = profile("alice@example.com", &new_key, 1);
    rec_profile.profile.identity_pubkey = new_pk.clone();
    rec_profile.profile.recovery = Some(proof.clone());
    rec_profile.profile.recovery_policy = Some(policy.clone());
    let signed_rec = sign_profile(rec_profile.profile, &new_key.secret_key).unwrap();

    let mut rec_event = NameEvent {
        version: 1,
        identifier_hash: id_hash,
        action: NameAction::RecoverKey,
        identity_pubkey: new_pk,
        profile_hash: profile_hash(&signed_rec).unwrap(),
        sequence: 1,
        previous_event_hash: Some(prev_event_hash),
        created_at: now_ts,
        identifier_attestation_hash: None,
        removed_method_hashes: Vec::new(),
        rotation: None,
        recovery_policy: Some(policy.clone()),
        recovery: Some(proof),
        owner_signature: String::new(),
    };
    rec_event.sign(&new_key.secret_key).unwrap();

    assert!(verify_identifier_history(&[register.clone(), rec_event.clone()]).is_ok());

    let dir = tempfile::tempdir().unwrap();
    let mut log = TransparencyLog::open(dir.path()).unwrap();
    log.append(register, &signed_reg).unwrap();
    assert!(log.append(rec_event, &signed_rec).is_ok());
}

#[test]
fn recovery_cannot_supply_its_own_policy_if_none_was_precommitted() {
    use satspath_core::recovery::{sign_guardian_authorization, KeyRecoveryProof, RecoveryPolicy};

    let key = generate_identity_keypair();
    let signed_reg = profile("alice@example.com", &key, 0);
    let register = event(&signed_reg, NameAction::Register, 0, None, &key.secret_key);

    let g1 = generate_identity_keypair();
    let attacker_policy =
        RecoveryPolicy::new(1, vec![hex::encode(g1.public_key.serialize())]).unwrap();

    let new_key = generate_identity_keypair();
    let id_hash = satspath_core::privacy::identifier_hash("alice@example.com");
    let prev_pk = hex::encode(key.public_key.serialize());
    let new_pk = hex::encode(new_key.public_key.serialize());
    let prev_event_hash = register.event_hash().unwrap();
    let now_ts = 1_700_000_100;

    let s1 = sign_guardian_authorization(
        &id_hash,
        &prev_pk,
        &new_pk,
        &prev_event_hash,
        1,
        now_ts,
        &g1.secret_key,
    );
    let proof = KeyRecoveryProof::create(
        id_hash.clone(),
        prev_pk,
        new_pk.clone(),
        &new_key.secret_key,
        prev_event_hash.clone(),
        1,
        now_ts,
        vec![s1],
    )
    .unwrap();

    let mut rec_profile = profile("alice@example.com", &new_key, 1);
    rec_profile.profile.identity_pubkey = new_pk.clone();
    rec_profile.profile.recovery = Some(proof.clone());
    rec_profile.profile.recovery_policy = Some(attacker_policy.clone());
    let signed_rec = sign_profile(rec_profile.profile, &new_key.secret_key).unwrap();

    let mut rec_event = NameEvent {
        version: 1,
        identifier_hash: id_hash,
        action: NameAction::RecoverKey,
        identity_pubkey: new_pk,
        profile_hash: profile_hash(&signed_rec).unwrap(),
        sequence: 1,
        previous_event_hash: Some(prev_event_hash),
        created_at: now_ts,
        identifier_attestation_hash: None,
        removed_method_hashes: Vec::new(),
        rotation: None,
        recovery_policy: Some(attacker_policy),
        recovery: Some(proof),
        owner_signature: String::new(),
    };
    rec_event.sign(&new_key.secret_key).unwrap();

    // Must be rejected with RecoveryDisabled because genesis had no pre-committed policy
    assert!(matches!(
        verify_identifier_history(&[register.clone(), rec_event.clone()]).unwrap_err(),
        SatsPathError::Transparency(TransparencyError::RecoveryDisabled)
    ));

    assert!(matches!(
        verify_event_transition(Some(&register), &rec_event).unwrap_err(),
        SatsPathError::Transparency(TransparencyError::RecoveryDisabled)
    ));
}

#[test]
fn recovery_event_rejects_key_rotation_proof() {
    use satspath_core::recovery::{sign_guardian_authorization, KeyRecoveryProof, RecoveryPolicy};

    let key = generate_identity_keypair();
    let g1 = generate_identity_keypair();
    let policy = RecoveryPolicy::new(1, vec![hex::encode(g1.public_key.serialize())]).unwrap();

    let mut reg_profile = profile("alice@example.com", &key, 0);
    reg_profile.profile.recovery_policy = Some(policy.clone());
    let signed_reg = sign_profile(reg_profile.profile, &key.secret_key).unwrap();
    let mut register = event(&signed_reg, NameAction::Register, 0, None, &key.secret_key);
    register.recovery_policy = Some(policy.clone());
    register.sign(&key.secret_key).unwrap();

    let new_key = generate_identity_keypair();
    let id_hash = satspath_core::privacy::identifier_hash("alice@example.com");
    let prev_pk = hex::encode(key.public_key.serialize());
    let new_pk = hex::encode(new_key.public_key.serialize());
    let prev_event_hash = register.event_hash().unwrap();
    let now_ts = 1_700_000_100;

    let s1 = sign_guardian_authorization(
        &id_hash,
        &prev_pk,
        &new_pk,
        &prev_event_hash,
        1,
        now_ts,
        &g1.secret_key,
    );
    let proof = KeyRecoveryProof::create(
        id_hash.clone(),
        prev_pk.clone(),
        new_pk.clone(),
        &new_key.secret_key,
        prev_event_hash.clone(),
        1,
        now_ts,
        vec![s1],
    )
    .unwrap();

    let rotation = KeyRotation::create(
        id_hash.clone(),
        prev_pk.clone(),
        &key.secret_key,
        new_pk.clone(),
        &new_key.secret_key,
        prev_event_hash.clone(),
        1,
    )
    .unwrap();

    let mut rec_profile = profile("alice@example.com", &new_key, 1);
    rec_profile.profile.identity_pubkey = new_pk.clone();
    rec_profile.profile.recovery = Some(proof.clone());
    rec_profile.profile.rotation = Some(rotation.clone());
    rec_profile.profile.recovery_policy = Some(policy.clone());
    let signed_rec = sign_profile(rec_profile.profile, &new_key.secret_key).unwrap();

    let mut rec_event = NameEvent {
        version: 1,
        identifier_hash: id_hash,
        action: NameAction::RecoverKey,
        identity_pubkey: new_pk,
        profile_hash: profile_hash(&signed_rec).unwrap(),
        sequence: 1,
        previous_event_hash: Some(prev_event_hash),
        created_at: now_ts,
        identifier_attestation_hash: None,
        removed_method_hashes: Vec::new(),
        rotation: Some(rotation),
        recovery_policy: Some(policy),
        recovery: Some(proof),
        owner_signature: String::new(),
    };
    rec_event.sign(&new_key.secret_key).unwrap();

    assert!(matches!(
        verify_identifier_history(&[register.clone(), rec_event.clone()]).unwrap_err(),
        SatsPathError::Transparency(TransparencyError::InvalidRecovery(_))
    ));

    assert!(matches!(
        verify_event_transition(Some(&register), &rec_event).unwrap_err(),
        SatsPathError::Transparency(TransparencyError::InvalidRecovery(_))
    ));
}

#[test]
fn non_recovery_event_rejects_recovery_proof() {
    use satspath_core::recovery::{sign_guardian_authorization, KeyRecoveryProof, RecoveryPolicy};

    let key = generate_identity_keypair();
    let g1 = generate_identity_keypair();
    let policy = RecoveryPolicy::new(1, vec![hex::encode(g1.public_key.serialize())]).unwrap();

    let id_hash = satspath_core::privacy::identifier_hash("alice@example.com");
    let pk = hex::encode(key.public_key.serialize());
    let s1 = sign_guardian_authorization(
        &id_hash,
        &pk,
        &pk,
        "00".repeat(32).as_str(),
        0,
        1_700_000_000,
        &g1.secret_key,
    );
    let proof = KeyRecoveryProof::create(
        id_hash.clone(),
        pk.clone(),
        pk.clone(),
        &key.secret_key,
        "00".repeat(32),
        0,
        1_700_000_000,
        vec![s1],
    )
    .unwrap();

    let mut reg_profile = profile("alice@example.com", &key, 0);
    reg_profile.profile.recovery = Some(proof.clone());
    reg_profile.profile.recovery_policy = Some(policy);
    let signed_reg = sign_profile(reg_profile.profile, &key.secret_key).unwrap();

    let mut register = event(&signed_reg, NameAction::Register, 0, None, &key.secret_key);
    register.recovery = Some(proof);
    register.sign(&key.secret_key).unwrap();

    assert!(matches!(
        verify_identifier_history(&[register.clone()]).unwrap_err(),
        SatsPathError::Transparency(TransparencyError::InvalidRecovery(_))
    ));

    assert!(matches!(
        verify_event_transition(None, &register).unwrap_err(),
        SatsPathError::Transparency(TransparencyError::InvalidRecovery(_))
    ));
}

#[test]
fn non_rotation_event_rejects_rotation_proof() {
    let key = generate_identity_keypair();
    let id_hash = satspath_core::privacy::identifier_hash("alice@example.com");
    let pk = hex::encode(key.public_key.serialize());

    let rotation = KeyRotation::create(
        id_hash,
        pk.clone(),
        &key.secret_key,
        pk,
        &key.secret_key,
        "00".repeat(32),
        0,
    )
    .unwrap();

    let mut reg_profile = profile("alice@example.com", &key, 0);
    reg_profile.profile.rotation = Some(rotation.clone());
    let signed_reg = sign_profile(reg_profile.profile, &key.secret_key).unwrap();

    let mut register = event(&signed_reg, NameAction::Register, 0, None, &key.secret_key);
    register.rotation = Some(rotation);
    register.sign(&key.secret_key).unwrap();

    assert!(matches!(
        verify_identifier_history(&[register.clone()]).unwrap_err(),
        SatsPathError::Transparency(TransparencyError::InvalidRotation(_))
    ));

    assert!(matches!(
        verify_event_transition(None, &register).unwrap_err(),
        SatsPathError::Transparency(TransparencyError::InvalidRotation(_))
    ));
}
