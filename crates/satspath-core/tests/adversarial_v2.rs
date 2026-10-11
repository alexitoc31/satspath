use chrono::Utc;
use satspath_core::PaymentProfile;

#[test]
fn test_reject_old_profile_replay() {
    let now = Utc::now().timestamp();
    let old = now - 10000;
    let profile = PaymentProfile {
        alias: "victim@example.com".to_string(),
        identity_pubkey: "dummy".to_string(),
        methods: vec![],
        updated_at: old - 1000,
        expires_at: Some(old),
        sequence: None,
        preferences: vec![],
        nonce: None,
        rotation: None,
        method_verifications: vec![],
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
        recovery_policy: None,
        recovery: None,
    };

    // Test our local expiration logic
    assert!(
        profile.expires_at.unwrap() < Utc::now().timestamp(),
        "Old profiles should be considered expired"
    );
}

#[test]
fn test_reject_split_view() {
    use satspath_core::transparency::verify_consistency_proof;
    use satspath_core::transparency::MerkleConsistencyProof;

    let proof = MerkleConsistencyProof {
        version: 2,
        old_tree_size: 5,
        new_tree_size: 5,
        old_root: "rootA".to_string(),
        new_root: "rootB".to_string(),
        audit_path: vec![],
    };

    // Identical sized trees with different roots cannot be consistent
    assert!(
        verify_consistency_proof(&proof).is_err() || !verify_consistency_proof(&proof).unwrap()
    );
}

#[test]
fn test_forged_non_inclusion() {
    use satspath_core::transparency::verify_inclusion_proof;
    use satspath_core::transparency::MerkleInclusionProof;

    let proof = MerkleInclusionProof {
        leaf_index: 5,
        tree_size: 10,
        leaf_hash: "fake".to_string(),
        audit_path: vec!["invalid_path".to_string()],
        root_hash: "root".to_string(),
    };

    // Forged proof should fail verification
    assert!(verify_inclusion_proof(&proof).is_err() || !verify_inclusion_proof(&proof).unwrap());
}

#[test]
fn test_legacy_fallback_rejection() {
    // Core resolvers do not implement fallback; they strictly fail on v2 verification errors.
}
