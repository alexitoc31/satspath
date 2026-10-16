//! Offline regressions for authenticated BIP-353 profile acceptance and persistence.
#![cfg(feature = "std")]

use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use satspath_core::bip353::{DnsTxtRecord, MockDnsTxtResolver};
use satspath_core::crypto::{generate_identity_keypair, sign_profile};
use satspath_core::resolver::{ChainResolver, ProfileResolver};
use satspath_core::{
    Bip353Resolver, BitcoinNetwork, IdentityKeypair, KeyRotation, PaymentMethod, PaymentProfile,
    Result, SatsPathError, SignedPaymentProfile,
};

/// Create public metadata signed by an identity key, with a chosen replay counter.
fn profile(key: &IdentityKeypair, sequence: Option<u64>) -> PaymentProfile {
    PaymentProfile {
        alias: "alice@example.com".into(),
        identity_pubkey: hex::encode(key.public_key.serialize()),
        methods: Vec::new(),
        updated_at: 1_700_000_000,
        expires_at: None,
        sequence,
        preferences: Vec::new(),
        nonce: None,
        rotation: None,
        method_verifications: Vec::new(),
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
        recovery_policy: None,
        recovery: None,
    }
}

/// A fallback that must never be reached after an authenticated security failure.
struct ForbiddenFallback;

#[async_trait]
impl ProfileResolver for ForbiddenFallback {
    /// Panic if a failure would be converted into another routing candidate.
    async fn resolve_alias(&self, _alias: &str) -> Result<SignedPaymentProfile> {
        panic!("security failure must not reach fallback routing")
    }
}

/// Fetch one signed profile through a fresh resolver while retaining the same disk pins.
async fn resolve_signed(
    signed: &SignedPaymentProfile,
    dir: &Path,
    alias: &str,
    check_fallback: bool,
) -> Result<SignedPaymentProfile> {
    let mut server = mockito::Server::new_async().await;
    let _mock = server
        .mock("GET", "/profile")
        .with_status(200)
        .with_body(serde_json::to_string(signed).unwrap())
        .create_async()
        .await;
    let mut dns = MockDnsTxtResolver::new();
    dns.insert(
        "alice.user._bitcoin-payment.example.com",
        DnsTxtRecord {
            strings: vec![format!("bitcoin:?sp-profile={}/profile", server.url())],
            dnssec_validated: true,
            ttl_seconds: Some(60),
        },
    );
    let resolver =
        Bip353Resolver::with_dns_resolver(Arc::new(dns), dir).with_allow_private_profile_url(true);
    if check_fallback {
        ChainResolver::new()
            .push(resolver)
            .push(ForbiddenFallback)
            .resolve_alias(alias)
            .await
    } else {
        resolver.resolve_alias(alias).await
    }
}

/// A valid signature cannot authorize private spending material in an onchain hint.
#[tokio::test]
async fn private_descriptor_is_rejected_before_pinning() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_identity_keypair();
    let mut metadata = profile(&key, Some(1));
    metadata.methods.push(PaymentMethod::Onchain {
        label: "Public descriptor".into(),
        network: BitcoinNetwork::Mainnet,
        address: None,
        silent_payment_pubkey: None,
        pubkey_hint: None,
        descriptor_hint: Some("wpkh(xprv123/0/*)".into()),
        address_list: Vec::new(),
    });
    let signed = sign_profile(metadata, &key.secret_key).unwrap();
    assert!(matches!(
        resolve_signed(&signed, dir.path(), "₿alice@example.com", true).await,
        Err(SatsPathError::PrivateMaterialRejected(_))
    ));
    let clean = sign_profile(profile(&key, Some(1)), &key.secret_key).unwrap();
    assert!(
        resolve_signed(&clean, dir.path(), "₿alice@example.com", false)
            .await
            .is_ok()
    );
}

/// Disk pins survive resolver reconstruction and reject replay or unauthorized replacement.
#[tokio::test]
async fn continuity_rejects_replays_and_accepts_authorized_rotation() {
    let dir = tempfile::tempdir().unwrap();
    let old = generate_identity_keypair();
    let new = generate_identity_keypair();
    let initial = sign_profile(profile(&old, Some(4)), &old.secret_key).unwrap();
    assert!(
        resolve_signed(&initial, dir.path(), "₿alice@example.com", false)
            .await
            .is_ok()
    );
    for sequence in [Some(3), Some(4), None] {
        let replay = sign_profile(profile(&old, sequence), &old.secret_key).unwrap();
        assert!(matches!(
            resolve_signed(&replay, dir.path(), "₿alice @ example.com", true).await,
            Err(SatsPathError::RegistryError(_))
        ));
    }
    let replacement = sign_profile(profile(&new, Some(5)), &new.secret_key).unwrap();
    assert!(matches!(
        resolve_signed(&replacement, dir.path(), "₿alice@example.com", true).await,
        Err(SatsPathError::UnauthorizedKeyReplacement)
    ));
    let mut rotated = profile(&new, Some(5));
    rotated.rotation = Some(
        KeyRotation::create(
            satspath_core::identifier_hash(&rotated.alias),
            initial.profile.identity_pubkey.clone(),
            &old.secret_key,
            rotated.identity_pubkey.clone(),
            &new.secret_key,
            "previous-authenticated-event".into(),
            5,
        )
        .unwrap(),
    );
    let mut bad_rotation = rotated.clone();
    bad_rotation
        .rotation
        .as_mut()
        .unwrap()
        .authorization_signature = "00".repeat(64);
    let bad = sign_profile(bad_rotation, &new.secret_key).unwrap();
    assert!(resolve_signed(&bad, dir.path(), "₿alice@example.com", true)
        .await
        .is_err());
    let valid = sign_profile(rotated, &new.secret_key).unwrap();
    assert!(
        resolve_signed(&valid, dir.path(), "₿alice@example.com", false)
            .await
            .is_ok()
    );
    let next = sign_profile(profile(&new, Some(6)), &new.secret_key).unwrap();
    assert!(
        resolve_signed(&next, dir.path(), "₿alice@example.com", false)
            .await
            .is_ok()
    );
}

/// Preserve the registry's legacy policy, then prohibit removal of an adopted counter.
#[tokio::test]
async fn legacy_profiles_can_adopt_sequences_but_cannot_remove_them() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_identity_keypair();
    let legacy = sign_profile(profile(&key, None), &key.secret_key).unwrap();
    for _ in 0..2 {
        assert!(
            resolve_signed(&legacy, dir.path(), "₿alice@example.com", false)
                .await
                .is_ok()
        );
    }
    let numbered = sign_profile(profile(&key, Some(1)), &key.secret_key).unwrap();
    assert!(
        resolve_signed(&numbered, dir.path(), "₿alice@example.com", false)
            .await
            .is_ok()
    );
    assert!(matches!(
        resolve_signed(&legacy, dir.path(), "₿alice@example.com", true).await,
        Err(SatsPathError::RegistryError(_))
    ));
}

/// Persist verified revocations and halt before a later failed lookup can reach fallback.
#[tokio::test]
async fn revocation_survives_restart_and_blocks_fallback() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_identity_keypair();
    let initial = sign_profile(profile(&key, Some(1)), &key.secret_key).unwrap();
    assert!(
        resolve_signed(&initial, dir.path(), "₿alice@example.com", false)
            .await
            .is_ok()
    );
    let mut revoked = profile(&key, Some(2));
    revoked.revoked = true;
    let revoked = sign_profile(revoked, &key.secret_key).unwrap();
    assert!(matches!(
        resolve_signed(&revoked, dir.path(), "₿alice@example.com", true).await,
        Err(SatsPathError::RegistryError(_))
    ));
    assert!(matches!(
        resolve_signed(&initial, dir.path(), "₿alice@example.com", true).await,
        Err(SatsPathError::RegistryError(_))
    ));
    let empty_dns = MockDnsTxtResolver::new();
    let resolver = Bip353Resolver::with_dns_resolver(Arc::new(empty_dns), dir.path());
    assert!(matches!(
        ChainResolver::new()
            .push(resolver)
            .push(ForbiddenFallback)
            .resolve_alias("₿alice@example.com")
            .await,
        Err(SatsPathError::RegistryError(_))
    ));
}

/// An unusable pin store is a terminal error, never an excuse to accept an unpinned key.
#[tokio::test]
async fn continuity_storage_failure_is_terminal() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("not-a-directory");
    std::fs::write(&file, b"occupied").unwrap();
    let key = generate_identity_keypair();
    let signed = sign_profile(profile(&key, Some(1)), &key.secret_key).unwrap();
    assert!(matches!(
        resolve_signed(&signed, &file, "₿alice@example.com", true).await,
        Err(SatsPathError::RegistryError(_))
    ));
}

/// A higher sequence cannot roll timestamps back, and rejection must not consume it.
#[tokio::test]
async fn stale_timestamp_does_not_advance_the_pin() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_identity_keypair();
    let initial = sign_profile(profile(&key, Some(1)), &key.secret_key).unwrap();
    resolve_signed(&initial, dir.path(), "₿alice@example.com", false)
        .await
        .unwrap();
    let mut stale = profile(&key, Some(2));
    stale.updated_at -= 1;
    let stale = sign_profile(stale, &key.secret_key).unwrap();
    assert!(matches!(
        resolve_signed(&stale, dir.path(), "₿alice@example.com", true).await,
        Err(SatsPathError::RegistryError(message)) if message.contains("older")
    ));
    let next = sign_profile(profile(&key, Some(2)), &key.secret_key).unwrap();
    let accepted = resolve_signed(&next, dir.path(), "₿alice@example.com", false)
        .await
        .unwrap();
    assert_eq!(accepted.signature, next.signature);
}

/// Tampering with a revocation must neither persist a tombstone nor block a valid update.
#[tokio::test]
async fn unauthenticated_revocation_cannot_poison_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_identity_keypair();
    let initial = sign_profile(profile(&key, Some(1)), &key.secret_key).unwrap();
    resolve_signed(&initial, dir.path(), "₿alice@example.com", false)
        .await
        .unwrap();
    let mut forged = initial.clone();
    forged.profile.revoked = true;
    forged.profile.sequence = Some(2);
    assert!(matches!(
        resolve_signed(&forged, dir.path(), "₿alice@example.com", true).await,
        Err(SatsPathError::InvalidSignature)
    ));
    let next = sign_profile(profile(&key, Some(2)), &key.secret_key).unwrap();
    resolve_signed(&next, dir.path(), "₿alice@example.com", false)
        .await
        .unwrap();
}

/// A valid signature for someone else's alias does not establish a first-use pin.
#[tokio::test]
async fn wrong_alias_profile_is_rejected_before_pinning() {
    let dir = tempfile::tempdir().unwrap();
    let attacker = generate_identity_keypair();
    let mut wrong_alias = profile(&attacker, Some(1));
    wrong_alias.alias = "mallory@example.com".into();
    let wrong_alias = sign_profile(wrong_alias, &attacker.secret_key).unwrap();
    assert!(matches!(
        resolve_signed(&wrong_alias, dir.path(), "₿alice@example.com", true).await,
        Err(SatsPathError::OwnershipProofInvalid(_))
    ));
    let owner = generate_identity_keypair();
    let genuine = sign_profile(profile(&owner, Some(1)), &owner.secret_key).unwrap();
    resolve_signed(&genuine, dir.path(), "₿alice@example.com", false)
        .await
        .unwrap();
}

/// Even valid rotation signatures must bind the expected identity and counter.
#[tokio::test]
async fn signed_rotation_must_bind_alias_sequence_and_history() {
    let dir = tempfile::tempdir().unwrap();
    let old = generate_identity_keypair();
    let new = generate_identity_keypair();
    let initial = sign_profile(profile(&old, Some(4)), &old.secret_key).unwrap();
    resolve_signed(&initial, dir.path(), "₿alice@example.com", false)
        .await
        .unwrap();
    for (alias, sequence, history) in [
        ("mallory@example.com", 5, "previous-event"),
        ("alice@example.com", 6, "previous-event"),
        ("alice@example.com", 5, ""),
    ] {
        let mut metadata = profile(&new, Some(sequence));
        metadata.rotation = Some(
            KeyRotation::create(
                satspath_core::identifier_hash(alias),
                initial.profile.identity_pubkey.clone(),
                &old.secret_key,
                metadata.identity_pubkey.clone(),
                &new.secret_key,
                history.into(),
                sequence,
            )
            .unwrap(),
        );
        let signed = sign_profile(metadata, &new.secret_key).unwrap();
        assert!(matches!(
            resolve_signed(&signed, dir.path(), "₿alice@example.com", true).await,
            Err(SatsPathError::InvalidRotation(_))
        ));
    }
    // All rejected replacements leave the original key eligible to update.
    let next = sign_profile(profile(&old, Some(5)), &old.secret_key).unwrap();
    resolve_signed(&next, dir.path(), "₿alice@example.com", false)
        .await
        .unwrap();
}

/// A revoked identity cannot be introduced as a first-use profile and later revived.
#[tokio::test]
async fn first_seen_revocation_is_a_durable_tombstone() {
    let dir = tempfile::tempdir().unwrap();
    let key = generate_identity_keypair();
    let mut revoked = profile(&key, Some(1));
    revoked.revoked = true;
    let revoked = sign_profile(revoked, &key.secret_key).unwrap();
    assert!(matches!(
        resolve_signed(&revoked, dir.path(), "₿alice@example.com", true).await,
        Err(SatsPathError::RegistryError(message)) if message.contains("revoked")
    ));
    let revived = sign_profile(profile(&key, Some(2)), &key.secret_key).unwrap();
    assert!(matches!(
        resolve_signed(&revived, dir.path(), "₿alice@example.com", true).await,
        Err(SatsPathError::RegistryError(message)) if message.contains("revoked")
    ));
}

/// The profile fetch path must never follow a redirect, even to a valid profile.
#[tokio::test]
async fn profile_redirect_is_rejected_without_fetching_target() {
    let mut server = mockito::Server::new_async().await;
    let key = generate_identity_keypair();
    let signed = sign_profile(profile(&key, Some(1)), &key.secret_key).unwrap();
    let target = server
        .mock("GET", "/target")
        .with_status(200)
        .with_body(serde_json::to_string(&signed).unwrap())
        .expect(0)
        .create_async()
        .await;
    let redirect = server
        .mock("GET", "/profile")
        .with_status(302)
        .with_header("location", &format!("{}/target", server.url()))
        .create_async()
        .await;
    assert!(matches!(
        satspath_core::resolvers::http::HttpResolver::new()
            .resolve_from_mock_url(&format!("{}/profile", server.url())).await,
        Err(SatsPathError::NetworkError(message)) if message.contains("302")
    ));
    redirect.assert_async().await;
    target.assert_async().await;
}
