use ml_dsa::{Keypair, MlDsa65, Signature, Signer, SigningKey, Verifier};

/// Implementation regression snapshots and parameter bound tests:
/// ML-DSA-65 (Security Category 3):
/// - Public key (vk) length: 1,952 bytes
/// - Signing key seed length: 32 bytes
/// - Signature length: 3,309 bytes
const ML_DSA_65_VK_LEN: usize = 1952;
const ML_DSA_65_SIG_LEN: usize = 3309;
const ML_DSA_65_SEED_LEN: usize = 32;

#[test]
fn test_mldsa65_parameter_bounds() {
    let seed_bytes = [0x42u8; ML_DSA_65_SEED_LEN];
    let seed: ml_dsa::Seed = seed_bytes.into();
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    let vk = sk.verifying_key();

    let encoded_vk = vk.encode();
    assert_eq!(
        encoded_vk.len(),
        ML_DSA_65_VK_LEN,
        "ML-DSA-65 verifying key must be exactly 1952 bytes according to FIPS 204"
    );

    let msg = b"SatsPath ML-DSA-65 Regression Snapshot Validation Message";
    let sig: Signature<MlDsa65> = sk.sign(msg);
    let encoded_sig = sig.encode();

    assert_eq!(
        encoded_sig.len(),
        ML_DSA_65_SIG_LEN,
        "ML-DSA-65 signature must be exactly 3309 bytes according to FIPS 204"
    );

    // Verify valid signature passes
    assert!(vk.verify(msg, &sig).is_ok());
}

#[test]
fn test_mldsa65_deterministic_seed_regression_snapshots() {
    // Known seed vector 1
    let seed1_bytes = [0x11u8; 32];
    let seed1: ml_dsa::Seed = seed1_bytes.into();
    let sk1 = SigningKey::<MlDsa65>::from_seed(&seed1);
    let vk1 = sk1.verifying_key();

    // Known seed vector 2 (identical seed must generate identical key)
    let seed2: ml_dsa::Seed = seed1_bytes.into();
    let sk2 = SigningKey::<MlDsa65>::from_seed(&seed2);
    let vk2 = sk2.verifying_key();

    assert_eq!(
        vk1.encode(),
        vk2.encode(),
        "Identical seeds must deterministically produce identical verifying keys"
    );

    // Deterministic key and signature regression snapshot validation:
    // Fixed constant expected SHA-256 digests for key derivation and deterministic signature
    use sha2::{Digest, Sha256};
    let vk_hash = hex::encode(Sha256::digest(vk1.encode()));
    const EXPECTED_VK_SHA256: &str =
        "0575d15a041b8b573635522018f2d25d0cc1c1d6d5295da66c52e12bc29402fc";
    assert_eq!(
        vk_hash, EXPECTED_VK_SHA256,
        "ML-DSA-65 derived verifying key digest must match regression snapshot"
    );

    let msg = b"SatsPath Deterministic Verification";
    let sig1 = sk1.sign(msg);
    let sig_hash = hex::encode(Sha256::digest(sig1.encode()));
    const EXPECTED_SIG_SHA256: &str =
        "dcacfe045e39b256eb85f58cba40f2e6ac178cb35817a9479c7fce13f8135ba9";
    assert_eq!(
        sig_hash, EXPECTED_SIG_SHA256,
        "ML-DSA-65 deterministic signature digest must match regression snapshot"
    );

    assert!(vk2.verify(msg, &sig1).is_ok());
}

#[test]
fn test_mldsa65_tampered_signature_rejection() {
    let seed_bytes = [0x77u8; 32];
    let seed: ml_dsa::Seed = seed_bytes.into();
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    let vk = sk.verifying_key();

    let msg = b"Financial transaction canonical payload";
    let sig = sk.sign(msg);
    let mut sig_bytes = sig.encode();

    // Flip a bit in the signature
    sig_bytes[100] ^= 0x01;

    let tampered_sig = Signature::<MlDsa65>::decode(&sig_bytes);
    let verification_rejected = match tampered_sig {
        Some(decoded) => vk.verify(msg, &decoded).is_err(),
        None => true, // Decoder rejection is an acceptable fail-closed outcome
    };
    assert!(
        verification_rejected,
        "Tampered signature bit must fail decoding or verification"
    );
}

#[test]
fn test_mldsa65_tampered_message_rejection() {
    let seed_bytes = [0x88u8; 32];
    let seed: ml_dsa::Seed = seed_bytes.into();
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    let vk = sk.verifying_key();

    let msg = b"Original message";
    let sig = sk.sign(msg);

    let tampered_msg = b"Tampered message";
    assert!(
        vk.verify(tampered_msg, &sig).is_err(),
        "Verification must fail when message is altered"
    );
}

#[test]
fn test_mldsa65_wrong_key_rejection() {
    let seed1: ml_dsa::Seed = [0xAAu8; 32].into();
    let sk1 = SigningKey::<MlDsa65>::from_seed(&seed1);

    let seed2: ml_dsa::Seed = [0xBBu8; 32].into();
    let sk2 = SigningKey::<MlDsa65>::from_seed(&seed2);
    let vk2 = sk2.verifying_key();

    let msg = b"Cross-key test message";
    let sig1 = sk1.sign(msg);

    assert!(
        vk2.verify(msg, &sig1).is_err(),
        "Signature from key 1 must be rejected by key 2"
    );
}

// Independently published NIST ACVP vectors; provenance and selection are in
// fixtures/README.md. Keep these separate from the project-selected snapshots.
fn acvp_vectors() -> serde_json::Value {
    serde_json::from_str(include_str!("fixtures/mldsa65-acvp.json")).unwrap()
}

fn acvp_bytes(vector: &serde_json::Value, field: &str) -> Vec<u8> {
    hex::decode(vector[field].as_str().expect("ACVP hex field")).unwrap()
}

#[test]
fn test_mldsa65_nist_acvp_key_generation() {
    let vectors = acvp_vectors();
    let vector = &vectors["keyGen"][0];
    let seed = ml_dsa::Seed::try_from(acvp_bytes(vector, "seed").as_slice()).unwrap();
    let sk = SigningKey::<MlDsa65>::from_seed(&seed);
    assert_eq!(
        sk.verifying_key().encode().as_slice(),
        acvp_bytes(vector, "pk")
    );
    // ACVP publishes the FIPS 204 expanded key, not the preferred seed encoding.
    #[allow(deprecated)]
    let expanded = sk.expanded_key().to_expanded();
    assert_eq!(expanded.as_slice(), acvp_bytes(vector, "sk"));
}

#[test]
fn test_mldsa65_nist_acvp_signing() {
    let vectors = acvp_vectors();
    let vector = &vectors["sigGen"][0];
    let encoded =
        ml_dsa::ExpandedSigningKeyBytes::<MlDsa65>::try_from(acvp_bytes(vector, "sk").as_slice())
            .unwrap();
    // This published signing fixture supplies only an expanded secret key.
    #[allow(deprecated)]
    let sk = ml_dsa::ExpandedSigningKey::<MlDsa65>::from_expanded(&encoded);
    let sig = sk
        .sign_deterministic(
            &acvp_bytes(vector, "message"),
            &acvp_bytes(vector, "context"),
        )
        .unwrap();
    assert_eq!(sig.encode().as_slice(), acvp_bytes(vector, "signature"));
}

#[test]
fn test_mldsa65_nist_acvp_verification() {
    let vectors = acvp_vectors();
    for vector in vectors["sigVer"].as_array().unwrap() {
        let encoded =
            ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(acvp_bytes(vector, "pk").as_slice())
                .unwrap();
        let vk = ml_dsa::VerifyingKey::<MlDsa65>::decode(&encoded);
        let encoded_sig = ml_dsa::EncodedSignature::<MlDsa65>::try_from(
            acvp_bytes(vector, "signature").as_slice(),
        )
        .unwrap();
        let accepted = Signature::<MlDsa65>::decode(&encoded_sig).is_some_and(|sig| {
            vk.verify_with_context(
                &acvp_bytes(vector, "message"),
                &acvp_bytes(vector, "context"),
                &sig,
            )
        });
        assert_eq!(
            accepted,
            vector["testPassed"].as_bool().unwrap(),
            "NIST ACVP verification tcId {}",
            vector["tcId"]
        );
    }
}
