//! NIST ACVP FIPS 204 verification vectors; provenance is in `vectors/README.md`.

use ml_dsa::{MlDsa65, Signature, Verifier, VerifyingKey};
use serde::Deserialize;

/// One external, pure ML-DSA-65 verification case and NIST's expected result.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VerificationVector {
    tc_id: u32,
    pk: String,
    message: String,
    context: String,
    signature: String,
    test_passed: bool,
}

/// Checks NIST's public keys, messages, contexts and signatures against its verdicts.
#[test]
fn nist_fips204_mldsa65_signature_verification() {
    let vectors: Vec<VerificationVector> =
        serde_json::from_str(include_str!("vectors/nist_mldsa65_sigver.json")).unwrap();
    assert_eq!(
        vectors
            .iter()
            .map(|vector| vector.tc_id)
            .collect::<Vec<_>>(),
        [34, 35, 39, 43],
        "The pinned NIST cases must all be exercised"
    );
    let context_free = vectors.iter().find(|vector| vector.tc_id == 35).unwrap();
    assert!(context_free.context.is_empty());
    assert!(context_free.test_passed, "NIST tcId 35 must be accepted");
    assert!(vectors.iter().any(|vector| !vector.test_passed));

    for vector in vectors {
        let pk = hex::decode(&vector.pk).unwrap();
        let message = hex::decode(&vector.message).unwrap();
        let context = hex::decode(&vector.context).unwrap();
        let signature = hex::decode(&vector.signature).unwrap();
        assert_eq!(pk.len(), 1952, "NIST tcId {} key length", vector.tc_id);
        assert_eq!(
            signature.len(),
            3309,
            "NIST tcId {} signature length",
            vector.tc_id
        );
        assert!(context.len() <= 255);

        let vk = VerifyingKey::<MlDsa65>::decode(&pk.as_slice().try_into().unwrap());
        let signature = Signature::<MlDsa65>::decode(&signature.as_slice().try_into().unwrap());
        // Malformed signatures may be rejected during decoding, before verification.
        let accepted = signature
            .as_ref()
            .is_some_and(|signature| vk.verify_with_context(&message, &context, signature));
        assert_eq!(accepted, vector.test_passed, "NIST tcId {}", vector.tc_id);
        if vector.tc_id == 35 {
            // Exercise the context-free API used by hybrid_verify as well.
            assert!(signature.is_some_and(|signature| vk.verify(&message, &signature).is_ok()));
        }
    }
}
