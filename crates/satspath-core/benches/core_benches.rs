//! Criterion benchmark suite for `satspath-core` cryptography, canonical serialization,
//! transparency Merkle / Sparse Merkle Tree operations (Issue #102).

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use satspath_core::crypto::{
    canonical_profile_bytes, generate_identity_keypair, sign_profile, verify_signed_profile,
};
use satspath_core::pointer::BitcoinNetwork;
use satspath_core::profile::{PaymentMethod, PaymentProfile};
use satspath_core::transparency::{
    consistency_proof, inclusion_proof, leaf_hash, merkle_root, verify_consistency,
    verify_inclusion_proof, IdentifierStatus, SparseMerkleTree, StateMapValue,
};

/// Build a three-rail payment profile for serialization and cryptography benchmarks.
fn sample_profile(pubkey_hex: String) -> PaymentProfile {
    PaymentProfile {
        alias: "satoshi@satspath.dev".to_string(),
        identity_pubkey: pubkey_hex,
        methods: vec![
            PaymentMethod::Lightning {
                label: "Lightning".to_string(),
                lightning_address: Some("satoshi@satspath.dev".to_string()),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: None,
            },
            PaymentMethod::Onchain {
                label: "Mainnet Vault".to_string(),
                network: BitcoinNetwork::Mainnet,
                address: Some("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string()),
                silent_payment_pubkey: None,
                pubkey_hint: None,
                descriptor_hint: None,
                address_list: Vec::new(),
            },
            PaymentMethod::Ark {
                label: "Ark ASP".to_string(),
                server: "https://ark.satspath.dev".to_string(),
                pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                    .to_string(),
                vtxo_pointer: None,
                opaque_uri: None,
                proof: None,
                expires_at: None,
            },
        ],
        updated_at: 1_700_000_000,
        expires_at: Some(1_900_000_000),
        sequence: Some(1),
        preferences: vec![
            "lightning".to_string(),
            "ark".to_string(),
            "onchain".to_string(),
        ],
        nonce: Some("bench_nonce_01".to_string()),
        rotation: None,
        method_verifications: Vec::new(),
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
        recovery_policy: None,
        recovery: None,
    }
}

/// Benchmark RFC 8785 canonical JSON serialization and BIP-340 Schnorr signing/verification.
fn bench_crypto_and_canonical_json(c: &mut Criterion) {
    let kp = generate_identity_keypair();
    let pubkey_hex = hex::encode(kp.public_key.serialize());
    let profile = sample_profile(pubkey_hex);
    let signed = sign_profile(profile.clone(), &kp.secret_key).expect("sign_profile");

    c.bench_function("canonical_profile_bytes", |b| {
        b.iter(|| {
            let bytes = canonical_profile_bytes(black_box(&profile)).unwrap();
            black_box(bytes)
        })
    });

    c.bench_function("sign_profile_schnorr", |b| {
        b.iter(|| {
            let res = sign_profile(black_box(profile.clone()), black_box(&kp.secret_key)).unwrap();
            black_box(res)
        })
    });

    c.bench_function("verify_signed_profile_schnorr", |b| {
        b.iter(|| {
            let ok = verify_signed_profile(black_box(&signed)).unwrap();
            black_box(ok)
        })
    });
}

/// Benchmark Merkle tree root computation, inclusion proofs, consistency proofs, and SMT inserts.
fn bench_merkle_transparency(c: &mut Criterion) {
    let leaves: Vec<[u8; 32]> = (0u32..256).map(|i| leaf_hash(&i.to_be_bytes())).collect();
    let old_size = 128usize;
    let old_root = merkle_root(&leaves[..old_size]);
    let new_root = merkle_root(&leaves);
    let inc_proof = inclusion_proof(&leaves, 77).expect("inclusion_proof");
    let cons_proof = consistency_proof(&leaves, old_size).expect("consistency_proof");

    c.bench_function("merkle_root_256_leaves", |b| {
        b.iter(|| black_box(merkle_root(black_box(&leaves))))
    });

    c.bench_function("merkle_inclusion_proof_gen_256", |b| {
        b.iter(|| black_box(inclusion_proof(black_box(&leaves), black_box(77)).unwrap()))
    });

    c.bench_function("merkle_inclusion_proof_verify_256", |b| {
        b.iter(|| black_box(verify_inclusion_proof(black_box(&inc_proof)).unwrap()))
    });

    c.bench_function("merkle_consistency_proof_gen_128_to_256", |b| {
        b.iter(|| black_box(consistency_proof(black_box(&leaves), black_box(old_size)).unwrap()))
    });

    c.bench_function("merkle_consistency_proof_verify_128_to_256", |b| {
        b.iter(|| {
            black_box(
                verify_consistency(
                    black_box(old_size as u64),
                    black_box(leaves.len() as u64),
                    black_box(&old_root),
                    black_box(&new_root),
                    black_box(&cons_proof),
                )
                .unwrap(),
            )
        })
    });

    c.bench_function("sparse_merkle_tree_insert_and_prove", |b| {
        b.iter(|| {
            let mut smt = SparseMerkleTree::new();
            let key = [0x42u8; 32];
            let val = StateMapValue {
                latest_event_hash: "aa".repeat(32),
                sequence: 1,
                status: IdentifierStatus::Registered,
            };
            smt.insert(black_box(key), black_box(val));
            let proof = smt.prove(&key);
            black_box(proof)
        })
    });
}

criterion_group!(
    benches,
    bench_crypto_and_canonical_json,
    bench_merkle_transparency
);
criterion_main!(benches);
