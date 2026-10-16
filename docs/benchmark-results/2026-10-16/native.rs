//! Copy into crates/satspath-wasm/examples/benchmark_comparison.rs to run.
#![allow(dead_code)]
#[path = "../src/crypto.rs"]
mod crypto;
#[path = "../src/topic.rs"]
mod topic;

use serde_json::{json, Value};
use std::{hint::black_box, time::Instant};

fn measure<T>(iterations: usize, mut operation: impl FnMut() -> T) -> Value {
    for _ in 0..20 {
        black_box(operation());
    }
    let samples: Vec<u64> = (0..7)
        .map(|_| {
            let start = Instant::now();
            for _ in 0..iterations {
                black_box(operation());
            }
            start.elapsed().as_nanos().try_into().unwrap()
        })
        .collect();
    json!({"iterations_per_sample": iterations, "elapsed_ns": samples})
}

fn main() {
    let fixture: Value = serde_json::from_str(
        &std::fs::read_to_string(std::env::args().nth(1).expect("fixture path")).unwrap(),
    )
    .unwrap();
    let profile = fixture["profile_json"].as_str().unwrap();
    let alias = fixture["alias"].as_str().unwrap();
    // Public test scalar 1; never use this identity for funds.
    let test_key = format!("{:064x}", 1);
    let signature = crypto::sign_profile_json(profile, &test_key);
    assert_eq!(signature.len(), 128);
    let signed =
        json!({"profile": serde_json::from_str::<Value>(profile).unwrap(), "signature": signature});
    let signed_json = signed.to_string();
    assert!(crypto::verify_signed_profile(&signed_json));
    let mut tampered = signed;
    tampered["profile"]["sequence"] = json!(2);
    assert!(!crypto::verify_signed_profile(&tampered.to_string()));
    assert!(!crypto::verify_signed_profile("{}"));
    assert_eq!(
        crypto::canonical_profile_json(profile),
        fixture["canonical_json"].as_str().unwrap().as_bytes()
    );
    assert_eq!(
        hex::encode(topic::topic_for_alias(alias)),
        fixture["topic_hex"].as_str().unwrap()
    );

    println!(
        "{}",
        json!({
            "correctness_checks": "passed: canonical bytes, sign/verify round trip, tampered and malformed rejection, SHA-256 topic vector",
            "warmup_iterations_per_operation": 20,
            "operations": {
                "canonical_profile_json": measure(2000, || crypto::canonical_profile_json(black_box(profile))),
                "sign_profile_json": measure(500, || crypto::sign_profile_json(black_box(profile), black_box(&test_key))),
                "verify_signed_profile": measure(500, || crypto::verify_signed_profile(black_box(&signed_json))),
                "topic_for_alias": measure(5000, || topic::topic_for_alias(black_box(alias)))
            }
        })
    );
}
