//! Criterion benchmark suite for `satspath-router` route selection and multi-rail scoring (Issue #102).

use std::hint::black_box;

use criterion::{criterion_group, criterion_main, Criterion};
use satspath_core::crypto::{generate_identity_keypair, sign_profile};
use satspath_core::pointer::BitcoinNetwork;
use satspath_core::profile::{PaymentMethod, PaymentProfile};
use satspath_core::SignedPaymentProfile;
use satspath_router::fees::FeeEstimate;
use satspath_router::router::{select_route_with_fees, RouteRequest};
use satspath_router::scoring::{score_routes, FeeSnapshot, RoutePreferences};
use satspath_router::urgency::PaymentUrgency;

/// Sign a profile offering Lightning, on-chain, and Ark methods for routing benchmarks.
fn build_multi_rail_signed_profile() -> SignedPaymentProfile {
    let kp = generate_identity_keypair();
    let profile = PaymentProfile {
        alias: "alice@satspath.dev".to_string(),
        identity_pubkey: hex::encode(kp.public_key.serialize()),
        methods: vec![
            PaymentMethod::Lightning {
                label: "Lightning Address".to_string(),
                lightning_address: Some("alice@satspath.dev".to_string()),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: None,
            },
            PaymentMethod::Onchain {
                label: "Mainnet SegWit".to_string(),
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
        expires_at: None,
        sequence: Some(1),
        preferences: vec![
            "lightning".to_string(),
            "ark".to_string(),
            "onchain".to_string(),
        ],
        nonce: None,
        rotation: None,
        method_verifications: Vec::new(),
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
        recovery_policy: None,
        recovery: None,
    };
    sign_profile(profile, &kp.secret_key).expect("sign_profile")
}

/// Benchmark route selection across fee scenarios and scoring of multiple payment rails.
fn bench_route_selection(c: &mut Criterion) {
    let signed_profile = build_multi_rail_signed_profile();

    let low_fees = FeeEstimate {
        fastest_fee: 4,
        half_hour_fee: 3,
        hour_fee: 2,
        economy_fee: 1,
        minimum_fee: 1,
    };
    let high_fees = FeeEstimate {
        fastest_fee: 45,
        half_hour_fee: 35,
        hour_fee: 25,
        economy_fee: 15,
        minimum_fee: 5,
    };

    let req_small_ln = RouteRequest {
        alias: "alice@satspath.dev".to_string(),
        amount_sats: 25_000,
        signed_profile: signed_profile.clone(),
        urgency: PaymentUrgency::Normal,
        max_fee_sats: None,
        max_fee_percent: None,
    };

    let req_large_amount = RouteRequest {
        alias: "alice@satspath.dev".to_string(),
        amount_sats: 250_000,
        signed_profile: signed_profile.clone(),
        urgency: PaymentUrgency::Normal,
        max_fee_sats: None,
        max_fee_percent: None,
    };

    assert!(matches!(
        select_route_with_fees(&req_small_ln, &low_fees)
            .unwrap()
            .selected_method,
        PaymentMethod::Lightning { .. }
    ));
    c.bench_function("select_route_lightning_under_threshold", |b| {
        b.iter(|| {
            black_box(
                select_route_with_fees(black_box(&req_small_ln), black_box(&low_fees)).unwrap(),
            )
        })
    });

    assert!(matches!(
        select_route_with_fees(&req_large_amount, &low_fees)
            .unwrap()
            .selected_method,
        PaymentMethod::Onchain { .. }
    ));
    c.bench_function("select_route_onchain_low_fee", |b| {
        b.iter(|| {
            black_box(
                select_route_with_fees(black_box(&req_large_amount), black_box(&low_fees)).unwrap(),
            )
        })
    });

    assert!(matches!(
        select_route_with_fees(&req_large_amount, &high_fees)
            .unwrap()
            .selected_method,
        PaymentMethod::Ark { .. }
    ));
    c.bench_function("select_route_ark_fallback_high_fee", |b| {
        b.iter(|| {
            black_box(
                select_route_with_fees(black_box(&req_large_amount), black_box(&high_fees))
                    .unwrap(),
            )
        })
    });

    let fee_snapshot = FeeSnapshot {
        lightning_fee_sats_estimate: Some(15),
        onchain_fastest_sat_vb: Some(4),
        onchain_half_hour_sat_vb: Some(3),
        onchain_hour_sat_vb: Some(2),
        ark_fee_sats_estimate: Some(5),
    };
    let preferences = RoutePreferences::default();
    c.bench_function("score_routes_multi_rail", |b| {
        b.iter(|| {
            black_box(
                score_routes(
                    black_box(50_000),
                    black_box(&signed_profile),
                    black_box(&fee_snapshot),
                    black_box(&preferences),
                )
                .unwrap(),
            )
        })
    });
}

criterion_group!(benches, bench_route_selection);
criterion_main!(benches);
