use proptest::prelude::*;
use satspath_core::crypto::sign_profile;
use satspath_core::{
    BitcoinNetwork, Bolt12Offer, PaymentMethod, PaymentProfile, SignedPaymentProfile,
};
use satspath_router::ark_routes::SenderCapabilities;
use satspath_router::fees::FeeEstimate;
use satspath_router::router::{select_route_with_fees, RouteRequest};
use satspath_router::scoring::{score_routes, FeeSnapshot, RoutePreferences};
use satspath_router::urgency::PaymentUrgency;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

// ── Strategies ─────────────────────────────────────────────────────────────

fn arb_secret_key() -> impl Strategy<Value = SecretKey> {
    any::<[u8; 32]>().prop_filter_map("valid secp256k1 secret key", |bytes| {
        SecretKey::from_slice(&bytes).ok()
    })
}

fn arb_bitcoin_network() -> impl Strategy<Value = BitcoinNetwork> {
    prop_oneof![
        Just(BitcoinNetwork::Mainnet),
        Just(BitcoinNetwork::Testnet),
        Just(BitcoinNetwork::Regtest),
    ]
}

fn arb_payment_method() -> impl Strategy<Value = PaymentMethod> {
    prop_oneof![
        (
            "[a-zA-Z0-9_-]{1,16}",
            arb_bitcoin_network(),
            proptest::option::of("bc1q[a-z0-9]{20,40}"),
            proptest::option::of("sp1q[a-z0-9]{30,50}"),
        )
            .prop_map(|(label, network, address, silent_payment_pubkey)| {
                PaymentMethod::Onchain {
                    label,
                    network,
                    address,
                    silent_payment_pubkey,
                    pubkey_hint: None,
                    descriptor_hint: None,
                    address_list: vec![],
                }
            }),
        (
            "[a-zA-Z0-9_-]{1,16}",
            proptest::option::of("[a-z0-9_]{1,15}@[a-z0-9_]{1,10}\\.com"),
            proptest::option::of("https://[a-z0-9.]+/lnurl"),
            proptest::option::of("lno1[a-z0-9]{20,50}"),
        )
            .prop_map(|(label, lightning_address, lnurl, bolt12)| {
                PaymentMethod::Lightning {
                    label,
                    lightning_address,
                    lnurl,
                    bolt12,
                    receiver_pubkey: None,
                }
            }),
        (
            "[a-zA-Z0-9_-]{1,16}",
            "https://[a-z0-9.]+/ark",
            "[0-9a-f]{66}",
        )
            .prop_map(|(label, server, pubkey)| {
                PaymentMethod::Ark {
                    label,
                    server,
                    pubkey,
                    vtxo_pointer: None,
                    proof: None,
                    expires_at: None,
                    opaque_uri: None,
                }
            }),
        (
            "[a-zA-Z0-9_-]{1,16}",
            "lno1[a-z0-9]{20,50}",
            arb_bitcoin_network(),
            proptest::option::of(100u64..10_000_000u64),
            "[0-9a-f]{66}",
        )
            .prop_map(|(label, offer, network, min_amt, issuer)| {
                PaymentMethod::Bolt12(Bolt12Offer {
                    label,
                    offer,
                    network,
                    minimum_amount_sats: min_amt,
                    expires_at: None,
                    issuer_pubkey: issuer,
                })
            }),
    ]
}

fn arb_signed_profile() -> impl Strategy<Value = SignedPaymentProfile> {
    (
        arb_secret_key(),
        "[a-z0-9_]{1,15}@[a-z0-9_]{1,10}\\.com",
        proptest::collection::vec(arb_payment_method(), 1..5),
        0i64..2_000_000_000i64,
        proptest::option::of(0u64..1_000_000u64),
    )
        .prop_map(|(sk, alias, methods, updated_at, sequence)| {
            let secp = Secp256k1::new();
            let pk = PublicKey::from_secret_key(&secp, &sk);
            let profile = PaymentProfile {
                alias,
                identity_pubkey: hex::encode(pk.serialize()),
                methods,
                updated_at,
                expires_at: None,
                sequence,
                preferences: vec!["lightning".into(), "onchain".into(), "ark".into()],
                nonce: None,
                rotation: None,
                method_verifications: vec![],
                hybrid_pubkey: None,
                pqc_required: false,
                revoked: false,
                recovery_policy: None,
                recovery: None,
            };
            sign_profile(profile, &sk).expect("profile signing")
        })
}

fn arb_fee_snapshot() -> impl Strategy<Value = FeeSnapshot> {
    (
        proptest::option::of(1u64..10_000u64),
        proptest::option::of(1u64..300u64),
        proptest::option::of(1u64..200u64),
        proptest::option::of(1u64..100u64),
        proptest::option::of(1u64..100u64),
    )
        .prop_map(|(ln, fastest, half_hour, hour, ark)| FeeSnapshot {
            lightning_fee_sats_estimate: ln,
            onchain_fastest_sat_vb: fastest,
            onchain_half_hour_sat_vb: half_hour,
            onchain_hour_sat_vb: hour,
            ark_fee_sats_estimate: ark,
        })
}

fn arb_fee_estimate() -> impl Strategy<Value = FeeEstimate> {
    (
        1u64..300u64,
        1u64..200u64,
        1u64..100u64,
        1u64..50u64,
        1u64..20u64,
    )
        .prop_map(|(fastest, half_hour, hour, economy, minimum)| {
            let mut est = FeeEstimate {
                fastest_fee: fastest,
                half_hour_fee: half_hour,
                hour_fee: hour,
                economy_fee: economy,
                minimum_fee: minimum,
            };
            est.sanitize();
            est
        })
}

fn arb_route_preferences() -> impl Strategy<Value = RoutePreferences> {
    (
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        any::<bool>(),
        proptest::option::of(100u64..50_000u64),
        any::<bool>(),
        any::<bool>(),
    )
        .prop_map(
            |(low_fee, speed, privacy, ark, max_fee, has_ln, has_chain)| RoutePreferences {
                prefer_low_fee: low_fee,
                prefer_speed: speed,
                prefer_privacy: privacy,
                allow_experimental_ark: ark,
                max_fee_sats: max_fee,
                sender_capabilities: SenderCapabilities {
                    has_lightning: has_ln,
                    has_onchain: has_chain,
                    ark_server: None,
                },
            },
        )
}

fn arb_payment_urgency() -> impl Strategy<Value = PaymentUrgency> {
    prop_oneof![
        Just(PaymentUrgency::Urgent),
        Just(PaymentUrgency::Commercial),
        Just(PaymentUrgency::Normal),
        Just(PaymentUrgency::Economy),
    ]
}

// ── Property Tests ─────────────────────────────────────────────────────────

proptest! {
    // ── 1. Route Scoring Determinism ───────────────────────────────────────

    #[test]
    fn test_score_routes_is_deterministic(
        amount_sats in 1u64..5_000_000u64,
        signed_profile in arb_signed_profile(),
        fee_snapshot in arb_fee_snapshot(),
        preferences in arb_route_preferences(),
    ) {
        let decision1 = score_routes(amount_sats, &signed_profile, &fee_snapshot, &preferences);
        let decision2 = score_routes(amount_sats, &signed_profile, &fee_snapshot, &preferences);

        match (&decision1, &decision2) {
            (Ok(d1), Ok(d2)) => {
                prop_assert_eq!(d1, d2, "score_routes must return identical RouteDecision for identical inputs");
            }
            (Err(e1), Err(e2)) => {
                prop_assert_eq!(e1.to_string(), e2.to_string(), "score_routes must return identical error for identical inputs");
            }
            _ => {
                prop_assert!(false, "score_routes returned differing success/failure for identical inputs");
            }
        }
    }

    // ── 2. Route Selection With Fees Determinism ───────────────────────────

    #[test]
    fn test_select_route_with_fees_is_deterministic(
        amount_sats in 1u64..5_000_000u64,
        signed_profile in arb_signed_profile(),
        urgency in arb_payment_urgency(),
        fee_est in arb_fee_estimate(),
    ) {
        let req = RouteRequest {
            alias: signed_profile.profile.alias.clone(),
            amount_sats,
            signed_profile,
            urgency,
            max_fee_sats: None,
            max_fee_percent: None,
        };

        let quote1 = select_route_with_fees(&req, &fee_est);
        let quote2 = select_route_with_fees(&req, &fee_est);

        match (&quote1, &quote2) {
            (Ok(q1), Ok(q2)) => {
                prop_assert_eq!(q1, q2, "select_route_with_fees must return identical RouteQuote for identical inputs");
            }
            (Err(e1), Err(e2)) => {
                prop_assert_eq!(e1.to_string(), e2.to_string(), "select_route_with_fees must return identical error for identical inputs");
            }
            _ => {
                prop_assert!(false, "select_route_with_fees returned differing success/failure for identical inputs");
            }
        }
    }

    // ── 3. Repeated Route Selection Idempotency ────────────────────────────

    #[test]
    fn test_route_selection_repeated_invocations_remain_consistent(
        amount_sats in 1u64..100_000u64,
        signed_profile in arb_signed_profile(),
        fee_est in arb_fee_estimate(),
    ) {
        let req = RouteRequest {
            alias: signed_profile.profile.alias.clone(),
            amount_sats,
            signed_profile,
            urgency: PaymentUrgency::Normal,
            max_fee_sats: None,
            max_fee_percent: None,
        };

        let first = select_route_with_fees(&req, &fee_est);
        for _ in 0..5 {
            let repeated = select_route_with_fees(&req, &fee_est);
            match (&first, &repeated) {
                (Ok(q1), Ok(q2)) => {
                    prop_assert_eq!(q1, q2, "repeated route evaluations must never fluctuate");
                }
                (Err(e1), Err(e2)) => {
                    prop_assert_eq!(e1.to_string(), e2.to_string(), "repeated route evaluations must return identical error");
                }
                _ => {
                    prop_assert!(false, "repeated route evaluations produced divergent outcomes");
                }
            }
        }
    }
}
