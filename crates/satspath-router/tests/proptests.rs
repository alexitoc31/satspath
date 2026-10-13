use bech32::ToBase32;
use proptest::prelude::*;
use satspath_core::crypto::sign_profile;
use satspath_core::{
    BitcoinNetwork, Bolt12Offer, PaymentMethod, PaymentProfile, SignedPaymentProfile,
};
use satspath_router::ark_routes::SenderCapabilities;
use satspath_router::bolt12::{
    encode_tlv_stream, BlindedHop, BlindedPath, TlvRecord, TLV_OFFER_DESCRIPTION, TLV_OFFER_PATHS,
};
use satspath_router::fees::FeeEstimate;
use satspath_router::router::{select_route_with_fees, RouteRequest};
use satspath_router::scoring::{score_routes, FeeSnapshot, RoutePreferences};
use satspath_router::urgency::PaymentUrgency;
use secp256k1::{PublicKey, Secp256k1, SecretKey};

// ── Helpers ────────────────────────────────────────────────────────────────

fn valid_blinded_bolt12_offer() -> String {
    let bp = BlindedPath {
        introduction_node_id: "02".to_string() + &"11".repeat(32),
        blinding_point: Some("02".to_string() + &"22".repeat(32)),
        blinded_hops: vec![BlindedHop {
            blinded_node_id: "03".to_string() + &"33".repeat(32),
            encrypted_payload: "aabbccddeeff".to_string(),
        }],
    };
    let bp_bytes = bp.encode_bytes().expect("encode bp");
    let records = vec![
        TlvRecord {
            tag: TLV_OFFER_DESCRIPTION,
            value: b"Blinded Offer".to_vec(),
        },
        TlvRecord {
            tag: TLV_OFFER_PATHS,
            value: bp_bytes,
        },
    ];
    let raw = encode_tlv_stream(&records);
    bech32::encode("lno", raw.to_base32(), bech32::Variant::Bech32m).expect("bech32")
}

const VALID_UNBLINDED_BOLT12_OFFER: &str =
    "lno1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";

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

fn arb_onchain_address(network: BitcoinNetwork) -> impl Strategy<Value = Option<String>> {
    let addr = match network {
        BitcoinNetwork::Mainnet => "bc1q00000000000000000000000000000000000000",
        BitcoinNetwork::Testnet => "tb1q00000000000000000000000000000000000000",
        BitcoinNetwork::Regtest => "bcrt1q000000000000000000000000000000000000",
    };
    prop_oneof![Just(None), Just(Some(addr.to_string())),]
}

fn arb_payment_method() -> impl Strategy<Value = PaymentMethod> {
    prop_oneof![
        (
            "[a-zA-Z0-9_-]{1,16}",
            arb_bitcoin_network(),
            proptest::option::of("sp1q00000000000000000000000000000000000000000000000000000000"),
        )
            .prop_flat_map(|(label, network, silent_payment_pubkey)| {
                arb_onchain_address(network).prop_map(move |address| PaymentMethod::Onchain {
                    label: label.clone(),
                    network,
                    address,
                    silent_payment_pubkey: silent_payment_pubkey.clone(),
                    pubkey_hint: None,
                    descriptor_hint: None,
                    address_list: vec![],
                })
            }),
        (
            "[a-zA-Z0-9_-]{1,16}",
            proptest::option::of("[a-z0-9_]{1,15}@[a-z0-9_]{1,10}\\.com"),
            proptest::option::of("https://example.com/lnurl"),
            prop_oneof![
                Just(Some(valid_blinded_bolt12_offer())),
                Just(Some(VALID_UNBLINDED_BOLT12_OFFER.to_string())),
                proptest::option::of("lno1[a-z0-9]{20,50}"),
            ],
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
            "https://example.com/ark",
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
            prop_oneof![
                Just(valid_blinded_bolt12_offer()),
                Just(VALID_UNBLINDED_BOLT12_OFFER.to_string()),
                "lno1[a-z0-9]{20,50}".prop_map(|s| s),
            ],
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
    // ── 1. Route Scoring Determinism & Contract Invariants ─────────────────

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
                // Contract: selected candidate must be available
                prop_assert!(d1.selected.available, "selected candidate must be marked available");
                // Contract: selected + alternatives is bounded by candidate methods count
                let total_candidates = d1.alternatives.len() + 1;
                prop_assert!(total_candidates <= signed_profile.profile.methods.len(), "candidates count bounded by methods count");
            }
            (Err(e1), Err(e2)) => {
                prop_assert_eq!(e1.to_string(), e2.to_string(), "score_routes must return identical error for identical inputs");
            }
            _ => {
                prop_assert!(false, "score_routes returned differing success/failure for identical inputs");
            }
        }
    }

    // ── 2. Route Selection With Fees Determinism & Contract Invariants ─────

    #[test]
    fn test_select_route_with_fees_is_deterministic(
        amount_sats in 1u64..5_000_000u64,
        signed_profile in arb_signed_profile(),
        urgency in arb_payment_urgency(),
        fee_est in arb_fee_estimate(),
        max_fee_sats in proptest::option::of(100u64..100_000u64),
        max_fee_percent in proptest::option::of(0.01f64..10.0f64),
    ) {
        let req = RouteRequest {
            alias: signed_profile.profile.alias.clone(),
            amount_sats,
            signed_profile: signed_profile.clone(),
            urgency,
            max_fee_sats,
            max_fee_percent,
        };

        let quote1 = select_route_with_fees(&req, &fee_est);
        let quote2 = select_route_with_fees(&req, &fee_est);

        match (&quote1, &quote2) {
            (Ok(q1), Ok(q2)) => {
                prop_assert_eq!(q1, q2, "select_route_with_fees must return identical RouteQuote for identical inputs");

                // Contract: When amount < 100,000 sats and an available Lightning method exists, Lightning is chosen
                let has_available_ln = req.signed_profile.profile.methods.iter().any(|m| {
                    satspath_router::lightning::is_lightning_available_for_amount_sync(m, amount_sats)
                });
                if amount_sats < 100_000 && has_available_ln {
                    prop_assert!(
                        matches!(q1.selected_method, PaymentMethod::Lightning { .. } | PaymentMethod::Bolt12(_)),
                        "Amount < 100,000 sats with available Lightning must choose Lightning/Bolt12"
                    );
                }
            }
            (Err(e1), Err(e2)) => {
                prop_assert_eq!(e1.to_string(), e2.to_string(), "select_route_with_fees must return identical error for identical inputs");
            }
            _ => {
                prop_assert!(false, "select_route_with_fees returned differing success/failure for identical inputs");
            }
        }
    }

    // ── 3. Payment Urgency Fee Rate Monotonicity ───────────────────────────

    #[test]
    fn test_payment_urgency_fee_rate_monotonicity(fee_est in arb_fee_estimate()) {
        let urgent = PaymentUrgency::Urgent.select_fee_rate(&fee_est);
        let commercial = PaymentUrgency::Commercial.select_fee_rate(&fee_est);
        let normal = PaymentUrgency::Normal.select_fee_rate(&fee_est);
        let economy = PaymentUrgency::Economy.select_fee_rate(&fee_est);

        prop_assert!(urgent >= commercial, "urgent fee rate must be >= commercial");
        prop_assert!(commercial >= normal, "commercial fee rate must be >= normal");
        prop_assert!(normal >= economy, "normal fee rate must be >= economy");
        prop_assert!(economy >= 1, "economy fee rate must be >= 1");
    }
}
