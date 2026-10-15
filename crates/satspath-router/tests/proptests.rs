use bech32::ToBase32;
use bitcoin::{Address, CompressedPublicKey, Network};
use proptest::prelude::*;
use satspath_core::crypto::sign_profile;
use satspath_core::{
    BitcoinNetwork, Bolt12Offer, PaymentMethod, PaymentPointer, PaymentProfile, SatsPathError,
    SignedPaymentProfile,
};
use satspath_router::ark_routes::SenderCapabilities;
use satspath_router::bolt12::{
    encode_tlv_stream, BlindedHop, BlindedPath, TlvRecord, TLV_OFFER_DESCRIPTION,
    TLV_OFFER_NODE_ID, TLV_OFFER_PATHS,
};
use satspath_router::fees::FeeEstimate;
use satspath_router::router::{select_route_with_fees, RouteRequest, SwapDirective};
use satspath_router::scoring::{
    score_routes, FeeSnapshot, PaymentRail, RouteCandidate, RoutePreferences,
};
use satspath_router::urgency::PaymentUrgency;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use std::str::FromStr;

// ── Helpers ────────────────────────────────────────────────────────────────

/// Build a parseable blinded offer fixture for routing determinism tests.
fn valid_blinded_bolt12_offer() -> String {
    let bp = BlindedPath {
        introduction_node_id: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .into(),
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

/// Build a parseable unblinded offer fixture without an encoded minimum amount.
fn valid_unblinded_bolt12_offer() -> String {
    let records = vec![
        TlvRecord {
            tag: TLV_OFFER_DESCRIPTION,
            value: b"Unblinded Offer".to_vec(),
        },
        TlvRecord {
            tag: TLV_OFFER_NODE_ID,
            value: hex::decode(
                "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            )
            .expect("valid offer issuer key"),
        },
    ];
    let raw = encode_tlv_stream(&records);
    bech32::encode("lno", raw.to_base32(), bech32::Variant::Bech32m).expect("bech32")
}

/// Map profile network names to the Bitcoin address library equivalents.
fn bitcoin_network(network: BitcoinNetwork) -> Network {
    match network {
        BitcoinNetwork::Mainnet => Network::Bitcoin,
        BitcoinNetwork::Testnet => Network::Testnet,
        BitcoinNetwork::Regtest => Network::Regtest,
    }
}

/// Build a profile fixture using an identity signing key and supplied methods.
fn payment_profile(sk: &SecretKey, methods: Vec<PaymentMethod>) -> PaymentProfile {
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), sk);
    PaymentProfile {
        alias: "alice@example.com".into(),
        identity_pubkey: hex::encode(pk.serialize()),
        methods,
        updated_at: 1,
        expires_at: None,
        sequence: None,
        preferences: vec!["lightning".into(), "onchain".into(), "ark".into()],
        nonce: None,
        rotation: None,
        method_verifications: vec![],
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
        recovery_policy: None,
        recovery: None,
    }
}

/// Sign a deterministic request with the fixture identity key.
fn route_request(amount_sats: u64, methods: Vec<PaymentMethod>) -> RouteRequest {
    let sk = SecretKey::from_slice(&[1u8; 32]).expect("fixture identity key");
    let profile = payment_profile(&sk, methods);
    RouteRequest {
        alias: profile.alias.clone(),
        amount_sats,
        signed_profile: sign_profile(profile, &sk).expect("sign fixture profile"),
        urgency: PaymentUrgency::Normal,
        max_fee_sats: None,
        max_fee_percent: None,
    }
}

/// Provide a Lightning Address for route boundary tests.
fn lightning_method() -> PaymentMethod {
    PaymentMethod::Lightning {
        label: "Lightning".into(),
        lightning_address: Some("alice@example.com".into()),
        lnurl: None,
        bolt12: None,
        receiver_pubkey: None,
    }
}

/// Provide a mainnet payment address derived solely from public key material.
fn onchain_method() -> PaymentMethod {
    let pk =
        PublicKey::from_str("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .expect("fixed public payment key");
    PaymentMethod::Onchain {
        label: "Bitcoin".into(),
        network: BitcoinNetwork::Mainnet,
        address: Some(Address::p2wpkh(&CompressedPublicKey(pk), Network::Bitcoin).to_string()),
        silent_payment_pubkey: None,
        pubkey_hint: None,
        descriptor_hint: None,
        address_list: vec![],
    }
}

/// Provide a public Ark receiver for routing tests.
fn ark_method() -> PaymentMethod {
    PaymentMethod::Ark {
        label: "Ark".into(),
        server: "https://example.com/ark".into(),
        pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
        vtxo_pointer: None,
        proof: None,
        expires_at: None,
        opaque_uri: None,
    }
}

/// Provide fee rates below the on-chain routing threshold.
fn low_fees() -> FeeEstimate {
    FeeEstimate {
        fastest_fee: 5,
        half_hour_fee: 4,
        hour_fee: 3,
        economy_fee: 2,
        minimum_fee: 1,
    }
}

/// Compute the expected score from candidate attributes and routing preferences.
fn expected_score(
    candidate: &RouteCandidate,
    preferences: &RoutePreferences,
    amount_sats: u64,
    profile_preferences: &[String],
) -> i64 {
    let mut score = i64::from(candidate.reliability_score) * 10
        + i64::from(candidate.privacy_score) * if preferences.prefer_privacy { 8 } else { 2 };
    if preferences.prefer_speed {
        score -= candidate.estimated_time_seconds.unwrap_or(3_600) as i64 / 30;
    }
    if preferences.prefer_low_fee {
        score -= candidate.estimated_fee_sats.unwrap_or(10_000) as i64 / 10;
    }
    match candidate.rail {
        PaymentRail::Lightning if amount_sats <= 1_000_000 => score += 30,
        PaymentRail::Onchain if amount_sats >= 1_000_000 => score += 20,
        PaymentRail::Ark if !preferences.allow_experimental_ark => score -= 1_000,
        _ => {}
    }
    let rail_name = match candidate.rail {
        PaymentRail::Lightning => "lightning",
        PaymentRail::Onchain => "onchain",
        PaymentRail::Ark => "ark",
    };
    if let Some(rank) = profile_preferences.iter().position(|p| p == rail_name) {
        score += 50i64.saturating_sub(rank as i64 * 10);
    }
    score
}

// ── Strategies ─────────────────────────────────────────────────────────────

/// Generate identity signing keys for profile tests.
fn arb_secret_key() -> impl Strategy<Value = SecretKey> {
    any::<[u8; 32]>().prop_filter_map("valid secp256k1 secret key", |bytes| {
        SecretKey::from_slice(&bytes).ok()
    })
}

/// Sample the Bitcoin networks represented by payment profiles.
fn arb_bitcoin_network() -> impl Strategy<Value = BitcoinNetwork> {
    prop_oneof![
        Just(BitcoinNetwork::Mainnet),
        Just(BitcoinNetwork::Testnet),
        Just(BitcoinNetwork::Regtest),
    ]
}

/// Optionally supply a network-specific address derived from a fixed public key.
fn arb_onchain_address(network: BitcoinNetwork) -> impl Strategy<Value = Option<String>> {
    let pk = PublicKey::from_slice(
        &hex::decode("031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078f")
            .expect("public address fixture"),
    )
    .expect("compressed public key");
    let address = Address::p2wpkh(&CompressedPublicKey(pk), bitcoin_network(network)).to_string();
    // Vary address presence for routing without generating private spending keys.
    prop_oneof![Just(None), Just(Some(address))]
}

/// Generate payment-method fields for property tests, including malformed pointers.
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
                Just(Some(valid_unblinded_bolt12_offer())),
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
                Just(valid_unblinded_bolt12_offer()),
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

/// Generate signed identity profiles with varying methods and routing preferences.
fn arb_signed_profile() -> impl Strategy<Value = SignedPaymentProfile> {
    (
        arb_secret_key(),
        "[a-z0-9_]{1,15}@[a-z0-9_]{1,10}\\.com",
        proptest::collection::vec(arb_payment_method(), 1..5),
        0i64..2_000_000_000i64,
        proptest::option::of(0u64..1_000_000u64),
        proptest::collection::vec(
            prop_oneof![
                Just("lightning".into()),
                Just("onchain".into()),
                Just("ark".into())
            ],
            0..4,
        ),
    )
        .prop_map(|(sk, alias, methods, updated_at, sequence, preferences)| {
            let mut profile = payment_profile(&sk, methods);
            profile.alias = alias;
            profile.updated_at = updated_at;
            profile.sequence = sequence;
            profile.preferences = preferences;
            sign_profile(profile, &sk).expect("profile signing")
        })
}

/// Generate optional fee inputs to exercise present and missing fee estimates.
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

/// Generate sanitized fee estimates for deterministic route selection.
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

/// Vary route priorities, fee limits, and sender capabilities.
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

/// Sample all urgency levels used by route selection.
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
    /// A fee limit includes the exact estimate and excludes an estimate one satoshi above it.
    #[test]
    fn test_score_routes_fee_limit_is_inclusive(fee in 0u64..10_000u64) {
        let req = route_request(10_000, vec![lightning_method()]);
        let snapshot = FeeSnapshot {
            lightning_fee_sats_estimate: Some(fee),
            ..FeeSnapshot::default()
        };
        let mut preferences = RoutePreferences {
            max_fee_sats: Some(fee),
            ..RoutePreferences::default()
        };
        let decision = score_routes(req.amount_sats, &req.signed_profile, &snapshot, &preferences)
            .expect("exact fee limit must allow the route");
        prop_assert_eq!(decision.selected.estimated_fee_sats, Some(fee));
        prop_assert_eq!(decision.selected.rail, PaymentRail::Lightning);
        prop_assert!(decision.alternatives.is_empty());
        if fee > 0 {
            preferences.max_fee_sats = Some(fee - 1);
            prop_assert!(matches!(
                score_routes(req.amount_sats, &req.signed_profile, &snapshot, &preferences),
                Err(SatsPathError::NoRouteFound(_))
            ));
        }
    }

    /// A validated fallback is selected below the BOLT12 offer minimum.
    #[test]
    fn test_validated_fallback_is_selected_regardless_of_offer_minimum(minimum in 1_001u64..100_000u64) {
        let offer = valid_unblinded_bolt12_offer();
        let bolt12 = PaymentMethod::Bolt12(Bolt12Offer {
            label: "Minimum amount offer".into(),
            offer: offer.clone(),
            network: BitcoinNetwork::Mainnet,
            minimum_amount_sats: Some(minimum),
            expires_at: None,
            issuer_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
        });
        let fallback = lightning_method();
        let mut req = route_request(minimum - 1, vec![bolt12.clone(), fallback.clone()]);
        let below = select_route_with_fees(&req, &low_fees()).expect("fallback below offer minimum");
        prop_assert_eq!(&below.selected_method, &fallback);
        prop_assert!(
            matches!(below.swap_directive, SwapDirective::LightningPayment { .. }),
            "fallback must use a direct Lightning payment"
        );
        req.amount_sats = minimum;
        let at = select_route_with_fees(&req, &low_fees()).expect("offer at minimum");
        prop_assert_eq!(at.selected_method, bolt12.clone());
        prop_assert!(satspath_router::lightning::is_lightning_available_for_amount_sync(&bolt12, minimum));
        let scored_below = score_routes(minimum - 1, &req.signed_profile, &FeeSnapshot::default(), &RoutePreferences::default()).unwrap();
        prop_assert!(
            matches!(scored_below.payment_pointer, PaymentPointer::LightningAddress { .. }),
            "fallback pointer expected"
        );
    }

    // ── 1. Route Scoring Determinism & Contract Invariants ─────────────────

    /// Check repeatable scoring, candidate eligibility, and maximal selected scores.
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
                let fee_eligible = |candidate: &RouteCandidate| preferences.max_fee_sats
                    .map(|max| candidate.estimated_fee_sats.unwrap_or(u64::MAX) <= max)
                    .unwrap_or(true);
                prop_assert!(fee_eligible(&d1.selected), "selected candidate must satisfy the fee limit");
                let highest_score = std::iter::once(&d1.selected)
                    .chain(d1.alternatives.iter())
                    .filter(|candidate| candidate.available && fee_eligible(candidate))
                    .map(|candidate| expected_score(candidate, &preferences, amount_sats, &signed_profile.profile.preferences))
                    .max();
                prop_assert_eq!(
                    Some(expected_score(&d1.selected, &preferences, amount_sats, &signed_profile.profile.preferences)),
                    highest_score,
                    "selected candidate must have the highest score among eligible candidates"
                );
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

    /// Check repeatable route quotes or errors for identical requests and fee estimates.
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

                // Contract: Below 100,000 sats, a valid available Lightning method is chosen.
                let has_available_ln = req.signed_profile.profile.methods.iter().any(|m| {
                    satspath_core::handoff::validate_method(m, amount_sats).is_ok()
                        && satspath_router::lightning::is_lightning_available_for_amount_sync(m, amount_sats)
                });
                if amount_sats < 100_000 && has_available_ln {
                    prop_assert!(
                        matches!(q1.selected_method, PaymentMethod::Lightning { .. } | PaymentMethod::Bolt12(_)),
                        "Amount < 100,000 sats with available Lightning must choose Lightning/Bolt12"
                    );
                }

                let selected_offer = match &q1.selected_method {
                    PaymentMethod::Bolt12(offer) => Some(&offer.offer),
                    PaymentMethod::Lightning { bolt12, .. } => bolt12.as_ref(),
                    _ => None,
                };
                if let Some(offer) = selected_offer {
                    let expected_blinded = if *offer == valid_blinded_bolt12_offer() {
                        Some(true)
                    } else if *offer == valid_unblinded_bolt12_offer() {
                        Some(false)
                    } else {
                        None
                    };
                    if let Some(expected) = expected_blinded {
                        prop_assert!(
                            matches!(&q1.swap_directive, SwapDirective::Bolt12Payment { has_blinded_paths, .. } if *has_blinded_paths == expected),
                            "selected BOLT12 quote must reflect the fixture's blinded paths"
                        );
                    }
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

}

#[test]
/// Verify that empty profiles return no route at amount boundaries.
fn test_empty_profiles_return_no_route_at_amount_boundaries() {
    for amount in [0, 1, 999, 1_000, 99_999, 100_000] {
        let req = route_request(amount, vec![]);
        assert!(matches!(
            score_routes(
                amount,
                &req.signed_profile,
                &FeeSnapshot::default(),
                &RoutePreferences::default()
            ),
            Err(SatsPathError::NoRouteFound(_) | SatsPathError::InvalidPaymentPointer(_))
        ));
        assert!(matches!(
            select_route_with_fees(&req, &low_fees()),
            Err(SatsPathError::NoRouteFound(_) | SatsPathError::InvalidPaymentPointer(_))
        ));
    }
}

#[test]
/// Verify that score routes onchain dust boundary and missing fees.
fn test_score_routes_onchain_dust_boundary_and_missing_fees() {
    let req = route_request(546, vec![onchain_method()]);
    let fees = FeeSnapshot {
        onchain_fastest_sat_vb: Some(1),
        ..FeeSnapshot::default()
    };
    let preferences = RoutePreferences::default();
    assert!(matches!(
        score_routes(545, &req.signed_profile, &fees, &preferences),
        Err(SatsPathError::NoRouteFound(_))
    ));
    let at_dust_limit = score_routes(546, &req.signed_profile, &fees, &preferences)
        .expect("onchain is available at the dust limit");
    assert_eq!(at_dust_limit.selected.rail, PaymentRail::Onchain);
    assert_eq!(at_dust_limit.selected.estimated_fee_sats, Some(141));
    assert!(matches!(
        score_routes(
            546,
            &req.signed_profile,
            &FeeSnapshot::default(),
            &preferences
        ),
        Err(SatsPathError::NoRouteFound(_))
    ));
}

#[test]
/// Verify that score routes pointer matches method after skipped candidate.
fn test_score_routes_pointer_matches_method_after_skipped_candidate() {
    let unavailable = PaymentMethod::Lightning {
        label: "No pointer".into(),
        lightning_address: None,
        lnurl: None,
        bolt12: None,
        receiver_pubkey: None,
    };
    let req = route_request(
        10_000,
        vec![unavailable, lightning_method(), onchain_method()],
    );
    let decision = score_routes(
        req.amount_sats,
        &req.signed_profile,
        &FeeSnapshot::default(),
        &RoutePreferences::default(),
    )
    .expect("usable method after skipped method");
    assert_eq!(decision.selected.rail, PaymentRail::Lightning);
    assert_eq!(
        decision.payment_pointer,
        PaymentPointer::LightningAddress {
            address: "alice@example.com".into(),
            receiver_pubkey: None,
        }
    );
    assert_eq!(decision.alternatives.len(), 1);
    assert_eq!(decision.alternatives[0].rail, PaymentRail::Onchain);
    assert!(!decision.alternatives[0].available);
}

#[test]
/// Verify that select route lightning amount thresholds.
fn test_select_route_lightning_amount_thresholds() {
    let lightning = lightning_method();
    let onchain = onchain_method();
    let mut req = route_request(1_000, vec![lightning.clone(), onchain.clone()]);
    for amount in [1_000, 99_999] {
        req.amount_sats = amount;
        let quote = select_route_with_fees(&req, &low_fees()).expect("Lightning below threshold");
        assert_eq!(quote.selected_method, lightning);
        assert!(quote.fee_snapshot.is_none());
        assert_eq!(
            quote.swap_directive,
            SwapDirective::LightningPayment {
                target_ln_address: Some("alice@example.com".into()),
            }
        );
    }
    req.amount_sats = 100_000;
    let quote = select_route_with_fees(&req, &low_fees()).expect("onchain at threshold");
    assert_eq!(quote.selected_method, onchain);
    assert!(quote.fee_snapshot.is_some());
    let lightning_only = route_request(999, vec![lightning.clone()]);
    assert!(matches!(
        select_route_with_fees(&lightning_only, &low_fees()),
        Err(SatsPathError::NoRouteFound(_))
    ));
    let lightning_only = route_request(100_000, vec![lightning]);
    assert!(matches!(
        select_route_with_fees(&lightning_only, &low_fees()),
        Err(SatsPathError::NoRouteFound(_))
    ));
}

#[test]
/// Verify that select route urgency changes onchain and ark choice.
fn test_select_route_urgency_changes_onchain_and_ark_choice() {
    let onchain = onchain_method();
    let ark = ark_method();
    let mut req = route_request(100_000, vec![onchain.clone(), ark.clone()]);
    let fees = FeeEstimate {
        fastest_fee: 10,
        half_hour_fee: 9,
        hour_fee: 8,
        economy_fee: 7,
        minimum_fee: 1,
    };
    for (urgency, expected) in [
        (PaymentUrgency::Urgent, &ark),
        (PaymentUrgency::Commercial, &onchain),
        (PaymentUrgency::Normal, &onchain),
        (PaymentUrgency::Economy, &onchain),
    ] {
        req.urgency = urgency;
        let quote = select_route_with_fees(&req, &fees).expect("route for urgency");
        assert_eq!(&quote.selected_method, expected, "{urgency:?}");
        let snapshot = quote.fee_snapshot.expect("provided fee snapshot");
        assert_eq!(snapshot.fastest_sat_vb, 10);
        assert_eq!(snapshot.half_hour_sat_vb, 9);
        assert_eq!(snapshot.hour_sat_vb, 8);
    }
}

/// Valid offers can be discovered and routed, but are not payable wallet QRs.
#[test]
fn test_offer_validation_for_both_method_variants() {
    for (offer, valid) in [
        (valid_blinded_bolt12_offer(), true),
        (valid_unblinded_bolt12_offer(), true),
        ("lno1malformed".into(), false),
    ] {
        for method in [
            PaymentMethod::Lightning {
                label: "Embedded offer".into(),
                lightning_address: None,
                lnurl: None,
                bolt12: Some(offer.clone()),
                receiver_pubkey: None,
            },
            PaymentMethod::Bolt12(Bolt12Offer {
                label: "Standalone offer".into(),
                offer: offer.clone(),
                network: BitcoinNetwork::Mainnet,
                minimum_amount_sats: None,
                expires_at: None,
                issuer_pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                    .into(),
            }),
        ] {
            let req = route_request(10_000, vec![method.clone()]);
            assert_eq!(
                score_routes(
                    req.amount_sats,
                    &req.signed_profile,
                    &FeeSnapshot::default(),
                    &RoutePreferences::default()
                )
                .is_ok(),
                valid
            );
            assert_eq!(select_route_with_fees(&req, &low_fees()).is_ok(), valid);
            assert!(satspath_router::build_qr_payload(&method, req.amount_sats).is_err());
        }
    }
}

/// Every native entry point rejects malformed, wrong-network, expired, or unsupported receivers.
#[tokio::test]
async fn invalid_methods_never_reach_wallet_handoff() {
    let mut wrong_network = onchain_method();
    if let PaymentMethod::Onchain { network, .. } = &mut wrong_network {
        *network = BitcoinNetwork::Testnet;
    }
    let mut invalid_address = onchain_method();
    if let PaymentMethod::Onchain { address, .. } = &mut invalid_address {
        *address = Some("bc1invalid".into());
    }
    let mut expired_ark = ark_method();
    if let PaymentMethod::Ark { expires_at, .. } = &mut expired_ark {
        *expires_at = Some(1);
    }
    let mut invalid_ark_key = ark_method();
    if let PaymentMethod::Ark { pubkey, .. } = &mut invalid_ark_key {
        *pubkey = "00".repeat(33);
    }
    let mut insecure_ark = ark_method();
    if let PaymentMethod::Ark { server, .. } = &mut insecure_ark {
        *server = "http://example.com".into();
    }
    for method in [
        wrong_network,
        invalid_address,
        expired_ark,
        invalid_ark_key,
        insecure_ark,
    ] {
        let req = route_request(10_000, vec![method.clone()]);
        let prefs = RoutePreferences {
            allow_experimental_ark: true,
            ..RoutePreferences::default()
        };
        assert!(score_routes(
            req.amount_sats,
            &req.signed_profile,
            &FeeSnapshot {
                onchain_fastest_sat_vb: Some(1),
                ..FeeSnapshot::default()
            },
            &prefs
        )
        .is_err());
        assert!(select_route_with_fees(&req, &low_fees()).is_err());
        assert!(satspath_router::build_qr_payload(&method, req.amount_sats).is_err());
    }
    for amount in [0, u64::MAX] {
        let req = route_request(amount, vec![lightning_method()]);
        assert!(satspath_router::select_route(&req).await.is_err());
        assert!(satspath_router::build_qr_payload(&lightning_method(), amount).is_err());
    }
    let method = PaymentMethod::Lightning {
        label: "bad invoice".into(),
        lightning_address: None,
        lnurl: None,
        bolt12: Some("lnbc1bad".into()),
        receiver_pubkey: None,
    };
    assert!(!satspath_router::lightning::is_lightning_available_for_amount(&method, 1000).await);
    assert!(!satspath_router::lightning::is_lightning_available_for_amount_sync(&method, 1000));
}
