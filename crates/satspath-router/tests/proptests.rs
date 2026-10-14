use bech32::ToBase32;
use bitcoin::{Address, CompressedPublicKey, Network};
use proptest::prelude::*;
use satspath_core::crypto::sign_profile;
use satspath_core::validation::validate_public_profile;
use satspath_core::{
    BitcoinNetwork, Bolt12Offer, PaymentMethod, PaymentProfile, SignedPaymentProfile,
};
use satspath_router::ark_routes::SenderCapabilities;
use satspath_router::bolt12::{
    encode_tlv_stream, write_tu64, BlindedHop, BlindedPath, TlvRecord, TLV_OFFER_AMOUNT,
    TLV_OFFER_DESCRIPTION, TLV_OFFER_NODE_ID, TLV_OFFER_PATHS,
};
use satspath_router::fees::FeeEstimate;
use satspath_router::router::{select_route_with_fees, RouteRequest};
use satspath_router::scoring::{
    score_routes, FeeSnapshot, PaymentRail, RouteCandidate, RoutePreferences,
};
use satspath_router::silent_payments::{
    create_silent_payment_address_for_network, parse_silent_payment_address,
};
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

fn valid_unblinded_bolt12_offer(minimum_amount_sats: Option<u64>) -> String {
    let mut records = vec![
        TlvRecord {
            tag: TLV_OFFER_DESCRIPTION,
            value: b"Unblinded Offer".to_vec(),
        },
        TlvRecord {
            tag: TLV_OFFER_NODE_ID,
            value: [vec![0x02], vec![0x11; 32]].concat(),
        },
    ];
    if let Some(minimum) = minimum_amount_sats {
        records.push(TlvRecord {
            tag: TLV_OFFER_AMOUNT,
            value: write_tu64(minimum * 1_000),
        });
    }
    let raw = encode_tlv_stream(&records);
    bech32::encode("lno", raw.to_base32(), bech32::Variant::Bech32m).expect("bech32")
}

fn bitcoin_network(network: BitcoinNetwork) -> Network {
    match network {
        BitcoinNetwork::Mainnet => Network::Bitcoin,
        BitcoinNetwork::Testnet => Network::Testnet,
        BitcoinNetwork::Regtest => Network::Regtest,
    }
}

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

fn onchain_method(
    network: BitcoinNetwork,
    address: Option<String>,
    silent_payment_pubkey: Option<String>,
) -> PaymentMethod {
    PaymentMethod::Onchain {
        label: "BTC".into(),
        network,
        address,
        silent_payment_pubkey,
        pubkey_hint: None,
        descriptor_hint: None,
        address_list: vec![],
    }
}

// Independent scoring oracle: use only the returned candidate's attributes and inputs.
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

fn corrupt_checksum(mut address: String) -> String {
    let last = address.pop().expect("nonempty address");
    address.push(if last == 'q' { 'p' } else { 'q' });
    address
}

fn bip352_data(version: u8, payload: &[u8]) -> Vec<bech32::u5> {
    let mut data = vec![bech32::u5::try_from_u8(version).expect("5-bit version")];
    data.extend(payload.to_base32());
    data
}

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
    let sk = SecretKey::from_slice(&[1; 32]).expect("fixture key");
    let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
    let address = Address::p2wpkh(&CompressedPublicKey(pk), bitcoin_network(network)).to_string();
    // Routing properties exercise method presence; validation is tested separately below.
    prop_oneof![Just(None), Just(Some(address))]
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
                Just(Some(valid_unblinded_bolt12_offer(None))),
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
                Just(valid_unblinded_bolt12_offer(None)),
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

    // Address validity is a validate_public_profile contract, separate from routing.
    #[test]
    fn test_public_profile_validates_bitcoin_network_and_address(
        sk in arb_secret_key(),
        network in arb_bitcoin_network(),
    ) {
        let pk = PublicKey::from_secret_key(&Secp256k1::new(), &sk);
        let address = Address::p2wpkh(&CompressedPublicKey(pk), bitcoin_network(network)).to_string();
        let mut profile = payment_profile(&sk, vec![onchain_method(network, Some(address.clone()), None)]);
        prop_assert!(validate_public_profile(&profile).is_ok(), "valid Bitcoin address must pass");

        let wrong_network = match network {
            BitcoinNetwork::Mainnet => BitcoinNetwork::Testnet,
            BitcoinNetwork::Testnet => BitcoinNetwork::Regtest,
            BitcoinNetwork::Regtest => BitcoinNetwork::Mainnet,
        };
        profile.methods = vec![onchain_method(wrong_network, Some(address.clone()), None)];
        prop_assert!(validate_public_profile(&profile).is_err(), "mismatched Bitcoin network must fail");

        profile.methods = vec![onchain_method(network, Some(corrupt_checksum(address)), None)];
        prop_assert!(validate_public_profile(&profile).is_err(), "malformed Bitcoin checksum must fail");
    }

    #[test]
    fn test_public_profile_validates_bip352_network_and_payload(
        network in arb_bitcoin_network(),
        truncated_length in 0usize..66,
        extra_length in 1usize..32,
    ) {
        // Fixed public-key fixtures avoid accidental private-material keywords in encodings.
        let scan_sk = SecretKey::from_slice(&[1; 32]).expect("scan fixture key");
        let spend_sk = SecretKey::from_slice(&[2; 32]).expect("spend fixture key");
        let secp = Secp256k1::new();
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);
        // Independently construct BIP-352's 5-bit version followed by the
        // Base32 conversion of the 66-byte compressed public-key pair.
        let hrp = if network == BitcoinNetwork::Mainnet { "sp" } else { "tsp" };
        let payload = [scan_pk.serialize(), spend_pk.serialize()].concat();
        let data = bip352_data(0, &payload);
        let address = bech32::encode(hrp, &data, bech32::Variant::Bech32m)
            .expect("valid silent payment fixture");
        prop_assert_eq!(address.len(), if hrp == "sp" { 116 } else { 117 });
        prop_assert_eq!(create_silent_payment_address_for_network(&scan_pk, &spend_pk, bitcoin_network(network))
            .expect("encode fixture"), address.clone());
        let mut profile = payment_profile(&spend_sk, vec![onchain_method(network, None, Some(address.clone()))]);
        prop_assert!(validate_public_profile(&profile).is_ok(), "valid BIP-352 address must pass");

        // Testnet and regtest both use tsp; only crossing mainnet is a mismatch.
        let wrong_network = if network == BitcoinNetwork::Mainnet {
            BitcoinNetwork::Testnet
        } else {
            BitcoinNetwork::Mainnet
        };
        profile.methods = vec![onchain_method(wrong_network, None, Some(address.clone()))];
        prop_assert!(validate_public_profile(&profile).is_err(), "mismatched BIP-352 network must fail");

        // Mutate the actual first 5-bit value, preserving the key payload.
        for version in 1..=31 {
            let mut versioned_data = data.clone();
            versioned_data[0] = bech32::u5::try_from_u8(version).expect("5-bit version");
            let versioned = bech32::encode(hrp, &versioned_data, bech32::Variant::Bech32m)
                .expect("encode versioned fixture");
            let parsed = parse_silent_payment_address(&versioned);
            prop_assert_eq!(parsed.is_ok(), version < 31);
            if let Ok((scan, spend, _)) = parsed {
                prop_assert_eq!((scan, spend), (scan_pk, spend_pk));
            }
            profile.methods = vec![onchain_method(network, None, Some(versioned))];
            prop_assert_eq!(validate_public_profile(&profile).is_ok(), version < 31,
                "BIP-352 version {} compatibility", version);

            // Versions 1–30 permit additional data after the key pair.
            let mut extended_payload = payload.clone();
            extended_payload.resize(payload.len() + extra_length, 0);
            let extended = bech32::encode(hrp, bip352_data(version, &extended_payload), bech32::Variant::Bech32m)
                .expect("encode extended fixture");
            let parsed = parse_silent_payment_address(&extended);
            prop_assert_eq!(parsed.is_ok(), version < 31);
            if let Ok((scan, spend, _)) = parsed {
                prop_assert_eq!((scan, spend), (scan_pk, spend_pk));
            }
            profile.methods = vec![onchain_method(network, None, Some(extended))];
            prop_assert_eq!(validate_public_profile(&profile).is_ok(), version < 31,
                "BIP-352 version {} with extra data", version);
        }

        // Re-encode malformed payloads with valid checksums so structural checks are exercised.
        for case in 0..7 {
            let mut malformed_payload = payload.clone();
            let mut variant = bech32::Variant::Bech32m;
            match case {
                0 => variant = bech32::Variant::Bech32,
                1 => malformed_payload.truncate(truncated_length),
                2 => malformed_payload.resize(payload.len() + extra_length, 0),
                3 => malformed_payload[0] = 4,
                4 => malformed_payload[1..33].fill(0xff),
                5 => malformed_payload[34..66].fill(0xff),
                6 => malformed_payload[33] = 4,
                _ => unreachable!(),
            }
            let malformed = bech32::encode(hrp, bip352_data(0, &malformed_payload), variant).expect("encode malformed fixture");
            profile.methods = vec![onchain_method(network, None, Some(malformed))];
            prop_assert!(validate_public_profile(&profile).is_err(), "malformed BIP-352 case {} must fail", case);
        }
        profile.methods = vec![onchain_method(network, None, Some(corrupt_checksum(address)))];
        prop_assert!(validate_public_profile(&profile).is_err(), "malformed BIP-352 checksum must fail");
    }
}

#[test]
fn test_bolt12_only_rejects_amount_below_encoded_minimum() {
    let sk = SecretKey::from_slice(&[1; 32]).expect("fixture key");
    let offer = valid_unblinded_bolt12_offer(Some(5_000));
    let methods = [
        PaymentMethod::Lightning {
            label: "BOLT12 only".into(),
            lightning_address: None,
            lnurl: None,
            bolt12: Some(offer.clone()),
            receiver_pubkey: None,
        },
        PaymentMethod::Bolt12(Bolt12Offer {
            label: "BOLT12 only".into(),
            offer,
            network: BitcoinNetwork::Mainnet,
            // Leave metadata unset to test the minimum encoded in the offer itself.
            minimum_amount_sats: None,
            expires_at: None,
            issuer_pubkey: hex::encode(
                PublicKey::from_secret_key(&Secp256k1::new(), &sk).serialize(),
            ),
        }),
    ];
    for method in methods {
        let mut req = RouteRequest {
            alias: "alice@example.com".into(),
            amount_sats: 4_999,
            signed_profile: sign_profile(payment_profile(&sk, vec![method.clone()]), &sk)
                .expect("sign fixture"),
            urgency: PaymentUrgency::Normal,
            max_fee_sats: None,
            max_fee_percent: None,
        };
        let fees = FeeEstimate::default();
        assert!(
            select_route_with_fees(&req, &fees).is_err(),
            "request below the encoded 5,000 sat minimum must be rejected"
        );
        req.amount_sats = 5_000;
        assert_eq!(
            select_route_with_fees(&req, &fees)
                .expect("minimum amount is payable")
                .selected_method,
            method
        );
    }
}
