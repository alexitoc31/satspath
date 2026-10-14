use bech32::{FromBase32, ToBase32};
use satspath_core::{
    BitcoinNetwork, Bolt12Offer as CoreBolt12Offer, PaymentMethod, PaymentProfile,
    SignedPaymentProfile,
};
use satspath_router::bolt12::{
    create_invoice_from_request, create_signed_invoice_request, decode_tlv_stream,
    encode_tlv_stream, parse_bolt12_invoice, parse_bolt12_invoice_request, parse_bolt12_offer,
    validate_bolt12_invoice_against_offer, write_tu64, BlindedHop, BlindedPath, Bolt12Offer,
    TlvRecord, TLV_OFFER_AMOUNT, TLV_OFFER_NODE_ID, TLV_OFFER_PATHS,
};
use satspath_router::lightning::is_lightning_available_for_amount;
use satspath_router::scoring::{score_routes, FeeSnapshot, PaymentRail, RoutePreferences};
use satspath_router::{
    is_lightning_available_for_amount_sync, select_route, select_route_with_fees, FeeEstimate,
    PaymentUrgency, RouteRequest, SwapDirective,
};
use secp256k1::rand::RngCore;

fn encode_offer(records: &[TlvRecord]) -> String {
    bech32::encode(
        "lno",
        encode_tlv_stream(records).to_base32(),
        bech32::Variant::Bech32m,
    )
    .unwrap()
}

fn issuer_id_record() -> TlvRecord {
    TlvRecord {
        // Type 22 is offer_issuer_id (called offer_node_id in this prototype).
        tag: TLV_OFFER_NODE_ID,
        value: hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap(),
    }
}

fn generate_key() -> secp256k1::SecretKey {
    let mut bytes = [0u8; 32];
    secp256k1::rand::thread_rng().fill_bytes(&mut bytes);
    secp256k1::SecretKey::from_slice(&bytes).unwrap()
}

fn dummy_signed_profile(alias: &str, methods: Vec<PaymentMethod>) -> SignedPaymentProfile {
    let key = satspath_core::crypto::generate_identity_keypair();
    let profile = PaymentProfile {
        alias: alias.to_string(),
        identity_pubkey: hex::encode(key.public_key.serialize()),
        methods,
        updated_at: 1_700_000_000,
        expires_at: None,
        sequence: Some(0),
        preferences: vec![],
        nonce: None,
        rotation: None,
        method_verifications: vec![],
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
        recovery_policy: None,
        recovery: None,
    };
    satspath_core::crypto::sign_profile(profile, &key.secret_key).unwrap()
}

#[test]
fn test_cln_ldk_bolt12_offer_parsing_and_blinded_paths() {
    let intro_node = "02".to_string() + &"aa".repeat(32);
    let hop_node = "03".to_string() + &"bb".repeat(32);

    let blinded_path = BlindedPath {
        introduction_node_id: intro_node.clone(),
        blinding_point: Some("02".to_string() + &"cc".repeat(32)),
        blinded_hops: vec![BlindedHop {
            blinded_node_id: hop_node,
            encrypted_payload: "aabbccddeeff".to_string(),
        }],
    };

    let offer = Bolt12Offer {
        offer: "lno1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_string(),
        description: Some("LDK/CLN Coffee Offer".to_string()),
        amount_msats: Some(21_000_000), // 21,000 sats
        currency: Some("btc".to_string()),
        min_amount_msats: Some(10_000_000),
        max_amount_msats: Some(100_000_000),
        quantity: Some(5),
        absolute_expiry: Some(2_000_000_000),
        relative_expiry: None,
        paths: None,
        blinded_paths: Some(vec![blinded_path]),
        issuer: Some("LN Coffee Bar".to_string()),
        node_id: Some("02".to_string() + &"dd".repeat(32)),
        signature: None,
    };

    assert!(offer.has_blinded_paths());
    assert_eq!(
        offer.primary_blinded_path().unwrap().introduction_node_id,
        intro_node
    );
    assert!(!offer.is_expired(1_700_000_000));
    assert!(offer.is_expired(2_100_000_000));
    assert!(offer.is_amount_valid(21_000_000));
    assert!(offer.is_amount_valid(50_000_000));
    assert!(!offer.is_amount_valid(5_000_000));
    assert!(!offer.is_amount_valid(150_000_000));
}

#[test]
fn test_bolt12_offer_to_invoice_request_to_invoice_roundtrip() {
    let payer_key = generate_key();
    let node_key = generate_key();

    let offer = Bolt12Offer {
        offer: "lno1pq...".to_string(),
        description: Some("Donation to Open Source".to_string()),
        amount_msats: Some(10_000_000), // 10,000 sats
        currency: Some("btc".to_string()),
        min_amount_msats: Some(1_000_000),
        max_amount_msats: None,
        quantity: None,
        absolute_expiry: None,
        relative_expiry: None,
        paths: None,
        blinded_paths: None,
        issuer: Some("SatsPath Contributor".to_string()),
        node_id: None,
        signature: None,
    };

    // 1. Payer generates signed invoice request
    let invreq = create_signed_invoice_request(
        &offer,
        10_000_000,
        &payer_key,
        Some("For Satoshi's vision"),
        Some(1),
    )
    .unwrap();

    let invreq_str = invreq.encode().unwrap();
    assert!(invreq_str.starts_with("lnr1"));

    // 2. Node decodes invoice request
    let parsed_invreq = parse_bolt12_invoice_request(&invreq_str).unwrap();
    assert_eq!(parsed_invreq.amount_msats, 10_000_000);
    assert_eq!(
        parsed_invreq.payer_note.as_deref(),
        Some("For Satoshi's vision")
    );

    // 3. Node creates signed BOLT12 invoice
    let mut payment_hash = [0u8; 32];
    secp256k1::rand::thread_rng().fill_bytes(&mut payment_hash);

    let invoice =
        create_invoice_from_request(&offer, &parsed_invreq, &node_key, payment_hash, Some(7200))
            .unwrap();

    assert_eq!(invoice.amount_msats, 10_000_000);
    assert!(invoice.invoice.starts_with("lni1"));

    // 4. Payer parses and validates the returned invoice
    let parsed_invoice = parse_bolt12_invoice(&invoice.invoice).unwrap();
    assert_eq!(parsed_invoice.amount_msats, 10_000_000);

    let val_res = validate_bolt12_invoice_against_offer(&parsed_invoice, &offer, 10_000_000);
    assert!(val_res.is_ok());

    // 5. Validation rejects incorrect amount
    let val_mismatch = validate_bolt12_invoice_against_offer(&parsed_invoice, &offer, 20_000_000);
    assert!(val_mismatch.is_err());
}

#[tokio::test]
async fn test_bolt12_routing_selection_and_directive() {
    let offer_str = encode_offer(&[issuer_id_record()]);
    let method = PaymentMethod::Bolt12(CoreBolt12Offer {
        label: "Primary BOLT12".to_string(),
        offer: offer_str.clone(),
        network: BitcoinNetwork::Mainnet,
        minimum_amount_sats: Some(1_000),
        expires_at: None,
        issuer_pubkey: "02".to_string() + &"11".repeat(32),
    });

    let profile = dummy_signed_profile("alice@satspath.com", vec![method.clone()]);
    let req = RouteRequest {
        alias: "alice@satspath.com".to_string(),
        amount_sats: 50_000,
        signed_profile: profile,
        urgency: PaymentUrgency::Normal,
        max_fee_sats: None,
        max_fee_percent: None,
    };

    let quote = select_route(&req).await.unwrap();
    assert_eq!(quote.selected_method, method);
    assert!(matches!(
        quote.swap_directive,
        SwapDirective::Bolt12Payment {
            ref offer,
            ..
        } if offer == &offer_str
    ));
}

#[tokio::test]
async fn test_bolt12_amount_availability_and_route_selection() {
    let invalid_bech32 = "lno1pq...";
    assert!(bech32::decode(invalid_bech32).is_err());
    let invalid_base32 = bech32::encode(
        "lno",
        vec![bech32::u5::try_from_u8(1).unwrap()],
        bech32::Variant::Bech32m,
    )
    .unwrap();
    let (_, data, _) = bech32::decode(&invalid_base32).unwrap();
    assert!(Vec::<u8>::from_base32(&data).is_err());
    let invalid_tlv = bech32::encode(
        "lno",
        [8, 2, 1].to_base32(), // Amount value claims two bytes but contains only one.
        bech32::Variant::Bech32m,
    )
    .unwrap();
    let (_, data, _) = bech32::decode(&invalid_tlv).unwrap();
    let raw = Vec::<u8>::from_base32(&data).unwrap();
    assert!(decode_tlv_stream(&raw).is_err());
    for offer in [invalid_bech32, &invalid_base32, &invalid_tlv] {
        assert!(parse_bolt12_offer(offer).is_err());
    }
    let malformed = encode_offer(&[TlvRecord {
        tag: TLV_OFFER_PATHS,
        value: vec![],
    }]);
    assert!(parse_bolt12_offer(&malformed).is_err());
    let missing_destination = encode_offer(&[]);
    let amount_without_destination = encode_offer(&[TlvRecord {
        tag: TLV_OFFER_AMOUNT,
        value: write_tu64(5_000_000),
    }]);
    for offer in [&missing_destination, &amount_without_destination] {
        let err = parse_bolt12_offer(offer).unwrap_err();
        assert!(err.to_string().contains("invoice-request destination"));
    }
    let amountless = encode_offer(&[issuer_id_record()]);
    let fixed_amount = encode_offer(&[
        TlvRecord {
            tag: TLV_OFFER_AMOUNT,
            value: write_tu64(5_000_000),
        },
        issuer_id_record(),
    ]);
    let node_id = hex::encode(issuer_id_record().value);
    let path_only = encode_offer(&[TlvRecord {
        tag: TLV_OFFER_PATHS,
        value: BlindedPath {
            introduction_node_id: node_id.clone(),
            blinding_point: Some(node_id.clone()),
            blinded_hops: vec![BlindedHop {
                blinded_node_id: node_id,
                encrypted_payload: "00".into(),
            }],
        }
        .encode_bytes()
        .unwrap(),
    }]);
    for offer in [&amountless, &fixed_amount, &path_only] {
        assert!(parse_bolt12_offer(offer).is_ok());
    }
    let fallback = PaymentMethod::Lightning {
        label: "Fallback LNURL".into(),
        lightning_address: None,
        lnurl: Some("https://example.com/lnurl".into()),
        bolt12: None,
        receiver_pubkey: None,
    };
    let fees = FeeEstimate {
        fastest_fee: 1,
        half_hour_fee: 1,
        hour_fee: 1,
        economy_fee: 1,
        minimum_fee: 1,
    };

    for (offer, amount_sats, expected) in [
        ("invalid", 5_000, false),
        (invalid_bech32, 5_000, false),
        (invalid_base32.as_str(), 5_000, false),
        (invalid_tlv.as_str(), 5_000, false),
        (malformed.as_str(), 5_000, false),
        (missing_destination.as_str(), 5_000, false),
        (amount_without_destination.as_str(), 5_000, false),
        (path_only.as_str(), 500, true),
        (amountless.as_str(), 499, true),
        (amountless.as_str(), 500, true),
        (fixed_amount.as_str(), 4_999, false),
        (fixed_amount.as_str(), 5_000, true),
        (fixed_amount.as_str(), 5_001, true),
    ] {
        for (method, expected) in [
            (
                PaymentMethod::Lightning {
                    label: "BOLT12".into(),
                    lightning_address: None,
                    lnurl: None,
                    bolt12: Some(offer.into()),
                    receiver_pubkey: None,
                },
                expected,
            ),
            (
                PaymentMethod::Bolt12(CoreBolt12Offer {
                    label: "BOLT12".into(),
                    offer: offer.into(),
                    network: BitcoinNetwork::Mainnet,
                    minimum_amount_sats: Some(500),
                    expires_at: None,
                    issuer_pubkey: "02".to_string() + &"11".repeat(32),
                }),
                expected && amount_sats >= 500,
            ),
        ] {
            assert_eq!(
                is_lightning_available_for_amount_sync(&method, amount_sats),
                expected
            );
            assert_eq!(
                is_lightning_available_for_amount(&method, amount_sats).await,
                expected
            );
            let profile =
                dummy_signed_profile("alice@example.com", vec![method.clone(), fallback.clone()]);
            let req = RouteRequest {
                alias: "alice@example.com".into(),
                amount_sats,
                signed_profile: profile,
                urgency: PaymentUrgency::Normal,
                max_fee_sats: None,
                max_fee_percent: None,
            };
            let selected = if expected { &method } else { &fallback };
            assert_eq!(
                &select_route_with_fees(&req, &fees).unwrap().selected_method,
                selected
            );
            assert_eq!(&select_route(&req).await.unwrap().selected_method, selected);
        }
    }
}

#[test]
fn test_bolt12_scoring_blinded_path_privacy_bonus() {
    let intro_node = "02".to_string() + &"aa".repeat(32);
    let hop_node = "03".to_string() + &"bb".repeat(32);

    let blinded_path = BlindedPath {
        introduction_node_id: intro_node,
        blinding_point: Some("02".to_string() + &"cc".repeat(32)),
        blinded_hops: vec![BlindedHop {
            blinded_node_id: hop_node,
            encrypted_payload: "112233".to_string(),
        }],
    };

    let offer = Bolt12Offer {
        offer: "lno1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_string(),
        description: Some("Private Merchant".to_string()),
        amount_msats: None,
        currency: Some("btc".to_string()),
        min_amount_msats: None,
        max_amount_msats: None,
        quantity: None,
        absolute_expiry: None,
        relative_expiry: None,
        paths: None,
        blinded_paths: Some(vec![blinded_path]),
        issuer: None,
        node_id: None,
        signature: None,
    };

    assert!(offer.has_blinded_paths());

    let method = PaymentMethod::Lightning {
        label: "Private LN".to_string(),
        lightning_address: None,
        lnurl: None,
        bolt12: Some(encode_offer(&[TlvRecord {
            tag: TLV_OFFER_PATHS,
            value: offer
                .primary_blinded_path()
                .unwrap()
                .encode_bytes()
                .unwrap(),
        }])),
        receiver_pubkey: None,
    };

    let profile = dummy_signed_profile("merchant@satspath.com", vec![method]);
    let fee_snap = FeeSnapshot::default();
    let prefs = RoutePreferences::default();

    let decision = score_routes(25_000, &profile, &fee_snap, &prefs).unwrap();
    assert_eq!(decision.selected.rail, PaymentRail::Lightning);
    // Privacy score receives bonus (score = 9 for blinded paths vs 7 for standard)
    assert!(decision.selected.privacy_score >= 8);
}
