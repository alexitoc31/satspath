use satspath_core::{
    BitcoinNetwork, Bolt12Offer as CoreBolt12Offer, PaymentMethod, PaymentProfile,
    SignedPaymentProfile,
};
use satspath_router::bolt12::{
    create_invoice_from_request, create_signed_invoice_request, parse_bolt12_invoice,
    parse_bolt12_invoice_request, validate_bolt12_invoice_against_offer, BlindedHop, BlindedPath,
    Bolt12Offer,
};
use satspath_router::scoring::{score_routes, FeeSnapshot, PaymentRail, RoutePreferences};
use satspath_router::{select_route, PaymentUrgency, RouteRequest, SwapDirective};
use secp256k1::rand::RngCore;

fn generate_key() -> secp256k1::SecretKey {
    let mut bytes = [0u8; 32];
    secp256k1::rand::thread_rng().fill_bytes(&mut bytes);
    secp256k1::SecretKey::from_slice(&bytes).unwrap()
}

fn dummy_signed_profile(alias: &str, method: PaymentMethod) -> SignedPaymentProfile {
    let key = satspath_core::crypto::generate_identity_keypair();
    let profile = PaymentProfile {
        alias: alias.to_string(),
        identity_pubkey: hex::encode(key.public_key.serialize()),
        methods: vec![method],
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
    let offer_str = "lno1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
    let method = PaymentMethod::Bolt12(CoreBolt12Offer {
        label: "Primary BOLT12".to_string(),
        offer: offer_str.to_string(),
        network: BitcoinNetwork::Mainnet,
        minimum_amount_sats: Some(1_000),
        expires_at: None,
        issuer_pubkey: "02".to_string() + &"11".repeat(32),
    });

    let profile = dummy_signed_profile("alice@satspath.com", method.clone());
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
        } if offer == offer_str
    ));
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
        bolt12: Some(offer.offer.clone()),
        receiver_pubkey: None,
    };

    let profile = dummy_signed_profile("merchant@satspath.com", method);
    let fee_snap = FeeSnapshot::default();
    let prefs = RoutePreferences::default();

    let decision = score_routes(25_000, &profile, &fee_snap, &prefs).unwrap();
    assert_eq!(decision.selected.rail, PaymentRail::Lightning);
    // Privacy score receives bonus (score = 9 for blinded paths vs 7 for standard)
    assert!(decision.selected.privacy_score >= 8);
}
