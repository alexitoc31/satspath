use bitcoin::secp256k1::{Parity, PublicKey, Scalar, Secp256k1, SecretKey};
use bitcoin::Network;
use rand::rngs::OsRng;
use satspath_core::pointer::BitcoinNetwork;
use satspath_core::profile::{PaymentMethod, PaymentProfile};
use satspath_core::validation::{validate_public_profile, validate_silent_payment_address};
use satspath_router::silent_payments::{
    compute_input_hash, create_silent_payment_address, create_silent_payment_address_for_network,
    derive_spending_privkey, detect_silent_payment_outputs, find_smallest_outpoint,
    generate_silent_payment_keys, parse_outpoint_to_bytes, parse_silent_payment_address,
    tagged_hash, SilentPayment, SilentPaymentInput, BIP0352_TAG_INPUTS, BIP0352_TAG_SHARED_SECRET,
};

#[test]
fn test_bip352_tagged_hash_domain_separation() {
    let tag_a = BIP0352_TAG_INPUTS;
    let tag_b = BIP0352_TAG_SHARED_SECRET;
    let data = b"sample_input_material";

    let hash_a = tagged_hash(tag_a, data);
    let hash_b = tagged_hash(tag_b, data);

    assert_ne!(
        hash_a, hash_b,
        "Domain separation between BIP0352 tags must produce distinct hashes"
    );
}

#[test]
fn test_bip352_mainnet_and_signet_address_derivation() {
    let secp = Secp256k1::new();
    let scan_sk = SecretKey::new(&mut OsRng);
    let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
    let spend_sk = SecretKey::new(&mut OsRng);
    let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

    // Mainnet derivation
    let mainnet_addr = create_silent_payment_address(&scan_pk, &spend_pk).unwrap();
    assert!(mainnet_addr.starts_with("sp1q"));
    validate_silent_payment_address(&mainnet_addr, BitcoinNetwork::Mainnet).unwrap();

    let (parsed_scan, parsed_spend, network) = parse_silent_payment_address(&mainnet_addr).unwrap();
    assert_eq!(parsed_scan, scan_pk);
    assert_eq!(parsed_spend, spend_pk);
    assert_eq!(network, Network::Bitcoin);

    // Signet / Testnet derivation
    let signet_addr =
        create_silent_payment_address_for_network(&scan_pk, &spend_pk, Network::Signet).unwrap();
    assert!(signet_addr.starts_with("tsp1q"));
    validate_silent_payment_address(&signet_addr, BitcoinNetwork::Testnet).unwrap();

    let (parsed_scan_s, parsed_spend_s, network_s) =
        parse_silent_payment_address(&signet_addr).unwrap();
    assert_eq!(parsed_scan_s, scan_pk);
    assert_eq!(parsed_spend_s, spend_pk);
    assert_eq!(network_s, Network::Testnet);
}

#[test]
fn test_bip352_sender_recipient_full_roundtrip_with_spending() {
    let secp = Secp256k1::new();

    // Recipient (Alice)
    let scan_sk = SecretKey::new(&mut OsRng);
    let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
    let spend_sk = SecretKey::new(&mut OsRng);
    let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

    // Sender (Bob) with single input
    let bob_sk = SecretKey::new(&mut OsRng);
    let bob_pk = PublicKey::from_secret_key(&secp, &bob_sk);

    let bob_input = SilentPaymentInput {
        outpoint: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:0".to_string(),
        input_pubkey: hex::encode(bob_pk.serialize()),
        input_privkey: Some(hex::encode(bob_sk.secret_bytes())),
    };

    let payment = SilentPayment::new(
        hex::encode(scan_pk.serialize()),
        hex::encode(spend_pk.serialize()),
        150_000,
        vec![bob_input],
        None,
        Network::Bitcoin,
    );

    // Bob creates two outputs to Alice (k=0 and k=1)
    let output_k0 = payment
        .create_output_with_index(&scan_pk, &spend_pk, 0)
        .unwrap();
    let output_k1 = payment
        .create_output_with_index(&scan_pk, &spend_pk, 1)
        .unwrap();

    assert_ne!(
        output_k0.script_pubkey, output_k1.script_pubkey,
        "Outputs for distinct indices k must have distinct scriptPubKeys"
    );
    assert!(output_k0.script_pubkey.starts_with("5120"));
    assert!(output_k1.script_pubkey.starts_with("5120"));

    // Simulated block containing mixed outputs
    let tx_outputs = vec![
        (
            "51201111111111111111111111111111111111111111111111111111111111111111".to_string(),
            25_000,
        ),
        (output_k0.script_pubkey.clone(), 75_000),
        (
            "51202222222222222222222222222222222222222222222222222222222222222222".to_string(),
            50_000,
        ),
        (output_k1.script_pubkey.clone(), 75_000),
    ];

    // Alice scans the block outputs using input_pubkey (bob_pk)
    // Note: since bob_input specified an outpoint, Bob computed shared secret using input_hash.
    let outpoint_bytes = parse_outpoint_to_bytes(
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789:0",
    )
    .unwrap();
    let input_hash = compute_input_hash(&outpoint_bytes, &bob_pk);

    let detected = SilentPayment::detect_outputs_with_input_hash(
        &scan_sk,
        &spend_pk,
        &bob_pk,
        &input_hash,
        &tx_outputs,
    )
    .unwrap();

    assert_eq!(detected.len(), 2, "Alice should detect exactly 2 outputs");
    assert_eq!(detected[0].script_pubkey, output_k0.script_pubkey);
    assert_eq!(detected[1].script_pubkey, output_k1.script_pubkey);

    // Alice derives spending private key for each detected output and verifies Taproot x-only match
    for (k, detected_out) in detected.iter().enumerate() {
        let shared_secret_pk = PublicKey::from_slice(
            &hex::decode(detected_out.shared_secret.as_ref().unwrap()).unwrap(),
        )
        .unwrap();

        let spending_sk = derive_spending_privkey(&spend_sk, &shared_secret_pk, k as u32).unwrap();
        let derived_pk = PublicKey::from_secret_key(&secp, &spending_sk);
        let (derived_x_only, parity) = derived_pk.x_only_public_key();

        // Must have even parity for Schnorr / BIP-340 compatibility
        assert_eq!(parity, Parity::Even);

        let expected_x_only = &detected_out.script_pubkey[4..];
        assert_eq!(hex::encode(derived_x_only.serialize()), expected_x_only);
    }
}

#[test]
fn test_bip352_multi_input_aggregation() {
    let secp = Secp256k1::new();

    // Recipient
    let (scan_sk_hex, scan_pk_hex, spend_sk_hex, spend_pk_hex) =
        generate_silent_payment_keys().unwrap();
    let scan_sk = SecretKey::from_slice(&hex::decode(scan_sk_hex).unwrap()).unwrap();
    let scan_pk = PublicKey::from_slice(&hex::decode(scan_pk_hex).unwrap()).unwrap();
    let spend_sk = SecretKey::from_slice(&hex::decode(spend_sk_hex).unwrap()).unwrap();
    let spend_pk = PublicKey::from_slice(&hex::decode(spend_pk_hex).unwrap()).unwrap();

    // 2 Inputs from sender
    let sk1 = SecretKey::new(&mut OsRng);
    let pk1 = PublicKey::from_secret_key(&secp, &sk1);
    let sk2 = SecretKey::new(&mut OsRng);
    let pk2 = PublicKey::from_secret_key(&secp, &sk2);

    let op1_str = "1111111111111111111111111111111111111111111111111111111111111111:0";
    let op2_str = "2222222222222222222222222222222222222222222222222222222222222222:1";

    let op1 = parse_outpoint_to_bytes(op1_str).unwrap();
    let op2 = parse_outpoint_to_bytes(op2_str).unwrap();
    let smallest_op = find_smallest_outpoint(&[op1, op2]).unwrap();
    assert_eq!(smallest_op, op1);

    // Sum private keys
    let sc2 = Scalar::from_be_bytes(sk2.secret_bytes()).unwrap();
    let sum_sk = sk1.add_tweak(&sc2).unwrap();
    let sum_scalar = Scalar::from_be_bytes(sum_sk.secret_bytes()).unwrap();
    let aggregate_pk = PublicKey::from_secret_key(&secp, &sum_sk);

    // Verify PublicKey::combine_keys matches sum of private keys
    let combined_pk = PublicKey::combine_keys(&[&pk1, &pk2]).unwrap();
    assert_eq!(aggregate_pk, combined_pk);

    // Also test direct detect_silent_payment_outputs with [pk1, pk2] (without input hash)
    let direct_shared_secret = scan_pk.mul_tweak(&secp, &sum_scalar).unwrap();
    let mut direct_tweak_data = Vec::with_capacity(37);
    direct_tweak_data.extend_from_slice(&direct_shared_secret.serialize());
    direct_tweak_data.extend_from_slice(&0u32.to_be_bytes());
    let direct_tweak_scalar =
        Scalar::from_be_bytes(tagged_hash(BIP0352_TAG_SHARED_SECRET, &direct_tweak_data)).unwrap();
    let direct_output_pk = spend_pk.add_exp_tweak(&secp, &direct_tweak_scalar).unwrap();
    let (direct_x_only, _) = direct_output_pk.x_only_public_key();
    let direct_script = format!("5120{}", hex::encode(direct_x_only.serialize()));

    let direct_tx_outputs = vec![(direct_script.clone(), 77_000)];
    let direct_detected =
        detect_silent_payment_outputs(&scan_sk, &spend_pk, &[pk1, pk2], &direct_tx_outputs)
            .unwrap();
    assert_eq!(direct_detected.len(), 1);
    assert_eq!(direct_detected[0].script_pubkey, direct_script);

    // Sender computes output with input hash
    let input_hash = compute_input_hash(&smallest_op, &aggregate_pk);
    let hash_scalar = Scalar::from_be_bytes(input_hash).unwrap();

    let shared_secret = scan_pk
        .mul_tweak(&secp, &sum_scalar)
        .unwrap()
        .mul_tweak(&secp, &hash_scalar)
        .unwrap();

    let mut tweak_data = Vec::with_capacity(37);
    tweak_data.extend_from_slice(&shared_secret.serialize());
    tweak_data.extend_from_slice(&0u32.to_be_bytes());

    let tweak_scalar =
        Scalar::from_be_bytes(tagged_hash(BIP0352_TAG_SHARED_SECRET, &tweak_data)).unwrap();
    let tweaked_output_pk = spend_pk.add_exp_tweak(&secp, &tweak_scalar).unwrap();
    let (x_only, _) = tweaked_output_pk.x_only_public_key();
    let expected_script = format!("5120{}", hex::encode(x_only.serialize()));

    // Recipient detects output with input pubkeys [pk1, pk2]
    let tx_outputs = vec![(expected_script.clone(), 99_000)];
    let detected = SilentPayment::detect_outputs_with_input_hash(
        &scan_sk,
        &spend_pk,
        &aggregate_pk,
        &input_hash,
        &tx_outputs,
    )
    .unwrap();

    assert_eq!(detected.len(), 1);
    assert_eq!(detected[0].script_pubkey, expected_script);

    // Recipient spending key derivation
    let spending_sk = derive_spending_privkey(&spend_sk, &shared_secret, 0).unwrap();
    let spending_pk = PublicKey::from_secret_key(&secp, &spending_sk);
    let (derived_x_only, _) = spending_pk.x_only_public_key();
    assert_eq!(
        hex::encode(derived_x_only.serialize()),
        &expected_script[4..]
    );
}

#[test]
fn test_bip352_profile_validation_integration() {
    let secp = Secp256k1::new();
    let scan_sk = SecretKey::new(&mut OsRng);
    let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
    let spend_sk = SecretKey::new(&mut OsRng);
    let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

    let mainnet_sp = create_silent_payment_address(&scan_pk, &spend_pk).unwrap();

    // Valid profile with BIP-352 silent payment method
    let valid_profile = PaymentProfile {
        alias: "alice@example.com".into(),
        identity_pubkey: hex::encode(spend_pk.serialize()),
        methods: vec![PaymentMethod::Onchain {
            label: "Cold Storage Silent Payment".into(),
            network: BitcoinNetwork::Mainnet,
            address: None,
            silent_payment_pubkey: Some(mainnet_sp),
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        }],
        updated_at: 100,
        expires_at: Some(200),
        sequence: None,
        preferences: vec![],
        nonce: None,
        rotation: None,
        method_verifications: Vec::new(),
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
        recovery_policy: None,
        recovery: None,
    };

    assert!(validate_public_profile(&valid_profile).is_ok());

    // Profile with invalid silent payment address (wrong network)
    let testnet_sp =
        create_silent_payment_address_for_network(&scan_pk, &spend_pk, Network::Testnet).unwrap();

    let invalid_profile = PaymentProfile {
        alias: "alice@example.com".into(),
        identity_pubkey: hex::encode(spend_pk.serialize()),
        methods: vec![PaymentMethod::Onchain {
            label: "Mismatched Network".into(),
            network: BitcoinNetwork::Mainnet, // Mainnet network with Testnet address
            address: None,
            silent_payment_pubkey: Some(testnet_sp),
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        }],
        updated_at: 100,
        expires_at: Some(200),
        sequence: None,
        preferences: vec![],
        nonce: None,
        rotation: None,
        method_verifications: Vec::new(),
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
        recovery_policy: None,
        recovery: None,
    };

    assert!(validate_public_profile(&invalid_profile).is_err());
}
