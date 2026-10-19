//! Wallet boundary and malformed-data regressions for public BIP-352 helpers.
use std::collections::HashMap;

use bitcoin::{
    consensus::serialize,
    hashes::{hash160, Hash},
    secp256k1::PublicKey,
    Network, Witness,
};
use satspath_core::{
    validation::validate_public_profile, BitcoinNetwork, PaymentMethod, PaymentProfile,
};
use satspath_router::{
    bip352_input_context, build_qr_payload, create_bip352_outputs,
    create_silent_payment_address_for_network, extract_bip352_input_pubkey,
    parse_silent_payment_address, scan_bip352_transaction, tagged_hash, Bip352PrevoutInput,
    Bip352ScanKeys, BIP0352_TAG_INPUTS, BIP0352_TAG_SHARED_SECRET,
};

/// Load the first public receiving vector for wallet-boundary regression tests.
fn fixture() -> (
    Vec<Bip352PrevoutInput>,
    Bip352ScanKeys,
    PublicKey,
    Vec<String>,
) {
    fixture_group(0)
}

/// Load a group's first receiving case as inputs, public keys, an ECDH point,
/// and output keys; omit labels because these regressions use unlabeled groups.
fn fixture_group(
    index: usize,
) -> (
    Vec<Bip352PrevoutInput>,
    Bip352ScanKeys,
    PublicKey,
    Vec<String>,
) {
    let groups: serde_json::Value = serde_json::from_str(include_str!(
        "data/bip352_send_and_receive_test_vectors.json"
    ))
    .unwrap();
    let given = &groups[index]["receiving"][0]["given"];
    let inputs = given["vin"]
        .as_array()
        .unwrap()
        .iter()
        .map(|vin| Bip352PrevoutInput {
            txid: vin["txid"].as_str().unwrap().into(),
            vout: vin["vout"].as_u64().unwrap() as u32,
            script_sig: vin["scriptSig"].as_str().unwrap().into(),
            txinwitness: vin["txinwitness"].as_str().unwrap().into(),
            prevout_script_pubkey: vin["prevout"]["scriptPubKey"]["hex"]
                .as_str()
                .unwrap()
                .into(),
        })
        .collect();
    let keys = Bip352ScanKeys {
        scan_pubkey: serde_json::from_value(given["scan_pubkey"].clone()).unwrap(),
        spend_pubkey: serde_json::from_value(given["spend_pubkey"].clone()).unwrap(),
        labels: vec![],
    };
    (
        inputs,
        keys,
        serde_json::from_value(given["host_shared_secret"].clone()).unwrap(),
        serde_json::from_value(given["outputs"].clone()).unwrap(),
    )
}

/// Require the recipient network to match even without eligible inputs, and
/// confirm that generated outputs can be detected on each supported network.
#[test]
fn network_context_is_enforced_before_generating_outputs() {
    let (inputs, keys, shared, _) = fixture();
    let shared_points = HashMap::from([(keys.scan_pubkey, shared)]);
    let networks = [Network::Bitcoin, Network::Testnet, Network::Regtest];
    for address_network in networks {
        let address = create_silent_payment_address_for_network(
            &keys.scan_pubkey,
            &keys.spend_pubkey,
            address_network,
        )
        .unwrap();
        for expected_network in networks {
            for vin in [inputs.as_slice(), &[]] {
                let result = create_bip352_outputs(
                    vin,
                    &[(address.clone(), 1)],
                    &shared_points,
                    expected_network,
                );
                assert_eq!(result.is_ok(), address_network == expected_network);
                if address_network == expected_network && !vin.is_empty() {
                    let sent = result.unwrap();
                    let detected = scan_bip352_transaction(
                        &keys,
                        vin,
                        &sent.outputs,
                        Some(&shared),
                        expected_network,
                    )
                    .unwrap();
                    assert_eq!(detected.outputs.len(), 1);
                    assert_eq!(detected.outputs[0].output_index, 0);
                    assert_eq!(detected.outputs[0].label, None);
                    assert_eq!(
                        detected.addresses.as_slice(),
                        std::slice::from_ref(&address)
                    );
                }
            }
        }
    }
    // Signet and Testnet4 intentionally share the testnet HRP.
    let address = create_silent_payment_address_for_network(
        &keys.scan_pubkey,
        &keys.spend_pubkey,
        Network::Testnet,
    )
    .unwrap();
    for network in [Network::Signet, Network::Testnet4] {
        assert!(
            create_bip352_outputs(&inputs, &[(address.clone(), 1)], &shared_points, network)
                .is_ok()
        );
    }
}

/// Reject malformed output hex and lengths before input shortcuts.
#[test]
fn scanner_rejects_every_malformed_output_even_without_eligible_inputs() {
    let (inputs, keys, shared, valid) = fixture();
    for malformed in [
        "not-hex".into(),
        "".into(),
        "00".repeat(31),
        "00".repeat(33),
    ] {
        let outputs = vec![valid[0].clone(), malformed];
        for vin in [inputs.as_slice(), &[]] {
            assert!(
                scan_bip352_transaction(&keys, vin, &outputs, Some(&shared), Network::Bitcoin)
                    .is_err()
            );
        }
    }
}

/// Skip invalid 32-byte curve points while retaining valid output matches,
/// including when candidate sets or eligible input sets have no matches.
#[test]
fn scanner_skips_invalid_curve_points_and_detects_valid_outputs() {
    let (inputs, keys, shared, valid) = fixture_group(10);
    let baseline =
        scan_bip352_transaction(&keys, &inputs, &valid, Some(&shared), Network::Bitcoin).unwrap();
    assert_eq!(baseline.outputs.len(), 2);
    let mut outputs = vec!["00".repeat(32), "ff".repeat(32)];
    for output in &valid {
        outputs.push(output.clone());
        outputs.push("00".repeat(32));
    }
    assert_eq!(
        scan_bip352_transaction(&keys, &inputs, &outputs, Some(&shared), Network::Bitcoin).unwrap(),
        baseline
    );
    for candidates in [outputs.as_slice(), &outputs[..2]] {
        let result =
            scan_bip352_transaction(&keys, &[], candidates, None, Network::Bitcoin).unwrap();
        assert!(result.outputs.is_empty());
    }
    assert!(scan_bip352_transaction(
        &keys,
        &inputs,
        &outputs[..2],
        Some(&shared),
        Network::Bitcoin,
    )
    .unwrap()
    .outputs
    .is_empty());
}

/// Build a public P2WPKH input, optionally nested in P2SH, with matching hashes.
fn witness_input(nested: bool) -> Bip352PrevoutInput {
    let (_, keys, _, _) = fixture();
    let pk_bytes = keys.scan_pubkey.serialize();
    witness_input_with_key(nested, &pk_bytes)
}

/// Build a witness input whose native or nested script hashes bind the supplied
/// key bytes, including ineligible encodings used by negative tests.
fn witness_input_with_key(nested: bool, pk_bytes: &[u8]) -> Bip352PrevoutInput {
    let pkh = hash160::Hash::hash(pk_bytes);
    let redeem = format!("0014{pkh}");
    let redeem_bytes = hex::decode(&redeem).unwrap();
    Bip352PrevoutInput {
        txid: "11".repeat(32),
        vout: 0,
        script_sig: if nested {
            format!("16{redeem}")
        } else {
            String::new()
        },
        txinwitness: hex::encode(serialize(&Witness::from_slice(&[&[1u8][..], pk_bytes]))),
        prevout_script_pubkey: if nested {
            format!("a914{}87", hash160::Hash::hash(&redeem_bytes))
        } else {
            redeem
        },
    }
}

/// Enforce witness and redeem-script hash bindings and reject malformed witnesses
/// and uncompressed witness keys that do not match the bound public-key hash.
#[test]
fn witness_keys_must_match_both_hash_bindings() {
    let (_, keys, shared, outputs) = fixture();
    let address = create_silent_payment_address_for_network(
        &keys.scan_pubkey,
        &keys.spend_pubkey,
        Network::Bitcoin,
    )
    .unwrap();
    let points = HashMap::from([(keys.scan_pubkey, shared)]);
    let assert_rejected = |input: Bip352PrevoutInput| {
        let inputs = [input];
        assert!(bip352_input_context(&inputs).is_err());
        assert!(
            create_bip352_outputs(&inputs, &[(address.clone(), 1)], &points, Network::Bitcoin)
                .is_err()
        );
        assert!(
            scan_bip352_transaction(&keys, &inputs, &outputs, Some(&shared), Network::Bitcoin)
                .is_err()
        );
    };
    for nested in [false, true] {
        let input = witness_input(nested);
        assert!(extract_bip352_input_pubkey(&input).unwrap().is_some());
        let mut wrong_prevout = input.clone();
        wrong_prevout.prevout_script_pubkey = if nested {
            format!("a914{}87", "00".repeat(20))
        } else {
            format!("0014{}", "00".repeat(20))
        };
        assert!(extract_bip352_input_pubkey(&wrong_prevout).is_err());
        assert_rejected(wrong_prevout);
        if nested {
            let mut wrong_inner = input.clone();
            let redeem = format!("0014{}", "00".repeat(20));
            wrong_inner.script_sig = format!("16{redeem}");
            wrong_inner.prevout_script_pubkey = format!(
                "a914{}87",
                hash160::Hash::hash(&hex::decode(redeem).unwrap())
            );
            assert!(extract_bip352_input_pubkey(&wrong_inner).is_err());
            assert_rejected(wrong_inner);
        }
        for witness in ["02ff".to_string(), format!("{}00", input.txinwitness)] {
            let mut malformed = input.clone();
            malformed.txinwitness = witness;
            assert!(extract_bip352_input_pubkey(&malformed).is_err());
        }
        let mut uncompressed = input.clone();
        let (_, keys, _, _) = fixture();
        uncompressed.txinwitness = hex::encode(serialize(&Witness::from_slice(&[
            &[1u8][..],
            &keys.scan_pubkey.serialize_uncompressed(),
        ])));
        assert_rejected(uncompressed);
    }
}

/// Skip hash-bound noncompressed witness encodings and reject hash mismatches
/// for both native and nested P2WPKH inputs.
#[test]
fn hash_bound_non_compressed_keys_are_ineligible() {
    let (_, keys, _, _) = fixture();
    let uncompressed = keys.scan_pubkey.serialize_uncompressed();
    let mut hybrid = uncompressed;
    hybrid[0] = 0x06 | (uncompressed[64] & 1);
    let ineligible_keys = [
        uncompressed.to_vec(),
        hybrid.to_vec(),
        vec![0x04; 33],
        vec![0x01],
        vec![],
    ];
    for pk_bytes in &ineligible_keys {
        for nested in [false, true] {
            let input = witness_input_with_key(nested, pk_bytes);
            assert_eq!(extract_bip352_input_pubkey(&input).unwrap(), None);
            let context = bip352_input_context(std::slice::from_ref(&input)).unwrap();
            assert!(context.input_pub_keys.is_empty());
            assert!(context.tweak.is_none());
            let mut mismatch = input;
            let mut other_key = pk_bytes.clone();
            other_key.push(0x01);
            mismatch.txinwitness =
                hex::encode(serialize(&Witness::from_slice(&[&[1u8][..], &other_key])));
            assert!(extract_bip352_input_pubkey(&mismatch).is_err());
        }
    }
}

/// Skip matching P2PKH pushes that are not valid compressed public keys, and
/// reject scripts without any push matching the prevout hash.
#[test]
fn p2pkh_skips_matching_keys_that_are_not_valid_compressed_keys() {
    let (_, keys, _, _) = fixture();
    let mut invalid_point = vec![0xff; 33];
    invalid_point[0] = 0x02;
    for pk_bytes in [
        keys.scan_pubkey.serialize_uncompressed().to_vec(),
        vec![0x04; 33],
        invalid_point,
        vec![0x01],
        vec![],
    ] {
        let mut input = witness_input(false);
        input.txinwitness.clear();
        input.prevout_script_pubkey = format!("76a914{}88ac", hash160::Hash::hash(&pk_bytes));
        input.script_sig = format!("{:02x}{}", pk_bytes.len(), hex::encode(&pk_bytes));
        assert_eq!(extract_bip352_input_pubkey(&input).unwrap(), None);
        let context = bip352_input_context(std::slice::from_ref(&input)).unwrap();
        assert!(context.input_pub_keys.is_empty());
        input.prevout_script_pubkey = format!(
            "76a914{}88ac",
            hash160::Hash::hash(&keys.scan_pubkey.serialize())
        );
        assert!(extract_bip352_input_pubkey(&input).is_err());
    }
}

/// Reject private input fields during deserialization and ensure that serialized
/// inputs and the vector fixture contain only the intended public data.
#[test]
fn only_public_input_fields_are_accepted_and_serialized() {
    let (inputs, _, _, _) = fixture();
    let public = serde_json::to_value(&inputs[0]).unwrap();
    assert_eq!(public.as_object().unwrap().len(), 5);
    assert_eq!(
        serde_json::from_value::<Bip352PrevoutInput>(public.clone()).unwrap(),
        inputs[0]
    );
    for forbidden in ["private_key", "input_privkey", "spend_privkey", "seed"] {
        let mut supplied = public.clone();
        supplied[forbidden] = "forbidden material".into();
        assert!(serde_json::from_value::<Bip352PrevoutInput>(supplied).is_err());
    }
    let vectors: serde_json::Value = serde_json::from_str(include_str!(
        "data/bip352_send_and_receive_test_vectors.json"
    ))
    .unwrap();
    /// Recursively reject private-key and signature field names in the fixture.
    fn assert_public(value: &serde_json::Value) {
        match value {
            serde_json::Value::Object(fields) => {
                for (key, child) in fields {
                    assert!(
                        !["private", "priv_key", "signature"]
                            .iter()
                            .any(|s| key.contains(s)),
                        "unexpected field {key}"
                    );
                    assert_public(child);
                }
            }
            serde_json::Value::Array(values) => values.iter().for_each(assert_public),
            _ => {}
        }
    }
    assert_public(&vectors);
}

/// Count repeated public keys from distinct inputs and reject repeated outpoints.
#[test]
fn duplicate_keys_count_but_duplicate_outpoints_fail() {
    let input = witness_input(false);
    assert!(bip352_input_context(&[input.clone(), input.clone()]).is_err());
    let mut other = input.clone();
    other.vout += 1;
    let context = bip352_input_context(&[input, other]).unwrap();
    assert_eq!(context.input_pub_keys.len(), 2);
    assert_eq!(context.input_pub_keys[0], context.input_pub_keys[1]);
    let expected = context.input_pub_keys[0]
        .combine(&context.input_pub_keys[1])
        .unwrap();
    assert_eq!(context.aggregate_pubkey, Some(expected));
}

/// Reject missing spend data, invalid Taproot keys, and mixed-case addresses,
/// while accepting uniformly uppercase address encodings.
#[test]
fn malformed_or_missing_spend_data_fails_closed() {
    let (inputs, keys, shared, outputs) = fixture();
    let mut malformed_inputs = vec![
        inputs[0].clone(),
        fixture_group(6).0[0].clone(),
        witness_input(false),
        witness_input(true),
    ];
    for input in &mut malformed_inputs {
        input.script_sig.clear();
        input.txinwitness.clear();
        assert!(bip352_input_context(std::slice::from_ref(input)).is_err());
        assert!(scan_bip352_transaction(
            &keys,
            std::slice::from_ref(input),
            &outputs,
            Some(&shared),
            Network::Bitcoin
        )
        .is_err());
    }
    let mut invalid_taproot = fixture_group(6).0[0].clone();
    invalid_taproot.prevout_script_pubkey = format!("5120{}", "ff".repeat(32));
    assert!(extract_bip352_input_pubkey(&invalid_taproot).is_err());
    let address = create_silent_payment_address_for_network(
        &keys.scan_pubkey,
        &keys.spend_pubkey,
        Network::Bitcoin,
    )
    .unwrap();
    let mut mixed_case = address.clone();
    mixed_case.replace_range(..1, "S");
    assert!(parse_silent_payment_address(&mixed_case).is_err());
    assert_eq!(
        parse_silent_payment_address(&address.to_uppercase()).unwrap(),
        parse_silent_payment_address(&address).unwrap()
    );
}

/// Require host-wallet ECDH points and validate recipient counts and addresses
/// before allocating outputs, including when the input set is empty.
#[test]
fn sender_requires_wallet_ecdh_and_bounds_counts_before_allocation() {
    let (inputs, keys, _, _) = fixture();
    let address = create_silent_payment_address_for_network(
        &keys.scan_pubkey,
        &keys.spend_pubkey,
        Network::Bitcoin,
    )
    .unwrap();
    let points = HashMap::new();
    assert!(
        create_bip352_outputs(&inputs, &[(address.clone(), 1)], &points, Network::Bitcoin).is_err()
    );
    for count in [0, 2324, usize::MAX] {
        assert!(
            create_bip352_outputs(&[], &[(address.clone(), count)], &points, Network::Bitcoin)
                .is_err()
        );
    }
    assert!(
        create_bip352_outputs(&[], &[("malformed".into(), 1)], &points, Network::Bitcoin).is_err()
    );
    assert!(create_bip352_outputs(
        &[],
        &[(address.clone(), 2323), (address, 1)],
        &points,
        Network::Bitcoin
    )
    .is_err());
    assert!(scan_bip352_transaction(&keys, &inputs, &[], None, Network::Bitcoin).is_err());
}

/// Preserve Silent Payment networks and exact satoshi amounts through profile
/// validation and BIP-21 handoff formatting, rejecting profile network mismatches.
#[test]
fn silent_payment_profile_and_wallet_handoff_preserve_network_and_amount() {
    let (_, keys, _, _) = fixture();
    for (network, profile_network) in [
        (Network::Bitcoin, BitcoinNetwork::Mainnet),
        (Network::Testnet, BitcoinNetwork::Testnet),
        (Network::Regtest, BitcoinNetwork::Regtest),
    ] {
        let address = create_silent_payment_address_for_network(
            &keys.scan_pubkey,
            &keys.spend_pubkey,
            network,
        )
        .unwrap();
        let method = PaymentMethod::Onchain {
            label: "Silent Payment".into(),
            network: profile_network,
            address: None,
            silent_payment_pubkey: Some(address.clone()),
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        };
        let profile: PaymentProfile = serde_json::from_value(serde_json::json!({
            "alias": "alice@example.com", "identity_pubkey": keys.spend_pubkey.to_string(),
            "methods": [method], "updated_at": 100, "expires_at": 200,
            "preferences": [], "nonce": null, "rotation": null,
        }))
        .unwrap();
        validate_public_profile(&profile).unwrap();
        for (sats, _btc) in [
            (1, "0.00000001"),
            (21_000, "0.00021000"),
            (100_000_001, "1.00000001"),
        ] {
            assert!(matches!(
                build_qr_payload(&profile.methods[0], sats),
                Err(satspath_core::SatsPathError::InvalidPaymentPointer(ref msg))
                    if msg.contains("silent payment handoffs require wallet-side validation")
            ));
        }
        assert_eq!(parse_silent_payment_address(&address).unwrap().2, network);
        let mut mismatch = profile.clone();
        if let PaymentMethod::Onchain { network: value, .. } = &mut mismatch.methods[0] {
            *value = if network == Network::Bitcoin {
                BitcoinNetwork::Testnet
            } else {
                BitcoinNetwork::Mainnet
            };
        }
        assert!(validate_public_profile(&mismatch).is_err());
    }
}

/// Ensure input hashing and output tweak hashing use distinct BIP-352 domains.
#[test]
fn tags_are_domain_separated() {
    assert_ne!(
        tagged_hash(BIP0352_TAG_INPUTS, b"data"),
        tagged_hash(BIP0352_TAG_SHARED_SECRET, b"data")
    );
}
