//! Public projections of all 28 official BIP-352 vector groups.
//! ECDH points and labeled public keys are host-wallet inputs. Spending-key
//! aggregation, private tweaks, and signature generation are outside the router.

use std::collections::{HashMap, HashSet};

use bitcoin::{secp256k1::PublicKey, Network};
use satspath_router::{
    bip352_input_context, create_bip352_outputs, parse_silent_payment_address,
    scan_bip352_transaction, Bip352PrevoutInput, Bip352ScanKeys,
};
use serde::Deserialize;

const VECTORS_JSON: &str = include_str!("data/bip352_send_and_receive_test_vectors.json");

#[derive(Debug, Deserialize)]
struct TestGroup {
    comment: String,
    sending: Vec<SendingCase>,
    receiving: Vec<ReceivingCase>,
}

#[derive(Debug, Deserialize)]
struct SendingCase {
    given: SendingGiven,
    expected: SendingExpected,
}

#[derive(Debug, Deserialize)]
struct SendingGiven {
    vin: Vec<VectorVin>,
    recipients: Vec<Recipient>,
    host_shared_secrets: HashMap<PublicKey, PublicKey>,
}

#[derive(Debug, Deserialize)]
struct Recipient {
    address: String,
    #[serde(default = "one")]
    count: usize,
    scan_pub_key: PublicKey,
    spend_pub_key: PublicKey,
}
/// Default a vector recipient's omitted output count to one.
fn one() -> usize {
    1
}

#[derive(Debug, Deserialize)]
struct SendingExpected {
    outputs: Vec<Vec<String>>,
    input_pub_keys: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct ReceivingCase {
    given: ReceivingGiven,
    expected: ReceivingExpected,
}

#[derive(Debug, Deserialize)]
struct ReceivingGiven {
    vin: Vec<VectorVin>,
    outputs: Vec<String>,
    scan_pubkey: PublicKey,
    spend_pubkey: PublicKey,
    labeled_spend_pubkeys: Vec<(u32, PublicKey)>,
    host_shared_secret: Option<PublicKey>,
}

#[derive(Debug, Deserialize)]
struct ReceivingExpected {
    addresses: Vec<String>,
    #[serde(default)]
    outputs: Vec<ExpectedRecvOutput>,
    n_outputs: Option<usize>,
    tweak: Option<String>,
    input_pub_key_sum: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExpectedRecvOutput {
    pub_key: String,
}

#[derive(Debug, Deserialize)]
struct VectorVin {
    txid: String,
    vout: u32,
    #[serde(rename = "scriptSig")]
    script_sig: String,
    txinwitness: String,
    prevout: VectorPrevout,
}
#[derive(Debug, Deserialize)]
struct VectorPrevout {
    #[serde(rename = "scriptPubKey")]
    script_pubkey: VectorScriptPubKey,
}
#[derive(Debug, Deserialize)]
struct VectorScriptPubKey {
    hex: String,
}

/// Convert a vector's public transaction fields into a router input descriptor.
fn to_prevout_input(v: &VectorVin) -> Bip352PrevoutInput {
    Bip352PrevoutInput {
        txid: v.txid.clone(),
        vout: v.vout,
        script_sig: v.script_sig.clone(),
        txinwitness: v.txinwitness.clone(),
        prevout_script_pubkey: v.prevout.script_pubkey.hex.clone(),
    }
}

/// Check eligible keys, recipient addresses, output keys, and the sender limit
/// across all 28 public vector groups using supplied host-wallet ECDH points.
#[test]
fn official_bip352_public_sending_vectors() {
    let groups: Vec<TestGroup> = serde_json::from_str(VECTORS_JSON).unwrap();
    assert_eq!(groups.len(), 28);
    for group in groups {
        for case in group.sending {
            let inputs: Vec<_> = case.given.vin.iter().map(to_prevout_input).collect();
            let recipients: Vec<_> = case
                .given
                .recipients
                .iter()
                .map(|r| {
                    let (scan, spend, _) = parse_silent_payment_address(&r.address).unwrap();
                    assert_eq!(scan, r.scan_pub_key);
                    assert_eq!(spend, r.spend_pub_key);
                    (r.address.clone(), r.count)
                })
                .collect();
            let context = bip352_input_context(&inputs).unwrap();
            let public_keys: Vec<_> = context
                .input_pub_keys
                .iter()
                .map(|pk| hex::encode(pk.serialize()))
                .collect();
            assert_eq!(
                public_keys, case.expected.input_pub_keys,
                "{}",
                group.comment
            );
            let result = create_bip352_outputs(
                &inputs,
                &recipients,
                &case.given.host_shared_secrets,
                Network::Bitcoin,
            );
            if recipients.iter().any(|(_, count)| *count > 2323) {
                assert!(result.unwrap_err().to_string().contains("K_max"));
                continue;
            }
            let result = result.unwrap_or_else(|e| panic!("{}: {e}", group.comment));
            assert_eq!(result.input_pub_keys, public_keys);
            let actual: HashSet<_> = result.outputs.iter().collect();
            assert!(
                case.expected.outputs.iter().any(|perm| {
                    perm.len() == result.outputs.len()
                        && perm.iter().collect::<HashSet<_>>() == actual
                }),
                "{}: unexpected outputs {:?}",
                group.comment,
                result.outputs
            );
        }
    }
}

/// Check aggregate keys, tweak points, addresses, and detected output keys across
/// all 28 public vector groups, including the point-at-infinity case.
#[test]
fn official_bip352_public_receiving_vectors() {
    let groups: Vec<TestGroup> = serde_json::from_str(VECTORS_JSON).unwrap();
    assert_eq!(groups.len(), 28);
    for group in groups {
        for case in group.receiving {
            let inputs: Vec<_> = case.given.vin.iter().map(to_prevout_input).collect();
            let keys = Bip352ScanKeys {
                scan_pubkey: case.given.scan_pubkey,
                spend_pubkey: case.given.spend_pubkey,
                labels: case.given.labeled_spend_pubkeys,
            };
            let context = bip352_input_context(&inputs).unwrap();
            assert_eq!(
                context
                    .aggregate_pubkey
                    .map(|pk| hex::encode(pk.serialize())),
                case.expected.input_pub_key_sum
            );
            assert_eq!(
                context.tweak.map(|pk| hex::encode(pk.serialize())),
                case.expected.tweak
            );
            let result = scan_bip352_transaction(
                &keys,
                &inputs,
                &case.given.outputs,
                case.given.host_shared_secret.as_ref(),
                Network::Bitcoin,
            );
            let result = result.unwrap_or_else(|e| panic!("{}: {e}", group.comment));
            assert_eq!(
                result.addresses, case.expected.addresses,
                "{}",
                group.comment
            );
            assert_eq!(
                result.input_pub_key_sum, case.expected.input_pub_key_sum,
                "{}",
                group.comment
            );
            assert_eq!(result.tweak, case.expected.tweak, "{}", group.comment);
            assert_eq!(
                result.outputs.len(),
                case.expected
                    .n_outputs
                    .unwrap_or(case.expected.outputs.len()),
                "{}",
                group.comment
            );
            for expected in &case.expected.outputs {
                assert!(
                    result
                        .outputs
                        .iter()
                        .any(|out| out.pub_key == expected.pub_key),
                    "{}: missing {}",
                    group.comment,
                    expected.pub_key
                );
            }
        }
    }
}
