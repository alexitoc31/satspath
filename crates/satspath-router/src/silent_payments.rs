//! Public BIP-352 address, input validation, and output detection helpers.
//!
//! The host wallet computes ECDH points and labeled spend public keys. It retains
//! all private keys, derives spending keys, verifies the final transaction, signs,
//! and broadcasts. This module accepts only public transaction data and curve points.
//!
//! Spending APIs are deliberately unavailable:
//! ```compile_fail
//! use satspath_router::extract_bip352_sender_privkey;
//! ```
//! ```compile_fail
//! use satspath_router::derive_spending_privkey;
//! ```
//! ```compile_fail
//! use satspath_router::derive_spending_privkey_from_scan;
//! ```
//! ```compile_fail
//! use satspath_router::generate_silent_payment_keys;
//! ```

use std::collections::{HashMap, HashSet};

use anyhow::{anyhow, Result};
use bech32::{FromBase32, ToBase32, Variant};
use bitcoin::consensus::Decodable;
use bitcoin::hashes::{hash160, Hash};
use bitcoin::script::Instruction;
use bitcoin::secp256k1::{Parity, PublicKey, Scalar, Secp256k1, XOnlyPublicKey};
use bitcoin::{Network, Script, Witness};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// BIP-352 tagged hash domain tag for input hash computation.
pub const BIP0352_TAG_INPUTS: &str = "BIP0352/Inputs";
/// BIP-352 tagged hash domain tag for shared secret derivation.
pub const BIP0352_TAG_SHARED_SECRET: &str = "BIP0352/SharedSecret";
/// BIP-352 tagged hash domain tag for recipient label derivation.
pub const BIP0352_TAG_LABEL: &str = "BIP0352/Label";

/// Maximum per-group recipient output index `K_max` defined by BIP-352 (`2323`).
pub const BIP0352_MAX_K: u32 = 2323;

/// BIP-341 NUMS point `H` (`50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0`).
/// Taproot script-path spends using `H` as their internal key must be skipped per BIP-352.
pub const BIP0352_NUMS_H: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

/// BIP-340 / BIP-352 tagged hash implementation:
/// `SHA256(SHA256(tag) || SHA256(tag) || data)`.
pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag_hash);
    hasher.update(tag_hash);
    hasher.update(data);
    hasher.finalize().into()
}

/// Parse an outpoint string in `"txid:vout"` format into standard 36-byte Bitcoin wire format:
/// 32 bytes txid (internal byte order / reversed hex) followed by 4 bytes vout (little-endian).
///
/// # Errors
/// Returns an error if the string does not match `txid:vout`, if the txid is not 64 hex chars,
/// or if `vout` is not a valid `u32`.
pub fn parse_outpoint_to_bytes(outpoint_str: &str) -> Result<[u8; 36]> {
    let parts: Vec<&str> = outpoint_str.split(':').collect();
    if parts.len() != 2 {
        return Err(anyhow!(
            "Invalid outpoint format, expected txid:vout, got '{outpoint_str}'"
        ));
    }
    let txid_hex = parts[0].trim();
    let vout_str = parts[1].trim();
    if txid_hex.len() != 64 {
        return Err(anyhow!("Invalid txid length in outpoint: {txid_hex}"));
    }
    let mut txid_bytes =
        hex::decode(txid_hex).map_err(|e| anyhow!("Invalid txid hex in outpoint: {e}"))?;
    // Bitcoin wire format stores txid in little-endian order (reversed from display hex)
    txid_bytes.reverse();
    let vout: u32 = vout_str
        .parse()
        .map_err(|e| anyhow!("Invalid vout in outpoint: {e}"))?;

    let mut out = [0u8; 36];
    out[..32].copy_from_slice(&txid_bytes);
    out[32..].copy_from_slice(&vout.to_le_bytes());
    Ok(out)
}

/// Find the lexicographically smallest 36-byte outpoint among inputs as required by BIP-352.
pub fn find_smallest_outpoint(outpoints: &[[u8; 36]]) -> Option<[u8; 36]> {
    outpoints.iter().copied().min()
}

/// Compute BIP-352 input hash: `TaggedHash("BIP0352/Inputs", outpoint_L || A)`.
pub fn compute_input_hash(
    smallest_outpoint: &[u8; 36],
    aggregate_input_pubkey: &PublicKey,
) -> [u8; 32] {
    let mut data = Vec::with_capacity(36 + 33);
    data.extend_from_slice(smallest_outpoint);
    data.extend_from_slice(&aggregate_input_pubkey.serialize());
    tagged_hash(BIP0352_TAG_INPUTS, &data)
}

/// Full transaction input descriptor for BIP-352 eligibility and public-key extraction.
/// Supply the final scriptSig/witness or placeholders with the same structure
/// exposing the real public key and any Taproot script-path control block.
/// Private spending fields are not part of this type:
/// ```compile_fail
/// use satspath_router::Bip352PrevoutInput;
/// let input = Bip352PrevoutInput {
///     txid: String::new(), vout: 0, script_sig: String::new(),
///     txinwitness: String::new(), prevout_script_pubkey: String::new(),
///     private_key: None,
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Bip352PrevoutInput {
    /// Transaction ID in display hex (64 characters).
    pub txid: String,
    /// Output index being spent.
    pub vout: u32,
    /// Hex-encoded `scriptSig`.
    pub script_sig: String,
    /// Hex-encoded consensus-serialized witness stack (`txinwitness`).
    pub txinwitness: String,
    /// Hex-encoded prevout `scriptPubKey`.
    pub prevout_script_pubkey: String,
}

impl Bip352PrevoutInput {
    /// Convert `(txid, vout)` to standard 36-byte wire format.
    ///
    /// # Errors
    /// Returns an error if `txid` is not valid 32-byte hex.
    pub fn outpoint_bytes(&self) -> Result<[u8; 36]> {
        parse_outpoint_to_bytes(&format!("{}:{}", self.txid, self.vout))
    }
}

/// Extract the eligible BIP-352 public key from a transaction input, if eligible.
///
/// Implements the exact input filtering rules from BIP-352:
/// - **P2TR**: `5120<32-byte x-only key>`. Skips script-path spends whose control block
///   internal key is the BIP-341 NUMS point `H`. Otherwise lifts the 32-byte output key
///   with even Y parity (`0x02 || x_only`).
/// - **P2WPKH**: `0014<20-byte hash160>`. `scriptSig` must be empty and the witness stack's
///   last element must be a 33-byte compressed public key.
/// - **P2SH-P2WPKH**: `a914<20-byte hash160>87` with `scriptSig == 160014<20-byte hash160>`
///   and a 33-byte compressed public key as the last witness element.
/// - **P2PKH**: `76a914<20-byte hash160>88ac`. Iterates over data pushes in `scriptSig`
///   and returns the 33-byte compressed public key whose `HASH160` matches the prevout hash.
///
/// Returns `Ok(Some((pubkey, is_taproot)))` when eligible, or `Ok(None)` when the input must be skipped.
///
/// # Errors
/// Returns an error for malformed encodings, invalid Taproot or compressed witness
/// curve points, missing P2PKH hash matches, or witness hash bindings.
pub fn extract_bip352_input_pubkey(
    input: &Bip352PrevoutInput,
) -> Result<Option<(PublicKey, bool)>> {
    let spk = hex::decode(input.prevout_script_pubkey.trim())
        .map_err(|e| anyhow!("Invalid prevout scriptPubKey hex: {e}"))?;
    let script_sig =
        hex::decode(input.script_sig.trim()).map_err(|e| anyhow!("Invalid scriptSig hex: {e}"))?;
    let witness_bytes = hex::decode(input.txinwitness.trim())
        .map_err(|e| anyhow!("Invalid txinwitness hex: {e}"))?;

    let witness_items: Vec<Vec<u8>> = if witness_bytes.is_empty() {
        Vec::new()
    } else {
        let mut cursor = std::io::Cursor::new(&witness_bytes);
        let witness = Witness::consensus_decode(&mut cursor)
            .map_err(|e| anyhow!("Invalid witness encoding: {e}"))?;
        if cursor.position() != witness_bytes.len() as u64 {
            return Err(anyhow!("Trailing bytes in witness encoding"));
        }
        witness.to_vec()
    };

    // 1. P2TR: OP_1 (0x51) OP_PUSHBYTES_32 (0x20) <32-byte x-only key>
    if spk.len() == 34 && spk[0] == 0x51 && spk[1] == 0x20 {
        if !script_sig.is_empty() || witness_items.is_empty() {
            return Err(anyhow!("Invalid or missing Taproot spend data"));
        }
        // Strip optional Taproot annex (last item starting with 0x50 when stack has >= 2 items)
        let stack_len = if witness_items.len() > 1
            && witness_items.last().and_then(|item| item.first()).copied() == Some(0x50)
        {
            witness_items.len() - 1
        } else {
            witness_items.len()
        };

        // Script-path spend has > 1 elements remaining; last element is control block
        if stack_len > 1 {
            let control_block = &witness_items[stack_len - 1];
            if control_block.len() < 33
                || control_block.len() > 33 + 32 * 128
                || !(control_block.len() - 33).is_multiple_of(32)
            {
                return Err(anyhow!("Invalid Taproot control block length"));
            }
            if control_block[1..33] == BIP0352_NUMS_H {
                return Ok(None);
            }
        }

        let xonly = XOnlyPublicKey::from_slice(&spk[2..34])
            .map_err(|e| anyhow!("Invalid Taproot output key: {e}"))?;
        let pk = PublicKey::from_x_only_public_key(xonly, Parity::Even);
        return Ok(Some((pk, true)));
    }

    // 2. P2WPKH: OP_0 (0x00) OP_PUSHBYTES_20 (0x14) <20-byte pubkey hash>
    if spk.len() == 22 && spk[0] == 0x00 && spk[1] == 0x14 {
        if !script_sig.is_empty() || witness_items.len() != 2 {
            return Err(anyhow!("Invalid or missing P2WPKH spend data"));
        }
        let pk_bytes = &witness_items[1];
        if hash160::Hash::hash(pk_bytes).as_byte_array() != &spk[2..22] {
            return Err(anyhow!("P2WPKH witness key does not match prevout hash"));
        }
        if pk_bytes.len() == 33 && (pk_bytes[0] == 0x02 || pk_bytes[0] == 0x03) {
            let pk = PublicKey::from_slice(pk_bytes)
                .map_err(|e| anyhow!("Invalid P2WPKH public key: {e}"))?;
            return Ok(Some((pk, false)));
        }
        return Ok(None); // Only compressed keys are eligible under BIP-352.
    }

    // 3. P2SH-P2WPKH: spk = a914<20-byte hash>87, scriptSig = 160014<20-byte hash>
    if spk.len() == 23 && spk[0] == 0xa9 && spk[1] == 0x14 && spk[22] == 0x87 {
        if script_sig.is_empty() {
            return Err(anyhow!("Missing P2SH redeem script"));
        }
        if script_sig.len() == 23
            && script_sig[0] == 0x16
            && script_sig[1] == 0x00
            && script_sig[2] == 0x14
        {
            if hash160::Hash::hash(&script_sig[1..]).as_byte_array() != &spk[2..22] {
                return Err(anyhow!("P2SH redeem script does not match prevout hash"));
            }
            if witness_items.len() != 2 {
                return Err(anyhow!("Invalid or missing P2SH-P2WPKH spend data"));
            }
            let pk_bytes = &witness_items[1];
            if hash160::Hash::hash(pk_bytes).as_byte_array() != &script_sig[3..23] {
                return Err(anyhow!(
                    "P2SH-P2WPKH witness key does not match redeem script hash"
                ));
            }
            if pk_bytes.len() == 33 && (pk_bytes[0] == 0x02 || pk_bytes[0] == 0x03) {
                let pk = PublicKey::from_slice(pk_bytes)
                    .map_err(|e| anyhow!("Invalid P2SH-P2WPKH public key: {e}"))?;
                return Ok(Some((pk, false)));
            }
            return Ok(None);
        }
        return Ok(None);
    }

    // 4. P2PKH: OP_DUP (0x76) OP_HASH160 (0xa9) OP_PUSHBYTES_20 (0x14) <20-byte hash> OP_EQUALVERIFY (0x88) OP_CHECKSIG (0xac)
    if spk.len() == 25
        && spk[0] == 0x76
        && spk[1] == 0xa9
        && spk[2] == 0x14
        && spk[23] == 0x88
        && spk[24] == 0xac
    {
        let expected_pkh = &spk[3..23];
        let script = Script::from_bytes(&script_sig);
        let mut matched_pk: Option<PublicKey> = None;
        let mut matched_key = false;
        for ins in script.instructions() {
            let Instruction::PushBytes(push) =
                ins.map_err(|e| anyhow!("Invalid P2PKH scriptSig: {e}"))?
            else {
                continue;
            };
            let bytes = push.as_bytes();
            if hash160::Hash::hash(bytes).as_byte_array() == expected_pkh {
                matched_key = true;
                if bytes.len() == 33 && (bytes[0] == 0x02 || bytes[0] == 0x03) {
                    matched_pk = PublicKey::from_slice(bytes).ok();
                }
            }
        }
        if !matched_key {
            return Err(anyhow!("Missing P2PKH key matching the prevout hash"));
        }
        return Ok(matched_pk.map(|pk| (pk, false)));
    }

    Ok(None)
}

/// Public input context for host-wallet ECDH computation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip352InputContext {
    /// Eligible input public keys, including duplicate keys from distinct inputs.
    pub input_pub_keys: Vec<PublicKey>,
    /// Aggregate public key A, absent for no eligible keys or a sum at infinity.
    pub aggregate_pubkey: Option<PublicKey>,
    /// Input hash bound to the smallest outpoint across all inputs.
    pub input_hash: Option<[u8; 32]>,
    /// Public point input_hash * A for the receiver's host wallet.
    pub tweak: Option<PublicKey>,
}

/// Validate public transaction input data and compute the BIP-352 input context.
/// Prevouts must come from an authenticated transaction source. This helper does
/// not execute scripts or verify transaction signatures.
pub fn bip352_input_context(inputs: &[Bip352PrevoutInput]) -> Result<Bip352InputContext> {
    let mut outpoints = Vec::with_capacity(inputs.len());
    let mut input_pub_keys = Vec::new();
    let mut seen = HashSet::new();
    for input in inputs {
        let outpoint = input.outpoint_bytes()?;
        if !seen.insert(outpoint) {
            return Err(anyhow!("Duplicate transaction outpoint"));
        }
        outpoints.push(outpoint);
        if let Some((pk, _)) = extract_bip352_input_pubkey(input)? {
            input_pub_keys.push(pk);
        }
    }
    let refs: Vec<_> = input_pub_keys.iter().collect();
    // Combining all keys together handles intermediate point cancellation.
    let aggregate_pubkey = if refs.is_empty() {
        None
    } else {
        PublicKey::combine_keys(&refs).ok()
    };
    let input_hash = aggregate_pubkey
        .zip(find_smallest_outpoint(&outpoints))
        .map(|(pk, outpoint)| compute_input_hash(&outpoint, &pk));
    let tweak = match (aggregate_pubkey, input_hash) {
        (Some(pk), Some(hash)) => {
            let scalar = Scalar::from_be_bytes(hash)
                .map_err(|e| anyhow!("Invalid input hash scalar: {e}"))?;
            Some(
                pk.mul_tweak(&Secp256k1::verification_only(), &scalar)
                    .map_err(|e| anyhow!("Invalid input tweak point: {e}"))?,
            )
        }
        _ => None,
    };
    Ok(Bip352InputContext {
        input_pub_keys,
        aggregate_pubkey,
        input_hash,
        tweak,
    })
}

/// Public output generation result. Contains no private keys or signing data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip352SendResult {
    /// Generated 32-byte x-only output public keys (hex).
    pub outputs: Vec<String>,
    /// Eligible input public keys (33-byte compressed hex).
    pub input_pub_keys: Vec<String>,
}

/// Generate output public keys using ECDH points supplied by the host wallet.
///
/// `shared_secrets` maps each recipient scan public key to the point
/// `input_hash * a * B_scan`, computed inside the wallet using its input keys.
/// The wallet must bind these points to this exact input set and independently
/// verify destinations and amounts before signing the final transaction.
///
/// All addresses are checked against `expected_network` before any empty-input
/// shortcut. Testnet and Signet share the `tsp` HRP; Regtest requires `sprt`.
/// Counts are bounded before allocating recipient output groups.
pub fn create_bip352_outputs(
    inputs: &[Bip352PrevoutInput],
    recipients: &[(String, usize)],
    shared_secrets: &HashMap<PublicKey, PublicKey>,
    expected_network: Network,
) -> Result<Bip352SendResult> {
    let mut group_order = Vec::new();
    let mut groups: HashMap<PublicKey, Vec<PublicKey>> = HashMap::new();
    for (address, count) in recipients {
        let (scan, spend, network) = parse_silent_payment_address(address)?;
        if silent_payment_hrp(network) != silent_payment_hrp(expected_network) {
            return Err(anyhow!("Silent Payment address network mismatch"));
        }
        if *count == 0 {
            return Err(anyhow!("Recipient output count must be positive"));
        }
        let entry = groups.entry(scan).or_insert_with(|| {
            group_order.push(scan);
            Vec::new()
        });
        if *count > BIP0352_MAX_K as usize - entry.len() {
            return Err(anyhow!("BIP-352 recipient group exceeds K_max"));
        }
        entry.extend(std::iter::repeat_n(spend, *count));
    }

    let context = bip352_input_context(inputs)?;
    let mut result = Bip352SendResult {
        outputs: Vec::new(),
        input_pub_keys: context
            .input_pub_keys
            .iter()
            .map(|pk| hex::encode(pk.serialize()))
            .collect(),
    };
    if context.tweak.is_none() {
        return Ok(result);
    }
    let secp = Secp256k1::verification_only();
    for scan in group_order {
        let shared = shared_secrets
            .get(&scan)
            .ok_or_else(|| anyhow!("Missing host-wallet ECDH point for recipient scan key"))?;
        for (k, spend) in groups[&scan].iter().enumerate() {
            let pk = derive_output_pubkey(&secp, spend, shared, k as u32)?;
            result
                .outputs
                .push(hex::encode(pk.x_only_public_key().0.serialize()));
        }
    }
    Ok(result)
}

/// Public receiver keys supplied by the host wallet, including labeled spend keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip352ScanKeys {
    pub scan_pubkey: PublicKey,
    pub spend_pubkey: PublicKey,
    /// `(label, B_spend + label_tweak * G)` pairs, in address display order.
    pub labels: Vec<(u32, PublicKey)>,
}

/// Public metadata identifying an output for further processing by the host wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip352DetectedOutput {
    /// 32-byte x-only output public key (hex).
    pub pub_key: String,
    /// BIP-352 output derivation index k (not the transaction's vout).
    pub output_index: u32,
    /// Matching wallet label, or None for an unlabeled output.
    pub label: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bip352ReceiveResult {
    pub addresses: Vec<String>,
    pub outputs: Vec<Bip352DetectedOutput>,
    /// Public point input_hash * A, if eligible inputs have a nonzero sum.
    pub tweak: Option<String>,
    pub input_pub_key_sum: Option<String>,
}

/// Detect outputs using only public keys and a host-wallet ECDH point.
///
/// The wallet supplies `shared_secret = b_scan * input_hash * A` for this exact
/// input set, plus labeled public keys. It retains all key derivation and signing
/// authority. No spending key or private tweak is accepted or returned.
/// Every candidate output is parsed before scanning, including transactions with
/// no eligible inputs; malformed hex and incorrect lengths return errors.
/// Values of 32 bytes that are not valid curve points are skipped.
/// Returned addresses use `expected_network`.
pub fn scan_bip352_transaction(
    keys: &Bip352ScanKeys,
    inputs: &[Bip352PrevoutInput],
    outputs_xonly: &[String],
    shared_secret: Option<&PublicKey>,
    expected_network: Network,
) -> Result<Bip352ReceiveResult> {
    let mut candidates = Vec::with_capacity(outputs_xonly.len());
    for out in outputs_xonly {
        let bytes = hex::decode(out.trim()).map_err(|e| anyhow!("Invalid output key hex: {e}"))?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "Invalid x-only output key length: expected 32 bytes"
            ));
        }
        if let Ok(candidate) = XOnlyPublicKey::from_slice(&bytes) {
            candidates.push(candidate);
        }
    }
    let context = bip352_input_context(inputs)?;
    let mut spend_keys = vec![(None, keys.spend_pubkey)];
    spend_keys.extend(keys.labels.iter().map(|(label, pk)| (Some(*label), *pk)));
    let addresses = spend_keys
        .iter()
        .map(|(_, spend)| {
            create_silent_payment_address_for_network(&keys.scan_pubkey, spend, expected_network)
        })
        .collect::<Result<_>>()?;
    let mut result = Bip352ReceiveResult {
        addresses,
        outputs: Vec::new(),
        tweak: context.tweak.map(|pk| hex::encode(pk.serialize())),
        input_pub_key_sum: context
            .aggregate_pubkey
            .map(|pk| hex::encode(pk.serialize())),
    };
    if context.tweak.is_none() {
        return Ok(result);
    }
    let shared = shared_secret.ok_or_else(|| anyhow!("Missing host-wallet ECDH point"))?;
    let secp = Secp256k1::verification_only();
    let mut used = HashSet::new();
    for k in 0..BIP0352_MAX_K {
        let expected = spend_keys
            .iter()
            .map(|(label, spend)| {
                Ok((
                    *label,
                    derive_output_pubkey(&secp, spend, shared, k)?
                        .x_only_public_key()
                        .0,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let matched = candidates.iter().enumerate().find_map(|(idx, candidate)| {
            if used.contains(&idx) {
                return None;
            }
            expected
                .iter()
                .find(|(_, pk)| pk == candidate)
                .map(|(label, _)| (idx, *label))
        });
        let Some((idx, label)) = matched else {
            break;
        };
        used.insert(idx);
        result.outputs.push(Bip352DetectedOutput {
            pub_key: hex::encode(candidates[idx].serialize()),
            output_index: k,
            label,
        });
    }
    Ok(result)
}

/// Derive `B_spend + t_k * G` from a host-wallet ECDH point and output index.
///
/// Returns an error if the tagged hash is outside the scalar range or the
/// resulting output point is at infinity.
fn derive_output_pubkey<C: bitcoin::secp256k1::Verification>(
    secp: &Secp256k1<C>,
    spend: &PublicKey,
    shared: &PublicKey,
    k: u32,
) -> Result<PublicKey> {
    let mut data = Vec::with_capacity(37);
    data.extend_from_slice(&shared.serialize());
    data.extend_from_slice(&k.to_be_bytes());
    let scalar = Scalar::from_be_bytes(tagged_hash(BIP0352_TAG_SHARED_SECRET, &data))
        .map_err(|e| anyhow!("Invalid output tweak scalar: {e}"))?;
    spend
        .add_exp_tweak(secp, &scalar)
        .map_err(|e| anyhow!("Invalid output public key: {e}"))
}

/// Return the BIP-352 prefix: `sp` for mainnet, `sprt` for regtest, otherwise `tsp`.
fn silent_payment_hrp(network: Network) -> &'static str {
    match network {
        Network::Bitcoin => "sp",
        Network::Regtest => "sprt",
        _ => "tsp",
    }
}

/// Silent Payment (BIP-352) Scan Public Key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SilentPaymentScanKey {
    /// The scan public key (33 bytes compressed hex)
    pub scan_pubkey: String,
    /// The spend public key (33 bytes compressed hex)
    pub spend_pubkey: Option<String>,
}

/// Silent Payment Address derived from scan and spend keys.
/// BIP-352: `bech32m(hrp, version || scan_pubkey || spend_pubkey)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SilentPaymentAddress {
    /// The silent payment bech32m address (sp1q..., tsp1q..., or sprt1q...)
    pub address: String,
    /// The scan public key (hex)
    pub scan_pubkey: String,
    /// The spend public key (hex)
    pub spend_pubkey: String,
    /// Optional label
    pub label: Option<String>,
}

impl SilentPaymentAddress {
    /// Construct a `SilentPaymentAddress` from public keys and network.
    ///
    /// # Errors
    /// Returns an error if Bech32m encoding fails.
    pub fn new(
        scan_pubkey: &PublicKey,
        spend_pubkey: &PublicKey,
        network: Network,
        label: Option<String>,
    ) -> Result<Self> {
        let address =
            create_silent_payment_address_for_network(scan_pubkey, spend_pubkey, network)?;
        Ok(Self {
            address,
            scan_pubkey: hex::encode(scan_pubkey.serialize()),
            spend_pubkey: hex::encode(spend_pubkey.serialize()),
            label,
        })
    }

    /// Parse a silent payment address string.
    ///
    /// # Errors
    /// Returns an error if the address string is not a valid BIP-352 Bech32m address.
    pub fn parse(address_str: &str) -> Result<Self> {
        let (scan_pk, spend_pk, _network) = parse_silent_payment_address(address_str)?;
        Ok(Self {
            address: address_str.trim().to_ascii_lowercase(),
            scan_pubkey: hex::encode(scan_pk.serialize()),
            spend_pubkey: hex::encode(spend_pk.serialize()),
            label: None,
        })
    }
}

/// Parse a silent payment scan public key from an address or legacy hex string.
pub fn parse_silent_payment_scan_key(scan_key: &str) -> Result<PublicKey, anyhow::Error> {
    let trimmed = scan_key.trim();
    if !trimmed.starts_with("sp1q")
        && !trimmed.starts_with("tsp1q")
        && !trimmed.starts_with("sprt1q")
    {
        return Err(anyhow!(
            "Invalid silent payment scan key: must start with 'sp1q', 'tsp1q', or 'sprt1q'"
        ));
    }

    // Try full bech32m address decode first
    if let Ok((scan_pub, _, _)) = parse_silent_payment_address(trimmed) {
        return Ok(scan_pub);
    }

    // Fallback: legacy hex format after prefix (used in mock unit tests)
    let hex_part = if let Some(stripped) = trimmed.strip_prefix("sprt1q") {
        stripped
    } else if let Some(stripped) = trimmed.strip_prefix("tsp1q") {
        stripped
    } else if let Some(stripped) = trimmed.strip_prefix("sp1q") {
        stripped
    } else {
        trimmed
    };
    if let Ok(bytes) = hex::decode(hex_part) {
        if bytes.len() == 33 {
            return PublicKey::from_slice(&bytes)
                .map_err(|e| anyhow!("Invalid public key bytes: {e}"));
        }
    }

    Err(anyhow!("Unable to parse silent payment scan key"))
}

/// Create a silent payment address from scan and spend public keys (defaults to Mainnet).
pub fn create_silent_payment_address(
    scan_pubkey: &PublicKey,
    spend_pubkey: &PublicKey,
) -> Result<String, anyhow::Error> {
    create_silent_payment_address_for_network(scan_pubkey, spend_pubkey, Network::Bitcoin)
}

/// Create a silent payment address for a specific network:
/// Mainnet uses HRP `"sp"`, Testnet/Signet use `"tsp"`, and Regtest uses `"sprt"`.
/// Payload: one 5-bit version `0` (`q`) followed by the base32 encoding of two 33-byte compressed keys.
pub fn create_silent_payment_address_for_network(
    scan_pubkey: &PublicKey,
    spend_pubkey: &PublicKey,
    network: Network,
) -> Result<String, anyhow::Error> {
    let hrp = match network {
        Network::Bitcoin => "sp",
        Network::Testnet | Network::Signet => "tsp",
        Network::Regtest => "sprt",
        _ => "tsp",
    };

    let mut payload = Vec::with_capacity(66);
    payload.extend_from_slice(&scan_pubkey.serialize());
    payload.extend_from_slice(&spend_pubkey.serialize());

    let mut data = vec![bech32::u5::try_from_u8(0)?];
    data.extend(payload.to_base32());
    let encoded = bech32::encode(hrp, data, Variant::Bech32m)
        .map_err(|e| anyhow!("Failed to encode silent payment address: {e}"))?;

    Ok(encoded)
}

/// Parse and validate a BIP-352 silent payment address string into `(scan_pubkey, spend_pubkey, Network)`.
pub fn parse_silent_payment_address(
    address: &str,
) -> Result<(PublicKey, PublicKey, Network), anyhow::Error> {
    let trimmed = address.trim();
    let lower = trimmed.to_ascii_lowercase();
    if trimmed != lower && trimmed != trimmed.to_ascii_uppercase() {
        return Err(anyhow!(
            "Invalid silent payment address: mixed case is not permitted"
        ));
    }

    let is_mainnet = lower.starts_with("sp1q");
    let is_testnet = lower.starts_with("tsp1q");
    let is_regtest = lower.starts_with("sprt1q");
    if !is_mainnet && !is_testnet && !is_regtest {
        return Err(anyhow!(
            "Invalid silent payment address prefix: expected 'sp1q', 'tsp1q', or 'sprt1q'"
        ));
    }

    let (hrp, data, variant) =
        bech32::decode(trimmed).map_err(|e| anyhow!("Failed to decode bech32 address: {e}"))?;

    if variant != Variant::Bech32m {
        return Err(anyhow!(
            "Invalid silent payment address encoding: expected Bech32m"
        ));
    }

    let network = match hrp.as_str() {
        "sp" => Network::Bitcoin,
        "tsp" => Network::Testnet,
        "sprt" => Network::Regtest,
        other => return Err(anyhow!("Unknown silent payment HRP: {other}")),
    };

    if data.first().map(|v| v.to_u8()) != Some(0) {
        return Err(anyhow!("Unsupported silent payment address version"));
    }
    let bytes = Vec::<u8>::from_base32(&data[1..])
        .map_err(|e| anyhow!("Failed to convert base32 data: {e}"))?;

    if bytes.len() != 66 {
        return Err(anyhow!(
            "Invalid silent payment address payload length: expected 66 bytes, got {}",
            bytes.len()
        ));
    }

    let scan_pubkey = PublicKey::from_slice(&bytes[..33])
        .map_err(|e| anyhow!("Invalid scan public key in address: {e}"))?;
    let spend_pubkey = PublicKey::from_slice(&bytes[33..])
        .map_err(|e| anyhow!("Invalid spend public key in address: {e}"))?;

    Ok((scan_pubkey, spend_pubkey, network))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    #[test]
    fn test_bip352_address_encode_decode_roundtrip() {
        let secp = Secp256k1::new();
        let scan_sk = SecretKey::new(&mut rand::thread_rng());
        let scan_pk = PublicKey::from_secret_key(&secp, &scan_sk);
        let spend_sk = SecretKey::new(&mut rand::thread_rng());
        let spend_pk = PublicKey::from_secret_key(&secp, &spend_sk);

        // Mainnet
        let mainnet_addr = create_silent_payment_address(&scan_pk, &spend_pk).unwrap();
        assert!(mainnet_addr.starts_with("sp1q"));
        let (parsed_scan, parsed_spend, net) = parse_silent_payment_address(&mainnet_addr).unwrap();
        assert_eq!(parsed_scan, scan_pk);
        assert_eq!(parsed_spend, spend_pk);
        assert_eq!(net, Network::Bitcoin);

        // Testnet
        let testnet_addr =
            create_silent_payment_address_for_network(&scan_pk, &spend_pk, Network::Testnet)
                .unwrap();
        assert!(testnet_addr.starts_with("tsp1q"));
        let (parsed_scan_t, parsed_spend_t, net_t) =
            parse_silent_payment_address(&testnet_addr).unwrap();
        assert_eq!(parsed_scan_t, scan_pk);
        assert_eq!(parsed_spend_t, spend_pk);
        assert_eq!(net_t, Network::Testnet);

        let regtest_addr =
            create_silent_payment_address_for_network(&scan_pk, &spend_pk, Network::Regtest)
                .unwrap();
        assert!(regtest_addr.starts_with("sprt1q"));
        let (parsed_scan_r, parsed_spend_r, net_r) =
            parse_silent_payment_address(&regtest_addr).unwrap();
        assert_eq!(
            (parsed_scan_r, parsed_spend_r, net_r),
            (scan_pk, spend_pk, Network::Regtest)
        );
        assert_eq!(
            parse_silent_payment_scan_key(&regtest_addr).unwrap(),
            scan_pk
        );
        assert!(satspath_handoff::silent(&regtest_addr, Network::Regtest).is_ok());
        assert!(satspath_handoff::silent(&regtest_addr, Network::Testnet).is_err());

        let signet_addr =
            create_silent_payment_address_for_network(&scan_pk, &spend_pk, Network::Signet)
                .unwrap();
        assert!(signet_addr.starts_with("tsp1q"));
        assert_eq!(
            parse_silent_payment_address(&signet_addr).unwrap().2,
            Network::Testnet
        );
    }
}
