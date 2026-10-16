//! Ark Service Provider (ASP) live client connector, VTXO DAG verifier, and settlement handoff builders.
//!
//! Provides non-custodial discovery, fee/round parameter querying (`GET /v1/info`),
//! VTXO covenant tree DAG verification, and host-wallet settlement handoff structures
//! (Boarding, In-Round Forfeit, and Out-of-Round / Arkade OOR transfers) for live `arkd` ASPs.

use std::collections::{HashMap, HashSet};
use std::str::FromStr;

use bitcoin::{Address, Amount, Denomination, Network};
use satspath_core::bip321::parse_bip321;

use anyhow::{anyhow, Context, Result};
use satspath_core::validation::{assert_no_private_material, validate_compressed_pubkey};
use satspath_core::PaymentMethod;
use serde::{Deserialize, Serialize};

/// Adapter trait for a synchronous Ark server client.
pub trait ArkClient {
    /// Whether the Ark server is reachable and available.
    fn is_available(&self) -> bool;
    /// Create a payment intent for `amount_sats` to `pubkey`.
    fn create_payment_intent(&self, amount_sats: u64, pubkey: &str) -> anyhow::Result<String>;
}

/// Simulated Ark intent payload for legacy synchronous tests.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SimulatedArkIntent {
    /// Unique intent identifier.
    pub intent_id: String,
    /// Recipient compressed public key (hex).
    pub pubkey: String,
    /// Amount in satoshis.
    pub amount_sats: u64,
    /// Intent lifecycle status.
    pub status: String,
    /// Target Ark ASP server URL.
    pub server_url: String,
}

/// Mock Ark client used in offline unit tests.
pub struct MockArkClient {
    /// Whether the mock server reports available.
    pub available: bool,
    /// Mock server URL.
    pub server_url: String,
}

impl ArkClient for MockArkClient {
    fn is_available(&self) -> bool {
        self.available
    }

    fn create_payment_intent(&self, amount_sats: u64, pubkey: &str) -> anyhow::Result<String> {
        if !self.available {
            anyhow::bail!("Ark server unavailable");
        }

        let intent_id = format!(
            "intent_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis()
        );
        let intent = SimulatedArkIntent {
            intent_id,
            pubkey: pubkey.to_string(),
            amount_sats,
            status: "waiting_for_payment".to_string(),
            server_url: self.server_url.clone(),
        };

        Ok(serde_json::to_string(&intent)?)
    }
}

/// Check whether any Ark method exists in a method list.
pub fn is_ark_available(methods: &[PaymentMethod]) -> bool {
    methods
        .iter()
        .any(|m| matches!(m, PaymentMethod::Ark { .. }))
}

/// Find the first Ark method in a method list.
pub fn first_ark_method(methods: &[PaymentMethod]) -> Option<&PaymentMethod> {
    methods
        .iter()
        .find(|m| matches!(m, PaymentMethod::Ark { .. }))
}

// ============================================================================
// Live Ark ASP Metadata, Fee Schedule & Settlement Handoff Structures
// ============================================================================

/// SatsPath fee schedule, when supplied by a source with matching semantics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct ArkFeeSchedule {
    /// Fixed base fee per VTXO transfer in satoshis.
    pub base_fee_sats: u64,
    /// Proportional fee rate in parts-per-million (ppm).
    pub ppm_rate: u64,
    /// Fixed fee in satoshis for onboarding an on-chain UTXO into the Ark.
    pub onboard_fee_sats: u64,
    /// Fixed fee in satoshis for collaborative redemption (offboarding) to on-chain.
    pub offboard_fee_sats: u64,
}

/// Validated ASP parameters mapped from discovery data with defined semantics.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkAspInfo {
    /// ASP 33-byte compressed secp256k1 public key (hex).
    pub pubkey: String,
    /// Network identifier (`"bitcoin"`, `"testnet"`, `"signet"`, `"regtest"`, or `"mutinynet"`).
    pub network: String,
    /// Interval between rounds, if known. arkd session duration is not an interval.
    pub round_interval_secs: Option<u64>,
    /// VTXO tree lifetime, if known. arkd session duration is not an expiry.
    pub vtxo_tree_expiry: Option<u64>,
    /// Unilateral exit timelock delay (CSV blocks/seconds).
    pub unilateral_exit_delay: u64,
    /// Minimum VTXO output amount (dust limit) in satoshis.
    pub dust_limit_sats: u64,
    /// Optional Taproot boarding descriptor template advertised by the ASP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boarding_descriptor_template: Option<String>,
    /// Fixed/ppm fee parameters, if known. arkd fee expressions do not map to this schedule.
    pub fees: Option<ArkFeeSchedule>,
}

impl ArkAspInfo {
    /// Validate the cryptographic and operational parameters returned by an ASP.
    ///
    /// # Errors
    /// Returns an error if the ASP `pubkey` is not a valid 33-byte compressed secp256k1 key,
    /// if a known `round_interval_secs` or `vtxo_tree_expiry` is zero, if the network is unknown,
    /// or if private material is present.
    pub fn validate(&self) -> Result<()> {
        validate_compressed_pubkey(&self.pubkey)
            .map_err(|e| anyhow!("invalid ASP public key: {e}"))?;
        if self.round_interval_secs == Some(0) {
            anyhow::bail!("ASP round_interval_secs must be greater than 0");
        }
        if self.vtxo_tree_expiry == Some(0) {
            anyhow::bail!("ASP vtxo_tree_expiry must be greater than 0");
        }
        if self.unilateral_exit_delay == 0 {
            anyhow::bail!("ASP unilateral_exit_delay must be greater than 0");
        }
        let net = self.network.trim().to_ascii_lowercase();
        if !matches!(
            net.as_str(),
            "bitcoin" | "mainnet" | "testnet" | "signet" | "regtest" | "mutinynet"
        ) {
            anyhow::bail!("unsupported ASP network: {}", self.network);
        }
        if let Some(ref desc) = self.boarding_descriptor_template {
            assert_no_private_material(desc).map_err(|e| anyhow!("{e}"))?;
        }
        Ok(())
    }

    /// Estimate the total fee in satoshis for an Ark VTXO transfer of `amount_sats`.
    pub fn estimate_transfer_fee(&self, amount_sats: u64) -> Result<u64> {
        let fees = self
            .fees
            .as_ref()
            .context("ASP transfer fee schedule unavailable")?;
        let proportional = amount_sats.saturating_mul(fees.ppm_rate) / 1_000_000;
        Ok(fees.base_fee_sats.saturating_add(proportional))
    }
}

/// Subset of arkd v0.9.16 GetInfoResponse used for discovery.
/// Fee expressions are decoded but cannot be translated into a fixed/ppm schedule.
#[cfg(feature = "std")]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ArkdInfoResponse {
    signer_pubkey: String,
    network: String,
    #[serde(deserialize_with = "deserialize_arkd_int64")]
    unilateral_exit_delay: i64,
    #[serde(deserialize_with = "deserialize_arkd_int64")]
    dust: i64,
    #[serde(rename = "fees")]
    _fees: ArkdFeeInfo,
}

#[cfg(feature = "std")]
#[derive(Deserialize)]
struct ArkdFeeInfo {
    #[serde(rename = "intentFee")]
    _intent_fee: ArkdIntentFeeInfo,
    #[serde(rename = "txFeeRate")]
    _tx_fee_rate: String,
}

#[cfg(feature = "std")]
#[derive(Deserialize)]
struct ArkdIntentFeeInfo {
    #[serde(rename = "offchainInput")]
    _offchain_input: String,
    #[serde(rename = "offchainOutput")]
    _offchain_output: String,
    #[serde(rename = "onchainInput")]
    _onchain_input: String,
    #[serde(rename = "onchainOutput")]
    _onchain_output: String,
}

/// Protobuf JSON encodes int64 as strings, while some gateways emit numbers.
#[cfg(feature = "std")]
fn deserialize_arkd_int64<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<i64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Int64 {
        Number(i64),
        String(String),
    }
    match Int64::deserialize(deserializer)? {
        Int64::Number(value) => Ok(value),
        Int64::String(value) => value.parse().map_err(serde::de::Error::custom),
    }
}

#[cfg(feature = "std")]
impl TryFrom<ArkdInfoResponse> for ArkAspInfo {
    type Error = anyhow::Error;

    fn try_from(wire: ArkdInfoResponse) -> Result<Self> {
        Ok(Self {
            pubkey: wire.signer_pubkey,
            network: wire.network,
            round_interval_secs: None,
            vtxo_tree_expiry: None,
            unilateral_exit_delay: wire
                .unilateral_exit_delay
                .try_into()
                .context("ASP unilateralExitDelay must be non-negative")?,
            dust_limit_sats: wire
                .dust
                .try_into()
                .context("ASP dust must be non-negative")?,
            boarding_descriptor_template: None,
            fees: None,
        })
    }
}

/// Node in an Ark virtual transaction output (VTXO) covenant tree DAG.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkVtxoTreeNode {
    /// Virtual transaction ID (64-char hex).
    pub txid: String,
    /// Parent virtual transaction ID (`None` for the root shared output transaction).
    pub parent_txid: Option<String>,
    /// Output index within this virtual transaction.
    pub vout: u32,
    /// Output value in satoshis.
    pub amount_sats: u64,
    /// 33-byte compressed ASP cosigning public key (hex).
    pub asp_cosign_pubkey: String,
    /// Optional 33-byte compressed receiver public key for leaf VTXOs (hex).
    pub receiver_pubkey: Option<String>,
    /// Relative expiry sequence / timelock.
    pub expiry_sequence: u32,
    /// Child virtual transaction IDs spending from this node.
    pub children: Vec<String>,
}

/// Structurally verify an Ark VTXO covenant tree DAG from `root_txid`
/// down to `target_vtxo_txid`.
///
/// Enforces:
/// - Acyclic parent-child linkage from `root_txid` to `target_vtxo_txid`.
/// - Every node in the tree commits to `expected_asp_pubkey`.
/// - Value conservation at every internal branch (`sum(children.amount_sats) <= parent.amount_sats`).
/// - The target is a leaf belonging to `expected_receiver_pubkey`, with
///   `amount_sats >= expected_amount_sats` and non-zero `expiry_sequence`.
///
/// Transaction IDs and cosigning scripts are not cryptographically verified.
///
/// # Errors
/// Returns an error if the DAG is cyclic, disconnected, violates value conservation,
/// mismatches the ASP or receiver public key, selects a non-leaf target, or under-funds the target VTXO.
pub fn verify_ark_vtxo_dag(
    nodes: &[ArkVtxoTreeNode],
    root_txid: &str,
    expected_asp_pubkey: &str,
    expected_receiver_pubkey: &str,
    target_vtxo_txid: &str,
    expected_amount_sats: u64,
) -> Result<()> {
    validate_compressed_pubkey(expected_asp_pubkey)
        .map_err(|e| anyhow!("invalid expected ASP pubkey: {e}"))?;

    validate_compressed_pubkey(expected_receiver_pubkey)
        .map_err(|e| anyhow!("invalid expected receiver pubkey: {e}"))?;

    let mut map: HashMap<&str, &ArkVtxoTreeNode> = HashMap::with_capacity(nodes.len());
    for node in nodes {
        if node.txid.len() != 64 || hex::decode(&node.txid).is_err() {
            anyhow::bail!("invalid VTXO node txid: {}", node.txid);
        }
        if !node
            .asp_cosign_pubkey
            .eq_ignore_ascii_case(expected_asp_pubkey)
        {
            anyhow::bail!(
                "VTXO node {} ASP pubkey {} does not match expected {}",
                node.txid,
                node.asp_cosign_pubkey,
                expected_asp_pubkey
            );
        }
        if node.expiry_sequence == 0 {
            anyhow::bail!("VTXO node {} has zero expiry_sequence", node.txid);
        }
        if map.insert(node.txid.as_str(), node).is_some() {
            anyhow::bail!("duplicate VTXO node txid in DAG: {}", node.txid);
        }
    }

    let root = map
        .get(root_txid)
        .ok_or_else(|| anyhow!("root VTXO node {root_txid} not found in DAG"))?;
    if root.parent_txid.is_some() {
        anyhow::bail!("root VTXO node {root_txid} must not have a parent_txid");
    }

    let target = map
        .get(target_vtxo_txid)
        .ok_or_else(|| anyhow!("target VTXO node {target_vtxo_txid} not found in DAG"))?;
    if !target.children.is_empty() {
        anyhow::bail!("target VTXO must be a leaf");
    }
    if !target
        .receiver_pubkey
        .as_deref()
        .is_some_and(|key| key.eq_ignore_ascii_case(expected_receiver_pubkey))
    {
        anyhow::bail!("target VTXO receiver pubkey mismatch");
    }
    if target.amount_sats < expected_amount_sats {
        anyhow::bail!(
            "target VTXO amount {} sats is less than expected {} sats",
            target.amount_sats,
            expected_amount_sats
        );
    }

    // Verify value conservation on every node with children
    for node in nodes {
        if !node.children.is_empty() {
            let mut children_sum: u64 = 0;
            for child_id in &node.children {
                let child = map
                    .get(child_id.as_str())
                    .ok_or_else(|| anyhow!("missing child VTXO node {child_id}"))?;
                if child.parent_txid.as_deref() != Some(node.txid.as_str()) {
                    anyhow::bail!(
                        "child VTXO {} parent_txid {:?} does not point to {}",
                        child.txid,
                        child.parent_txid,
                        node.txid
                    );
                }
                children_sum = children_sum
                    .checked_add(child.amount_sats)
                    .context("VTXO children amount overflow")?;
            }
            if children_sum > node.amount_sats {
                anyhow::bail!(
                    "VTXO value inflation at node {}: children sum {} > parent {}",
                    node.txid,
                    children_sum,
                    node.amount_sats
                );
            }
        }
    }

    // Walk backwards from target_vtxo_txid to root_txid to prove reachability and acyclicity
    let mut visited = HashSet::new();
    let mut curr = *target;
    loop {
        if !visited.insert(curr.txid.as_str()) {
            anyhow::bail!("cycle detected in VTXO DAG at {}", curr.txid);
        }
        if curr.txid == root_txid {
            break;
        }
        let Some(ref parent_id) = curr.parent_txid else {
            anyhow::bail!(
                "target VTXO {target_vtxo_txid} is disconnected from root {root_txid} at {}",
                curr.txid
            );
        };
        let parent = map
            .get(parent_id.as_str())
            .ok_or_else(|| anyhow!("missing ancestor VTXO node {parent_id}"))?;
        if !parent.children.iter().any(|c| c == &curr.txid) {
            anyhow::bail!(
                "parent VTXO {} does not list {} among its children",
                parent.txid,
                curr.txid
            );
        }
        curr = parent;
    }

    Ok(())
}

/// Handoff descriptor for boarding on-chain funds into an Ark ASP round.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkBoardingHandoff {
    /// Target Ark ASP server URL.
    pub server_url: String,
    /// On-chain Taproot boarding address (`bc1p...` / `tb1p...` / `bcrt1p...`).
    pub boarding_address: String,
    /// ASP 33-byte compressed public key (hex).
    pub asp_pubkey: String,
    /// Recipient/user 33-byte compressed public key (hex).
    pub user_pubkey: String,
    /// Unilateral exit delay (blocks/seconds) in the boarding Tapscript branch.
    pub exit_delay: u64,
    /// Amount in satoshis to board.
    pub amount_sats: u64,
    /// Formatted `bitcoin:` BIP-21 URI for the host wallet to sign and broadcast.
    pub bip21_uri: String,
}

/// Handoff structure for an in-round VTXO forfeit + refresh settlement (e.g. Arkade Money).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkForfeitHandoff {
    /// Target Ark ASP server URL.
    pub server_url: String,
    /// Active ASP round identifier.
    pub round_id: String,
    /// Input VTXO outpoint being forfeited (`txid:vout`).
    pub input_vtxo_outpoint: String,
    /// Connector output outpoint from the round commitment transaction (`txid:vout`).
    pub connector_outpoint: String,
    /// Unsigned or partially-signed forfeit PSBT (base64) for the host wallet to inspect and sign.
    pub forfeit_psbt_base64: String,
    /// Root txid of the new VTXO covenant tree in which the receiver's VTXO is created.
    pub new_vtxo_tree_root: String,
    /// ASP 33-byte compressed public key (hex).
    pub asp_pubkey: String,
    /// Recipient 33-byte compressed public key (hex).
    pub receiver_pubkey: String,
    /// Amount in satoshis transferred to the recipient VTXO.
    pub amount_sats: u64,
}

/// Out-of-round (OOR / Arkoor) instant VTXO payment request handoff for compatible host wallets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkOorPaymentRequest {
    /// Target Ark ASP server URL.
    pub server_url: String,
    /// ASP 33-byte compressed public key (hex).
    pub asp_pubkey: String,
    /// Sender VTXO outpoint (`txid:vout`) being spent out-of-round.
    pub sender_vtxo_outpoint: String,
    /// Recipient 33-byte compressed public key (hex).
    pub receiver_pubkey: String,
    /// Payment amount in satoshis.
    pub amount_sats: u64,
    /// ASP fee in satoshis.
    pub fee_sats: u64,
    /// Remaining VTXO expiry window inherited by the OOR output.
    pub vtxo_tree_expiry: u64,
    /// Canonical `ark:` handoff URI for wallet invocation.
    pub ark_uri: String,
}

/// Unified non-custodial Ark settlement handoff payload for host wallets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "settlement_mode", rename_all = "snake_case")]
pub enum ArkSettlementHandoff {
    /// On-chain to Ark boarding output handoff.
    Boarding(ArkBoardingHandoff),
    /// In-round VTXO forfeit + tree refresh handoff.
    InRoundForfeit(ArkForfeitHandoff),
    /// Out-of-round (OOR) instant VTXO transfer handoff.
    OutOfRound(ArkOorPaymentRequest),
}

impl ArkSettlementHandoff {
    /// Validate this settlement handoff against the live `ArkAspInfo` parameters.
    ///
    /// Fails closed if keys are malformed, amounts fall below `asp_info.dust_limit_sats`,
    /// the ASP public key mismatches, or any field contains private key material.
    pub fn validate(&self, asp_info: &ArkAspInfo) -> Result<()> {
        asp_info.validate()?;
        let asp_network = ArkNetwork::from_asp_name(&asp_info.network)?.bitcoin_network();
        let serialized = serde_json::to_string(self)?;
        assert_no_private_material(&serialized).map_err(|e| anyhow!("{e}"))?;

        match self {
            Self::Boarding(b) => {
                if !b.asp_pubkey.eq_ignore_ascii_case(&asp_info.pubkey) {
                    anyhow::bail!("boarding handoff ASP pubkey mismatch");
                }
                validate_compressed_pubkey(&b.user_pubkey)
                    .map_err(|e| anyhow!("invalid boarding user_pubkey: {e}"))?;
                if b.amount_sats < asp_info.dust_limit_sats {
                    anyhow::bail!(
                        "boarding amount {} sats is below ASP dust limit {} sats",
                        b.amount_sats,
                        asp_info.dust_limit_sats
                    );
                }
                let address = Address::from_str(&b.boarding_address)
                    .context("invalid boarding address")?
                    .require_network(asp_network)
                    .context("boarding address network mismatch")?;
                let uri = parse_bip321(&b.bip21_uri)?;
                let uri_address = Address::from_str(
                    uri.address
                        .as_deref()
                        .context("boarding BIP-21 address missing")?,
                )?
                .require_network(asp_network)
                .context("boarding BIP-21 address network mismatch")?;
                if uri_address != address {
                    anyhow::bail!("boarding BIP-21 address mismatch");
                }
                // The shared URI parser retains only the last amount. Reject duplicate
                // amounts here so wallets cannot interpret a different payment value.
                let amount_count = b.bip21_uri.split_once('?').map_or(0, |(_, query)| {
                    query
                        .split('&')
                        .filter(|pair| {
                            pair.split('=')
                                .next()
                                .is_some_and(|key| key.eq_ignore_ascii_case("amount"))
                        })
                        .count()
                });
                if amount_count != 1 {
                    anyhow::bail!("boarding BIP-21 must contain exactly one amount");
                }
                let amount = Amount::from_str_in(
                    uri.amount_btc
                        .as_deref()
                        .context("boarding BIP-21 amount missing")?,
                    Denomination::Bitcoin,
                )
                .context("invalid boarding BIP-21 amount")?;
                if amount.to_sat() != b.amount_sats {
                    anyhow::bail!("boarding BIP-21 amount mismatch");
                }
                if b.exit_delay != asp_info.unilateral_exit_delay {
                    anyhow::bail!("boarding exit delay mismatch");
                }
            }
            Self::InRoundForfeit(f) => {
                if !f.asp_pubkey.eq_ignore_ascii_case(&asp_info.pubkey) {
                    anyhow::bail!("forfeit handoff ASP pubkey mismatch");
                }
                validate_compressed_pubkey(&f.receiver_pubkey)
                    .map_err(|e| anyhow!("invalid forfeit receiver_pubkey: {e}"))?;
                if f.amount_sats < asp_info.dust_limit_sats {
                    anyhow::bail!(
                        "forfeit amount {} sats is below ASP dust limit {} sats",
                        f.amount_sats,
                        asp_info.dust_limit_sats
                    );
                }
                crate::silent_payments::parse_outpoint_to_bytes(&f.input_vtxo_outpoint)?;
                crate::silent_payments::parse_outpoint_to_bytes(&f.connector_outpoint)?;
                if f.forfeit_psbt_base64.trim().is_empty() {
                    anyhow::bail!("forfeit_psbt_base64 cannot be empty");
                }
            }
            Self::OutOfRound(oor) => {
                if !oor.asp_pubkey.eq_ignore_ascii_case(&asp_info.pubkey) {
                    anyhow::bail!("OOR handoff ASP pubkey mismatch");
                }
                validate_compressed_pubkey(&oor.receiver_pubkey)
                    .map_err(|e| anyhow!("invalid OOR receiver_pubkey: {e}"))?;
                if oor.amount_sats < asp_info.dust_limit_sats {
                    anyhow::bail!(
                        "OOR amount {} sats is below ASP dust limit {} sats",
                        oor.amount_sats,
                        asp_info.dust_limit_sats
                    );
                }
                crate::silent_payments::parse_outpoint_to_bytes(&oor.sender_vtxo_outpoint)?;
            }
        }
        Ok(())
    }
}

/// Receipt returned by an Ark ASP after registering a round or OOR settlement intent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkRoundSubmissionReceipt {
    /// Assigned round ID or OOR package ID.
    pub submission_id: String,
    /// ASP status (`"registered"`, `"cosigned"`, `"broadcast"`).
    pub status: String,
    /// Root txid of the VTXO tree or OOR transaction.
    pub vtxo_txid: Option<String>,
}

impl ArkRoundSubmissionReceipt {
    /// Reject incomplete or malformed submission acknowledgements.
    pub fn validate(&self) -> Result<()> {
        if self.submission_id.trim().is_empty() {
            anyhow::bail!("Ark submission ID cannot be empty");
        }
        if !matches!(
            self.status.as_str(),
            "registered" | "cosigned" | "broadcast"
        ) {
            anyhow::bail!("unsupported Ark submission status");
        }
        if let Some(txid) = &self.vtxo_txid {
            if txid.len() != 64 || hex::decode(txid).is_err() {
                anyhow::bail!("invalid Ark submission VTXO txid");
            }
        }
        Ok(())
    }
}

/// Intended Ark chain. Mutinynet remains distinct from public signet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArkNetwork {
    Bitcoin,
    Testnet,
    Signet,
    Regtest,
    Mutinynet,
}

impl ArkNetwork {
    fn from_asp_name(name: &str) -> Result<Self> {
        match name.trim().to_ascii_lowercase().as_str() {
            "bitcoin" | "mainnet" => Ok(Self::Bitcoin),
            "testnet" => Ok(Self::Testnet),
            "signet" => Ok(Self::Signet),
            "regtest" => Ok(Self::Regtest),
            "mutinynet" => Ok(Self::Mutinynet),
            _ => anyhow::bail!("unsupported ASP network: {name}"),
        }
    }

    fn bitcoin_network(self) -> Network {
        match self {
            Self::Bitcoin => Network::Bitcoin,
            Self::Testnet => Network::Testnet,
            Self::Signet | Self::Mutinynet => Network::Signet,
            Self::Regtest => Network::Regtest,
        }
    }
}

// Wire contract pinned to arkade-os/arkd v0.9.16 (e2d9ed443df7a0dfb3aa1e5c824de9541ff71047),
// api-spec/protobuf/ark/v1/{service,types}.proto. Payloads are prepared by the host wallet.
/// Request for POST /v1/tx/submit. SatsPath never constructs or signs these transactions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArkSubmitTxRequest {
    pub signed_ark_tx: String,
    pub checkpoint_txs: Vec<String>,
}

/// Cosigned transaction data that must be returned to the host wallet for finalization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArkSubmitTxResponse {
    pub ark_txid: String,
    pub final_ark_tx: String,
    pub signed_checkpoint_txs: Vec<String>,
}

/// Host-wallet BIP-322 intent proof and its message.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkIntent {
    pub proof: String,
    pub message: String,
}

/// Request for POST /v1/batch/registerIntent.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkRegisterIntentRequest {
    pub intent: ArkIntent,
}

/// Intent registration acknowledgement from arkd.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ArkRegisterIntentResponse {
    pub intent_id: String,
}

/// Endpoint-specific data supplied by the host wallet in addition to routing metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArkSettlementSubmission {
    Transaction(ArkSubmitTxRequest),
    Intent(ArkRegisterIntentRequest),
}

/// Endpoint-specific response, preserving signed data required by the host wallet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArkSettlementSubmissionResponse {
    Transaction(ArkSubmitTxResponse),
    Intent(ArkRegisterIntentResponse),
}

impl ArkSettlementSubmissionResponse {
    /// Build a validated routing receipt without discarding the wallet response.
    pub fn receipt(&self) -> Result<ArkRoundSubmissionReceipt> {
        let receipt = match self {
            Self::Transaction(tx) => {
                if tx.final_ark_tx.trim().is_empty()
                    || tx.signed_checkpoint_txs.is_empty()
                    || tx
                        .signed_checkpoint_txs
                        .iter()
                        .any(|tx| tx.trim().is_empty())
                {
                    anyhow::bail!("incomplete Ark transaction submission response");
                }
                ArkRoundSubmissionReceipt {
                    submission_id: tx.ark_txid.clone(),
                    status: "cosigned".to_string(),
                    vtxo_txid: Some(tx.ark_txid.clone()),
                }
            }
            Self::Intent(intent) => ArkRoundSubmissionReceipt {
                submission_id: intent.intent_id.clone(),
                status: "registered".to_string(),
                vtxo_txid: None,
            },
        };
        receipt.validate()?;
        Ok(receipt)
    }
}

#[cfg(feature = "std")]
fn normalized_server_url(server_url: &str) -> Result<url::Url> {
    let mut url = url::Url::parse(server_url).context("invalid Ark server URL")?;
    if !matches!(url.scheme(), "https" | "http")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        anyhow::bail!("invalid Ark server base URL");
    }
    let path = url.path().trim_end_matches('/').to_string();
    url.set_path(&path);
    Ok(url)
}

/// Live Ark Service Provider HTTP connector (`arkd` REST client).
///
/// The local HTTP bypass is unavailable in production builds:
/// ```compile_fail
/// use satspath_router::ark::{ArkNetwork, LiveArkAspClient};
/// let client = LiveArkAspClient::new_for_test("http://127.0.0.1:7070", ArkNetwork::Regtest);
/// ```
#[derive(Debug, Clone)]
pub struct LiveArkAspClient {
    server_url: String,
    expected_network: ArkNetwork,
    mainnet_execution_enabled: bool,
    #[cfg(test)]
    allow_http_for_test: bool,
}

/// Read an HTTP response body up to `max_bytes`, failing closed if the stream exceeds the bound.
#[cfg(feature = "std")]
async fn read_bounded_bytes(mut resp: reqwest::Response, max_bytes: usize) -> Result<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            anyhow::bail!("Ark ASP response content-length ({len}) exceeds {max_bytes} bytes");
        }
    }
    let mut out = Vec::new();
    while let Some(chunk) = resp.chunk().await.context("reading Ark ASP stream")? {
        if out.len() + chunk.len() > max_bytes {
            anyhow::bail!("Ark ASP response body exceeded {max_bytes} bytes");
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

impl LiveArkAspClient {
    /// Construct a new live Ark ASP client for `server_url` (HTTPS required).
    pub fn new(server_url: impl Into<String>, expected_network: ArkNetwork) -> Self {
        Self {
            server_url: server_url.into().trim_end_matches('/').to_string(),
            expected_network,
            mainnet_execution_enabled: false,
            #[cfg(test)]
            allow_http_for_test: false,
        }
    }

    /// Construct a live Ark ASP client allowing HTTP for local/containerized `arkd` integration tests.
    #[cfg(test)]
    fn new_for_test(server_url: impl Into<String>, expected_network: ArkNetwork) -> Self {
        Self {
            allow_http_for_test: true,
            ..Self::new(server_url, expected_network)
        }
    }

    /// Explicitly opt in to forwarding host-wallet submissions on mainnet.
    /// Disabled by default; this does not authorize SatsPath to sign or construct transactions.
    pub fn with_mainnet_execution(mut self, enabled: bool) -> Self {
        self.mainnet_execution_enabled = enabled;
        self
    }

    fn validate_network(&self, info: &ArkAspInfo) -> Result<()> {
        let network = ArkNetwork::from_asp_name(&info.network)?;
        if network != self.expected_network {
            anyhow::bail!("Ark ASP network does not match intended router network");
        }
        if network == ArkNetwork::Bitcoin && !self.mainnet_execution_enabled {
            anyhow::bail!("Ark mainnet execution requires explicit opt-in");
        }
        Ok(())
    }

    /// Return the configured ASP base URL.
    pub fn server_url(&self) -> &str {
        &self.server_url
    }

    /// Validate an endpoint URL before issuing a request.
    fn validate_endpoint(&self, url: &str) -> Result<()> {
        #[cfg(test)]
        if self.allow_http_for_test {
            if !url.starts_with("http://") && !url.starts_with("https://") {
                anyhow::bail!("unsupported scheme in ASP URL: {url}");
            }
            return Ok(());
        }
        satspath_core::ssrf::validate_url(url, false)
            .map_err(|e| anyhow!("blocked Ark ASP URL: {e}"))
    }

    /// Query `GET {server_url}/v1/info` on the live Ark ASP node and validate the returned parameters.
    #[cfg(feature = "std")]
    pub async fn get_asp_info(&self) -> Result<ArkAspInfo> {
        let url = format!("{}/v1/info", self.server_url);
        self.validate_endpoint(&url)?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let resp = client
            .get(&url)
            .send()
            .await
            .context("querying Ark ASP /v1/info")?;
        if !resp.status().is_success() {
            anyhow::bail!("Ark ASP /v1/info returned HTTP {}", resp.status());
        }
        let body = read_bounded_bytes(resp, 64 * 1024).await?;
        let wire: ArkdInfoResponse =
            serde_json::from_slice(&body).context("decoding arkd info JSON")?;
        let info = ArkAspInfo::try_from(wire)?;
        info.validate()?;
        self.validate_network(&info)?;
        Ok(info)
    }

    /// Construct and validate an out-of-round (`ArkSettlementHandoff::OutOfRound`) handoff using live ASP parameters.
    #[cfg(feature = "std")]
    pub async fn build_oor_handoff(
        &self,
        sender_vtxo_outpoint: &str,
        receiver_pubkey: &str,
        amount_sats: u64,
    ) -> Result<(ArkAspInfo, ArkSettlementHandoff)> {
        let info = self.get_asp_info().await?;
        let vtxo_tree_expiry = info
            .vtxo_tree_expiry
            .context("ASP VTXO tree expiry unavailable")?;
        let fee_sats = info.estimate_transfer_fee(amount_sats)?;
        let ark_uri = format!(
            "ark:{receiver_pubkey}?server={}&amount={amount_sats}&asp_pubkey={}",
            urlencoding::encode(&self.server_url),
            info.pubkey
        );
        let handoff = ArkSettlementHandoff::OutOfRound(ArkOorPaymentRequest {
            server_url: self.server_url.clone(),
            asp_pubkey: info.pubkey.clone(),
            sender_vtxo_outpoint: sender_vtxo_outpoint.to_string(),
            receiver_pubkey: receiver_pubkey.to_string(),
            amount_sats,
            fee_sats,
            vtxo_tree_expiry,
            ark_uri,
        });
        handoff.validate(&info)?;
        Ok((info, handoff))
    }

    /// Forward host-wallet payloads to the pinned arkd v1 submission API.
    /// Handoff metadata alone cannot form a valid transaction or BIP-322 intent proof.
    #[cfg(feature = "std")]
    pub async fn submit_settlement_handoff(
        &self,
        asp_info: &ArkAspInfo,
        handoff: &ArkSettlementHandoff,
        submission: &ArkSettlementSubmission,
    ) -> Result<ArkSettlementSubmissionResponse> {
        self.validate_network(asp_info)?;
        handoff.validate(asp_info)?;
        let handoff_server = match handoff {
            ArkSettlementHandoff::Boarding(b) => &b.server_url,
            ArkSettlementHandoff::InRoundForfeit(f) => &f.server_url,
            ArkSettlementHandoff::OutOfRound(oor) => &oor.server_url,
        };
        if normalized_server_url(handoff_server)? != normalized_server_url(&self.server_url)? {
            anyhow::bail!("handoff ASP server does not match configured client ASP");
        }
        let (path, payload) = match (handoff, submission) {
            (ArkSettlementHandoff::OutOfRound(_), ArkSettlementSubmission::Transaction(tx)) => {
                if tx.signed_ark_tx.trim().is_empty()
                    || tx.checkpoint_txs.is_empty()
                    || tx.checkpoint_txs.iter().any(|tx| tx.trim().is_empty())
                {
                    anyhow::bail!("wallet-prepared Ark transaction and checkpoints are required");
                }
                ("/v1/tx/submit", serde_json::to_value(tx)?)
            }
            (
                ArkSettlementHandoff::Boarding(_) | ArkSettlementHandoff::InRoundForfeit(_),
                ArkSettlementSubmission::Intent(request),
            ) => {
                if request.intent.proof.trim().is_empty()
                    || request.intent.message.trim().is_empty()
                {
                    anyhow::bail!("wallet-prepared Ark intent proof and message are required");
                }
                ("/v1/batch/registerIntent", serde_json::to_value(request)?)
            }
            _ => anyhow::bail!("Ark submission payload does not match settlement mode"),
        };
        assert_no_private_material(&serde_json::to_string(&payload)?)
            .map_err(|e| anyhow!("{e}"))?;
        let url = format!("{}{path}", self.server_url);
        self.validate_endpoint(&url)?;

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()?;
        let resp = client
            .post(&url)
            .json(&payload)
            .send()
            .await
            .context("submitting Ark settlement to ASP")?;
        if !resp.status().is_success() {
            anyhow::bail!("Ark ASP submission returned HTTP {}", resp.status());
        }
        let body = read_bounded_bytes(resp, 64 * 1024).await?;
        let response = match submission {
            ArkSettlementSubmission::Transaction(_) => {
                ArkSettlementSubmissionResponse::Transaction(
                    serde_json::from_slice(&body).context("decoding arkd SubmitTxResponse")?,
                )
            }
            ArkSettlementSubmission::Intent(_) => ArkSettlementSubmissionResponse::Intent(
                serde_json::from_slice(&body).context("decoding arkd RegisterIntentResponse")?,
            ),
        };
        response.receipt()?;
        Ok(response)
    }
}

#[cfg(test)]
mod tests;
