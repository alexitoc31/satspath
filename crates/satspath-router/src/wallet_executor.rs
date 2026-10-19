//! Standardized non-custodial [`WalletExecutor`] SDK bridges for BDK, LDK, and Boltz Swaps.
//!
//! # Non-Custodial Invariant
//! SatsPath discovers capabilities, verifies cryptographic profile identities, scores routes,
//! and outputs validated payment handoff payloads (`QuoteResponse`). SatsPath **never** holds,
//! requests, or generates user seed phrases, `xprv`/`tprv` keys, or Lightning node credentials.
//! All transaction signing and settlement broadcast are sovereignly executed by the host wallet
//! via the trait bridges defined in this module.

use std::str::FromStr;

use anyhow::Result;
use async_trait::async_trait;
use bitcoin::absolute::LockTime;
use bitcoin::psbt::Psbt;
use bitcoin::{Address, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut};
use lightning_invoice::{Bolt11Invoice, Currency};
use satspath_core::bip321::parse_bip321;
use satspath_core::crypto::{check_profile_expiry, fingerprint_pubkey, verify_signed_profile};
use satspath_core::execution::{
    ExecutionGatePolicy, OnchainReceipt, PaymentReceipt, WalletExecutor,
};
use satspath_core::pointer::BitcoinNetwork;
use satspath_core::privacy::{canonical_identifier, identifier_hash};
use satspath_core::transparency::{
    next_identifier_sequence, verify_checkpoint_inclusion, NameAction,
    TransactionalTransparencyStore,
};
use satspath_core::validation::{
    assert_no_private_material, validate_amount_sats, validate_bitcoin_address,
};
use satspath_core::PaymentMethod;
use satspath_core::{Result as CoreResult, SatsPathError};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::quote_response::{build_qr_payload, QuoteResponse};
use satspath_core::resolver::ResolverSource;

/// Unified receipt returned after a host wallet executes a validated SatsPath handoff payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "rail", rename_all = "snake_case")]
pub enum HandoffExecutionReceipt {
    /// On-chain Bitcoin transaction executed by the host wallet (e.g. BDK).
    Onchain(OnchainReceipt),
    /// Lightning BOLT11 payment executed by the host wallet (e.g. LDK).
    Lightning(PaymentReceipt),
    /// Host-broadcast swap spend; confirmations must be tracked separately.
    SwapSettlement {
        /// Swap identifier.
        swap_id: String,
        /// Settlement kind (`"reverse_claim"` or `"submarine_refund"`).
        settlement_kind: String,
        /// Broadcast on-chain transaction ID (64-char hex).
        txid: String,
        /// Net output amount in satoshis delivered to the host wallet address.
        output_amount_sats: u64,
        /// Miner fee in satoshis.
        fee_sats: u64,
    },
}

// ============================================================================
// 1. Reference BDK (Bitcoin Development Kit) On-Chain Bridge
// ============================================================================

/// Non-custodial UTXO input descriptor supplied by a host BDK wallet for PSBT construction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BdkUtxoDescriptor {
    /// Previous output transaction ID (64-char hex).
    pub txid: String,
    /// Previous output index.
    pub vout: u32,
    /// Value of the UTXO in satoshis.
    pub amount_sats: u64,
    /// Hex-encoded `scriptPubKey` of the UTXO.
    pub script_pubkey_hex: String,
}

/// Callback interface implemented by the host BDK wallet.
///
/// The host wallet retains exclusive control over private spending keys: it supplies public
/// UTXO descriptors and a change address, inspects the unsigned PSBT constructed by the bridge,
/// signs it internally, and broadcasts the finalized transaction.
#[async_trait]
pub trait BdkHostWallet: Send + Sync {
    /// Select spendable public UTXOs and a host-controlled change address to fund `target_sats`.
    async fn select_utxos_and_change(
        &self,
        target_sats: u64,
        fee_rate_sat_vb: u64,
    ) -> Result<(Vec<BdkUtxoDescriptor>, String)>;

    /// Inspect, sign, and broadcast an unsigned base64 PSBT, returning the 64-char hex `txid`.
    async fn sign_and_broadcast_psbt(&self, unsigned_psbt_base64: &str) -> Result<String>;
}

/// Reference BDK on-chain executor that validates BIP-21 handoffs, constructs unsigned PSBTs
/// with strict fee guardrails, and delegates signing + broadcast to a [`BdkHostWallet`].
pub struct BdkOnchainBridge<W: BdkHostWallet> {
    network: BitcoinNetwork,
    max_fee_rate_sat_vb: u64,
    default_fee_rate_sat_vb: u64,
    host_wallet: W,
}

impl<W: BdkHostWallet> BdkOnchainBridge<W> {
    /// Construct a new BDK on-chain bridge for `network` with a maximum fee-rate cap.
    pub fn new(
        network: BitcoinNetwork,
        default_fee_rate_sat_vb: u64,
        max_fee_rate_sat_vb: u64,
        host_wallet: W,
    ) -> Self {
        Self {
            network,
            max_fee_rate_sat_vb,
            default_fee_rate_sat_vb,
            host_wallet,
        }
    }

    /// Construct an unsigned [`Psbt`] for an on-chain payment, enforcing address network validation,
    /// fee guardrails, and dust thresholds.
    pub async fn build_unsigned_psbt(
        &self,
        destination_address: &str,
        amount_sats: u64,
        fee_rate_sat_vb: Option<u64>,
    ) -> CoreResult<(Psbt, u64)> {
        validate_amount_sats(amount_sats)?;
        assert_no_private_material(destination_address)?;
        validate_bitcoin_address(destination_address, self.network)?;

        let rate = fee_rate_sat_vb.unwrap_or(self.default_fee_rate_sat_vb);
        if rate == 0 || rate > self.max_fee_rate_sat_vb {
            return Err(SatsPathError::ValidationError(format!(
                "Fee rate {rate} sat/vB is outside allowed bounds (1..={} sat/vB)",
                self.max_fee_rate_sat_vb
            )));
        }

        // Estimate 1-in-2-out SegWit vBytes (~141 vB)
        let estimated_fee_sats = rate.saturating_mul(141);
        let required_total = amount_sats.saturating_add(estimated_fee_sats);

        let (utxos, change_address) = self
            .host_wallet
            .select_utxos_and_change(required_total, rate)
            .await
            .map_err(|e| {
                SatsPathError::ValidationError(format!("BDK coin selection failed: {e}"))
            })?;

        if utxos.is_empty() {
            return Err(SatsPathError::ValidationError(
                "BDK host wallet returned no UTXOs".into(),
            ));
        }
        validate_bitcoin_address(&change_address, self.network)?;

        let mut total_in: u64 = 0;
        let mut tx_ins = Vec::with_capacity(utxos.len());
        let mut witness_utxos = Vec::with_capacity(utxos.len());

        for u in &utxos {
            let outpoint = OutPoint::from_str(&format!("{}:{}", u.txid, u.vout)).map_err(|e| {
                SatsPathError::ValidationError(format!("invalid UTXO outpoint: {e}"))
            })?;
            let spk_bytes = hex::decode(u.script_pubkey_hex.trim()).map_err(|e| {
                SatsPathError::ValidationError(format!("invalid UTXO scriptPubKey hex: {e}"))
            })?;
            total_in = total_in.saturating_add(u.amount_sats);
            tx_ins.push(TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: bitcoin::Witness::new(),
            });
            witness_utxos.push(TxOut {
                value: Amount::from_sat(u.amount_sats),
                script_pubkey: ScriptBuf::from_bytes(spk_bytes),
            });
        }

        if total_in < required_total {
            return Err(SatsPathError::ValidationError(format!(
                "insufficient UTXO funds: input {total_in} sats < required {required_total} sats"
            )));
        }

        let dest_addr = Address::from_str(destination_address.trim())
            .map_err(|e| SatsPathError::InvalidPaymentPointer(e.to_string()))?
            .assume_checked();
        let change_addr = Address::from_str(change_address.trim())
            .map_err(|e| SatsPathError::InvalidPaymentPointer(e.to_string()))?
            .assume_checked();

        let change_sats = total_in - required_total;
        let mut outputs = vec![TxOut {
            value: Amount::from_sat(amount_sats),
            script_pubkey: dest_addr.script_pubkey(),
        }];
        if change_sats >= 546 {
            outputs.push(TxOut {
                value: Amount::from_sat(change_sats),
                script_pubkey: change_addr.script_pubkey(),
            });
        }

        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: tx_ins,
            output: outputs,
        };

        let mut psbt = Psbt::from_unsigned_tx(unsigned_tx)
            .map_err(|e| SatsPathError::ValidationError(format!("PSBT creation failed: {e}")))?;
        for (idx, w_utxo) in witness_utxos.into_iter().enumerate() {
            psbt.inputs[idx].witness_utxo = Some(w_utxo);
        }

        Ok((psbt, estimated_fee_sats))
    }

    /// Parse a `bitcoin:` BIP-21 URI handoff, construct an unsigned PSBT, and execute via the host wallet.
    pub async fn execute_bip21_uri(
        &self,
        bip21_uri: &str,
        fallback_amount_sats: u64,
        fee_rate_sat_vb: Option<u64>,
    ) -> CoreResult<OnchainReceipt> {
        assert_no_private_material(bip21_uri)?;
        let parsed = parse_bip321(bip21_uri)?;
        let address = parsed.address.ok_or_else(|| {
            SatsPathError::InvalidPaymentUri("BIP-21 URI is missing an on-chain address".into())
        })?;
        let amount_sats = if let Some(ref btc_str) = parsed.amount_btc {
            let amt =
                Amount::from_str_in(btc_str, bitcoin::Denomination::Bitcoin).map_err(|e| {
                    SatsPathError::InvalidPaymentUri(format!("invalid BTC amount: {e}"))
                })?;
            amt.to_sat()
        } else {
            fallback_amount_sats
        };
        if amount_sats != fallback_amount_sats {
            return Err(SatsPathError::ValidationError(format!(
                "BIP-21 URI amount ({amount_sats} sats) mismatches expected quote amount ({fallback_amount_sats} sats)"
            )));
        }
        let (psbt, fee_sats) = self
            .build_unsigned_psbt(&address, amount_sats, fee_rate_sat_vb)
            .await?;
        let psbt_hex = psbt.serialize_hex();
        let txid = self
            .host_wallet
            .sign_and_broadcast_psbt(&psbt_hex)
            .await
            .map_err(|e| {
                SatsPathError::NetworkError(format!("BDK PSBT signing/broadcast failed: {e}"))
            })?;
        Ok(OnchainReceipt {
            txid,
            amount_sats,
            fee_sats,
            destination: address,
            timestamp: chrono::Utc::now().timestamp(),
        })
    }
}

// ============================================================================
// 2. Reference LDK / LNURL Lightning Bridge
// ============================================================================

/// Callback interface implemented by a host LDK node or LNURL-capable wallet.
#[async_trait]
pub trait LdkHostNode: Send + Sync {
    /// Dispatch a validated BOLT11 invoice payment through the host Lightning node.
    async fn send_bolt11_payment(
        &self,
        bolt11_invoice: &str,
        expected_amount_msats: u64,
        max_fee_msats: u64,
    ) -> Result<PaymentReceipt>;
}

/// Reference LDK / Lightning executor that validates BOLT11 invoices (signature, network,
/// expiry, and exact amount) before delegating payment execution to an [`LdkHostNode`].
pub struct LdkLightningBridge<L: LdkHostNode> {
    network: BitcoinNetwork,
    max_fee_bps: u64,
    host_node: L,
}

impl<L: LdkHostNode> LdkLightningBridge<L> {
    /// Construct a new LDK Lightning bridge for `network` with a maximum routing fee in basis points.
    pub fn new(network: BitcoinNetwork, max_fee_bps: u64, host_node: L) -> Self {
        Self {
            network,
            max_fee_bps,
            host_node,
        }
    }

    /// Validate a BOLT11 invoice and execute payment via the host LDK node.
    pub async fn validate_and_pay_bolt11(
        &self,
        invoice_str: &str,
        expected_amount_sats: u64,
    ) -> CoreResult<PaymentReceipt> {
        let validated =
            validate_handoff_bolt11(invoice_str.trim(), expected_amount_sats, self.network)?;
        let amount_msats = validated
            .amount_milli_satoshis()
            .expect("validated exact amount");
        let max_fee_msats = (amount_msats.saturating_mul(self.max_fee_bps) / 10_000).max(1_000);

        self.host_node
            .send_bolt11_payment(invoice_str.trim(), amount_msats, max_fee_msats)
            .await
            .map_err(|e| SatsPathError::NetworkError(format!("LDK payment failed: {e}")))
    }
}

// ============================================================================
// 3. Combined Non-Custodial Host Wallet Bridge (BDK + LDK -> WalletExecutor)
// ============================================================================

/// Combined non-custodial host wallet adapter implementing [`WalletExecutor`] by bridging
/// on-chain operations to [`BdkOnchainBridge`] and Lightning operations to [`LdkLightningBridge`].
pub struct HostWalletSdkBridge<W: BdkHostWallet, L: LdkHostNode> {
    network: BitcoinNetwork,
    bdk: BdkOnchainBridge<W>,
    ldk: LdkLightningBridge<L>,
}

impl<W: BdkHostWallet, L: LdkHostNode> HostWalletSdkBridge<W, L> {
    /// Construct a unified host wallet bridge from a BDK on-chain bridge and an LDK Lightning bridge.
    pub fn new(
        network: BitcoinNetwork,
        bdk: BdkOnchainBridge<W>,
        ldk: LdkLightningBridge<L>,
    ) -> Self {
        Self { network, bdk, ldk }
    }

    /// Reference to the underlying [`BdkOnchainBridge`].
    pub fn bdk(&self) -> &BdkOnchainBridge<W> {
        &self.bdk
    }

    /// Reference to the underlying [`LdkLightningBridge`].
    pub fn ldk(&self) -> &LdkLightningBridge<L> {
        &self.ldk
    }
}

#[async_trait]
impl<W: BdkHostWallet, L: LdkHostNode> WalletExecutor for HostWalletSdkBridge<W, L> {
    /// Return the configured host wallet network.
    fn network(&self) -> BitcoinNetwork {
        self.network
    }

    /// Reject fractional satoshis and validate the exact invoice before host dispatch.
    async fn pay_bolt11(
        &self,
        invoice: &str,
        amount_msats: Option<u64>,
    ) -> CoreResult<PaymentReceipt> {
        let amount_msats = amount_msats.ok_or_else(|| {
            SatsPathError::ValidationError(
                "amount_msats is required for verified BOLT11 execution".into(),
            )
        })?;
        if amount_msats % 1_000 != 0 {
            return Err(SatsPathError::ValidationError(
                "amount_msats must be an exact number of satoshis".into(),
            ));
        }
        let amount_sats = amount_msats / 1_000;
        self.ldk.validate_and_pay_bolt11(invoice, amount_sats).await
    }

    /// Build an on-chain PSBT and delegate its execution to the host wallet.
    async fn send_onchain(
        &self,
        destination_address: &str,
        amount_sats: u64,
        fee_rate_sat_vb: Option<u64>,
    ) -> CoreResult<OnchainReceipt> {
        let (psbt, fee_sats) = self
            .bdk
            .build_unsigned_psbt(destination_address, amount_sats, fee_rate_sat_vb)
            .await?;
        let psbt_b64 = base64_encode_psbt(&psbt);
        let txid = self.sign_and_broadcast_psbt(&psbt_b64).await?;
        Ok(OnchainReceipt {
            txid,
            amount_sats,
            fee_sats,
            destination: destination_address.to_string(),
            timestamp: chrono::Utc::now().timestamp(),
        })
    }

    /// Delegate PSBT signing and broadcasting and validate the returned transaction ID.
    async fn sign_and_broadcast_psbt(&self, psbt_base64: &str) -> CoreResult<String> {
        if psbt_base64.trim().is_empty() {
            return Err(SatsPathError::ValidationError(
                "PSBT cannot be empty".into(),
            ));
        }
        assert_no_private_material(psbt_base64)?;
        let txid = self
            .bdk
            .host_wallet
            .sign_and_broadcast_psbt(psbt_base64)
            .await
            .map_err(|e| {
                SatsPathError::NetworkError(format!("BDK PSBT signing/broadcast failed: {e}"))
            })?;
        if txid.len() != 64 || hex::decode(&txid).is_err() {
            return Err(SatsPathError::ValidationError(format!(
                "host wallet returned invalid txid: {txid}"
            )));
        }
        Ok(txid)
    }

    async fn send_onchain_with_max_fee(
        &self,
        destination: &str,
        amount_sats: u64,
        max_fee_sats: u64,
    ) -> CoreResult<OnchainReceipt> {
        let (psbt, _) = self
            .bdk
            .build_unsigned_psbt(destination, amount_sats, None)
            .await?;
        let total_in = psbt.inputs.iter().try_fold(0u64, |sum, input| {
            sum.checked_add(
                input
                    .witness_utxo
                    .as_ref()
                    .ok_or_else(|| {
                        SatsPathError::ValidationError("missing PSBT funding evidence".into())
                    })?
                    .value
                    .to_sat(),
            )
            .ok_or_else(|| SatsPathError::ValidationError("UTXO sum overflow".into()))
        })?;
        let total_out = psbt
            .unsigned_tx
            .output
            .iter()
            .try_fold(0u64, |sum, output| {
                sum.checked_add(output.value.to_sat())
                    .ok_or_else(|| SatsPathError::ValidationError("output sum overflow".into()))
            })?;
        let fee_sats = total_in
            .checked_sub(total_out)
            .ok_or_else(|| SatsPathError::ValidationError("negative PSBT fee".into()))?;
        if fee_sats > max_fee_sats {
            return Err(SatsPathError::ValidationError(
                "PSBT fee exceeds approved maximum".into(),
            ));
        }
        let expected_txid = psbt.unsigned_tx.compute_txid().to_string();
        let txid = self
            .sign_and_broadcast_psbt(&base64_encode_psbt(&psbt))
            .await?;
        if txid != expected_txid {
            return Err(SatsPathError::ValidationError(
                "host broadcast txid does not match approved PSBT".into(),
            ));
        }
        Ok(OnchainReceipt {
            txid,
            amount_sats,
            fee_sats,
            destination: destination.into(),
            timestamp: chrono::Utc::now().timestamp(),
        })
    }

    async fn pay_bolt11_with_max_fee(
        &self,
        invoice: &str,
        amount_msats: u64,
        max_fee_msats: u64,
    ) -> CoreResult<PaymentReceipt> {
        if !amount_msats.is_multiple_of(1_000) || max_fee_msats == 0 {
            return Err(SatsPathError::ValidationError(
                "invalid fee-bound invoice amount".into(),
            ));
        }
        let validated = validate_handoff_bolt11(invoice, amount_msats / 1_000, self.network)?;
        let adapter_cap = (amount_msats.saturating_mul(self.ldk.max_fee_bps) / 10_000).max(1_000);
        let cap = max_fee_msats.min(adapter_cap);
        if cap == 0 {
            return Err(SatsPathError::ValidationError(
                "Lightning fee cap is zero".into(),
            ));
        }
        let receipt = self
            .ldk
            .host_node
            .send_bolt11_payment(invoice, amount_msats, cap)
            .await
            .map_err(|e| SatsPathError::NetworkError(format!("LDK payment failed: {e}")))?;
        if receipt.amount_msats != amount_msats
            || receipt.fee_msats > cap
            || receipt.payment_hash != validated.payment_hash().to_string()
        {
            return Err(SatsPathError::ValidationError(
                "host Lightning receipt does not match approved intent".into(),
            ));
        }
        Ok(receipt)
    }
}

/// Encode a [`Psbt`] to hex using its consensus serialization.
fn base64_encode_psbt(psbt: &Psbt) -> String {
    psbt.serialize_hex()
}

// ============================================================================
// 4. Boltz Testnet Swap Claim/Refund Host-Wallet Execution Bridge
// ============================================================================

/// Public swap terms and fresh chain evidence obtained by the sovereign host wallet.
/// The host must authenticate these terms against its saved swap agreement and query
/// its trusted Bitcoin node for the confirmed, unspent lockup and current tip.
#[derive(Debug, Clone)]
pub struct BoltzSwapEvidence {
    pub network: BitcoinNetwork,
    pub lockup_transaction: Transaction,
    pub lockup_vout: u32,
    pub confirmations: u32,
    pub unspent: bool,
    pub current_block_height: u32,
    pub payment_hash: [u8; 32],
    pub claim_pubkey: bitcoin::PublicKey,
    pub refund_pubkey: bitcoin::PublicKey,
    pub timeout_block_height: u32,
    pub destination_address: String,
    pub max_fee_sats: u64,
}

/// Host-owned signing, chain verification and broadcasting boundary.
#[async_trait]
pub trait BoltzHostSignerBroadcaster: Send + Sync {
    /// Load authenticated swap terms and fresh chain evidence, independently of
    /// caller-supplied outpoints/amounts. Missing evidence disables execution.
    async fn swap_evidence(&self, _swap_id: &str) -> Result<BoltzSwapEvidence> {
        anyhow::bail!("verified swap evidence unavailable")
    }

    /// Inspect/authorize the spend and return a low-S DER ECDSA signature followed
    /// by SIGHASH_ALL (0x01), using the saved swap's claim or refund spending key.
    async fn sign_swap_digest(&self, swap_id: &str, sighash: [u8; 32]) -> Result<Vec<u8>>;

    /// Broadcast on the configured test network; return the transaction's txid.
    /// A broadcast receipt does not attest to settlement confirmations.
    async fn broadcast_swap_tx(&self, raw_tx_hex: &str) -> Result<String>;
}

/// Testnet/Regtest legacy Boltz native P2WSH HTLC spends. Mainnet, Taproot,
/// nested SegWit and cross-chain scripts are deliberately unsupported.
pub struct BoltzTestnetSwapBridge<S: BoltzHostSignerBroadcaster> {
    network: BitcoinNetwork,
    signer: S,
}

impl<S: BoltzHostSignerBroadcaster> BoltzTestnetSwapBridge<S> {
    pub fn new(network: BitcoinNetwork, signer: S) -> Self {
        Self { network, signer }
    }

    /// Claim a confirmed reverse-swap lockup using its committed 32-byte preimage.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_reverse_claim(
        &self,
        swap_id: &str,
        lockup_txid: &str,
        lockup_vout: u32,
        lockup_amount_sats: u64,
        preimage_hex: &str,
        redeem_script_hex: &str,
        destination_address: &str,
        miner_fee_sats: u64,
    ) -> CoreResult<HandoffExecutionReceipt> {
        let preimage: [u8; 32] = hex::decode(preimage_hex)
            .map_err(|_| invalid_swap("invalid preimage"))?
            .try_into()
            .map_err(|_| invalid_swap("preimage must be 32 bytes"))?;
        self.execute_swap(
            swap_id,
            lockup_txid,
            lockup_vout,
            lockup_amount_sats,
            Some(preimage),
            None,
            redeem_script_hex,
            destination_address,
            miner_fee_sats,
        )
        .await
    }

    /// Refund a submarine swap after its block-height CLTV has matured.
    /// The supplied height is cross-checked against the host's trusted node.
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_submarine_refund(
        &self,
        swap_id: &str,
        lockup_txid: &str,
        lockup_vout: u32,
        lockup_amount_sats: u64,
        timeout_block_height: u32,
        current_block_height: u32,
        redeem_script_hex: &str,
        destination_address: &str,
        miner_fee_sats: u64,
    ) -> CoreResult<HandoffExecutionReceipt> {
        self.execute_swap(
            swap_id,
            lockup_txid,
            lockup_vout,
            lockup_amount_sats,
            None,
            Some((timeout_block_height, current_block_height)),
            redeem_script_hex,
            destination_address,
            miner_fee_sats,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn execute_swap(
        &self,
        swap_id: &str,
        lockup_txid: &str,
        lockup_vout: u32,
        amount: u64,
        preimage: Option<[u8; 32]>,
        refund_heights: Option<(u32, u32)>,
        script_hex: &str,
        destination: &str,
        fee: u64,
    ) -> CoreResult<HandoffExecutionReceipt> {
        use bitcoin::hashes::{hash160, ripemd160, sha256, Hash};
        use bitcoin::secp256k1::{Message, Secp256k1};
        use bitcoin::sighash::{EcdsaSighashType, SighashCache};
        if self.network == BitcoinNetwork::Mainnet {
            return Err(invalid_swap("Mainnet execution is disabled"));
        }
        validate_amount_sats(amount)?;
        validate_bitcoin_address(destination, self.network)?;
        if swap_id.trim().is_empty() || fee == 0 || fee > 10_000 {
            return Err(invalid_swap(
                "invalid swap ID or miner fee (1..=10000 sats)",
            ));
        }
        let output_amount = amount
            .checked_sub(fee)
            .filter(|value| *value >= 546)
            .ok_or_else(|| invalid_swap("fee exceeds amount or output is dust"))?;
        let evidence = self
            .signer
            .swap_evidence(swap_id)
            .await
            .map_err(|e| invalid_swap(&format!("lockup evidence: {e}")))?;
        let outpoint = OutPoint::from_str(&format!("{lockup_txid}:{lockup_vout}"))
            .map_err(|_| invalid_swap("invalid lockup outpoint"))?;
        let script = ScriptBuf::from_bytes(
            hex::decode(script_hex).map_err(|_| invalid_swap("invalid witness script hex"))?,
        );
        if evidence.network != self.network
            || evidence.confirmations == 0
            || !evidence.unspent
            || evidence.lockup_transaction.compute_txid() != outpoint.txid
            || evidence.lockup_vout != lockup_vout
            || evidence.destination_address != destination
            || fee > evidence.max_fee_sats
            || evidence.timeout_block_height == 0
            || evidence.timeout_block_height >= 500_000_000
            || !evidence.claim_pubkey.compressed
            || !evidence.refund_pubkey.compressed
            || script != boltz_witness_script(&evidence, preimage.is_some())
        {
            return Err(invalid_swap(
                "swap terms, witness script or lockup evidence mismatch",
            ));
        }
        let lockup = evidence
            .lockup_transaction
            .output
            .get(lockup_vout as usize)
            .ok_or_else(|| invalid_swap("lockup output missing"))?;
        if lockup.value.to_sat() != amount || lockup.script_pubkey != script.to_p2wsh() {
            return Err(invalid_swap("lockup amount or P2WSH commitment mismatch"));
        }
        let (lock_time, key, selector, kind) = if let Some(preimage) = preimage {
            if sha256::Hash::hash(&preimage).to_byte_array() != evidence.payment_hash {
                return Err(invalid_swap("preimage does not match payment hash"));
            }
            (
                LockTime::ZERO,
                evidence.claim_pubkey,
                preimage.to_vec(),
                "reverse_claim",
            )
        } else {
            let (timeout, height) =
                refund_heights.ok_or_else(|| invalid_swap("missing refund height"))?;
            if hash160::Hash::hash(&[]).to_byte_array()
                == ripemd160::Hash::hash(&evidence.payment_hash).to_byte_array()
            {
                return Err(invalid_swap(
                    "empty refund selector would take the claim branch",
                ));
            }
            if timeout != evidence.timeout_block_height
                || height != evidence.current_block_height
                || height < timeout
            {
                return Err(invalid_swap(
                    "CLTV has not matured or height evidence mismatch",
                ));
            }
            (
                LockTime::from_height(timeout).map_err(|_| invalid_swap("invalid CLTV height"))?,
                evidence.refund_pubkey,
                vec![],
                "submarine_refund",
            )
        };
        let address = Address::from_str(destination)
            .map_err(|_| invalid_swap("invalid destination"))?
            .assume_checked();
        let mut tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_LOCKTIME_NO_RBF,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_amount),
                script_pubkey: address.script_pubkey(),
            }],
        };
        // Include the SegWit overhead and a conservative maximum DER signature
        // plus SIGHASH_ALL byte, with the selector for this claim/refund template.
        let mut estimated_tx = tx.clone();
        estimated_tx.input[0].witness =
            bitcoin::Witness::from_slice(&[&[0u8; 73][..], selector.as_slice(), script.as_bytes()]);
        let minimum_fee = estimated_tx.vsize() as u64;
        if fee < minimum_fee {
            return Err(invalid_swap(&format!(
                "miner fee {fee} sats is below the 1 sat/vB minimum ({minimum_fee} sats)"
            )));
        }
        let sighash = SighashCache::new(&tx)
            .p2wsh_signature_hash(0, &script, lockup.value, EcdsaSighashType::All)
            .map_err(|_| invalid_swap("cannot compute BIP143 sighash"))?
            .to_byte_array();
        let bytes = self
            .signer
            .sign_swap_digest(swap_id, sighash)
            .await
            .map_err(|e| invalid_swap(&format!("host signing failed: {e}")))?;
        let signature = bitcoin::ecdsa::Signature::from_slice(&bytes)
            .map_err(|_| invalid_swap("invalid host ECDSA signature"))?;
        let mut normalized = signature.signature;
        normalized.normalize_s();
        if signature.sighash_type != EcdsaSighashType::All
            || normalized != signature.signature
            || Secp256k1::verification_only()
                .verify_ecdsa(
                    &Message::from_digest(sighash),
                    &signature.signature,
                    &key.inner,
                )
                .is_err()
        {
            return Err(invalid_swap("host signature does not authorize this spend"));
        }
        tx.input[0].witness = bitcoin::Witness::from_slice(&[bytes, selector, script.into_bytes()]);
        let expected_txid = tx.compute_txid().to_string();
        let txid = self
            .signer
            .broadcast_swap_tx(&bitcoin::consensus::encode::serialize_hex(&tx))
            .await
            .map_err(|e| SatsPathError::NetworkError(format!("host broadcast failed: {e}")))?;
        if txid != expected_txid {
            return Err(invalid_swap("broadcast transaction ID mismatch"));
        }
        Ok(HandoffExecutionReceipt::SwapSettlement {
            swap_id: swap_id.into(),
            settlement_kind: kind.into(),
            txid,
            output_amount_sats: output_amount,
            fee_sats: fee,
        })
    }
}

fn invalid_swap(message: &str) -> SatsPathError {
    SatsPathError::ValidationError(format!("Boltz swap: {message}"))
}

/// Reconstruct the complete legacy Boltz script from authenticated public terms.
/// Exact byte equality rejects extra opcodes, alternate branches and nonminimal pushes.
fn boltz_witness_script(terms: &BoltzSwapEvidence, reverse: bool) -> ScriptBuf {
    use bitcoin::hashes::{ripemd160, Hash};
    use bitcoin::opcodes::all::*;
    use bitcoin::script::Builder;
    let commitment = ripemd160::Hash::hash(&terms.payment_hash).to_byte_array();
    let builder = if reverse {
        Builder::new()
            .push_opcode(OP_SIZE)
            .push_int(32)
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_opcode(OP_HASH160)
            .push_slice(commitment)
            .push_opcode(OP_EQUALVERIFY)
            .push_key(&terms.claim_pubkey)
            .push_opcode(OP_ELSE)
            .push_opcode(OP_DROP)
    } else {
        Builder::new()
            .push_opcode(OP_HASH160)
            .push_slice(commitment)
            .push_opcode(OP_EQUAL)
            .push_opcode(OP_IF)
            .push_key(&terms.claim_pubkey)
            .push_opcode(OP_ELSE)
    };
    builder
        .push_int(terms.timeout_block_height as i64)
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_key(&terms.refund_pubkey)
        .push_opcode(OP_ENDIF)
        .push_opcode(OP_CHECKSIG)
        .into_script()
}

// ============================================================================
// 5. End-to-End QuoteResponse -> WalletExecutor Dispatcher
// ============================================================================

/// Public, canonical, inspectable description of a *single* proposed payment.
/// This is not an authorization to spend. The host must show it to the payer
/// and call [`PaymentIntent::approve`] before dispatch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentIntent {
    pub recipient_identity: String,
    pub verified_identity_key: String,
    pub selected_capability: PaymentMethod,
    pub network: BitcoinNetwork,
    pub amount_sats: u64,
    pub destination: String,
    pub estimated_fee_sats: Option<u64>,
    pub max_fee_sats: u64,
    pub expiry: Option<i64>,
    pub resolver_sources: Vec<ResolverSource>,
    pub verification_status: IntentVerification,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IntentVerification {
    pub profile_signature_verified: bool,
    pub identifier_verified: bool,
    pub key_continuity_verified: bool,
    pub transparency_verified: bool,
}

impl PaymentIntent {
    /// RFC 8785 serialization. Reject numbers that cannot be represented exactly
    /// by JCS/ECMAScript so distinct approved intents cannot share a digest.
    pub fn canonical_bytes(&self) -> CoreResult<Vec<u8>> {
        let value = serde_json::to_value(self)
            .map_err(|e| SatsPathError::SerializationError(e.to_string()))?;
        ensure_jcs_exact_numbers(&value)?;
        serde_json_canonicalizer::to_vec(&value)
            .map_err(|e| SatsPathError::SerializationError(e.to_string()))
    }

    /// Explicit host approval binds every displayed field to the eventual dispatch.
    /// `user_confirmed` must be obtained from the host UI, never from a resolver.
    pub fn approve(self, user_confirmed: bool) -> CoreResult<ApprovedPaymentIntent> {
        if !user_confirmed {
            return Err(SatsPathError::ValidationError(
                "payment intent requires explicit host-wallet approval".into(),
            ));
        }
        if self.resolver_sources.is_empty() || self.max_fee_sats == 0 {
            return Err(SatsPathError::ValidationError(
                "payment intent requires resolver provenance and a maximum fee".into(),
            ));
        }
        if let Some(expiry) = self.expiry {
            if chrono::Utc::now().timestamp() >= expiry {
                return Err(SatsPathError::ValidationError(
                    "payment intent expired".into(),
                ));
            }
        }
        let digest = Sha256::digest(self.canonical_bytes()?);
        Ok(ApprovedPaymentIntent {
            intent: self,
            digest: digest.into(),
        })
    }
}

fn ensure_jcs_exact_numbers(value: &serde_json::Value) -> CoreResult<()> {
    const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
    match value {
        serde_json::Value::Number(number) => {
            let exact = number.as_u64().is_some_and(|n| n <= MAX_SAFE_INTEGER)
                || number.as_i64().is_some_and(|n| {
                    n >= -(MAX_SAFE_INTEGER as i64) && n <= MAX_SAFE_INTEGER as i64
                });
            if !exact {
                return Err(SatsPathError::ValidationError(
                    "payment intent contains a number outside the exact JCS integer range".into(),
                ));
            }
        }
        serde_json::Value::Array(items) => {
            for item in items {
                ensure_jcs_exact_numbers(item)?;
            }
        }
        serde_json::Value::Object(fields) => {
            for item in fields.values() {
                ensure_jcs_exact_numbers(item)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Non-deserializable, single-use approval. Its fields cannot be edited after
/// approval; the dispatcher also reconstructs the intent from fresh signed state.
pub struct ApprovedPaymentIntent {
    intent: PaymentIntent,
    digest: [u8; 32],
}

impl ApprovedPaymentIntent {
    pub fn intent(&self) -> &PaymentIntent {
        &self.intent
    }
}

/// Prepare a payment for host inspection using *current* identity, witness,
/// gossip and checkpoint evidence. Resolver provenance is supplied by the
/// caller that actually performed resolution, not inferred from quote flags.
#[allow(clippy::too_many_arguments)]
pub fn prepare_payment_intent(
    profile_store: &TransactionalTransparencyStore,
    trust: &HandoffTrust,
    transparency: &HandoffTransparencyEvidence,
    quote_response: &QuoteResponse,
    network: BitcoinNetwork,
    amount_sats: u64,
    max_fee_sats: u64,
    resolver_sources: Vec<ResolverSource>,
) -> CoreResult<PaymentIntent> {
    validate_amount_sats(amount_sats)?;
    if resolver_sources.is_empty() || max_fee_sats == 0 {
        return Err(SatsPathError::ValidationError(
            "resolver provenance and a positive maximum fee are required".into(),
        ));
    }
    let QuoteResponse::Ok {
        recipient,
        selected_method,
        qr,
        fee_sats,
        ..
    } = quote_response
    else {
        return Err(SatsPathError::ValidationError(
            "cannot prepare a non-Ok quote".into(),
        ));
    };
    if !recipient.profile_signature_verified {
        return Err(SatsPathError::InvalidSignature);
    }
    if fee_sats.is_some_and(|fee| fee > max_fee_sats) {
        return Err(SatsPathError::ValidationError(
            "estimated fee exceeds the host maximum fee".into(),
        ));
    }
    verify_current_handoff_profile(
        profile_store,
        trust,
        transparency,
        recipient,
        selected_method,
    )?;
    let signed = profile_store
        .profile(&recipient.alias)?
        .ok_or_else(|| SatsPathError::AliasNotFound(recipient.alias.clone()))?;
    let mut expiry = signed.profile.expires_at;
    if expiry.is_some_and(|end| chrono::Utc::now().timestamp() >= end) {
        return Err(SatsPathError::ValidationError(
            "payment profile expired".into(),
        ));
    }
    assert_no_private_material(qr)?;
    let destination = match selected_method {
        PaymentMethod::Onchain {
            network: method_network,
            silent_payment_pubkey: None,
            ..
        } if *method_network == network
            && build_qr_payload(selected_method, amount_sats)? == *qr =>
        {
            let address = parse_bip321(qr)?.address.ok_or_else(|| {
                SatsPathError::InvalidPaymentUri("on-chain handoff has no address".into())
            })?;
            validate_bitcoin_address(&address, network)?;
            address
        }
        PaymentMethod::Lightning {
            lightning_address,
            receiver_pubkey,
            ..
        } => {
            let invoice = validate_handoff_bolt11(qr, amount_sats, network)?;
            let payee = invoice.recover_payee_pub_key().to_string();
            if lightning_address.as_deref() != Some(qr.as_str())
                && receiver_pubkey.as_deref() != Some(payee.as_str())
            {
                return Err(SatsPathError::ValidationError(
                    "invoice payee is not bound to the signed method".into(),
                ));
            }
            let invoice_end = invoice
                .expires_at()
                .and_then(|duration| i64::try_from(duration.as_secs()).ok())
                .ok_or_else(|| SatsPathError::ValidationError("invalid invoice expiry".into()))?;
            expiry = Some(expiry.map_or(invoice_end, |end| end.min(invoice_end)));
            qr.clone()
        }
        _ => {
            return Err(SatsPathError::ValidationError(
                "unsupported or network-mismatched payment intent".into(),
            ));
        }
    };
    Ok(PaymentIntent {
        recipient_identity: signed.profile.alias,
        verified_identity_key: signed.profile.identity_pubkey,
        selected_capability: selected_method.clone(),
        network,
        amount_sats,
        destination,
        estimated_fee_sats: *fee_sats,
        max_fee_sats,
        expiry,
        resolver_sources,
        verification_status: IntentVerification {
            profile_signature_verified: true,
            identifier_verified: recipient.identifier_verified,
            key_continuity_verified: true,
            transparency_verified: true,
        },
    })
}

/// Host-configured trust anchors, kept outside serialized quotes. Bootstrap the
/// checkpoint store out of band from a trusted checkpoint before executing. Reuse
/// this instance across calls and give its pin directory a single process owner.
pub struct HandoffTrust {
    pub checkpoints: std::sync::Mutex<satspath_core::transparency::CheckpointStore>,
    pub witness_quorum: u8,
    pub witness_pubkeys: Vec<String>,
    pub observer_pubkeys: Vec<String>,
}

/// Required evidence fetched from witnesses and independent observers for this
/// resolution. Serialized status flags are never used as proof of verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandoffTransparencyEvidence {
    pub current_state_proof: satspath_core::transparency::StateMapProof,
    pub witness_cosignatures: Vec<satspath_core::transparency::WitnessCosignature>,
    pub gossip_observations: Vec<satspath_core::transparency::GossipObservation>,
}

fn verify_handoff_transparency(
    trust: &HandoffTrust,
    evidence: &HandoffTransparencyEvidence,
    log: &satspath_core::transparency::TransparencyLog,
    checkpoint: &satspath_core::transparency::TransparencyCheckpoint,
    latest: &satspath_core::transparency::NameEvent,
) -> CoreResult<()> {
    use satspath_core::transparency::{
        verify_checkpoint_state_binding, verify_checkpoint_transition,
        verify_witness_quorum_against_checkpoint, DimensionStatus, IdentifierStatus,
        PinnedCheckpoint, StateMapValue,
    };
    let invalid = || {
        SatsPathError::ValidationError(
            "handoff transparency evidence or trust policy invalid".into(),
        )
    };
    let proof = &evidence.current_state_proof;
    verify_checkpoint_state_binding(proof, checkpoint)?;
    if proof.key_hash != latest.identifier_hash
        || proof.value
            != Some(StateMapValue {
                latest_event_hash: latest.event_hash()?,
                sequence: latest.sequence,
                status: IdentifierStatus::Registered,
            })
    {
        // A valid non-inclusion proof authenticates absence, never a payable alias.
        return Err(invalid());
    }
    // BIP340 identities are x-only. Reject duplicate encodings and opposite-parity
    // aliases in the configured policy before using the core quorum verifier.
    let mut identities = std::collections::HashSet::new();
    for key in &trust.witness_pubkeys {
        let identity = if key.len() == 64 {
            bitcoin::secp256k1::XOnlyPublicKey::from_str(key).map_err(|_| invalid())?
        } else {
            bitcoin::secp256k1::PublicKey::from_str(key)
                .map_err(|_| invalid())?
                .x_only_public_key()
                .0
        };
        if !identities.insert(identity.serialize()) {
            return Err(invalid());
        }
    }
    if trust.witness_quorum == 0
        || verify_witness_quorum_against_checkpoint(
            Some(checkpoint),
            &evidence.witness_cosignatures,
            trust.witness_quorum,
            &trust.witness_pubkeys,
        ) != DimensionStatus::Verified
        || evidence.gossip_observations.is_empty()
    {
        return Err(invalid());
    }
    let pins = trust.checkpoints.lock().map_err(|_| invalid())?;
    let pin = pins
        .load()?
        .into_iter()
        .find(|pin| pin.log_id == checkpoint.log_id)
        .ok_or_else(invalid)?;
    let consistency = if pin.tree_size < checkpoint.log_size {
        if !log.checkpoints().iter().any(|cp| {
            cp.log_size == pin.tree_size
                && cp.checkpoint_hash().ok().as_deref() == Some(pin.checkpoint_hash.as_str())
        }) {
            return Err(invalid());
        }
        Some(log.consistency(pin.tree_size, checkpoint.log_size)?)
    } else {
        None
    };
    verify_checkpoint_transition(&pin, checkpoint, consistency.as_ref())?;
    // The core transition verifier compares log roots at equal size; also bind
    // the entire signed checkpoint, including map_root, against the persisted pin.
    if pin.tree_size == checkpoint.log_size
        && pin.checkpoint_hash != checkpoint.checkpoint_hash()?
    {
        return Err(invalid());
    }
    for observation in &evidence.gossip_observations {
        observation.verify(
            &checkpoint.log_id,
            &checkpoint.operator_pubkey,
            &trust.observer_pubkeys,
            chrono::Utc::now().timestamp(),
        )?;
        let observed = &observation.checkpoint;
        // Ahead observations must be synchronized before dispatch. Old views
        // need an RFC6962 proof into our view; equal-size views must be identical.
        if observed.log_size > checkpoint.log_size
            || (observed.log_size == checkpoint.log_size
                && observed.checkpoint_hash()? != checkpoint.checkpoint_hash()?)
        {
            return Err(invalid());
        }
        let observed_pin = PinnedCheckpoint {
            log_id: observed.log_id.clone(),
            operator_pubkey: observed.operator_pubkey.clone(),
            operator_sequence: observed.operator_sequence,
            tree_size: observed.log_size,
            root_hash: observed.log_root.clone(),
            checkpoint_hash: observed.checkpoint_hash()?,
            first_seen_at: observation.observed_at,
            last_seen_at: observation.observed_at,
        };
        let consistency = if observed.log_size < checkpoint.log_size {
            // Require the full historical checkpoint too: a log-root proof alone
            // cannot authenticate an older observation's state-map root.
            if !log.checkpoints().iter().any(|cp| {
                cp.checkpoint_hash().ok().as_deref() == Some(observed_pin.checkpoint_hash.as_str())
            }) {
                return Err(invalid());
            }
            Some(log.consistency(observed.log_size, checkpoint.log_size)?)
        } else {
            None
        };
        verify_checkpoint_transition(&observed_pin, checkpoint, consistency.as_ref())?;
    }
    // Persist before dispatch. IO failure must never result in a wallet call.
    pins.pin_verified(checkpoint)?;
    Ok(())
}

/// Verify current local identity state and a payment payload before host dispatch.
///
/// `profile_store` must be the caller's authoritative, continuously updated local
/// transparency store. The profile and history are loaded afresh for each call;
/// missing state, revocations, unauthorized key changes and stale payment methods
/// fail closed. A state-map proof, nonzero witness quorum, independent gossip and
/// a persisted checkpoint pin are required. The serialized quote flags are insufficient.
///
/// BOLT11 invoices must match the configured network and exact amount. A fetched
/// invoice also requires a payee key bound to the current signed Lightning method;
/// an LNURL/address alone cannot authenticate an arbitrary invoice. Unsupported
/// BOLT12, Ark, Silent Payment and swap handoffs remain disabled.
#[allow(clippy::too_many_arguments)]
pub async fn execute_quote_handoff(
    executor: &dyn WalletExecutor,
    profile_store: &TransactionalTransparencyStore,
    trust: &HandoffTrust,
    transparency: &HandoffTransparencyEvidence,
    quote_response: &QuoteResponse,
    approved: ApprovedPaymentIntent,
    policy: &ExecutionGatePolicy,
) -> CoreResult<HandoffExecutionReceipt> {
    let expected_amount_sats = approved.intent.amount_sats;
    validate_amount_sats(expected_amount_sats)?;
    policy.check_execution_safety(executor.network(), expected_amount_sats, true)?;
    let refreshed = prepare_payment_intent(
        profile_store,
        trust,
        transparency,
        quote_response,
        executor.network(),
        expected_amount_sats,
        approved.intent.max_fee_sats,
        approved.intent.resolver_sources.clone(),
    )?;
    if refreshed != approved.intent
        || Sha256::digest(refreshed.canonical_bytes()?).as_slice() != approved.digest
    {
        return Err(SatsPathError::ValidationError(
            "approved payment intent changed before dispatch".into(),
        ));
    }

    let QuoteResponse::Ok {
        recipient,
        selected_method,
        qr,
        ..
    } = quote_response
    else {
        return Err(SatsPathError::ValidationError(
            "cannot execute non-Ok QuoteResponse".into(),
        ));
    };

    if !recipient.profile_signature_verified {
        return Err(SatsPathError::InvalidSignature);
    }

    verify_current_handoff_profile(
        profile_store,
        trust,
        transparency,
        recipient,
        selected_method,
    )?;

    assert_no_private_material(qr)?;
    let trimmed = qr.trim();
    let lower = trimmed.to_ascii_lowercase();

    if lower.starts_with("bitcoin:") {
        if !matches!(selected_method, PaymentMethod::Onchain { network, silent_payment_pubkey: None, .. } if *network == executor.network())
            || build_qr_payload(selected_method, expected_amount_sats)? != trimmed
        {
            return Err(SatsPathError::ValidationError(
                "handoff does not match the current signed on-chain method".into(),
            ));
        }
        let parsed = parse_bip321(trimmed)?;
        let addr = parsed.address.ok_or_else(|| {
            SatsPathError::InvalidPaymentUri("BIP-21 handoff URI is missing address".into())
        })?;
        validate_bitcoin_address(&addr, executor.network())?;
        if let Some(ref btc_str) = parsed.amount_btc {
            let amt =
                Amount::from_str_in(btc_str, bitcoin::Denomination::Bitcoin).map_err(|e| {
                    SatsPathError::InvalidPaymentUri(format!("invalid BTC amount: {e}"))
                })?;
            if amt.to_sat() != expected_amount_sats {
                return Err(SatsPathError::ValidationError(format!(
                    "BIP-21 handoff amount {} sats does not match expected {} sats",
                    amt.to_sat(),
                    expected_amount_sats
                )));
            }
        }
        let receipt = executor
            .send_onchain_with_max_fee(&addr, expected_amount_sats, approved.intent.max_fee_sats)
            .await?;
        return Ok(HandoffExecutionReceipt::Onchain(receipt));
    }

    if lower.starts_with("lnbc") || lower.starts_with("lntb") {
        let invoice = validate_handoff_bolt11(trimmed, expected_amount_sats, executor.network())?;
        let PaymentMethod::Lightning {
            lightning_address,
            receiver_pubkey,
            ..
        } = selected_method
        else {
            return Err(SatsPathError::ValidationError(
                "BOLT11 handoff requires a signed Lightning method".into(),
            ));
        };
        let payee = invoice.recover_payee_pub_key().to_string();
        let matches_direct = lightning_address.as_deref() == Some(trimmed);
        if !matches_direct && receiver_pubkey.as_deref() != Some(payee.as_str()) {
            return Err(SatsPathError::ValidationError(
                "BOLT11 payee is not bound to the current signed profile".into(),
            ));
        }
        let receipt = executor
            .pay_bolt11_with_max_fee(
                trimmed,
                invoice
                    .amount_milli_satoshis()
                    .expect("validated invoice amount"),
                approved
                    .intent
                    .max_fee_sats
                    .checked_mul(1_000)
                    .ok_or_else(|| SatsPathError::ValidationError("fee cap overflow".into()))?,
            )
            .await?;
        return Ok(HandoffExecutionReceipt::Lightning(receipt));
    }

    Err(SatsPathError::ValidationError(format!(
        "unsupported handoff payload scheme for direct WalletExecutor settlement: {trimmed}"
    )))
}

/// Decode and verify a BOLT11 invoice against an exact satoshi amount and network.
fn validate_handoff_bolt11(
    invoice_str: &str,
    expected_amount_sats: u64,
    network: BitcoinNetwork,
) -> CoreResult<Bolt11Invoice> {
    assert_no_private_material(invoice_str)?;
    validate_amount_sats(expected_amount_sats)?;
    let expected_msats = expected_amount_sats.checked_mul(1_000).ok_or_else(|| {
        SatsPathError::ValidationError("BOLT11 millisatoshi amount overflow".into())
    })?;
    if expected_msats > satspath_core::validation::MAX_PREVIEW_AMOUNT_SATS.saturating_mul(1_000) {
        return Err(SatsPathError::ValidationError(
            "invoice amount exceeds maximum allowed".into(),
        ));
    }
    // Bolt11Invoice's constructor verifies the signature and all semantic fields.
    let invoice = Bolt11Invoice::from_str(invoice_str)
        .map_err(|e| SatsPathError::ValidationError(format!("BOLT11 validation failed: {e}")))?;
    let currency = match network {
        BitcoinNetwork::Mainnet => Currency::Bitcoin,
        BitcoinNetwork::Testnet => Currency::BitcoinTestnet,
        BitcoinNetwork::Regtest => Currency::Regtest,
        BitcoinNetwork::Signet => Currency::Signet,
    };
    if invoice.currency() != currency {
        return Err(SatsPathError::ValidationError(format!(
            "BOLT11 invoice network does not match wallet network {network:?}"
        )));
    }
    let invoice_msats = invoice.amount_milli_satoshis().ok_or_else(|| {
        SatsPathError::ValidationError(
            "BOLT11 validation failed: invoice has no amount set — ambiguous invoice rejected"
                .into(),
        )
    })?;
    if invoice_msats != expected_msats {
        return Err(SatsPathError::ValidationError(format!(
            "BOLT11 validation failed: invoice amount mismatch: requested {} msats but invoice contains {} msats",
            expected_msats, invoice_msats
        )));
    }
    if invoice.is_expired() {
        return Err(SatsPathError::ValidationError(
            "BOLT11 validation failed: invoice has expired and cannot be paid".into(),
        ));
    }
    Ok(invoice)
}

/// Reload and verify the alias history and bind the selected method to its current profile.
fn verify_current_handoff_profile(
    store: &TransactionalTransparencyStore,
    trust: &HandoffTrust,
    transparency: &HandoffTransparencyEvidence,
    recipient: &crate::quote_response::QuoteRecipient,
    selected_method: &PaymentMethod,
) -> CoreResult<()> {
    let signed = store
        .profile(&recipient.alias)?
        .ok_or_else(|| SatsPathError::AliasNotFound(recipient.alias.clone()))?;
    let profile = &signed.profile;
    if canonical_identifier(&profile.alias) != canonical_identifier(&recipient.alias)
        || !verify_signed_profile(&signed)?
    {
        return Err(SatsPathError::InvalidSignature);
    }
    check_profile_expiry(profile)?;
    let log = store.load_log()?;
    let history: Vec<_> = log
        .history(&identifier_hash(&recipient.alias))
        .into_iter()
        .cloned()
        .collect();
    // Validates all signatures, authorized rotations and strictly increasing sequences,
    // and binds the latest event's full profile hash, identity key and sequence.
    next_identifier_sequence(Some(&signed), &history)?;
    let latest = history.last().ok_or_else(|| {
        SatsPathError::ValidationError("handoff requires transparency history".into())
    })?;
    if profile.revoked || latest.action == NameAction::Revoke {
        return Err(SatsPathError::RegistryError(
            "handoff recipient has been revoked".into(),
        ));
    }
    let checkpoint = log.checkpoints().last().ok_or_else(|| {
        SatsPathError::ValidationError("handoff requires a transparency checkpoint".into())
    })?;
    let event_hash = latest.event_hash()?;
    let inclusion = log.inclusion(&event_hash, None)?;
    verify_checkpoint_inclusion(&event_hash, &inclusion, checkpoint)?;
    if recipient.fingerprint.as_deref()
        != Some(fingerprint_pubkey(&profile.identity_pubkey)?.as_str())
        || !profile.methods.contains(selected_method)
    {
        return Err(SatsPathError::ValidationError(
            "quote no longer matches the current recipient profile".into(),
        ));
    }
    verify_handoff_transparency(trust, transparency, &log, checkpoint, latest)?;
    Ok(())
}
