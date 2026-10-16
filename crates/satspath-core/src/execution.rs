use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::pointer::BitcoinNetwork;
use crate::{Result, SatsPathError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionMode {
    /// Local/mock preview only.
    Preview,
    /// Real mainnet public data is allowed, but execution is not.
    MainnetPreview,
    /// Testnet-only experimental swap/Ark intent gates.
    TestnetExperimental,
    /// Manual execution by the user via a third-party wallet.
    ManualWallet,
}

/// A receipt for an executed Lightning payment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PaymentReceipt {
    pub payment_hash: String,
    pub preimage: Option<String>,
    pub amount_msats: u64,
    pub fee_msats: u64,
    pub timestamp: i64,
}

/// A receipt for an executed on-chain Bitcoin transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OnchainReceipt {
    pub txid: String,
    pub amount_sats: u64,
    pub fee_sats: u64,
    pub destination: String,
    pub timestamp: i64,
}

/// Confirmation gates for payment execution safety, especially on Mainnet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecutionGatePolicy {
    pub mainnet_enabled: bool,
    pub max_mainnet_payment_sats: u64,
    pub require_manual_confirmation: bool,
    pub allow_testnet_execution: bool,
}

impl Default for ExecutionGatePolicy {
    fn default() -> Self {
        Self {
            mainnet_enabled: false,
            max_mainnet_payment_sats: 1000,
            require_manual_confirmation: true,
            allow_testnet_execution: true,
        }
    }
}

impl ExecutionGatePolicy {
    pub fn testnet_default() -> Self {
        Self {
            mainnet_enabled: false,
            max_mainnet_payment_sats: 1000,
            require_manual_confirmation: false,
            allow_testnet_execution: true,
        }
    }

    pub fn mainnet_guarded(max_sats: u64, require_confirmation: bool) -> Self {
        Self {
            mainnet_enabled: true,
            max_mainnet_payment_sats: max_sats,
            require_manual_confirmation: require_confirmation,
            allow_testnet_execution: true,
        }
    }

    /// Evaluates if the payment execution passes safety gates.
    pub fn check_execution_safety(
        &self,
        network: BitcoinNetwork,
        amount_sats: u64,
        user_confirmed: bool,
    ) -> Result<()> {
        match network {
            BitcoinNetwork::Mainnet => {
                if !self.mainnet_enabled {
                    return Err(SatsPathError::ValidationError(
                        "Mainnet execution is disabled by policy. Preview mode only.".into(),
                    ));
                }
                if amount_sats > self.max_mainnet_payment_sats {
                    return Err(SatsPathError::ValidationError(format!(
                        "Payment of {} sats exceeds max allowed mainnet limit of {} sats",
                        amount_sats, self.max_mainnet_payment_sats
                    )));
                }
                if self.require_manual_confirmation && !user_confirmed {
                    return Err(SatsPathError::ValidationError(
                        "Mainnet payment execution requires explicit user confirmation".into(),
                    ));
                }
                Ok(())
            }
            BitcoinNetwork::Testnet | BitcoinNetwork::Regtest | BitcoinNetwork::Signet => {
                if !self.allow_testnet_execution {
                    return Err(SatsPathError::ValidationError(
                        "Testnet execution disabled by policy".into(),
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Non-custodial host wallet interface for executing payments.
///
/// Invariants:
/// - SatsPath MUST NOT store spending keys.
/// - All execution goes through the host wallet (e.g. LDK, BDK, Breez, Core Lightning).
#[async_trait]
pub trait WalletExecutor: Send + Sync {
    /// Return the Bitcoin network the host wallet is configured for.
    fn network(&self) -> BitcoinNetwork;

    /// Pay a BOLT11 invoice via the host wallet's Lightning node.
    async fn pay_bolt11(&self, invoice: &str, amount_msats: Option<u64>) -> Result<PaymentReceipt>;

    /// Send an on-chain transaction from the host wallet.
    async fn send_onchain(
        &self,
        destination_address: &str,
        amount_sats: u64,
        fee_rate_sat_vb: Option<u64>,
    ) -> Result<OnchainReceipt>;

    /// Sign and broadcast an on-chain PSBT (partially signed bitcoin transaction), returning the txid.
    async fn sign_and_broadcast_psbt(&self, psbt_base64: &str) -> Result<String>;
}

/// Reference in-memory mock wallet executor for testnet/regtest test suites and simulations.
pub struct MockWalletExecutor {
    pub network: BitcoinNetwork,
    pub simulated_fee_msats: u64,
    pub simulated_onchain_fee_sats: u64,
}

impl MockWalletExecutor {
    pub fn new(network: BitcoinNetwork) -> Self {
        Self {
            network,
            simulated_fee_msats: 1000,
            simulated_onchain_fee_sats: 250,
        }
    }
}

#[async_trait]
impl WalletExecutor for MockWalletExecutor {
    fn network(&self) -> BitcoinNetwork {
        self.network
    }

    async fn pay_bolt11(&self, invoice: &str, amount_msats: Option<u64>) -> Result<PaymentReceipt> {
        if invoice.is_empty() {
            return Err(SatsPathError::ValidationError("Empty invoice".into()));
        }
        let now = chrono::Utc::now().timestamp();
        use sha2::{Digest, Sha256};
        let hash = hex::encode(Sha256::digest(invoice.as_bytes()));
        let preimage = hex::encode(Sha256::digest(hash.as_bytes()));

        Ok(PaymentReceipt {
            payment_hash: hash,
            preimage: Some(preimage),
            amount_msats: amount_msats.unwrap_or(10_000),
            fee_msats: self.simulated_fee_msats,
            timestamp: now,
        })
    }

    async fn send_onchain(
        &self,
        destination_address: &str,
        amount_sats: u64,
        _fee_rate_sat_vb: Option<u64>,
    ) -> Result<OnchainReceipt> {
        if destination_address.is_empty() {
            return Err(SatsPathError::ValidationError(
                "Empty destination address".into(),
            ));
        }
        let now = chrono::Utc::now().timestamp();
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(destination_address.as_bytes());
        hasher.update(amount_sats.to_be_bytes());
        hasher.update(now.to_be_bytes());
        let txid = hex::encode(hasher.finalize());

        Ok(OnchainReceipt {
            txid,
            amount_sats,
            fee_sats: self.simulated_onchain_fee_sats,
            destination: destination_address.to_string(),
            timestamp: now,
        })
    }

    async fn sign_and_broadcast_psbt(&self, psbt_base64: &str) -> Result<String> {
        if psbt_base64.is_empty() {
            return Err(SatsPathError::ValidationError("Empty PSBT".into()));
        }
        use sha2::{Digest, Sha256};
        let txid = hex::encode(Sha256::digest(psbt_base64.as_bytes()));
        Ok(txid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_mock_wallet_executor_lightning_and_onchain() {
        let executor = MockWalletExecutor::new(BitcoinNetwork::Testnet);
        assert_eq!(executor.network(), BitcoinNetwork::Testnet);

        let bolt11_receipt = executor
            .pay_bolt11("lntb10u1p3...", Some(50_000))
            .await
            .expect("pay bolt11");
        assert_eq!(bolt11_receipt.amount_msats, 50_000);
        assert_eq!(bolt11_receipt.fee_msats, 1000);
        assert!(bolt11_receipt.preimage.is_some());

        let onchain_receipt = executor
            .send_onchain(
                "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
                15_000,
                Some(5),
            )
            .await
            .expect("send onchain");
        assert_eq!(onchain_receipt.amount_sats, 15_000);
        assert_eq!(onchain_receipt.fee_sats, 250);
        assert_eq!(onchain_receipt.txid.len(), 64);

        let psbt_txid = executor
            .sign_and_broadcast_psbt("cHNidP8BAFICAAAA...")
            .await
            .expect("sign and broadcast psbt");
        assert_eq!(psbt_txid.len(), 64);
    }

    #[test]
    fn test_execution_gate_policy_mainnet_vs_testnet() {
        let default_gate = ExecutionGatePolicy::default();

        // Testnet execution passes
        assert!(default_gate
            .check_execution_safety(BitcoinNetwork::Testnet, 50_000, false)
            .is_ok());

        // Mainnet blocked by default
        let err_mainnet = default_gate
            .check_execution_safety(BitcoinNetwork::Mainnet, 500, false)
            .unwrap_err();
        assert!(err_mainnet.to_string().contains("disabled by policy"));

        // Mainnet enabled with limits and confirmation
        let mainnet_gate = ExecutionGatePolicy::mainnet_guarded(1000, true);

        // Exceeding amount limit is rejected
        let err_exceed = mainnet_gate
            .check_execution_safety(BitcoinNetwork::Mainnet, 1500, true)
            .unwrap_err();
        assert!(err_exceed
            .to_string()
            .contains("exceeds max allowed mainnet limit"));

        // Missing confirmation is rejected
        let err_unconfirmed = mainnet_gate
            .check_execution_safety(BitcoinNetwork::Mainnet, 500, false)
            .unwrap_err();
        assert!(err_unconfirmed
            .to_string()
            .contains("requires explicit user confirmation"));

        // Valid confirmed mainnet payment within limits passes
        assert!(mainnet_gate
            .check_execution_safety(BitcoinNetwork::Mainnet, 500, true)
            .is_ok());
    }
}
