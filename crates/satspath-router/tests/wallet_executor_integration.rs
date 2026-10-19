//! End-to-end integration tests for the standardized `WalletExecutor` SDK interface and
//! non-custodial host wallet bridges (BDK on-chain, LDK Lightning, and Boltz Testnet Swaps)
//! per Issue #156.

use std::str::FromStr;

use anyhow::Result;
use async_trait::async_trait;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::psbt::Psbt;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::Address;
use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
use satspath_core::crypto::{generate_identity_keypair, sign_profile};
use satspath_core::execution::{
    ExecutionGatePolicy, OnchainReceipt, PaymentReceipt, WalletExecutor,
};
use satspath_core::pointer::BitcoinNetwork;
use satspath_core::profile::{PaymentMethod, PaymentProfile};
use satspath_core::resolver::{ProfileResolver, ResolverSource};
use satspath_core::transparency::{
    profile_hash, NameAction, NameEvent, TransactionalTransparencyStore,
};
use satspath_core::{IdentityKeypair, SignedPaymentProfile};
use satspath_router::quote_response::{
    build_qr_payload, quote_with_resolver, QuoteRecipient, QuoteResponse,
};
use satspath_router::wallet_executor::{
    execute_quote_handoff as execute_approved_handoff, prepare_payment_intent, BdkHostWallet,
    BdkOnchainBridge, BdkUtxoDescriptor, BoltzHostSignerBroadcaster, BoltzSwapEvidence,
    BoltzTestnetSwapBridge, HandoffExecutionReceipt, HandoffTransparencyEvidence, HandoffTrust,
    HostWalletSdkBridge, LdkHostNode, LdkLightningBridge,
};
use sha2::{Digest, Sha256};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

// ─── Simulated Sovereign BDK Host Wallet ────────────────────────────────────────

struct SimulatedBdkWallet {
    change_address: String,
    utxo: BdkUtxoDescriptor,
}

impl SimulatedBdkWallet {
    /// Supply one public Testnet UTXO and a change address.
    fn new_testnet() -> Self {
        let addr_str = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
        let addr = Address::from_str(addr_str).unwrap().assume_checked();
        Self {
            change_address: addr_str.to_string(),
            utxo: BdkUtxoDescriptor {
                txid: "11".repeat(32),
                vout: 0,
                amount_sats: 500_000,
                script_pubkey_hex: hex::encode(addr.script_pubkey().as_bytes()),
            },
        }
    }
}

#[async_trait]
impl BdkHostWallet for SimulatedBdkWallet {
    /// Return the fixed public funding UTXO.
    async fn select_utxos_and_change(
        &self,
        _target_sats: u64,
        _fee_rate_sat_vb: u64,
    ) -> Result<(Vec<BdkUtxoDescriptor>, String)> {
        Ok((vec![self.utxo.clone()], self.change_address.clone()))
    }

    /// Inspect the unsigned PSBT and return a synthetic transaction ID for this test.
    async fn sign_and_broadcast_psbt(&self, unsigned_psbt_hex: &str) -> Result<String> {
        // Verify valid PSBT deserialization and witness_utxo presence
        let psbt_bytes = hex::decode(unsigned_psbt_hex)?;
        let psbt = Psbt::deserialize(&psbt_bytes)?;
        assert_eq!(psbt.inputs.len(), 1);
        assert!(psbt.inputs[0].witness_utxo.is_some());
        assert!(!psbt.unsigned_tx.output.is_empty());

        let txid = psbt.unsigned_tx.compute_txid().to_string();
        Ok(txid)
    }
}

// ─── Simulated Sovereign LDK Host Node ──────────────────────────────────────────

struct SimulatedLdkNode;

#[async_trait]
impl LdkHostNode for SimulatedLdkNode {
    /// Return a synthetic payment receipt after host dispatch.
    async fn send_bolt11_payment(
        &self,
        bolt11_invoice: &str,
        expected_amount_msats: u64,
        max_fee_msats: u64,
    ) -> Result<PaymentReceipt> {
        assert!(max_fee_msats >= 1_000);
        let payment_hash = lightning_invoice::Bolt11Invoice::from_str(bolt11_invoice)?
            .payment_hash()
            .to_string();
        let preimage = hex::encode(Sha256::digest(payment_hash.as_bytes()));
        Ok(PaymentReceipt {
            payment_hash,
            preimage: Some(preimage),
            amount_msats: expected_amount_msats,
            fee_msats: 250,
            timestamp: 1_700_000_000,
        })
    }
}

struct FeeCapLdkNode {
    last_cap: Arc<AtomicU64>,
}

#[async_trait]
impl LdkHostNode for FeeCapLdkNode {
    async fn send_bolt11_payment(
        &self,
        invoice: &str,
        amount_msats: u64,
        max_fee_msats: u64,
    ) -> Result<PaymentReceipt> {
        self.last_cap.store(max_fee_msats, Ordering::SeqCst);
        Ok(PaymentReceipt {
            payment_hash: lightning_invoice::Bolt11Invoice::from_str(invoice)?
                .payment_hash()
                .to_string(),
            preimage: None,
            amount_msats,
            fee_msats: 0,
            timestamp: 1_700_000_000,
        })
    }
}

// ─── Simulated Sovereign Boltz Swap Signer & Broadcaster ────────────────────────

struct RejectBoltzHostCalls;

#[async_trait]
impl BoltzHostSignerBroadcaster for RejectBoltzHostCalls {
    /// Fail the test if disabled swap execution ever requests a signature.
    async fn sign_swap_digest(&self, _swap_id: &str, _sighash: [u8; 32]) -> Result<Vec<u8>> {
        panic!("disabled swap execution must never sign");
    }

    /// Fail the test if disabled swap execution ever requests a broadcast.
    async fn broadcast_swap_tx(&self, _raw_tx_hex: &str) -> Result<String> {
        panic!("disabled swap execution must never broadcast");
    }
}

// ─── Mock Profile Resolver ──────────────────────────────────────────────────────

struct StaticProfileResolver {
    signed: SignedPaymentProfile,
}

#[async_trait]
impl ProfileResolver for StaticProfileResolver {
    /// Resolve only the fixture alias.
    async fn resolve_alias(&self, alias: &str) -> satspath_core::Result<SignedPaymentProfile> {
        if alias == self.signed.profile.alias {
            Ok(self.signed.clone())
        } else {
            Err(satspath_core::SatsPathError::AliasNotFound(alias.into()))
        }
    }
}

/// Build a valid signed Testnet BOLT11 invoice for `amount_sats`.
fn make_testnet_bolt11(amount_sats: u64) -> String {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x33; 32]).unwrap();
    let payment_hash = sha256::Hash::from_slice(&[0x55; 32]).unwrap();
    let payment_secret = PaymentSecret([0x77; 32]);

    let invoice = InvoiceBuilder::new(Currency::BitcoinTestnet)
        .description("Testnet Coffee".into())
        .payment_hash(payment_hash)
        .payment_secret(payment_secret)
        .amount_milli_satoshis(amount_sats * 1_000)
        .current_timestamp()
        .min_final_cltv_expiry_delta(144)
        .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &sk))
        .unwrap();
    invoice.to_string()
}

/// Resolve a quote and execute its current, transparency-bound on-chain method.
#[tokio::test]
async fn test_end_to_end_alias_resolution_to_bdk_onchain_execution() {
    let kp = generate_identity_keypair();
    let recipient_addr = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    let profile = PaymentProfile {
        alias: "merchant@satspath.dev".to_string(),
        identity_pubkey: hex::encode(kp.public_key.serialize()),
        methods: vec![PaymentMethod::Onchain {
            label: "Testnet Vault".into(),
            network: BitcoinNetwork::Testnet,
            address: Some(recipient_addr.to_string()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: Vec::new(),
        }],
        updated_at: 1_700_000_000,
        expires_at: None,
        sequence: Some(0),
        preferences: Vec::new(),
        nonce: None,
        rotation: None,
        method_verifications: Vec::new(),
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
        recovery_policy: None,
        recovery: None,
    };
    let signed = sign_profile(profile, &kp.secret_key).unwrap();
    let home = tempfile::tempdir().unwrap();
    let store = TransactionalTransparencyStore::open(home.path()).unwrap();
    commit_profile(&store, &signed, &kp, NameAction::Register);
    let resolver = StaticProfileResolver { signed };

    // 1. Resolve alias and generate QuoteResponse handoff
    let quote_resp = quote_with_resolver(&resolver, "merchant@satspath.dev", 120_000).await;

    // 2. Execute handoff via HostWalletSdkBridge (BDK + LDK)
    let bdk = BdkOnchainBridge::new(
        BitcoinNetwork::Testnet,
        5,
        100,
        SimulatedBdkWallet::new_testnet(),
    );
    let ldk = LdkLightningBridge::new(BitcoinNetwork::Testnet, 100, SimulatedLdkNode);
    let sdk_bridge = HostWalletSdkBridge::new(BitcoinNetwork::Testnet, bdk, ldk);

    let receipt = execute_quote_handoff(
        &sdk_bridge,
        &store,
        &quote_resp,
        120_000,
        &ExecutionGatePolicy::testnet_default(),
        true,
    )
    .await
    .expect("BDK on-chain execution must succeed");

    match receipt {
        HandoffExecutionReceipt::Onchain(onchain) => {
            assert_eq!(onchain.amount_sats, 120_000);
            assert_eq!(onchain.destination, recipient_addr);
            assert_eq!(onchain.txid.len(), 64);
            assert_eq!(onchain.fee_sats, 5 * 141);
        }
        other => panic!("expected Onchain receipt, got {other:?}"),
    }
}

/// Validate the exact invoice amount before LDK host dispatch.
#[tokio::test]
async fn test_ldk_lightning_bridge_validates_and_executes_bolt11() {
    let invoice_str = make_testnet_bolt11(25_000);
    let bdk = BdkOnchainBridge::new(
        BitcoinNetwork::Testnet,
        5,
        100,
        SimulatedBdkWallet::new_testnet(),
    );
    let ldk = LdkLightningBridge::new(BitcoinNetwork::Testnet, 100, SimulatedLdkNode);
    let sdk_bridge = HostWalletSdkBridge::new(BitcoinNetwork::Testnet, bdk, ldk);

    // 1. Exact amount match succeeds
    let receipt = sdk_bridge
        .ldk()
        .validate_and_pay_bolt11(&invoice_str, 25_000)
        .await
        .expect("valid testnet BOLT11 must execute");
    assert_eq!(receipt.amount_msats, 25_000_000);
    assert!(receipt.preimage.is_some());

    // 2. Amount mismatch is rejected before calling host LDK node
    let err_amt = sdk_bridge
        .ldk()
        .validate_and_pay_bolt11(&invoice_str, 30_000)
        .await
        .unwrap_err();
    assert!(err_amt.to_string().contains("BOLT11 validation failed"));
}

/// Isolate unsupported scripts from missing evidence and disabled Mainnet execution.
#[tokio::test]
async fn boltz_unsupported_scripts_and_missing_evidence_fail_closed() {
    let preimage = [0x99; 32];
    let mut formerly_accepted_script = vec![0x82, 0x01, 0x20, 0x87, 0x63, 0xa8, 0x20];
    formerly_accepted_script.extend_from_slice(&Sha256::digest(preimage));
    formerly_accepted_script.push(0x88);
    for network in [BitcoinNetwork::Testnet, BitcoinNetwork::Regtest] {
        for reverse in [true, false] {
            let (mut host, _) = swap_fixture(reverse);
            host.evidence.network = network;
            let txid = host.evidence.lockup_transaction.compute_txid().to_string();
            let destination = host.evidence.destination_address.clone();
            let signs = host.signs.clone();
            let broadcasts = host.broadcasts.clone();
            let bridge = BoltzTestnetSwapBridge::new(network, host);
            for script in [
                hex::encode(&formerly_accepted_script),
                "51".into(),
                "5120".to_owned() + &"11".repeat(32),
                String::new(),
            ] {
                let result = if reverse {
                    bridge
                        .execute_reverse_claim(
                            "swap",
                            &txid,
                            0,
                            50_000,
                            &hex::encode(preimage),
                            &script,
                            &destination,
                            500,
                        )
                        .await
                } else {
                    bridge
                        .execute_submarine_refund(
                            "swap",
                            &txid,
                            0,
                            50_000,
                            800_000,
                            800_000,
                            &script,
                            &destination,
                            500,
                        )
                        .await
                };
                assert!(result
                    .unwrap_err()
                    .to_string()
                    .contains("witness script or lockup evidence mismatch"));
            }
            assert_eq!(signs.load(Ordering::SeqCst), 0);
            assert_eq!(broadcasts.load(Ordering::SeqCst), 0);
        }
    }

    for network in [
        BitcoinNetwork::Mainnet,
        BitcoinNetwork::Testnet,
        BitcoinNetwork::Regtest,
    ] {
        let bridge = BoltzTestnetSwapBridge::new(network, RejectBoltzHostCalls);
        for reverse in [true, false] {
            let (host, script) = swap_fixture(reverse);
            let txid = host.evidence.lockup_transaction.compute_txid().to_string();
            let destination = &host.evidence.destination_address;
            let result = if reverse {
                bridge
                    .execute_reverse_claim(
                        "swap",
                        &txid,
                        0,
                        50_000,
                        &hex::encode(preimage),
                        &script,
                        destination,
                        500,
                    )
                    .await
            } else {
                bridge
                    .execute_submarine_refund(
                        "swap",
                        &txid,
                        0,
                        50_000,
                        800_000,
                        800_000,
                        &script,
                        destination,
                        500,
                    )
                    .await
            };
            let expected = if network == BitcoinNetwork::Mainnet {
                "Mainnet execution is disabled"
            } else {
                "lockup evidence: verified swap evidence unavailable"
            };
            assert!(result.unwrap_err().to_string().contains(expected));
        }
    }
}

/// Build signed invoices, including expired or amountless adversarial fixtures.
fn make_invoice(currency: Currency, amount_msats: Option<u64>, expired: bool) -> String {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[0x33; 32]).unwrap();
    let builder = InvoiceBuilder::new(currency)
        .description("wallet handoff regression".into())
        .payment_hash(sha256::Hash::hash(&[0x55; 32]))
        .payment_secret(PaymentSecret([0x77; 32]))
        .min_final_cltv_expiry_delta(144);
    let builder = match amount_msats {
        Some(amount) => builder.amount_milli_satoshis(amount),
        None => builder,
    };
    let builder = if expired {
        builder
            .timestamp(SystemTime::now() - Duration::from_secs(3600))
            .expiry_time(Duration::from_secs(1))
    } else {
        builder.current_timestamp()
    };
    builder
        .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &sk))
        .unwrap()
        .to_string()
}

/// Commit a real signed event and checkpoint for the supplied test profile.
fn commit_profile(
    store: &TransactionalTransparencyStore,
    signed: &SignedPaymentProfile,
    identity: &IdentityKeypair,
    action: NameAction,
) {
    let log = store.load_log().unwrap();
    let identifier = satspath_core::identifier_hash(&signed.profile.alias);
    let previous = log
        .history(&identifier)
        .last()
        .map(|event| event.event_hash().unwrap());
    let mut event = NameEvent {
        version: 1,
        identifier_hash: identifier,
        action,
        identity_pubkey: signed.profile.identity_pubkey.clone(),
        profile_hash: profile_hash(signed).unwrap(),
        sequence: signed.profile.sequence.unwrap(),
        previous_event_hash: previous,
        created_at: chrono::Utc::now().timestamp(),
        identifier_attestation_hash: None,
        removed_method_hashes: vec![],
        rotation: signed.profile.rotation.clone(),
        recovery_policy: signed.profile.recovery_policy.clone(),
        recovery: signed.profile.recovery.clone(),
        owner_signature: String::new(),
    };
    event.sign(&identity.secret_key).unwrap();
    let operator = SecretKey::from_slice(&[0x66; 32]).unwrap();
    let checkpoint = log
        .prepare_append(event.clone(), signed)
        .unwrap()
        .prepare_checkpoint(&operator)
        .unwrap();
    store
        .commit_profile_event_checkpoint(&signed.profile.alias, signed, &event, &checkpoint)
        .unwrap();
}

/// Create a signed profile binding an invoice and the Lightning node's public key.
fn signed_lightning_profile(identity: &IdentityKeypair, invoice: &str) -> SignedPaymentProfile {
    let payee = lightning_invoice::Bolt11Invoice::from_str(invoice)
        .unwrap()
        .recover_payee_pub_key()
        .to_string();
    sign_profile(
        PaymentProfile {
            alias: "merchant@satspath.dev".into(),
            identity_pubkey: hex::encode(identity.public_key.serialize()),
            methods: vec![PaymentMethod::Lightning {
                label: "Test node".into(),
                lightning_address: Some(invoice.into()),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: Some(payee),
            }],
            updated_at: chrono::Utc::now().timestamp(),
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
        },
        &identity.secret_key,
    )
    .unwrap()
}

/// Build the public handoff representation for an authenticated fixture profile.
fn quote_for(signed: &SignedPaymentProfile, amount_sats: u64) -> QuoteResponse {
    let method = signed.profile.methods[0].clone();
    let qr = match &method {
        PaymentMethod::Lightning {
            lightning_address, ..
        } => lightning_address.clone().unwrap_or_default(),
        _ => build_qr_payload(&method, amount_sats).unwrap(),
    };
    QuoteResponse::Ok {
        recipient: QuoteRecipient {
            alias: signed.profile.alias.clone(),
            verified: true,
            profile_signature_verified: true,
            identifier_verified: false,
            identifier_verification: "test".into(),
            fingerprint: Some(
                satspath_core::crypto::fingerprint_pubkey(&signed.profile.identity_pubkey).unwrap(),
            ),
        },
        qr,
        selected_method: method,
        fee_sats: None,
        eta: None,
        reason: "fixture".into(),
        execution: None,
        wallet_hint: None,
    }
}

/// Deliberately permissive executor used to prove the dispatcher validates first.
struct CountingExecutor {
    network: BitcoinNetwork,
    calls: AtomicUsize,
}

#[async_trait]
impl WalletExecutor for CountingExecutor {
    /// Return the network under test.
    fn network(&self) -> BitcoinNetwork {
        self.network
    }

    /// Accept any invoice to detect dispatcher validation bypasses.
    async fn pay_bolt11(
        &self,
        invoice: &str,
        amount_msats: Option<u64>,
    ) -> satspath_core::Result<PaymentReceipt> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(PaymentReceipt {
            payment_hash: lightning_invoice::Bolt11Invoice::from_str(invoice)
                .map_err(|e| satspath_core::SatsPathError::ValidationError(e.to_string()))?
                .payment_hash()
                .to_string(),
            preimage: None,
            amount_msats: amount_msats.unwrap_or(0),
            fee_msats: 0,
            timestamp: 0,
        })
    }

    /// Count an on-chain dispatch without touching a network.
    async fn send_onchain(
        &self,
        destination: &str,
        amount_sats: u64,
        _fee_rate: Option<u64>,
    ) -> satspath_core::Result<OnchainReceipt> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        Ok(OnchainReceipt {
            txid: "11".repeat(32),
            amount_sats,
            fee_sats: 0,
            destination: destination.into(),
            timestamp: 0,
        })
    }

    /// Reject unexpected PSBT calls from dispatcher tests.
    async fn sign_and_broadcast_psbt(&self, _psbt: &str) -> satspath_core::Result<String> {
        panic!("unexpected PSBT dispatch")
    }

    async fn send_onchain_with_max_fee(
        &self,
        destination: &str,
        amount_sats: u64,
        max_fee_sats: u64,
    ) -> satspath_core::Result<OnchainReceipt> {
        assert!(max_fee_sats > 0);
        self.send_onchain(destination, amount_sats, None).await
    }

    async fn pay_bolt11_with_max_fee(
        &self,
        invoice: &str,
        amount_msats: u64,
        max_fee_msats: u64,
    ) -> satspath_core::Result<PaymentReceipt> {
        assert!(max_fee_msats > 0);
        self.pay_bolt11(invoice, Some(amount_msats)).await
    }
}

/// Accept exactly the matching BOLT11 network and reject all other currencies at both boundaries.
#[tokio::test]
async fn bolt11_networks_are_exact_in_bridge_and_dispatcher() {
    for (network, currency) in [
        (BitcoinNetwork::Mainnet, Currency::Bitcoin),
        (BitcoinNetwork::Testnet, Currency::BitcoinTestnet),
        (BitcoinNetwork::Regtest, Currency::Regtest),
    ] {
        for invoice_currency in [
            Currency::Bitcoin,
            Currency::BitcoinTestnet,
            Currency::Regtest,
            Currency::Signet,
            Currency::Simnet,
        ] {
            let invoice = make_invoice(invoice_currency.clone(), Some(1_000), false);
            let bridge = LdkLightningBridge::new(network, 100, SimulatedLdkNode);
            let should_pass = currency == invoice_currency;
            assert_eq!(
                bridge.validate_and_pay_bolt11(&invoice, 1).await.is_ok(),
                should_pass
            );
            let identity = generate_identity_keypair();
            let signed = signed_lightning_profile(&identity, &invoice);
            let home = tempfile::tempdir().unwrap();
            let store = TransactionalTransparencyStore::open(home.path()).unwrap();
            commit_profile(&store, &signed, &identity, NameAction::Register);
            let executor = CountingExecutor {
                network,
                calls: AtomicUsize::new(0),
            };
            let result = execute_quote_handoff(
                &executor,
                &store,
                &quote_for(&signed, 1),
                1,
                &ExecutionGatePolicy::mainnet_guarded(1, true),
                true,
            )
            .await;
            assert_eq!(
                result.is_ok(),
                should_pass,
                "{network:?} / {invoice_currency:?}: {result:?}"
            );
            assert_eq!(
                executor.calls.load(Ordering::SeqCst),
                usize::from(should_pass)
            );
        }
    }
}

/// Reject malformed, expired, amountless, fractional, zero and overflowing invoices before execution.
#[tokio::test]
async fn dispatcher_and_bridge_reject_invalid_bolt11_amounts_and_payloads() {
    let good = make_testnet_bolt11(1);
    let identity = generate_identity_keypair();
    let signed = signed_lightning_profile(&identity, &good);
    let home = tempfile::tempdir().unwrap();
    let store = TransactionalTransparencyStore::open(home.path()).unwrap();
    commit_profile(&store, &signed, &identity, NameAction::Register);
    let executor = CountingExecutor {
        network: BitcoinNetwork::Testnet,
        calls: AtomicUsize::new(0),
    };
    let bridge = LdkLightningBridge::new(BitcoinNetwork::Testnet, 100, SimulatedLdkNode);
    let cases = [
        (invoice_with_invalid_signature(), 1),
        ("lntb1garbage".into(), 1),
        (make_invoice(Currency::BitcoinTestnet, Some(1_000), true), 1),
        (make_invoice(Currency::BitcoinTestnet, None, false), 1),
        (
            make_invoice(Currency::BitcoinTestnet, Some(1_001), false),
            1,
        ),
        (good.clone(), 2),
        (good.clone(), 0),
        (good, u64::MAX),
    ];
    for (invoice, amount) in cases {
        assert!(bridge
            .validate_and_pay_bolt11(&invoice, amount)
            .await
            .is_err());
        let mut quote = quote_for(&signed, amount);
        if let QuoteResponse::Ok { qr, .. } = &mut quote {
            *qr = invoice;
        }
        assert!(execute_quote_handoff(
            &executor,
            &store,
            &quote,
            amount,
            &ExecutionGatePolicy::testnet_default(),
            true
        )
        .await
        .is_err());
    }
    for scheme in [
        "lno1unsupported",
        "ark:unsupported",
        "sp1unsupported",
        "bitcoin:sp1unsupported",
    ] {
        let mut quote = quote_for(&signed, 1);
        if let QuoteResponse::Ok { qr, .. } = &mut quote {
            *qr = scheme.into();
        }
        assert!(execute_quote_handoff(
            &executor,
            &store,
            &quote,
            1,
            &ExecutionGatePolicy::testnet_default(),
            true
        )
        .await
        .is_err());
    }
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
}

/// Reject exact-msat inputs that would otherwise be truncated by the SDK adapter.
#[tokio::test]
async fn sdk_bridge_rejects_fractional_satoshis() {
    let sdk = HostWalletSdkBridge::new(
        BitcoinNetwork::Testnet,
        BdkOnchainBridge::new(
            BitcoinNetwork::Testnet,
            5,
            100,
            SimulatedBdkWallet::new_testnet(),
        ),
        LdkLightningBridge::new(BitcoinNetwork::Testnet, 100, SimulatedLdkNode),
    );
    let invoice = make_testnet_bolt11(1);
    for amount in [Some(1_001), Some(999), Some(0), None] {
        assert!(sdk.pay_bolt11(&invoice, amount).await.is_err());
    }
    assert_eq!(
        sdk.pay_bolt11(&invoice, Some(1_000))
            .await
            .unwrap()
            .amount_msats,
        1_000
    );
}

/// Reload state after quote creation and reject both revocations and replaced payment methods.
#[tokio::test]
async fn handoff_rejects_quotes_after_revocation_or_profile_update() {
    for action in [NameAction::Revoke, NameAction::UpdateProfile] {
        let invoice = make_testnet_bolt11(1_000);
        let identity = generate_identity_keypair();
        let signed = signed_lightning_profile(&identity, &invoice);
        let home = tempfile::tempdir().unwrap();
        let store = TransactionalTransparencyStore::open(home.path()).unwrap();
        commit_profile(&store, &signed, &identity, NameAction::Register);
        let quote = quote_for(&signed, 1_000);
        assert!(matches!(quote, QuoteResponse::Ok { .. }));
        let executor = CountingExecutor {
            network: BitcoinNetwork::Testnet,
            calls: AtomicUsize::new(0),
        };
        assert!(execute_quote_handoff(
            &executor,
            &store,
            &quote,
            1_000,
            &ExecutionGatePolicy::testnet_default(),
            true
        )
        .await
        .is_ok());
        executor.calls.store(0, Ordering::SeqCst);
        let mut updated = signed.profile.clone();
        updated.sequence = Some(1);
        if action == NameAction::Revoke {
            updated.revoked = true;
        } else {
            updated.methods.clear();
        }
        let updated = sign_profile(updated, &identity.secret_key).unwrap();
        commit_profile(&store, &updated, &identity, action);
        assert!(execute_quote_handoff(
            &executor,
            &store,
            &quote,
            1_000,
            &ExecutionGatePolicy::testnet_default(),
            true
        )
        .await
        .is_err());
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    }
}

/// A serialized signature flag and fingerprint cannot authorize a missing profile or changed payload.
#[tokio::test]
async fn handoff_rejects_missing_current_state_and_unbound_destinations() {
    let invoice = make_testnet_bolt11(1);
    let identity = generate_identity_keypair();
    let signed = signed_lightning_profile(&identity, &invoice);
    let home = tempfile::tempdir().unwrap();
    let store = TransactionalTransparencyStore::open(home.path()).unwrap();
    let executor = CountingExecutor {
        network: BitcoinNetwork::Testnet,
        calls: AtomicUsize::new(0),
    };
    let quote = quote_for(&signed, 1);
    assert!(execute_quote_handoff(
        &executor,
        &store,
        &quote,
        1,
        &ExecutionGatePolicy::testnet_default(),
        true
    )
    .await
    .is_err());
    commit_profile(&store, &signed, &identity, NameAction::Register);
    let mut changed = quote.clone();
    if let QuoteResponse::Ok { qr, .. } = &mut changed {
        *qr = "bitcoin:mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn?amount=0.00000001".into();
    }
    assert!(execute_quote_handoff(
        &executor,
        &store,
        &changed,
        1,
        &ExecutionGatePolicy::testnet_default(),
        true
    )
    .await
    .is_err());
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
}

/// Build a checksum-valid invoice signed by a different key than its explicit payee.
fn invoice_with_invalid_signature() -> String {
    let secp = Secp256k1::new();
    let signer = SecretKey::from_slice(&[0x33; 32]).unwrap();
    let wrong_payee = bitcoin::secp256k1::PublicKey::from_secret_key(
        &secp,
        &SecretKey::from_slice(&[0x22; 32]).unwrap(),
    );
    InvoiceBuilder::new(Currency::BitcoinTestnet)
        .description("invalid signature".into())
        .payment_hash(sha256::Hash::hash(&[0x55; 32]))
        .payment_secret(PaymentSecret([0x77; 32]))
        .amount_milli_satoshis(1_000)
        .current_timestamp()
        .min_final_cltv_expiry_delta(144)
        .payee_pub_key(wrong_payee)
        .build_raw()
        .unwrap()
        .sign(|hash| Ok::<_, ()>(secp.sign_ecdsa_recoverable(hash, &signer)))
        .unwrap()
        .to_string()
}

/// Reject a stale identity after an authorized rotation, even when its payment method is unchanged.
#[tokio::test]
async fn handoff_rejects_quote_after_identity_rotation() {
    let invoice = make_testnet_bolt11(1);
    let old = generate_identity_keypair();
    let new = generate_identity_keypair();
    let signed = signed_lightning_profile(&old, &invoice);
    let home = tempfile::tempdir().unwrap();
    let store = TransactionalTransparencyStore::open(home.path()).unwrap();
    commit_profile(&store, &signed, &old, NameAction::Register);
    let quote = quote_for(&signed, 1);
    let mut rotated = signed.profile.clone();
    rotated.sequence = Some(1);
    rotated.identity_pubkey = hex::encode(new.public_key.serialize());
    let log = store.load_log().unwrap();
    let previous = log.events().last().unwrap().event_hash().unwrap();
    rotated.rotation = Some(
        satspath_core::KeyRotation::create(
            satspath_core::identifier_hash(&rotated.alias),
            signed.profile.identity_pubkey.clone(),
            &old.secret_key,
            rotated.identity_pubkey.clone(),
            &new.secret_key,
            previous,
            1,
        )
        .unwrap(),
    );
    let rotated = sign_profile(rotated, &new.secret_key).unwrap();
    commit_profile(&store, &rotated, &old, NameAction::RotateKey);
    let executor = CountingExecutor {
        network: BitcoinNetwork::Testnet,
        calls: AtomicUsize::new(0),
    };
    assert!(execute_quote_handoff(
        &executor,
        &store,
        &quote,
        1,
        &ExecutionGatePolicy::testnet_default(),
        true
    )
    .await
    .is_err());
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);
    assert!(execute_quote_handoff(
        &executor,
        &store,
        &quote_for(&rotated, 1),
        1,
        &ExecutionGatePolicy::testnet_default(),
        true
    )
    .await
    .is_ok());
}

/// Bind fetched invoices to the signed payee key and reject an unrelated invoice signer.
#[tokio::test]
async fn fetched_invoice_requires_current_signed_payee_key() {
    let invoice = make_testnet_bolt11(1);
    let identity = generate_identity_keypair();
    for bind_payee in [false, true] {
        let mut profile = signed_lightning_profile(&identity, &invoice).profile;
        if let PaymentMethod::Lightning {
            lightning_address,
            receiver_pubkey,
            ..
        } = &mut profile.methods[0]
        {
            *lightning_address = Some("merchant@example.com".into());
            if !bind_payee {
                *receiver_pubkey = None;
            }
        }
        let signed = sign_profile(profile, &identity.secret_key).unwrap();
        let home = tempfile::tempdir().unwrap();
        let store = TransactionalTransparencyStore::open(home.path()).unwrap();
        commit_profile(&store, &signed, &identity, NameAction::Register);
        let mut quote = quote_for(&signed, 1);
        if let QuoteResponse::Ok { qr, .. } = &mut quote {
            *qr = invoice.clone();
        }
        let executor = CountingExecutor {
            network: BitcoinNetwork::Testnet,
            calls: AtomicUsize::new(0),
        };
        assert_eq!(
            execute_quote_handoff(
                &executor,
                &store,
                &quote,
                1,
                &ExecutionGatePolicy::testnet_default(),
                true
            )
            .await
            .is_ok(),
            bind_payee
        );
        assert_eq!(
            executor.calls.load(Ordering::SeqCst),
            usize::from(bind_payee)
        );
        if let QuoteResponse::Ok { qr, .. } = &mut quote {
            let raw = lightning_invoice::Bolt11Invoice::from_str(&invoice)
                .unwrap()
                .into_signed_raw()
                .raw_invoice()
                .clone();
            let other_key = SecretKey::from_slice(&[0x22; 32]).unwrap();
            *qr = raw
                .sign(|hash| Ok::<_, ()>(Secp256k1::new().sign_ecdsa_recoverable(hash, &other_key)))
                .unwrap()
                .to_string();
        }
        assert!(execute_quote_handoff(
            &executor,
            &store,
            &quote,
            1,
            &ExecutionGatePolicy::testnet_default(),
            true
        )
        .await
        .is_err());
        assert_eq!(
            executor.calls.load(Ordering::SeqCst),
            usize::from(bind_payee)
        );
    }
}

/// Supply real signed witness/gossip evidence for existing handoff regression tests.
fn transparency_fixture(
    store: &TransactionalTransparencyStore,
    alias: &str,
    pins_dir: &std::path::Path,
) -> satspath_core::Result<(HandoffTrust, HandoffTransparencyEvidence)> {
    use satspath_core::transparency::{CheckpointStore, GossipObservation, WitnessCosignature};
    let log = store.load_log()?;
    let cp = log.checkpoints().last().ok_or_else(|| {
        satspath_core::SatsPathError::ValidationError("missing checkpoint".into())
    })?;
    let pins = CheckpointStore::new(pins_dir);
    pins.pin_verified(cp)?;
    let mut signatures = vec![];
    let mut witnesses = vec![];
    for byte in [0x71, 0x72] {
        let key = SecretKey::from_slice(&[byte; 32]).unwrap();
        let pubkey =
            bitcoin::secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &key).to_string();
        let mut signature = WitnessCosignature {
            version: 1,
            witness_id: format!("witness-{byte}"),
            witness_pubkey: pubkey.clone(),
            checkpoint_hash: cp.checkpoint_hash()?,
            tree_size: cp.log_size,
            timestamp: chrono::Utc::now().timestamp(),
            signature: String::new(),
        };
        signature.signature =
            satspath_core::crypto::sign_message(&signature.signing_message(), &key);
        signatures.push(signature);
        witnesses.push(pubkey);
    }
    let observer = SecretKey::from_slice(&[0x73; 32]).unwrap();
    let gossip = GossipObservation::sign(cp.clone(), &observer, chrono::Utc::now().timestamp())?;
    Ok((
        HandoffTrust {
            checkpoints: std::sync::Mutex::new(pins),
            witness_quorum: 2,
            witness_pubkeys: witnesses,
            observer_pubkeys: vec![gossip.observer_pubkey.clone()],
        },
        HandoffTransparencyEvidence {
            current_state_proof: log.prove_state(&satspath_core::identifier_hash(alias))?,
            witness_cosignatures: signatures,
            gossip_observations: vec![gossip],
        },
    ))
}

async fn execute_quote_handoff(
    executor: &dyn WalletExecutor,
    store: &TransactionalTransparencyStore,
    quote: &QuoteResponse,
    amount: u64,
    policy: &ExecutionGatePolicy,
    confirmed: bool,
) -> satspath_core::Result<HandoffExecutionReceipt> {
    let QuoteResponse::Ok { recipient, .. } = quote else {
        return Err(satspath_core::SatsPathError::ValidationError(
            "invalid test quote".into(),
        ));
    };
    let dir = tempfile::tempdir().unwrap();
    let (trust, evidence) = transparency_fixture(store, &recipient.alias, dir.path())?;
    execute_with_evidence(
        executor, store, &trust, &evidence, quote, amount, policy, confirmed,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn execute_with_evidence(
    executor: &dyn WalletExecutor,
    store: &TransactionalTransparencyStore,
    trust: &HandoffTrust,
    evidence: &HandoffTransparencyEvidence,
    quote: &QuoteResponse,
    amount: u64,
    policy: &ExecutionGatePolicy,
    confirmed: bool,
) -> satspath_core::Result<HandoffExecutionReceipt> {
    let intent = prepare_payment_intent(
        store,
        trust,
        evidence,
        quote,
        executor.network(),
        amount,
        10_000,
        vec![ResolverSource::LocalRegistry],
    )?;
    let approved = intent.approve(confirmed)?;
    execute_approved_handoff(executor, store, trust, evidence, quote, approved, policy).await
}

/// Every transparency dimension must fail before dispatch; a complete 2-of-2 proof succeeds.
#[tokio::test]
async fn handoff_requires_state_quorum_gossip_and_persisted_checkpoint() {
    let identity = generate_identity_keypair();
    let signed = signed_lightning_profile(&identity, &make_testnet_bolt11(1_000));
    let home = tempfile::tempdir().unwrap();
    let store = TransactionalTransparencyStore::open(home.path()).unwrap();
    commit_profile(&store, &signed, &identity, NameAction::Register);
    let executor = CountingExecutor {
        network: BitcoinNetwork::Testnet,
        calls: AtomicUsize::new(0),
    };
    let quote = quote_for(&signed, 1_000);
    for case in 0..19 {
        let dir = tempfile::tempdir().unwrap();
        let (mut trust, mut evidence) =
            transparency_fixture(&store, &signed.profile.alias, dir.path()).unwrap();
        match case {
            0 => evidence.current_state_proof.audit_path.clear(),
            1 => evidence.current_state_proof.key_hash = "ff".repeat(32),
            2 => {
                evidence
                    .current_state_proof
                    .value
                    .as_mut()
                    .unwrap()
                    .latest_event_hash = "ff".repeat(32)
            }
            3 => evidence.current_state_proof.value = None,
            4 => evidence.witness_cosignatures.clear(),
            5 => evidence.witness_cosignatures[1] = evidence.witness_cosignatures[0].clone(),
            6 => evidence.witness_cosignatures[0].checkpoint_hash = "ff".repeat(32),
            7 => evidence.witness_cosignatures[0].tree_size += 1,
            8 => evidence.witness_cosignatures[0].signature = "00".repeat(64),
            9 => trust.witness_quorum = 0,
            10 => {
                trust.witness_pubkeys.remove(0);
            }
            11 => evidence.gossip_observations.clear(),
            12 => trust.observer_pubkeys.clear(),
            13 => {
                let cp = &mut evidence.gossip_observations[0].checkpoint;
                cp.map_root = Some("ff".repeat(32));
                cp.sign(&SecretKey::from_slice(&[0x66; 32]).unwrap())
                    .unwrap();
                evidence.gossip_observations[0] =
                    satspath_core::transparency::GossipObservation::sign(
                        cp.clone(),
                        &SecretKey::from_slice(&[0x73; 32]).unwrap(),
                        chrono::Utc::now().timestamp(),
                    )
                    .unwrap();
            }
            14 => {
                let mut cp = store
                    .load_log()
                    .unwrap()
                    .checkpoints()
                    .last()
                    .unwrap()
                    .clone();
                cp.log_size += 1;
                cp.sign(&SecretKey::from_slice(&[0x66; 32]).unwrap())
                    .unwrap();
                trust.checkpoints.lock().unwrap().pin_verified(&cp).unwrap();
            }
            15 => {
                let mut cp = store
                    .load_log()
                    .unwrap()
                    .checkpoints()
                    .last()
                    .unwrap()
                    .clone();
                cp.map_root = Some("ff".repeat(32));
                cp.sign(&SecretKey::from_slice(&[0x66; 32]).unwrap())
                    .unwrap();
                trust.checkpoints.lock().unwrap().pin_verified(&cp).unwrap();
            }
            16 => {
                std::fs::remove_file(dir.path().join("transparency-pins.json")).unwrap();
            }
            17 => {
                evidence.current_state_proof = store
                    .load_log()
                    .unwrap()
                    .prove_state(&satspath_core::identifier_hash("absent@example.com"))
                    .unwrap();
            }
            18 => {
                let key =
                    bitcoin::secp256k1::PublicKey::from_str(&trust.witness_pubkeys[0]).unwrap();
                trust.witness_pubkeys[1] = key.negate(&Secp256k1::new()).to_string();
            }
            _ => unreachable!(),
        };
        assert!(
            execute_with_evidence(
                &executor,
                &store,
                &trust,
                &evidence,
                &quote,
                1_000,
                &ExecutionGatePolicy::testnet_default(),
                true
            )
            .await
            .is_err(),
            "case {case}"
        );
        assert_eq!(executor.calls.load(Ordering::SeqCst), 0, "case {case}");
    }
    let dir = tempfile::tempdir().unwrap();
    let (mut trust, mut evidence) =
        transparency_fixture(&store, &signed.profile.alias, dir.path()).unwrap();
    // X-only and compressed public keys both identify BIP340 witnesses.
    let key = bitcoin::secp256k1::PublicKey::from_str(&trust.witness_pubkeys[0]).unwrap();
    trust.witness_pubkeys[0] = key.x_only_public_key().0.to_string();
    evidence.witness_cosignatures[0].witness_pubkey = trust.witness_pubkeys[0].clone();
    let previous_observation = evidence.gossip_observations[0].clone();
    execute_with_evidence(
        &executor,
        &store,
        &trust,
        &evidence,
        &quote,
        1_000,
        &ExecutionGatePolicy::testnet_default(),
        true,
    )
    .await
    .unwrap();
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    // A later profile/checkpoint must extend the persisted pin with an RFC6962 proof.
    let mut updated = signed.profile.clone();
    updated.sequence = Some(1);
    let updated = sign_profile(updated, &identity.secret_key).unwrap();
    commit_profile(&store, &updated, &identity, NameAction::UpdateProfile);
    let other = tempfile::tempdir().unwrap();
    let (_, mut evidence) =
        transparency_fixture(&store, &updated.profile.alias, other.path()).unwrap();
    evidence.witness_cosignatures[0].witness_pubkey = trust.witness_pubkeys[0].clone();
    evidence
        .gossip_observations
        .push(previous_observation.clone());
    // A consistent log-root extension must not hide a fork in the pinned map root.
    let mut fork = previous_observation.checkpoint.clone();
    fork.map_root = Some("ff".repeat(32));
    fork.sign(&SecretKey::from_slice(&[0x66; 32]).unwrap())
        .unwrap();
    trust
        .checkpoints
        .lock()
        .unwrap()
        .pin_verified(&fork)
        .unwrap();
    assert!(execute_with_evidence(
        &executor,
        &store,
        &trust,
        &evidence,
        &quote_for(&updated, 1_000),
        1_000,
        &ExecutionGatePolicy::testnet_default(),
        true
    )
    .await
    .is_err());
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
    trust
        .checkpoints
        .lock()
        .unwrap()
        .pin_verified(&previous_observation.checkpoint)
        .unwrap();
    execute_with_evidence(
        &executor,
        &store,
        &trust,
        &evidence,
        &quote_for(&updated, 1_000),
        1_000,
        &ExecutionGatePolicy::testnet_default(),
        true,
    )
    .await
    .unwrap();
    let reloaded = satspath_core::transparency::CheckpointStore::new(dir.path())
        .load()
        .unwrap();
    assert_eq!(reloaded[0].tree_size, 2);
}

struct SimulatedBoltzHost {
    evidence: BoltzSwapEvidence,
    key: SecretKey,
    signs: std::sync::Arc<AtomicUsize>,
    broadcasts: std::sync::Arc<AtomicUsize>,
    wrong_txid: bool,
}

#[async_trait]
impl BoltzHostSignerBroadcaster for SimulatedBoltzHost {
    async fn swap_evidence(&self, _: &str) -> Result<BoltzSwapEvidence> {
        Ok(self.evidence.clone())
    }
    async fn sign_swap_digest(&self, _: &str, digest: [u8; 32]) -> Result<Vec<u8>> {
        self.signs.fetch_add(1, Ordering::SeqCst);
        let sig = Secp256k1::new()
            .sign_ecdsa(&bitcoin::secp256k1::Message::from_digest(digest), &self.key);
        let mut bytes = sig.serialize_der().to_vec();
        bytes.push(1);
        Ok(bytes)
    }
    async fn broadcast_swap_tx(&self, raw: &str) -> Result<String> {
        let tx: bitcoin::Transaction = bitcoin::consensus::deserialize(&hex::decode(raw)?)?;
        assert_eq!(tx.input.len(), 1);
        assert_eq!(tx.output.len(), 1);
        assert_eq!(
            tx.input[0].sequence,
            bitcoin::Sequence::ENABLE_LOCKTIME_NO_RBF
        );
        let fee =
            self.evidence.lockup_transaction.output[0].value.to_sat() - tx.output[0].value.to_sat();
        assert!(fee >= tx.vsize() as u64);
        assert!(fee <= self.evidence.max_fee_sats);
        let stack: Vec<_> = tx.input[0].witness.iter().collect();
        assert_eq!(stack.len(), 3);
        let script = bitcoin::ScriptBuf::from_bytes(stack[2].to_vec());
        assert_eq!(
            script.to_p2wsh(),
            self.evidence.lockup_transaction.output[0].script_pubkey
        );
        let claim = !stack[1].is_empty();
        let key = if claim {
            assert_eq!(
                sha256::Hash::hash(stack[1]).to_byte_array(),
                self.evidence.payment_hash
            );
            assert_eq!(tx.lock_time, bitcoin::absolute::LockTime::ZERO);
            self.evidence.claim_pubkey
        } else {
            assert_eq!(
                tx.lock_time.to_consensus_u32(),
                self.evidence.timeout_block_height
            );
            self.evidence.refund_pubkey
        };
        let hash = bitcoin::sighash::SighashCache::new(&tx).p2wsh_signature_hash(
            0,
            &script,
            bitcoin::Amount::from_sat(50_000),
            bitcoin::sighash::EcdsaSighashType::All,
        )?;
        let sig = bitcoin::ecdsa::Signature::from_slice(stack[0])?;
        Secp256k1::new().verify_ecdsa(
            &bitcoin::secp256k1::Message::from_digest(hash.to_byte_array()),
            &sig.signature,
            &key.inner,
        )?;
        self.broadcasts.fetch_add(1, Ordering::SeqCst);
        Ok(if self.wrong_txid {
            "ff".repeat(32)
        } else {
            tx.compute_txid().to_string()
        })
    }
}

/// Independently encode the legacy Boltz scripts (800000 = 0x0c3500).
fn swap_fixture(reverse: bool) -> (SimulatedBoltzHost, String) {
    swap_fixture_with_hash(reverse, sha256::Hash::hash(&[0x99; 32]).to_byte_array())
}

fn swap_fixture_with_hash(reverse: bool, payment_hash: [u8; 32]) -> (SimulatedBoltzHost, String) {
    use bitcoin::hashes::ripemd160;
    let claim = SecretKey::from_slice(&[0x21; 32]).unwrap();
    let refund = SecretKey::from_slice(&[0x22; 32]).unwrap();
    let claim_pubkey = bitcoin::PublicKey::new(claim.public_key(&Secp256k1::new()));
    let refund_pubkey = bitcoin::PublicKey::new(refund.public_key(&Secp256k1::new()));
    let hash = ripemd160::Hash::hash(&payment_hash);
    let script_hex = if reverse {
        format!("8201208763a914{hash}8821{claim_pubkey}67750300350cb17521{refund_pubkey}68ac")
    } else {
        format!("a914{hash}876321{claim_pubkey}670300350cb17521{refund_pubkey}68ac")
    };
    let script = bitcoin::ScriptBuf::from_bytes(hex::decode(&script_hex).unwrap());
    let lockup_transaction = bitcoin::Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: bitcoin::Amount::from_sat(50_000),
            script_pubkey: script.to_p2wsh(),
        }],
    };
    (
        SimulatedBoltzHost {
            evidence: BoltzSwapEvidence {
                network: BitcoinNetwork::Testnet,
                lockup_transaction,
                lockup_vout: 0,
                confirmations: 1,
                unspent: true,
                current_block_height: 800_000,
                payment_hash,
                claim_pubkey,
                refund_pubkey,
                timeout_block_height: 800_000,
                destination_address: "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn".into(),
                max_fee_sats: 1_000,
            },
            key: if reverse { claim } else { refund },
            signs: Default::default(),
            broadcasts: Default::default(),
            wrong_txid: false,
        },
        script_hex,
    )
}

/// Valid testnet claim/refund paths use real BIP143 signatures; malformed inputs never sign.
#[tokio::test]
async fn boltz_testnet_claim_refund_validation_and_host_execution() {
    for reverse in [true, false] {
        for case in 0..18 {
            let (mut host, mut script) = swap_fixture(reverse);
            let mut txid = host.evidence.lockup_transaction.compute_txid().to_string();
            let mut network = BitcoinNetwork::Testnet;
            let mut destination = host.evidence.destination_address.clone();
            let mut amount = 50_000;
            let mut fee = 500;
            let mut preimage = hex::encode([0x99; 32]);
            let mut height = 800_000;
            match case {
                0 => {} // successful spend
                1 => network = BitcoinNetwork::Mainnet,
                2 => script.push_str("51"),
                3 => amount += 1,
                4 => destination = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT".into(),
                5 => fee = 10_001,
                6 => fee = 0,
                7 => host.evidence.unspent = false,
                8 => host.evidence.confirmations = 0,
                9 => {
                    host.evidence.lockup_transaction.output[0].value =
                        bitcoin::Amount::from_sat(50_001)
                }
                10 => {
                    host.evidence.lockup_transaction.output[0].script_pubkey =
                        bitcoin::ScriptBuf::new()
                }
                11 => {
                    preimage = hex::encode([0x88; 32]);
                    height -= 1;
                }
                12 => host.evidence.network = BitcoinNetwork::Regtest,
                13 => host.evidence.max_fee_sats = 499,
                14 => host.evidence.destination_address = "another destination".into(),
                15 => host.key = SecretKey::from_slice(&[0x23; 32]).unwrap(),
                16 => host.wrong_txid = true,
                17 => host.evidence.timeout_block_height += 1,
                _ => unreachable!(),
            }
            if matches!(case, 9 | 10) {
                txid = host.evidence.lockup_transaction.compute_txid().to_string();
            }
            let signs = host.signs.clone();
            let broadcasts = host.broadcasts.clone();
            let bridge = BoltzTestnetSwapBridge::new(network, host);
            let result = if reverse {
                bridge
                    .execute_reverse_claim(
                        "swap",
                        &txid,
                        0,
                        amount,
                        &preimage,
                        &script,
                        &destination,
                        fee,
                    )
                    .await
            } else {
                bridge
                    .execute_submarine_refund(
                        "swap",
                        &txid,
                        0,
                        amount,
                        800_000,
                        height,
                        &script,
                        &destination,
                        fee,
                    )
                    .await
            };
            if case == 2 {
                assert!(result
                    .as_ref()
                    .unwrap_err()
                    .to_string()
                    .contains("witness script or lockup evidence mismatch"));
            }
            assert_eq!(
                result.is_ok(),
                case == 0,
                "reverse={reverse} case={case}: {result:?}"
            );
            assert_eq!(
                signs.load(Ordering::SeqCst),
                usize::from(matches!(case, 0 | 15 | 16)),
                "case {case}"
            );
            assert_eq!(
                broadcasts.load(Ordering::SeqCst),
                usize::from(matches!(case, 0 | 16)),
                "case {case}"
            );
        }
    }
}

/// Price each spend's worst-case witness and destination before host signing.
#[tokio::test]
async fn boltz_minimum_relay_fee_is_checked_before_signing() {
    for network in [BitcoinNetwork::Testnet, BitcoinNetwork::Regtest] {
        let bitcoin_network = match network {
            BitcoinNetwork::Testnet => bitcoin::Network::Testnet,
            BitcoinNetwork::Regtest => bitcoin::Network::Regtest,
            _ => unreachable!(),
        };
        for reverse in [true, false] {
            // Independently calculated weights with a 73-byte signature element:
            // P2PKH: 557 WU claim / 520 WU refund; P2WSH: 593 / 556 WU.
            for (destination, minimum_fee) in [
                (
                    "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn".to_string(),
                    if reverse { 140 } else { 130 },
                ),
                (
                    Address::p2wsh(&bitcoin::ScriptBuf::new(), bitcoin_network).to_string(),
                    if reverse { 149 } else { 139 },
                ),
            ] {
                for fee in [1, minimum_fee - 1, minimum_fee] {
                    let (mut host, script) = swap_fixture(reverse);
                    host.evidence.network = network;
                    host.evidence.destination_address = destination.clone();
                    let txid = host.evidence.lockup_transaction.compute_txid().to_string();
                    let signs = host.signs.clone();
                    let broadcasts = host.broadcasts.clone();
                    let bridge = BoltzTestnetSwapBridge::new(network, host);
                    let result = if reverse {
                        bridge
                            .execute_reverse_claim(
                                "swap",
                                &txid,
                                0,
                                50_000,
                                &hex::encode([0x99; 32]),
                                &script,
                                &destination,
                                fee,
                            )
                            .await
                    } else {
                        bridge
                            .execute_submarine_refund(
                                "swap",
                                &txid,
                                0,
                                50_000,
                                800_000,
                                800_000,
                                &script,
                                &destination,
                                fee,
                            )
                            .await
                    };
                    if fee < minimum_fee {
                        assert!(result
                            .unwrap_err()
                            .to_string()
                            .contains(&format!("below the 1 sat/vB minimum ({minimum_fee} sats)")));
                    } else {
                        assert!(matches!(
                            result.unwrap(),
                            HandoffExecutionReceipt::SwapSettlement {
                                fee_sats, output_amount_sats, ..
                            } if fee_sats == fee && output_amount_sats == 50_000 - fee
                        ));
                    }
                    let expected_calls = usize::from(fee == minimum_fee);
                    assert_eq!(signs.load(Ordering::SeqCst), expected_calls);
                    assert_eq!(broadcasts.load(Ordering::SeqCst), expected_calls);
                }
            }
        }
    }
}

/// The empty refund selector must actually select CLTV, even for adversarial hash commitments.
#[tokio::test]
async fn boltz_refund_rejects_hash_that_selects_claim_branch() {
    let (host, script) = swap_fixture_with_hash(false, sha256::Hash::hash(&[]).to_byte_array());
    let txid = host.evidence.lockup_transaction.compute_txid().to_string();
    let destination = host.evidence.destination_address.clone();
    let signs = host.signs.clone();
    let bridge = BoltzTestnetSwapBridge::new(BitcoinNetwork::Testnet, host);
    let result = bridge
        .execute_submarine_refund(
            "swap",
            &txid,
            0,
            50_000,
            800_000,
            800_000,
            &script,
            &destination,
            500,
        )
        .await;
    assert!(result.unwrap_err().to_string().contains("claim branch"));
    assert_eq!(signs.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn approval_binds_amount_destination_fee_and_current_state() {
    let invoice = make_testnet_bolt11(1);
    let identity = generate_identity_keypair();
    let signed = signed_lightning_profile(&identity, &invoice);
    let home = tempfile::tempdir().unwrap();
    let store = TransactionalTransparencyStore::open(home.path()).unwrap();
    commit_profile(&store, &signed, &identity, NameAction::Register);
    let pins = tempfile::tempdir().unwrap();
    let (trust, evidence) =
        transparency_fixture(&store, &signed.profile.alias, pins.path()).unwrap();
    let quote = quote_for(&signed, 1);
    let executor = CountingExecutor {
        network: BitcoinNetwork::Testnet,
        calls: AtomicUsize::new(0),
    };
    let prepare = |quote: &QuoteResponse| {
        prepare_payment_intent(
            &store,
            &trust,
            &evidence,
            quote,
            BitcoinNetwork::Testnet,
            1,
            500,
            vec![ResolverSource::LocalRegistry],
        )
    };
    let intent = prepare(&quote).unwrap();
    assert_eq!(intent.amount_sats, 1);
    assert_eq!(intent.destination, invoice);
    assert!(intent.verification_status.transparency_verified);
    assert!(intent.clone().approve(false).is_err());
    let bytes = intent.canonical_bytes().unwrap();
    let mut tampered = intent.clone();
    tampered.amount_sats += 1;
    assert_ne!(tampered.canonical_bytes().unwrap(), bytes);
    tampered.max_fee_sats = (1 << 53) - 1;
    assert!(tampered.canonical_bytes().is_ok());
    tampered.max_fee_sats += 1;
    assert!(tampered.canonical_bytes().is_err());
    assert!(tampered.approve(true).is_err());
    assert!(prepare_payment_intent(
        &store,
        &trust,
        &evidence,
        &quote,
        BitcoinNetwork::Mainnet,
        1,
        500,
        vec![ResolverSource::LocalRegistry]
    )
    .is_err());
    assert!(prepare_payment_intent(
        &store,
        &trust,
        &evidence,
        &quote,
        BitcoinNetwork::Testnet,
        1,
        500,
        vec![]
    )
    .is_err());
    let mut changed = quote.clone();
    if let QuoteResponse::Ok { fee_sats, .. } = &mut changed {
        *fee_sats = Some(501);
    }
    assert!(prepare(&changed).is_err());
    let approved = intent.approve(true).unwrap();
    assert!(execute_approved_handoff(
        &executor,
        &store,
        &trust,
        &evidence,
        &changed,
        approved,
        &ExecutionGatePolicy::testnet_default(),
    )
    .await
    .is_err());
    assert_eq!(executor.calls.load(Ordering::SeqCst), 0);

    let approved = prepare(&quote).unwrap().approve(true).unwrap();
    let receipt = execute_approved_handoff(
        &executor,
        &store,
        &trust,
        &evidence,
        &quote,
        approved,
        &ExecutionGatePolicy::testnet_default(),
    )
    .await
    .unwrap();
    assert!(matches!(receipt, HandoffExecutionReceipt::Lightning(_)));
    assert_eq!(executor.calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn bdk_fee_cap_rejects_before_host_signs() {
    let bridge = HostWalletSdkBridge::new(
        BitcoinNetwork::Testnet,
        BdkOnchainBridge::new(
            BitcoinNetwork::Testnet,
            5,
            100,
            SimulatedBdkWallet::new_testnet(),
        ),
        LdkLightningBridge::new(BitcoinNetwork::Testnet, 100, SimulatedLdkNode),
    );
    let destination = "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx";
    assert!(bridge
        .send_onchain_with_max_fee(destination, 100_000, 1)
        .await
        .unwrap_err()
        .to_string()
        .contains("approved maximum"));
    let receipt = bridge
        .send_onchain_with_max_fee(destination, 100_000, 705)
        .await
        .unwrap();
    assert_eq!(receipt.fee_sats, 705);
}

#[tokio::test]
async fn ldk_fee_cap_restores_floor_without_exceeding_approval() {
    let last_cap = Arc::new(AtomicU64::new(0));
    let bridge = HostWalletSdkBridge::new(
        BitcoinNetwork::Testnet,
        BdkOnchainBridge::new(
            BitcoinNetwork::Testnet,
            5,
            100,
            SimulatedBdkWallet::new_testnet(),
        ),
        LdkLightningBridge::new(
            BitcoinNetwork::Testnet,
            100,
            FeeCapLdkNode {
                last_cap: last_cap.clone(),
            },
        ),
    );
    let invoice = make_testnet_bolt11(1);
    bridge
        .pay_bolt11_with_max_fee(&invoice, 1_000, 2_000)
        .await
        .unwrap();
    assert_eq!(last_cap.load(Ordering::SeqCst), 1_000);
    bridge
        .pay_bolt11_with_max_fee(&invoice, 1_000, 500)
        .await
        .unwrap();
    assert_eq!(last_cap.load(Ordering::SeqCst), 500);
    assert!(bridge
        .pay_bolt11_with_max_fee(&invoice, 1_000, 0)
        .await
        .is_err());
    assert_eq!(last_cap.load(Ordering::SeqCst), 500);
}

#[test]
fn rfc8785_number_vector_uses_ecmascript_formatting() {
    // RFC 8785 section 3.2.2.3; gibson042 Canonical JSON formats these differently.
    let value: serde_json::Value = serde_json::from_str(
        r#"{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001]}"#,
    )
    .unwrap();
    assert_eq!(
        serde_json_canonicalizer::to_string(&value).unwrap(),
        r#"{"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27]}"#
    );
}
