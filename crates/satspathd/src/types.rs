//! All request/response serialization types for the satspathd HTTP API.

use serde::{Deserialize, Serialize};

use satspath_core::{
    MerkleConsistencyProof, MerkleInclusionProof, PaymentMethod, SignedPaymentProfile,
};
use satspath_router::QuoteResponse;

use crate::config::WalletState;
use crate::rate_limit;

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
pub(crate) struct StatusResponse {
    pub(crate) daemon: &'static str,
    pub(crate) version: &'static str,
    pub(crate) bind: String,
    pub(crate) network: String,
    pub(crate) home: String,
    pub(crate) wallet_initialized: bool,
    pub(crate) alias: Option<String>,
    pub(crate) identity_fingerprint: Option<String>,
    pub(crate) methods: Vec<String>,
    pub(crate) safety: SafetyStatus,
    pub(crate) rate_limit: rate_limit::RateLimiterStats,
    pub(crate) is_tls: bool,
    pub(crate) behind_proxy: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct NodeResponse {
    pub(crate) status: StatusResponse,
    pub(crate) profile: ProfileResponse,
}

#[derive(Debug, Serialize)]
pub(crate) struct SafetyStatus {
    pub(crate) moves_funds: bool,
    pub(crate) signs_bitcoin_transactions: bool,
    pub(crate) broadcasts_transactions: bool,
    pub(crate) stores_wallet_seeds_or_spending_keys: bool,
    pub(crate) manages_signed_profiles: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProfileResponse {
    pub(crate) wallet: crate::config::WalletState,
    pub(crate) signed_profile: Option<SignedPaymentProfile>,
    pub(crate) signature_valid: Option<bool>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PreviewResponse<T: Serialize> {
    pub(crate) mode: &'static str,
    pub(crate) warnings: Vec<&'static str>,
    pub(crate) quote: T,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub(crate) enum PayResponse {
    WalletHandoff {
        decision_protocol: &'static str,
        recipient: String,
        amount_sats: u64,
        quote: QuoteResponse,
        payment_payload: String,
        qr_svg: String,
        handoff: WalletHandoff,
        safety: SafetyStatus,
    },
    InviteCreated {
        decision_protocol: &'static str,
        recipient_hint: String,
        amount_sats: u64,
        quote: QuoteResponse,
        safety: SafetyStatus,
    },
    NoRoute {
        decision_protocol: &'static str,
        reason: String,
        quote: QuoteResponse,
        safety: SafetyStatus,
    },
    InvalidSignature {
        decision_protocol: &'static str,
        quote: QuoteResponse,
        safety: SafetyStatus,
    },
}

#[derive(Debug, Serialize)]
pub(crate) struct WalletHandoff {
    pub(crate) mode: &'static str,
    pub(crate) instruction: &'static str,
    pub(crate) opens_external_wallet: bool,
    pub(crate) daemon_executes_payment: bool,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub(crate) enum DnsResolveResponse {
    Ok {
        resolution: satspath_core::bip353::Bip353Resolution,
        parsed: satspath_core::bip321::ParsedBip321Uri,
    },
    Error {
        name: String,
        error: String,
        strict_mode: bool,
    },
}

#[derive(Debug, Serialize)]
pub(crate) struct ErrorResponse {
    pub(crate) error: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct KeyRotationResponse {
    pub(crate) alias: String,
    pub(crate) sequence: u64,
    pub(crate) previous_fingerprint: String,
    pub(crate) new_fingerprint: String,
    pub(crate) event_hash: String,
    pub(crate) checkpoint_hash: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ProfileRecoverRequest {
    pub(crate) alias: String,
    pub(crate) proof: satspath_core::recovery::KeyRecoveryProof,
    pub(crate) signed_profile: satspath_core::SignedPaymentProfile,
    #[serde(default)]
    pub(crate) event_created_at: Option<i64>,
    #[serde(default)]
    pub(crate) event_signature: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct KeyRecoveryResponse {
    pub(crate) alias: String,
    pub(crate) sequence: u64,
    pub(crate) previous_fingerprint: String,
    pub(crate) new_fingerprint: String,
    pub(crate) event_hash: String,
    pub(crate) checkpoint_hash: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct ReceiveView {
    /// Masked alias, e.g. `r***@gmail.com` -- the raw identifier is never exposed.
    pub(crate) alias: String,
    pub(crate) rail: String,
    pub(crate) payload: String,
    pub(crate) qr_svg: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
#[allow(clippy::large_enum_variant)]
pub(crate) enum SendResponse {
    Ok {
        mode: &'static str,
        rail: String,
        reason: String,
        recipient: String,
        profile_signature_verified: bool,
        identifier_verified: bool,
        identifier_verification: &'static str,
        amount_sats: u64,
        payload: String,
        qr_svg: String,
        safety: SafetyStatus,
    },
    Invite {
        mode: &'static str,
        experimental: bool,
        recipient_hint: String,
        amount_sats: u64,
        claim_url: String,
        email: EmailInvite,
        safety: SafetyStatus,
    },
    InvalidSignature {
        recipient: String,
    },
    NoRoute {
        reason: String,
    },
}

#[derive(Debug, Serialize)]
pub(crate) struct EmailInvite {
    pub(crate) to: String,
    pub(crate) subject: String,
    pub(crate) body: String,
    pub(crate) mailto: String,
}

// ---------------------------------------------------------------------------
// Request types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(crate) struct ProfileUpdateRequest {
    pub(crate) alias: Option<String>,
    pub(crate) lightning_address: Option<String>,
    pub(crate) onchain_address: Option<String>,
    pub(crate) onchain_pubkey: Option<String>,
    pub(crate) ark_server: Option<String>,
    pub(crate) ark_pubkey: Option<String>,
    #[serde(default)]
    pub(crate) remove_methods: Vec<String>,
    pub(crate) recovery_policy: Option<satspath_core::recovery::RecoveryPolicy>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct AliasRequest {
    pub(crate) alias: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct VerifyRequest {
    pub(crate) alias: String,
    pub(crate) token: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct QuoteRequest {
    pub(crate) recipient: String,
    pub(crate) amount_sats: u64,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PayRequest {
    pub(crate) recipient: String,
    pub(crate) amount_sats: u64,
    #[serde(default)]
    pub(crate) memo: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct DnsResolveRequest {
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) allow_insecure_dns_for_dev: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct InclusionVerifyRequest {
    pub(crate) event_hash: String,
    pub(crate) proof: MerkleInclusionProof,
    pub(crate) checkpoint: satspath_core::TransparencyCheckpoint,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ConsistencyVerifyRequest {
    pub(crate) proof: MerkleConsistencyProof,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ReceiveRequest {
    pub(crate) rail: Option<String>,
    pub(crate) amount_sats: Option<u64>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SendRequest {
    pub(crate) recipient: String,
    pub(crate) amount_sats: u64,
    /// Model Lightning routing health (defaults to healthy).
    #[serde(default)]
    pub(crate) routing_ok: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct ClaimRequest {
    pub(crate) invite_id: String,
    pub(crate) alias: String,
    #[serde(default)]
    pub(crate) signed_profile: Option<satspath_core::SignedPaymentProfile>,
    #[serde(default)]
    pub(crate) lightning_address: Option<String>,
    #[serde(default)]
    pub(crate) onchain_address: Option<String>,
    #[serde(default)]
    pub(crate) onchain_pubkey: Option<String>,
    #[serde(default)]
    pub(crate) ark_server: Option<String>,
    #[serde(default)]
    pub(crate) ark_pubkey: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ClaimResponse {
    pub(crate) status: String,
    pub(crate) invite_id: String,
    pub(crate) alias: String,
    pub(crate) amount_sats: u64,
    pub(crate) profile_pubkey: String,
    pub(crate) claimed_at: i64,
    pub(crate) message: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct InspectInviteResponse {
    pub(crate) invite_id: String,
    pub(crate) identifier_hash: String,
    pub(crate) display_hint: String,
    pub(crate) amount_sats: u64,
    pub(crate) memo: Option<String>,
    pub(crate) status: satspath_core::InviteStatus,
    pub(crate) is_expired: bool,
    pub(crate) is_claimable: bool,
    pub(crate) created_at: i64,
    pub(crate) expires_at: i64,
    pub(crate) sender_verified: bool,
    pub(crate) sender_pubkey: Option<String>,
}

// ---------------------------------------------------------------------------
// Helper to build PaymentMethod list from wallet state
// ---------------------------------------------------------------------------

pub(crate) fn build_methods(wallet: &WalletState, network: &str) -> Vec<PaymentMethod> {
    let mut methods = Vec::new();
    if let Some(addr) = &wallet.lightning_address {
        methods.push(PaymentMethod::Lightning {
            label: "Lightning Address".into(),
            lightning_address: Some(addr.clone()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        });
    }
    if let Some(addr) = &wallet.onchain_address {
        methods.push(PaymentMethod::Onchain {
            label: format!("Bitcoin ({})", network),
            network: bitcoin_network(network),
            address: Some(addr.clone()),
            silent_payment_pubkey: None,
            pubkey_hint: wallet.onchain_pubkey.clone(),
            descriptor_hint: None,
            address_list: vec![],
        });
    }
    if let (Some(server), Some(pubkey)) = (&wallet.ark_server, &wallet.ark_pubkey) {
        methods.push(PaymentMethod::Ark {
            label: "Ark".into(),
            server: server.clone(),
            pubkey: pubkey.clone(),
            vtxo_pointer: None,
            opaque_uri: None,
            proof: None,
            expires_at: None,
        });
    }
    methods
}

pub(crate) fn bitcoin_network(network: &str) -> satspath_core::BitcoinNetwork {
    use satspath_core::BitcoinNetwork;
    match network.to_ascii_lowercase().as_str() {
        "mainnet" | "bitcoin" => BitcoinNetwork::Mainnet,
        "regtest" => BitcoinNetwork::Regtest,
        // devnet uses testnet-form receive addresses until a distinct core
        // network enum is added.
        _ => BitcoinNetwork::Testnet,
    }
}

pub(crate) fn safety_status() -> SafetyStatus {
    SafetyStatus {
        moves_funds: false,
        signs_bitcoin_transactions: false,
        broadcasts_transactions: false,
        stores_wallet_seeds_or_spending_keys: false,
        manages_signed_profiles: true,
    }
}

pub(crate) fn safety_warnings() -> Vec<&'static str> {
    vec![
        "satspathd does not move funds",
        "satspathd does not sign Bitcoin transactions",
        "satspathd does not broadcast transactions",
        "payment execution happens in an external wallet",
    ]
}

pub(crate) fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

pub(crate) fn fmt_btc(sats: u64) -> String {
    format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)
}

/// Minimal percent-encoding for mailto: query components.
pub(crate) fn pct(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}
