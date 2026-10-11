use serde::{Deserialize, Serialize};

use crate::ark::ArkOwnershipProof;
use crate::pointer::BitcoinNetwork;

/// A single payment method supported by the profile owner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum PaymentMethod {
    /// On-chain Bitcoin. Multiple entries are encouraged for privacy.
    Onchain {
        label: String,
        #[serde(default = "default_bitcoin_network")]
        network: BitcoinNetwork,
        /// Static address (legacy, discouraged by spec).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        address: Option<String>,
        /// BIP-352 Silent Payment scan pubkey (sp1q...).
        /// When present, the payer derives an ephemeral address per-payment.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        silent_payment_pubkey: Option<String>,
        #[serde(default)]
        pubkey_hint: Option<String>,
        #[serde(default)]
        descriptor_hint: Option<String>,
        /// List of pre-derived addresses for wallets that don't support BIP-352.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        address_list: Vec<String>,
    },
    /// Lightning Network via LNURL, Lightning Address, or BOLT12.
    Lightning {
        label: String,
        #[serde(default)]
        lightning_address: Option<String>,
        #[serde(default)]
        lnurl: Option<String>,
        #[serde(default)]
        bolt12: Option<String>,
        #[serde(default)]
        receiver_pubkey: Option<String>,
    },
    /// Ark virtual UTXO protocol.
    Ark {
        label: String,
        server: String,
        pubkey: String,
        #[serde(default)]
        vtxo_pointer: Option<String>,
        #[serde(default)]
        proof: Option<ArkOwnershipProof>,
        #[serde(default)]
        expires_at: Option<i64>,
        /// Opaque Arkade receive URI (`ark1q…` address or `ark:` URI).
        ///
        /// Set when the user registered via `--arkade-uri` and only a public
        /// receive string is available from Arkade.money.  When `Some`, the
        /// method is always `PreviewOnly` / `execution: manual_wallet`.
        /// `server` and `pubkey` will be empty strings in this case.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        opaque_uri: Option<String>,
    },
    /// Direct BOLT12 offer (BIP-353 compatible).
    Bolt12(Bolt12Offer),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Bolt12Offer {
    pub label: String,
    pub offer: String,
    #[serde(default = "default_bitcoin_network")]
    pub network: BitcoinNetwork,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub minimum_amount_sats: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    pub issuer_pubkey: String,
}

fn default_bitcoin_network() -> BitcoinNetwork {
    BitcoinNetwork::Mainnet
}

impl PaymentMethod {
    pub fn method_name(&self) -> &'static str {
        match self {
            PaymentMethod::Onchain { .. } => "Onchain",
            PaymentMethod::Lightning { .. } => "Lightning",
            PaymentMethod::Ark { .. } => "Ark",
            PaymentMethod::Bolt12(_) => "Bolt12",
        }
    }

    pub fn label(&self) -> &str {
        match self {
            PaymentMethod::Onchain { label, .. } => label,
            PaymentMethod::Lightning { label, .. } => label,
            PaymentMethod::Ark { label, .. } => label,
            PaymentMethod::Bolt12(offer) => &offer.label,
        }
    }

    /// A stable, public, privacy-safe identifier for this method.
    ///
    /// An ownership proof is bound to this descriptor so it cannot be lifted
    /// from one method and replayed onto another. It never contains private
    /// material (no xprv, descriptor, seed, etc.) — only public pointers.
    pub fn ownership_descriptor(&self) -> String {
        match self {
            PaymentMethod::Onchain {
                network,
                silent_payment_pubkey,
                address,
                ..
            } => {
                let net = match network {
                    BitcoinNetwork::Mainnet => "mainnet",
                    BitcoinNetwork::Testnet => "testnet",
                    BitcoinNetwork::Regtest => "regtest",
                };
                if let Some(sp) = silent_payment_pubkey {
                    format!("onchain:{net}:sp:{sp}")
                } else if let Some(addr) = address {
                    format!("onchain:{net}:{addr}")
                } else {
                    format!("onchain:{net}:unknown")
                }
            }
            PaymentMethod::Lightning {
                lightning_address,
                lnurl,
                bolt12,
                label,
                ..
            } => {
                if let Some(addr) = lightning_address {
                    format!("ln-address:{}", addr.trim().to_ascii_lowercase())
                } else if let Some(url) = lnurl {
                    format!("lnurl:{url}")
                } else if let Some(offer) = bolt12 {
                    format!("bolt12:{offer}")
                } else {
                    format!("lightning:{label}")
                }
            }
            PaymentMethod::Bolt12(offer_data) => {
                format!("bolt12:{}", offer_data.offer)
            }
            PaymentMethod::Ark { pubkey, .. } => format!("ark:{pubkey}"),
        }
    }
}

/// A user-owned payment profile associating an alias with payment methods.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentProfile {
    /// Human-readable identifier, e.g. "alice@example.com"
    pub alias: String,
    /// Hex-encoded secp256k1 compressed public key
    pub identity_pubkey: String,
    /// Ordered list of payment methods (most preferred first)
    pub methods: Vec<PaymentMethod>,
    /// Unix timestamp of last update
    pub updated_at: i64,
    /// Optional Unix timestamp after which this profile should be considered
    /// expired and must not be used for routing.
    /// `None` means the profile does not expire (non-expiring).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    /// Monotonically increasing sequence number for replay protection.
    /// Each profile update must have a strictly higher sequence than the previous.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    /// Ordered rail preference list, e.g. `["lightning", "ark", "onchain"]`.
    /// The router uses this to break ties between equally-scored candidates.
    /// Omitted from the wire when empty (backward-compatible with old profiles).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub preferences: Vec<String>,
    /// The random nonce for replay protection (v0.1 spec §10).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Optional key rotation object (v0.1 spec §29).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotation: Option<crate::rotation::KeyRotation>,
    /// Ownership-proof attestations, one per (proven) method, bound to the
    /// method's [`PaymentMethod::ownership_descriptor`].
    ///
    /// Omitted from the wire when empty, so profiles authored before ownership
    /// proofs existed serialize — and verify — byte-for-byte identically. The
    /// identity signature commits to this list, making attestations
    /// tamper-evident.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub method_verifications: Vec<crate::ownership::MethodVerification>,
    /// PQC: Post-quantum hybrid public key bundle (classical + PQC)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hybrid_pubkey: Option<satspath_pqc::types::HybridPublicKey>,
    /// PQC: If true, verifiers MUST check the hybrid_signature. If false, it's optional.
    #[serde(default)]
    pub pqc_required: bool,
    /// Indicates if this profile (and identity key) has been revoked by the owner.
    #[serde(default)]
    pub revoked: bool,
    /// Optional pre-committed recovery policy (Issue #97).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_policy: Option<crate::recovery::RecoveryPolicy>,
    /// Optional key recovery proof object (Issue #97).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<crate::recovery::KeyRecoveryProof>,
}

/// A payment profile together with the owner's signature over its contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedPaymentProfile {
    pub profile: PaymentProfile,
    /// Hex-encoded secp256k1 Schnorr signature (64 bytes)
    pub signature: String,
    /// PQC: Hybrid signature (Schnorr + ML-DSA)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hybrid_signature: Option<satspath_pqc::types::HybridSignature>,
}

/// A parsed universal SatsPath payment request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRequest {
    pub version: u32,
    pub alias: String,
    pub amount_sats: Option<u64>,
    pub memo: Option<String>,
    /// Optional Unix timestamp after which this payment request expires.
    /// Distinct from the profile's own `expires_at`. Omitted when not set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
    pub profile_hint: Option<String>,
}

/// An invitation for an unregistered user to claim a pending payment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Invite {
    /// SHA-256 hash of the alias (hex)
    pub alias_hash: String,
    pub amount_sats: u64,
    pub created_at: i64,
    /// Unix timestamp after which this invite expires.
    pub expires_at: i64,
    pub claim_url: String,
    pub warning: String,
    /// Hex-encoded Schnorr signature by the sender's identity key.
    /// Binds the invite to the sender's identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_signature: Option<String>,
    /// Sender's identity pubkey (hex) for verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_pubkey: Option<String>,
    /// Unique invite ID if assigned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite_id: Option<String>,
}

/// Non-custodial invite state for an identifier with no published profile yet.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InviteRecord {
    pub invite_id: String,
    pub identifier_hash: String,
    pub display_hint: String,
    pub amount_sats: u64,
    pub memo: Option<String>,
    pub sender_fingerprint: String,
    pub status: InviteStatus,
    pub created_at: i64,
    pub expires_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_pubkey: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sender_signature: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_at: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_profile_pubkey: Option<String>,
}

/// Notification generated when an invite is claimed by the receiver.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClaimNotification {
    pub notification_id: String,
    pub invite_id: String,
    pub identifier_hash: String,
    pub display_hint: String,
    pub amount_sats: u64,
    pub claimed_at: i64,
    pub claimed_profile_pubkey: String,
    pub read: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum InviteStatus {
    #[serde(rename = "waiting_for_claim")]
    Created,
    EmailSent,
    ClaimedWithPublicProfile,
    Expired,
    Cancelled,
}

/// Public claim policy metadata only. It is never sufficient to spend funds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ClaimPolicy {
    SingleSig {
        receiver_pubkey: String,
    },
    Multisig {
        threshold: u8,
        pubkeys: Vec<String>,
        descriptor: Option<String>,
    },
    FutureTaproot {
        internal_key: String,
        script_policy_hint: Option<String>,
    },
}
