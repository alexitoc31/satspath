//! `satspath-wasm` — Minimal WASM bindings for SatsPath.
//!
//! Provides:
//!   - `verify_signed_profile` — secp256k1 Schnorr verification
//!   - `canonical_profile_json` — deterministic canonical JSON bytes
//!   - `fingerprint_pubkey` — 8-char pubkey fingerprint
//!   - `topic_for_alias` — SHA-256 P2P topic derivation
//!   - `resolve_alias` — resolver chain: local → BIP353 → HTTPS well-known → Nostr NIP-05
//!   - `quote` — resolve + verify + route + build QR payload
//!   - `build_qr_payload` — payment URI builder (BOLT11, BIP21, ark:)
//!
//! All dependencies are WASM-compatible (no tokio, reqwest, mio).

#![allow(warnings)]
use wasm_bindgen::prelude::*;

pub mod bolt12;
mod crypto;
pub mod handoff;
mod helpers;
mod resolver;
mod router;
mod ssrf;
mod topic;
pub mod types;

pub use bolt12::fetch_bolt12_invoice;
pub use crypto::{
    canonical_profile_json, derive_identity_keypair_from_seed, fingerprint_pubkey,
    verify_signed_profile,
};
pub use helpers::{identifier_hash, mask_identifier};
pub use resolver::{
    Bip353Resolver, ChainResolver, HttpsWellKnownResolver, LocalRegistry, NostrNip05Resolver,
};
pub use router::{build_qr_payload, fetch_fee_estimate, quote, select_route, select_route_live};
pub use topic::topic_for_alias;
pub use types::{
    ArkOwnershipProof, BitcoinNetwork, ExecutionMode, FeeEstimate, FeeRateSnapshot, Invite,
    KeyRotation, MethodVerification, PaymentMethod, PaymentProfile, PaymentUrgency, QuoteRecipient,
    QuoteResponse, RouteQuote, RouteRequest, SignedPaymentProfile, SwapDirective, FALLBACK_FEES,
    LIGHTNING_THRESHOLD_SATS, ONCHAIN_FEE_BUFFER, ONCHAIN_FEE_THRESHOLD_SAT_VB,
};

/// Initialize the WASM module (better panic messages in JS console).
/// Call once at startup in Node.js: `init()`.
#[wasm_bindgen(start)]
pub fn main() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}
