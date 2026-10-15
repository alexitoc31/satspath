//! The UX/backend **quote response contract**.
//!
//! One call — [`quote`] — resolves a recipient, verifies the signed profile,
//! checks expiry, selects a route, and builds a payment payload, returning a
//! single JSON-serializable [`QuoteResponse`] the frontend can render directly
//! by matching on `status`. The backend owns all protocol complexity.
//!
//! # Safety
//!
//! Responses carry **public data only**: payment profiles, public keys,
//! addresses, Lightning Addresses, LNURL/BOLT11 pointers, BIP-21 URIs, Ark
//! pointers, and invites. No funds are moved, nothing is signed or broadcast,
//! and no private key, seed, xprv, macaroon, cert, or secret is ever included —
//! [`build_qr_payload`] additionally screens payloads for private material.

use satspath_core::{
    create_invite,
    crypto::{check_profile_expiry, fingerprint_pubkey, verify_signed_profile},
    identifier_hash,
    profile::PaymentProfile,
    registry::Registry,
    resolver::{ChainResolver, ProfileResolver},
    resolvers::{bip353::Bip353Resolver, http::HttpResolver, nostr::NostrResolver},
    validation::validate_amount_sats,
    BitcoinNetwork, Invite, PaymentMethod, SatsPathError,
};
use serde::{Deserialize, Serialize};

use crate::fees::FeeEstimate;
use crate::handoff::{fmt_btc, validate_payload};
use crate::router::{select_route, select_route_with_fees, RouteRequest};
use tracing::Instrument;

/// Public, frontend-facing description of the recipient.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QuoteRecipient {
    pub alias: String,
    /// Backward-compatible verification flag.
    ///
    /// New clients should prefer `profile_signature_verified` and
    /// `identifier_verified`. For signed-profile quotes this mirrors profile
    /// signature verification. For direct BIP-353 previews, legacy behavior may
    /// mirror DNSSEC identifier verification instead.
    pub verified: bool,
    pub profile_signature_verified: bool,
    pub identifier_verified: bool,
    pub identifier_verification: String,
    pub fingerprint: Option<String>,
}

/// The single response the UX renders by matching on `status`.
///
/// Serializes with an internal `status` tag in `snake_case`
/// (`ok` / `not_registered` / `no_route` / `invalid_signature`).
///
/// The `Ok` variant is intentionally larger than the others: the response shape
/// is the public UX/JSON contract, which embeds `PaymentMethod` unchanged. We do
/// not box it (that would alter the Rust API for consumers); the wire shape is
/// identical either way.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum QuoteResponse {
    Ok {
        recipient: QuoteRecipient,
        /// The selected payment method, embedded unchanged.
        selected_method: PaymentMethod,
        fee_sats: Option<u64>,
        eta: Option<String>,
        reason: String,
        qr: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        execution: Option<satspath_core::ExecutionMode>,
        #[serde(skip_serializing_if = "Option::is_none")]
        wallet_hint: Option<String>,
    },
    NotRegistered {
        invite: Invite,
    },
    NoRoute {
        reason: String,
    },
    InvalidSignature {
        recipient: QuoteRecipient,
    },
}

impl QuoteResponse {
    /// The `status` string this response serializes to (handy for callers/tests).
    pub fn status(&self) -> &'static str {
        match self {
            QuoteResponse::Ok { .. } => "ok",
            QuoteResponse::NotRegistered { .. } => "not_registered",
            QuoteResponse::NoRoute { .. } => "no_route",
            QuoteResponse::InvalidSignature { .. } => "invalid_signature",
        }
    }
}

// ─── Public entry points ──────────────────────────────────────────────────────

/// Resolve, verify, route, and build a payment payload for `recipient`.
///
/// Builds the default resolver chain (local registry → BIP-353 → HTTP → Nostr)
/// Only amount-bound, validated on-chain payloads are emitted. Lightning and
/// experimental rails return `no_route` until a network-bound invoice handoff
/// can be validated here; an amount-less pointer is never a payable QR.
///
/// Returns a [`QuoteResponse`] for every protocol outcome (found / not
/// registered / no route / invalid signature) — the frontend never sees a Rust
/// error type.
pub async fn quote(recipient: &str, amount_sats: u64) -> QuoteResponse {
    let resolver = default_resolver();
    quote_inner(&resolver, recipient, amount_sats, None).await
}

/// Like [`quote`], but against a caller-supplied resolver (e.g. an API server
/// that manages its own resolver chain). Uses live mempool fees.
pub async fn quote_with_resolver<R>(
    resolver: &R,
    recipient: &str,
    amount_sats: u64,
) -> QuoteResponse
where
    R: ProfileResolver + Sync + ?Sized,
{
    quote_inner(resolver, recipient, amount_sats, None).await
}

/// Route a profile only after an external transparency verifier has accepted
/// it. The allow-list contains independently verified ownership descriptors.
pub async fn quote_verified_profile(
    mut signed: satspath_core::SignedPaymentProfile,
    recipient: &str,
    amount_sats: u64,
    allowed_method_descriptors: &[String],
) -> QuoteResponse {
    if let Err(e) = validate_amount_sats(amount_sats) {
        return QuoteResponse::NoRoute {
            reason: e.to_string(),
        };
    }
    let verified = verify_signed_profile(&signed).unwrap_or(false);
    if !verified {
        return QuoteResponse::InvalidSignature {
            recipient: recipient_of(&signed.profile, false),
        };
    }
    signed.profile.methods.retain(|method| {
        allowed_method_descriptors
            .iter()
            .any(|descriptor| descriptor == &method.ownership_descriptor())
    });
    if signed.profile.methods.is_empty() {
        return QuoteResponse::NoRoute {
            reason: "transparency verified, but no payment method has a valid ownership proof"
                .into(),
        };
    }
    let recipient_hash = identifier_hash(recipient);
    route_verified_signed(signed, recipient, &recipient_hash, amount_sats, None).await
}

// ─── QR / payment payload ──────────────────────────────────────────────────────

/// Build a public payment payload for a method.
///
/// - **On-chain** — a validated BIP-21 URI: `bitcoin:<address>?amount=<btc>`.
/// - **Lightning, BOLT12, Ark, Silent Payments** — fail closed until a
///   network- and amount-bound payload can be validated.
pub fn build_qr_payload(method: &PaymentMethod, amount_sats: u64) -> satspath_core::Result<String> {
    validate_amount_sats(amount_sats)?;
    let (payload, network) = match method {
        PaymentMethod::Lightning { .. } => {
            return Err(SatsPathError::InvalidPaymentPointer(
                "Lightning pointers cannot bind the amount; a verified invoice is required".into(),
            ));
        }
        PaymentMethod::Onchain {
            network,
            address,
            silent_payment_pubkey,
            ..
        } => {
            if silent_payment_pubkey.is_some() {
                return Err(SatsPathError::InvalidPaymentPointer(
                    "silent payment handoffs require wallet-side validation".into(),
                ));
            }
            let address = address.as_deref().ok_or_else(|| {
                SatsPathError::InvalidPaymentPointer("on-chain method has no address".into())
            })?;
            let network = match network {
                BitcoinNetwork::Mainnet => "mainnet",
                BitcoinNetwork::Testnet => "testnet",
                BitcoinNetwork::Regtest => "regtest",
            };
            (
                format!("bitcoin:{address}?amount={}", fmt_btc(amount_sats)),
                network,
            )
        }
        PaymentMethod::Ark { .. } | PaymentMethod::Bolt12(_) => {
            return Err(SatsPathError::InvalidPaymentPointer(
                "experimental rail handoffs require protocol-aware wallet validation".into(),
            ));
        }
    };

    validate_payload(method, &payload, network, Some(amount_sats))
        .map_err(|e| SatsPathError::InvalidPaymentPointer(e.to_string()))?;
    Ok(payload)
}

// ─── Core orchestration ─────────────────────────────────────────────────────────

/// The shared quote pipeline.
///
/// `fees`: `Some` uses deterministic routing (no network — used by tests);
/// `None` fetches live mempool fees.
async fn quote_inner<R>(
    resolver: &R,
    recipient: &str,
    amount_sats: u64,
    fees: Option<FeeEstimate>,
) -> QuoteResponse
where
    R: ProfileResolver + Sync + ?Sized,
{
    if let Err(e) = validate_amount_sats(amount_sats) {
        return QuoteResponse::NoRoute {
            reason: e.to_string(),
        };
    }
    let recipient_hash = identifier_hash(recipient);

    // 1. Resolve. Anything unresolvable becomes an invite — never a hard error.
    let resolve_span = tracing::info_span!("satspath.resolve", identifier_hash = %recipient_hash);
    let signed = match resolver
        .resolve_alias(recipient)
        .instrument(resolve_span)
        .await
    {
        Ok(signed) => signed,
        Err(_) => {
            return QuoteResponse::NotRegistered {
                // No sender key in preview mode; invite is unsigned (no sender identity binding)
                // TTL: 24 hours
                invite: create_invite(recipient, amount_sats, None, 24 * 3600),
            };
        }
    };

    // 2. Verify signature.
    let verify_span = tracing::info_span!("satspath.verify", identifier_hash = %recipient_hash);
    let verified = {
        let _guard = verify_span.enter();
        verify_signed_profile(&signed).unwrap_or(false)
    };
    let recipient_info = recipient_of(&signed.profile, verified);
    if !verified {
        return QuoteResponse::InvalidSignature {
            recipient: recipient_info,
        };
    }

    route_verified_signed(signed, recipient, &recipient_hash, amount_sats, fees).await
}

async fn route_verified_signed(
    mut signed: satspath_core::SignedPaymentProfile,
    recipient: &str,
    recipient_hash: &str,
    amount_sats: u64,
    fees: Option<FeeEstimate>,
) -> QuoteResponse {
    let recipient_info = recipient_of(&signed.profile, true);

    // 3. Expiry (mapped to no_route to keep the frontend contract to four states).
    if check_profile_expiry(&signed.profile).is_err() {
        return QuoteResponse::NoRoute {
            reason: "Profile expired.".into(),
        };
    }

    // Filter to methods that can produce a validated payable QR before routing,
    // so an unpayable preferred rail (e.g. static Lightning pointer) does not
    // shadow a valid on-chain handoff.
    let mut last_payload_err = None;
    signed
        .profile
        .methods
        .retain(|method| match build_qr_payload(method, amount_sats) {
            Ok(_) => true,
            Err(e) => {
                last_payload_err = Some(e);
                false
            }
        });
    if signed.profile.methods.is_empty() {
        return QuoteResponse::NoRoute {
            reason: match last_payload_err {
                Some(e) => format!("could not build payment payload: {e}"),
                None => "No usable rail found in profile.".into(),
            },
        };
    }

    // 4. Route.
    let route_span = tracing::info_span!(
        "satspath.route",
        identifier_hash = %recipient_hash,
        amount_sats = %amount_sats
    );
    let req = RouteRequest {
        alias: recipient.to_string(),
        amount_sats,
        signed_profile: signed.clone(),
        urgency: crate::urgency::PaymentUrgency::Normal,
        max_fee_sats: None,
        max_fee_percent: None,
    };
    let route = match fees {
        Some(fee_est) => {
            let _guard = route_span.enter();
            select_route_with_fees(&req, &fee_est)
        }
        None => select_route(&req).instrument(route_span).await,
    };
    let route = match route {
        Ok(route) => route,
        Err(SatsPathError::NoRouteFound(reason)) => return QuoteResponse::NoRoute { reason },
        Err(e) => {
            return QuoteResponse::NoRoute {
                reason: e.to_string(),
            }
        }
    };

    // 5. Build the payment payload.
    let qr = match build_qr_payload(&route.selected_method, amount_sats) {
        Ok(payload) => payload,
        Err(e) => {
            return QuoteResponse::NoRoute {
                reason: format!("could not build payment payload: {e}"),
            }
        }
    };

    QuoteResponse::Ok {
        recipient: recipient_info,
        selected_method: route.selected_method,
        fee_sats: route.estimated_fee_sats,
        eta: route.estimated_confirmation,
        reason: route.reason,
        qr,
        execution: route.execution,
        wallet_hint: route.wallet_hint,
    }
}

fn recipient_of(profile: &PaymentProfile, verified: bool) -> QuoteRecipient {
    QuoteRecipient {
        alias: profile.alias.clone(),
        verified,
        profile_signature_verified: verified,
        identifier_verified: false,
        identifier_verification:
            "identifier-only; no inbox/domain ownership proof in this response".into(),
        fingerprint: fingerprint_pubkey(&profile.identity_pubkey).ok(),
    }
}

/// The default resolver chain, mirroring the CLI: local registry, then public
/// resolvers. Registry lives in the always-gitignored `.satspath/`.
fn default_resolver() -> ChainResolver {
    let mut chain = ChainResolver::new();
    if let Ok(registry) = Registry::open(std::path::Path::new(".satspath")) {
        chain = chain.push(registry);
    }
    chain = chain.push(Bip353Resolver::new());
    chain = chain.push(HttpResolver::new());
    chain.push(NostrResolver::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use satspath_core::crypto::{generate_identity_keypair, sign_profile};
    use satspath_core::{BitcoinNetwork, PaymentProfile, SignedPaymentProfile};

    // Deterministic fees: cheap next block (on-chain viable when a method exists).
    fn cheap_fees() -> FeeEstimate {
        FeeEstimate {
            fastest_fee: 5,
            half_hour_fee: 4,
            hour_fee: 3,
            economy_fee: 2,
            minimum_fee: 1,
        }
    }

    // Expensive next block (> 20 sat/vB): on-chain not acceptable.
    fn expensive_fees() -> FeeEstimate {
        FeeEstimate {
            fastest_fee: 35,
            half_hour_fee: 30,
            hour_fee: 25,
            economy_fee: 20,
            minimum_fee: 10,
        }
    }

    struct MockResolver {
        signed: Option<SignedPaymentProfile>,
    }

    #[async_trait]
    impl ProfileResolver for MockResolver {
        async fn resolve_alias(&self, alias: &str) -> satspath_core::Result<SignedPaymentProfile> {
            self.signed
                .clone()
                .ok_or_else(|| SatsPathError::AliasNotFound(alias.to_string()))
        }
    }

    fn sign(profile: PaymentProfile, secret: &secp256k1::SecretKey) -> SignedPaymentProfile {
        sign_profile(profile, secret).unwrap()
    }

    fn base_profile(
        alias: &str,
        methods: Vec<PaymentMethod>,
    ) -> (PaymentProfile, secp256k1::SecretKey) {
        let kp = generate_identity_keypair();
        let profile = PaymentProfile {
            alias: alias.to_string(),
            identity_pubkey: hex::encode(kp.public_key.serialize()),
            methods,
            updated_at: 1_700_000_000,
            expires_at: None,
            sequence: None,
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: Vec::new(),
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
            recovery_policy: None,
            recovery: None,
        };
        (profile, kp.secret_key)
    }

    fn lightning_method(addr: &str) -> PaymentMethod {
        PaymentMethod::Lightning {
            label: "Lightning Address".into(),
            lightning_address: Some(addr.into()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        }
    }

    fn onchain_method(addr: &str) -> PaymentMethod {
        PaymentMethod::Onchain {
            label: "Bitcoin".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some(addr.into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        }
    }

    fn ark_method(server: &str, pubkey: &str) -> PaymentMethod {
        PaymentMethod::Ark {
            label: "Ark".into(),
            server: server.into(),
            pubkey: pubkey.into(),
            opaque_uri: None,
            vtxo_pointer: None,
            proof: None,
            expires_at: None,
        }
    }

    fn lightning_resolver(alias: &str, addr: &str) -> MockResolver {
        let (profile, secret) = base_profile(alias, vec![lightning_method(addr)]);
        MockResolver {
            signed: Some(sign(profile, &secret)),
        }
    }

    fn onchain_resolver(alias: &str, addr: &str) -> MockResolver {
        let (profile, secret) = base_profile(alias, vec![onchain_method(addr)]);
        MockResolver {
            signed: Some(sign(profile, &secret)),
        }
    }

    // Amount-less Lightning addresses must not be presented as payable QRs.
    #[tokio::test]
    async fn registered_lightning_user_without_invoice_returns_no_route() {
        let resolver = lightning_resolver("rodrigo@satspath.dev", "rodrigo@getalby.com");
        let resp = quote_inner(&resolver, "rodrigo@satspath.dev", 1000, Some(cheap_fees())).await;

        assert!(matches!(resp, QuoteResponse::NoRoute { .. }));
    }

    #[tokio::test]
    async fn lightning_plus_onchain_profile_routes_to_onchain_qr() {
        let (profile, secret) = base_profile(
            "rodrigo@satspath.dev",
            vec![
                lightning_method("rodrigo@getalby.com"),
                onchain_method("1BoatSLRHtKNngkdXEeobR76b53LETtpyT"),
            ],
        );
        let resolver = MockResolver {
            signed: Some(sign(profile, &secret)),
        };
        let resp = quote_inner(&resolver, "rodrigo@satspath.dev", 1000, Some(cheap_fees())).await;
        match resp {
            QuoteResponse::Ok {
                selected_method,
                qr,
                ..
            } => {
                assert!(matches!(selected_method, PaymentMethod::Onchain { .. }));
                assert_eq!(
                    qr,
                    "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00001000"
                );
            }
            other => panic!("expected Ok with on-chain QR, got {}", other.status()),
        }
    }

    // 8–9: unknown user → not_registered with invite fields.
    #[tokio::test]
    async fn unknown_user_returns_not_registered_with_invite() {
        let resolver = MockResolver { signed: None };
        let resp = quote_inner(&resolver, "ghost@nowhere.dev", 21_000, Some(cheap_fees())).await;
        match resp {
            QuoteResponse::NotRegistered { invite } => {
                assert!(!invite.alias_hash.is_empty());
                assert_eq!(invite.amount_sats, 21_000);
                assert!(invite.claim_url.contains("alias_hash="));
                assert!(invite.claim_url.contains("amount=21000"));
            }
            other => panic!("expected NotRegistered, got {}", other.status()),
        }
    }

    #[tokio::test]
    async fn invalid_amount_does_not_create_invite_or_run_routing() {
        let resolver = MockResolver { signed: None };
        for amount in [0, u64::MAX] {
            assert!(matches!(
                quote_inner(&resolver, "ghost@nowhere.dev", amount, Some(cheap_fees())).await,
                QuoteResponse::NoRoute { .. }
            ));
        }
    }

    // 10: no usable route → no_route.
    #[tokio::test]
    async fn no_usable_route_returns_no_route() {
        // On-chain only, fees too high (35 > 20), no Lightning/Ark fallback.
        let (profile, secret) = base_profile("carol@satspath.dev", vec![]);
        let resolver = MockResolver {
            signed: Some(sign(profile, &secret)),
        };
        let resp = quote_inner(
            &resolver,
            "carol@satspath.dev",
            500_000,
            Some(expensive_fees()),
        )
        .await;
        assert_eq!(resp.status(), "no_route");
        assert!(matches!(resp, QuoteResponse::NoRoute { .. }));
    }

    // 11 & 12: invalid signature → invalid_signature, and never ok.
    #[tokio::test]
    async fn tampered_profile_returns_invalid_signature_never_ok() {
        let (profile, secret) = base_profile(
            "rodrigo@satspath.dev",
            vec![lightning_method("r@getalby.com")],
        );
        let mut signed = sign(profile, &secret);
        // Tamper after signing — signature no longer matches.
        signed.profile.alias = "evil@hacker.com".into();
        let resolver = MockResolver {
            signed: Some(signed),
        };
        let resp = quote_inner(&resolver, "evil@hacker.com", 1000, Some(cheap_fees())).await;

        assert_ne!(
            resp.status(),
            "ok",
            "a tampered profile must never return ok"
        );
        match resp {
            QuoteResponse::InvalidSignature { recipient } => {
                assert!(!recipient.verified);
                assert!(!recipient.profile_signature_verified);
                assert!(!recipient.identifier_verified);
                assert!(recipient.fingerprint.is_some());
            }
            other => panic!("expected InvalidSignature, got {}", other.status()),
        }
    }

    // 13: on-chain QR is a BIP-21 URI.
    #[test]
    fn qr_payload_onchain_is_bip21() {
        let method = onchain_method("1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
        let qr = build_qr_payload(&method, 21_000).unwrap();
        assert_eq!(
            qr,
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00021000"
        );
    }

    // Experimental Ark pointers are not payable without protocol validation.
    #[test]
    fn qr_payload_ark_fails_closed() {
        let method = ark_method(
            "https://ark.example.com",
            "02c0ded4d352532ee6d5d3fb69c7f08988c0a2b9f68a10fa79b2e769c123456789",
        );
        assert!(build_qr_payload(&method, 42).is_err());
    }

    // 15: JSON serialization uses snake_case status values.
    #[tokio::test]
    async fn json_uses_snake_case_status_values() {
        let resolver =
            onchain_resolver("rodrigo@satspath.dev", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
        let ok = quote_inner(
            &resolver,
            "rodrigo@satspath.dev",
            21_000,
            Some(cheap_fees()),
        )
        .await;
        let json = serde_json::to_string(&ok).unwrap();
        assert!(json.contains("\"status\":\"ok\""), "json: {json}");

        let nr = quote_inner(
            &MockResolver { signed: None },
            "x@y.z",
            1,
            Some(cheap_fees()),
        )
        .await;
        assert!(serde_json::to_string(&nr)
            .unwrap()
            .contains("\"status\":\"not_registered\""));

        let (p, s) = base_profile("c@d.e", vec![]);
        let route_resolver = MockResolver {
            signed: Some(sign(p, &s)),
        };
        let nroute = quote_inner(&route_resolver, "c@d.e", 500_000, Some(expensive_fees())).await;
        assert!(serde_json::to_string(&nroute)
            .unwrap()
            .contains("\"status\":\"no_route\""));

        let (p2, s2) = base_profile("r@s.t", vec![lightning_method("r@getalby.com")]);
        let mut tampered = sign(p2, &s2);
        tampered.profile.alias = "evil@x.y".into();
        let inv_resolver = MockResolver {
            signed: Some(tampered),
        };
        let inv = quote_inner(&inv_resolver, "evil@x.y", 1000, Some(cheap_fees())).await;
        assert!(serde_json::to_string(&inv)
            .unwrap()
            .contains("\"status\":\"invalid_signature\""));
    }

    // Success JSON embeds PaymentMethod with its `type` tag, unchanged.
    #[tokio::test]
    async fn ok_json_embeds_selected_method_with_type_tag() {
        let resolver =
            onchain_resolver("rodrigo@satspath.dev", "1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
        let ok = quote_inner(
            &resolver,
            "rodrigo@satspath.dev",
            21_000,
            Some(cheap_fees()),
        )
        .await;
        let v: serde_json::Value = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["status"], "ok");
        assert_eq!(v["selected_method"]["type"], "Onchain");
        assert_eq!(
            v["selected_method"]["address"],
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
        );
        assert_eq!(v["recipient"]["verified"], true);
        assert_eq!(v["recipient"]["profile_signature_verified"], true);
        assert_eq!(v["recipient"]["identifier_verified"], false);
    }
}
