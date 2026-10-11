use satspath_core::{PaymentMethod, SatsPathError, SignedPaymentProfile};

use crate::ark::{first_ark_method, is_ark_available};
use crate::fees::{fetch_fee_estimate, FeeEstimate};
use crate::lightning::{
    estimate_lightning_fee_sats, is_lightning_available, is_lightning_available_for_amount_sync,
};
use crate::onchain::{estimate_onchain_fee_sats, first_onchain_method, is_onchain_available};

const LIGHTNING_THRESHOLD_SATS: u64 = 100_000;

/// A routing request: who to pay and how much.
#[derive(Debug, Clone)]
pub struct RouteRequest {
    pub alias: String,
    pub amount_sats: u64,
    pub signed_profile: SignedPaymentProfile,
    pub urgency: crate::urgency::PaymentUrgency,
    pub max_fee_sats: Option<u64>,
    pub max_fee_percent: Option<f64>,
}

/// Describes the specific execution path needed for the selected route.
/// Used by the experimental swap engine; safe path ignores this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SwapDirective {
    /// Direct Lightning payment via LNURL/Lightning Address.
    LightningPayment { target_ln_address: Option<String> },
    /// BOLT12 payment via offer or fetched invoice.
    Bolt12Payment {
        offer: String,
        target_invoice: Option<String>,
        has_blinded_paths: bool,
    },
    /// Submarine Swap: on-chain/Ark → Lightning (requires Boltz).
    SubmarineSwap { target_invoice: Option<String> },
    /// Reverse Swap: Lightning → on-chain (requires Boltz).
    ReverseSwap {
        target_address: Option<String>,
        silent_payment_pubkey: Option<String>,
    },
    /// Chain Swap: Ark/L1 → L1/Ark (requires Boltz).
    ChainSwap {
        target_address: Option<String>,
        silent_payment_pubkey: Option<String>,
    },
    /// Direct Ark VTXO transfer (same Ark server).
    ArkTransfer { server: String, pubkey: String },
    /// Manual Arkade execution.
    ArkadeManual,
}

/// Snapshot of live mempool fee rates used in the routing decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeRateSnapshot {
    pub fastest_sat_vb: u64,
    pub half_hour_sat_vb: u64,
    pub hour_sat_vb: u64,
}

/// The selected payment rail and all information needed to execute it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteQuote {
    pub selected_method: PaymentMethod,
    pub reason: String,
    pub estimated_fee_sats: Option<u64>,
    pub estimated_confirmation: Option<String>,
    /// Live fee snapshot (present when mempool was queried).
    pub fee_snapshot: Option<FeeRateSnapshot>,
    /// Execution directive for the experimental swap engine.
    pub swap_directive: SwapDirective,
    pub execution: Option<satspath_core::ExecutionMode>,
    pub wallet_hint: Option<String>,
}

/// Select the best available payment rail.
///
/// Priority:
///   1. Lightning  — if amount < 100 000 sats and a Lightning method exists.
///      NOTE: Lightning is checked BEFORE on-chain fees.
///      The dust threshold must NOT block Lightning route selection.
///   2. On-chain   — if fastestFee ≤ 20 sat/vB (next block, <10 min).
///   3. Ark        — fallback when on-chain fees are too high.
///   4. Error      — no suitable rail found.
pub async fn select_route(req: &RouteRequest) -> satspath_core::Result<RouteQuote> {
    let methods = &req.signed_profile.profile.methods;

    // 1. Lightning — evaluated first, independent of fee environment.
    if req.amount_sats < LIGHTNING_THRESHOLD_SATS {
        for ln in methods.iter().filter(|m| is_lightning_available(m)) {
            // Check Lightning dust threshold (min_sendable from LNURL)
            if !is_lightning_available_for_amount_sync(ln, req.amount_sats) {
                continue; // Try next Lightning method
            }
            let ln_address = match ln {
                PaymentMethod::Lightning {
                    lightning_address, ..
                } => lightning_address.clone(),
                _ => None,
            };
            let swap_directive = match ln {
                PaymentMethod::Lightning {
                    bolt12: Some(offer),
                    ..
                } => {
                    let parsed = crate::bolt12::parse_bolt12_offer(offer).ok();
                    let has_blinded = parsed
                        .as_ref()
                        .map(|o| o.has_blinded_paths())
                        .unwrap_or(false);
                    SwapDirective::Bolt12Payment {
                        offer: offer.clone(),
                        target_invoice: None,
                        has_blinded_paths: has_blinded,
                    }
                }
                PaymentMethod::Bolt12(offer_data) => {
                    let parsed = crate::bolt12::parse_bolt12_offer(&offer_data.offer).ok();
                    let has_blinded = parsed
                        .as_ref()
                        .map(|o| o.has_blinded_paths())
                        .unwrap_or(false);
                    SwapDirective::Bolt12Payment {
                        offer: offer_data.offer.clone(),
                        target_invoice: None,
                        has_blinded_paths: has_blinded,
                    }
                }
                _ => SwapDirective::LightningPayment {
                    target_ln_address: ln_address,
                },
            };
            let fee = estimate_lightning_fee_sats(req.amount_sats);
            return Ok(RouteQuote {
                selected_method: ln.clone(),
                reason: format!(
                    "Amount ({} sats) is below {} sats threshold and Lightning is available.",
                    req.amount_sats, LIGHTNING_THRESHOLD_SATS
                ),
                estimated_fee_sats: Some(fee),
                estimated_confirmation: Some("instant".into()),
                fee_snapshot: None,
                swap_directive,
                execution: None,
                wallet_hint: None,
            });
        }
    }

    // Fetch live fees only when we need to evaluate on-chain or Ark.
    let fee_est = fetch_fee_estimate().await?;
    let snapshot = FeeRateSnapshot {
        fastest_sat_vb: fee_est.fastest_fee,
        half_hour_sat_vb: fee_est.half_hour_fee,
        hour_sat_vb: fee_est.hour_fee,
    };

    // 2. On-chain — evaluate selected urgency fee rate against threshold (<= 10 sat/vB for acceptable).
    let selected_fee_rate_raw = req.urgency.select_fee_rate(&fee_est);
    let selected_fee_rate = (selected_fee_rate_raw as f64 * 1.10).ceil() as u64;
    let expected_conf = req.urgency.expected_confirmation();

    if is_onchain_available(methods) && selected_fee_rate <= 10 {
        let method = first_onchain_method(methods).unwrap().clone();
        let fee = estimate_onchain_fee_sats(selected_fee_rate);
        let (target_address, silent_payment_pubkey) = match &method {
            PaymentMethod::Onchain {
                address,
                silent_payment_pubkey,
                ..
            } => (address.clone(), silent_payment_pubkey.clone()),
            _ => unreachable!(),
        };
        return Ok(RouteQuote {
            selected_method: method,
            reason: format!(
                "Fee ({} sat/vB) is cheap. Confirmation expected in {}.",
                selected_fee_rate, expected_conf
            ),
            estimated_fee_sats: Some(fee),
            estimated_confirmation: Some(expected_conf.into()),
            fee_snapshot: Some(snapshot),
            swap_directive: SwapDirective::ChainSwap {
                target_address,
                silent_payment_pubkey,
            },
            execution: None,
            wallet_hint: None,
        });
    }

    if is_ark_available(methods) {
        let method = first_ark_method(methods).unwrap().clone();
        let (server, pubkey, opaque_uri) = match &method {
            PaymentMethod::Ark {
                server,
                pubkey,
                opaque_uri,
                ..
            } => (server.clone(), pubkey.clone(), opaque_uri.clone()),
            _ => unreachable!(),
        };
        let reason = if is_onchain_available(methods) {
            format!(
                "On-chain fee ({} sat/vB) exceeds 10 sat/vB. Falling back to Ark.",
                selected_fee_rate
            )
        } else {
            "No Lightning (amount above threshold) or on-chain method. Using Ark.".into()
        };

        let (swap_directive, execution, wallet_hint) = if opaque_uri.is_some() {
            (
                SwapDirective::ArkadeManual,
                Some(satspath_core::ExecutionMode::ManualWallet),
                Some("arkade".into()),
            )
        } else {
            (SwapDirective::ArkTransfer { server, pubkey }, None, None)
        };

        return Ok(RouteQuote {
            selected_method: method,
            reason,
            estimated_fee_sats: Some(1),
            estimated_confirmation: Some("near-instant via Ark round".into()),
            fee_snapshot: Some(snapshot),
            swap_directive,
            execution,
            wallet_hint,
        });
    }

    // Last resort: on-chain even with high fees, but warn the user (WS-3)
    if is_onchain_available(methods) {
        let method = first_onchain_method(methods).unwrap().clone();
        let fee = estimate_onchain_fee_sats(selected_fee_rate);
        let (target_address, silent_payment_pubkey) = match &method {
            PaymentMethod::Onchain {
                address,
                silent_payment_pubkey,
                ..
            } => (address.clone(), silent_payment_pubkey.clone()),
            _ => unreachable!(),
        };
        return Ok(RouteQuote {
            selected_method: method,
            reason: format!(
                "⚠ On-chain fee rate is high ({} sat/vB) but no alternative rail is available. \
                 Consider waiting for lower fees.",
                selected_fee_rate
            ),
            estimated_fee_sats: Some(fee),
            estimated_confirmation: Some(expected_conf.into()),
            fee_snapshot: Some(snapshot),
            swap_directive: SwapDirective::ChainSwap {
                target_address,
                silent_payment_pubkey,
            },
            execution: None,
            wallet_hint: None,
        });
    }

    Err(SatsPathError::NoRouteFound(format!(
        "No usable rail for {} sats to {}. \
         Lightning: {} sats threshold not met or no LN method. \
         On-chain: fee {} sat/vB > 10 sat/vB. \
         Ark: no method configured.",
        req.amount_sats, req.alias, LIGHTNING_THRESHOLD_SATS, selected_fee_rate,
    )))
}

/// Deterministic route selection for unit tests (pre-fetched fee estimate).
pub fn select_route_with_fees(
    req: &RouteRequest,
    fee_est: &FeeEstimate,
) -> satspath_core::Result<RouteQuote> {
    let methods = &req.signed_profile.profile.methods;

    // Lightning first — no fee check, but enforce dust threshold.
    if req.amount_sats < LIGHTNING_THRESHOLD_SATS {
        if let Some(ln) = methods
            .iter()
            .find(|m| is_lightning_available_for_amount_sync(m, req.amount_sats))
        {
            let ln_address = match ln {
                PaymentMethod::Lightning {
                    lightning_address, ..
                } => lightning_address.clone(),
                _ => None,
            };
            let swap_directive = match ln {
                PaymentMethod::Lightning {
                    bolt12: Some(offer),
                    ..
                } => {
                    let parsed = crate::bolt12::parse_bolt12_offer(offer).ok();
                    let has_blinded = parsed
                        .as_ref()
                        .map(|o| o.has_blinded_paths())
                        .unwrap_or(false);
                    SwapDirective::Bolt12Payment {
                        offer: offer.clone(),
                        target_invoice: None,
                        has_blinded_paths: has_blinded,
                    }
                }
                PaymentMethod::Bolt12(offer_data) => {
                    let parsed = crate::bolt12::parse_bolt12_offer(&offer_data.offer).ok();
                    let has_blinded = parsed
                        .as_ref()
                        .map(|o| o.has_blinded_paths())
                        .unwrap_or(false);
                    SwapDirective::Bolt12Payment {
                        offer: offer_data.offer.clone(),
                        target_invoice: None,
                        has_blinded_paths: has_blinded,
                    }
                }
                _ => SwapDirective::LightningPayment {
                    target_ln_address: ln_address,
                },
            };
            let fee = estimate_lightning_fee_sats(req.amount_sats);
            return Ok(RouteQuote {
                selected_method: ln.clone(),
                reason: format!(
                    "Amount ({} sats) is below {} sats threshold and Lightning is available.",
                    req.amount_sats, LIGHTNING_THRESHOLD_SATS
                ),
                estimated_fee_sats: Some(fee),
                estimated_confirmation: Some("instant".into()),
                fee_snapshot: None,
                swap_directive,
                execution: None,
                wallet_hint: None,
            });
        }
    }

    let snapshot = FeeRateSnapshot {
        fastest_sat_vb: fee_est.fastest_fee,
        half_hour_sat_vb: fee_est.half_hour_fee,
        hour_sat_vb: fee_est.hour_fee,
    };

    let selected_fee_rate_raw = req.urgency.select_fee_rate(fee_est);
    let selected_fee_rate = (selected_fee_rate_raw as f64 * 1.10).ceil() as u64;
    let expected_conf = req.urgency.expected_confirmation();

    if is_onchain_available(methods) && selected_fee_rate <= 10 {
        let method = first_onchain_method(methods).unwrap().clone();
        let fee = estimate_onchain_fee_sats(selected_fee_rate);
        let (target_address, silent_payment_pubkey) = match &method {
            PaymentMethod::Onchain {
                address,
                silent_payment_pubkey,
                ..
            } => (address.clone(), silent_payment_pubkey.clone()),
            _ => unreachable!(),
        };
        return Ok(RouteQuote {
            selected_method: method,
            reason: format!(
                "Fee ({} sat/vB) is cheap. Confirmation expected in {}.",
                selected_fee_rate, expected_conf
            ),
            estimated_fee_sats: Some(fee),
            estimated_confirmation: Some(expected_conf.into()),
            fee_snapshot: Some(snapshot),
            swap_directive: SwapDirective::ChainSwap {
                target_address,
                silent_payment_pubkey,
            },
            execution: None,
            wallet_hint: None,
        });
    }

    if is_ark_available(methods) {
        let method = first_ark_method(methods).unwrap().clone();
        let (server, pubkey, opaque_uri) = match &method {
            PaymentMethod::Ark {
                server,
                pubkey,
                opaque_uri,
                ..
            } => (server.clone(), pubkey.clone(), opaque_uri.clone()),
            _ => unreachable!(),
        };

        let (swap_directive, execution, wallet_hint) = if opaque_uri.is_some() {
            (
                SwapDirective::ArkadeManual,
                Some(satspath_core::ExecutionMode::ManualWallet),
                Some("arkade".into()),
            )
        } else {
            (SwapDirective::ArkTransfer { server, pubkey }, None, None)
        };

        return Ok(RouteQuote {
            selected_method: method,
            reason: format!(
                "On-chain fee ({} sat/vB) exceeds 10 sat/vB. Falling back to Ark.",
                selected_fee_rate
            ),
            estimated_fee_sats: Some(1),
            estimated_confirmation: Some("near-instant via Ark round".into()),
            fee_snapshot: Some(snapshot),
            swap_directive,
            execution,
            wallet_hint,
        });
    }

    if is_onchain_available(methods) {
        let method = first_onchain_method(methods).unwrap().clone();
        let fee = estimate_onchain_fee_sats(selected_fee_rate);
        let (target_address, silent_payment_pubkey) = match &method {
            PaymentMethod::Onchain {
                address,
                silent_payment_pubkey,
                ..
            } => (address.clone(), silent_payment_pubkey.clone()),
            _ => unreachable!(),
        };
        return Ok(RouteQuote {
            selected_method: method,
            reason: format!(
                "⚠ On-chain fee rate is high ({} sat/vB) but no alternative rail is available. \
                 Consider waiting for lower fees.",
                selected_fee_rate
            ),
            estimated_fee_sats: Some(fee),
            estimated_confirmation: Some(expected_conf.into()),
            fee_snapshot: Some(snapshot),
            swap_directive: SwapDirective::ChainSwap {
                target_address,
                silent_payment_pubkey,
            },
            execution: None,
            wallet_hint: None,
        });
    }

    Err(SatsPathError::NoRouteFound(format!(
        "No usable rail for {} sats to {}.",
        req.amount_sats, req.alias,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use satspath_core::{
        crypto::{generate_identity_keypair, sign_profile},
        BitcoinNetwork, PaymentMethod, PaymentProfile,
    };

    fn low_fees() -> FeeEstimate {
        FeeEstimate {
            fastest_fee: 5,
            half_hour_fee: 4,
            hour_fee: 3,
            economy_fee: 2,
            minimum_fee: 1,
        }
    }

    fn high_fees() -> FeeEstimate {
        FeeEstimate {
            fastest_fee: 50,
            half_hour_fee: 30,
            hour_fee: 20,
            economy_fee: 15,
            minimum_fee: 10,
        }
    }

    fn make_profile(methods: Vec<PaymentMethod>) -> SignedPaymentProfile {
        let kp = generate_identity_keypair();
        let pubkey_hex = hex::encode(kp.public_key.serialize());
        let profile = PaymentProfile {
            alias: "test@example.com".into(),
            identity_pubkey: pubkey_hex,
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
        sign_profile(profile, &kp.secret_key).unwrap()
    }

    #[test]
    fn chooses_lightning_for_small_amount() {
        let signed = make_profile(vec![PaymentMethod::Lightning {
            label: "LN".into(),
            lightning_address: Some("test@example.com".into()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        }]);
        let req = RouteRequest {
            alias: "test@example.com".into(),
            amount_sats: 21_000,
            signed_profile: signed,
            urgency: crate::urgency::PaymentUrgency::Normal,
            max_fee_sats: None,
            max_fee_percent: None,
        };
        let q = select_route_with_fees(&req, &low_fees()).unwrap();
        assert!(matches!(q.selected_method, PaymentMethod::Lightning { .. }));
    }

    #[test]
    fn lightning_not_blocked_by_fees() {
        // Even with extreme fees, Lightning for small amounts must still win.
        let signed = make_profile(vec![PaymentMethod::Lightning {
            label: "LN".into(),
            lightning_address: Some("test@example.com".into()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        }]);
        let extreme_fees = FeeEstimate {
            fastest_fee: 500,
            half_hour_fee: 400,
            hour_fee: 300,
            economy_fee: 200,
            minimum_fee: 100,
        };
        let req = RouteRequest {
            alias: "test@example.com".into(),
            amount_sats: 1_000,
            signed_profile: signed,
            urgency: crate::urgency::PaymentUrgency::Normal,
            max_fee_sats: None,
            max_fee_percent: None,
        };
        let q = select_route_with_fees(&req, &extreme_fees).unwrap();
        assert!(matches!(q.selected_method, PaymentMethod::Lightning { .. }));
    }

    #[test]
    fn chooses_onchain_for_large_amount_low_fees() {
        let signed = make_profile(vec![PaymentMethod::Onchain {
            label: "BTC".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some("bc1q...".into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        }]);
        let req = RouteRequest {
            alias: "test@example.com".into(),
            amount_sats: 500_000,
            signed_profile: signed,
            urgency: crate::urgency::PaymentUrgency::Normal,
            max_fee_sats: None,
            max_fee_percent: None,
        };
        let q = select_route_with_fees(&req, &low_fees()).unwrap();
        assert!(matches!(q.selected_method, PaymentMethod::Onchain { .. }));
        assert!(q.reason.contains("4 sat/vB"));
    }

    #[test]
    fn falls_back_to_ark_when_fees_high() {
        let signed = make_profile(vec![
            PaymentMethod::Onchain {
                label: "BTC".into(),
                network: BitcoinNetwork::Mainnet,
                address: Some("bc1q...".into()),
                silent_payment_pubkey: None,
                pubkey_hint: None,
                descriptor_hint: None,
                address_list: vec![],
            },
            PaymentMethod::Ark {
                label: "Ark".into(),
                server: "https://ark.example.com".into(),
                pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
                opaque_uri: None,
                vtxo_pointer: None,
                proof: None,
                expires_at: None,
            },
        ]);
        let req = RouteRequest {
            alias: "test@example.com".into(),
            amount_sats: 500_000,
            signed_profile: signed,
            urgency: crate::urgency::PaymentUrgency::Normal,
            max_fee_sats: None,
            max_fee_percent: None,
        };
        let q = select_route_with_fees(&req, &high_fees()).unwrap();
        assert!(matches!(q.selected_method, PaymentMethod::Ark { .. }));
        assert!(q.reason.contains("Falling back to Ark."));
    }

    #[test]
    fn no_route_when_no_methods() {
        let signed = make_profile(vec![]);
        let req = RouteRequest {
            alias: "test@example.com".into(),
            amount_sats: 500_000,
            signed_profile: signed,
            urgency: crate::urgency::PaymentUrgency::Normal,
            max_fee_sats: None,
            max_fee_percent: None,
        };
        assert!(matches!(
            select_route_with_fees(&req, &high_fees()).unwrap_err(),
            SatsPathError::NoRouteFound(_)
        ));
    }

    #[test]
    fn onchain_boundary_at_10_sat_vb_hour_fee() {
        let signed = make_profile(vec![PaymentMethod::Onchain {
            label: "BTC".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some("bc1q...".into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        }]);
        let req = RouteRequest {
            alias: "test@example.com".into(),
            amount_sats: 500_000,
            signed_profile: signed,
            urgency: crate::urgency::PaymentUrgency::Normal,
            max_fee_sats: None,
            max_fee_percent: None,
        };

        let at = FeeEstimate {
            fastest_fee: 15,
            half_hour_fee: 12,
            hour_fee: 9, // 9 * 1.10 = 9.9 => ceil(9.9) = 10, passes threshold
            economy_fee: 5,
            minimum_fee: 1,
        };
        assert!(matches!(
            select_route_with_fees(&req, &at).unwrap().selected_method,
            PaymentMethod::Onchain { .. }
        ));

        let above = FeeEstimate {
            fastest_fee: 20,
            half_hour_fee: 15,
            hour_fee: 10, // 10 * 1.1 = 11 => fails threshold
            economy_fee: 6,
            minimum_fee: 2,
        };
        let q = select_route_with_fees(&req, &above).unwrap();
        assert!(matches!(q.selected_method, PaymentMethod::Onchain { .. }));
        assert!(q.reason.contains("11 sat/vB"));
        assert!(q.reason.contains("no alternative rail is available"));
    }
}
