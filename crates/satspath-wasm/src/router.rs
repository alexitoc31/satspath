//! WASM-compatible router — TypeScript port of Rust satspath-router logic

use crate::types::{
    BitcoinNetwork, ExecutionMode, FeeEstimate, FeeRateSnapshot, Invite, PaymentMethod,
    PaymentUrgency, QuoteRecipient, QuoteResponse, RouteQuote, RouteRequest, SignedPaymentProfile,
    SwapDirective,
};

use crate::{fingerprint_pubkey, mask_identifier, ChainResolver};

use bitcoin::{Address, Network};
use std::str::FromStr;

use js_sys::Date;
use wasm_bindgen::prelude::*;
use wasm_bindgen_futures::JsFuture;
use web_sys::{window, Request, RequestInit, RequestMode, Response};

// Constants matching Rust satspath-router
const LIGHTNING_THRESHOLD_SATS: u64 = 100_000;
const ONCHAIN_FEE_THRESHOLD_SAT_VB: u64 = 10;
const ONCHAIN_FEE_BUFFER: f64 = 1.10;

/// Fallback fees when network is unavailable (conservative estimates)
const FALLBACK_FEES: FeeEstimate = FeeEstimate {
    fastest_fee: 20,
    half_hour_fee: 15,
    hour_fee: 10,
    economy_fee: 5,
    minimum_fee: 1,
};

/// Main router function — exact port of Rust `select_route`
pub fn select_route(req: &RouteRequest, fees: &FeeEstimate) -> Result<RouteQuote, String> {
    let methods = &req.signed_profile.profile.methods;

    // 1. LIGHTNING — evaluated FIRST, independent of fee environment
    if req.amount_sats < LIGHTNING_THRESHOLD_SATS {
        for method in methods.iter().filter(|m| is_lightning_available(m)) {
            if !is_lightning_available_for_amount(method, req.amount_sats) {
                continue;
            }
            let swap_directive = match method {
                PaymentMethod::Lightning {
                    bolt12: Some(offer),
                    ..
                } => SwapDirective::Bolt12Payment {
                    offer: offer.clone(),
                    target_invoice: None,
                    has_blinded_paths: false,
                },
                _ => SwapDirective::LightningPayment {
                    target_ln_address: match method {
                        PaymentMethod::Lightning {
                            lightning_address, ..
                        } => lightning_address.clone(),
                        _ => None,
                    },
                },
            };
            let fee = estimate_lightning_fee(req.amount_sats);
            return Ok(RouteQuote {
                selected_method: method.clone(),
                reason: format!(
                    "Amount ({} sats) is below {} sats threshold and Lightning is available.",
                    req.amount_sats, LIGHTNING_THRESHOLD_SATS
                ),
                estimated_fee_sats: fee,
                estimated_confirmation: "instant".to_string(),
                fee_snapshot: None,
                swap_directive,
                execution: ExecutionMode::ManualWallet,
                wallet_hint:
                    "Use any Lightning wallet (LDK, Breez, Phoenix, etc.) to pay the invoice."
                        .to_string(),
            });
        }
    }

    // 2. ON-CHAIN — evaluate fee rate
    let selected_fee_rate_raw = req.urgency.select_fee_rate(fees);
    let selected_fee_rate = ((selected_fee_rate_raw as f64) * 1.10).ceil() as u64; // 10% buffer
    let expected_conf = req.urgency.expected_confirmation();

    if is_onchain_available(methods) && selected_fee_rate <= ONCHAIN_FEE_THRESHOLD_SAT_VB {
        let method = first_onchain_method(methods).unwrap().clone();
        let fee = estimate_onchain_fee(req.amount_sats, selected_fee_rate);
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
            estimated_fee_sats: fee,
            estimated_confirmation: expected_conf.to_string(),
            fee_snapshot: Some(fees.clone()),
            swap_directive: SwapDirective::ChainSwap {
                target_address,
                silent_payment_pubkey,
            },
            execution: ExecutionMode::ManualWallet,
            wallet_hint: "Use any BIP-21 compatible wallet (BlueWallet, Sparrow, Electrum, etc.)"
                .to_string(),
        });
    }

    // 3. ARK — fallback when on-chain fees are high
    if is_ark_available(methods) {
        let method = first_ark_method(methods).unwrap().clone();
        let (server, pubkey, is_arkade, reason) = match &method {
            PaymentMethod::Ark {
                server,
                pubkey,
                opaque_uri,
                ..
            } => {
                let reason = if is_onchain_available(methods) {
                    format!(
                        "On-chain fee ({} sat/vB) exceeds {} sat/vB. Falling back to Ark.",
                        selected_fee_rate, ONCHAIN_FEE_THRESHOLD_SAT_VB
                    )
                } else {
                    "No Lightning (amount above threshold) or on-chain method. Using Ark."
                        .to_string()
                };
                (server.clone(), pubkey.clone(), opaque_uri.is_some(), reason)
            }
            _ => unreachable!(),
        };

        let (swap_directive, execution, wallet_hint) = if is_arkade {
            (
                SwapDirective::ArkadeManual,
                ExecutionMode::ManualWallet,
                "Open Arkade.money wallet to complete the VTXO transfer.".to_string(),
            )
        } else {
            (
                SwapDirective::ArkTransfer { server, pubkey },
                ExecutionMode::TestnetExperimental,
                "Ark VTXO transfer (testnet preview).".to_string(),
            )
        };

        return Ok(RouteQuote {
            selected_method: method,
            reason,
            estimated_fee_sats: 1, // Ark server absorbs fees
            estimated_confirmation: "near-instant via Ark round".to_string(),
            fee_snapshot: Some(fees.clone()),
            swap_directive,
            execution,
            wallet_hint,
        });
    }

    // 4. LAST RESORT: on-chain even with high fees, but warn the user
    if is_onchain_available(methods) {
        let method = first_onchain_method(methods).unwrap().clone();
        let fee = estimate_onchain_fee(req.amount_sats, selected_fee_rate);
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
                "⚠ On-chain fee rate is high ({} sat/vB) but no alternative rail is available. Consider waiting for lower fees.",
                selected_fee_rate
            ),
            estimated_fee_sats: fee,
            estimated_confirmation: expected_conf.to_string(),
            fee_snapshot: Some(fees.clone()),
            swap_directive: SwapDirective::ChainSwap { target_address, silent_payment_pubkey },
            execution: ExecutionMode::ManualWallet,
            wallet_hint: "Use any BIP-21 compatible wallet.".to_string(),
        });
    }

    Err(format!(
        "No usable rail for {} sats to {}. Lightning: {} sats threshold not met or no LN method. On-chain: fee {} sat/vB > {} sat/vB. Ark: no method configured.",
        req.amount_sats, req.alias, LIGHTNING_THRESHOLD_SATS, selected_fee_rate, ONCHAIN_FEE_THRESHOLD_SAT_VB
    ))
}

/// Async wrapper that fetches live fees from mempool.space
pub async fn select_route_live(req: &RouteRequest) -> Result<RouteQuote, String> {
    let fees = match fetch_fee_estimate().await {
        Ok(f) => f,
        Err(_) => FALLBACK_FEES.clone(),
    };
    select_route(req, &fees)
}

/// Fetch fee estimates from mempool.space
pub async fn fetch_fee_estimate() -> Result<FeeEstimate, String> {
    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::Cors);

    let request =
        Request::new_with_str_and_init("https://mempool.space/api/v1/fees/recommended", &opts)
            .map_err(|e| format!("Request creation failed: {:?}", e))?;

    let window = window().ok_or("no window")?;
    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("Fetch failed: {:?}", e))?;
    let response: Response = resp_value.dyn_into().map_err(|_| "Invalid response")?;

    if !response.ok() {
        return Ok(FALLBACK_FEES.clone());
    }

    let json_value = JsFuture::from(
        response
            .json()
            .map_err(|e| format!("JSON parse failed: {:?}", e))?,
    )
    .await
    .map_err(|e| format!("JSON parse failed: {:?}", e))?;

    let estimate: serde_json::Value = serde_wasm_bindgen::from_value(json_value)
        .map_err(|e| format!("Deserialization failed: {:?}", e))?;

    Ok(FeeEstimate {
        fastest_fee: estimate["fastestFee"].as_u64().unwrap_or(10),
        half_hour_fee: estimate["halfHourFee"].as_u64().unwrap_or(10),
        hour_fee: estimate["hourFee"].as_u64().unwrap_or(10),
        economy_fee: estimate["economyFee"].as_u64().unwrap_or(5),
        minimum_fee: estimate["minimumFee"].as_u64().unwrap_or(1),
    })
}

/// Build a payable QR only when the address, network, and amount can be checked.
/// Unsupported rails must not be rendered as apparently payable wallet handoffs.
pub fn build_qr_payload(method: &PaymentMethod, amount_sats: u64) -> Result<String, String> {
    if amount_sats == 0 || amount_sats > 21_000_000 * 100_000_000 {
        return Err("amount must be positive and within the Bitcoin supply".into());
    }
    match method {
        PaymentMethod::Lightning { .. } => {
            Err("Lightning pointers cannot bind the amount; a verified invoice is required".into())
        }
        PaymentMethod::Onchain {
            network,
            address,
            silent_payment_pubkey,
            ..
        } => {
            if silent_payment_pubkey.is_some() {
                return Err("silent payment handoffs require wallet-side validation".into());
            }
            let address = address.as_deref().ok_or("on-chain method has no address")?;
            if address.trim() != address || address.len() > 128 {
                return Err("malformed on-chain address".into());
            }
            let expected = match network {
                BitcoinNetwork::Mainnet => Network::Bitcoin,
                BitcoinNetwork::Testnet => Network::Testnet,
                BitcoinNetwork::Regtest => Network::Regtest,
            };
            let parsed = Address::from_str(address).map_err(|_| "invalid on-chain address")?;
            if !parsed.is_valid_for_network(expected) {
                return Err("on-chain address network mismatch".into());
            }
            if *network != BitcoinNetwork::Mainnet
                && parsed.is_valid_for_network(Network::Testnet)
                && parsed.is_valid_for_network(Network::Regtest)
            {
                return Err("ambiguous testnet/regtest legacy address".into());
            }
            Ok(format!(
                "bitcoin:{address}?amount={}.{:08}",
                amount_sats / 100_000_000,
                amount_sats % 100_000_000
            ))
        }
        PaymentMethod::Ark { .. } => {
            Err("Ark pointers require protocol-aware wallet validation".into())
        }
    }
}

// ===== High-level quote function =====

/// Full quote pipeline: resolve → verify → route → build QR
pub async fn quote(recipient: &str, amount_sats: u64) -> Result<QuoteResponse, String> {
    if amount_sats == 0 || amount_sats > 21_000_000 * 100_000_000 {
        return Ok(QuoteResponse::NoRoute {
            reason: "amount must be positive and within the Bitcoin supply".into(),
        });
    }
    // 1. Resolve
    let chain_resolver = ChainResolver::new();
    let signed_json = chain_resolver.resolve_alias(recipient).await?;

    // Parse the JSON string to get the profile
    let mut signed: SignedPaymentProfile =
        serde_json::from_str(&signed_json).map_err(|e| e.to_string())?;

    // 2. Verify signature
    let profile_json = serde_json::to_string(&signed.profile).map_err(|e| e.to_string())?;
    if !crate::verify_signed_profile(&profile_json) {
        let recipient_info = build_recipient_info(&signed.profile, false);
        return Ok(QuoteResponse::InvalidSignature {
            recipient: recipient_info,
        });
    }

    let recipient_info = build_recipient_info(&signed.profile, true);

    // 3. Check expiry
    if let Some(expires) = signed.profile.expires_at {
        if expires * 1000 < js_sys::Date::now() as i64 {
            return Ok(QuoteResponse::NoRoute {
                reason: "Profile expired.".to_string(),
            });
        }
    }

    // 4. Filter to methods that can produce a validated payable QR before routing.
    let mut last_payload_err = None;
    signed
        .profile
        .methods
        .retain(|method| match build_qr_payload(method, amount_sats) {
            Ok(_) => true,
            Err(reason) => {
                last_payload_err = Some(reason);
                false
            }
        });
    if signed.profile.methods.is_empty() {
        return Ok(QuoteResponse::NoRoute {
            reason: last_payload_err
                .unwrap_or_else(|| "No usable rail found in profile.".to_string()),
        });
    }

    // 5. Route selection
    let route_req = RouteRequest {
        alias: recipient.to_string(),
        amount_sats: amount_sats,
        signed_profile: signed.clone(),
        urgency: PaymentUrgency::Normal,
        max_fee_sats: None,
        max_fee_percent: None,
    };

    let route_quote = select_route_live(&route_req).await?;

    // No invoice is fetched in this layer: a Lightning pointer or experimental
    // offer cannot be used as an amount-bound wallet handoff.
    let qr = match build_qr_payload(&route_quote.selected_method, amount_sats) {
        Ok(qr) => qr,
        Err(reason) => return Ok(QuoteResponse::NoRoute { reason }),
    };

    Ok(QuoteResponse::Ok {
        recipient: recipient_info,
        selected_method: route_quote.selected_method,
        fee_sats: route_quote.estimated_fee_sats,
        eta: route_quote.estimated_confirmation,
        reason: route_quote.reason,
        qr,
        execution: route_quote.execution,
        wallet_hint: route_quote.wallet_hint,
    })
}

fn build_recipient_info(profile: &crate::types::PaymentProfile, verified: bool) -> QuoteRecipient {
    QuoteRecipient {
        alias: profile.alias.clone(),
        verified,
        profile_signature_verified: verified,
        identifier_verified: false,
        identifier_verification:
            "identifier-only; no inbox/domain ownership proof in this response".to_string(),
        fingerprint: Some(fingerprint_pubkey(&profile.identity_pubkey)),
    }
}

// ===== Helpers =====

fn is_lightning_available(method: &PaymentMethod) -> bool {
    matches!(method, PaymentMethod::Lightning { .. })
}

fn is_lightning_available_for_amount(method: &PaymentMethod, _amount_sats: u64) -> bool {
    if let PaymentMethod::Lightning {
        lightning_address,
        lnurl,
        bolt12,
        ..
    } = method
    {
        lightning_address.is_some() || lnurl.is_some() || bolt12.is_some()
    } else {
        false
    }
}

fn is_onchain_available(methods: &[PaymentMethod]) -> bool {
    methods
        .iter()
        .any(|m| matches!(m, PaymentMethod::Onchain { .. }))
}

fn first_onchain_method(methods: &[PaymentMethod]) -> Option<&PaymentMethod> {
    methods
        .iter()
        .find(|m| matches!(m, PaymentMethod::Onchain { .. }))
}

fn is_ark_available(methods: &[PaymentMethod]) -> bool {
    methods
        .iter()
        .any(|m| matches!(m, PaymentMethod::Ark { .. }))
}

fn first_ark_method(methods: &[PaymentMethod]) -> Option<&PaymentMethod> {
    methods
        .iter()
        .find(|m| matches!(m, PaymentMethod::Ark { .. }))
}

fn estimate_lightning_fee(amount_sats: u64) -> u64 {
    (amount_sats as f64 * 0.0001).ceil() as u64 // ~10 ppm
}

fn estimate_onchain_fee(_amount_sats: u64, fee_rate_sat_vb: u64) -> u64 {
    // ~140 vbytes for 1-in-2-out taproot
    (140 * fee_rate_sat_vb).max(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lightning_threshold() {
        assert_eq!(LIGHTNING_THRESHOLD_SATS, 100_000);
    }

    #[test]
    fn onchain_fee_threshold() {
        assert_eq!(ONCHAIN_FEE_THRESHOLD_SAT_VB, 10);
    }

    #[test]
    fn test_build_qr_payload_rejects_unsupported_silent_payment() {
        let method = PaymentMethod::Onchain {
            label: "Main".to_string(),
            network: crate::types::BitcoinNetwork::Mainnet,
            address: Some("bc1qold".to_string()),
            silent_payment_pubkey: Some(
                "sp1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".to_string(),
            ),
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        };

        assert!(build_qr_payload(&method, 100_000).is_err());
    }

    #[test]
    fn test_build_qr_payload_requires_valid_network_and_amount() {
        let method = PaymentMethod::Onchain {
            label: "Main".to_string(),
            network: crate::types::BitcoinNetwork::Mainnet,
            address: Some("1BoatSLRHtKNngkdXEeobR76b53LETtpyT".to_string()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        };

        let payload = build_qr_payload(&method, 50_000).unwrap();
        assert_eq!(
            payload,
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00050000"
        );
        assert!(build_qr_payload(&method, 0).is_err());
        assert!(build_qr_payload(&method, u64::MAX).is_err());
        let mut wrong_network = method.clone();
        if let PaymentMethod::Onchain { network, .. } = &mut wrong_network {
            *network = BitcoinNetwork::Testnet;
        }
        assert!(build_qr_payload(&wrong_network, 50_000).is_err());
        let mut invalid_address = method;
        if let PaymentMethod::Onchain { address, .. } = &mut invalid_address {
            *address = Some("bc1qold".into());
        }
        assert!(build_qr_payload(&invalid_address, 50_000).is_err());
    }

    #[test]
    fn test_build_qr_payload_rejects_unbound_lightning_and_ark() {
        let lightning = PaymentMethod::Lightning {
            label: "Lightning".into(),
            lightning_address: Some("alice@example.com".into()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        };
        assert!(build_qr_payload(&lightning, 50_000).is_err());
        let ark = PaymentMethod::Ark {
            label: "Ark".into(),
            server: "https://ark.example.com".into(),
            pubkey: "02".repeat(33),
            vtxo_pointer: None,
            opaque_uri: None,
            proof: None,
            expires_at: None,
        };
        assert!(build_qr_payload(&ark, 50_000).is_err());
    }

    #[test]
    fn quote_js_rejects_fractional_non_finite_and_out_of_range_amounts() {
        for amount in [
            0.0,
            -1.0,
            1.5,
            f64::NAN,
            f64::INFINITY,
            21_000_001.0 * 100_000_000.0,
        ] {
            assert!(checked_amount_sats(amount).is_err());
        }
        assert_eq!(checked_amount_sats(50_000.0).unwrap(), 50_000);
    }
}

fn checked_amount_sats(amount_sats: f64) -> Result<u64, String> {
    if !amount_sats.is_finite()
        || amount_sats.fract() != 0.0
        || !(1.0..=2_100_000_000_000_000.0).contains(&amount_sats)
    {
        return Err("amount must be a positive whole number of sats within Bitcoin supply".into());
    }
    Ok(amount_sats as u64)
}

#[wasm_bindgen(js_name = quote)]
pub async fn quote_js(recipient: &str, amount_sats: f64) -> Result<JsValue, JsValue> {
    let amount_sats = checked_amount_sats(amount_sats).map_err(|e| JsValue::from_str(&e))?;
    match quote(recipient, amount_sats).await {
        Ok(resp) => {
            Ok(serde_wasm_bindgen::to_value(&resp)
                .map_err(|e| JsValue::from_str(&e.to_string()))?)
        }
        Err(e) => Err(JsValue::from_str(&e)),
    }
}
