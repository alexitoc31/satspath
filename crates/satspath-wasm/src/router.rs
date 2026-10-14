//! WASM-compatible router — TypeScript port of Rust satspath-router logic

use crate::types::{
    ExecutionMode, FeeEstimate, FeeRateSnapshot, Invite, PaymentMethod, PaymentUrgency,
    QuoteRecipient, QuoteResponse, RouteQuote, RouteRequest, SignedPaymentProfile, SwapDirective,
};

use crate::{fingerprint_pubkey, mask_identifier, ChainResolver};

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
    satspath_handoff::amount(req.amount_sats)?;
    let valid_methods: Vec<_> = req
        .signed_profile
        .profile
        .methods
        .iter()
        .filter(|method| crate::handoff::validate_method(method, req.amount_sats).is_ok())
        .cloned()
        .collect();
    if valid_methods.is_empty() {
        return Err("no validated payment methods".into());
    }
    let methods = &valid_methods;

    // 1. LIGHTNING — evaluated FIRST, independent of fee environment
    if req.amount_sats < LIGHTNING_THRESHOLD_SATS {
        for method in methods.iter().filter(|m| is_lightning_available(m)) {
            if !is_lightning_available_for_amount(method, req.amount_sats) {
                continue;
            }
            let swap_directive = match method {
                PaymentMethod::Lightning {
                    bolt12: Some(invoice),
                    ..
                } if invoice.to_ascii_lowercase().starts_with("lnbc") => {
                    SwapDirective::LightningPayment {
                        target_ln_address: None,
                    }
                }
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

/// Build QR payload for a payment method
pub fn build_qr_payload(method: &PaymentMethod, amount_sats: u64) -> Result<String, String> {
    crate::handoff::validate_method(method, amount_sats)?;
    match method {
        PaymentMethod::Lightning {
            lnurl,
            lightning_address,
            bolt12,
            ..
        } => Ok(lnurl
            .clone()
            .or_else(|| lightning_address.clone())
            .or_else(|| bolt12.clone())
            .ok_or_else(|| "Lightning method has no address, LNURL, or BOLT12".to_string())?),
        PaymentMethod::Onchain {
            address,
            silent_payment_pubkey,
            ..
        } => {
            let target = silent_payment_pubkey
                .clone()
                .unwrap_or_else(|| address.clone().unwrap_or_default());
            let btc = format!(
                "{}.{:08}",
                amount_sats / 100_000_000,
                amount_sats % 100_000_000
            );
            Ok(format!("bitcoin:{}?amount={}", target, btc))
        }
        PaymentMethod::Ark { server, pubkey, .. } => {
            // Simple URL encoding - replace special chars
            let encode = |s: &str| {
                s.replace(' ', "%20")
                    .replace('&', "%26")
                    .replace('=', "%3D")
                    .replace('?', "%3F")
                    .replace('#', "%23")
            };
            Ok(format!(
                "ark:{}?server={}&amount={}",
                encode(pubkey),
                encode(server),
                amount_sats
            ))
        }
    }
}

// ===== High-level quote function =====

/// Full quote pipeline: resolve → verify → route → build QR
pub async fn quote(recipient: &str, amount_sats: u64) -> Result<QuoteResponse, String> {
    // 1. Resolve
    let chain_resolver = ChainResolver::new();
    let signed_json = chain_resolver.resolve_alias(recipient).await?;

    // Parse the JSON string to get the profile
    let signed: SignedPaymentProfile =
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

    // 4. Route selection
    let route_req = RouteRequest {
        alias: recipient.to_string(),
        amount_sats: amount_sats,
        signed_profile: signed.clone(),
        urgency: PaymentUrgency::Normal,
        max_fee_sats: None,
        max_fee_percent: None,
    };

    let route_quote = select_route_live(&route_req).await?;

    // 5. Build QR payload
    let mut qr = build_qr_payload(&route_quote.selected_method, amount_sats)?;

    // 6. Optionally fetch real BOLT11 for Lightning
    if let PaymentMethod::Lightning {
        lightning_address,
        bolt12,
        ..
    } = &route_quote.selected_method
    {
        if let Some(addr) = lightning_address {
            if let Ok(invoice) = fetch_real_invoice(addr, amount_sats).await {
                qr = invoice;
            }
        } else if let Some(offer) = bolt12 {
            let proxy = "https://bolt12-proxy.satspath.dev";
            if let Ok(invoice) =
                crate::bolt12::fetch_bolt12_invoice(offer, amount_sats, proxy).await
            {
                qr = invoice;
            }
        }
    }

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

/// Fetch real BOLT11 invoice from LNURL-pay
async fn fetch_real_invoice(lightning_address: &str, amount_sats: u64) -> Result<String, String> {
    let [user, domain] = lightning_address
        .split('@')
        .collect::<Vec<_>>()
        .try_into()
        .map_err(|_| "Invalid lightning address")?;
    let lnurl = format!("https://{}/.well-known/lnurlp/{}", domain, user);

    let mut opts = RequestInit::new();
    opts.method("GET");
    opts.mode(RequestMode::Cors);

    let request = Request::new_with_str_and_init(&lnurl, &opts)
        .map_err(|e| format!("LNURL request failed: {:?}", e))?;

    let win = web_sys::window().ok_or("no window")?;
    let resp_value = JsFuture::from(win.fetch_with_request(&request))
        .await
        .map_err(|e| format!("LNURL fetch failed: {:?}", e))?;
    let response: Response = resp_value
        .dyn_into()
        .map_err(|_| "Invalid LNURL response")?;

    if !response.ok() {
        return Err("LNURL fetch failed".to_string());
    }

    let json_value = JsFuture::from(
        response
            .json()
            .map_err(|e| format!("LNURL JSON failed: {:?}", e))?,
    )
    .await
    .map_err(|e| format!("LNURL JSON parse failed: {:?}", e))?;

    let meta: serde_json::Value = serde_wasm_bindgen::from_value(json_value)
        .map_err(|e| format!("LNURL deserialize failed: {:?}", e))?;

    let callback = meta["callback"].as_str().ok_or("No callback in LNURL")?;
    let mut callback_url = format!("{}?amount={}", callback, amount_sats * 1000); // msats

    let inv_request = Request::new_with_str_and_init(&callback_url, &RequestInit::new())
        .map_err(|e| format!("Invoice request failed: {:?}", e))?;

    let win2 = web_sys::window().ok_or("no window")?;
    let inv_resp_value = JsFuture::from(win2.fetch_with_request(&inv_request))
        .await
        .map_err(|e| format!("Invoice fetch failed: {:?}", e))?;
    let inv_response: Response = inv_resp_value
        .dyn_into()
        .map_err(|_| "Invalid invoice response")?;

    if !inv_response.ok() {
        return Err("Invoice fetch failed".to_string());
    }

    let inv_json = JsFuture::from(
        inv_response
            .json()
            .map_err(|e| format!("Invoice JSON failed: {:?}", e))?,
    )
    .await
    .map_err(|e| format!("Invoice JSON parse failed: {:?}", e))?;

    let invoice: serde_json::Value = serde_wasm_bindgen::from_value(inv_json)
        .map_err(|e| format!("Invoice deserialize failed: {:?}", e))?;

    invoice["pr"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| "No invoice in response".to_string())
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

    /// Invalid or cross-network receivers cannot become browser QR payloads or routes.
    #[test]
    fn rejects_invalid_wallet_handoffs() {
        let mut method = PaymentMethod::Onchain {
            label: "receiver".into(),
            network: crate::BitcoinNetwork::Mainnet,
            address: Some("1BoatSLRHtKNngkdXEeobR76b53LETtpyT".into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        };
        for amount in [0, u64::MAX] {
            assert!(build_qr_payload(&method, amount).is_err());
        }
        if let PaymentMethod::Onchain { network, .. } = &mut method {
            *network = crate::BitcoinNetwork::Testnet;
        }
        assert!(build_qr_payload(&method, 1000).is_err());
        for payload in ["lno1invalid", "lnbc1invalid"] {
            let method = PaymentMethod::Lightning {
                label: "bad".into(),
                lightning_address: None,
                lnurl: None,
                bolt12: Some(payload.into()),
                receiver_pubkey: None,
            };
            assert!(build_qr_payload(&method, 1000).is_err());
        }
        let method = PaymentMethod::Ark {
            label: "expired".into(),
            server: "https://ark.example".into(),
            pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
            vtxo_pointer: None,
            opaque_uri: None,
            proof: None,
            expires_at: Some(1),
        };
        assert!(build_qr_payload(&method, 1000).is_err());
    }

    #[test]
    fn lightning_threshold() {
        assert_eq!(LIGHTNING_THRESHOLD_SATS, 100_000);
    }

    #[test]
    fn onchain_fee_threshold() {
        assert_eq!(ONCHAIN_FEE_THRESHOLD_SAT_VB, 10);
    }

    #[test]
    /// Verify that build qr payload silent payment.
    fn test_build_qr_payload_silent_payment() {
        use bech32::ToBase32;
        let key = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap();
        let mut data = vec![bech32::u5::try_from_u8(0).unwrap()];
        data.extend([key.clone(), key].concat().to_base32());
        let silent = bech32::encode("sp", data, bech32::Variant::Bech32m).unwrap();

        let method = PaymentMethod::Onchain {
            label: "Main".to_string(),
            network: crate::types::BitcoinNetwork::Mainnet,
            address: Some("1BoatSLRHtKNngkdXEeobR76b53LETtpyT".to_string()),
            silent_payment_pubkey: Some(silent.clone()),
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        };

        let payload = build_qr_payload(&method, 100_000).unwrap();
        // Should prioritize silent_payment_pubkey over address
        assert_eq!(payload, format!("bitcoin:{silent}?amount=0.00100000"));
    }

    #[test]
    /// Verify that build qr payload fallback address.
    fn test_build_qr_payload_fallback_address() {
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
    }
}
#[wasm_bindgen(js_name = quote)]
pub async fn quote_js(recipient: &str, amount_sats: f64) -> Result<JsValue, JsValue> {
    if !amount_sats.is_finite()
        || amount_sats.fract() != 0.0
        || amount_sats < 1.0
        || amount_sats > satspath_handoff::MAX_SATS as f64
    {
        return Err(JsValue::from_str(
            "amount must be an integral, positive number of satoshis within Bitcoin supply",
        ));
    }
    match quote(recipient, amount_sats as u64).await {
        Ok(resp) => {
            Ok(serde_wasm_bindgen::to_value(&resp)
                .map_err(|e| JsValue::from_str(&e.to_string()))?)
        }
        Err(e) => Err(JsValue::from_str(&e)),
    }
}
