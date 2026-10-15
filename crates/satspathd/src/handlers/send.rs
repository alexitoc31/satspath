//! Send, receive, broadcast, and email invite handlers.

use anyhow::Result;
use satspath_core::{
    privacy::mask_identifier,
    validation::{assert_no_private_material, validate_amount_sats},
    PaymentMethod, ProfileResolver, SatsPathError,
};
use satspath_router::{
    fees::fetch_fee_estimate,
    handoff::{fmt_btc, validate_payload},
    select_priority_route,
};

use crate::config::AppState;
use crate::handlers::profile::ensure_signed_profile;
use crate::handlers::resolve::resolver_chain;
use crate::handlers::wallet::load_wallet;
use crate::types::{
    build_methods, pct, safety_status, EmailInvite, ReceiveRequest, ReceiveView, SendRequest,
    SendResponse,
};
use crate::ui::qr_svg;

/// Choose a configured receive rail and validate its final public QR payload.
pub(crate) fn receive_view(state: &AppState, req: ReceiveRequest) -> Result<ReceiveView> {
    let wallet = load_wallet(&state.home)?;
    let alias = wallet
        .alias
        .clone()
        .ok_or_else(|| anyhow::anyhow!("no profile yet -- set one via POST /v1/profile"))?;
    let methods = build_methods(&wallet, &state.network);

    let method = if let Some(req_rail) = req.rail {
        let req_rail = req_rail.to_lowercase();
        methods
            .into_iter()
            .find(|m| m.method_name().to_lowercase() == req_rail)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "requested rail '{}' is not configured in your profile",
                    req_rail
                )
            })?
    } else {
        let onchain = methods
            .iter()
            .find(|m| matches!(m, PaymentMethod::Onchain { .. }));
        let lightning = methods
            .iter()
            .find(|m| matches!(m, PaymentMethod::Lightning { .. }));
        (if req.amount_sats.is_some() {
            onchain.or(lightning)
        } else {
            lightning.or(onchain)
        })
        .or_else(|| {
            methods
                .iter()
                .find(|m| matches!(m, PaymentMethod::Ark { .. }))
        })
        .ok_or_else(|| {
            anyhow::anyhow!("no receive methods -- add one via POST /v1/profile/methods")
        })?
        .clone()
    };

    let mut payload = receive_payload_for(&method)?;

    // Append amount if requested
    if let Some(sats) = req.amount_sats {
        if matches!(method, PaymentMethod::Onchain { .. }) {
            payload = format!("{}?amount={}", payload, fmt_btc(sats));
        } else if matches!(method, PaymentMethod::Ark { .. }) {
            payload = format!("{}&amount={}", payload, sats);
        }
        // Note: Lightning Address/LNURL doesn't support amount in the static string.
    }

    validate_payload(&method, &payload, &state.network, req.amount_sats)?;

    Ok(ReceiveView {
        alias: mask_identifier(&alias),
        rail: method.method_name().to_string(),
        qr_svg: qr_svg(&payload)?,
        payload,
    })
}

/// A public, amount-less receive pointer for a method.
pub(crate) fn receive_payload_for(method: &PaymentMethod) -> Result<String> {
    let payload = match method {
        PaymentMethod::Lightning {
            lightning_address: Some(addr),
            ..
        } => addr.clone(),
        PaymentMethod::Lightning {
            lnurl: Some(url), ..
        } => url.clone(),
        PaymentMethod::Onchain {
            address,
            silent_payment_pubkey,
            ..
        } => {
            let target = silent_payment_pubkey
                .clone()
                .unwrap_or_else(|| address.clone().unwrap_or_default());
            format!("bitcoin:{target}")
        }
        PaymentMethod::Ark { server, pubkey, .. } => {
            format!("satspath:ark?server={server}&pubkey={pubkey}")
        }
        _ => anyhow::bail!("selected method has no receive pointer"),
    };
    assert_no_private_material(&payload)?;
    Ok(payload)
}

/// Resolve the recipient, pick a rail by priority, and return the best QR.
/// If the recipient is not registered, return an EXPERIMENTAL email invite.
pub(crate) async fn send_response(state: &AppState, body: SendRequest) -> SendResponse {
    if let Err(e) = validate_amount_sats(body.amount_sats) {
        return SendResponse::NoRoute {
            reason: e.to_string(),
        };
    }
    let resolver = resolver_chain(&state.home);
    send_response_with_resolver(state, body, &resolver).await
}

/// Resolve a recipient through the supplied resolver and gate its payable QR.
pub(crate) async fn send_response_with_resolver(
    state: &AppState,
    body: SendRequest,
    resolver: &(impl ProfileResolver + Sync),
) -> SendResponse {
    if let Err(e) = validate_amount_sats(body.amount_sats) {
        return SendResponse::NoRoute {
            reason: e.to_string(),
        };
    }
    match resolver.resolve_alias(&body.recipient).await {
        Ok(signed) => {
            if !matches!(
                satspath_core::crypto::verify_signed_profile(&signed),
                Ok(true)
            ) {
                return SendResponse::InvalidSignature {
                    recipient: mask_identifier(&body.recipient),
                };
            }
            let fee = fetch_fee_estimate().await;
            let routing_ok = body.routing_ok.unwrap_or(true);
            let payable_methods =
                payable_methods(&signed.profile.methods, body.amount_sats, &state.network);
            match select_priority_route(
                body.amount_sats,
                &fee.unwrap_or_default(),
                &payable_methods,
                routing_ok,
            ) {
                Some(decision) => {
                    let payload = match send_payload_for(&decision.method, body.amount_sats)
                        .and_then(|payload| {
                            validate_payload(
                                &decision.method,
                                &payload,
                                &state.network,
                                Some(body.amount_sats),
                            )?;
                            Ok(payload)
                        }) {
                        Ok(p) => p,
                        Err(e) => {
                            return SendResponse::NoRoute {
                                reason: e.to_string(),
                            }
                        }
                    };
                    let qr = match qr_svg(&payload) {
                        Ok(q) => q,
                        Err(e) => {
                            return SendResponse::NoRoute {
                                reason: e.to_string(),
                            }
                        }
                    };
                    SendResponse::Ok {
                        mode: "preview_only",
                        rail: decision.rail.to_string(),
                        reason: decision.reason,
                        recipient: mask_identifier(&body.recipient),
                        profile_signature_verified: true,
                        identifier_verified: false,
                        identifier_verification:
                            "identifier-only; no inbox/domain ownership proof in this response",
                        amount_sats: body.amount_sats,
                        payload,
                        qr_svg: qr,
                        safety: safety_status(),
                    }
                }
                None => SendResponse::NoRoute {
                    reason: "recipient exposes no safely payable rail".to_string(),
                },
            }
        }
        Err(SatsPathError::Bip353Unauthenticated) => SendResponse::NoRoute {
            reason: SatsPathError::Bip353Unauthenticated.to_string(),
        },
        Err(_) => {
            let secret_opt = load_wallet(&state.home).ok().and_then(|w| {
                w.identity_pubkey.and_then(|pk| {
                    crate::handlers::wallet::load_identity_key(&state.home, &pk).ok()
                })
            });
            let invite = satspath_core::create_invite(
                &body.recipient,
                body.amount_sats,
                secret_opt.as_ref(),
                86400,
            );

            // Persist invite record to InviteStore
            if let Ok(mut store) = satspath_core::InviteStore::open(&state.home) {
                let sender_fp = secret_opt
                    .as_ref()
                    .map(|sk| {
                        let secp = secp256k1::Secp256k1::new();
                        let pk = secp256k1::PublicKey::from_secret_key(&secp, sk);
                        hex::encode(pk.serialize())
                    })
                    .unwrap_or_else(|| "local-sender".to_string());

                let mut record = satspath_core::create_signed_invite_record(
                    &body.recipient,
                    body.amount_sats,
                    None,
                    sender_fp,
                    86400,
                    secret_opt.as_ref(),
                );
                if let Some(ref iid) = invite.invite_id {
                    record.invite_id = iid.clone();
                }
                let _ = store.insert(record);
            }

            let email = build_email_invite(&body.recipient, body.amount_sats, &invite.claim_url);
            SendResponse::Invite {
                mode: "preview_only",
                experimental: true,
                recipient_hint: mask_identifier(&body.recipient),
                amount_sats: body.amount_sats,
                claim_url: invite.claim_url,
                email,
                safety: safety_status(),
            }
        }
    }
}

/// Retain only signed-profile methods that can produce a validated payable QR.
fn payable_methods(
    methods: &[PaymentMethod],
    amount_sats: u64,
    network: &str,
) -> Vec<PaymentMethod> {
    methods
        .iter()
        .filter(|method| {
            send_payload_for(method, amount_sats)
                .and_then(|payload| validate_payload(method, &payload, network, Some(amount_sats)))
                .is_ok()
        })
        .cloned()
        .collect()
}

/// Build an experimental invite for an alias without a usable signed profile.
pub(crate) fn build_email_invite(
    recipient: &str,
    amount_sats: u64,
    claim_url: &str,
) -> EmailInvite {
    let subject = "You were sent Bitcoin with SatsPath".to_string();
    let body = format!(
        r"Someone wants to send you {amount_sats} sats with SatsPath.

Press the button to download the SatsPath wallet and receive your funds
locally. You generate your own keys; nobody custodies them:

{claim_url}

[EXPERIMENTAL] SatsPath does not move funds or sign transactions for you."
    );
    let mailto = format!(
        "mailto:{}?subject={}&body={}",
        recipient,
        pct(&subject),
        pct(&body)
    );
    EmailInvite {
        to: recipient.to_string(),
        subject,
        body,
        mailto,
    }
}

/// A payable pointer for a method, including the amount where the URI supports it.
pub(crate) fn send_payload_for(method: &PaymentMethod, amount_sats: u64) -> Result<String> {
    let payload = match method {
        PaymentMethod::Lightning {
            lightning_address: Some(a),
            ..
        } => a.clone(),
        PaymentMethod::Lightning { lnurl: Some(u), .. } => u.clone(),
        PaymentMethod::Onchain {
            address,
            silent_payment_pubkey,
            ..
        } => {
            let target = silent_payment_pubkey
                .clone()
                .unwrap_or_else(|| address.clone().unwrap_or_default());
            format!("bitcoin:{target}?amount={}", fmt_btc(amount_sats))
        }
        PaymentMethod::Ark { server, pubkey, .. } => {
            format!("satspath:ark?server={server}&pubkey={pubkey}&amount={amount_sats}")
        }
        _ => anyhow::bail!("selected method has no payable pointer"),
    };
    assert_no_private_material(&payload)?;
    Ok(payload)
}

/// Save the profile; enabled transports independently manage publication.
pub(crate) fn broadcast(state: &AppState) -> Result<serde_json::Value> {
    let mut wallet = load_wallet(&state.home)?;
    if wallet.alias.is_none() {
        anyhow::bail!("set your profile first (alias + methods) before broadcasting");
    }
    ensure_signed_profile(&state.home, &mut wallet, &state.network)?;
    Ok(
        serde_json::json!({ "broadcasting": false, "status": "Profile saved. Enabled transports manage publication; saving is not proof of network availability." }),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use satspath_core::BitcoinNetwork;
    use satspath_router::fees::FeeEstimate;

    fn onchain(address: &str) -> PaymentMethod {
        PaymentMethod::Onchain {
            label: "On-chain".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some(address.into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        }
    }

    #[test]
    fn send_skips_unpayable_preferred_rails_before_selecting_route() {
        let good = onchain("1BoatSLRHtKNngkdXEeobR76b53LETtpyT");
        let methods = vec![
            onchain("invalid-address"),
            PaymentMethod::Lightning {
                label: "Lightning".into(),
                lightning_address: Some("alice@example.com".into()),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: None,
            },
            good.clone(),
        ];
        let payable = payable_methods(&methods, 21_000, "mainnet");
        assert_eq!(payable, vec![good.clone()]);

        // High fees would pick Lightning first, but its static pointer has no
        // amount-bound invoice. The router's last resort is the valid on-chain QR.
        let high_fee = FeeEstimate {
            fastest_fee: 40,
            ..FeeEstimate::default()
        };
        let selected = select_priority_route(21_000, &high_fee, &payable, true).unwrap();
        assert_eq!(selected.rail, "onchain");
        assert_eq!(selected.method, good);
        assert!(validate_payload(
            &selected.method,
            &send_payload_for(&selected.method, 21_000).unwrap(),
            "mainnet",
            Some(21_000)
        )
        .is_ok());
    }

    #[test]
    fn send_has_no_route_when_every_method_is_unpayable() {
        let methods = [PaymentMethod::Lightning {
            label: "Lightning".into(),
            lightning_address: Some("alice@example.com".into()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        }];
        assert!(payable_methods(&methods, 21_000, "mainnet").is_empty());
        assert!(payable_methods(
            &[onchain("1BoatSLRHtKNngkdXEeobR76b53LETtpyT")],
            21_000,
            "devnet"
        )
        .is_empty());
    }
}
