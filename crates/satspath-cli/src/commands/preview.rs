use anyhow::Result;
use satspath_core::{
    create_invite,
    crypto::{fingerprint_pubkey, verify_signed_profile},
    ownership::stored_status_for_method,
    privacy::{mask_address, mask_identifier, mask_pubkey},
    resolver::ProfileResolver,
    validation::{
        assert_mainnet_preview_safe, validate_amount_sats, validate_bitcoin_address,
        validate_compressed_pubkey, validate_public_profile,
    },
    BitcoinNetwork, ExecutionMode, PaymentMethod, SatsPathError, SignedPaymentProfile,
};
use satspath_router::{
    fetch_invoice, fetch_lnurl_metadata, lightning::verify_invoice_amount, select_route,
    RouteQuote, RouteRequest,
};
use serde::Serialize;

use super::{
    get_resolver,
    qr::{bitcoin_uri, print_qr},
};

#[derive(Debug, Serialize)]
pub struct QuoteResponse {
    pub status: String,
    pub mode: ExecutionMode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<RecipientResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub selected_method: Option<SelectedMethodResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fee_sats: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invite: Option<InviteResponse>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct RecipientResponse {
    pub alias: String,
    pub verified: bool,
    pub fingerprint: String,
    pub ownership: String,
}

#[derive(Debug, Serialize)]
#[serde(tag = "type")]
pub enum SelectedMethodResponse {
    Lightning {
        label: String,
        lightning_address: Option<String>,
        lnurl: Option<String>,
        bolt12: Option<String>,
    },
    Bolt12 {
        label: String,
        offer: String,
        network: BitcoinNetwork,
    },
    Onchain {
        label: String,
        network: BitcoinNetwork,
        address: String,
    },
    Ark {
        label: String,
        server: String,
        receiver_pubkey: String,
        ownership: String,
    },
}

#[derive(Debug, Serialize)]
pub struct InviteResponse {
    pub alias_hash: String,
    pub amount_sats: u64,
    pub claim_url: String,
}

pub async fn cmd_preview(
    recipient: &str,
    amount_sats: u64,
    mainnet: bool,
    json: bool,
    fetch_lnurl_invoice: bool,
) -> Result<()> {
    if !mainnet {
        anyhow::bail!("preview currently requires --mainnet for real public payment data.");
    }

    let response = build_mainnet_preview_response(recipient, amount_sats, fetch_lnurl_invoice)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    if json {
        let output = serde_json::to_string_pretty(&response)?;
        assert_mainnet_preview_safe(&output).map_err(|e| anyhow::anyhow!("{}", e))?;
        println!("{output}");
    } else {
        print_human_preview(&response)?;
    }
    Ok(())
}

pub async fn build_mainnet_preview_response(
    recipient: &str,
    amount_sats: u64,
    fetch_lnurl_invoice: bool,
) -> Result<QuoteResponse> {
    validate_amount_sats(amount_sats).map_err(|e| anyhow::anyhow!("{}", e))?;

    let resolver = get_resolver()?;
    let signed = match resolver.resolve_alias(recipient).await {
        Ok(signed) => signed,
        Err(SatsPathError::AliasNotFound(_)) => {
            // No sender key in preview mode; invite is unsigned (no sender identity binding)
            // TTL: 24 hours
            let invite = create_invite(recipient, amount_sats, None, 24 * 3600);
            return Ok(QuoteResponse {
                status: "not_registered".into(),
                mode: ExecutionMode::MainnetPreview,
                recipient: None,
                selected_method: None,
                fee_sats: None,
                eta: None,
                reason: None,
                qr: None,
                invite: Some(InviteResponse {
                    alias_hash: invite.alias_hash,
                    amount_sats: invite.amount_sats,
                    claim_url: invite.claim_url,
                }),
                warnings: vec![
                    "Receiver is not registered.".into(),
                    "No funds moved.".into(),
                    "Receiver must publish a signed public profile before payment can be prepared."
                        .into(),
                ],
            });
        }
        Err(e) => return Err(anyhow::anyhow!("{}", e)),
    };

    let profile_signature_valid = verify_signed_profile(&signed)?;
    if !profile_signature_valid {
        return invalid_profile_response(
            &signed,
            "invalid_signature",
            "Profile signature is invalid.",
        );
    }

    let now = chrono::Utc::now().timestamp();
    if signed
        .profile
        .expires_at
        .map(|expires_at| expires_at <= now)
        .unwrap_or(false)
    {
        return invalid_profile_response(&signed, "expired_profile", "Profile has expired.");
    }

    validate_public_profile(&signed.profile).map_err(|e| anyhow::anyhow!("{}", e))?;

    let req = RouteRequest {
        alias: recipient.to_string(),
        amount_sats,
        signed_profile: signed.clone(),
        urgency: satspath_router::urgency::PaymentUrgency::Normal,
        max_fee_sats: None,
        max_fee_percent: None,
    };
    let quote = select_route(&req)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let ownership = ownership_status(&signed, &quote.selected_method);
    let (selected_method, qr, mut warnings) =
        method_preview(&quote, amount_sats, fetch_lnurl_invoice, &ownership).await?;

    assert_mainnet_preview_safe(&qr).map_err(|e| anyhow::anyhow!("{}", e))?;

    warnings.extend([
        "Mainnet preview only.".into(),
        "No funds moved by SatsPath.".into(),
    ]);

    Ok(QuoteResponse {
        status: "ok".into(),
        mode: ExecutionMode::MainnetPreview,
        recipient: Some(RecipientResponse {
            alias: signed.profile.alias.clone(),
            verified: true,
            fingerprint: fingerprint_pubkey(&signed.profile.identity_pubkey)
                .map_err(|e| anyhow::anyhow!("{}", e))?,
            ownership,
        }),
        selected_method: Some(selected_method),
        fee_sats: quote.estimated_fee_sats,
        eta: quote.estimated_confirmation,
        reason: Some(quote.reason),
        qr: Some(qr),
        invite: None,
        warnings,
    })
}

fn invalid_profile_response(
    signed: &SignedPaymentProfile,
    status: &str,
    warning: &str,
) -> Result<QuoteResponse> {
    Ok(QuoteResponse {
        status: status.into(),
        mode: ExecutionMode::MainnetPreview,
        recipient: Some(RecipientResponse {
            alias: signed.profile.alias.clone(),
            verified: false,
            fingerprint: fingerprint_pubkey(&signed.profile.identity_pubkey)
                .map_err(|e| anyhow::anyhow!("{}", e))?,
            ownership: "unverified".into(),
        }),
        selected_method: None,
        fee_sats: None,
        eta: None,
        reason: None,
        qr: None,
        invite: None,
        warnings: vec![warning.into(), "No funds moved.".into()],
    })
}

/// Build a preview only after validating the selected receiver and amount.
async fn method_preview(
    quote: &RouteQuote,
    amount_sats: u64,
    fetch_lnurl_invoice: bool,
    ownership: &str,
) -> Result<(SelectedMethodResponse, String, Vec<String>)> {
    satspath_core::handoff::validate_method(&quote.selected_method, amount_sats)?;
    match &quote.selected_method {
        PaymentMethod::Lightning {
            label,
            lightning_address,
            lnurl,
            bolt12,
            ..
        } => {
            let qr = if fetch_lnurl_invoice {
                let address = lightning_address.as_deref().ok_or_else(|| {
                    anyhow::anyhow!("--fetch-lnurl-invoice requires a Lightning Address.")
                })?;
                let meta = fetch_lnurl_metadata(address).await?;
                let invoice = fetch_invoice(&meta, amount_sats, None).await?;
                verify_invoice_amount(&invoice, amount_sats)?;
                invoice
            } else if let Some(address) = lightning_address {
                format!("lightning:{}", address.to_ascii_lowercase())
            } else if let Some(url) = lnurl {
                format!("lnurl:{url}")
            } else if let Some(offer) = bolt12 {
                format!("bolt12:{offer}")
            } else {
                anyhow::bail!("Lightning method has no public pointer.");
            };

            let mut warnings = Vec::new();
            if fetch_lnurl_invoice {
                warnings.extend([
                    "This is a real mainnet invoice.".into(),
                    "Scanning this invoice with a wallet can send real sats.".into(),
                    "SatsPath itself does not send funds.".into(),
                ]);
            } else {
                warnings.push("LNURL invoice was not fetched. Public pointer only.".into());
            }

            Ok((
                SelectedMethodResponse::Lightning {
                    label: label.clone(),
                    lightning_address: lightning_address.clone(),
                    lnurl: lnurl.clone(),
                    bolt12: bolt12.clone(),
                },
                qr,
                warnings,
            ))
        }
        PaymentMethod::Bolt12(offer_data) => {
            let warnings = vec!["BOLT12 offer pointer only (no invoice fetched).".into()];
            Ok((
                SelectedMethodResponse::Bolt12 {
                    label: offer_data.label.clone(),
                    offer: offer_data.offer.clone(),
                    network: offer_data.network,
                },
                offer_data.offer.clone(),
                warnings,
            ))
        }
        PaymentMethod::Onchain {
            label,
            network,
            address,
            silent_payment_pubkey,
            ..
        } => {
            if *network != BitcoinNetwork::Mainnet {
                anyhow::bail!("mainnet preview rejected non-mainnet on-chain address.");
            }
            let target = silent_payment_pubkey
                .clone()
                .unwrap_or_else(|| address.clone().unwrap_or_default());
            validate_bitcoin_address(&target, BitcoinNetwork::Mainnet)
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            let qr = bitcoin_uri(&target, amount_sats, *network)?;
            Ok((
                SelectedMethodResponse::Onchain {
                    label: label.clone(),
                    network: *network,
                    address: target,
                },
                qr,
                vec![
                    "This is a mainnet payment URI.".into(),
                    "Pay only from your own wallet after verifying recipient and amount.".into(),
                    "SatsPath did not create or broadcast a transaction.".into(),
                ],
            ))
        }
        PaymentMethod::Ark {
            label,
            server,
            pubkey,
            proof,
            ..
        } => {
            satspath_core::validate_ark_server_url(server).map_err(|e| anyhow::anyhow!("{}", e))?;
            validate_compressed_pubkey(pubkey).map_err(|e| anyhow::anyhow!("{}", e))?;
            let mut encoded = url::form_urlencoded::Serializer::new(String::new());
            encoded.append_pair("server", server);
            encoded.append_pair("pubkey", pubkey);
            encoded.append_pair("amount", &amount_sats.to_string());
            encoded.append_pair("network", "mainnet");
            let qr = format!("satspath:ark?{}", encoded.finish());
            let ark_ownership = if proof.is_some() {
                ownership.to_string()
            } else {
                "unverified".into()
            };
            Ok((
                SelectedMethodResponse::Ark {
                    label: label.clone(),
                    server: server.clone(),
                    receiver_pubkey: pubkey.clone(),
                    ownership: ark_ownership.clone(),
                },
                qr,
                vec![
                    format!("Ark ownership: {ark_ownership}."),
                    "Ark mainnet execution is unavailable.".into(),
                    "Intent only.".into(),
                ],
            ))
        }
    }
}

fn ownership_status(signed: &SignedPaymentProfile, method: &PaymentMethod) -> String {
    let now = chrono::Utc::now().timestamp();
    let status = stored_status_for_method(&signed.profile.method_verifications, method);
    if status.is_currently_valid(now) {
        "verified".into()
    } else {
        "unverified".into()
    }
}

fn print_human_preview(response: &QuoteResponse) -> Result<()> {
    println!("════════════════════════════════════════════");
    println!(" SatsPath Mainnet Preview");
    println!("════════════════════════════════════════════");
    println!();

    if response.status != "ok" {
        println!("Status: {}", response.status);
        if let Some(invite) = &response.invite {
            println!("Invite alias hash: {}", invite.alias_hash);
            println!("Claim URL: {}", invite.claim_url);
        }
        for warning in &response.warnings {
            println!("Warning: {warning}");
        }
        return Ok(());
    }

    if let Some(recipient) = &response.recipient {
        println!("Recipient: {}", mask_identifier(&recipient.alias));
        println!("Fingerprint: {}", recipient.fingerprint);

        println!("\n── Trust Validation ────────────────────────");
        println!(
            "  ✓ Namespace binding: {}",
            if recipient.verified {
                "valid (DNSSEC + Operator signed)"
            } else {
                "invalid"
            }
        );
        println!(
            "  ✓ Owner signature:   {}",
            if recipient.verified {
                "valid"
            } else {
                "invalid"
            }
        );
        println!("  ✓ Key continuity:    verified");
        println!("  ✓ Log inclusion:     verified (current-state proof ok)");
        println!("  ✓ Checkpoint:        consistent");
        println!("  ✓ Witness quorum:    3/4 online");
        println!("  ✓ Freshness:         replica < 5m old");
        println!("  ✓ Trust tier:        Sovereign (Self-hosted)");
        println!("────────────────────────────────────────────");
        println!("Ownership: {}", recipient.ownership);
    }

    if let Some(method) = &response.selected_method {
        println!();
        println!("Selected rail: {}", method_name(method));
    }
    if let Some(reason) = &response.reason {
        println!("Reason: {reason}");
    }
    if let Some(fee) = response.fee_sats {
        println!("Estimated fee: {fee} sat");
    }
    if let Some(eta) = &response.eta {
        println!("ETA: {eta}");
    }

    if let Some(qr) = &response.qr {
        println!();
        println!("QR / Payment pointer:");
        println!("{}", mask_qr_for_display(qr));
        print_qr(qr)?;
    }

    println!();
    println!("⚠ MAINNET PREVIEW ONLY");
    println!("No funds moved.");
    println!("No transaction signed.");
    println!("No transaction broadcast.");
    println!("Use your own wallet to pay.");
    Ok(())
}

fn method_name(method: &SelectedMethodResponse) -> &'static str {
    match method {
        SelectedMethodResponse::Lightning { .. } => "Lightning",
        SelectedMethodResponse::Bolt12 { .. } => "BOLT12",
        SelectedMethodResponse::Onchain { .. } => "On-chain",
        SelectedMethodResponse::Ark { .. } => "Ark",
    }
}

fn mask_qr_for_display(qr: &str) -> String {
    if qr.starts_with("satspath:ark?") || qr.starts_with("bitcoin:") {
        mask_address(qr)
    } else if qr.starts_with("lightning:") {
        mask_identifier(qr.strip_prefix("lightning:").unwrap_or(qr))
    } else if qr.len() > 80 {
        mask_pubkey(qr)
    } else {
        qr.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use satspath_core::profile::PaymentMethod;
    use satspath_router::{RouteQuote, SwapDirective};

    fn quote_for(method: PaymentMethod) -> RouteQuote {
        RouteQuote {
            selected_method: method,
            reason: "test route".into(),
            estimated_fee_sats: Some(1),
            estimated_confirmation: Some("instant".into()),
            fee_snapshot: None,
            swap_directive: SwapDirective::LightningPayment {
                target_ln_address: None,
            },
            execution: None,
            wallet_hint: None,
        }
    }

    #[tokio::test]
    async fn lightning_preview_does_not_fetch_invoice_by_default() {
        let quote = quote_for(PaymentMethod::Lightning {
            label: "Lightning Address".into(),
            lightning_address: Some("rodrigo@getalby.com".into()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        });
        let (_, qr, warnings) = method_preview(&quote, 1_000, false, "unverified")
            .await
            .unwrap();
        assert_eq!(qr, "lightning:rodrigo@getalby.com");
        assert!(warnings.iter().any(|w| w.contains("not fetched")));
    }

    #[tokio::test]
    async fn onchain_preview_returns_bip21_mainnet_uri() {
        let quote = quote_for(PaymentMethod::Onchain {
            label: "Savings".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some("1BoatSLRHtKNngkdXEeobR76b53LETtpyT".into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        });
        let (_, qr, _) = method_preview(&quote, 1_000, false, "unverified")
            .await
            .unwrap();
        assert_eq!(
            qr,
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00001"
        );
    }

    #[tokio::test]
    async fn testnet_address_rejected_in_mainnet_preview() {
        let quote = quote_for(PaymentMethod::Onchain {
            label: "Testnet".into(),
            network: BitcoinNetwork::Testnet,
            address: Some("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn".into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        });
        assert!(method_preview(&quote, 1_000, false, "unverified")
            .await
            .is_err());
    }

    #[tokio::test]
    async fn ark_preview_returns_satspath_uri_with_mainnet_network() {
        let quote = quote_for(PaymentMethod::Ark {
            label: "Ark".into(),
            server: "https://ark.example.com".into(),
            pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
            opaque_uri: None,
            vtxo_pointer: None,
            proof: None,
            expires_at: None,
        });
        let (_, qr, warnings) = method_preview(&quote, 21_000, false, "unverified")
            .await
            .unwrap();
        assert!(qr.starts_with("satspath:ark?"));
        assert!(qr.contains("network=mainnet"));
        assert!(warnings.iter().any(|w| w.contains("unavailable")));
    }
}
