use anyhow::Result;

use satspath_core::{
    crypto::verify_signed_profile,
    evaluate_method_trust_for_profile,
    privacy::{mask_address, mask_identifier, mask_invoice},
    resolver::ProfileResolver,
    validation::validate_amount_sats,
    PaymentMethod,
};
use satspath_router::{
    fetch_invoice, fetch_lnurl_metadata, handoff::validate_payload, lightning::lightning_address,
    select_route, QuoteResponse, RouteRequest,
};

use super::{
    get_resolver,
    qr::{bitcoin_uri, print_qr},
};

/// Emit the machine-readable quote contract as a single JSON object and nothing
/// else, so the UX / API layer can consume it directly. Human-facing output
/// stays in [`cmd_quote`].
pub async fn cmd_quote_json(alias: &str, amount_sats: u64) -> Result<()> {
    let response = satspath_router::quote(alias, amount_sats).await;
    if let QuoteResponse::Ok {
        selected_method,
        qr,
        ..
    } = &response
    {
        validate_quote_qr(selected_method, qr, amount_sats)?;
    }
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// Resolve and print a route only when its wallet QR passes mainnet validation.
pub async fn cmd_quote(alias: &str, amount_sats: u64) -> Result<()> {
    validate_amount_sats(amount_sats)?;
    let resolver = get_resolver()?;

    println!("Resolving identifier '{}'...", mask_identifier(alias));
    let signed = resolver
        .resolve_alias(alias)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
    println!("found.");

    print!("Verifying signature... ");
    if !verify_signed_profile(&signed)? {
        anyhow::bail!("Signature INVALID. Profile may be tampered.");
    }
    println!("valid.");

    let now = chrono::Utc::now().timestamp();
    if signed.profile.updated_at > now - 86400 && signed.profile.sequence.unwrap_or(1) == 1 {
        println!();
        println!("  ⚠  WARNING: This profile was created very recently (within 24 hours).");
        println!("     Please verify this is the correct recipient before sending funds.");
        println!();
    }

    print!("Fetching mempool fees + selecting rail... ");
    let mut routable = signed.clone();
    routable.profile.methods = eligible_quote_methods(&signed.profile.methods, amount_sats);
    if routable.profile.methods.is_empty() {
        if signed.profile.methods.iter().any(|m| {
            matches!(
                m,
                PaymentMethod::Lightning {
                    receiver_pubkey: None,
                    ..
                }
            )
        }) {
            anyhow::bail!("Lightning invoice requires a verified receiver public key");
        }
        anyhow::bail!("recipient exposes no eligible mainnet wallet handoff rail");
    }

    let (quote, prefetched_ln_invoice) = loop {
        let req = RouteRequest {
            alias: alias.to_string(),
            amount_sats,
            signed_profile: routable.clone(),
            urgency: satspath_router::urgency::PaymentUrgency::Normal,
            max_fee_sats: None,
            max_fee_percent: None,
        };
        let quote = select_route(&req)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        if matches!(quote.selected_method, PaymentMethod::Lightning { .. }) {
            let has_fallback = routable.profile.methods.len() > 1;
            let ln_result = async {
                if matches!(
                    quote.selected_method,
                    PaymentMethod::Lightning {
                        receiver_pubkey: None,
                        ..
                    }
                ) {
                    anyhow::bail!("Lightning invoice requires a verified receiver public key");
                }
                let ln_addr = lightning_address(&quote.selected_method)
                    .ok_or_else(|| anyhow::anyhow!("no Lightning Address in method"))?;
                let meta = fetch_lnurl_metadata(ln_addr).await?;
                let invoice = fetch_invoice(&meta, amount_sats, None).await?;
                validate_quote_qr(&quote.selected_method, &invoice, amount_sats)?;
                Ok::<String, anyhow::Error>(invoice)
            }
            .await;

            match ln_result {
                Ok(invoice) => break (quote, Some(Ok(invoice))),
                Err(err) if has_fallback => {
                    if let Some(pos) = routable
                        .profile
                        .methods
                        .iter()
                        .position(|m| m == &quote.selected_method)
                    {
                        routable.profile.methods.remove(pos);
                        continue;
                    }
                    break (quote, Some(Err(err)));
                }
                Err(err) => break (quote, Some(Err(err))),
            }
        }

        break (quote, None);
    };
    println!("done.");

    if let Some(snap) = &quote.fee_snapshot {
        println!();
        println!("  Mempool fees (sat/vB)");
        println!("  ├─ Next block  (~10 min): {} sat/vB", snap.fastest_sat_vb);
        println!(
            "  ├─ 30 minutes           : {} sat/vB",
            snap.half_hour_sat_vb
        );
        println!("  └─ 60 minutes           : {} sat/vB", snap.hour_sat_vb);
    }

    println!();
    println!("  ┌─────────────────────────────────────────┐");
    println!(
        "  │  Rail   : {:30}  │",
        quote.selected_method.method_name()
    );
    println!("  │  Label  : {:30}  │", quote.selected_method.label());
    if let Some(fee) = quote.estimated_fee_sats {
        println!("  │  Fee    : {:30}  │", format!("{} sats", fee));
    }
    if let Some(conf) = &quote.estimated_confirmation {
        println!("  │  Confirm: {:30}  │", conf);
    }
    println!("  └─────────────────────────────────────────┘");
    println!("  Reason: {}", quote.reason);

    // Ownership trust of the selected rail, re-verified client-side. Unifies
    // method_verifications and any inline Ark pointer proof under one signal.
    let trust = evaluate_method_trust_for_profile(
        &signed.profile,
        &quote.selected_method,
        chrono::Utc::now().timestamp(),
        None,
    );
    println!("  Ownership: {}", trust.badge());
    if trust.is_suspicious() {
        println!("  ⚠  This rail's ownership proof did not verify — treat with caution.");
    }

    println!();
    match &quote.selected_method {
        PaymentMethod::Bolt12(offer_data) => {
            validate_quote_qr(&quote.selected_method, &offer_data.offer, amount_sats)?;
            println!("  BOLT12 Offer:");
            println!("  ─────────────────────────────────────────");
            print_qr(&offer_data.offer)?;
            println!("  {}", offer_data.offer);
            println!("  Preview only. No funds moved.");
        }
        PaymentMethod::Lightning { .. } => {
            let ln_addr = lightning_address(&quote.selected_method)
                .ok_or_else(|| anyhow::anyhow!("no Lightning Address in method"))?;

            print!("  Fetching invoice from {}... ", mask_identifier(ln_addr));
            match prefetched_ln_invoice.expect("Lightning quote always pre-evaluates invoice") {
                Ok(invoice) => {
                    validate_quote_qr(&quote.selected_method, &invoice, amount_sats)?;
                    println!("received.");
                    println!();
                    println!("  Scan to pay — Lightning ({} sats)", amount_sats);
                    println!("  ─────────────────────────────────────────");
                    print_qr(&invoice)?;
                    println!("  {}...", mask_invoice(&invoice));
                    println!(
                        "  Warning: this is a real invoice QR generated from public metadata."
                    );
                }
                Err(_e) => {
                    println!("unavailable (Lightning invoice could not be fetched).");
                    println!("  Preview only. No funds moved.");
                }
            }
        }
        PaymentMethod::Onchain {
            address,
            silent_payment_pubkey,
            ..
        } => {
            let target = silent_payment_pubkey
                .clone()
                .unwrap_or_else(|| address.clone().unwrap_or_default());
            let uri = bitcoin_uri(&target, amount_sats);
            validate_quote_qr(&quote.selected_method, &uri, amount_sats)?;
            println!("  Scan to pay — Bitcoin on-chain ({} sats)", amount_sats);
            println!("  ─────────────────────────────────────────");
            print_qr(&uri)?;
            println!("  {}", mask_address(&uri));
        }
        PaymentMethod::Ark { .. } => {
            anyhow::bail!("Ark wallet handoffs are not supported");
        }
    }

    Ok(())
}

/// Filter profile methods down to rails that can produce a validated mainnet handoff.
fn eligible_quote_methods(methods: &[PaymentMethod], amount_sats: u64) -> Vec<PaymentMethod> {
    methods
        .iter()
        .filter(|method| match method {
            PaymentMethod::Lightning {
                lightning_address: Some(addr),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: Some(pubkey),
                ..
            } => {
                satspath_core::validation::validate_lightning_address(addr).is_ok()
                    && pubkey.parse::<secp256k1::PublicKey>().is_ok()
            }
            PaymentMethod::Onchain {
                address: Some(address),
                silent_payment_pubkey: None,
                ..
            } => {
                let uri = bitcoin_uri(address, amount_sats);
                validate_quote_qr(method, &uri, amount_sats).is_ok()
            }
            _ => false,
        })
        .cloned()
        .collect()
}

/// Check a mainnet CLI quote against its selected method before displaying it.
fn validate_quote_qr(method: &PaymentMethod, qr: &str, amount_sats: u64) -> Result<()> {
    validate_payload(method, qr, "mainnet", Some(amount_sats))
}

#[cfg(test)]
mod tests {
    use super::*;
    use satspath_core::{profile::Bolt12Offer, BitcoinNetwork};

    #[test]
    fn cli_quote_rejects_unsupported_and_unbound_qrs() {
        let onchain = PaymentMethod::Onchain {
            label: "On-chain".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some("1BoatSLRHtKNngkdXEeobR76b53LETtpyT".into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        };
        let valid = bitcoin_uri("1BoatSLRHtKNngkdXEeobR76b53LETtpyT", 21_000);
        assert!(validate_quote_qr(&onchain, &valid, 21_000).is_ok());
        assert!(validate_quote_qr(&onchain, &valid, 21_001).is_err());
        assert!(validate_quote_qr(&onchain, &format!("{valid}&lno=lno1qoffer"), 21_000).is_err());

        let lightning = PaymentMethod::Lightning {
            label: "Lightning".into(),
            lightning_address: Some("alice@example.com".into()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        };
        assert!(validate_quote_qr(&lightning, "alice@example.com", 21_000).is_err());
        assert!(validate_quote_qr(&lightning, "lnbc1invalid", 21_000).is_err());

        let bolt12 = PaymentMethod::Bolt12(Bolt12Offer {
            label: "Offer".into(),
            offer: "lno1qoffer".into(),
            network: BitcoinNetwork::Mainnet,
            minimum_amount_sats: None,
            expires_at: None,
            issuer_pubkey: String::new(),
        });
        assert!(validate_quote_qr(&bolt12, "lno1qoffer", 21_000).is_err());
    }

    #[test]
    fn mixed_profile_skips_unverified_lightning_and_selects_eligible_onchain() {
        let onchain = PaymentMethod::Onchain {
            label: "On-chain".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some("1BoatSLRHtKNngkdXEeobR76b53LETtpyT".into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        };
        let methods = vec![
            PaymentMethod::Lightning {
                label: "Lightning".into(),
                lightning_address: Some("alice@example.com".into()),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: None,
            },
            onchain.clone(),
        ];
        let eligible = eligible_quote_methods(&methods, 21_000);
        assert_eq!(eligible, vec![onchain]);
    }
}
