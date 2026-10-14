use anyhow::Result;

use satspath_core::{
    crypto::verify_signed_profile,
    evaluate_method_trust_for_profile,
    privacy::{mask_address, mask_identifier, mask_invoice, mask_pubkey},
    resolver::ProfileResolver,
    PaymentMethod,
};
use satspath_router::{
    fetch_invoice, fetch_lnurl_metadata, lightning::lightning_address, select_route, RouteRequest,
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
    println!("{}", serde_json::to_string_pretty(&response)?);
    Ok(())
}

/// Verify that cmd quote.
pub async fn cmd_quote(alias: &str, amount_sats: u64) -> Result<()> {
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
    let req = RouteRequest {
        alias: alias.to_string(),
        amount_sats,
        signed_profile: signed.clone(),
        urgency: satspath_router::urgency::PaymentUrgency::Normal,
        max_fee_sats: None,
        max_fee_percent: None,
    };
    let quote = select_route(&req)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;
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
            match fetch_lnurl_metadata(ln_addr).await {
                Ok(meta) => {
                    match fetch_invoice(&meta, amount_sats, None).await {
                        Ok(invoice) => {
                            println!("received.");
                            println!();
                            println!("  Scan to pay — Lightning ({} sats)", amount_sats);
                            println!("  ─────────────────────────────────────────");
                            print_qr(&invoice.to_uppercase())?;
                            println!("  {}...", mask_invoice(&invoice));
                            println!("  Warning: this is a real invoice QR generated from public metadata.");
                        }
                        Err(e) => {
                            println!("unavailable ({e}).");
                            println!("  Preview only. No funds moved.");
                        }
                    }
                }
                Err(e) => {
                    println!("unavailable ({e}).");
                    println!("  Preview only. No funds moved.");
                }
            }
        }
        PaymentMethod::Onchain {
            network,
            address,
            silent_payment_pubkey,
            ..
        } => {
            let target = silent_payment_pubkey
                .clone()
                .unwrap_or_else(|| address.clone().unwrap_or_default());
            let uri = bitcoin_uri(&target, amount_sats, *network)?;
            println!("  Scan to pay — Bitcoin on-chain ({} sats)", amount_sats);
            println!("  ─────────────────────────────────────────");
            print_qr(&uri)?;
            println!("  {}", mask_address(&uri));
        }
        PaymentMethod::Ark { pubkey, server, .. } => {
            println!("  Ark payment via {}", mask_address(server));
            println!("  Pubkey: {}", mask_pubkey(pubkey));
            println!(
                "  ⚠  [EXPERIMENTAL] Use --experimental-swaps --testnet to attempt execution."
            );
            println!("  Use `satspath pay --mainnet-preview` for public pointer preview.");
        }
    }

    Ok(())
}
