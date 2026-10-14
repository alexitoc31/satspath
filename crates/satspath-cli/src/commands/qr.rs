use anyhow::Result;
use qrcode::render::unicode;
use qrcode::QrCode;

pub fn print_qr(data: &str) -> Result<()> {
    let code =
        QrCode::new(data.as_bytes()).map_err(|e| anyhow::anyhow!("QR encode error: {}", e))?;
    let image = code
        .render::<unicode::Dense1x2>()
        .dark_color(unicode::Dense1x2::Dark)
        .light_color(unicode::Dense1x2::Light)
        .quiet_zone(true)
        .build();
    println!("{}", image);
    Ok(())
}

/// BIP-21 Bitcoin URI: `bitcoin:<address>?amount=<btc>`
pub fn bitcoin_uri(
    address: &str,
    amount_sats: u64,
    network: satspath_core::BitcoinNetwork,
) -> Result<String> {
    satspath_core::pointer::build_qr_payload(
        &satspath_core::PaymentPointer::OnchainAddress {
            network,
            address: address.into(),
            claim_policy: None,
        },
        amount_sats,
    )?;
    Ok(format!(
        "bitcoin:{address}?amount={}.{:08}",
        amount_sats / 100_000_000,
        amount_sats % 100_000_000
    ))
}
