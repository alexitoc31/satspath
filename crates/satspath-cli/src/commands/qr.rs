use anyhow::Result;
use qrcode::render::unicode;
use qrcode::QrCode;
use satspath_router::handoff::fmt_btc;

/// Render a caller-validated public payment payload as a terminal QR.
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
pub fn bitcoin_uri(address: &str, amount_sats: u64) -> String {
    format!("bitcoin:{address}?amount={}", fmt_btc(amount_sats))
}
