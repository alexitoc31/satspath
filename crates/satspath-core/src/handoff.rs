//! Validate methods before route selection and wallet payload construction.
use bitcoin::Network;
use satspath_handoff as check;

/// Validate all supplied receiver fields, including metadata hidden by pointer priority.
pub fn validate_method(method: &crate::PaymentMethod, sats: u64) -> crate::Result<()> {
    validate(method, sats, chrono::Utc::now().timestamp())
        .map_err(crate::SatsPathError::InvalidPaymentPointer)
}

/// Validate using an explicit clock so expiry tests remain deterministic.
fn validate(method: &crate::PaymentMethod, sats: u64, now: i64) -> Result<(), String> {
    check::amount(sats)?;
    use crate::PaymentMethod;
    match method {
        PaymentMethod::Onchain {
            network,
            address,
            silent_payment_pubkey,
            ..
        } => {
            let network = match network {
                crate::BitcoinNetwork::Mainnet => Network::Bitcoin,
                crate::BitcoinNetwork::Testnet => Network::Testnet,
                crate::BitcoinNetwork::Regtest => Network::Regtest,
            };
            if address.is_none() && silent_payment_pubkey.is_none() {
                return Err("missing on-chain receiver".into());
            }
            if let Some(address) = address {
                check::onchain(address, network)?;
            }
            if let Some(address) = silent_payment_pubkey {
                check::silent(address, network)?;
            }
            Ok(())
        }
        PaymentMethod::Lightning {
            lightning_address,
            lnurl,
            bolt12,
            receiver_pubkey,
            ..
        } => {
            if lightning_address.is_none() && lnurl.is_none() && bolt12.is_none() {
                return Err("missing Lightning receiver".into());
            }
            if let Some(address) = lightning_address {
                check::lightning_address(address)?;
            }
            if let Some(url) = lnurl {
                check::https(url)?;
            }
            if let Some(key) = receiver_pubkey {
                check::public_key(&hex::decode(key).map_err(|e| e.to_string())?)?;
            }
            if let Some(offer) = bolt12 {
                if offer.to_ascii_lowercase().starts_with("lnbc")
                    || offer.to_ascii_lowercase().starts_with("lntb")
                    || offer.to_ascii_lowercase().starts_with("lnbcrt")
                {
                    check::bolt11(offer, sats, Network::Bitcoin, now.max(0) as u64)?;
                } else {
                    check::bolt12(offer)?;
                }
            }
            Ok(())
        }
        PaymentMethod::Ark {
            server,
            pubkey,
            vtxo_pointer,
            opaque_uri,
            expires_at,
            ..
        } => check::ark(
            server,
            &hex::decode(pubkey).map_err(|e| e.to_string())?,
            vtxo_pointer.as_deref(),
            opaque_uri.as_deref(),
            *expires_at,
            now,
        ),
        PaymentMethod::Bolt12(offer) => check::bolt12(&offer.offer),
    }
}
