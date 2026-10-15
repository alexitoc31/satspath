use serde::{Deserialize, Serialize};
use url::form_urlencoded;

use crate::errors::{Result, SatsPathError};
use crate::profile::ClaimPolicy;
use crate::validation::{assert_no_private_material, validate_amount_sats};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

/// Public payment pointer data only.
///
/// This type must never contain seeds, private keys, macaroons, node certs,
/// wallet signing keys, or API secrets.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PaymentPointer {
    LightningAddress {
        address: String,
        receiver_pubkey: Option<String>,
    },
    LnurlPay {
        callback_url: String,
        receiver_pubkey: Option<String>,
    },
    Bolt11Invoice {
        invoice: String,
        amount_sats: Option<u64>,
    },
    OnchainAddress {
        network: BitcoinNetwork,
        address: String,
        claim_policy: Option<ClaimPolicy>,
    },
    Bolt12Offer {
        offer: String,
    },
    Ark {
        server: String,
        receiver_pubkey: String,
        vtxo_pointer: Option<String>,
    },
}

impl PaymentPointer {
    /// Return the human-readable rail name for a payment pointer.
    pub fn rail_name(&self) -> &'static str {
        match self {
            PaymentPointer::LightningAddress { .. } => "Lightning Address",
            PaymentPointer::LnurlPay { .. } => "LNURL Pay",
            PaymentPointer::Bolt11Invoice { .. } => "BOLT11 Invoice",
            PaymentPointer::Bolt12Offer { .. } => "BOLT12 Offer",
            PaymentPointer::OnchainAddress { .. } => "On-chain Bitcoin",
            PaymentPointer::Ark { .. } => "Ark",
        }
    }
}

/// Validate a direct pointer before it becomes a wallet payload.
fn validate_handoff(pointer: &PaymentPointer, sats: u64) -> Result<()> {
    use satspath_handoff as check;
    let now = chrono::Utc::now().timestamp();
    let result = match pointer {
        PaymentPointer::LightningAddress { address, .. } => check::lightning_address(address),
        PaymentPointer::LnurlPay { callback_url, .. } => check::https(callback_url),
        PaymentPointer::Bolt11Invoice { invoice, .. } => check::bolt11_network(invoice)
            .ok_or_else(|| "unrecognized BOLT11 network".to_string())
            .and_then(|network| check::bolt11(invoice, sats, network, now.max(0) as u64)),
        PaymentPointer::Bolt12Offer { offer } => check::bolt12(offer, None, now.max(0) as u64),
        PaymentPointer::OnchainAddress {
            network, address, ..
        } => {
            let network = match network {
                BitcoinNetwork::Mainnet => bitcoin::Network::Bitcoin,
                BitcoinNetwork::Testnet => bitcoin::Network::Testnet,
                BitcoinNetwork::Regtest => bitcoin::Network::Regtest,
            };
            let is_silent = bech32::decode(address)
                .map(|(hrp, _, _)| {
                    let hrp_lower = hrp.to_ascii_lowercase();
                    matches!(hrp_lower.as_str(), "sp" | "tsp" | "sprt")
                })
                .unwrap_or(false);
            if is_silent {
                check::silent(address, network)
            } else {
                check::onchain(address, network)
            }
        }
        PaymentPointer::Ark {
            server,
            receiver_pubkey,
            vtxo_pointer,
        } => {
            let key = hex::decode(receiver_pubkey)
                .map_err(|e| SatsPathError::InvalidPublicKey(e.to_string()))?;
            check::ark(server, &key, vtxo_pointer.as_deref(), None, None, now)
        }
    };
    result.map_err(SatsPathError::InvalidPaymentPointer)
}

/// Build a validated public wallet payload for a positive amount.
pub fn build_qr_payload(pointer: &PaymentPointer, amount_sats: u64) -> Result<String> {
    validate_amount_sats(amount_sats)?;
    validate_handoff(pointer, amount_sats)?;

    let payload = match pointer {
        PaymentPointer::LightningAddress { address, .. } => {
            format!(
                "lightning:{}?amount={}",
                address.to_lowercase(),
                amount_sats
            )
        }
        PaymentPointer::LnurlPay { callback_url, .. } => {
            let amount_msats = amount_sats
                .checked_mul(1_000)
                .ok_or_else(|| SatsPathError::InvalidPaymentPointer("amount overflow".into()))?;
            let mut url = url::Url::parse(callback_url)
                .map_err(|e| SatsPathError::InvalidPaymentPointer(e.to_string()))?;
            url.query_pairs_mut()
                .append_pair("amount", &amount_msats.to_string());
            url.to_string()
        }
        PaymentPointer::Bolt11Invoice {
            invoice: _,
            amount_sats: Some(invoice_amount),
        } if *invoice_amount != amount_sats => {
            return Err(SatsPathError::InvalidPaymentPointer(format!(
                "BOLT11 amount mismatch: invoice={invoice_amount} sats request={amount_sats} sats"
            )));
        }
        PaymentPointer::Bolt11Invoice { invoice, .. } => invoice.clone(),
        PaymentPointer::Bolt12Offer { offer } => offer.clone(),
        PaymentPointer::OnchainAddress { address, .. } => {
            let btc = sats_to_btc(amount_sats);
            format!("bitcoin:{address}?amount={btc}")
        }
        PaymentPointer::Ark {
            server,
            receiver_pubkey,
            vtxo_pointer,
        } => {
            let mut encoded = form_urlencoded::Serializer::new(String::new());
            encoded.append_pair("server", server);
            encoded.append_pair("pubkey", receiver_pubkey);
            encoded.append_pair("amount", &amount_sats.to_string());
            if let Some(vtxo) = vtxo_pointer {
                encoded.append_pair("vtxo", vtxo);
            }
            format!("satspath:ark?{}", encoded.finish())
        }
    };

    assert_no_private_material(&payload)?;
    Ok(payload)
}

fn sats_to_btc(amount_sats: u64) -> String {
    let whole = amount_sats / 100_000_000;
    let frac = amount_sats % 100_000_000;
    let mut value = format!("{whole}.{frac:08}");
    while value.ends_with('0') {
        value.pop();
    }
    if value.ends_with('.') {
        value.push('0');
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::ToBase32;

    #[test]
    fn bolt12_qr_payload_checks_expiry_and_features_without_a_network() {
        let key = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap();
        for hrp in ["lno", "lnot", "lnob", "lnos"] {
            for (fields, accepted) in [
                (vec![], true),
                (vec![14, 0], false),
                (
                    [vec![14, 8], u64::MAX.to_be_bytes().to_vec()].concat(),
                    true,
                ),
                (vec![12, 1, 1], false),
                (vec![12, 1, 2], true),
            ] {
                let raw = [fields, vec![22, 33], key.clone()].concat();
                let offer = bech32::encode(hrp, raw.to_base32(), bech32::Variant::Bech32m).unwrap();
                let pointer = PaymentPointer::Bolt12Offer {
                    offer: offer.clone(),
                };
                let result = build_qr_payload(&pointer, 1);
                if accepted {
                    assert_eq!(result.unwrap(), offer);
                } else {
                    assert!(result.is_err(), "{offer}");
                }
            }
        }
    }

    #[test]
    /// Verify that qr payload for bolt11 rejects malformed invoice.
    fn qr_payload_for_bolt11_rejects_malformed_invoice() {
        let invoice = "lnbc210n1pexampleinvoice".to_string();
        let pointer = PaymentPointer::Bolt11Invoice {
            invoice: invoice.clone(),
            amount_sats: Some(21_000),
        };
        assert!(build_qr_payload(&pointer, 21_000).is_err());
    }

    #[test]
    fn qr_payload_for_onchain_returns_bip21_uri() {
        let pointer = PaymentPointer::OnchainAddress {
            network: BitcoinNetwork::Mainnet,
            address: "1BoatSLRHtKNngkdXEeobR76b53LETtpyT".into(),
            claim_policy: None,
        };
        assert_eq!(
            build_qr_payload(&pointer, 21_000).unwrap(),
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00021"
        );
    }

    #[test]
    fn qr_payload_routes_silent_payment_by_hrp_and_network() {
        let key = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap();
        let mut data = vec![bech32::u5::try_from_u8(0).unwrap()];
        data.extend([key.clone(), key].concat().to_base32());
        for (network, hrp) in [
            (BitcoinNetwork::Mainnet, "sp"),
            (BitcoinNetwork::Testnet, "tsp"),
            (BitcoinNetwork::Regtest, "sprt"),
        ] {
            let address = bech32::encode(hrp, &data, bech32::Variant::Bech32m).unwrap();
            let pointer = PaymentPointer::OnchainAddress {
                network,
                address: address.clone(),
                claim_policy: None,
            };
            assert!(build_qr_payload(&pointer, 21_000).is_ok(), "{hrp}");
            let wrong_network = PaymentPointer::OnchainAddress {
                network: BitcoinNetwork::Mainnet,
                address,
                claim_policy: None,
            };
            if network != BitcoinNetwork::Mainnet {
                assert!(build_qr_payload(&wrong_network, 21_000).is_err(), "{hrp}");
            }
        }
    }

    #[test]
    fn qr_payload_for_ark_returns_satspath_ark_uri() {
        let pointer = PaymentPointer::Ark {
            server: "https://ark.example.com".into(),
            receiver_pubkey: "02c0ded4d352532ee6d5d3fb69c7f08988c0a2b9f68a10fa79b2e769c123456789"
                .into(),
            vtxo_pointer: None,
        };
        let payload = build_qr_payload(&pointer, 42).unwrap();
        assert!(payload.starts_with("satspath:ark?"));
        assert!(payload.contains("server=https%3A%2F%2Fark.example.com"));
        assert!(payload.contains("amount=42"));
    }

    #[test]
    fn qr_payload_rejects_private_material() {
        let pointer = PaymentPointer::Bolt11Invoice {
            invoice: "lnbc1contains_xprv_secret".into(),
            amount_sats: Some(1),
        };
        assert!(build_qr_payload(&pointer, 1).is_err());
    }

    #[test]
    fn bolt11_amount_mismatch_fails() {
        let pointer = PaymentPointer::Bolt11Invoice {
            invoice: "lnbc210n1pexampleinvoice".into(),
            amount_sats: Some(21_000),
        };
        assert!(build_qr_payload(&pointer, 1_000).is_err());
    }
}
