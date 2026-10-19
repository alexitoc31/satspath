//! Final validation of public payment payloads before they leave the daemon.

use std::str::FromStr;

use anyhow::{bail, Context, Result};
use bitcoin::{Address, Network};
use lightning_invoice::{Bolt11Invoice, Currency};
use satspath_core::{
    bip321::{parse_bip321, Bip321Instruction},
    validation::{
        assert_no_private_material, validate_amount_sats, validate_bitcoin_address,
        validate_lightning_address,
    },
    BitcoinNetwork, PaymentMethod,
};

use crate::lightning::validate_bolt11_invoice_for_network;

/// Format an exact on-chain amount without floating-point rounding.
pub fn fmt_btc(sats: u64) -> String {
    format!("{}.{:08}", sats / 100_000_000, sats % 100_000_000)
}

const MAX_PAYLOAD_BYTES: usize = 4_096;

/// A single fail-closed gate for outgoing daemon payment and receive payloads.
/// Amount-less receive pointers are not treated as amount-bound payment handoffs.
pub fn validate_payload(
    method: &PaymentMethod,
    payload: &str,
    network: &str,
    amount_sats: Option<u64>,
) -> Result<()> {
    if payload.is_empty()
        || payload.len() > MAX_PAYLOAD_BYTES
        || payload.trim() != payload
        || !payload.is_ascii()
    {
        bail!("payment payload is empty, oversized, or malformed");
    }
    assert_no_private_material(payload)?;
    if let Some(amount) = amount_sats {
        validate_amount_sats(amount)?;
    }
    let expected_network = configured_network(network)?;

    match method {
        PaymentMethod::Onchain {
            network: method_network,
            address,
            silent_payment_pubkey,
            ..
        } => {
            if method_network != &expected_network {
                bail!("on-chain method network does not match daemon network");
            }
            if silent_payment_pubkey.is_some() {
                bail!("silent payment handoffs are not supported until strict wallet validation is available");
            }
            let address = address
                .as_deref()
                .context("on-chain method has no address")?;
            validate_bitcoin_address(address, expected_network)?;
            // Testnet and regtest share legacy Base58 prefixes; only their
            // distinct SegWit HRPs can bind a payload to one of these networks.
            let parsed_address = Address::from_str(address)?;
            if expected_network != BitcoinNetwork::Mainnet
                && parsed_address.is_valid_for_network(Network::Testnet)
                && parsed_address.is_valid_for_network(Network::Regtest)
            {
                bail!("ambiguous testnet/regtest legacy address");
            }
            let expected = match amount_sats {
                Some(amount) => format!("bitcoin:{address}?amount={}", fmt_btc(amount)),
                None => format!("bitcoin:{address}"),
            };
            if payload != expected {
                bail!(
                    "Bitcoin URI address, amount, or parameters do not match the selected method"
                );
            }
            let parsed = parse_bip321(payload)?;
            if parsed.address.as_deref() != Some(address)
                || parsed.amount_btc.as_deref() != amount_sats.map(fmt_btc).as_deref()
                || !matches!(
                    parsed.instructions.as_slice(),
                    [Bip321Instruction::Onchain { .. }]
                )
            {
                bail!("Bitcoin URI contains conflicting or unsupported instructions");
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
            let pointer = match (
                lightning_address.as_deref(),
                lnurl.as_deref(),
                bolt12.as_deref(),
            ) {
                (Some(address), None, None) => {
                    validate_lightning_address(address)?;
                    address
                }
                (None, Some(url), None) => {
                    validate_lnurl(url)?;
                    url
                }
                (None, None, Some(_)) => {
                    bail!("BOLT12 offers are not supported as wallet handoffs")
                }
                _ => bail!("Lightning method must have exactly one supported pointer"),
            };
            match amount_sats {
                None if payload == pointer => Ok(()),
                None => bail!("receive pointer does not match the selected Lightning method"),
                Some(_) if payload == pointer => {
                    bail!("Lightning pointer cannot bind the requested amount; an invoice is required")
                }
                Some(amount) => {
                    validate_bolt11(payload, receiver_pubkey.as_deref(), network, amount)
                }
            }
        }
        PaymentMethod::Bolt12(_) => {
            bail!("BOLT12 offers are not supported as wallet handoffs")
        }
        PaymentMethod::Ark { .. } => {
            bail!("Ark pointers are not supported as wallet handoffs")
        }
    }
}

/// Interpret the configured chain name, rejecting unknown networks.
///
/// `devnet` intentionally aliases to [`BitcoinNetwork::Testnet`] (and
/// `Currency::BitcoinTestnet` in [`validate_bolt11`]) for local `satspathd`
/// development. Testnet3, Testnet4, and Signet share the `tb` HRP under
/// `bitcoin::Network::Testnet`, while Mainnet remains strictly isolated.
fn configured_network(network: &str) -> Result<BitcoinNetwork> {
    match network.to_ascii_lowercase().as_str() {
        "mainnet" | "bitcoin" => Ok(BitcoinNetwork::Mainnet),
        // Intentional alias: local `devnet` uses Testnet/Signet (`tb`) encodings.
        "testnet" | "devnet" => Ok(BitcoinNetwork::Testnet),
        "regtest" => Ok(BitcoinNetwork::Regtest),
        _ => bail!("unsupported daemon network for payment handoff"),
    }
}

/// Require an unambiguous HTTPS URL for an amount-less LNURL pointer.
fn validate_lnurl(pointer: &str) -> Result<()> {
    let url = url::Url::parse(pointer).context("invalid LNURL pointer")?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        bail!("LNURL pointer must be an unambiguous HTTPS URL without credentials");
    }
    Ok(())
}

/// Bind a BOLT11 invoice to its signed payee, network, amount, and expiry.
fn validate_bolt11(
    payload: &str,
    receiver_pubkey: Option<&str>,
    network: &str,
    amount_sats: u64,
) -> Result<()> {
    let expected_currency = match network.to_ascii_lowercase().as_str() {
        "mainnet" | "bitcoin" => Currency::Bitcoin,
        // Keep `devnet` aligned with `configured_network` (`BitcoinNetwork::Testnet`).
        "testnet" | "devnet" => Currency::BitcoinTestnet,
        "regtest" => Currency::Regtest,
        _ => bail!("unsupported Lightning network for payment handoff"),
    };
    let invoice = Bolt11Invoice::from_str(payload).context("invalid BOLT11 invoice")?;
    if invoice.currency() != expected_currency {
        bail!("BOLT11 invoice network does not match daemon network");
    }
    let expected_pubkey = receiver_pubkey
        .context("BOLT11 invoice cannot be bound to a verified receiver public key")?
        .parse::<secp256k1::PublicKey>()
        .context("invalid receiver public key")?;
    if invoice.recover_payee_pub_key() != expected_pubkey {
        bail!("BOLT11 invoice payee does not match the selected method");
    }
    let amount_msats = amount_sats.checked_mul(1_000).context("amount overflow")?;
    validate_bolt11_invoice_for_network(payload, amount_msats, Some(invoice.network()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{sha256, Hash};
    use lightning_invoice::{InvoiceBuilder, PaymentSecret};
    use satspath_core::BitcoinNetwork;
    use secp256k1::{Secp256k1, SecretKey};
    use std::time::{Duration, SystemTime};

    const MAINNET_ADDRESS: &str = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT";

    #[test]
    fn fmt_btc_preserves_eight_decimal_places() {
        assert_eq!(fmt_btc(0), "0.00000000");
        assert_eq!(fmt_btc(21_000), "0.00021000");
        assert_eq!(fmt_btc(100_000_000), "1.00000000");
    }

    fn onchain(address: &str) -> PaymentMethod {
        PaymentMethod::Onchain {
            label: "onchain".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some(address.into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        }
    }

    fn segwit_address(network: Network) -> String {
        let secret = SecretKey::from_slice(&[1; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &secret);
        let compressed = bitcoin::CompressedPublicKey::from_slice(&pubkey.serialize()).unwrap();
        Address::p2wpkh(&compressed, network).to_string()
    }

    fn invoice(currency: Currency, amount_msats: Option<u64>, expired: bool) -> (String, String) {
        let secret = SecretKey::from_slice(&[1; 32]).unwrap();
        let pubkey = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &secret).to_string();
        let builder = InvoiceBuilder::new(currency)
            .description("test".into())
            .payment_hash(sha256::Hash::hash(&[2; 32]))
            .payment_secret(PaymentSecret([3; 32]))
            .min_final_cltv_expiry_delta(144);
        let builder = if let Some(amount) = amount_msats {
            builder.amount_milli_satoshis(amount)
        } else {
            builder
        };
        let builder = if expired {
            builder
                .timestamp(SystemTime::now() - Duration::from_secs(3_600))
                .expiry_time(Duration::from_secs(1))
        } else {
            builder.current_timestamp()
        };
        let signed = builder
            .build_signed(|hash| {
                let message = secp256k1::Message::from_digest_slice(hash.as_ref()).unwrap();
                Secp256k1::new().sign_ecdsa_recoverable(&message, &secret)
            })
            .unwrap();
        (signed.to_string(), pubkey)
    }

    #[test]
    fn accepts_only_matching_onchain_amount_and_network() {
        let method = onchain(MAINNET_ADDRESS);
        let valid = format!("bitcoin:{MAINNET_ADDRESS}?amount=0.00021000");
        assert!(validate_payload(&method, &valid, "mainnet", Some(21_000)).is_ok());
        assert!(validate_payload(&method, &valid, "devnet", Some(21_000)).is_err());
        assert!(validate_payload(&method, &valid, "mainnet", Some(21_001)).is_err());
        assert!(validate_payload(&method, &valid, "mainnet", Some(0)).is_err());
        assert!(validate_payload(&method, &valid, "mainnet", Some(u64::MAX)).is_err());
    }

    #[test]
    fn rejects_ambiguous_or_malformed_bitcoin_uris() {
        let method = onchain(MAINNET_ADDRESS);
        for payload in [
            format!("bitcoin:{MAINNET_ADDRESS}?amount=0.00021000&amount=1"),
            format!("bitcoin:{MAINNET_ADDRESS}?amount=0.00021000&lightning=attacker"),
            format!("bitcoin:{MAINNET_ADDRESS}?amount=1e-4"),
            "bitcoin:invalid?amount=0.00021000".into(),
            format!("bitcoin:{MAINNET_ADDRESS}?amount=0.00021000%26amount%3D1"),
        ] {
            assert!(
                validate_payload(&method, &payload, "mainnet", Some(21_000)).is_err(),
                "accepted {payload}"
            );
        }
    }

    #[test]
    fn segwit_hrps_bind_testnet_and_regtest_but_legacy_does_not() {
        let tb = segwit_address(Network::Testnet);
        let bcrt = segwit_address(Network::Regtest);
        let mut testnet = onchain(&tb);
        if let PaymentMethod::Onchain { network, .. } = &mut testnet {
            *network = BitcoinNetwork::Testnet;
        }
        let mut regtest = onchain(&bcrt);
        if let PaymentMethod::Onchain { network, .. } = &mut regtest {
            *network = BitcoinNetwork::Regtest;
        }
        assert!(validate_payload(
            &testnet,
            &format!("bitcoin:{tb}?amount=0.00021000"),
            "devnet",
            Some(21_000)
        )
        .is_ok());
        assert!(validate_payload(
            &regtest,
            &format!("bitcoin:{bcrt}?amount=0.00021000"),
            "regtest",
            Some(21_000)
        )
        .is_ok());
        assert!(validate_payload(
            &testnet,
            &format!("bitcoin:{tb}?amount=0.00021000"),
            "regtest",
            Some(21_000)
        )
        .is_err());

        let mut legacy = onchain("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn");
        if let PaymentMethod::Onchain { network, .. } = &mut legacy {
            *network = BitcoinNetwork::Testnet;
        }
        assert!(validate_payload(
            &legacy,
            "bitcoin:mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
            "testnet",
            None
        )
        .is_err());
    }

    #[test]
    fn receive_pointers_are_amountless_or_explicitly_bound() {
        let method = onchain(MAINNET_ADDRESS);
        let payload = format!("bitcoin:{MAINNET_ADDRESS}");
        assert!(validate_payload(&method, &payload, "mainnet", None).is_ok());
        assert!(validate_payload(&method, &payload, "mainnet", Some(21_000)).is_err());

        let lightning = PaymentMethod::Lightning {
            label: "Lightning".into(),
            lightning_address: Some("alice@example.com".into()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        };
        assert!(validate_payload(&lightning, "alice@example.com", "mainnet", None).is_ok());
        assert!(
            validate_payload(&lightning, "alice@example.com", "mainnet", Some(21_000)).is_err()
        );
    }

    #[test]
    fn lnurl_receive_pointers_reject_ambiguous_urls() {
        let method = PaymentMethod::Lightning {
            label: "LNURL".into(),
            lightning_address: None,
            lnurl: Some("https://example.com/lnurl".into()),
            bolt12: None,
            receiver_pubkey: None,
        };
        assert!(validate_payload(&method, "https://example.com/lnurl", "mainnet", None).is_ok());
        assert!(validate_payload(
            &method,
            "https://example.com/lnurl",
            "mainnet",
            Some(21_000)
        )
        .is_err());
        for bad in [
            "http://example.com/lnurl",
            "https://example.com/lnurl?amount=1&amount=2",
            "https://user:pass@example.com/lnurl",
        ] {
            let mut method = method.clone();
            if let PaymentMethod::Lightning { lnurl, .. } = &mut method {
                *lnurl = Some(bad.into());
            }
            assert!(validate_payload(&method, bad, "mainnet", None).is_err());
        }
    }

    #[test]
    fn bolt11_requires_valid_signature_payee_network_amount_and_expiry() {
        let (valid, payee) = invoice(Currency::Bitcoin, Some(21_000_000), false);
        let method = PaymentMethod::Lightning {
            label: "Invoice".into(),
            lightning_address: Some("alice@example.com".into()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: Some(payee),
        };
        assert!(validate_payload(&method, &valid, "mainnet", Some(21_000)).is_ok());
        assert!(validate_payload(&method, &valid, "devnet", Some(21_000)).is_err());
        assert!(validate_payload(&method, &valid, "mainnet", Some(20_999)).is_err());
        assert!(validate_payload(&method, "lnbc1invalid", "mainnet", Some(21_000)).is_err());

        let (expired, _) = invoice(Currency::Bitcoin, Some(21_000_000), true);
        assert!(validate_payload(&method, &expired, "mainnet", Some(21_000)).is_err());
        let (amountless, _) = invoice(Currency::Bitcoin, None, false);
        assert!(validate_payload(&method, &amountless, "mainnet", Some(21_000)).is_err());
        let (testnet, _) = invoice(Currency::BitcoinTestnet, Some(21_000_000), false);
        assert!(validate_payload(&method, &testnet, "mainnet", Some(21_000)).is_err());

        let mut unbound = method.clone();
        if let PaymentMethod::Lightning {
            receiver_pubkey, ..
        } = &mut unbound
        {
            *receiver_pubkey = None;
        }
        assert!(validate_payload(&unbound, &valid, "mainnet", Some(21_000)).is_err());
        let mut wrong_payee = method;
        if let PaymentMethod::Lightning {
            receiver_pubkey, ..
        } = &mut wrong_payee
        {
            let secret = SecretKey::from_slice(&[4; 32]).unwrap();
            *receiver_pubkey =
                Some(secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), &secret).to_string());
        }
        assert!(validate_payload(&wrong_payee, &valid, "mainnet", Some(21_000)).is_err());
    }

    #[test]
    fn experimental_or_unbound_rails_fail_closed() {
        let silent = PaymentMethod::Onchain {
            label: "silent".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some(MAINNET_ADDRESS.into()),
            silent_payment_pubkey: Some("sp1invalid".into()),
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        };
        assert!(validate_payload(
            &silent,
            "bitcoin:sp1invalid?amount=0.00021000",
            "mainnet",
            Some(21_000)
        )
        .is_err());

        let ark = PaymentMethod::Ark {
            label: "Ark".into(),
            server: "https://ark.example.com".into(),
            pubkey: "02".repeat(33),
            vtxo_pointer: None,
            opaque_uri: None,
            proof: None,
            expires_at: None,
        };
        assert!(validate_payload(
            &ark,
            "satspath:ark?server=https://ark.example.com",
            "mainnet",
            None
        )
        .is_err());
    }
}
