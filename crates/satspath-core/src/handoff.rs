//! Validate methods before route selection and wallet payload construction.
use bitcoin::Network;
use satspath_handoff as check;

/// Validate all supplied receiver fields, including metadata hidden by pointer priority.
pub fn validate_method(method: &crate::PaymentMethod, sats: u64) -> crate::Result<()> {
    validate(method, sats, chrono::Utc::now().timestamp(), None)
        .map_err(crate::SatsPathError::InvalidPaymentPointer)
}

/// Validate a method for a specific wallet network, including Lightning invoices.
pub fn validate_method_for_network(
    method: &crate::PaymentMethod,
    sats: u64,
    network: crate::BitcoinNetwork,
) -> crate::Result<()> {
    let network = match network {
        crate::BitcoinNetwork::Mainnet => Network::Bitcoin,
        crate::BitcoinNetwork::Testnet => Network::Testnet,
        crate::BitcoinNetwork::Regtest => Network::Regtest,
    };
    validate(method, sats, chrono::Utc::now().timestamp(), Some(network))
        .map_err(crate::SatsPathError::InvalidPaymentPointer)
}

/// Validate a fetched invoice against the requested network and amount before handoff.
pub fn validate_invoice_for_network(
    invoice: &str,
    sats: u64,
    network: crate::BitcoinNetwork,
) -> crate::Result<()> {
    let network = match network {
        crate::BitcoinNetwork::Mainnet => Network::Bitcoin,
        crate::BitcoinNetwork::Testnet => Network::Testnet,
        crate::BitcoinNetwork::Regtest => Network::Regtest,
    };
    check::bolt11(
        invoice,
        sats,
        network,
        chrono::Utc::now().timestamp().max(0) as u64,
    )
    .map_err(crate::SatsPathError::InvalidPaymentPointer)
}

/// Validate using an explicit clock so expiry tests remain deterministic.
fn validate(
    method: &crate::PaymentMethod,
    sats: u64,
    now: i64,
    network: Option<Network>,
) -> Result<(), String> {
    if let crate::PaymentMethod::Bolt12(offer) = method {
        if offer.expires_at.is_some_and(|expiry| expiry <= now) {
            return Err("BOLT12 method expired".into());
        }
    }
    check::validate_method(method.into(), sats, now, network)
}

impl<'a> From<&'a crate::PaymentMethod> for check::PaymentMethod<'a> {
    fn from(method: &'a crate::PaymentMethod) -> Self {
        use crate::PaymentMethod;
        match method {
            PaymentMethod::Onchain {
                network,
                address,
                silent_payment_pubkey,
                ..
            } => Self::Onchain {
                network: match network {
                    crate::BitcoinNetwork::Mainnet => Network::Bitcoin,
                    crate::BitcoinNetwork::Testnet => Network::Testnet,
                    crate::BitcoinNetwork::Regtest => Network::Regtest,
                },
                address: address.as_deref(),
                silent_payment_pubkey: silent_payment_pubkey.as_deref(),
            },
            PaymentMethod::Lightning {
                lightning_address,
                lnurl,
                bolt12,
                receiver_pubkey,
                ..
            } => Self::Lightning {
                lightning_address: lightning_address.as_deref(),
                lnurl: lnurl.as_deref(),
                bolt12: bolt12.as_deref(),
                receiver_pubkey: receiver_pubkey.as_deref(),
            },
            PaymentMethod::Ark {
                server,
                pubkey,
                vtxo_pointer,
                opaque_uri,
                expires_at,
                ..
            } => Self::Ark {
                server,
                pubkey,
                vtxo_pointer: vtxo_pointer.as_deref(),
                opaque_uri: opaque_uri.as_deref(),
                expires_at: *expires_at,
            },
            PaymentMethod::Bolt12(offer) => Self::Bolt12(
                &offer.offer,
                Some(match offer.network {
                    crate::BitcoinNetwork::Mainnet => Network::Bitcoin,
                    crate::BitcoinNetwork::Testnet => Network::Testnet,
                    crate::BitcoinNetwork::Regtest => Network::Regtest,
                }),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bolt12_handoff_uses_declared_network_and_clock() {
        use crate::{profile::Bolt12Offer, BitcoinNetwork};
        use bech32::ToBase32;
        use bitcoin::blockdata::constants::ChainHash;
        let key = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap();
        for (declared, network) in [
            (BitcoinNetwork::Mainnet, Network::Bitcoin),
            (BitcoinNetwork::Testnet, Network::Testnet),
            (BitcoinNetwork::Regtest, Network::Regtest),
        ] {
            let chain = ChainHash::using_genesis_block(network);
            let raw = [&[2, 32][..], chain.as_bytes(), &[14, 1, 101, 22, 33], &key].concat();
            let offer = bech32::encode("lno", raw.to_base32(), bech32::Variant::Bech32m).unwrap();
            let mut method = crate::PaymentMethod::Bolt12(Bolt12Offer {
                label: "offer".into(),
                offer,
                network: declared,
                minimum_amount_sats: None,
                expires_at: None,
                issuer_pubkey: hex::encode(&key),
            });
            assert!(validate(&method, 1, 100, None).is_ok());
            assert!(validate(&method, 1, 101, None).is_err());
            if let crate::PaymentMethod::Bolt12(offer) = &mut method {
                offer.expires_at = Some(100);
            }
            assert!(validate(&method, 1, 100, None).is_err());
            if let crate::PaymentMethod::Bolt12(offer) = &mut method {
                offer.expires_at = Some(101);
            }
            assert!(validate(&method, 1, 100, None).is_ok());
            if let crate::PaymentMethod::Bolt12(offer) = &mut method {
                offer.network = if network == Network::Bitcoin {
                    BitcoinNetwork::Testnet
                } else {
                    BitcoinNetwork::Mainnet
                };
            }
            assert!(validate(&method, 1, 100, None).is_err());
        }
    }

    /// The public BOLT11 testnet vector must pass through the shared method validator.
    #[test]
    fn testnet_invoice_handoff_uses_shared_policy() {
        let method = crate::PaymentMethod::Lightning {
            label: "testnet invoice".into(),
            lightning_address: None,
            lnurl: None,
            bolt12: Some("lntb20m1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygshp58yjmdan79s6qqdhdzgynm4zwqd5d7xmw5fk98klysy043l2ahrqspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqfpp3x9et2e20v6pu37c5d9vax37wxq72un989qrsgqdj545axuxtnfemtpwkc45hx9d2ft7x04mt8q7y6t0k2dge9e7h8kpy9p34ytyslj3yu569aalz2xdk8xkd7ltxqld94u8h2esmsmacgpghe9k8".into()),
            receiver_pubkey: None,
        };
        assert!(validate(&method, 2_000_000, 1_496_314_658, None).is_ok());
        assert!(validate(&method, 2_000_001, 1_496_314_658, None).is_err());
        assert!(validate(&method, 2_000_000, 1_496_318_258, None).is_err());
        assert!(validate(&method, 2_000_000, 1_496_314_658, Some(Network::Bitcoin)).is_err());
        assert!(validate(&method, 2_000_000, 1_496_314_658, Some(Network::Testnet)).is_ok());
    }
}
