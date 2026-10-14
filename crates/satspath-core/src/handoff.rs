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
    check::validate_method(method.into(), sats, now)
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
            PaymentMethod::Bolt12(offer) => Self::Bolt12(&offer.offer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(validate(&method, 2_000_000, 1_496_314_658).is_ok());
        assert!(validate(&method, 2_000_001, 1_496_314_658).is_err());
        assert!(validate(&method, 2_000_000, 1_496_318_258).is_err());
    }
}
