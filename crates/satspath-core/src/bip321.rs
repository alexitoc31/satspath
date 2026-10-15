//! BIP-321 `bitcoin:` URI parsing.
//!
//! A BIP-353 DNS record reconstructs into a `bitcoin:` URI; this module parses
//! it into structured, public payment instructions. Parsing is **inert**: it
//! never pays, signs, or broadcasts — it only extracts what a wallet *could* do.
//!
//! Supported keys: on-chain address (URI path), `amount`, `lightning` (BOLT11),
//! `lno` (BOLT12 offer), `sp` (Silent Payment, preview-only). Unknown `req-*`
//! parameters make the URI invalid; other unknown parameters are captured, with
//! wallet handoff restricted to `label`, `message`, and `sp-profile*`. The
//! optional SatsPath extension `sp-profile` / `sp-profile-hash` is captured
//! without breaking BIP-321 compatibility.

use serde::{Deserialize, Serialize};

use crate::errors::{Result, SatsPathError};

/// One decoded BIP-321 instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Bip321Instruction {
    Onchain {
        address: String,
        amount_btc: Option<String>,
    },
    LightningBolt11 {
        invoice: String,
    },
    Bolt12Offer {
        offer: String,
    },
    SilentPayment {
        address: String,
    },
    Unknown {
        key: String,
        value: String,
        required: bool,
    },
}

/// A parsed `bitcoin:` URI.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParsedBip321Uri {
    pub raw: String,
    pub address: Option<String>,
    pub amount_btc: Option<String>,
    pub instructions: Vec<Bip321Instruction>,
    /// Optional SatsPath extension: a URL to fetch the signed profile after the
    /// domain is BIP-353 verified. Non-required, ignorable by other wallets.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sp_profile: Option<String>,
    /// Optional SatsPath extension: a SHA-256 of the expected signed profile.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub sp_profile_hash: Option<String>,
}

pub const MAX_BIP321_URI_BYTES: usize = 65_536;

impl ParsedBip321Uri {
    /// Validate every embedded rail before exposing the full URI to a wallet.
    pub fn validate_handoff(&self, sats: u64, network: bitcoin::Network, now: u64) -> Result<()> {
        let validate = || -> std::result::Result<(), String> {
            use satspath_handoff as check;
            check::amount(sats)?;
            if let Some(value) = &self.amount_btc {
                if check::btc_amount(value)? != sats {
                    return Err("URI amount does not match request".into());
                }
            }
            for instruction in &self.instructions {
                match instruction {
                    Bip321Instruction::Onchain { address, .. } => check::onchain(address, network)?,
                    Bip321Instruction::LightningBolt11 { invoice } => {
                        check::bolt11(invoice, sats, network, now)?
                    }
                    Bip321Instruction::Bolt12Offer { offer } => {
                        check::bolt12(offer, Some(network), now)?
                    }
                    Bip321Instruction::SilentPayment { address } => {
                        check::silent(address, network)?
                    }
                    Bip321Instruction::Unknown { key, required, .. } => {
                        if *required
                            || !(matches!(key.as_str(), "label" | "message")
                                || key.starts_with("sp-profile"))
                        {
                            return Err(format!("unsupported wallet URI parameter: {key}"));
                        }
                    }
                }
            }
            Ok(())
        };
        validate().map_err(SatsPathError::InvalidPaymentUri)
    }
}

/// Parse a `bitcoin:` URI into structured BIP-321 instructions.
///
/// # Errors
/// - The URI does not begin with `bitcoin:`.
/// - It carries an unsupported **required** (`req-*`) parameter.
pub fn parse_bip321(uri: &str) -> Result<ParsedBip321Uri> {
    if uri.len() > MAX_BIP321_URI_BYTES {
        return Err(SatsPathError::InvalidPaymentUri(
            "URI exceeds maximum allowed length (64KB)".into(),
        ));
    }
    let rest = uri.strip_prefix("bitcoin:").ok_or_else(|| {
        SatsPathError::InvalidPaymentUri("payment instruction must start with bitcoin:".into())
    })?;

    if rest.contains('#') {
        return Err(SatsPathError::InvalidPaymentUri(
            "URI fragments are forbidden".into(),
        ));
    }
    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (rest, None),
    };

    let address = if path.is_empty() {
        None
    } else {
        Some(percent_decode(path)?)
    };

    let mut instructions = Vec::new();
    let mut amount_btc: Option<String> = None;
    let mut sp_profile: Option<String> = None;
    let mut sp_profile_hash: Option<String> = None;

    let mut seen = std::collections::HashSet::new();
    if let Some(query) = query {
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (raw_key, raw_val) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            let key = percent_decode(raw_key)?.to_ascii_lowercase();
            let value = percent_decode(raw_val)?;
            if !seen.insert(key.clone()) {
                return Err(SatsPathError::InvalidPaymentUri(
                    "duplicate URI parameter".into(),
                ));
            }

            match key.as_str() {
                "amount" => amount_btc = Some(value),
                "lightning" => {
                    instructions.push(Bip321Instruction::LightningBolt11 { invoice: value })
                }
                "lno" => instructions.push(Bip321Instruction::Bolt12Offer { offer: value }),
                "sp" => instructions.push(Bip321Instruction::SilentPayment { address: value }),
                "sp-profile" => sp_profile = Some(value),
                "sp-profile-hash" => sp_profile_hash = Some(value),
                other => {
                    let required = other.starts_with("req-");
                    instructions.push(Bip321Instruction::Unknown {
                        key: key.clone(),
                        value,
                        required,
                    });
                }
            }
        }
    }

    // An unsupported *required* parameter invalidates the whole URI (BIP-21/321).
    if instructions
        .iter()
        .any(|i| matches!(i, Bip321Instruction::Unknown { required: true, .. }))
    {
        return Err(SatsPathError::InvalidPaymentUri(
            "unsupported required req-* parameter in bitcoin: URI".into(),
        ));
    }

    if let Some(address) = &address {
        use std::str::FromStr;
        bitcoin::Address::from_str(address)
            .map_err(|e| SatsPathError::InvalidPaymentUri(e.to_string()))?;
    }
    if let Some(value) = &amount_btc {
        satspath_handoff::btc_amount(value).map_err(SatsPathError::InvalidPaymentUri)?;
    }

    // Surface the on-chain address as its own instruction at the front.
    if let Some(addr) = &address {
        instructions.insert(
            0,
            Bip321Instruction::Onchain {
                address: addr.clone(),
                amount_btc: amount_btc.clone(),
            },
        );
    }

    Ok(ParsedBip321Uri {
        raw: uri.to_string(),
        address,
        amount_btc,
        instructions,
        sp_profile,
        sp_profile_hash,
    })
}

/// Decode RFC-3986 percent escapes (`%XX`). Unlike form decoding, `+` is left
/// untouched, matching BIP-21/321 URI semantics.
fn percent_decode(s: &str) -> Result<String> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let escaped = bytes
                .get(i + 1)
                .and_then(|&h| hex_nibble(h))
                .zip(bytes.get(i + 2).and_then(|&l| hex_nibble(l)));
            let (h, l) = escaped
                .ok_or_else(|| SatsPathError::InvalidPaymentUri("invalid percent escape".into()))?;
            out.push(h * 16 + l);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).map_err(|_| SatsPathError::InvalidPaymentUri("URI is not UTF-8".into()))
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bolt12_handoff_checks_clock_features_and_network() {
        use bech32::ToBase32;
        use bitcoin::{blockdata::constants::ChainHash, Network};
        let key = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap();
        for variant in [bech32::Variant::Bech32, bech32::Variant::Bech32m] {
            for (hrp, fields, expected_error) in [
                ("lno", vec![14, 1, 101], None),
                ("lno", vec![14, 1, 100], Some("expired")),
                ("lno", vec![12, 1, 2], None),
                ("lno", vec![12, 1, 1], Some("required")),
                ("lnot", vec![], None),
                (
                    "lno",
                    [&[2, 32][..], ChainHash::BITCOIN.as_bytes()].concat(),
                    None,
                ),
                (
                    "lno",
                    [&[2, 32][..], ChainHash::TESTNET3.as_bytes()].concat(),
                    Some("chain"),
                ),
            ] {
                let raw = [fields, vec![22, 33], key.clone()].concat();
                let offer = bech32::encode(hrp, raw.to_base32(), variant).unwrap();
                let parsed = parse_bip321(&format!("bitcoin:?lno={offer}")).unwrap();
                let result = parsed.validate_handoff(1, Network::Bitcoin, 100);
                if let Some(message) = expected_error {
                    assert!(result.unwrap_err().to_string().contains(message), "{offer}");
                } else {
                    result.unwrap();
                }
            }
        }
    }

    /// Parsing rejects malformed amounts and addresses; handoff checks every embedded rail.
    #[test]
    fn rejects_unsafe_uri_handoffs() {
        for uri in [
            "bitcoin:bc1bad",
            "bitcoin:?amount=0",
            "bitcoin:?amount=-1",
            "bitcoin:?amount=NaN",
            "bitcoin:?amount=0.000000001",
            "bitcoin:?amount=1&amount=2",
            "bitcoin:?amount=1&%61mount=2",
            "bitcoin:?%72eq-unknown=1",
            "bitcoin:?amount=%",
            "bitcoin:?amount=%FF",
        ] {
            assert!(parse_bip321(uri).is_err(), "{uri}");
        }
        let valid = "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00001000";
        let parsed = parse_bip321(valid).unwrap();
        assert!(parsed
            .validate_handoff(1000, bitcoin::Network::Bitcoin, 100)
            .is_ok());
        assert!(parsed
            .validate_handoff(1001, bitcoin::Network::Bitcoin, 100)
            .is_err());
        assert!(parsed
            .validate_handoff(1000, bitcoin::Network::Testnet, 100)
            .is_err());
        for extra in [
            "&lightning=lnbc1invalid",
            "&lno=lno1invalid",
            "&sp=sp1invalid",
        ] {
            assert!(parse_bip321(&format!("{valid}{extra}"))
                .unwrap()
                .validate_handoff(1000, bitcoin::Network::Bitcoin, 100)
                .is_err());
        }
    }

    /// Optional parsing stays forward compatible; wallet handoff uses an allowlist.
    #[test]
    fn handoff_rejects_unknown_parameters_except_metadata() {
        let base = "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00001000";
        for parameter in [
            "label=Coffee",
            "message=Thanks",
            "sp-profile=https%3A%2F%2Fexample.com%2Fprofile",
            "sp-profile-hash=abc",
            "sp-profile-version=1",
        ] {
            let parsed = parse_bip321(&format!("{base}&{parameter}")).unwrap();
            assert!(
                parsed
                    .validate_handoff(1000, bitcoin::Network::Bitcoin, 100)
                    .is_ok(),
                "{parameter}"
            );
        }
        for parameter in [
            "somefuture=x",
            "payjoin=https%3A%2F%2Fexample.com",
            "%70j=x",
        ] {
            let parsed = parse_bip321(&format!("{base}&{parameter}")).unwrap();
            assert!(
                parsed
                    .validate_handoff(1000, bitcoin::Network::Bitcoin, 100)
                    .is_err(),
                "{parameter}"
            );
        }
    }

    #[test]
    /// Verify that parses onchain with amount.
    fn parses_onchain_with_amount() {
        let p =
            parse_bip321("bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00021000").unwrap();
        assert_eq!(
            p.address.as_deref(),
            Some("1BoatSLRHtKNngkdXEeobR76b53LETtpyT")
        );
        assert_eq!(p.amount_btc.as_deref(), Some("0.00021000"));
        assert!(p.instructions.iter().any(|i| matches!(
            i,
            Bip321Instruction::Onchain { address, amount_btc }
                if address == "1BoatSLRHtKNngkdXEeobR76b53LETtpyT" && amount_btc.as_deref() == Some("0.00021000")
        )));
    }

    #[test]
    fn parses_lightning_bolt11() {
        let p = parse_bip321("bitcoin:?lightning=lnbc20n1pexample&amount=0.00001000").unwrap();
        assert!(p.address.is_none());
        assert!(p
            .instructions
            .iter()
            .any(|i| matches!(i, Bip321Instruction::LightningBolt11 { invoice } if invoice == "lnbc20n1pexample")));
    }

    #[test]
    fn parses_lno_bolt12_offer() {
        let p = parse_bip321("bitcoin:?lno=lno1qexampleoffer").unwrap();
        assert!(p
            .instructions
            .iter()
            .any(|i| matches!(i, Bip321Instruction::Bolt12Offer { offer } if offer == "lno1qexampleoffer")));
    }

    #[test]
    fn parses_silent_payment_preview() {
        let p = parse_bip321("bitcoin:?sp=sp1qexample").unwrap();
        assert!(p
            .instructions
            .iter()
            .any(|i| matches!(i, Bip321Instruction::SilentPayment { address } if address == "sp1qexample")));
    }

    #[test]
    fn unknown_optional_param_is_ignored_safely() {
        // Unknown but NOT req-* → captured as Unknown{required:false}, URI valid.
        let p = parse_bip321("bitcoin:?label=Coffee&somefuture=x").unwrap();
        assert!(p
            .instructions
            .iter()
            .all(|i| !matches!(i, Bip321Instruction::Unknown { required: true, .. })));
    }

    #[test]
    fn unknown_required_param_invalidates() {
        let err = parse_bip321("bitcoin:?req-future=1").unwrap_err();
        assert!(matches!(err, SatsPathError::InvalidPaymentUri(_)));
    }

    #[test]
    fn rejects_non_bitcoin_scheme() {
        assert!(parse_bip321("lightning:lnbc1...").is_err());
    }

    #[test]
    fn captures_sp_profile_extension() {
        let p = parse_bip321(
            "bitcoin:?lno=lno1x&sp-profile=https%3A%2F%2Fsatspath.dev%2F.well-known%2Fsatspath%2Frodrigo",
        )
        .unwrap();
        assert_eq!(
            p.sp_profile.as_deref(),
            Some("https://satspath.dev/.well-known/satspath/rodrigo")
        );
    }

    #[test]
    fn percent_decoding_amount_and_values() {
        let p = parse_bip321("bitcoin:?lno=a%20b").unwrap();
        assert!(p
            .instructions
            .iter()
            .any(|i| matches!(i, Bip321Instruction::Bolt12Offer { offer } if offer == "a b")));
    }

    /// Accept URIs at the 64 KiB limit and reject those one byte over it.
    #[test]
    fn enforces_uri_length_boundary() {
        let prefix = "bitcoin:?message=";
        let at_limit = format!("{prefix}{}", "x".repeat(65_536 - prefix.len()));
        assert_eq!(at_limit.len(), 65_536);
        assert!(parse_bip321(&at_limit).is_ok());

        let over_limit = format!("{prefix}{}", "x".repeat(65_537 - prefix.len()));
        assert_eq!(over_limit.len(), 65_537);
        assert!(matches!(
            parse_bip321(&over_limit),
            Err(SatsPathError::InvalidPaymentUri(message))
                if message.contains("exceeds maximum allowed length")
        ));
    }

    /// Reject an oversized URI with the expected length-limit error.
    #[test]
    fn test_rejects_oversized_uri() {
        let huge_uri = format!(
            "bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa?message={}",
            "x".repeat(70_000)
        );
        let err = parse_bip321(&huge_uri).unwrap_err();
        assert!(
            matches!(err, SatsPathError::InvalidPaymentUri(msg) if msg.contains("exceeds maximum allowed length"))
        );
    }
}
