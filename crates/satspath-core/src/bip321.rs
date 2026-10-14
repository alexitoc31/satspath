//! BIP-321 `bitcoin:` URI parsing.
//!
//! A BIP-353 DNS record reconstructs into a `bitcoin:` URI; this module parses
//! it into structured, public payment instructions. Parsing is **inert**: it
//! never pays, signs, or broadcasts — it only extracts what a wallet *could* do.
//!
//! Supported keys: on-chain address (URI path), `amount`, `lightning` (BOLT11),
//! `lno` (BOLT12 offer), `sp` (Silent Payment, preview-only). Unknown `req-*`
//! parameters make the URI invalid; other unknown parameters are ignored. The
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

    let (path, query) = match rest.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (rest, None),
    };

    let address = if path.is_empty() {
        None
    } else {
        Some(percent_decode(path))
    };

    let mut instructions = Vec::new();
    let mut amount_btc: Option<String> = None;
    let mut sp_profile: Option<String> = None;
    let mut sp_profile_hash: Option<String> = None;

    if let Some(query) = query {
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (raw_key, raw_val) = match pair.split_once('=') {
                Some((k, v)) => (k, v),
                None => (pair, ""),
            };
            let key = raw_key.to_ascii_lowercase();
            let value = percent_decode(raw_val);

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
fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
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
    fn parses_onchain_with_amount() {
        let p = parse_bip321("bitcoin:bc1qexample?amount=0.00021000").unwrap();
        assert_eq!(p.address.as_deref(), Some("bc1qexample"));
        assert_eq!(p.amount_btc.as_deref(), Some("0.00021000"));
        assert!(p.instructions.iter().any(|i| matches!(
            i,
            Bip321Instruction::Onchain { address, amount_btc }
                if address == "bc1qexample" && amount_btc.as_deref() == Some("0.00021000")
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
