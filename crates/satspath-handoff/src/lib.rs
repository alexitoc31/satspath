//! Fail-closed, transport-independent validation shared by native and browser handoffs.
use bech32::FromBase32;
use bitcoin::{Address, Network};
use lightning_invoice::Bolt11Invoice;
use std::{str::FromStr, time::Duration};

/// Maximum number of satoshis in Bitcoin's supply.
pub const MAX_SATS: u64 = 21_000_000 * 100_000_000;

/// Reject zero, overflow-prone, and above-supply payment amounts.
pub fn amount(sats: u64) -> Result<(), String> {
    if sats == 0 || sats > MAX_SATS {
        return Err("payment amount must be positive and within Bitcoin supply".into());
    }
    Ok(())
}

/// Parse a positive, exact decimal BTC amount without floating-point rounding.
pub fn btc_amount(value: &str) -> Result<u64, String> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    if whole.is_empty()
        || !whole.bytes().all(|b| b.is_ascii_digit())
        || fraction.len() > 8
        || !fraction.bytes().all(|b| b.is_ascii_digit())
        || (value.contains('.') && fraction.is_empty())
    {
        return Err("invalid BTC amount".into());
    }
    let sats = whole
        .parse::<u64>()
        .ok()
        .and_then(|n| n.checked_mul(100_000_000))
        .and_then(|n| {
            n.checked_add(
                fraction.parse::<u64>().unwrap_or(0) * 10u64.pow(8 - fraction.len() as u32),
            )
        })
        .ok_or("BTC amount overflow")?;
    amount(sats)?;
    Ok(sats)
}

/// Decode a Bitcoin address and enforce the declared network.
pub fn onchain(address: &str, network: Network) -> Result<(), String> {
    Address::from_str(address)
        .map_err(|e| e.to_string())?
        .require_network(network)
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// Validate BIP-352 version zero, Bech32m, network, and both curve points.
pub fn silent(address: &str, network: Network) -> Result<(), String> {
    let (hrp, data, variant) = bech32::decode(address).map_err(|e| e.to_string())?;
    let expected = if network == Network::Bitcoin {
        "sp"
    } else {
        "tsp"
    };
    if hrp != expected
        || variant != bech32::Variant::Bech32m
        || data.first().map(|v| v.to_u8()) != Some(0)
    {
        return Err("invalid Silent Payment network, version, or checksum".into());
    }
    let keys = Vec::<u8>::from_base32(&data[1..]).map_err(|e| e.to_string())?;
    if keys.len() != 66 {
        return Err("Silent Payment requires two compressed keys".into());
    }
    public_key(&keys[..33])?;
    public_key(&keys[33..])
}

/// Reject invalid or uncompressed public receiver keys.
pub fn public_key(bytes: &[u8]) -> Result<(), String> {
    if bytes.len() != 33 {
        return Err("expected a compressed receiver key".into());
    }
    secp256k1::PublicKey::from_slice(bytes).map_err(|e| e.to_string())?;
    Ok(())
}

/// Validate an HTTPS receiver URL without credentials, fragments, or a missing host.
pub fn https(value: &str) -> Result<(), String> {
    let url = url::Url::parse(value).map_err(|e| e.to_string())?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err("receiver URL must be HTTPS without credentials or fragments".into());
    }
    Ok(())
}

/// Validate a Lightning Address before constructing its HTTPS discovery URL.
pub fn lightning_address(value: &str) -> Result<(), String> {
    let (user, domain) = value.split_once('@').ok_or("invalid Lightning Address")?;
    if user.is_empty()
        || !user
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-+".contains(&b))
        || !domain.contains('.')
        || domain.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err("invalid Lightning Address".into());
    }
    https(&format!("https://{domain}/.well-known/lnurlp/{user}"))
}

/// Verify a decoded BOLT11 invoice's signature, network, exact amount, and expiry.
pub fn bolt11(value: &str, sats: u64, network: Network, now: u64) -> Result<(), String> {
    amount(sats)?;
    let invoice = Bolt11Invoice::from_str(value).map_err(|e| e.to_string())?;
    if invoice.network() != network
        || invoice.amount_milli_satoshis() != Some(sats * 1000)
        || invoice
            .expires_at()
            .is_none_or(|expiry| expiry <= Duration::from_secs(now))
    {
        return Err("invoice network, amount, or expiry mismatch".into());
    }
    Ok(())
}

/// Prototype offers cannot be safely handed to interoperable wallets.
/// Fail closed until a standards-conformant BOLT12 decoder is integrated.
pub fn bolt12(_value: &str) -> Result<(), String> {
    Err("BOLT12 wallet handoff unavailable: standards-conformant offer validation is not implemented".into())
}

/// Validate the supported Ark server/key receiver form and optional expiry.
/// Opaque URIs and VTXOs lack a protocol decoder and must not become wallet payloads.
pub fn ark(
    server: &str,
    key: &[u8],
    vtxo: Option<&str>,
    opaque: Option<&str>,
    expires: Option<i64>,
    now: i64,
) -> Result<(), String> {
    https(server)?;
    public_key(key)?;
    if vtxo.is_some() || opaque.is_some() {
        return Err("opaque Ark URI/VTXO handoff requires protocol validation".into());
    }
    if expires.is_some_and(|expiry| expiry <= now) {
        return Err("Ark receiver expired".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bech32::ToBase32;

    /// Decimal parsing must preserve satoshis and reject ambiguous or excessive amounts.
    #[test]
    fn exact_amount_boundaries() {
        assert_eq!(btc_amount("0.00000001").unwrap(), 1);
        assert_eq!(btc_amount("21000000").unwrap(), MAX_SATS);
        for value in [
            "0",
            "-1",
            "+1",
            "1e-8",
            "NaN",
            "0.000000001",
            "21000000.00000001",
            "18446744073709551616",
            "1.",
        ] {
            assert!(btc_amount(value).is_err(), "{value}");
        }
        for value in [0, MAX_SATS + 1, u64::MAX] {
            assert!(amount(value).is_err());
        }
    }

    /// Bitcoin addresses must decode and agree with the selected network.
    #[test]
    fn onchain_network_and_checksum() {
        let address = "1BoatSLRHtKNngkdXEeobR76b53LETtpyT";
        assert!(onchain(address, Network::Bitcoin).is_ok());
        assert!(onchain(address, Network::Testnet).is_err());
        assert!(onchain("bc1invalid", Network::Bitcoin).is_err());
    }

    /// BIP-352 uses a five-bit version followed by the two compressed public keys.
    #[test]
    fn silent_payment_network_version_keys_and_checksum() {
        let key = secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap()
        .serialize();
        let mut data = vec![bech32::u5::try_from_u8(0).unwrap()];
        data.extend([key, key].concat().to_base32());
        let address = bech32::encode("sp", &data, bech32::Variant::Bech32m).unwrap();
        assert!(silent(&address, Network::Bitcoin).is_ok());
        assert!(silent(&address, Network::Testnet).is_err());
        assert!(silent(
            &bech32::encode("sp", &data, bech32::Variant::Bech32).unwrap(),
            Network::Bitcoin
        )
        .is_err());
        data[0] = bech32::u5::try_from_u8(1).unwrap();
        assert!(silent(
            &bech32::encode("sp", &data, bech32::Variant::Bech32m).unwrap(),
            Network::Bitcoin
        )
        .is_err());
        let mut invalid = vec![bech32::u5::try_from_u8(0).unwrap()];
        invalid.extend([0u8; 66].to_base32());
        assert!(silent(
            &bech32::encode("sp", &invalid, bech32::Variant::Bech32m).unwrap(),
            Network::Bitcoin
        )
        .is_err());
    }

    /// Unsupported protocol forms and expired Ark receivers are unavailable.
    #[test]
    fn unsupported_and_expired_receivers_fail_closed() {
        let key = secp256k1::PublicKey::from_str(
            "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
        )
        .unwrap()
        .serialize();
        assert!(ark("https://ark.example", &key, None, None, Some(101), 100).is_ok());
        assert!(ark("https://ark.example", &key, None, None, Some(100), 100).is_err());
        assert!(ark("http://ark.example", &key, None, None, None, 100).is_err());
        assert!(ark("https://ark.example", &[0; 33], None, None, None, 100).is_err());
        assert!(ark(
            "https://ark.example",
            &key,
            Some("vtxo:bad"),
            None,
            None,
            100
        )
        .is_err());
        assert!(ark(
            "https://ark.example",
            &key,
            None,
            Some("ark:bad"),
            None,
            100
        )
        .is_err());
        assert!(bolt12("lno1malformed").is_err());
        assert!(bolt11("lnbc1malformed", 1000, Network::Bitcoin, 100).is_err());
    }
}

#[cfg(test)]
mod invoice_tests {
    use super::*;

    /// BOLT #11's public coffee invoice needs no private key fixture.
    #[test]
    fn bolt11_network_exact_amount_and_expiry() {
        let invoice = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";
        assert!(bolt11(invoice, 250_000, Network::Bitcoin, 1_496_314_658).is_ok());
        assert!(bolt11(invoice, 250_001, Network::Bitcoin, 1_496_314_658).is_err());
        assert!(bolt11(invoice, 250_000, Network::Testnet, 1_496_314_658).is_err());
        assert!(bolt11(invoice, 250_000, Network::Bitcoin, 1_496_314_718).is_err());
    }
}
