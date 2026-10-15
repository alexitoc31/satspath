//! Fail-closed, transport-independent validation shared by native and browser handoffs.
use bech32::FromBase32;
use bitcoin::{Address, Network};
use lightning_invoice::Bolt11Invoice;
use std::{str::FromStr, time::Duration};

/// Maximum number of satoshis in Bitcoin's supply.
pub const MAX_SATS: u64 = 21_000_000 * 100_000_000;

/// Borrowed receiver fields adapted from native or browser payment methods.
pub enum PaymentMethod<'a> {
    Onchain {
        network: Network,
        address: Option<&'a str>,
        silent_payment_pubkey: Option<&'a str>,
    },
    Lightning {
        lightning_address: Option<&'a str>,
        lnurl: Option<&'a str>,
        bolt12: Option<&'a str>,
        receiver_pubkey: Option<&'a str>,
    },
    Ark {
        server: &'a str,
        pubkey: &'a str,
        vtxo_pointer: Option<&'a str>,
        opaque_uri: Option<&'a str>,
        expires_at: Option<i64>,
    },
    Bolt12(&'a str, Option<Network>),
}

/// Validate every supplied receiver field before route selection or wallet handoff.
/// The explicit clock keeps native and browser expiry policy identical.
pub fn validate_method(
    method: PaymentMethod<'_>,
    sats: u64,
    now: i64,
    expected_network: Option<Network>,
) -> Result<(), String> {
    amount(sats)?;
    match method {
        PaymentMethod::Onchain {
            network,
            address,
            silent_payment_pubkey,
        } => {
            if expected_network.is_some_and(|expected| expected != network) {
                return Err("on-chain network mismatch".into());
            }
            if address.is_none() && silent_payment_pubkey.is_none() {
                return Err("missing on-chain receiver".into());
            }
            if let Some(address) = address {
                onchain(address, network)?;
            }
            if let Some(address) = silent_payment_pubkey {
                silent(address, network)?;
            }
            Ok(())
        }
        PaymentMethod::Lightning {
            lightning_address,
            lnurl,
            bolt12: offer,
            receiver_pubkey,
        } => {
            if lightning_address.is_none() && lnurl.is_none() && offer.is_none() {
                return Err("missing Lightning receiver".into());
            }
            if let Some(address) = lightning_address {
                self::lightning_address(address)?;
            }
            if let Some(url) = lnurl {
                https(url)?;
            }
            if let Some(key) = receiver_pubkey {
                public_key(&hex::decode(key).map_err(|e| e.to_string())?)?;
            }
            if let Some(offer) = offer {
                if let Some(network) = bolt11_network(offer) {
                    if expected_network.is_some_and(|expected| expected != network) {
                        return Err("BOLT11 invoice network mismatch".into());
                    }
                    bolt11(offer, sats, network, now.max(0) as u64)?;
                } else {
                    bolt12(offer, expected_network, now.max(0) as u64)?;
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
        } => ark(
            server,
            &hex::decode(pubkey).map_err(|e| e.to_string())?,
            vtxo_pointer,
            opaque_uri,
            expires_at,
            now,
        ),
        PaymentMethod::Bolt12(offer, network) => {
            if expected_network.is_some_and(|expected| network.is_some_and(|n| n != expected)) {
                return Err("BOLT12 method network mismatch".into());
            }
            bolt12(offer, expected_network.or(network), now.max(0) as u64)
        }
    }
}

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
    let fraction_val = if fraction.is_empty() {
        0u64
    } else {
        fraction
            .parse::<u64>()
            .map_err(|e| format!("invalid fractional BTC amount: {e}"))?
    };
    let frac_sats = fraction_val
        .checked_mul(10u64.pow(8 - fraction.len() as u32))
        .ok_or("BTC amount overflow")?;
    let sats = whole
        .parse::<u64>()
        .map_err(|e| format!("invalid whole BTC amount: {e}"))?
        .checked_mul(100_000_000)
        .and_then(|n| n.checked_add(frac_sats))
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
    let expected = match network {
        Network::Bitcoin => "sp",
        Network::Regtest => "sprt",
        _ => "tsp",
    };
    if hrp.to_ascii_lowercase() != expected
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

/// Classify a BOLT11 invoice human-readable part (HRP) case-insensitively.
pub fn bolt11_network(s: &str) -> Option<Network> {
    let lower = s.to_ascii_lowercase();
    // Regtest must precede mainnet because `lnbcrt` starts with `lnbc`.
    if lower.starts_with("lnbcrt") {
        Some(Network::Regtest)
    } else if lower.starts_with("lntb") {
        Some(Network::Testnet)
    } else if lower.starts_with("lnbc") {
        Some(Network::Bitcoin)
    } else {
        None
    }
}

/// Verify a static profile BOLT11 invoice's signature, network, positive whole-sat amount, and expiry.
pub fn bolt11_profile(value: &str, network: Network, now: u64) -> Result<(), String> {
    let invoice = Bolt11Invoice::from_str(value).map_err(|e| e.to_string())?;
    let Some(msats) = invoice.amount_milli_satoshis() else {
        return Err("invoice amount is required".into());
    };
    if msats % 1000 != 0 {
        return Err("invoice amount must be a whole number of satoshis".into());
    }
    bolt11(value, msats / 1000, network, now)
}

/// Verify a decoded BOLT11 invoice's signature, network, exact amount, and expiry.
pub fn bolt11(value: &str, sats: u64, network: Network, now: u64) -> Result<(), String> {
    amount(sats)?;
    let invoice = Bolt11Invoice::from_str(value).map_err(|e| e.to_string())?;
    let expected_msats = sats.checked_mul(1000).ok_or("amount overflow in msats")?;
    if invoice.network() != network
        || invoice.amount_milli_satoshis() != Some(expected_msats)
        || invoice
            .expires_at()
            .is_none_or(|expiry| expiry <= Duration::from_secs(now))
    {
        return Err("invoice network, amount, or expiry mismatch".into());
    }
    Ok(())
}

/// Read one canonical bigsize integer without reading past the supplied TLV bytes.
fn bolt12_bigsize(input: &mut &[u8]) -> Result<u64, String> {
    let prefix = bolt12_take(input, 1)?[0];
    let (length, minimum) = match prefix {
        0..=0xfc => return Ok(u64::from(prefix)),
        0xfd => (2, 0xfd),
        0xfe => (4, 0x1_0000),
        0xff => (8, 0x1_0000_0000),
    };
    let mut bytes = [0u8; 8];
    bytes[8 - length..].copy_from_slice(bolt12_take(input, length)?);
    let value = u64::from_be_bytes(bytes);
    if value < minimum {
        return Err("non-canonical BOLT12 bigsize".into());
    }
    Ok(value)
}

fn bolt12_take<'a>(input: &mut &'a [u8], length: usize) -> Result<&'a [u8], String> {
    if length > input.len() {
        return Err("truncated BOLT12 TLV stream".into());
    }
    let (value, rest) = input.split_at(length);
    *input = rest;
    Ok(value)
}

/// Check concatenated BOLT #4 blinded paths, each including at least one hop.
fn bolt12_path(mut value: &[u8]) -> Result<(), String> {
    if value.is_empty() {
        return Err("BOLT12 offer paths must not be empty".into());
    }
    while !value.is_empty() {
        match value[0] {
            0 | 1 => {
                bolt12_take(&mut value, 9)?;
            } // sciddir: direction + u64.
            2 | 3 => public_key(bolt12_take(&mut value, 33)?)?,
            _ => return Err("invalid BOLT12 introduction node".into()),
        }
        public_key(bolt12_take(&mut value, 33)?)?; // First path key.
        let hops = usize::from(bolt12_take(&mut value, 1)?[0]);
        if hops == 0 || hops > 100 || hops > value.len() / 35 {
            return Err("invalid BOLT12 offer path hop count".into());
        }
        for _ in 0..hops {
            public_key(bolt12_take(&mut value, 33)?)?;
            let length = bolt12_take(&mut value, 2)?;
            let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
            bolt12_take(&mut value, length)?;
        }
    }
    Ok(())
}

/// Validate a BOLT12 offer's encoding, destination, required features, and expiry.
/// The `lno` HRP is network-neutral; `offer_chains` selects non-Bitcoin chains.
pub fn bolt12(value: &str, network: Option<Network>, now: u64) -> Result<(), String> {
    let trimmed = value.trim();
    if !trimmed.starts_with("lno1")
        && !trimmed.starts_with("lnot1")
        && !trimmed.starts_with("lnob1")
        && !trimmed.starts_with("lnos1")
    {
        return Err("invalid BOLT12 offer prefix".into());
    }
    use bitcoin::bech32::primitives::decode::CheckedHrpstring;
    use bitcoin::bech32::primitives::NoChecksum;

    let (hrp, raw_bytes): (String, Vec<u8>) = if let Ok((hrp, data, _)) = bech32::decode(trimmed) {
        let raw = Vec::<u8>::from_base32(&data).map_err(|e| e.to_string())?;
        (hrp, raw)
    } else {
        let checked = CheckedHrpstring::new::<NoChecksum>(trimmed)
            .map_err(|e| format!("invalid BOLT12 offer encoding: {e}"))?;
        checked
            .validate_segwit_padding()
            .map_err(|e| format!("invalid BOLT12 offer padding: {e}"))?;
        (
            checked.hrp().as_str().to_string(),
            checked.byte_iter().collect(),
        )
    };
    if !matches!(hrp.as_str(), "lno" | "lnot" | "lnob" | "lnos") {
        return Err("invalid BOLT12 offer HRP".into());
    }
    let mut raw = raw_bytes.as_slice();
    let mut last_type = None;
    let mut has_offer_chains = false;
    let mut has_currency = false;
    let mut has_amount = false;
    let mut has_description = false;
    let mut has_destination = false;
    while !raw.is_empty() {
        let tag = bolt12_bigsize(&mut raw)?;
        if last_type.is_some_and(|previous| tag <= previous) {
            return Err("BOLT12 TLV types must be strictly ascending".into());
        }
        last_type = Some(tag);
        let length =
            usize::try_from(bolt12_bigsize(&mut raw)?).map_err(|_| "BOLT12 TLV length overflow")?;
        let payload = bolt12_take(&mut raw, length)?;
        if !matches!(tag, 1..=79 | 1_000_000_000..=1_999_999_999) {
            return Err(format!("out-of-range BOLT12 offer TLV type: {tag}"));
        }
        match tag {
            2 => {
                has_offer_chains = true;
                if payload.is_empty() || !payload.len().is_multiple_of(32) {
                    return Err("invalid BOLT12 offer chain hashes".into());
                }
                if let Some(network) = network {
                    let chain =
                        bitcoin::blockdata::constants::ChainHash::using_genesis_block(network);
                    if !payload
                        .as_chunks::<32>()
                        .0
                        .iter()
                        .any(|hash| hash == chain.as_bytes())
                    {
                        return Err("BOLT12 offer chain network mismatch".into());
                    }
                }
            }
            6 => {
                has_currency = true;
            }
            8 => {
                if payload.is_empty() || payload.len() > 8 || payload.first() == Some(&0) {
                    return Err("invalid BOLT12 offer amount".into());
                }
                has_amount = true;
            }
            10 => {
                has_description = true;
            }
            12 => {
                // No required offer features are supported. Even bits are required;
                // unknown odd bits are optional and can be ignored.
                if payload.iter().any(|byte| byte & 0x55 != 0) {
                    return Err("unknown required BOLT12 offer feature".into());
                }
            }
            14 => {
                // BOLT truncated u64: at most eight big-endian bytes, no leading zero.
                if payload.len() > 8 || payload.first() == Some(&0) {
                    return Err("invalid BOLT12 offer absolute expiry".into());
                }
                let mut bytes = [0u8; 8];
                bytes[8 - payload.len()..].copy_from_slice(payload);
                if u64::from_be_bytes(bytes) <= now {
                    return Err("BOLT12 offer expired".into());
                }
            }
            16 => {
                bolt12_path(payload)?;
                has_destination = true;
            }
            22 => {
                public_key(payload)?;
                has_destination = true;
            }
            4 | 18 | 20 => {}
            _ if tag.is_multiple_of(2) => {
                return Err(format!("unknown even BOLT12 TLV type: {tag}"))
            }
            _ => {}
        }
    }
    if has_amount && !has_description {
        return Err("BOLT12 offer with amount requires description".into());
    }
    if has_currency && !has_amount {
        return Err("BOLT12 offer with currency requires amount".into());
    }
    if network.is_some_and(|network| network != Network::Bitcoin) && !has_offer_chains {
        return Err("non-Bitcoin BOLT12 offer requires offer_chains".into());
    }
    if !has_destination {
        return Err("BOLT12 offer missing invoice-request destination".into());
    }
    Ok(())
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

    fn offer_with_fields(hrp: &str, fields: &[u8]) -> String {
        let key = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap();
        let raw = [fields, &[22, 33], &key].concat();
        bitcoin::bech32::encode::<bitcoin::bech32::primitives::NoChecksum>(
            bitcoin::bech32::Hrp::parse(hrp).unwrap(),
            &raw,
        )
        .unwrap()
    }

    #[test]
    fn bolt12_expiry_is_canonical_and_strictly_in_the_future() {
        for (expiry, accepted) in [
            (vec![], false), // Empty tu64 is zero.
            (vec![99], false),
            (vec![100], false),
            (vec![101], true),
            (vec![1, 0], true),
            (u64::MAX.to_be_bytes().to_vec(), true),
            (vec![0, 101], false), // Non-minimal tu64.
            (vec![1; 9], false),
        ] {
            let fields = [vec![14, expiry.len() as u8], expiry].concat();
            let offer = offer_with_fields("lno", &fields);
            assert_eq!(bolt12(&offer, None, 100).is_ok(), accepted, "{fields:?}");
        }
        assert!(bolt12(&offer_with_fields("lno", &[]), None, u64::MAX).is_ok());
        assert!(bolt12(&offer_with_fields("lno", &[14, 0]), None, 0).is_err());
    }

    #[test]
    fn bolt12_rejects_required_features_and_ignores_optional_features() {
        assert!(bolt12(&offer_with_fields("lno", &[12, 0]), None, 100).is_ok());
        for bit in 0..24 {
            let mut fields = vec![12, 3, 0, 0, 0];
            fields[4 - bit / 8] = 1 << (bit % 8);
            let offer = offer_with_fields("lno", &fields);
            assert_eq!(bolt12(&offer, None, 100).is_ok(), bit % 2 == 1, "bit {bit}");
        }
        assert!(bolt12(&offer_with_fields("lno", &[12, 1, 3]), None, 100).is_err());
    }

    #[test]
    fn bolt12_network_checks_explicit_chain_membership() {
        use bitcoin::blockdata::constants::ChainHash;
        let networks = [
            (Network::Bitcoin, "lno"),
            (Network::Testnet, "lno"),
            (Network::Testnet4, "lno"),
            (Network::Regtest, "lno"),
            (Network::Signet, "lno"),
        ];
        for (network, hrp) in networks {
            let chain = ChainHash::using_genesis_block(network);
            let fields = [&[2, 32][..], chain.as_bytes()].concat();
            let offer = offer_with_fields(hrp, &fields);
            assert!(bolt12(&offer, None, 100).is_ok());
            assert!(bolt12(&offer_with_fields(hrp, &[]), None, 100).is_ok());
            for (selected, _) in networks {
                assert_eq!(
                    bolt12(&offer, Some(selected), 100).is_ok(),
                    network == selected,
                    "{network:?} offer on {selected:?}"
                );
            }
            assert_eq!(
                bolt12(&offer_with_fields(hrp, &[]), Some(network), 100).is_ok(),
                network == Network::Bitcoin
            );
        }

        let chains = [
            &[2, 64][..],
            ChainHash::BITCOIN.as_bytes(),
            ChainHash::TESTNET3.as_bytes(),
        ]
        .concat();
        assert!(bolt12(
            &offer_with_fields("lno", &chains),
            Some(Network::Testnet),
            100
        )
        .is_ok());
        assert!(bolt12(
            &offer_with_fields("lno", &chains),
            Some(Network::Regtest),
            100
        )
        .is_err());
        let mut reversed = ChainHash::BITCOIN.as_bytes().to_vec();
        reversed.reverse();
        let fields = [&[2, 32][..], &reversed].concat();
        assert!(bolt12(
            &offer_with_fields("lno", &fields),
            Some(Network::Bitcoin),
            100
        )
        .is_err());

        for length in [0, 1, 31, 33, 63, 65] {
            let fields = [vec![2, length], vec![1; length as usize]].concat();
            let offer = offer_with_fields("lno", &fields);
            assert!(bolt12(&offer, None, 100).is_err(), "length {length}");
            assert!(bolt12(&offer, Some(Network::Bitcoin), 100).is_err());
        }
    }

    #[test]
    fn bolt12_method_validation_passes_clock_and_optional_network() {
        let offer = offer_with_fields("lno", &[14, 1, 101]);
        for now in [100, 101, 102] {
            assert_eq!(
                validate_method(
                    PaymentMethod::Bolt12(&offer, Some(Network::Bitcoin)),
                    1,
                    now,
                    None
                )
                .is_ok(),
                now < 101
            );
            assert_eq!(
                validate_method(
                    PaymentMethod::Lightning {
                        lightning_address: Some("alice@example.com"),
                        lnurl: None,
                        bolt12: Some(&offer),
                        receiver_pubkey: None,
                    },
                    1,
                    now,
                    None
                )
                .is_ok(),
                now < 101
            );
        }
        assert!(validate_method(
            PaymentMethod::Bolt12(&offer, Some(Network::Testnet)),
            1,
            100,
            None
        )
        .is_err());
        assert!(validate_method(PaymentMethod::Bolt12(&offer, None), 1, 100, None).is_ok());
    }

    #[test]
    fn bolt12_requires_an_ordered_tlv_destination() {
        let key = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap();
        let mut node_record = vec![22, 33];
        node_record.extend_from_slice(&key);
        let encode =
            |raw: &[u8]| bech32::encode("lno", raw.to_base32(), bech32::Variant::Bech32m).unwrap();
        let checksumless = bitcoin::bech32::encode::<bitcoin::bech32::primitives::NoChecksum>(
            bitcoin::bech32::Hrp::parse("lno").unwrap(),
            &node_record,
        )
        .unwrap();
        assert!(bolt12(&encode(&node_record), None, 0).is_ok());
        assert!(bolt12(&checksumless, None, 0).is_ok());

        let mut path = [
            key.as_slice(),
            key.as_slice(),
            &[1],
            key.as_slice(),
            &[0, 1, 42],
        ]
        .concat();
        let mut path_record = vec![16, path.len() as u8];
        path_record.append(&mut path);
        assert!(bolt12(&encode(&path_record), None, 0).is_ok());

        let mut duplicate = node_record.clone();
        duplicate.extend_from_slice(&node_record);
        let mut descending = node_record.clone();
        descending.extend_from_slice(&[10, 1, b'x']);
        let mut truncated = vec![22, 34];
        truncated.extend_from_slice(&key);
        let mut bad_key = vec![22, 33];
        bad_key.extend_from_slice(&[0; 33]);
        for invalid in [
            "lno1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq".into(),
            encode(&[]),
            encode(&[10, 1, b'x']),
            encode(&[16, 0]),
            encode(&bad_key),
            encode(&truncated),
            encode(&duplicate),
            encode(&descending),
            encode(&[0xfd, 0, 22, 0]),
        ] {
            assert!(
                bolt12(&invalid, None, 0).is_err(),
                "accepted malformed offer: {invalid}"
            );
        }
    }

    #[test]
    fn bolt12_accepts_ldk_concatenated_blinded_paths() {
        // LDK's parses_bech32_encoded_offers vector: a public-key introduction
        // followed by sciddir 1x2x3, direction 1.
        // https://github.com/lightningdevkit/rust-lightning/blob/e3439aa835be3193e2ab39699c4a3c24cc84164b/lightning/src/offers/offer.rs#L2463
        assert!(bolt12(
            include_str!("../tests/data/ldk-offer-two-paths.txt"),
            None,
            0
        )
        .is_ok());
    }

    #[test]
    fn bolt12_unknown_tlv_parity() {
        let key = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")
            .unwrap();
        for (tag, accepted) in [
            (23, true),
            (24, false),
            (79, true),
            (80, false),
            (81, false),
        ] {
            let raw = [vec![22, 33], key.clone(), vec![tag, 0]].concat();
            let offer = bech32::encode("lno", raw.to_base32(), bech32::Variant::Bech32m).unwrap();
            assert_eq!(bolt12(&offer, None, 0).is_ok(), accepted, "tag {tag}");
        }
        // Tag 0 is outside the allowed offer range [1, 79] U [1_000_000_000, 1_999_999_999].
        let zero_tag = [vec![0, 0, 22, 33], key.clone()].concat();
        let offer_zero =
            bech32::encode("lno", zero_tag.to_base32(), bech32::Variant::Bech32m).unwrap();
        assert!(bolt12(&offer_zero, None, 0).is_err());

        // Offer with amount requires description; offer with currency requires amount.
        let with_amount_and_desc =
            offer_with_fields("lno", &[8, 2, 0x03, 0xe8, 10, 4, b't', b'e', b's', b't']);
        assert!(bolt12(&with_amount_and_desc, None, 0).is_ok());
        let amount_without_desc = offer_with_fields("lno", &[8, 2, 0x03, 0xe8]);
        assert!(bolt12(&amount_without_desc, None, 0).is_err());
        let currency_without_amount = offer_with_fields(
            "lno",
            &[6, 3, b'u', b's', b'd', 10, 4, b't', b'e', b's', b't'],
        );
        assert!(bolt12(&currency_without_amount, None, 0).is_err());
    }

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
        assert!(bolt12("lno1malformed", None, 0).is_err());
        assert!(bolt11("lnbc1malformed", 1000, Network::Bitcoin, 100).is_err());
    }
}

#[cfg(test)]
mod invoice_tests {
    use super::*;

    /// Invoice currency determines the network for method handoff, including regtest.
    #[test]
    fn method_handoff_uses_invoice_network_and_enforces_amount_and_expiry() {
        use bitcoin::{
            hashes::{sha256, Hash},
            secp256k1::{Secp256k1, SecretKey},
        };
        use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};

        let secp = Secp256k1::new();
        let fixture_key = SecretKey::from_slice(&[1; 32]).unwrap();
        for currency in [
            Currency::Bitcoin,
            Currency::BitcoinTestnet,
            Currency::Regtest,
        ] {
            let invoice = InvoiceBuilder::new(currency.clone())
                .description("handoff regression fixture".into())
                .payment_hash(sha256::Hash::hash(b"handoff regression fixture"))
                .payment_secret(PaymentSecret([42; 32]))
                .duration_since_epoch(Duration::from_secs(100))
                .expiry_time(Duration::from_secs(60))
                .min_final_cltv_expiry_delta(18)
                .amount_milli_satoshis(1_000_000)
                .build_signed(|hash| secp.sign_ecdsa_recoverable(hash, &fixture_key))
                .unwrap()
                .to_string();
            for invoice in [&invoice, &invoice.to_ascii_uppercase()] {
                let method = || PaymentMethod::Lightning {
                    lightning_address: None,
                    lnurl: None,
                    bolt12: Some(invoice),
                    receiver_pubkey: None,
                };
                assert!(
                    validate_method(method(), 1000, 100, None).is_ok(),
                    "{currency:?}"
                );
                assert!(validate_method(method(), 1001, 100, None).is_err());
                assert!(validate_method(method(), 1000, 160, None).is_err());
                assert!(
                    validate_method(method(), 1000, 100, Some(Network::Bitcoin)).is_ok()
                        == matches!(currency, Currency::Bitcoin)
                );
            }
        }
    }

    /// BOLT #11's public coffee invoice needs no private key fixture.
    #[test]
    fn bolt11_network_exact_amount_and_expiry() {
        let invoice = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";
        assert!(bolt11(invoice, 250_000, Network::Bitcoin, 1_496_314_658).is_ok());
        assert!(bolt11(invoice, 250_001, Network::Bitcoin, 1_496_314_658).is_err());
        assert!(bolt11(invoice, 250_000, Network::Testnet, 1_496_314_658).is_err());
        assert!(bolt11(invoice, 250_000, Network::Bitcoin, 1_496_314_718).is_err());
    }

    #[test]
    fn bolt11_network_classification() {
        assert_eq!(bolt11_network("lnbc100u..."), Some(Network::Bitcoin));
        assert_eq!(bolt11_network("LNBC100U..."), Some(Network::Bitcoin));
        assert_eq!(bolt11_network("lntb20m..."), Some(Network::Testnet));
        assert_eq!(bolt11_network("LNTB20M..."), Some(Network::Testnet));
        assert_eq!(bolt11_network("lnbcrt50u..."), Some(Network::Regtest));
        assert_eq!(bolt11_network("LNBCRT50U..."), Some(Network::Regtest));
        assert_eq!(bolt11_network("lno1..."), None);
        assert_eq!(bolt11_network("bc1q..."), None);
    }

    #[test]
    fn bolt11_amount_overflow_is_rejected() {
        let invoice = "lnbc2500u1pvjluezsp5zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zyg3zygspp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpu9qrsgquk0rl77nj30yxdy8j9vdx85fkpmdla2087ne0xh8nhedh8w27kyke0lp53ut353s06fv3qfegext0eh0ymjpf39tuven09sam30g4vgpfna3rh";
        assert!(bolt11(invoice, u64::MAX, Network::Bitcoin, 1_496_314_658).is_err());
    }
}
