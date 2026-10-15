use lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use satspath_core::PaymentMethod;

pub fn is_lightning_available(method: &PaymentMethod) -> bool {
    match method {
        PaymentMethod::Lightning {
            lnurl,
            lightning_address,
            bolt12,
            ..
        } => lnurl.is_some() || lightning_address.is_some() || bolt12.is_some(),
        PaymentMethod::Bolt12(_) => true,
        _ => false,
    }
}

/// Check if Lightning is available for a specific amount by checking LNURL min_sendable.
/// Returns true if the amount is >= min_sendable (or if no LNURL to check).
pub async fn is_lightning_available_for_amount(method: &PaymentMethod, amount_sats: u64) -> bool {
    match method {
        PaymentMethod::Lightning {
            lightning_address: Some(addr),
            lnurl: None,
            bolt12: None,
            ..
        } => {
            // Try to fetch LNURL metadata to check min_sendable
            match fetch_lnurl_metadata(addr).await {
                Ok(meta) => amount_sats * 1_000 >= meta.min_sendable,
                Err(_) => true, // If we can't fetch, assume it's available (fail-open for UX)
            }
        }
        PaymentMethod::Lightning {
            lnurl: Some(_),
            lightning_address: None,
            bolt12: None,
            ..
        } => {
            // LNURL present but no lightning_address - we'd need to fetch the LNURL
            // For now, assume available (could fetch in future)
            true
        }
        PaymentMethod::Lightning {
            bolt12: Some(offer_str),
            ..
        } => {
            if let Some(network) = satspath_handoff::bolt11_network(offer_str) {
                satspath_handoff::bolt11(
                    offer_str,
                    amount_sats,
                    network,
                    chrono::Utc::now().timestamp().max(0) as u64,
                )
                .is_ok()
            } else {
                crate::bolt12::parse_bolt12_offer(offer_str)
                    .map(|offer| {
                        amount_sats
                            .checked_mul(1_000)
                            .is_some_and(|amount_msats| offer.is_amount_valid(amount_msats))
                    })
                    .unwrap_or(false)
            }
        }
        PaymentMethod::Bolt12(offer_data) => {
            bolt12_profile_offer_available(offer_data, amount_sats)
        }
        _ => false,
    }
}

pub fn lightning_address(method: &PaymentMethod) -> Option<&str> {
    match method {
        PaymentMethod::Lightning {
            lightning_address, ..
        } => lightning_address.as_deref(),
        _ => None,
    }
}

/// Check if Lightning is available for a specific amount (synchronous version).
/// Uses a default minimum of 1000 sats (1,000,000 msats) if LNURL metadata unavailable.
pub fn is_lightning_available_for_amount_sync(method: &PaymentMethod, amount_sats: u64) -> bool {
    const DEFAULT_MIN_SENDABLE_MSATS: u64 = 1_000_000; // 1000 sats
    match method {
        PaymentMethod::Lightning {
            lightning_address: Some(_),
            lnurl: None,
            bolt12: None,
            ..
        } => amount_sats * 1_000 >= DEFAULT_MIN_SENDABLE_MSATS,
        PaymentMethod::Lightning {
            lnurl: Some(_),
            lightning_address: None,
            bolt12: None,
            ..
        } => true, // Can't check without fetching
        PaymentMethod::Lightning {
            bolt12: Some(offer_str),
            ..
        } => {
            if let Some(network) = satspath_handoff::bolt11_network(offer_str) {
                satspath_handoff::bolt11(
                    offer_str,
                    amount_sats,
                    network,
                    chrono::Utc::now().timestamp().max(0) as u64,
                )
                .is_ok()
            } else {
                crate::bolt12::parse_bolt12_offer(offer_str)
                    .map(|offer| {
                        amount_sats
                            .checked_mul(1_000)
                            .is_some_and(|amount_msats| offer.is_amount_valid(amount_msats))
                    })
                    .unwrap_or(false)
            }
        }
        PaymentMethod::Bolt12(offer_data) => {
            bolt12_profile_offer_available(offer_data, amount_sats)
        }
        _ => false,
    }
}

fn bolt12_profile_offer_available(
    offer_data: &satspath_core::Bolt12Offer,
    amount_sats: u64,
) -> bool {
    if offer_data
        .expires_at
        .is_some_and(|expiry| expiry <= chrono::Utc::now().timestamp())
        || offer_data
            .minimum_amount_sats
            .is_some_and(|minimum| amount_sats < minimum)
    {
        return false;
    }
    crate::bolt12::parse_bolt12_offer(&offer_data.offer)
        .map(|offer| {
            amount_sats
                .checked_mul(1_000)
                .is_some_and(|amount_msats| offer.is_amount_valid(amount_msats))
        })
        .unwrap_or(false)
}

pub fn estimate_lightning_fee_sats(amount_sats: u64) -> u64 {
    std::cmp::max(1, amount_sats / 10_000)
}

// ─── LNURL-pay two-step protocol ─────────────────────────────────────────────

/// Response from step 1: GET https://domain/.well-known/lnurlp/<user>
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LnurlPayMetadata {
    pub callback: String,
    pub min_sendable: u64, // millisatoshis
    pub max_sendable: u64, // millisatoshis
    pub tag: String,
    #[serde(default)]
    pub comment_allowed: u64,
}

/// Response from step 2: GET {callback}?amount=<msats>
/// The LNURL spec allows either a `pr` field (success) or an error response.
#[derive(Debug, Deserialize)]
pub struct LnurlInvoiceResponse {
    /// BOLT11 payment request (success case).
    pub pr: Option<String>,
    /// LNURL error status string (e.g. "ERROR"). Present on failure.
    #[serde(default)]
    pub status: Option<String>,
    /// Human-readable reason for the error.
    #[serde(default)]
    pub reason: Option<String>,
}

/// A parsed and validated BOLT11 invoice returned by the LNURL callback.
#[derive(Debug, Serialize)]
pub struct ValidatedInvoice {
    /// The raw BOLT11 string.
    pub bolt11: String,
    /// Amount in millisatoshis as decoded from the invoice.
    pub amount_msats: u64,
    /// Whether the invoice is within its validity window.
    pub is_fresh: bool,
}

/// Step 1: resolve a Lightning Address to LNURL-pay metadata.
/// `user@domain` → GET `https://domain/.well-known/lnurlp/user`
pub async fn fetch_lnurl_metadata(lightning_address: &str) -> anyhow::Result<LnurlPayMetadata> {
    fetch_lnurl_metadata_internal(lightning_address, true).await
}

/// Fetch LNURL metadata with explicit SSRF enforcement control (test-only transport path for mock servers).
#[cfg(test)]
pub(crate) async fn fetch_lnurl_metadata_with_options(
    lightning_address: &str,
    enforce_ssrf: bool,
) -> anyhow::Result<LnurlPayMetadata> {
    fetch_lnurl_metadata_internal(lightning_address, enforce_ssrf).await
}

async fn fetch_lnurl_metadata_internal(
    lightning_address: &str,
    enforce_ssrf: bool,
) -> anyhow::Result<LnurlPayMetadata> {
    let parts: Vec<&str> = lightning_address.split('@').collect();
    if parts.len() != 2 {
        anyhow::bail!("invalid Lightning Address: {}", lightning_address);
    }
    let domain = parts[1].trim();
    let scheme =
        if !enforce_ssrf && (domain.starts_with("127.0.0.1") || domain.starts_with("localhost")) {
            "http"
        } else {
            "https"
        };
    let url = format!(
        "{}://{}/.well-known/lnurlp/{}",
        scheme,
        domain,
        parts[0].trim()
    );
    let client = if enforce_ssrf {
        satspath_core::outbound::validate_request_url(&url)?;
        satspath_core::outbound::http_client(std::time::Duration::from_secs(10))
    } else {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?
    };
    let meta = client
        .get(&url)
        .send()
        .await?
        .json::<LnurlPayMetadata>()
        .await?;
    if meta.tag != "payRequest" {
        anyhow::bail!("unexpected LNURL tag: {}", meta.tag);
    }
    Ok(meta)
}

/// Step 2: call the callback to get a real BOLT11 invoice.
///
/// # LNURL-02 Validation
/// This function performs full validation of the returned invoice:
/// 1. Detects LNURL ERROR responses and returns them as a typed failure.
/// 2. Checks that `pr` is present and non-empty.
/// 3. Decodes the BOLT11 invoice using `lightning-invoice`.
/// 4. Verifies that the invoice amount (in msats) matches the requested amount.
/// 5. Checks that the invoice has not expired.
pub async fn fetch_invoice(
    meta: &LnurlPayMetadata,
    amount_sats: u64,
    comment: Option<&str>,
) -> anyhow::Result<String> {
    fetch_invoice_internal(meta, amount_sats, comment, true).await
}

/// Fetch invoice with explicit SSRF enforcement control (test-only transport path for mock servers).
#[cfg(test)]
pub(crate) async fn fetch_invoice_with_options(
    meta: &LnurlPayMetadata,
    amount_sats: u64,
    comment: Option<&str>,
    enforce_ssrf: bool,
) -> anyhow::Result<String> {
    fetch_invoice_internal(meta, amount_sats, comment, enforce_ssrf).await
}

async fn fetch_invoice_internal(
    meta: &LnurlPayMetadata,
    amount_sats: u64,
    comment: Option<&str>,
    enforce_ssrf: bool,
) -> anyhow::Result<String> {
    satspath_core::validation::validate_amount_sats(amount_sats)?;
    let amount_msats = amount_sats * 1_000;
    if amount_msats < meta.min_sendable {
        anyhow::bail!(
            "amount {} sats ({} msats) below minimum {} msats",
            amount_sats,
            amount_msats,
            meta.min_sendable
        );
    }
    if amount_msats > meta.max_sendable {
        anyhow::bail!(
            "amount {} sats ({} msats) exceeds maximum {} msats",
            amount_sats,
            amount_msats,
            meta.max_sendable
        );
    }

    let mut url = format!("{}?amount={}", meta.callback, amount_msats);
    if let Some(c) = comment {
        if meta.comment_allowed > 0 {
            let trimmed = &c[..c.len().min(meta.comment_allowed as usize)];
            url.push_str(&format!("&comment={}", urlencoding::encode(trimmed)));
        }
    }

    let client = if enforce_ssrf {
        satspath_core::outbound::validate_request_url(&url)?;
        satspath_core::outbound::http_client(std::time::Duration::from_secs(10))
    } else {
        reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()?
    };
    let raw_body = client.get(&url).send().await?.text().await?;
    let resp: LnurlInvoiceResponse = serde_json::from_str(&raw_body)
        .map_err(|e| anyhow::anyhow!("failed to parse LNURL callback response: {e}"))?;

    // LNURL-02: typed LNURL ERROR response
    if resp.status.as_deref() == Some("ERROR") {
        anyhow::bail!(
            "LNURL server returned error: {}",
            resp.reason.as_deref().unwrap_or("unknown reason")
        );
    }

    let bolt11 = resp
        .pr
        .ok_or_else(|| anyhow::anyhow!("LNURL callback returned no invoice (missing 'pr')"))?;

    if bolt11.is_empty() {
        anyhow::bail!("LNURL callback returned empty invoice");
    }

    // LNURL-02: decode and validate the BOLT11 invoice
    validate_bolt11_invoice(&bolt11, amount_msats)?;

    Ok(bolt11)
}

/// Decode a BOLT11 invoice and validate its amount and expiry.
///
/// Returns an error if:
/// - The invoice is unparseable.
/// - The invoice amount does not match `expected_msats`.
/// - The invoice has expired.
pub fn validate_bolt11_invoice(
    bolt11: &str,
    expected_msats: u64,
) -> anyhow::Result<ValidatedInvoice> {
    let invoice = Bolt11Invoice::from_str(bolt11)
        .map_err(|e| anyhow::anyhow!("failed to parse BOLT11 invoice: {e:?}"))?;

    if expected_msats == 0
        || expected_msats > satspath_core::validation::MAX_PREVIEW_AMOUNT_SATS * 1000
        || invoice.network() != bitcoin::Network::Bitcoin
    {
        anyhow::bail!("invoice network or amount is invalid");
    }
    // LNURL-02: verify amount matches
    let invoice_msats = invoice
        .amount_milli_satoshis()
        .ok_or_else(|| anyhow::anyhow!("invoice has no amount set — ambiguous invoice rejected"))?;

    if invoice_msats != expected_msats {
        anyhow::bail!(
            "invoice amount mismatch: requested {} msats but invoice contains {} msats",
            expected_msats,
            invoice_msats
        );
    }

    // LNURL-02: check expiry
    let is_fresh = !invoice.is_expired();
    if !is_fresh {
        anyhow::bail!("invoice has expired and cannot be paid");
    }

    Ok(ValidatedInvoice {
        bolt11: bolt11.to_string(),
        amount_msats: invoice_msats,
        is_fresh,
    })
}

// ─── BOLT11 invoice amount verification ───────────────────────────────────────

/// Parse the satoshi amount encoded in a BOLT11 invoice's human-readable part (HRP).
///
/// BOLT11 HRP format: `ln<network>[<amount><multiplier>]`
/// Networks: `bc` (mainnet), `tb` (testnet), `bcrt` (regtest)
/// Multipliers: m (milli), u (micro), n (nano), p (pico)
///
/// Returns `None` if the invoice carries no amount (amount-less invoice).
pub fn parse_bolt11_amount_sats(invoice: &str) -> Option<u64> {
    let inv = invoice.to_lowercase();
    // bech32 separator: the last '1' in the string
    let sep = inv.rfind('1')?;
    let hrp = &inv[..sep];

    // Strip the network prefix to get the optional amount string
    let amount_str = hrp
        .strip_prefix("lnbc") // mainnet
        .or_else(|| hrp.strip_prefix("lntb")) // testnet
        .or_else(|| hrp.strip_prefix("lnbcrt")) // regtest
        .or_else(|| hrp.strip_prefix("lnsb")) // signet
        .or_else(|| hrp.strip_prefix("lntbs"))?; // testnet4

    if amount_str.is_empty() {
        return None; // amount-less invoice
    }

    // Last char may be a multiplier letter
    let last_char = amount_str.chars().last()?;
    let (digits, multiplier) = if last_char.is_alphabetic() {
        (&amount_str[..amount_str.len() - 1], Some(last_char))
    } else {
        (amount_str, None)
    };

    if digits.is_empty() {
        return None;
    }

    let amount_val: u64 = digits.parse().ok()?;

    // BOLT11 amounts are BTC scaled by the multiplier.
    // 1 BTC = 100_000_000 sats.
    match multiplier {
        None => amount_val.checked_mul(100_000_000),  // raw BTC
        Some('m') => amount_val.checked_mul(100_000), // milli-BTC = 1e5 sats
        Some('u') => amount_val.checked_mul(100),     // micro-BTC = 100 sats
        Some('n') => {
            // nano-BTC = 0.1 sats; must be divisible by 10 for whole sats
            if !amount_val.is_multiple_of(10) {
                return None;
            }
            Some(amount_val / 10)
        }
        Some('p') => {
            // pico-BTC = 0.0001 sats; must be divisible by 10_000
            if !amount_val.is_multiple_of(10_000) {
                return None;
            }
            Some(amount_val / 10_000)
        }
        _ => None,
    }
}

/// Verify that a BOLT11 invoice encodes exactly `expected_sats`.
///
/// Aborts if:
/// - The invoice carries no amount (amount-less invoices are not accepted)
/// - The encoded amount does not match `expected_sats`
///
/// Note: expiry verification requires bech32 data field decoding and is tracked
/// as Engine v1 work. Until implemented, expiry is not checked here.
pub fn verify_invoice_amount(invoice: &str, expected_sats: u64) -> anyhow::Result<()> {
    match parse_bolt11_amount_sats(invoice) {
        None => anyhow::bail!(
            "invoice carries no amount (amount-less BOLT11 not accepted in Engine v0). \
             Expected {} sats.",
            expected_sats
        ),
        Some(invoice_sats) if invoice_sats != expected_sats => anyhow::bail!(
            "invoice amount mismatch: invoice encodes {} sats, expected {} sats. \
             Refusing to display a mismatched invoice.",
            invoice_sats,
            expected_sats
        ),
        Some(_) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::{sha256, Hash};
    use lightning_invoice::{Currency, InvoiceBuilder, PaymentSecret};
    use satspath_core::crypto::generate_identity_keypair;
    use secp256k1::Secp256k1;
    use std::time::{Duration, SystemTime};

    fn make_test_invoice(amount_msats: Option<u64>, expired: bool) -> String {
        let kp = generate_identity_keypair();
        let payment_hash = sha256::Hash::hash(&[2; 32]);
        let payment_secret = PaymentSecret([3; 32]);

        let builder = InvoiceBuilder::new(Currency::Bitcoin)
            .description("test".into())
            .payment_hash(payment_hash)
            .payment_secret(payment_secret)
            .min_final_cltv_expiry_delta(144);

        let builder = if let Some(amt) = amount_msats {
            builder.amount_milli_satoshis(amt)
        } else {
            builder
        };

        let builder_with_time = if expired {
            let past = SystemTime::now() - Duration::from_secs(3600);
            builder.timestamp(past).expiry_time(Duration::from_secs(1))
        } else {
            builder.current_timestamp()
        };

        builder_with_time
            .build_signed(|hash| {
                let secp = Secp256k1::new();
                let msg = secp256k1::Message::from_digest_slice(hash.as_ref()).unwrap();
                secp.sign_ecdsa_recoverable(&msg, &kp.secret_key)
            })
            .unwrap()
            .to_string()
    }

    #[test]
    fn valid_bolt11_invoice_accepted() {
        let inv = make_test_invoice(Some(1000), false);
        assert!(validate_bolt11_invoice(&inv, 1000).is_ok());
    }

    #[test]
    fn invoice_amount_mismatch_fails() {
        let inv = make_test_invoice(Some(1000), false);
        let err = validate_bolt11_invoice(&inv, 500).unwrap_err();
        assert!(err.to_string().contains("mismatch"));
    }

    #[test]
    fn zero_or_missing_amount_fails() {
        let inv = make_test_invoice(None, false);
        let err = validate_bolt11_invoice(&inv, 1000).unwrap_err();
        assert!(err.to_string().contains("no amount"));
    }

    #[test]
    fn expired_invoice_fails() {
        let inv = make_test_invoice(Some(1000), true);
        let err = validate_bolt11_invoice(&inv, 1000).unwrap_err();
        assert!(err.to_string().contains("expired"));
    }

    #[test]
    fn garbage_invoice_rejected() {
        let result = validate_bolt11_invoice("not_a_real_invoice", 1_000);
        assert!(result.is_err(), "unparseable invoice must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to parse"));
    }

    #[test]
    fn estimate_lightning_fee_minimum_one_sat() {
        assert_eq!(estimate_lightning_fee_sats(0), 1);
        assert_eq!(estimate_lightning_fee_sats(100), 1);
        assert_eq!(estimate_lightning_fee_sats(10_000), 1);
        assert_eq!(estimate_lightning_fee_sats(20_000), 2);
    }

    #[tokio::test]
    async fn bolt11_accepted_in_availability_checks() {
        let inv = make_test_invoice(Some(1_000_000), false); // 1,000 sats = 1,000,000 msats
        let method = PaymentMethod::Lightning {
            label: "Invoice".into(),
            lightning_address: None,
            lnurl: None,
            bolt12: Some(inv),
            receiver_pubkey: None,
        };
        assert!(is_lightning_available_for_amount(&method, 1000).await);
        assert!(is_lightning_available_for_amount_sync(&method, 1000));
        assert!(!is_lightning_available_for_amount(&method, 500).await);
        assert!(!is_lightning_available_for_amount_sync(&method, 500));
    }
}
