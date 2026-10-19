//! BOLT12 transport and host wallet handoff. Public-data codecs are shared with core.
use anyhow::{anyhow, Context, Result};
pub use satspath_core::bolt12::*;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// Blinded Path Resolution & Onion Message Dispatch (CLN / LDK Interoperability)
// ============================================================================

/// Resolved onion message delivery route extracted from a [`Bolt12Offer`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedOnionRoute {
    /// Entry point into the route (`NodeId` or `DirectedShortChannelId`).
    pub introduction: IntroductionNode,
    /// Ephemeral 33-byte blinding point (hex), if routing over a blinded path.
    pub blinding_point: Option<String>,
    /// Ordered blinded hops to traverse after the introduction node.
    pub blinded_hops: Vec<BlindedHop>,
}

/// Resolve the onion message delivery route for a [`Bolt12Offer`].
///
/// Prefers the offer's primary [`BlindedPath`] (preserving receiver privacy via
/// `IntroductionNode::NodeId` or `IntroductionNode::DirectedShortChannelId`),
/// falling back to a direct single-hop route to `offer.node_id` if no blinded path is present.
///
/// # Errors
/// Returns an error if the offer has neither a valid blinded path nor a valid `node_id`.
pub fn resolve_offer_onion_route(offer: &Bolt12Offer) -> Result<ResolvedOnionRoute> {
    if let Some(primary) = offer.primary_blinded_path() {
        let intro = primary.parsed_introduction_node()?;
        return Ok(ResolvedOnionRoute {
            introduction: intro,
            blinding_point: primary.blinding_point.clone(),
            blinded_hops: primary.blinded_hops.clone(),
        });
    }

    if let Some(ref nid) = offer.node_id {
        let bytes = hex::decode(nid).context("invalid offer node_id hex")?;
        satspath_core::validation::validate_compressed_pubkey(&hex::encode(bytes))?;
        return Ok(ResolvedOnionRoute {
            introduction: IntroductionNode::NodeId(nid.clone()),
            blinding_point: None,
            blinded_hops: Vec::new(),
        });
    }

    anyhow::bail!("BOLT12 offer contains neither blinded_paths nor node_id")
}

/// Complete BOLT #12 onion message payload envelope ready for dispatch over a Lightning node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnionMessageEnvelope {
    /// Target route resolved from the offer (`offer_paths` or `offer_issuer_id`).
    pub destination_route: ResolvedOnionRoute,
    /// Payer's reply blinded path (`invreq_paths`) so the recipient node can return the `invoice`.
    pub reply_blinded_path: BlindedPath,
    /// Raw TLV wire bytes of the signed `invoice_request` (onion message TLV type `64`).
    pub invoice_request_tlv_hex: String,
    /// Checksumless Bech32-encoded `invoice_request` (`lnr1...`).
    pub invoice_request_bech32: String,
}

/// Build a signed [`OnionMessageEnvelope`] from a [`Bolt12Offer`] and host wallet signer.
///
/// # Errors
/// Returns an error if the offer is expired, the amount is out of bounds, or route resolution fails.
pub fn build_invoice_request_onion_envelope(
    offer: &Bolt12Offer,
    amount_msats: u64,
    payer_key: &dyn Bolt12Signer,
    reply_blinded_path: BlindedPath,
    payer_note: Option<&str>,
    quantity: Option<u64>,
) -> Result<(Bolt12InvoiceRequest, OnionMessageEnvelope)> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if offer.is_expired(now) {
        anyhow::bail!("Cannot construct invoice_request: BOLT12 offer has expired");
    }
    if !offer.is_amount_valid(amount_msats) {
        anyhow::bail!(
            "Amount {amount_msats} msats is outside bounds for offer (min: {:?}, max: {:?})",
            offer.min_amount_msats,
            offer.max_amount_msats
        );
    }

    let destination_route = resolve_offer_onion_route(offer)?;

    let payer_pubkey = hex::encode(payer_key.public_key().serialize());

    let mut req = create_invoice_request(
        offer,
        amount_msats,
        Some(payer_pubkey),
        quantity,
        payer_note.map(|s| s.to_string()),
        None,
        Some(vec![reply_blinded_path.clone()]),
        Some(3600),
    )?;

    let offer_id = offer.offer_id()?;
    let unsigned_records = req.to_unsigned_tlv_records(&offer_id)?;
    let sig = sign_bolt12_tlv_stream("invoice_request", &unsigned_records, payer_key)?;
    req.signature = Some(hex::encode(sig));

    let tlv_bytes = req.to_tlv_bytes()?;
    let bech32_str = req.encode()?;

    let envelope = OnionMessageEnvelope {
        destination_route,
        reply_blinded_path,
        invoice_request_tlv_hex: hex::encode(&tlv_bytes),
        invoice_request_bech32: bech32_str,
    };

    Ok((req, envelope))
}

/// Transport abstraction for dispatching a BOLT #12 `invoice_request` over Onion Messages
/// (e.g. via Core Lightning `fetchinvoice` / `sendonionmessage` or LDK `OnionMessenger`)
/// and returning the verified [`Bolt12Invoice`].
pub trait OnionMessageTransport: Send + Sync {
    /// Dispatch `envelope` for `offer` and return the resulting [`Bolt12Invoice`].
    ///
    /// # Errors
    /// Returns an error if transport fails or if the returned invoice fails validation.
    fn dispatch_invoice_request(
        &self,
        offer: &Bolt12Offer,
        request: &Bolt12InvoiceRequest,
        envelope: &OnionMessageEnvelope,
    ) -> Result<Bolt12Invoice>;
}

/// Reference Core Lightning (CLN) / LDK node responder used for conformance and integration testing.
///
/// Validates the incoming [`OnionMessageEnvelope`] (blinded path structure, `offer_id` Merkle root,
/// and payer `invoice_request` Schnorr signature) and signs a standards-compliant [`Bolt12Invoice`]
/// with the recipient node's key.
pub struct ReferenceNodeOnionTransport<'a> {
    signer: &'a dyn Bolt12Signer,
    payment_hash: [u8; 32],
}

impl<'a> ReferenceNodeOnionTransport<'a> {
    /// Construct a new reference CLN/LDK node responder with a host signer and `payment_hash`.
    pub fn new(signer: &'a dyn Bolt12Signer, payment_hash: [u8; 32]) -> Self {
        Self {
            signer,
            payment_hash,
        }
    }
}

impl OnionMessageTransport for ReferenceNodeOnionTransport<'_> {
    fn dispatch_invoice_request(
        &self,
        offer: &Bolt12Offer,
        request: &Bolt12InvoiceRequest,
        envelope: &OnionMessageEnvelope,
    ) -> Result<Bolt12Invoice> {
        // 1. Verify reply path is valid BOLT #4 wire format
        let reply_bytes = envelope.reply_blinded_path.encode_bytes()?;
        let _ = BlindedPath::decode_bytes(&reply_bytes)?;

        // 2. Verify invoice_request signature against offer Merkle root
        let offer_id = offer.offer_id()?;
        if !request.verify_signature(&offer_id)? {
            anyhow::bail!("recipient node rejected invoice_request: invalid Schnorr signature");
        }

        // 3. Construct and sign concrete BOLT12 invoice
        let inv = create_invoice_from_request(
            offer,
            request,
            self.signer,
            self.payment_hash,
            Some(3600),
        )?;
        validate_bolt12_invoice_against_offer(&inv, offer, request.amount_msats)?;
        Ok(inv)
    }
}

/// Dispatch an `invoice_request` via a provided [`OnionMessageTransport`] and validate the returned invoice.
pub fn fetch_bolt12_invoice_via_transport(
    transport: &dyn OnionMessageTransport,
    offer: &Bolt12Offer,
    amount_msats: u64,
    payer_key: &dyn Bolt12Signer,
    reply_blinded_path: BlindedPath,
    payer_note: Option<&str>,
    quantity: Option<u64>,
) -> Result<Bolt12Invoice> {
    let (req, envelope) = build_invoice_request_onion_envelope(
        offer,
        amount_msats,
        payer_key,
        reply_blinded_path,
        payer_note,
        quantity,
    )?;
    let invoice = transport.dispatch_invoice_request(offer, &req, &envelope)?;
    validate_bolt12_invoice_against_offer(&invoice, offer, amount_msats)?;
    if !invoice.verify_signature()? {
        anyhow::bail!("BOLT12 invoice failed Schnorr Merkle signature verification");
    }
    Ok(invoice)
}

// ============================================================================
// Invoice Fetching and Validation
// ============================================================================

/// Fetch a BOLT12 invoice from an offer via configured HTTP gateway.
pub async fn fetch_bolt12_invoice(
    offer: &Bolt12Offer,
    amount_msats: u64,
    _payer_node_id: Option<String>,
    _quantity: Option<u64>,
    _payer_note: Option<String>,
) -> Result<Bolt12Invoice> {
    // 1. Expiry check
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if offer.is_expired(now) {
        anyhow::bail!("Cannot fetch invoice: BOLT12 offer has expired");
    }

    // 2. Amount boundary validation
    if !offer.is_amount_valid(amount_msats) {
        anyhow::bail!(
            "Amount {} msats is outside bounds for offer (min: {:?}, max: {:?})",
            amount_msats,
            offer.min_amount_msats,
            offer.max_amount_msats
        );
    }

    // 4. HTTP Gateway / Proxy fetch
    if let Ok(proxy_base) = std::env::var("SATSPATH_BOLT12_PROXY") {
        let trimmed_proxy = proxy_base.trim_end_matches('/');
        let url = format!(
            "{}/invoice?offer={}&amount_msats={}",
            trimmed_proxy,
            urlencoding::encode(&offer.offer),
            amount_msats
        );

        #[cfg(feature = "std")]
        {
            let client = satspath_core::ssrf::pinned_http_client(&url, false).await?;
            let mut resp = client
                .get(&url)
                .send()
                .await
                .context("sending BOLT12 proxy request")?;
            if !resp.status().is_success() {
                anyhow::bail!("BOLT12 proxy returned HTTP error: {}", resp.status());
            }
            let mut bytes = Vec::new();
            while let Some(chunk) = resp.chunk().await? {
                if bytes.len() + chunk.len() > 50 * 1024 {
                    anyhow::bail!("BOLT12 proxy response exceeds 50KB");
                }
                bytes.extend_from_slice(&chunk);
            }
            let data: serde_json::Value =
                serde_json::from_slice(&bytes).context("decoding proxy JSON")?;
            let inv_str = data["invoice"]
                .as_str()
                .ok_or_else(|| anyhow!("missing 'invoice' string in proxy response"))?;
            let parsed_inv = parse_bolt12_invoice(inv_str)?;
            validate_bolt12_invoice_against_offer(&parsed_inv, offer, amount_msats)?;
            return Ok(parsed_inv);
        }
    }

    // 5. Default: Informative error indicating required transport gateway
    Err(anyhow!(
        "BOLT12 onion message transport requires an active Lightning node connection or configured proxy (SATSPATH_BOLT12_PROXY)"
    ))
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    include!("../tests/support/signer.rs");
    use bech32::ToBase32;
    use std::io::Cursor;

    const VALID_NODE_ID: &str =
        "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    /// Verify that `parse_bolt12_offer` rejects malformed encoding.
    #[test]
    fn test_parse_bolt12_offer_rejects_malformed_encoding() {
        let offer = "lno1pq...";
        let result = parse_bolt12_offer(offer);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bolt12_offer_hrps() {
        let raw = encode_tlv_stream(&[TlvRecord {
            tag: TLV_OFFER_NODE_ID,
            value: hex::decode(VALID_NODE_ID).unwrap(),
        }]);
        for hrp in ["lno", "lnot", "lnob", "lnos"] {
            let offer = bech32::encode(hrp, raw.to_base32(), bech32::Variant::Bech32m).unwrap();
            assert!(parse_bolt12_offer(&offer).is_ok(), "HRP: {hrp}");

            let invalid_hrp = format!("{hrp}1other");
            let offer =
                bech32::encode(&invalid_hrp, raw.to_base32(), bech32::Variant::Bech32m).unwrap();
            let err = parse_bolt12_offer(&offer).unwrap_err();
            assert!(err.to_string().contains("invalid BOLT12 offer HRP"));
        }
    }

    #[test]
    fn test_parse_bolt12_offer_checksumless_and_plus_continuation() {
        let raw = encode_tlv_stream(&[
            TlvRecord {
                tag: TLV_OFFER_DESCRIPTION,
                value: b"Donation".to_vec(),
            },
            TlvRecord {
                tag: TLV_OFFER_NODE_ID,
                value: hex::decode(VALID_NODE_ID).unwrap(),
            },
        ]);
        for hrp_str in ["lno", "lnot", "lnob", "lnos"] {
            let offer = encode_bolt12_bech32_checksumless(hrp_str, &raw).unwrap();
            let parsed = parse_bolt12_offer(&offer).unwrap();
            assert_eq!(parsed.description.as_deref(), Some("Donation"));
            assert_eq!(parsed.node_id.as_deref(), Some(VALID_NODE_ID));

            // Also test BOLT12 '+' multiline continuation
            let (first_half, second_half) = offer.split_at(20);
            let multiline = format!("{first_half}+\n  {second_half}");
            let parsed_multiline = parse_bolt12_offer(&multiline).unwrap();
            assert_eq!(parsed_multiline.offer, offer);
            assert_eq!(
                parsed_multiline.offer_id().unwrap(),
                parsed.offer_id().unwrap()
            );
        }
    }

    #[test]
    fn test_bolt12_merkle_root_and_signature_verification() {
        let sk = TestSigner(secp256k1::SecretKey::from_slice(&[0x42; 32]).unwrap());
        let secp = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);
        let pk_hex = hex::encode(pk.serialize());

        let mut records = vec![
            TlvRecord {
                tag: TLV_OFFER_DESCRIPTION,
                value: b"SatsPath Coffee".to_vec(),
            },
            TlvRecord {
                tag: TLV_OFFER_NODE_ID,
                value: pk.serialize().to_vec(),
            },
        ];
        let sig = sign_bolt12_tlv_stream("offer", &records, &sk).unwrap();
        records.push(TlvRecord {
            tag: TLV_SIGNATURE,
            value: sig.to_vec(),
        });

        let raw = encode_tlv_stream(&records);
        let offer_str = encode_bolt12_bech32_checksumless("lno", &raw).unwrap();
        let parsed = parse_bolt12_offer(&offer_str).unwrap();
        assert_eq!(parsed.node_id.as_deref(), Some(pk_hex.as_str()));
        assert!(parsed.verify_signature().unwrap());
    }

    #[test]
    fn test_parse_bolt12_offer_invalid_prefix() {
        let offer = "invalid";
        let result = parse_bolt12_offer(offer);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_bolt12_invoice_request_rejects_unsigned() {
        let raw = encode_tlv_stream(&[
            TlvRecord {
                tag: TLV_INVREQ_OFFER_ID,
                value: [0x11; 32].to_vec(),
            },
            TlvRecord {
                tag: TLV_INVREQ_AMOUNT,
                value: write_tu64(25_000),
            },
        ]);
        let request = encode_bolt12_bech32_checksumless("lnr", &raw).unwrap();
        assert!(parse_bolt12_invoice_request(&request).is_err());
        assert!(parse_bolt12_invoice_request("lnr1...").is_err());
    }

    #[test]
    fn test_validate_bolt12_invoice_amount_match() {
        let invoice = Bolt12Invoice {
            invoice: "lni1...".to_string(),
            description: None,
            amount_msats: 100_000,
            currency: "btc".to_string(),
            created_at: 0,
            relative_expiry: None,
            absolute_expiry: None,
            payment_hash: None,
            fallback_address: None,
            routes: None,
            blinded_paths: None,
            node_id: None,
            signature: None,
        };

        let result = validate_bolt12_invoice(&invoice, 100_000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_bolt12_invoice_amount_mismatch() {
        let invoice = Bolt12Invoice {
            invoice: "lni1...".to_string(),
            description: None,
            amount_msats: 200_000,
            currency: "btc".to_string(),
            created_at: 0,
            relative_expiry: None,
            absolute_expiry: None,
            payment_hash: None,
            fallback_address: None,
            routes: None,
            blinded_paths: None,
            node_id: None,
            signature: None,
        };

        let result = validate_bolt12_invoice(&invoice, 100_000);
        assert!(result.is_err());
    }

    #[test]
    fn test_tlv_roundtrip_bigsize_and_tu64() {
        let mut buf = Vec::new();
        write_bigsize(0x42, &mut buf);
        write_bigsize(0x1234, &mut buf);
        write_bigsize(0x12345678, &mut buf);

        let mut cursor = Cursor::new(buf.as_slice());
        assert_eq!(read_bigsize(&mut cursor).unwrap(), 0x42);
        assert_eq!(read_bigsize(&mut cursor).unwrap(), 0x1234);
        assert_eq!(read_bigsize(&mut cursor).unwrap(), 0x12345678);

        assert_eq!(read_tu64(&write_tu64(0)).unwrap(), 0);
        assert_eq!(read_tu64(&write_tu64(100_000)).unwrap(), 100_000);
        assert_eq!(
            read_tu64(&write_tu64(18_000_000_000)).unwrap(),
            18_000_000_000
        );
    }

    #[test]
    fn test_blinded_path_encoding_and_decoding() {
        let intro_node = VALID_NODE_ID.to_string();
        let bp_point = "03".to_string() + &"22".repeat(32);
        let hop_node = "02".to_string() + &"33".repeat(32);
        let enc_payload = "deadbeefcafe";

        let path = BlindedPath {
            introduction_node_id: intro_node.clone(),
            blinding_point: Some(bp_point.clone()),
            blinded_hops: vec![BlindedHop {
                blinded_node_id: hop_node.clone(),
                encrypted_payload: enc_payload.to_string(),
            }],
        };

        let bytes = path.encode_bytes().unwrap();
        let decoded = BlindedPath::decode_bytes(&bytes).unwrap();
        assert_eq!(decoded.introduction_node_id, intro_node);
        assert_eq!(decoded.blinding_point, Some(bp_point));
        assert_eq!(decoded.blinded_hops.len(), 1);
        assert_eq!(decoded.blinded_hops[0].blinded_node_id, hop_node);
        assert_eq!(decoded.blinded_hops[0].encrypted_payload, enc_payload);
    }

    #[test]
    fn test_blinded_path_encoding_hop_limit() {
        let hop = BlindedHop {
            blinded_node_id: "02".to_string() + &"33".repeat(32),
            encrypted_payload: "deadbeef".to_string(),
        };
        let mut path = BlindedPath {
            introduction_node_id: VALID_NODE_ID.to_string(),
            blinding_point: Some("03".to_string() + &"22".repeat(32)),
            blinded_hops: vec![hop.clone(); 100],
        };

        let bytes = path.encode_bytes().unwrap();
        assert_eq!(BlindedPath::decode_bytes(&bytes).unwrap(), path);

        let raw = encode_tlv_stream(&[TlvRecord {
            tag: TLV_OFFER_PATHS,
            value: bytes,
        }]);
        let offer = bech32::encode("lno", raw.to_base32(), bech32::Variant::Bech32m).unwrap();
        assert_eq!(
            parse_bolt12_offer(&offer).unwrap().blinded_paths,
            Some(vec![path.clone()])
        );

        path.blinded_hops.push(hop);
        let err = path.encode_bytes().unwrap_err();
        assert!(err.to_string().contains("excessive num_hops"));
    }

    #[test]
    fn test_parse_bolt12_offer_rejects_invalid_blinded_paths() {
        let key_bytes = hex::decode(VALID_NODE_ID).unwrap();
        let mut zero_hops = key_bytes.repeat(2);
        zero_hops.push(0);

        let mut excessive_hops = key_bytes.repeat(2);
        excessive_hops.push(101);

        let mut truncated_hop = key_bytes.repeat(2);
        truncated_hop.push(1);

        let mut truncated_payload = truncated_hop.clone();
        truncated_payload.extend_from_slice(&key_bytes);
        truncated_payload.extend_from_slice(&1u16.to_be_bytes());

        for (path_bytes, expected_error) in [
            (vec![], "paths must not be empty"),
            (zero_hops, "num_hops must be at least 1"),
            (excessive_hops, "excessive num_hops"),
            (truncated_hop, "invalid num_hops"),
            (truncated_payload, "encrypted payload length"),
        ] {
            let raw = encode_tlv_stream(&[TlvRecord {
                tag: TLV_OFFER_PATHS,
                value: path_bytes,
            }]);
            let offer = bech32::encode("lno", raw.to_base32(), bech32::Variant::Bech32m).unwrap();
            let err = parse_bolt12_offer(&offer).unwrap_err();
            assert!(
                format!("{err:#}").contains(expected_error),
                "expected '{expected_error}', got '{err:#}'"
            );
        }
    }

    #[test]
    fn test_create_and_encode_signed_invoice_request() {
        use secp256k1::rand::RngCore;
        let mut key_bytes = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut key_bytes);
        let payer_key = TestSigner(secp256k1::SecretKey::from_slice(&key_bytes).unwrap());

        let raw_offer = encode_tlv_stream(&[TlvRecord {
            tag: TLV_OFFER_NODE_ID,
            value: hex::decode(VALID_NODE_ID).unwrap(),
        }]);
        let offer_str = encode_bolt12_bech32_checksumless("lno", &raw_offer).unwrap();
        let offer = parse_bolt12_offer(&offer_str).unwrap();

        let req = create_signed_invoice_request(
            &offer,
            50_000_000,
            &payer_key,
            Some("Thanks for the coffee!"),
            Some(1),
        )
        .unwrap();

        assert_eq!(req.amount_msats, 50_000_000);
        assert!(req.payer_node_id.is_some());
        assert!(req.signature.is_some());
        assert!(req.verify_signature(&offer.offer_id().unwrap()).unwrap());

        let encoded = req.encode().unwrap();
        assert!(encoded.starts_with("lnr1"));

        let parsed = parse_bolt12_invoice_request(&encoded).unwrap();
        assert_eq!(parsed.amount_msats, 50_000_000);
        assert_eq!(
            parsed.payer_note,
            Some("Thanks for the coffee!".to_string())
        );
    }

    /// Reject a TLV value length that exceeds the available payload bytes.
    #[test]
    fn test_decode_tlv_stream_bounds() {
        let truncated_tlv = vec![0x01, 0xfd, 0x03, 0xe8, 0xaa, 0xbb];
        let err = decode_tlv_stream(&truncated_tlv).unwrap_err();
        assert!(err.to_string().contains("exceeds remaining stream bytes"));
    }

    /// Reject a blinded path declaring more than the maximum 100 hops.
    #[test]
    fn test_blinded_path_bounds() {
        let key_bytes = hex::decode(VALID_NODE_ID).unwrap();
        let mut malformed_path = key_bytes.repeat(2);
        malformed_path.push(200); // num_hops > 100
        let err = BlindedPath::decode_bytes(&malformed_path).unwrap_err();
        assert!(err.to_string().contains("excessive num_hops"));
    }

    #[test]
    fn test_blinded_path_wire_boundaries() {
        let key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let mut path = BlindedPath {
            introduction_node_id: key.into(),
            blinding_point: Some(key.into()),
            blinded_hops: vec![BlindedHop {
                blinded_node_id: key.into(),
                encrypted_payload: String::new(),
            }],
        };
        for intro in [key, "000000010000020003", "010000010000020003"] {
            path.introduction_node_id = intro.into();
            for length in [0, 252, 253, 256, u16::MAX as usize] {
                path.blinded_hops[0].encrypted_payload = "ab".repeat(length);
                let bytes = path.encode_bytes().unwrap();
                let hop_start = intro.len() / 2 + 33 + 1;
                assert_eq!(
                    &bytes[hop_start + 33..hop_start + 35],
                    &(length as u16).to_be_bytes()
                );
                assert_eq!(BlindedPath::decode_bytes(&bytes).unwrap(), path);
                // Check the handoff validator against the same fixed-width payload.
                let raw = encode_tlv_stream(&[TlvRecord {
                    tag: TLV_OFFER_PATHS,
                    value: bytes,
                }]);
                let offer =
                    bech32::encode("lno", raw.to_base32(), bech32::Variant::Bech32m).unwrap();
                satspath_handoff::bolt12(&offer, None, 0).unwrap();
            }
        }
        path.blinded_hops[0].encrypted_payload = "ab".repeat(u16::MAX as usize + 1);
        assert!(path.encode_bytes().is_err());
        path.blinded_hops.clear();
        assert!(path.encode_bytes().is_err());
    }

    #[test]
    fn test_blinded_path_rejects_invalid_keys_and_truncation() {
        let key = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let path = BlindedPath {
            introduction_node_id: key.into(),
            blinding_point: Some(key.into()),
            blinded_hops: vec![BlindedHop {
                blinded_node_id: key.into(),
                encrypted_payload: "abcd".into(),
            }],
        };
        let valid = path.encode_bytes().unwrap();
        for offset in [0, 33, 67] {
            let mut invalid = valid.clone();
            // Compressed prefix with an x coordinate which is not on secp256k1.
            invalid[offset + 1..offset + 33].fill(0xff);
            assert!(BlindedPath::decode_bytes(&invalid).is_err());
            let raw = encode_tlv_stream(&[TlvRecord {
                tag: TLV_OFFER_PATHS,
                value: invalid,
            }]);
            let offer = bech32::encode("lno", raw.to_base32(), bech32::Variant::Bech32m).unwrap();
            assert!(satspath_handoff::bolt12(&offer, None, 0).is_err());
        }
        for end in 0..valid.len() {
            assert!(BlindedPath::decode_bytes(&valid[..end]).is_err());
        }
        for invalid in [
            "04".repeat(33),
            "00".repeat(33),
            "02".to_string() + &"ff".repeat(32),
        ] {
            let mut modified = path.clone();
            modified.introduction_node_id = invalid.clone();
            assert!(modified.encode_bytes().is_err());
            modified = path.clone();
            modified.blinding_point = Some(invalid.clone());
            assert!(modified.encode_bytes().is_err());
            modified = path.clone();
            modified.blinded_hops[0].blinded_node_id = invalid;
            assert!(modified.encode_bytes().is_err());
        }
        let mut missing_key = path;
        missing_key.blinding_point = None;
        assert!(missing_key.encode_bytes().is_err());
    }
}
