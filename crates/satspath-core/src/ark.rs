use secp256k1::schnorr::Signature;
use secp256k1::{Message, PublicKey, Secp256k1, XOnlyPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::errors::{Result, SatsPathError};
use crate::validation::{assert_no_private_material, validate_compressed_pubkey};

// ─── Arkade / Ark public pointer classification ────────────────────────────

/// Classifies how a public Arkade/Ark receive pointer is represented.
///
/// This is a **display and routing type only** — it is never stored in the
/// profile directly and never contains private material.
///
/// Preference order (most descriptive → most opaque):
///   1. `ServerPubkey`  — preferred; full Ark server URL + compressed pubkey.
///   2. `VtxoPointer`   — allowed when Arkade exposes a VTXO pointer string.
///   3. `OpaqueUri`     — allowed when Arkade only exposes an `ark1q…` address
///      or an `ark:` URI; always `execution: manual_wallet`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "variant")]
pub enum ArkadePointer {
    /// Full Ark server URL + compressed secp256k1 receiver pubkey.
    ServerPubkey { server: String, pubkey: String },
    /// Opaque VTXO pointer string from Arkade (server known, vtxo pointer given).
    VtxoPointer {
        server: String,
        vtxo_pointer: String,
    },
    /// Opaque `ark1q…` address or `ark:` URI from Arkade when only a receive
    /// string / QR is available. Always `PreviewOnly` / `manual_wallet`.
    OpaqueUri { uri: String },
}

/// Derive the routing-layer [`ArkadePointer`] variant from a `PaymentMethod::Ark`.
///
/// Returns `None` when the method is not an Ark method.
pub fn classify_ark_method(method: &crate::profile::PaymentMethod) -> Option<ArkadePointer> {
    match method {
        crate::profile::PaymentMethod::Ark {
            server,
            pubkey,
            vtxo_pointer,
            opaque_uri,
            ..
        } => {
            // Opaque URI takes priority when present — it means the user only
            // provided an ark1q address / ark: URI from Arkade.
            if let Some(uri) = opaque_uri {
                return Some(ArkadePointer::OpaqueUri { uri: uri.clone() });
            }
            // VTXO pointer available alongside server URL.
            if !server.is_empty() {
                if let Some(vtxo) = vtxo_pointer {
                    return Some(ArkadePointer::VtxoPointer {
                        server: server.clone(),
                        vtxo_pointer: vtxo.clone(),
                    });
                }
                // Full server + pubkey.
                if !pubkey.is_empty() {
                    return Some(ArkadePointer::ServerPubkey {
                        server: server.clone(),
                        pubkey: pubkey.clone(),
                    });
                }
            }
            None
        }
        _ => None,
    }
}

/// Validate a public Arkade opaque URI (`ark1q…` address or `ark:` URI).
///
/// Rules:
/// - Must start with `ark1` (bech32 Arkade address) or `ark:` (URI scheme).
/// - Must not contain private material.
/// - Must not be empty.
pub fn validate_arkade_opaque_uri(uri: &str) -> Result<()> {
    let trimmed = uri.trim();
    if trimmed.is_empty() {
        return Err(SatsPathError::InvalidPaymentPointer(
            "Arkade URI must not be empty".into(),
        ));
    }
    let lower = trimmed.to_ascii_lowercase();
    if !lower.starts_with("ark1") && !lower.starts_with("ark:") {
        return Err(SatsPathError::InvalidPaymentPointer(
            "Arkade URI must start with 'ark1' (bech32 address) or 'ark:' (URI scheme)".into(),
        ));
    }
    assert_no_private_material(trimmed)?;
    Ok(())
}

/// Build a QR/URI payload for an [`ArkadePointer`].
///
/// - `ServerPubkey`  → `ark:<pubkey>?server=…&amount=…`
///
/// Opaque URIs and VTXO pointers are rejected until protocol decoding is available.
/// The resulting payload is always checked for private material.
pub fn build_arkade_qr(pointer: &ArkadePointer, amount_sats: u64) -> Result<String> {
    use url::form_urlencoded;
    crate::validation::validate_amount_sats(amount_sats)?;
    match pointer {
        ArkadePointer::ServerPubkey { server, pubkey } => {
            let key =
                hex::decode(pubkey).map_err(|e| SatsPathError::InvalidPublicKey(e.to_string()))?;
            satspath_handoff::ark(
                server,
                &key,
                None,
                None,
                None,
                chrono::Utc::now().timestamp(),
            )
            .map_err(SatsPathError::InvalidPaymentPointer)?;
            let mut enc = form_urlencoded::Serializer::new(String::new());
            enc.append_pair("server", server);
            enc.append_pair("amount", &amount_sats.to_string());
            let payload = format!("ark:{}?{}", pubkey, enc.finish());
            assert_no_private_material(&payload)?;
            Ok(payload)
        }
        ArkadePointer::VtxoPointer { .. } | ArkadePointer::OpaqueUri { .. } => {
            Err(SatsPathError::InvalidPaymentPointer(
                "opaque Ark URI/VTXO handoff requires protocol validation".into(),
            ))
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ArkRouteKind {
    ArkToArk,
    ArkToLightning,
    LightningToArk,
    ArkToOnchain,
    OnchainToArk,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkReceivePointer {
    pub server: String,
    pub receiver_pubkey: String,
    pub vtxo_pointer: Option<String>,
    pub proof: Option<ArkOwnershipProof>,
    pub expires_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkOwnershipProof {
    pub message: String,
    pub signature: String,
    pub pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ArkIntentStatus {
    PreviewOnly,
    TestnetReady,
    TestnetExecutionBlocked,
    ExecutedTestnet,
    Expired,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ArkPaymentIntent {
    pub route_kind: ArkRouteKind,
    pub amount_sats: u64,
    pub receiver_pointer: ArkReceivePointer,
    pub status: ArkIntentStatus,
    pub created_at: i64,
    pub expires_at: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ClientValidationReport {
    pub profile_signature_valid: bool,
    pub profile_fresh: bool,
    pub ark_pointer_valid: bool,
    pub ark_ownership_verified: bool,
    pub method_verified: bool,
    pub safe_for_preview: bool,
    pub safe_for_testnet_execution: bool,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

pub fn ark_ownership_challenge(
    alias: &str,
    identity_pubkey: &str,
    ark_server: &str,
    receiver_pubkey: &str,
    nonce: &str,
) -> String {
    format!(
        "SatsPath Ownership Proof v1\nalias={alias}\nidentity={identity_pubkey}\nmethod=ark:{ark_server}:{receiver_pubkey}\nissued_at={nonce}"
    )
}

pub fn validate_ark_server_url(server: &str) -> Result<()> {
    assert_no_private_material(server)?;
    let parsed =
        Url::parse(server).map_err(|e| SatsPathError::InvalidPaymentPointer(e.to_string()))?;
    if parsed.scheme() != "https" {
        return Err(SatsPathError::InvalidPaymentPointer(
            "Ark server URL must use https".into(),
        ));
    }
    if parsed.host_str().is_none() {
        return Err(SatsPathError::InvalidPaymentPointer(
            "Ark server URL must include a host".into(),
        ));
    }
    Ok(())
}

pub fn validate_ark_receive_pointer(pointer: &ArkReceivePointer, now: i64) -> Result<()> {
    validate_ark_server_url(&pointer.server)?;
    validate_compressed_pubkey(&pointer.receiver_pubkey)?;
    if let Some(vtxo) = &pointer.vtxo_pointer {
        assert_no_private_material(vtxo)?;
    }
    if let Some(expires_at) = pointer.expires_at {
        if expires_at <= now {
            return Err(SatsPathError::InvalidPaymentPointer(
                "Ark receive pointer expired".into(),
            ));
        }
    }
    Ok(())
}

pub fn verify_ark_ownership_proof(
    alias: &str,
    identity_pubkey: &str,
    pointer: &ArkReceivePointer,
    now: i64,
) -> Result<bool> {
    validate_ark_receive_pointer(pointer, now)?;
    let Some(proof) = &pointer.proof else {
        return Ok(false);
    };
    validate_compressed_pubkey(&proof.pubkey)?;
    if proof.pubkey != pointer.receiver_pubkey {
        return Err(SatsPathError::InvalidSignature);
    }
    if let Some(expires_at) = pointer.expires_at {
        if expires_at <= now {
            return Err(SatsPathError::InvalidPaymentPointer(
                "Ark ownership proof expired".into(),
            ));
        }
    }

    // Use the method descriptor for binding, consistent with ownership.rs
    let method_descriptor = format!("ark:{}", pointer.receiver_pubkey);
    let expected_message = ark_ownership_challenge(
        alias,
        identity_pubkey,
        &pointer.server,
        &pointer.receiver_pubkey,
        &method_descriptor, // nonce field repurposed as method descriptor for exact match
    );

    // Require exact message match (no prefix-based replay)
    if proof.message != expected_message {
        return Err(SatsPathError::InvalidSignature);
    }

    let pubkey_bytes =
        hex::decode(&proof.pubkey).map_err(|e| SatsPathError::InvalidPublicKey(e.to_string()))?;

    let x_only_public_key = if pubkey_bytes.len() == 32 {
        XOnlyPublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| SatsPathError::InvalidPublicKey(e.to_string()))?
    } else {
        let public_key = PublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| SatsPathError::InvalidPublicKey(e.to_string()))?;
        public_key.x_only_public_key().0
    };

    let sig_bytes =
        hex::decode(&proof.signature).map_err(|e| SatsPathError::CryptoError(e.to_string()))?;
    let sig =
        Signature::from_slice(&sig_bytes).map_err(|e| SatsPathError::CryptoError(e.to_string()))?;
    let digest = Sha256::digest(proof.message.as_bytes());
    let message = Message::from_digest(digest.into());
    Ok(Secp256k1::verification_only()
        .verify_schnorr(&sig, &message, &x_only_public_key)
        .is_ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Keypair, Secp256k1, SecretKey};

    fn signed_pointer(
        alias: &str,
        identity_pubkey: &str,
        server: &str,
        _nonce: &str,
        expires_at: Option<i64>,
    ) -> ArkReceivePointer {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let pubkey = secret.public_key(&secp);
        let pubkey_hex = hex::encode(pubkey.serialize());
        // Use method descriptor as "nonce" for exact message matching
        let method_descriptor = format!("ark:{}", pubkey_hex);
        let message = ark_ownership_challenge(
            alias,
            identity_pubkey,
            server,
            &pubkey_hex,
            &method_descriptor,
        );
        let digest = Sha256::digest(message.as_bytes());
        let sig = secp.sign_schnorr(&Message::from_digest(digest.into()), &keypair);
        ArkReceivePointer {
            server: server.into(),
            receiver_pubkey: pubkey_hex.clone(),
            vtxo_pointer: None,
            proof: Some(ArkOwnershipProof {
                message,
                signature: hex::encode(sig.serialize()),
                pubkey: pubkey_hex,
            }),
            expires_at,
        }
    }

    #[test]
    fn valid_proof_accepted() {
        let identity_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pointer = signed_pointer(
            "alice@example.com",
            identity_pubkey,
            "https://ark.example.com",
            "n1",
            Some(2_000),
        );
        assert!(
            verify_ark_ownership_proof("alice@example.com", identity_pubkey, &pointer, 1_000)
                .unwrap()
        );
    }

    #[test]
    fn pubkey_incorrect_rejected() {
        let identity_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let mut pointer = signed_pointer(
            "alice@example.com",
            identity_pubkey,
            "https://ark.example.com",
            "n1",
            Some(2_000),
        );
        pointer.receiver_pubkey =
            "0279be667ef9dcbbac55a0a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into();
        assert!(
            verify_ark_ownership_proof("alice@example.com", identity_pubkey, &pointer, 1_000)
                .is_err()
        );
    }

    #[test]
    fn server_incorrect_rejected() {
        let identity_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let mut pointer = signed_pointer(
            "alice@example.com",
            identity_pubkey,
            "https://ark.example.com",
            "n1",
            Some(2_000),
        );
        pointer.server = "https://evil.example.com".into();
        assert!(
            verify_ark_ownership_proof("alice@example.com", identity_pubkey, &pointer, 1_000)
                .is_err()
        );
    }

    #[test]
    fn alias_incorrect_rejected() {
        let identity_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pointer = signed_pointer(
            "alice@example.com",
            identity_pubkey,
            "https://ark.example.com",
            "n1",
            Some(2_000),
        );
        assert!(
            verify_ark_ownership_proof("bob@example.com", identity_pubkey, &pointer, 1_000)
                .is_err()
        );
    }

    #[test]
    fn malformed_signature_rejected() {
        let identity_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let mut pointer = signed_pointer(
            "alice@example.com",
            identity_pubkey,
            "https://ark.example.com",
            "n1",
            Some(2_000),
        );
        pointer.proof.as_mut().unwrap().signature = "not-hex".into();
        assert!(
            verify_ark_ownership_proof("alice@example.com", identity_pubkey, &pointer, 1_000)
                .is_err()
        );
    }

    #[test]
    fn proof_expired_rejected() {
        let identity_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let pointer = signed_pointer(
            "alice@example.com",
            identity_pubkey,
            "https://ark.example.com",
            "n1",
            Some(999),
        );
        assert!(
            verify_ark_ownership_proof("alice@example.com", identity_pubkey, &pointer, 1_000)
                .is_err()
        );
    }

    // ─── ArkadePointer / opaque URI tests ────────────────────────────────────

    #[test]
    fn arkade_opaque_uri_ark1q_accepted() {
        assert!(validate_arkade_opaque_uri(
            "ark1qexampleaddress0000000000000000000000000000000000000000000000"
        )
        .is_ok());
    }

    #[test]
    fn arkade_opaque_uri_ark_scheme_accepted() {
        assert!(validate_arkade_opaque_uri("ark:ark1qexampleaddress").is_ok());
    }

    #[test]
    fn arkade_opaque_uri_private_material_rejected() {
        assert!(validate_arkade_opaque_uri("ark1qcontains_xprv_private").is_err());
    }

    #[test]
    fn arkade_opaque_uri_wrong_prefix_rejected() {
        assert!(validate_arkade_opaque_uri("bitcoin:bc1qexample").is_err());
    }

    #[test]
    fn arkade_opaque_uri_empty_rejected() {
        assert!(validate_arkade_opaque_uri("").is_err());
    }

    #[test]
    /// Verify that build arkade qr rejects unvalidated opaque address.
    fn build_arkade_qr_rejects_unvalidated_opaque_address() {
        let pointer = ArkadePointer::OpaqueUri {
            uri: "ark1qexampleaddress".into(),
        };
        assert!(build_arkade_qr(&pointer, 21_000).is_err());
    }

    #[test]
    /// Verify that build arkade qr rejects unvalidated opaque uri.
    fn build_arkade_qr_rejects_unvalidated_opaque_uri() {
        let pointer = ArkadePointer::OpaqueUri {
            uri: "ark:ark1qexampleaddress".into(),
        };
        assert!(build_arkade_qr(&pointer, 21_000).is_err());
    }

    #[test]
    fn build_arkade_qr_server_pubkey_returns_ark_uri() {
        let pointer = ArkadePointer::ServerPubkey {
            server: "https://ark.example.com".into(),
            pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
        };
        let qr = build_arkade_qr(&pointer, 42).unwrap();
        assert!(qr.starts_with(
            "ark:0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798?"
        ));
        assert!(qr.contains("server="));
        assert!(qr.contains("amount=42"));
    }

    #[test]
    /// Verify that build arkade qr rejects unvalidated vtxo.
    fn build_arkade_qr_rejects_unvalidated_vtxo() {
        let pointer = ArkadePointer::VtxoPointer {
            server: "https://ark.example.com".into(),
            vtxo_pointer: "vtxo:abc123".into(),
        };
        assert!(build_arkade_qr(&pointer, 1_000).is_err());
    }

    #[test]
    fn classify_ark_method_opaque_uri_wins() {
        use crate::profile::PaymentMethod;
        let method = PaymentMethod::Ark {
            label: "Arkade".into(),
            server: "".into(),
            pubkey: "".into(),
            vtxo_pointer: None,
            proof: None,
            expires_at: None,
            opaque_uri: Some("ark1qexample".into()),
        };
        assert!(matches!(
            classify_ark_method(&method),
            Some(ArkadePointer::OpaqueUri { .. })
        ));
    }

    #[test]
    fn classify_ark_method_server_pubkey_path() {
        use crate::profile::PaymentMethod;
        let method = PaymentMethod::Ark {
            label: "Ark".into(),
            server: "https://ark.example.com".into(),
            pubkey: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
            vtxo_pointer: None,
            proof: None,
            expires_at: None,
            opaque_uri: None,
        };
        assert!(matches!(
            classify_ark_method(&method),
            Some(ArkadePointer::ServerPubkey { .. })
        ));
    }
}
