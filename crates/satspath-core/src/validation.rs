use bitcoin::{Address, Network};
use secp256k1::PublicKey;
use std::str::FromStr;

use crate::ark::{validate_ark_receive_pointer, verify_ark_ownership_proof, ArkReceivePointer};
use crate::errors::{Result, SatsPathError};
use crate::pointer::BitcoinNetwork;
use crate::profile::{ClaimPolicy, PaymentMethod, PaymentProfile};

pub const LARGE_PREVIEW_AMOUNT_SATS: u64 = 100_000_000;
pub const MAX_PREVIEW_AMOUNT_SATS: u64 = 21_000_000 * 100_000_000;

pub fn validate_amount_sats(amount_sats: u64) -> Result<()> {
    if amount_sats == 0 {
        return Err(SatsPathError::InvalidPaymentPointer(
            "amount must be positive".into(),
        ));
    }
    if amount_sats > MAX_PREVIEW_AMOUNT_SATS {
        return Err(SatsPathError::InvalidPaymentPointer(
            "amount exceeds Bitcoin supply".into(),
        ));
    }
    Ok(())
}

pub fn validate_compressed_pubkey(pubkey_hex: &str) -> Result<()> {
    let bytes =
        hex::decode(pubkey_hex).map_err(|e| SatsPathError::InvalidPublicKey(e.to_string()))?;
    if bytes.len() != 33 || !matches!(bytes.first(), Some(0x02 | 0x03)) {
        return Err(SatsPathError::InvalidPublicKey(
            "expected 33-byte compressed secp256k1 pubkey".into(),
        ));
    }
    PublicKey::from_slice(&bytes).map_err(|e| SatsPathError::InvalidPublicKey(e.to_string()))?;
    Ok(())
}

pub fn validate_lightning_address(address: &str) -> Result<()> {
    let trimmed = address.trim();
    let Some((local, domain)) = trimmed.split_once('@') else {
        return Err(SatsPathError::InvalidPaymentPointer(
            "Lightning Address must be user@domain".into(),
        ));
    };
    let valid_local = !local.is_empty()
        && local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '+'));
    let valid_domain = domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && domain
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'));
    if valid_local && valid_domain {
        Ok(())
    } else {
        Err(SatsPathError::InvalidPaymentPointer(
            "invalid Lightning Address format".into(),
        ))
    }
}

/// Validate a BOLT12 offer string using the shared handoff validator.
pub fn validate_bolt12_offer(offer: &str) -> Result<()> {
    validate_bolt12_offer_for_network(offer, None)
}

fn validate_bolt12_offer_for_network(offer: &str, network: Option<BitcoinNetwork>) -> Result<()> {
    let trimmed = offer.trim();
    assert_no_private_material(trimmed)?;
    let network = network.map(|net| match net {
        BitcoinNetwork::Mainnet => Network::Bitcoin,
        BitcoinNetwork::Testnet => Network::Testnet,
        BitcoinNetwork::Regtest => Network::Regtest,
    });
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    satspath_handoff::bolt12(trimmed, network, now).map_err(SatsPathError::InvalidPaymentPointer)
}

/// Decode a Bitcoin address and require the declared network.
pub fn validate_bitcoin_address(address: &str, network: BitcoinNetwork) -> Result<()> {
    let parsed = Address::from_str(address.trim())
        .map_err(|e| SatsPathError::InvalidPaymentPointer(e.to_string()))?;
    let expected = match network {
        BitcoinNetwork::Mainnet => Network::Bitcoin,
        BitcoinNetwork::Testnet => Network::Testnet,
        BitcoinNetwork::Regtest => Network::Regtest,
    };
    parsed
        .require_network(expected)
        .map_err(|e| SatsPathError::InvalidPaymentPointer(e.to_string()))?;
    Ok(())
}

/// Validate BIP-352 encoding and public keys using the shared wallet policy.
pub fn validate_silent_payment_address(address: &str, network: BitcoinNetwork) -> Result<()> {
    let address = address.trim();
    assert_no_private_material(address)?;
    let network = match network {
        BitcoinNetwork::Mainnet => Network::Bitcoin,
        BitcoinNetwork::Testnet => Network::Testnet,
        BitcoinNetwork::Regtest => Network::Regtest,
    };
    satspath_handoff::silent(address, network).map_err(SatsPathError::InvalidPaymentPointer)
}

pub fn assert_no_private_material(payload: &str) -> Result<()> {
    let lower = payload.to_ascii_lowercase();
    let blocked = [
        "xprv",
        "tprv",
        "seed phrase",
        "mnemonic",
        "private_key",
        "private key",
        "secret_key",
        "macaroon",
        "cert",
        "api_key",
        "apikey",
        "secret_key",
        "secret_hex",
        "password",
    ];
    if let Some(term) = blocked.iter().find(|term| lower.contains(**term)) {
        return Err(SatsPathError::PrivateMaterialRejected((*term).into()));
    }

    let word_count = payload
        .split(|c: char| !c.is_ascii_alphabetic())
        .filter(|word| word.len() >= 3)
        .count();
    if word_count >= 12 && lower.contains("seed") {
        return Err(SatsPathError::PrivateMaterialRejected(
            "seed phrase-like payload".into(),
        ));
    }
    Ok(())
}

pub fn assert_mainnet_preview_safe(payload: &str) -> Result<()> {
    assert_no_private_material(payload)?;

    let lower = payload.to_ascii_lowercase();
    let blocked = [
        "seed",
        "mnemonic",
        "xprv",
        "tprv",
        "private key",
        "privkey",
        "macaroon",
        "cert",
        "api_key",
        "secret_key",
        "secret_hex",
        "password",
        "refund_key",
        "claim_key",
        "preimage",
    ];
    if let Some(term) = blocked.iter().find(|term| lower.contains(**term)) {
        return Err(SatsPathError::PrivateMaterialRejected((*term).into()));
    }

    let secret_field_names = [
        "seed",
        "mnemonic",
        "xprv",
        "tprv",
        "private_key",
        "privkey",
        "macaroon",
        "cert",
        "api_key",
        "secret_key",
        "secret_hex",
        "password",
        "refund_key",
        "claim_key",
        "preimage",
    ];
    for field in secret_field_names {
        if lower.contains(&format!("\"{field}\"")) || lower.contains(&format!("'{field}'")) {
            return Err(SatsPathError::PrivateMaterialRejected(format!(
                "secret-bearing field `{field}`"
            )));
        }
    }

    Ok(())
}

pub fn validate_claim_policy(policy: &ClaimPolicy) -> Result<()> {
    match policy {
        ClaimPolicy::SingleSig { receiver_pubkey } => validate_compressed_pubkey(receiver_pubkey),
        ClaimPolicy::Multisig {
            threshold,
            pubkeys,
            descriptor,
        } => {
            if *threshold == 0 || usize::from(*threshold) > pubkeys.len() {
                return Err(SatsPathError::InvalidPaymentPointer(
                    "invalid multisig threshold".into(),
                ));
            }
            for pubkey in pubkeys {
                validate_compressed_pubkey(pubkey)?;
            }
            if let Some(descriptor) = descriptor {
                assert_no_private_material(descriptor)?;
            }
            Ok(())
        }
        ClaimPolicy::FutureTaproot {
            internal_key,
            script_policy_hint,
        } => {
            validate_compressed_pubkey(internal_key)?;
            if let Some(hint) = script_policy_hint {
                assert_no_private_material(hint)?;
            }
            Ok(())
        }
    }
}

pub fn validate_public_profile(profile: &PaymentProfile) -> Result<()> {
    assert_no_private_material(&profile.alias)?;
    validate_compressed_pubkey(&profile.identity_pubkey)?;
    if let Some(expires_at) = profile.expires_at {
        if expires_at <= profile.updated_at {
            return Err(SatsPathError::InvalidPaymentPointer(
                "profile expires before it is updated".into(),
            ));
        }
    }

    for method in &profile.methods {
        match method {
            PaymentMethod::Lightning {
                lightning_address,
                lnurl,
                bolt12,
                receiver_pubkey,
                ..
            } => {
                if let Some(address) = lightning_address {
                    validate_lightning_address(address)?;
                }
                if let Some(url) = lnurl {
                    assert_no_private_material(url)?;
                    satspath_handoff::https(url).map_err(SatsPathError::InvalidPaymentPointer)?;
                }
                if let Some(invoice) = bolt12 {
                    assert_no_private_material(invoice)?;
                    if let Some(network) = satspath_handoff::bolt11_network(invoice) {
                        let now = chrono::Utc::now().timestamp().max(0) as u64;
                        satspath_handoff::bolt11_profile(invoice, network, now)
                            .map_err(SatsPathError::InvalidPaymentPointer)?;
                    } else {
                        validate_bolt12_offer(invoice)?;
                    }
                }
                if let Some(pubkey) = receiver_pubkey {
                    validate_compressed_pubkey(pubkey)?;
                }
            }
            PaymentMethod::Onchain {
                network,
                address,
                silent_payment_pubkey,
                pubkey_hint,
                descriptor_hint,
                ..
            } => {
                if let Some(addr) = address {
                    validate_bitcoin_address(addr, *network)?;
                }
                if let Some(sp) = silent_payment_pubkey {
                    validate_silent_payment_address(sp, *network)?;
                }
                if let Some(pubkey) = pubkey_hint {
                    validate_compressed_pubkey(pubkey)?;
                }
                if let Some(descriptor) = descriptor_hint {
                    assert_no_private_material(descriptor)?;
                }
            }
            PaymentMethod::Bolt12(offer) => {
                validate_bolt12_offer_for_network(&offer.offer, Some(offer.network))?;
            }
            PaymentMethod::Ark {
                server,
                pubkey,
                vtxo_pointer,
                proof,
                expires_at,
                opaque_uri,
                ..
            } => {
                if let Some(uri) = opaque_uri {
                    // Arkade opaque URI path -- server + pubkey are empty sentinels.
                    // Validate only the public URI; ownership proof is not possible.
                    crate::ark::validate_arkade_opaque_uri(uri)?;
                } else {
                    // Full server + pubkey path -- existing validation.
                    let pointer = ArkReceivePointer {
                        server: server.clone(),
                        receiver_pubkey: pubkey.clone(),
                        vtxo_pointer: vtxo_pointer.clone(),
                        proof: proof.clone(),
                        expires_at: *expires_at,
                    };
                    let now = chrono::Utc::now().timestamp();
                    validate_ark_receive_pointer(&pointer, now)?;
                    if proof.is_some()
                        && !verify_ark_ownership_proof(
                            &profile.alias,
                            &profile.identity_pubkey,
                            &pointer,
                            now,
                        )?
                    {
                        return Err(SatsPathError::InvalidSignature);
                    }
                }
            }
        }
    }

    // Ownership attestations are structurally validated here (no private
    // material, well-formed proofs, sane expiry). Cryptographic re-verification
    // is performed separately at resolve time by
    // `ownership::verify_method_verification`.
    for verification in &profile.method_verifications {
        crate::ownership::validate_method_verification(verification)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const VALID_PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    #[test]
    fn mainnet_address_accepted_in_mainnet_preview() {
        assert!(validate_bitcoin_address(
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            BitcoinNetwork::Mainnet
        )
        .is_ok());
    }

    #[test]
    fn testnet_address_rejected_in_mainnet_preview() {
        assert!(validate_bitcoin_address(
            "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
            BitcoinNetwork::Mainnet
        )
        .is_err());
    }

    #[test]
    fn compressed_secp256k1_pubkey_accepted() {
        assert!(validate_compressed_pubkey(VALID_PUBKEY).is_ok());
    }

    #[test]
    fn invalid_pubkey_rejected() {
        assert!(validate_compressed_pubkey("04abcdef").is_err());
    }

    #[test]
    fn lightning_address_parsed() {
        assert!(validate_lightning_address("rodrigo@example.com").is_ok());
        assert!(validate_lightning_address("not-an-address").is_err());
    }

    #[test]
    fn profile_rejects_private_material() {
        let profile = PaymentProfile {
            alias: "alice@example.com".into(),
            identity_pubkey: VALID_PUBKEY.into(),
            methods: vec![PaymentMethod::Lightning {
                label: "LN".into(),
                lightning_address: Some("alice@example.com".into()),
                lnurl: None,
                bolt12: Some("secret xprv payload".into()),
                receiver_pubkey: None,
            }],
            updated_at: 1,
            expires_at: Some(2),
            sequence: None,
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: Vec::new(),
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
            recovery_policy: None,
            recovery: None,
        };
        assert!(validate_public_profile(&profile).is_err());
    }

    #[test]
    fn mainnet_preview_safe_rejects_secret_terms() {
        assert!(assert_mainnet_preview_safe("bitcoin:bc1qexample?amount=0.1").is_ok());
        assert!(assert_mainnet_preview_safe("{\"claim_key\":\"abc\"}").is_err());
        assert!(assert_mainnet_preview_safe("lnbc1_refund_key_payload").is_err());
    }

    #[test]
    fn multisig_claim_policy_validates_pubkeys() {
        let policy = ClaimPolicy::Multisig {
            threshold: 2,
            pubkeys: vec![VALID_PUBKEY.into(), VALID_PUBKEY.into()],
            descriptor: Some("wsh(sortedmulti(2,...))".into()),
        };
        assert!(validate_claim_policy(&policy).is_ok());
    }

    #[test]
    /// Verify that silent payment address validation.
    fn silent_payment_address_validation() {
        use bech32::ToBase32;

        let key = hex::decode(VALID_PUBKEY).unwrap();
        let mut payload = vec![bech32::u5::try_from_u8(0).unwrap()];
        payload.extend([key.clone(), key].concat().to_base32());
        let mainnet_sp = bech32::encode("sp", &payload, bech32::Variant::Bech32m).unwrap();
        let testnet_sp = bech32::encode("tsp", &payload, bech32::Variant::Bech32m).unwrap();

        // Valid addresses
        assert!(validate_silent_payment_address(&mainnet_sp, BitcoinNetwork::Mainnet).is_ok());
        assert!(validate_silent_payment_address(&testnet_sp, BitcoinNetwork::Testnet).is_ok());
        assert!(validate_silent_payment_address(
            &format!(" \t{mainnet_sp}\n"),
            BitcoinNetwork::Mainnet
        )
        .is_ok());
        assert!(validate_silent_payment_address(
            &format!("\n{testnet_sp} \t"),
            BitcoinNetwork::Testnet
        )
        .is_ok());

        // Network mismatch
        assert!(validate_silent_payment_address(&mainnet_sp, BitcoinNetwork::Testnet).is_err());
        assert!(validate_silent_payment_address(&testnet_sp, BitcoinNetwork::Mainnet).is_err());

        // Empty address
        assert!(validate_silent_payment_address("", BitcoinNetwork::Mainnet).is_err());

        // Private material rejected
        assert!(
            validate_silent_payment_address("sp1q_xprv_secret", BitcoinNetwork::Mainnet).is_err()
        );
        assert!(matches!(
            validate_silent_payment_address(" \tsp1q_xprv_secret\n", BitcoinNetwork::Mainnet),
            Err(SatsPathError::PrivateMaterialRejected(_))
        ));

        // Truncated payload
        let truncated = bech32::encode("sp", &payload[..30], bech32::Variant::Bech32m).unwrap();
        assert!(validate_silent_payment_address(&truncated, BitcoinNetwork::Mainnet).is_err());

        // Invalid version byte
        let mut bad_version_payload = payload.clone();
        bad_version_payload[0] = bech32::u5::try_from_u8(1).unwrap();
        let bad_version =
            bech32::encode("sp", bad_version_payload, bech32::Variant::Bech32m).unwrap();
        assert!(validate_silent_payment_address(&bad_version, BitcoinNetwork::Mainnet).is_err());
    }

    #[test]
    fn bolt12_and_profile_validation_match_handoff_rules() {
        let checksumless = "lno1pgx9getnwss8vetrw3hhyucs5ypjgef743p5fzqq9nqxh0ah7y87rzv3ud0eleps9kl2d5348hq2k8qzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgqpqqqqqqqqqqqqqqqqqqqqqqqqqqqzqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqyqszqgpqqzq3zyg3zyg3zygs";
        assert!(validate_bolt12_offer(checksumless).is_ok());

        let mut profile = PaymentProfile {
            alias: "alice@example.com".into(),
            identity_pubkey: VALID_PUBKEY.into(),
            methods: vec![PaymentMethod::Lightning {
                label: "BOLT12".into(),
                lightning_address: None,
                lnurl: Some("https://example.com/.well-known/lnurlp/alice".into()),
                bolt12: Some(checksumless.into()),
                receiver_pubkey: None,
            }],
            updated_at: 1,
            expires_at: Some(2),
            sequence: None,
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: Vec::new(),
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
            recovery_policy: None,
            recovery: None,
        };
        assert!(validate_public_profile(&profile).is_ok());

        profile.methods = vec![PaymentMethod::Lightning {
            label: "Insecure LNURL".into(),
            lightning_address: None,
            lnurl: Some("http://example.com/.well-known/lnurlp/alice".into()),
            bolt12: None,
            receiver_pubkey: None,
        }];
        assert!(validate_public_profile(&profile).is_err());
    }
}
