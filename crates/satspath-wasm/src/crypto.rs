//! WASM-exported crypto functions for SatsPath.
//!
//! Replaces `@noble/curves` + `@noble/hashes` in `sdk/satspath-p2p`.
//! Uses the exact same algorithm as `satspath-core::crypto`:
//!   sig = Schnorr(SHA-256("SatsPathProfileV1" || canonical_json(profile)))

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use wasm_bindgen::prelude::*;

/// Domain separator — must match satspath-core::crypto::PROFILE_DOMAIN_SEPARATOR
const PROFILE_DOMAIN_SEPARATOR: &[u8] = b"SatsPathProfileV1";

#[wasm_bindgen]
pub struct IdentityKeypair {
    pubkey_hex: String,
    secret_key_hex: String,
}

#[wasm_bindgen]
impl IdentityKeypair {
    #[wasm_bindgen(getter)]
    pub fn pubkey_hex(&self) -> String {
        self.pubkey_hex.clone()
    }
    #[wasm_bindgen(getter)]
    pub fn secret_key_hex(&self) -> String {
        self.secret_key_hex.clone()
    }
}

/// Generate a fresh secp256k1 keypair for the identity.
#[wasm_bindgen]
pub fn generate_identity_keypair() -> IdentityKeypair {
    let secp = secp256k1::Secp256k1::new();
    let (sk, pk) = secp.generate_keypair(&mut rand_core::OsRng);
    IdentityKeypair {
        pubkey_hex: hex::encode(pk.serialize()),
        secret_key_hex: hex::encode(sk.secret_bytes()),
    }
}

/// Derive a deterministic secp256k1 identity keypair from wallet seed bytes.
#[wasm_bindgen]
pub fn derive_identity_keypair_from_seed(
    seed: &[u8],
    account_index: u32,
) -> Option<IdentityKeypair> {
    if seed.is_empty() {
        return None;
    }
    use hmac::{Hmac, Mac};
    use sha2::Sha512;
    type HmacSha512 = Hmac<Sha512>;

    let mut mac = HmacSha512::new_from_slice(b"SatsPath Identity Key m/9737'/0'").ok()?;
    mac.update(seed);
    mac.update(&account_index.to_be_bytes());
    let result = mac.finalize().into_bytes();

    let mut candidate = [0u8; 32];
    candidate.copy_from_slice(&result[..32]);

    let secp = secp256k1::Secp256k1::new();
    let sk = secp256k1::SecretKey::from_slice(&candidate).ok()?;
    let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

    Some(IdentityKeypair {
        pubkey_hex: hex::encode(pk.serialize()),
        secret_key_hex: hex::encode(sk.secret_bytes()),
    })
}

/// Sign a canonical JSON profile using Schnorr.
/// Takes the profile JSON and the secret key hex.
/// Returns the signature in hex.
#[wasm_bindgen]
pub fn sign_profile_json(profile_json: &str, secret_key_hex: &str) -> String {
    let sk_bytes = match hex::decode(secret_key_hex) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    let keypair =
        match secp256k1::Keypair::from_seckey_slice(&secp256k1::Secp256k1::new(), &sk_bytes) {
            Ok(kp) => kp,
            Err(_) => return String::new(),
        };

    let canonical_bytes = canonical_profile_json(profile_json);
    if canonical_bytes.is_empty() {
        return String::new();
    }

    let mut hasher = Sha256::new();
    hasher.update(PROFILE_DOMAIN_SEPARATOR);
    hasher.update(&canonical_bytes);
    let digest = hasher.finalize();

    let msg = match secp256k1::Message::from_digest_slice(&digest) {
        Ok(m) => m,
        Err(_) => return String::new(),
    };

    let sig =
        secp256k1::Secp256k1::new().sign_schnorr_with_rng(&msg, &keypair, &mut rand_core::OsRng);
    hex::encode(sig.as_ref())
}

/// Opaque classical and post-quantum signing keys, available when `pqc` is enabled.
#[cfg(feature = "pqc")]
#[wasm_bindgen]
pub struct HybridIdentityKeypair {
    keypair: satspath_pqc::hybrid_sig::HybridSigningKeyPair,
}

#[cfg(feature = "pqc")]
#[wasm_bindgen]
impl HybridIdentityKeypair {
    /// Return the compressed secp256k1 identity public key as hex.
    #[wasm_bindgen(getter)]
    pub fn classical_pubkey_hex(&self) -> String {
        hex::encode(self.keypair.classical_pk.serialize())
    }
    /// Return the encoded ML-DSA verification key as hex.
    #[wasm_bindgen(getter)]
    pub fn pqc_verification_key_hex(&self) -> String {
        hex::encode(self.keypair.pqc_vk.encode())
    }
}

/// Generate a fresh hybrid keypair for the identity.
#[cfg(feature = "pqc")]
#[wasm_bindgen]
pub fn generate_hybrid_identity_keypair() -> HybridIdentityKeypair {
    HybridIdentityKeypair {
        keypair: satspath_pqc::hybrid_sig::generate_hybrid_keypair(),
    }
}

/// Sign a canonical JSON profile using Hybrid Signature (Schnorr + ML-DSA).
/// Borrows an opaque keypair so signing material stays inside WASM.
/// Returns a JSON string of the `HybridSignature` object, or empty string on error.
#[cfg(feature = "pqc")]
#[wasm_bindgen]
pub fn sign_hybrid_profile_json(profile_json: &str, keypair: &HybridIdentityKeypair) -> String {
    let canonical_bytes = canonical_profile_json(profile_json);
    if canonical_bytes.is_empty() {
        return String::new();
    }

    let sig = satspath_pqc::hybrid_sig::hybrid_sign(&canonical_bytes, &keypair.keypair);
    serde_json::to_string(&sig).unwrap_or_default()
}

#[derive(Debug, Deserialize, Serialize)]
struct SignedPaymentProfile {
    profile: Value,
    signature: String,
}

/// Verify a SatsPath `SignedPaymentProfile` passed as a JSON string.
///
/// Returns `true` only if the secp256k1 Schnorr signature is valid for the
/// profile's `identity_pubkey`. Returns `false` on any error — never throws.
///
/// Algorithm (matches Protocol v0.1 §12 / satspath-core):
///   digest = SHA-256("SatsPathProfileV1" || canonical_json(profile))
///   verify Schnorr(sig, digest, identity_pubkey)
///
/// Also attempts legacy fallback (insertion-order JSON, no domain separator)
/// for profiles signed by very early satspath-core versions using ECDSA.
#[wasm_bindgen]
pub fn verify_signed_profile(signed_json: &str) -> bool {
    let signed: SignedPaymentProfile = match serde_json::from_str(signed_json) {
        Ok(v) => v,
        Err(_) => return false,
    };

    let pubkey_str = match signed
        .profile
        .get("identity_pubkey")
        .and_then(Value::as_str)
    {
        Some(s) => s,
        None => return false,
    };

    let pubkey_bytes = match hex::decode(pubkey_str) {
        Ok(b) => b,
        Err(_) => return false,
    };

    // Parse pubkey as XOnlyPublicKey (32 bytes) or full PublicKey (33 bytes)
    let x_only_public_key = if pubkey_bytes.len() == 32 {
        match secp256k1::XOnlyPublicKey::from_slice(&pubkey_bytes) {
            Ok(k) => k,
            Err(_) => return false,
        }
    } else {
        match secp256k1::PublicKey::from_slice(&pubkey_bytes) {
            Ok(k) => k.x_only_public_key().0,
            Err(_) => return false,
        }
    };

    let sig_bytes = match hex::decode(&signed.signature) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let sig = match secp256k1::schnorr::Signature::from_slice(&sig_bytes) {
        Ok(s) => s,
        Err(_) => return false,
    };

    let secp = secp256k1::Secp256k1::verification_only();

    // Try current canonical JSON (key-sorted) with domain separator
    if let Ok(canonical_bytes) = canonical_json_bytes(&signed.profile) {
        let mut hasher = Sha256::new();
        hasher.update(PROFILE_DOMAIN_SEPARATOR);
        hasher.update(&canonical_bytes);
        let digest = hasher.finalize();
        if let Ok(msg) = secp256k1::Message::from_digest_slice(&digest) {
            if secp.verify_schnorr(&sig, &msg, &x_only_public_key).is_ok() {
                return true;
            }
        }
    }

    // Legacy fallback: insertion-order JSON (no domain separator), ECDSA
    if let Ok(ecdsa_sig) = secp256k1::ecdsa::Signature::from_der(&sig_bytes) {
        if let Ok(pubkey) = secp256k1::PublicKey::from_slice(&pubkey_bytes) {
            let legacy_json = match serde_json::to_string(&signed.profile) {
                Ok(s) => s,
                Err(_) => return false,
            };
            let legacy_digest = Sha256::digest(legacy_json.as_bytes());
            if let Ok(msg) = secp256k1::Message::from_digest_slice(&legacy_digest) {
                return secp.verify_ecdsa(&msg, &ecdsa_sig, &pubkey).is_ok();
            }
        }
    }

    false
}

/// Return the canonical UTF-8 JSON bytes of a profile JSON string.
///
/// Same as `satspath-core::crypto::canonical_profile_bytes` but callable from JS.
/// Returns an empty `Uint8Array` on parse/serialization error.
#[wasm_bindgen]
pub fn canonical_profile_json(profile_json: &str) -> Vec<u8> {
    let value: Value = match serde_json::from_str(profile_json) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    canonical_json_bytes(&value).unwrap_or_default()
}

/// Compute the 8-char fingerprint of a compressed secp256k1 pubkey.
///
/// Returns the first 8 hex characters (matching Rust `fingerprint_pubkey`).
/// Returns empty string on invalid input.
#[wasm_bindgen]
pub fn fingerprint_pubkey(pubkey_hex: &str) -> String {
    let bytes = match hex::decode(pubkey_hex) {
        Ok(b) => b,
        Err(_) => return String::new(),
    };
    if bytes.len() != 33 {
        return String::new();
    }
    // Skip the 02/03 prefix, take first 4 bytes = 8 hex chars
    hex::encode(&bytes[1..5])
}

/// Serialize a JSON value into deterministic UTF-8 bytes with sorted object keys.
///
/// Omits whitespace and preserves array order. Propagates serialization errors
/// from [`write_canonical_value`] as strings.
fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let mut buf = Vec::new();
    write_canonical_value(value, &mut buf)?;
    Ok(buf)
}

/// Append a JSON value recursively, sorting object keys and omitting whitespace.
///
/// Preserves existing bytes in `buf` and array order; keys use Rust string ordering.
/// Propagates JSON serialization errors as strings, leaving any bytes already
/// appended in `buf` on error.
fn write_canonical_value(value: &Value, buf: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => buf.extend_from_slice(b"null"),
        Value::Bool(true) => buf.extend_from_slice(b"true"),
        Value::Bool(false) => buf.extend_from_slice(b"false"),
        Value::Number(n) => {
            let s = serde_json::to_string(n).map_err(|e| e.to_string())?;
            buf.extend_from_slice(s.as_bytes());
        }
        Value::String(s) => {
            let escaped = serde_json::to_string(s).map_err(|e| e.to_string())?;
            buf.extend_from_slice(escaped.as_bytes());
        }
        Value::Array(arr) => {
            buf.push(b'[');
            for (idx, item) in arr.iter().enumerate() {
                if idx > 0 {
                    buf.push(b',');
                }
                write_canonical_value(item, buf)?;
            }
            buf.push(b']');
        }
        Value::Object(map) => {
            buf.push(b'{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (idx, k) in keys.iter().enumerate() {
                if idx > 0 {
                    buf.push(b',');
                }
                let key_escaped = serde_json::to_string(k).map_err(|e| e.to_string())?;
                buf.extend_from_slice(key_escaped.as_bytes());
                buf.push(b':');
                write_canonical_value(&map[*k], buf)?;
            }
            buf.push(b'}');
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "pqc")]
    #[test]
    fn hybrid_signing_uses_opaque_keypair() {
        use satspath_pqc::{
            hybrid_sig::hybrid_verify,
            types::{HybridPublicKey, HybridSignature, PqcSuite},
        };

        let keypair = generate_hybrid_identity_keypair();
        let public_key = HybridPublicKey {
            classical_pubkey: keypair.classical_pubkey_hex(),
            pqc_verification_key: keypair.pqc_verification_key_hex(),
            suite: PqcSuite::MlDsa65Schnorr,
        };

        assert!(sign_hybrid_profile_json("invalid json", &keypair).is_empty());
        for profile in [r#"{"b":1,"a":2}"#, r#"{"a":3,"b":1}"#] {
            let signature: HybridSignature =
                serde_json::from_str(&sign_hybrid_profile_json(profile, &keypair)).unwrap();
            assert!(hybrid_verify(
                &canonical_profile_json(profile),
                &signature,
                &public_key,
            ));
            assert!(!hybrid_verify(b"tampered", &signature, &public_key));
        }
    }

    #[test]
    fn fingerprint_matches_rust() {
        let pk = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        assert_eq!(fingerprint_pubkey(pk), "79be667e");
    }

    #[test]
    fn canonical_json_deterministic() {
        let a = r#"{"b":1,"a":2}"#;
        let b = r#"{"a":2,"b":1}"#;
        assert_eq!(canonical_profile_json(a), canonical_profile_json(b));
    }
}
