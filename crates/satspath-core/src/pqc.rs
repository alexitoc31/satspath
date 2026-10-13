use serde::{Deserialize, Serialize};

/// Identifies the PQC algorithm suite used.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PqcSuite {
    /// ML-KEM-768 + X25519 (hybrid KEM, NIST security level 3)
    #[serde(rename = "mlkem768_x25519")]
    MlKem768X25519,
    /// ML-DSA-65 + Schnorr secp256k1 (hybrid signature, NIST security level 3)
    #[serde(rename = "mldsa65_schnorr")]
    MlDsa65Schnorr,
}

/// A hybrid signature that contains both classical and post-quantum components.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridSignature {
    /// Classical Schnorr signature (secp256k1) — hex-encoded
    pub schnorr_sig: String,
    /// ML-DSA-65 (Dilithium) signature — hex-encoded
    pub pqc_sig: String,
    /// Algorithm suite identifier
    pub suite: PqcSuite,
}

/// A hybrid public key bundle containing both classical and PQC keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HybridPublicKey {
    /// Classical secp256k1 public key (33-byte compressed, hex)
    pub classical_pubkey: String,
    /// ML-DSA-65 verification key — hex-encoded
    pub pqc_verification_key: String,
    /// Algorithm suite identifier
    pub suite: PqcSuite,
}

#[cfg(feature = "pqc")]
impl From<satspath_pqc::types::HybridPublicKey> for HybridPublicKey {
    /// Moves a PQC public key bundle into the core wire type, preserving its suite.
    fn from(pk: satspath_pqc::types::HybridPublicKey) -> Self {
        Self {
            classical_pubkey: pk.classical_pubkey,
            pqc_verification_key: pk.pqc_verification_key,
            suite: match pk.suite {
                satspath_pqc::types::PqcSuite::MlKem768X25519 => PqcSuite::MlKem768X25519,
                satspath_pqc::types::PqcSuite::MlDsa65Schnorr => PqcSuite::MlDsa65Schnorr,
            },
        }
    }
}

#[cfg(feature = "pqc")]
impl From<satspath_pqc::types::HybridSignature> for HybridSignature {
    /// Moves a PQC signature into the core wire type, preserving both signatures and suite.
    fn from(sig: satspath_pqc::types::HybridSignature) -> Self {
        Self {
            schnorr_sig: sig.schnorr_sig,
            pqc_sig: sig.pqc_sig,
            suite: match sig.suite {
                satspath_pqc::types::PqcSuite::MlKem768X25519 => PqcSuite::MlKem768X25519,
                satspath_pqc::types::PqcSuite::MlDsa65Schnorr => PqcSuite::MlDsa65Schnorr,
            },
        }
    }
}

#[cfg(feature = "pqc")]
impl From<&HybridPublicKey> for satspath_pqc::types::HybridPublicKey {
    /// Copies a core public key bundle into the PQC verifier's type without validation.
    fn from(pk: &HybridPublicKey) -> Self {
        Self {
            classical_pubkey: pk.classical_pubkey.clone(),
            pqc_verification_key: pk.pqc_verification_key.clone(),
            suite: match pk.suite {
                PqcSuite::MlKem768X25519 => satspath_pqc::types::PqcSuite::MlKem768X25519,
                PqcSuite::MlDsa65Schnorr => satspath_pqc::types::PqcSuite::MlDsa65Schnorr,
            },
        }
    }
}

#[cfg(feature = "pqc")]
impl From<&HybridSignature> for satspath_pqc::types::HybridSignature {
    /// Copies a core signature into the PQC verifier's type without validation.
    fn from(sig: &HybridSignature) -> Self {
        Self {
            schnorr_sig: sig.schnorr_sig.clone(),
            pqc_sig: sig.pqc_sig.clone(),
            suite: match sig.suite {
                PqcSuite::MlKem768X25519 => satspath_pqc::types::PqcSuite::MlKem768X25519,
                PqcSuite::MlDsa65Schnorr => satspath_pqc::types::PqcSuite::MlDsa65Schnorr,
            },
        }
    }
}
