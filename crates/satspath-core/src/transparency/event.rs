use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::crypto::{canonical_profile_bytes, sign_message};
use crate::{Result, SignedPaymentProfile};

use super::TransparencyError;

pub const NAME_EVENT_PAYLOAD_DOMAIN: &[u8] = b"SatsPathNameEventPayloadV1";
pub const SIGNED_NAME_EVENT_DOMAIN: &[u8] = b"SatsPathSignedNameEventV1";
pub const NAME_EVENT_SIGNATURE_DOMAIN: &str = "SatsPathNameEventSignatureV1";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NameAction {
    Register,
    UpdateProfile,
    RotateKey,
    Revoke,
    RecoverKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NameEvent {
    pub version: u16,
    pub identifier_hash: String,
    pub action: NameAction,
    pub identity_pubkey: String,
    pub profile_hash: String,
    pub sequence: u64,
    pub previous_event_hash: Option<String>,
    pub created_at: i64,
    pub identifier_attestation_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub removed_method_hashes: Vec<String>,
    pub rotation: Option<crate::rotation::KeyRotation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_policy: Option<crate::recovery::RecoveryPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<crate::recovery::KeyRecoveryProof>,
    pub owner_signature: String,
}

#[derive(Serialize)]
struct UnsignedEvent<'a> {
    version: u16,
    identifier_hash: &'a str,
    action: NameAction,
    identity_pubkey: &'a str,
    profile_hash: &'a str,
    sequence: u64,
    previous_event_hash: &'a Option<String>,
    created_at: i64,
    identifier_attestation_hash: &'a Option<String>,
    removed_method_hashes: &'a [String],
    rotation: &'a Option<crate::rotation::KeyRotation>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_policy: &'a Option<crate::recovery::RecoveryPolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery: &'a Option<crate::recovery::KeyRecoveryProof>,
}

impl NameEvent {
    pub fn unsigned_canonical_bytes(&self) -> Result<Vec<u8>> {
        let value = serde_json::to_value(UnsignedEvent {
            version: self.version,
            identifier_hash: &self.identifier_hash,
            action: self.action,
            identity_pubkey: &self.identity_pubkey,
            profile_hash: &self.profile_hash,
            sequence: self.sequence,
            previous_event_hash: &self.previous_event_hash,
            created_at: self.created_at,
            identifier_attestation_hash: &self.identifier_attestation_hash,
            removed_method_hashes: &self.removed_method_hashes,
            rotation: &self.rotation,
            recovery_policy: &self.recovery_policy,
            recovery: &self.recovery,
        })?;
        Ok(canonical_json::to_string(&value)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?
            .into_bytes())
    }

    pub fn signing_payload_hash(&self) -> Result<String> {
        let mut h = Sha256::new();
        h.update(NAME_EVENT_PAYLOAD_DOMAIN);
        h.update(self.unsigned_canonical_bytes()?);
        Ok(hex::encode(h.finalize()))
    }

    /// Hash committed by the Merkle leaf and by the next event in the chain.
    /// Unlike the signing payload, this commits to the exact owner signature.
    pub fn signed_event_hash(&self) -> Result<String> {
        let value = serde_json::to_value(self)?;
        let canonical = canonical_json::to_string(&value)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?;
        let mut h = Sha256::new();
        h.update(SIGNED_NAME_EVENT_DOMAIN);
        h.update(canonical.as_bytes());
        Ok(hex::encode(h.finalize()))
    }

    /// Backward-compatible name. Event identity always means the signed event.
    pub fn event_hash(&self) -> Result<String> {
        self.signed_event_hash()
    }

    pub fn signing_message(&self) -> Result<String> {
        Ok(format!(
            "{}\n{}",
            NAME_EVENT_SIGNATURE_DOMAIN,
            self.signing_payload_hash()?
        ))
    }

    pub fn sign(&mut self, secret_key: &SecretKey) -> Result<()> {
        self.owner_signature = sign_message(&self.signing_message()?, secret_key);
        Ok(())
    }
}

pub fn payment_method_descriptor_hash(descriptor: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"SatsPathPaymentMethodDescriptorV1");
    h.update(descriptor.as_bytes());
    hex::encode(h.finalize())
}

pub fn profile_hash(profile: &SignedPaymentProfile) -> Result<String> {
    let mut h = Sha256::new();
    h.update(b"SatsPathSignedPaymentProfileV1");
    h.update(canonical_profile_bytes(&profile.profile)?);
    h.update(hex::decode(&profile.signature).map_err(|_| TransparencyError::ProfileHashMismatch)?);
    Ok(hex::encode(h.finalize()))
}
