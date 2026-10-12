use serde::{Deserialize, Serialize};

use crate::crypto::{sign_message, verify_message_signature};
use crate::{Result, SatsPathError, SignedPaymentProfile};

pub const ROTATION_AUTHORIZATION_DOMAIN: &str = "SatsPathKeyRotationAuthorizationV1";
pub const ROTATION_ACCEPTANCE_DOMAIN: &str = "SatsPathKeyRotationAcceptanceV1";

/// A proof of key rotation.
/// If present, the `PaymentProfile::identity_pubkey` is the new key, and this object
/// proves that the rotation was authorized by the old key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRotation {
    #[serde(default = "rotation_version")]
    pub version: u16,
    #[serde(default)]
    pub identifier_hash: String,
    /// The previous identity public key (hex).
    pub previous_pubkey: String,
    /// The new identity public key (hex) - must match the profile's identity_pubkey.
    pub new_pubkey: String,
    /// Signature of the new pubkey created by the previous secret key.
    pub authorization_signature: String,
    /// Proof that the new key is possessed by the party accepting the rotation.
    #[serde(default)]
    pub acceptance_signature: String,
    #[serde(default)]
    pub previous_event_hash: String,
    #[serde(default)]
    pub sequence: u64,
    /// The timestamp when the rotation occurred.
    pub rotated_at: i64,
}

const fn rotation_version() -> u16 {
    1
}

impl KeyRotation {
    /// Create a new KeyRotation object, signing the new pubkey with the old secret key.
    pub fn create(
        identifier_hash: String,
        previous_pubkey_hex: String,
        old_secret_key: &secp256k1::SecretKey,
        new_pubkey_hex: String,
        new_secret_key: &secp256k1::SecretKey,
        previous_event_hash: String,
        sequence: u64,
    ) -> Result<Self> {
        let rotated_at = chrono::Utc::now().timestamp();
        let authorization_message = rotation_message(
            ROTATION_AUTHORIZATION_DOMAIN,
            &identifier_hash,
            &previous_pubkey_hex,
            &new_pubkey_hex,
            &previous_event_hash,
            sequence,
            rotated_at,
        );
        let acceptance_message = rotation_message(
            ROTATION_ACCEPTANCE_DOMAIN,
            &identifier_hash,
            &previous_pubkey_hex,
            &new_pubkey_hex,
            &previous_event_hash,
            sequence,
            rotated_at,
        );
        Ok(Self {
            version: 1,
            identifier_hash,
            previous_pubkey: previous_pubkey_hex,
            new_pubkey: new_pubkey_hex,
            authorization_signature: sign_message(&authorization_message, old_secret_key),
            acceptance_signature: sign_message(&acceptance_message, new_secret_key),
            previous_event_hash,
            sequence,
            rotated_at,
        })
    }

    /// Verify the rotation authorization signature.
    pub fn verify(&self) -> Result<bool> {
        if self.version != 1
            || self.identifier_hash.is_empty()
            || self.previous_event_hash.is_empty()
            || self.sequence == 0
            || self.acceptance_signature.is_empty()
        {
            return Ok(false);
        }
        let authorization_message = rotation_message(
            ROTATION_AUTHORIZATION_DOMAIN,
            &self.identifier_hash,
            &self.previous_pubkey,
            &self.new_pubkey,
            &self.previous_event_hash,
            self.sequence,
            self.rotated_at,
        );
        let acceptance_message = rotation_message(
            ROTATION_ACCEPTANCE_DOMAIN,
            &self.identifier_hash,
            &self.previous_pubkey,
            &self.new_pubkey,
            &self.previous_event_hash,
            self.sequence,
            self.rotated_at,
        );
        Ok(verify_message_signature(
            &authorization_message,
            &self.authorization_signature,
            &self.previous_pubkey,
        )? && verify_message_signature(
            &acceptance_message,
            &self.acceptance_signature,
            &self.new_pubkey,
        )?)
    }
}

pub fn rotation_message(
    domain: &str,
    identifier: &str,
    old_pubkey: &str,
    new_pubkey: &str,
    previous_event_hash: &str,
    sequence: u64,
    rotated_at: i64,
) -> String {
    format!(
        "{domain}\n{identifier}\n{old_pubkey}\n{new_pubkey}\n{previous_event_hash}\n{sequence}\n{rotated_at}"
    )
}

/// Apply a key rotation to a signed payment profile.
/// The profile must have a valid KeyRotation, and the new pubkey must match the rotation's new_pubkey.
pub fn apply_key_rotation(
    profile: &SignedPaymentProfile,
    new_pubkey_hex: &str,
) -> Result<SignedPaymentProfile> {
    let rotation = profile.profile.rotation.as_ref().ok_or_else(|| {
        crate::errors::SatsPathError::CryptoError("no key rotation in profile".into())
    })?;

    if rotation.new_pubkey != new_pubkey_hex {
        return Err(crate::errors::SatsPathError::CryptoError(
            "new pubkey doesn't match rotation".into(),
        ));
    }

    if rotation.previous_pubkey != profile.profile.identity_pubkey {
        return Err(crate::errors::SatsPathError::InvalidRotation(
            "rotation previous_pubkey does not match profile identity_pubkey".into(),
        ));
    }

    if rotation.identifier_hash != crate::privacy::identifier_hash(&profile.profile.alias) {
        return Err(crate::errors::SatsPathError::InvalidRotation(
            "rotation identifier_hash does not match profile alias".into(),
        ));
    }

    let expected_sequence = profile.profile.sequence.unwrap_or(0).saturating_add(1);
    if rotation.sequence != expected_sequence {
        return Err(crate::errors::SatsPathError::InvalidRotation(
            "rotation sequence must equal the next profile sequence".into(),
        ));
    }

    if !rotation.verify()? {
        return Err(crate::errors::SatsPathError::InvalidSignature);
    }

    // Create new profile with updated identity pubkey
    let mut new_profile = profile.profile.clone();
    new_profile.identity_pubkey = new_pubkey_hex.to_string();
    new_profile.sequence = Some(rotation.sequence);
    // Clear rotation since it's been applied
    new_profile.rotation = None;

    // The new profile needs to be signed with the NEW secret key
    // For now, we return the profile without signature (caller must re-sign)
    Ok(SignedPaymentProfile {
        profile: new_profile,
        signature: String::new(),
        hybrid_signature: None, // Placeholder - must be re-signed
    })
}

/// Get the effective identity pubkey, considering key rotation.
/// If a valid key rotation bound to this profile is present, returns the new pubkey.
/// Otherwise returns the profile's identity_pubkey.
pub fn get_effective_identity_pubkey(profile: &SignedPaymentProfile) -> Result<String> {
    if is_rotation_valid(profile)? {
        if let Some(rotation) = &profile.profile.rotation {
            return Ok(rotation.new_pubkey.clone());
        }
    }
    Ok(profile.profile.identity_pubkey.clone())
}

/// Check if a key rotation is valid and strictly bound to the profile.
pub fn is_rotation_valid(profile: &SignedPaymentProfile) -> Result<bool> {
    if let Some(rotation) = &profile.profile.rotation {
        if rotation.identifier_hash != crate::privacy::identifier_hash(&profile.profile.alias) {
            return Ok(false);
        }
        if rotation.previous_pubkey != profile.profile.identity_pubkey
            && rotation.new_pubkey != profile.profile.identity_pubkey
        {
            return Ok(false);
        }
        if let Some(seq) = profile.profile.sequence {
            if rotation.new_pubkey == profile.profile.identity_pubkey && rotation.sequence != seq {
                return Ok(false);
            }
            if rotation.previous_pubkey == profile.profile.identity_pubkey
                && rotation.sequence != seq.saturating_add(1)
            {
                return Ok(false);
            }
        }
        rotation.verify()
    } else {
        Ok(false)
    }
}

/// Rotate the identity key of a signed payment profile.
/// This creates a new KeyRotation and updates the profile.
/// Returns the new profile with the rotation applied (but not yet signed).
pub fn rotate_identity_key(
    profile: &SignedPaymentProfile,
    old_secret_key: &secp256k1::SecretKey,
    new_secret_key: &secp256k1::SecretKey,
    previous_event_hash: &str,
    sequence: u64,
) -> Result<SignedPaymentProfile> {
    let secp = secp256k1::Secp256k1::new();
    let new_public_key = secp256k1::PublicKey::from_secret_key(&secp, new_secret_key);
    let new_pubkey_hex = hex::encode(new_public_key.serialize());

    let old_pubkey_hex = profile.profile.identity_pubkey.clone();

    let old_derived = secp256k1::PublicKey::from_secret_key(&secp, old_secret_key);
    if hex::encode(old_derived.serialize()) != old_pubkey_hex {
        return Err(SatsPathError::InvalidRotation(
            "old secret key does not control the current identity key".into(),
        ));
    }
    let next_sequence = profile.profile.sequence.unwrap_or(0).saturating_add(1);
    if sequence != next_sequence {
        return Err(SatsPathError::InvalidRotation(
            "rotation sequence must equal the canonical next sequence".into(),
        ));
    }
    let rotation = KeyRotation::create(
        crate::privacy::identifier_hash(&profile.profile.alias),
        old_pubkey_hex,
        old_secret_key,
        new_pubkey_hex.clone(),
        new_secret_key,
        previous_event_hash.to_owned(),
        sequence,
    )?;

    let mut new_profile = profile.profile.clone();
    new_profile.identity_pubkey = new_pubkey_hex;
    new_profile.rotation = Some(rotation);
    new_profile.sequence = Some(sequence);
    // Clear signature since it needs to be re-signed with the new key
    // The caller must re-sign with the new secret key
    Ok(SignedPaymentProfile {
        profile: new_profile,
        signature: String::new(),
        hybrid_signature: None,
    })
}

/// Verify a key rotation between old and new profiles.
pub fn verify_key_rotation(
    old_profile: &SignedPaymentProfile,
    new_profile: &SignedPaymentProfile,
) -> Result<bool> {
    // The new profile should have a rotation pointing from old pubkey to new pubkey
    if let Some(rotation) = &new_profile.profile.rotation {
        if rotation.previous_pubkey != old_profile.profile.identity_pubkey {
            return Ok(false);
        }
        if rotation.new_pubkey != new_profile.profile.identity_pubkey {
            return Ok(false);
        }
        if rotation.identifier_hash != crate::privacy::identifier_hash(&old_profile.profile.alias)
            || new_profile.profile.alias != old_profile.profile.alias
            || rotation.sequence != new_profile.profile.sequence.unwrap_or(0)
            || rotation.sequence != old_profile.profile.sequence.unwrap_or(0).saturating_add(1)
        {
            return Ok(false);
        }
        Ok(rotation.verify()? && crate::crypto::verify_signed_profile(new_profile)?)
    } else {
        Ok(false)
    }
}
