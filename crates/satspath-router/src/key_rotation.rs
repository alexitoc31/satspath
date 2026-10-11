use chrono;
use hex;
use satspath_core::crypto;
use satspath_core::{KeyRotation, SatsPathError, SignedPaymentProfile};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

/// Rotate the identity key for a profile
///
/// This creates a new KeyRotation object and updates the profile with the new identity key.
/// The rotation must be signed by the OLD identity key to prove authorization.
pub fn rotate_identity_key(
    profile: &SignedPaymentProfile,
    old_secret_key: &SecretKey,
    new_secret_key: &SecretKey,
    previous_event_hash: &str,
) -> Result<KeyRotation, SatsPathError> {
    let new_identity_pubkey =
        hex::encode(PublicKey::from_secret_key(&Secp256k1::new(), new_secret_key).serialize());
    let rotation = KeyRotation::create(
        satspath_core::privacy::identifier_hash(&profile.profile.alias),
        profile.profile.identity_pubkey.clone(),
        old_secret_key,
        new_identity_pubkey,
        new_secret_key,
        previous_event_hash.to_owned(),
        profile.profile.sequence.unwrap_or(0) + 1,
    )?;

    Ok(rotation)
}

/// Verify a key rotation
///
/// This verifies that the rotation was authorized by the old identity key.
pub fn verify_key_rotation(rotation: &KeyRotation) -> Result<bool, SatsPathError> {
    rotation.verify()
}

/// Apply a verified key rotation to a profile
///
/// This creates a new profile with the rotated identity key and updated sequence number.
pub fn apply_key_rotation(
    profile: &SignedPaymentProfile,
    rotation: &KeyRotation,
    new_secret_key: &SecretKey,
) -> Result<SignedPaymentProfile, SatsPathError> {
    // Verify the rotation first
    if !verify_key_rotation(rotation)? {
        return Err(SatsPathError::InvalidSignature);
    }

    // Verify the new pubkey matches the rotation
    if rotation.new_pubkey
        != hex::encode(PublicKey::from_secret_key(&Secp256k1::new(), new_secret_key).serialize())
    {
        return Err(SatsPathError::InvalidSignature);
    }

    // Create new profile with rotated key
    let mut new_profile = profile.profile.clone();
    new_profile.identity_pubkey = rotation.new_pubkey.clone();
    new_profile.sequence = Some(profile.profile.sequence.unwrap_or(0) + 1);
    new_profile.rotation = Some(rotation.clone());
    new_profile.updated_at = chrono::Utc::now().timestamp();
    new_profile.nonce = Some(crypto::generate_nonce());

    // Sign with new secret key
    let signed = satspath_core::crypto::sign_profile(new_profile, new_secret_key)
        .map_err(|_e| SatsPathError::InvalidSignature)?;

    Ok(signed)
}

/// Check if a profile's key rotation is valid
pub fn is_rotation_valid(profile: &SignedPaymentProfile) -> bool {
    if let Some(rotation) = &profile.profile.rotation {
        rotation.verify().unwrap_or(false)
    } else {
        false
    }
}

/// Get the current effective identity key for a profile
/// Returns the rotated key if a valid rotation exists, otherwise the original
pub fn get_effective_identity_pubkey(profile: &SignedPaymentProfile) -> String {
    if let Some(rotation) = &profile.profile.rotation {
        if rotation.verify().unwrap_or(false) {
            return rotation.new_pubkey.clone();
        }
    }
    profile.profile.identity_pubkey.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use satspath_core::crypto::{generate_identity_keypair, sign_profile};
    use satspath_core::{PaymentMethod, PaymentProfile};

    fn make_profile(methods: Vec<PaymentMethod>) -> (SignedPaymentProfile, secp256k1::SecretKey) {
        let kp = generate_identity_keypair();
        let pubkey_hex = hex::encode(kp.public_key.serialize());
        let profile = PaymentProfile {
            alias: "test@example.com".into(),
            identity_pubkey: pubkey_hex,
            methods,
            updated_at: 1_700_000_000,
            expires_at: None,
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
        let signed = sign_profile(profile, &kp.secret_key).unwrap();
        (signed, kp.secret_key)
    }

    #[test]
    fn test_key_rotation_creation() {
        let (profile, old_sk) = make_profile(vec![]);
        let new_kp = generate_identity_keypair();

        let rotation = rotate_identity_key(&profile, &old_sk, &new_kp.secret_key, "11aa").unwrap();

        assert_eq!(rotation.previous_pubkey, profile.profile.identity_pubkey);
        assert_eq!(
            rotation.new_pubkey,
            hex::encode(new_kp.public_key.serialize())
        );
        assert!(rotation.verify().unwrap());
    }

    #[test]
    fn test_key_rotation_application() {
        let (profile, old_sk) = make_profile(vec![]);
        let new_kp = generate_identity_keypair();

        let rotation = rotate_identity_key(&profile, &old_sk, &new_kp.secret_key, "11aa").unwrap();

        let new_profile = apply_key_rotation(&profile, &rotation, &new_kp.secret_key).unwrap();

        assert_eq!(new_profile.profile.identity_pubkey, rotation.new_pubkey);
        assert_eq!(new_profile.profile.sequence, Some(1));
        assert!(new_profile.profile.rotation.is_some());
    }

    #[test]
    fn test_invalid_rotation_rejected() {
        let (profile, old_sk) = make_profile(vec![]);
        let new_kp = generate_identity_keypair();

        let rotation = rotate_identity_key(&profile, &old_sk, &new_kp.secret_key, "11aa").unwrap();

        // Try to apply with wrong secret key
        let wrong_kp = generate_identity_keypair();
        let result = apply_key_rotation(&profile, &rotation, &wrong_kp.secret_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_effective_identity_pubkey() {
        let (profile, old_sk) = make_profile(vec![]);
        let original = get_effective_identity_pubkey(&profile);
        assert_eq!(original, profile.profile.identity_pubkey);

        let new_kp = generate_identity_keypair();
        let rotation = rotate_identity_key(&profile, &old_sk, &new_kp.secret_key, "11aa").unwrap();

        let rotated_profile = apply_key_rotation(&profile, &rotation, &new_kp.secret_key).unwrap();
        let effective = get_effective_identity_pubkey(&rotated_profile);
        assert_eq!(effective, rotation.new_pubkey);
    }
}
