use serde::{Deserialize, Serialize};

use crate::crypto::{sign_message, verify_message_signature};
use crate::validation::validate_compressed_pubkey;
use crate::{Result, SatsPathError, SignedPaymentProfile};

pub const RECOVERY_AUTHORIZATION_DOMAIN: &str = "SatsPathKeyRecoveryAuthorizationV1";
pub const RECOVERY_ACCEPTANCE_DOMAIN: &str = "SatsPathKeyRecoveryAcceptanceV1";

const fn default_recovery_version() -> u16 {
    1
}

/// A pre-committed recovery policy defining an M-of-N threshold of guardian public keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecoveryPolicy {
    #[serde(default = "default_recovery_version")]
    pub version: u16,
    /// Minimum number of guardian signatures required (M)
    pub threshold: u8,
    /// List of distinct compressed secp256k1 public keys of authorized guardians (N)
    pub guardians: Vec<String>,
}

impl RecoveryPolicy {
    /// Create and validate a new RecoveryPolicy.
    pub fn new(threshold: u8, guardians: Vec<String>) -> Result<Self> {
        let policy = Self {
            version: 1,
            threshold,
            guardians,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Validate the policy parameters (version, threshold, guardian keys, uniqueness).
    pub fn validate(&self) -> Result<()> {
        if self.version != 1 {
            return Err(SatsPathError::ValidationError(
                "unsupported recovery policy version".into(),
            ));
        }
        if self.threshold == 0 {
            return Err(SatsPathError::ValidationError(
                "recovery threshold must be at least 1".into(),
            ));
        }
        if (self.threshold as usize) > self.guardians.len() {
            return Err(SatsPathError::ValidationError(format!(
                "recovery threshold {} exceeds number of guardians {}",
                self.threshold,
                self.guardians.len()
            )));
        }
        if self.guardians.len() > 32 {
            return Err(SatsPathError::ValidationError(
                "cannot exceed 32 guardians in recovery policy".into(),
            ));
        }
        let mut distinct = std::collections::HashSet::new();
        for g in &self.guardians {
            validate_compressed_pubkey(g).map_err(|e| {
                SatsPathError::ValidationError(format!("invalid guardian pubkey: {e}"))
            })?;
            // BIP-340 verifies against x-only keys: 02X and 03X represent the same signer.
            if !distinct.insert(g[2..].to_ascii_lowercase()) {
                return Err(SatsPathError::ValidationError(format!(
                    "duplicate guardian pubkey in recovery policy: {g}"
                )));
            }
        }
        Ok(())
    }
}

/// A signature from an authorized guardian approving a key recovery.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardianSignature {
    /// Compressed secp256k1 public key of the guardian.
    pub guardian_pubkey: String,
    /// Hex-encoded Schnorr signature.
    pub signature: String,
}

/// A cryptographic proof of key recovery authorized by threshold guardians.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KeyRecoveryProof {
    #[serde(default = "default_recovery_version")]
    pub version: u16,
    pub identifier_hash: String,
    pub previous_pubkey: String,
    pub new_pubkey: String,
    pub previous_event_hash: String,
    pub sequence: u64,
    pub guardian_signatures: Vec<GuardianSignature>,
    pub acceptance_signature: String,
    pub recovered_at: i64,
}

impl KeyRecoveryProof {
    /// Construct a new KeyRecoveryProof, signing acceptance with the new identity secret key.
    #[allow(clippy::too_many_arguments)]
    pub fn create(
        identifier_hash: String,
        previous_pubkey: String,
        new_pubkey: String,
        new_secret_key: &secp256k1::SecretKey,
        previous_event_hash: String,
        sequence: u64,
        recovered_at: i64,
        guardian_signatures: Vec<GuardianSignature>,
    ) -> Result<Self> {
        let acceptance_message = recovery_message(
            RECOVERY_ACCEPTANCE_DOMAIN,
            &identifier_hash,
            &previous_pubkey,
            &new_pubkey,
            &previous_event_hash,
            sequence,
            recovered_at,
        );
        let acceptance_signature = sign_message(&acceptance_message, new_secret_key);
        Ok(Self {
            version: 1,
            identifier_hash,
            previous_pubkey,
            new_pubkey,
            previous_event_hash,
            sequence,
            guardian_signatures,
            acceptance_signature,
            recovered_at,
        })
    }

    /// Verify the acceptance signature and ensure threshold guardian signatures are valid and distinct.
    pub fn verify(&self, policy: &RecoveryPolicy) -> Result<bool> {
        policy.validate()?;
        if self.version != 1
            || self.identifier_hash.is_empty()
            || self.previous_event_hash.is_empty()
            || self.sequence == 0
            || self.acceptance_signature.is_empty()
        {
            return Ok(false);
        }

        // Verify acceptance by the new identity key
        let acceptance_message = recovery_message(
            RECOVERY_ACCEPTANCE_DOMAIN,
            &self.identifier_hash,
            &self.previous_pubkey,
            &self.new_pubkey,
            &self.previous_event_hash,
            self.sequence,
            self.recovered_at,
        );
        if !verify_message_signature(
            &acceptance_message,
            &self.acceptance_signature,
            &self.new_pubkey,
        )? {
            return Ok(false);
        }

        // Verify threshold guardian signatures
        let auth_message = recovery_message(
            RECOVERY_AUTHORIZATION_DOMAIN,
            &self.identifier_hash,
            &self.previous_pubkey,
            &self.new_pubkey,
            &self.previous_event_hash,
            self.sequence,
            self.recovered_at,
        );

        let allowed_guardians: std::collections::HashSet<String> = policy
            .guardians
            .iter()
            .map(|g| g[2..].to_ascii_lowercase())
            .collect();

        let mut seen_guardians = std::collections::HashSet::new();
        for sig in &self.guardian_signatures {
            validate_compressed_pubkey(&sig.guardian_pubkey).map_err(|e| {
                SatsPathError::ValidationError(format!("invalid guardian pubkey: {e}"))
            })?;
            let x_only = sig.guardian_pubkey[2..].to_ascii_lowercase();
            if !allowed_guardians.contains(&x_only) {
                return Ok(false);
            }
            if !seen_guardians.insert(x_only) {
                // Duplicate signature from the same guardian
                return Ok(false);
            }
            if !verify_message_signature(&auth_message, &sig.signature, &sig.guardian_pubkey)? {
                return Ok(false);
            }
        }

        Ok(seen_guardians.len() >= policy.threshold as usize)
    }
}

/// Canonical message format for recovery authorization and acceptance.
pub fn recovery_message(
    domain: &str,
    identifier_hash: &str,
    old_pubkey: &str,
    new_pubkey: &str,
    previous_event_hash: &str,
    sequence: u64,
    recovered_at: i64,
) -> String {
    format!(
        "{domain}\n{identifier_hash}\n{old_pubkey}\n{new_pubkey}\n{previous_event_hash}\n{sequence}\n{recovered_at}"
    )
}

/// Helper for a guardian to sign recovery authorization using their private key.
pub fn sign_guardian_authorization(
    identifier_hash: &str,
    old_pubkey: &str,
    new_pubkey: &str,
    previous_event_hash: &str,
    sequence: u64,
    recovered_at: i64,
    guardian_secret: &secp256k1::SecretKey,
) -> GuardianSignature {
    let secp = secp256k1::Secp256k1::new();
    let guardian_pubkey =
        hex::encode(secp256k1::PublicKey::from_secret_key(&secp, guardian_secret).serialize());
    let msg = recovery_message(
        RECOVERY_AUTHORIZATION_DOMAIN,
        identifier_hash,
        old_pubkey,
        new_pubkey,
        previous_event_hash,
        sequence,
        recovered_at,
    );
    let signature = sign_message(&msg, guardian_secret);
    GuardianSignature {
        guardian_pubkey,
        signature,
    }
}

/// Apply a key recovery to a signed payment profile.
/// Creates a new profile with the new identity pubkey and sets the recovery proof.
pub fn recover_identity_key(
    profile: &SignedPaymentProfile,
    new_pubkey_hex: String,
    new_secret_key: &secp256k1::SecretKey,
    previous_event_hash: &str,
    sequence: u64,
    recovered_at: i64,
    guardian_signatures: Vec<GuardianSignature>,
) -> Result<SignedPaymentProfile> {
    let next_sequence = profile.profile.sequence.unwrap_or(0).saturating_add(1);
    if sequence != next_sequence {
        return Err(SatsPathError::ValidationError(
            "recovery sequence must equal canonical next sequence".into(),
        ));
    }
    let policy = profile.profile.recovery_policy.as_ref().ok_or_else(|| {
        SatsPathError::ValidationError("profile has no committed recovery policy".into())
    })?;

    let recovery = KeyRecoveryProof::create(
        crate::privacy::identifier_hash(&profile.profile.alias),
        profile.profile.identity_pubkey.clone(),
        new_pubkey_hex.clone(),
        new_secret_key,
        previous_event_hash.to_owned(),
        sequence,
        recovered_at,
        guardian_signatures,
    )?;

    if !recovery.verify(policy)? {
        return Err(SatsPathError::ValidationError(
            "recovery proof failed verification against recovery policy".into(),
        ));
    }

    let mut new_profile = profile.profile.clone();
    new_profile.identity_pubkey = new_pubkey_hex;
    new_profile.recovery = Some(recovery);
    new_profile.sequence = Some(sequence);
    let now = chrono::Utc::now().timestamp();
    new_profile.updated_at = now.max(profile.profile.updated_at);
    new_profile.expires_at = Some(new_profile.updated_at + 30 * 24 * 3600);
    new_profile.nonce = Some(crate::crypto::generate_nonce());
    new_profile.rotation = None;
    new_profile.method_verifications.clear();
    new_profile.hybrid_pubkey = None;
    new_profile.pqc_required = false;
    // Profile signature is cleared; caller must sign with new_secret_key
    Ok(SignedPaymentProfile {
        profile: new_profile,
        signature: String::new(),
        hybrid_signature: None,
    })
}

/// Verify key recovery between an old profile and a recovered new profile.
pub fn verify_key_recovery(
    old_profile: &SignedPaymentProfile,
    new_profile: &SignedPaymentProfile,
) -> Result<bool> {
    let policy = match &old_profile.profile.recovery_policy {
        Some(p) => p,
        None => return Ok(false),
    };
    if let Some(recovery) = &new_profile.profile.recovery {
        if new_profile.profile.rotation.is_some() {
            return Ok(false);
        }
        if recovery.previous_pubkey != old_profile.profile.identity_pubkey {
            return Ok(false);
        }
        if recovery.new_pubkey != new_profile.profile.identity_pubkey {
            return Ok(false);
        }
        if recovery.identifier_hash != crate::privacy::identifier_hash(&old_profile.profile.alias)
            || new_profile.profile.alias != old_profile.profile.alias
            || recovery.sequence != new_profile.profile.sequence.unwrap_or(0)
            || recovery.sequence != old_profile.profile.sequence.unwrap_or(0).saturating_add(1)
        {
            return Ok(false);
        }
        Ok(recovery.verify(policy)? && crate::crypto::verify_signed_profile(new_profile)?)
    } else {
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_identity_keypair, sign_profile};
    use crate::PaymentProfile;

    #[test]
    fn test_recovery_policy_validation() {
        let g1 = generate_identity_keypair();
        let g2 = generate_identity_keypair();
        let p1 = hex::encode(g1.public_key.serialize());
        let p2 = hex::encode(g2.public_key.serialize());

        // Valid 2-of-2 policy
        let policy = RecoveryPolicy::new(2, vec![p1.clone(), p2.clone()]).unwrap();
        assert_eq!(policy.threshold, 2);

        // Threshold 0 invalid
        assert!(RecoveryPolicy::new(0, vec![p1.clone()]).is_err());

        // Threshold exceeds count
        assert!(RecoveryPolicy::new(3, vec![p1.clone(), p2.clone()]).is_err());

        // Duplicate guardians invalid
        assert!(RecoveryPolicy::new(1, vec![p1.clone(), p1.clone()]).is_err());

        // Invalid pubkey hex
        assert!(RecoveryPolicy::new(1, vec!["not_a_pubkey".into()]).is_err());
    }

    #[test]
    fn test_threshold_key_recovery_success() {
        let id_old = generate_identity_keypair();
        let id_new = generate_identity_keypair();
        let g1 = generate_identity_keypair();
        let g2 = generate_identity_keypair();
        let g3 = generate_identity_keypair();

        let old_pk = hex::encode(id_old.public_key.serialize());
        let new_pk = hex::encode(id_new.public_key.serialize());
        let p1 = hex::encode(g1.public_key.serialize());
        let p2 = hex::encode(g2.public_key.serialize());
        let p3 = hex::encode(g3.public_key.serialize());

        // 2-of-3 policy
        let policy = RecoveryPolicy::new(2, vec![p1, p2, p3]).unwrap();

        let profile = PaymentProfile {
            alias: "alice@example.com".into(),
            identity_pubkey: old_pk.clone(),
            methods: vec![],
            updated_at: 1000,
            expires_at: None,
            sequence: Some(1),
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: vec![],
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
            recovery_policy: Some(policy.clone()),
            recovery: None,
        };
        let signed_old = sign_profile(profile, &id_old.secret_key).unwrap();

        let ident_hash = crate::privacy::identifier_hash("alice@example.com");
        let prev_event_hash = "prev_event_hash_12345".to_string();
        let seq = 2;
        let now = chrono::Utc::now().timestamp();

        // 2 guardians sign
        let sig1 = sign_guardian_authorization(
            &ident_hash,
            &old_pk,
            &new_pk,
            &prev_event_hash,
            seq,
            now,
            &g1.secret_key,
        );
        let sig2 = sign_guardian_authorization(
            &ident_hash,
            &old_pk,
            &new_pk,
            &prev_event_hash,
            seq,
            now,
            &g2.secret_key,
        );

        let proof = KeyRecoveryProof::create(
            ident_hash,
            old_pk,
            new_pk.clone(),
            &id_new.secret_key,
            prev_event_hash.clone(),
            seq,
            now,
            vec![sig1, sig2],
        )
        .unwrap();

        assert!(proof.verify(&policy).unwrap());

        // Test recover_identity_key helper
        let unsigned_new = recover_identity_key(
            &signed_old,
            new_pk,
            &id_new.secret_key,
            &prev_event_hash,
            seq,
            now,
            proof.guardian_signatures.clone(),
        )
        .unwrap();
        let signed_new = sign_profile(unsigned_new.profile, &id_new.secret_key).unwrap();
        assert!(verify_key_recovery(&signed_old, &signed_new).unwrap());
    }

    #[test]
    fn test_threshold_key_recovery_insufficient_or_unauthorized_guardians() {
        let id_old = generate_identity_keypair();
        let id_new = generate_identity_keypair();
        let g1 = generate_identity_keypair();
        let g2 = generate_identity_keypair();
        let outsider = generate_identity_keypair();

        let old_pk = hex::encode(id_old.public_key.serialize());
        let new_pk = hex::encode(id_new.public_key.serialize());
        let p1 = hex::encode(g1.public_key.serialize());
        let p2 = hex::encode(g2.public_key.serialize());

        // 2-of-2 policy
        let policy = RecoveryPolicy::new(2, vec![p1, p2]).unwrap();
        let ident_hash = crate::privacy::identifier_hash("alice@example.com");
        let prev_event_hash = "prev_hash".to_string();
        let seq = 2;
        let now = chrono::Utc::now().timestamp();

        let sig1 = sign_guardian_authorization(
            &ident_hash,
            &old_pk,
            &new_pk,
            &prev_event_hash,
            seq,
            now,
            &g1.secret_key,
        );

        // Insufficient: only 1 signature when 2 required
        let proof_insufficient = KeyRecoveryProof::create(
            ident_hash.clone(),
            old_pk.clone(),
            new_pk.clone(),
            &id_new.secret_key,
            prev_event_hash.clone(),
            seq,
            now,
            vec![sig1.clone()],
        )
        .unwrap();
        assert!(!proof_insufficient.verify(&policy).unwrap());

        // Duplicate signature from g1 should not count as 2
        let proof_duplicate = KeyRecoveryProof::create(
            ident_hash.clone(),
            old_pk.clone(),
            new_pk.clone(),
            &id_new.secret_key,
            prev_event_hash.clone(),
            seq,
            now,
            vec![sig1.clone(), sig1.clone()],
        )
        .unwrap();
        assert!(!proof_duplicate.verify(&policy).unwrap());

        // Unauthorized outsider signature
        let sig_outsider = sign_guardian_authorization(
            &ident_hash,
            &old_pk,
            &new_pk,
            &prev_event_hash,
            seq,
            now,
            &outsider.secret_key,
        );
        let proof_outsider = KeyRecoveryProof::create(
            ident_hash,
            old_pk,
            new_pk,
            &id_new.secret_key,
            prev_event_hash,
            seq,
            now,
            vec![sig1, sig_outsider],
        )
        .unwrap();
        assert!(!proof_outsider.verify(&policy).unwrap());
    }

    #[test]
    fn guardian_policy_and_proof_reject_opposite_parity_encodings_of_same_key() {
        let g1 = generate_identity_keypair();
        let g1_even = hex::encode(g1.public_key.serialize());
        // Invert prefix between 02 and 03
        let alt_prefix = if g1_even.starts_with("02") {
            "03"
        } else {
            "02"
        };
        let g1_odd = format!("{alt_prefix}{}", &g1_even[2..]);

        // Policy cannot include both 02X and 03X
        let policy_err = RecoveryPolicy::new(2, vec![g1_even.clone(), g1_odd.clone()]);
        assert!(policy_err.is_err());
    }
}
