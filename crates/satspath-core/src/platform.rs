use crate::privacy::{identifier_hash, mask_identifier};
use crate::{Result, SatsPathError, SignedPaymentProfile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailChallenge {
    pub challenge_id: String,
    pub identifier_hash: String,
    pub expires_at: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentifier {
    pub identifier_hash: String,
    pub verified_at: i64,
}

/// Platform-layer inbox verifier.
///
/// Verification proves access to an inbox. It does not prove domain ownership,
/// transfer custody, or give SatsPath access to wallet keys.
pub trait EmailVerifier {
    fn create_challenge(&self, identifier: &str) -> Result<EmailChallenge>;
    fn verify_challenge(&self, token: &str) -> Result<VerifiedIdentifier>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishReceipt {
    pub profile_fingerprint: String,
    pub published_at: i64,
    pub location_hint: Option<String>,
}

pub trait ProfilePublisher {
    fn publish_profile(&self, profile: &SignedPaymentProfile) -> Result<PublishReceipt>;
}

/// Development-only mock. It proves nothing about the identifier, so the
/// `satspathd` daemon gates it behind an explicit operator opt-in and refuses
/// it when the daemon serves mainnet.
pub struct MockEmailVerifier {
    pub now: i64,
    pub ttl_seconds: i64,
}

impl EmailVerifier for MockEmailVerifier {
    fn create_challenge(&self, identifier: &str) -> Result<EmailChallenge> {
        Ok(EmailChallenge {
            challenge_id: format!("mock-{}", mask_identifier(identifier)),
            identifier_hash: identifier_hash(identifier),
            expires_at: self.now + self.ttl_seconds,
        })
    }

    fn verify_challenge(&self, token: &str) -> Result<VerifiedIdentifier> {
        if token.is_empty() || token.contains("seed") || token.contains("xprv") {
            return Err(SatsPathError::PrivateMaterialRejected(
                "invalid verification token".into(),
            ));
        }
        Ok(VerifiedIdentifier {
            identifier_hash: identifier_hash(token),
            verified_at: self.now,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn email_verification_creates_verified_identifier_not_keys() {
        let verifier = MockEmailVerifier {
            now: 1_700_000_000,
            ttl_seconds: 600,
        };
        let challenge = verifier.create_challenge("Alice@Gmail.com").unwrap();
        assert!(!challenge.identifier_hash.contains("Alice"));
        assert!(challenge.expires_at > verifier.now);

        let verified = verifier.verify_challenge("Alice@Gmail.com").unwrap();
        assert_eq!(verified.verified_at, verifier.now);
        assert!(!format!("{verified:?}").contains("private"));
    }
}
