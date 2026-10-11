use crate::fees::FeeEstimate;
use satspath_core::{SatsPathError, SignedPaymentProfile, SplitPaymentRequest};

/// Split Payment Route - represents a single payment within a split
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitPaymentRoute {
    /// The recipient alias
    pub recipient_alias: String,
    /// The percentage of the total amount
    pub percent: u8,
    /// The amount in satoshis for this split
    pub amount_sats: u64,
    /// The selected route for this split
    pub route: crate::RouteQuote,
}

/// Split Payment Routing Request
#[derive(Debug, Clone)]
pub struct SplitPaymentRoutingRequest {
    /// The split payment request
    pub split_request: SplitPaymentRequest,
    /// Map of recipient aliases to their signed profiles
    pub recipient_profiles: std::collections::HashMap<String, SignedPaymentProfile>,
    /// Fee estimate for routing decisions
    pub fee_estimate: FeeEstimate,
    /// Urgency for routing
    pub urgency: crate::urgency::PaymentUrgency,
}

/// Result of Split Payment routing
#[derive(Debug, Clone)]
pub struct SplitPaymentRoutingResult {
    /// Individual routes for each split
    pub routes: Vec<SplitPaymentRoute>,
    /// Total estimated fee
    pub total_fee_sats: u64,
    /// Whether all splits could be routed
    pub all_routed: bool,
    /// Errors for any failed splits
    pub errors: Vec<String>,
}

/// Route a Split Payment Request
///
/// This takes a SplitPaymentRequest and routes each split independently
/// based on the recipient's payment profile and preferences.
pub async fn route_split_payment(
    request: SplitPaymentRoutingRequest,
) -> Result<SplitPaymentRoutingResult, SatsPathError> {
    let mut routes = Vec::new();
    let mut total_fee_sats = 0u64;
    let mut errors = Vec::new();
    let mut all_routed = true;

    for split in &request.split_request.splits {
        let recipient_alias = &split.alias;

        // Get the recipient's profile
        let recipient_profile = match request.recipient_profiles.get(recipient_alias) {
            Some(profile) => profile,
            None => {
                let err = format!("No profile found for recipient: {}", recipient_alias);
                errors.push(err.clone());
                all_routed = false;
                continue;
            }
        };

        let amount_sats = request.split_request.total_amount_sats * u64::from(split.percent) / 100;

        // Create a route request for this split
        let route_request = crate::RouteRequest {
            alias: recipient_alias.clone(),
            amount_sats,
            signed_profile: recipient_profile.clone(),
            urgency: request.urgency,
            max_fee_sats: None,
            max_fee_percent: None,
        };

        // Route this split
        match crate::select_route(&route_request).await {
            Ok(route) => {
                total_fee_sats =
                    total_fee_sats.saturating_add(route.estimated_fee_sats.unwrap_or(0));
                routes.push(SplitPaymentRoute {
                    recipient_alias: recipient_alias.clone(),
                    percent: split.percent,
                    amount_sats,
                    route,
                });
            }
            Err(e) => {
                let err = format!("Failed to route split for {}: {}", recipient_alias, e);
                errors.push(err);
                all_routed = false;
            }
        }
    }

    Ok(SplitPaymentRoutingResult {
        routes,
        total_fee_sats,
        all_routed,
        errors,
    })
}

/// Validate a split payment request
pub fn validate_split_request(request: &SplitPaymentRequest) -> Result<(), SatsPathError> {
    request.validate()
}

/// Calculate individual amounts from a split request
pub fn calculate_split_amounts(request: &SplitPaymentRequest) -> Vec<(String, u64)> {
    request
        .amounts()
        .into_iter()
        .map(|(alias, amount)| (alias.to_string(), amount))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use satspath_core::{
        crypto::{generate_identity_keypair, sign_profile},
        PaymentMethod, PaymentProfile, SplitRecipient,
    };

    #[allow(dead_code)]
    fn signed_profile(methods: Vec<PaymentMethod>) -> SignedPaymentProfile {
        let kp = generate_identity_keypair();
        let pubkey_hex = hex::encode(kp.public_key.serialize());
        let profile = PaymentProfile {
            alias: "test@example.com".into(),
            identity_pubkey: pubkey_hex,
            methods,
            updated_at: 1,
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
        sign_profile(profile, &kp.secret_key).unwrap()
    }

    #[test]
    fn test_split_payment_validation() {
        let request = SplitPaymentRequest {
            version: 1,
            total_amount_sats: 100_000,
            splits: vec![
                SplitRecipient {
                    alias: "alice@example.com".into(),
                    percent: 50,
                },
                SplitRecipient {
                    alias: "bob@example.com".into(),
                    percent: 50,
                },
            ],
            memo: Some("Split payment test".into()),
        };

        assert!(validate_split_request(&request).is_ok());
    }

    #[test]
    fn test_split_payment_validation_fails_on_invalid_percent() {
        let request = SplitPaymentRequest {
            version: 1,
            total_amount_sats: 100_000,
            splits: vec![
                SplitRecipient {
                    alias: "alice@example.com".into(),
                    percent: 60,
                },
                SplitRecipient {
                    alias: "bob@example.com".into(),
                    percent: 30,
                },
            ],
            memo: None,
        };

        assert!(validate_split_request(&request).is_err());
    }

    #[test]
    fn test_split_amounts() {
        let request = SplitPaymentRequest {
            version: 1,
            total_amount_sats: 100_000,
            splits: vec![
                SplitRecipient {
                    alias: "alice@example.com".into(),
                    percent: 50,
                },
                SplitRecipient {
                    alias: "bob@example.com".into(),
                    percent: 30,
                },
                SplitRecipient {
                    alias: "carol@example.com".into(),
                    percent: 20,
                },
            ],
            memo: None,
        };

        let amounts = calculate_split_amounts(&request);
        assert_eq!(amounts.len(), 3);
        assert_eq!(amounts[0].1, 50_000);
        assert_eq!(amounts[1].1, 30_000);
        assert_eq!(amounts[2].1, 20_000);
    }
}
