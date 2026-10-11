use satspath_core::{PaymentMethod, PaymentPointer, Result, SatsPathError, SignedPaymentProfile};

use crate::ark_routes::SenderCapabilities;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentRail {
    Lightning,
    Onchain,
    Ark,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteCandidate {
    pub rail: PaymentRail,
    pub estimated_fee_sats: Option<u64>,
    pub estimated_time_seconds: Option<u64>,
    pub privacy_score: u8,
    pub reliability_score: u8,
    pub requires_user_action: bool,
    pub available: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FeeSnapshot {
    pub lightning_fee_sats_estimate: Option<u64>,
    pub onchain_fastest_sat_vb: Option<u64>,
    pub onchain_half_hour_sat_vb: Option<u64>,
    pub onchain_hour_sat_vb: Option<u64>,
    pub ark_fee_sats_estimate: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePreferences {
    pub prefer_low_fee: bool,
    pub prefer_speed: bool,
    pub prefer_privacy: bool,
    pub allow_experimental_ark: bool,
    pub max_fee_sats: Option<u64>,
    pub sender_capabilities: SenderCapabilities,
}

impl Default for RoutePreferences {
    fn default() -> Self {
        Self {
            prefer_low_fee: true,
            prefer_speed: true,
            prefer_privacy: false,
            allow_experimental_ark: false,
            max_fee_sats: None,
            sender_capabilities: SenderCapabilities::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    pub selected: RouteCandidate,
    pub alternatives: Vec<RouteCandidate>,
    pub payment_pointer: PaymentPointer,
    pub explanation: String,
}

pub fn score_routes(
    amount_sats: u64,
    profile: &SignedPaymentProfile,
    fee_snapshot: &FeeSnapshot,
    preferences: &RoutePreferences,
) -> Result<RouteDecision> {
    let mut candidates = Vec::new();
    let mut pointers = Vec::new();

    for method in &profile.profile.methods {
        match method {
            PaymentMethod::Lightning {
                lightning_address,
                lnurl,
                bolt12,
                receiver_pubkey,
                ..
            } => {
                let fee = fee_snapshot
                    .lightning_fee_sats_estimate
                    .unwrap_or_else(|| std::cmp::max(1, amount_sats / 10_000));
                let available = lightning_address.is_some() || lnurl.is_some() || bolt12.is_some();
                let mut privacy_score = 7;
                let pointer = if let Some(address) = lightning_address {
                    PaymentPointer::LightningAddress {
                        address: address.clone(),
                        receiver_pubkey: receiver_pubkey.clone(),
                    }
                } else if let Some(callback_url) = lnurl {
                    PaymentPointer::LnurlPay {
                        callback_url: callback_url.clone(),
                        receiver_pubkey: receiver_pubkey.clone(),
                    }
                } else if let Some(invoice) = bolt11_like(bolt12.as_deref()) {
                    PaymentPointer::Bolt11Invoice {
                        invoice: invoice.to_string(),
                        amount_sats: Some(amount_sats),
                    }
                } else if let Some(offer_str) = bolt12.as_deref() {
                    let parsed = crate::bolt12::parse_bolt12_offer(offer_str).ok();
                    let has_blinded = parsed
                        .as_ref()
                        .map(|o| o.has_blinded_paths())
                        .unwrap_or(false);
                    if has_blinded {
                        privacy_score = 9;
                    } else {
                        privacy_score = 8;
                    }
                    PaymentPointer::Bolt12Offer {
                        offer: offer_str.to_string(),
                    }
                } else {
                    continue;
                };
                candidates.push(RouteCandidate {
                    rail: PaymentRail::Lightning,
                    estimated_fee_sats: Some(fee),
                    estimated_time_seconds: Some(5),
                    privacy_score,
                    reliability_score: 8,
                    requires_user_action: true,
                    available,
                    reason: "Lightning available for low-latency payment pointer.".into(),
                });
                pointers.push(pointer);
            }
            PaymentMethod::Onchain {
                network,
                address,
                silent_payment_pubkey,
                descriptor_hint,
                ..
            } => {
                let sats_per_vb = fee_snapshot
                    .onchain_fastest_sat_vb
                    .or(fee_snapshot.onchain_half_hour_sat_vb)
                    .or(fee_snapshot.onchain_hour_sat_vb);
                let fee = sats_per_vb.map(|rate| rate * 141);
                let dust = amount_sats < 546;
                let policy_complexity = policy_complexity_hint(descriptor_hint.as_deref());
                candidates.push(RouteCandidate {
                    rail: PaymentRail::Onchain,
                    estimated_fee_sats: fee,
                    estimated_time_seconds: Some(600),
                    privacy_score: 4,
                    reliability_score: 10u8.saturating_sub(policy_complexity),
                    requires_user_action: true,
                    available: !dust && fee.is_some(),
                    reason: if dust {
                        "Amount is dust/economically irrational for on-chain output.".into()
                    } else if policy_complexity > 1 {
                        "On-chain address available with public policy complexity hint.".into()
                    } else {
                        "On-chain address available; fee depends on mempool.".into()
                    },
                });
                pointers.push(PaymentPointer::OnchainAddress {
                    network: *network,
                    address: silent_payment_pubkey
                        .clone()
                        .unwrap_or_else(|| address.clone().unwrap_or_default()),
                    claim_policy: None,
                });
            }
            PaymentMethod::Bolt12(offer_data) => {
                let fee = fee_snapshot
                    .lightning_fee_sats_estimate
                    .unwrap_or_else(|| std::cmp::max(1, amount_sats / 10_000));
                let parsed = crate::bolt12::parse_bolt12_offer(&offer_data.offer).ok();
                let has_blinded = parsed
                    .as_ref()
                    .map(|o| o.has_blinded_paths())
                    .unwrap_or(false);
                let privacy_score = if has_blinded { 9 } else { 8 };
                candidates.push(RouteCandidate {
                    rail: PaymentRail::Lightning,
                    estimated_fee_sats: Some(fee),
                    estimated_time_seconds: Some(2),
                    privacy_score,
                    reliability_score: 9,
                    requires_user_action: true,
                    available: true,
                    reason: "BOLT12 offer available for Lightning payment.".into(),
                });
                pointers.push(PaymentPointer::Bolt12Offer {
                    offer: offer_data.offer.clone(),
                });
            }
            PaymentMethod::Ark {
                server,
                pubkey,
                vtxo_pointer,
                ..
            } => {
                let available = preferences.allow_experimental_ark;
                let plan =
                    crate::ark_routes::plan_ark_route(&preferences.sender_capabilities, profile);
                candidates.push(RouteCandidate {
                    rail: PaymentRail::Ark,
                    estimated_fee_sats: fee_snapshot.ark_fee_sats_estimate.or(Some(1)),
                    estimated_time_seconds: Some(30),
                    privacy_score: 8,
                    reliability_score: if available { 5 } else { 2 },
                    requires_user_action: true,
                    available,
                    reason: if let Some(plan) = plan {
                        format!("{} Ark routes remain testnet-gated.", plan.reason)
                    } else if available {
                        "Ark pointer available; no executable sender path declared; intent preview only."
                            .into()
                    } else {
                        "Ark pointer available but experimental Ark is disabled.".into()
                    },
                });
                pointers.push(PaymentPointer::Ark {
                    server: server.clone(),
                    receiver_pubkey: pubkey.clone(),
                    vtxo_pointer: vtxo_pointer.clone(),
                });
            }
        }
    }

    let selected_index = candidates
        .iter()
        .enumerate()
        .filter(|(_, c)| c.available)
        .filter(|(_, c)| {
            preferences
                .max_fee_sats
                .map(|max| c.estimated_fee_sats.unwrap_or(u64::MAX) <= max)
                .unwrap_or(true)
        })
        .max_by_key(|(_, c)| {
            candidate_score(c, preferences, amount_sats, &profile.profile.preferences)
        })
        .map(|(idx, _)| idx)
        .ok_or_else(|| SatsPathError::NoRouteFound("no available scored route".into()))?;

    let selected = candidates[selected_index].clone();
    let payment_pointer = pointers[selected_index].clone();
    let alternatives = candidates
        .into_iter()
        .enumerate()
        .filter_map(|(idx, candidate)| (idx != selected_index).then_some(candidate))
        .collect();
    let explanation = format!(
        "Selected {:?}: {} Fee: {:?}, ETA: {:?}.",
        selected.rail,
        selected.reason,
        selected.estimated_fee_sats,
        selected.estimated_time_seconds
    );

    Ok(RouteDecision {
        selected,
        alternatives,
        payment_pointer,
        explanation,
    })
}

fn candidate_score(
    candidate: &RouteCandidate,
    preferences: &RoutePreferences,
    amount_sats: u64,
    profile_preferences: &[String],
) -> i64 {
    let mut score = 0i64;
    score += i64::from(candidate.reliability_score) * 10;
    score += i64::from(candidate.privacy_score) * if preferences.prefer_privacy { 8 } else { 2 };
    if preferences.prefer_speed {
        score -= candidate.estimated_time_seconds.unwrap_or(3_600) as i64 / 30;
    }
    if preferences.prefer_low_fee {
        score -= candidate.estimated_fee_sats.unwrap_or(10_000) as i64 / 10;
    }
    if candidate.rail == PaymentRail::Lightning && amount_sats <= 1_000_000 {
        score += 30;
    }
    if candidate.rail == PaymentRail::Onchain && amount_sats >= 1_000_000 {
        score += 20;
    }
    if candidate.rail == PaymentRail::Ark && !preferences.allow_experimental_ark {
        score -= 1_000;
    }

    // Apply profile preference bonus (WS-3)
    let rail_name = match candidate.rail {
        PaymentRail::Lightning => "lightning",
        PaymentRail::Onchain => "onchain",
        PaymentRail::Ark => "ark",
    };
    if let Some(pos) = profile_preferences.iter().position(|p| p == rail_name) {
        // High bonus for 1st preference (50), tapering off for subsequent ones
        score += 50i64.saturating_sub(pos as i64 * 10);
    }

    score
}

fn bolt11_like(value: Option<&str>) -> Option<&str> {
    value.filter(|invoice| invoice.starts_with("lnbc") || invoice.starts_with("lntb"))
}

fn policy_complexity_hint(descriptor_hint: Option<&str>) -> u8 {
    let Some(hint) = descriptor_hint else {
        return 1;
    };
    let lower = hint.to_ascii_lowercase();
    if lower.contains("multi") {
        3
    } else if lower.contains("tr(") || lower.contains("taproot") {
        2
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use satspath_core::{
        crypto::{generate_identity_keypair, sign_profile},
        BitcoinNetwork, PaymentProfile,
    };

    fn signed(methods: Vec<PaymentMethod>) -> SignedPaymentProfile {
        let kp = generate_identity_keypair();
        let profile = PaymentProfile {
            alias: "alice@example.com".into(),
            identity_pubkey: hex::encode(kp.public_key.serialize()),
            methods,
            updated_at: 1,
            expires_at: None,
            sequence: None,
            preferences: vec!["lightning".into(), "ark".into(), "onchain".into()],
            nonce: Some(satspath_core::crypto::generate_nonce()),
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
    fn lightning_route_selected_for_small_amount() {
        let profile = signed(vec![PaymentMethod::Lightning {
            label: "LN".into(),
            lightning_address: Some("alice@example.com".into()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        }]);
        let decision = score_routes(
            1_000,
            &profile,
            &FeeSnapshot::default(),
            &RoutePreferences::default(),
        )
        .unwrap();
        assert_eq!(decision.selected.rail, PaymentRail::Lightning);
    }

    #[test]
    fn onchain_selected_when_large_and_fee_acceptable() {
        let profile = signed(vec![PaymentMethod::Onchain {
            label: "BTC".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some("1BoatSLRHtKNngkdXEeobR76b53LETtpyT".into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        }]);
        let fees = FeeSnapshot {
            onchain_fastest_sat_vb: Some(2),
            ..FeeSnapshot::default()
        };
        let decision =
            score_routes(2_000_000, &profile, &fees, &RoutePreferences::default()).unwrap();
        assert_eq!(decision.selected.rail, PaymentRail::Onchain);
    }

    #[test]
    fn onchain_policy_complexity_affects_reason() {
        let profile = signed(vec![PaymentMethod::Onchain {
            label: "BTC".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some("1BoatSLRHtKNngkdXEeobR76b53LETtpyT".into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: Some("wsh(sortedmulti(2,...))".into()),
            address_list: vec![],
        }]);
        let fees = FeeSnapshot {
            onchain_fastest_sat_vb: Some(2),
            ..FeeSnapshot::default()
        };
        let decision =
            score_routes(2_000_000, &profile, &fees, &RoutePreferences::default()).unwrap();
        assert!(decision.selected.reason.contains("policy complexity"));
    }

    #[test]
    fn ark_selected_only_when_allowed() {
        let valid_pubkey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
        let profile = signed(vec![PaymentMethod::Ark {
            label: "Ark".into(),
            server: "https://ark.example.com".into(),
            pubkey: valid_pubkey.into(),
            opaque_uri: None,
            vtxo_pointer: None,
            proof: None,
            expires_at: None,
        }]);
        assert!(score_routes(
            1_000,
            &profile,
            &FeeSnapshot::default(),
            &RoutePreferences::default()
        )
        .is_err());

        let preferences = RoutePreferences {
            allow_experimental_ark: true,
            ..RoutePreferences::default()
        };
        let decision =
            score_routes(1_000, &profile, &FeeSnapshot::default(), &preferences).unwrap();
        assert_eq!(decision.selected.rail, PaymentRail::Ark);
    }
}
