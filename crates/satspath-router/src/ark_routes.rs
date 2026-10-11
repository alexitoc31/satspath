use satspath_core::{ArkRouteKind, PaymentMethod, SignedPaymentProfile};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArkRoutePlan {
    pub kind: ArkRouteKind,
    pub requires_swap: bool,
    pub requires_boltz: bool,
    pub requires_ark_bridge: bool,
    pub testnet_only: bool,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SenderCapabilities {
    pub ark_server: Option<String>,
    pub has_lightning: bool,
    pub has_onchain: bool,
}

pub fn plan_ark_route(
    sender: &SenderCapabilities,
    receiver: &SignedPaymentProfile,
) -> Option<ArkRoutePlan> {
    let receiver_ark = first_ark(receiver);
    let receiver_lightning = has_lightning(receiver);
    let receiver_onchain = has_onchain(receiver);

    if let (Some(sender_server), Some((receiver_server, _receiver_pubkey))) =
        (&sender.ark_server, receiver_ark)
    {
        if sender_server == receiver_server {
            return Some(ArkRoutePlan {
                kind: ArkRouteKind::ArkToArk,
                requires_swap: false,
                requires_boltz: false,
                requires_ark_bridge: true,
                testnet_only: true,
                reason: "Sender and receiver use the same Ark server; direct VTXO transfer intent."
                    .into(),
            });
        }
    }

    if sender.ark_server.is_some() && receiver_lightning {
        return Some(ArkRoutePlan {
            kind: ArkRouteKind::ArkToLightning,
            requires_swap: true,
            requires_boltz: true,
            requires_ark_bridge: true,
            testnet_only: true,
            reason: "Sender has Ark and receiver has Lightning; requires swap/offboard path."
                .into(),
        });
    }

    if sender.has_lightning && receiver_ark.is_some() {
        return Some(ArkRoutePlan {
            kind: ArkRouteKind::LightningToArk,
            requires_swap: true,
            requires_boltz: true,
            requires_ark_bridge: true,
            testnet_only: true,
            reason: "Sender has Lightning and receiver has Ark; requires onboard/reverse path."
                .into(),
        });
    }

    if sender.ark_server.is_some() && receiver_onchain {
        return Some(ArkRoutePlan {
            kind: ArkRouteKind::ArkToOnchain,
            requires_swap: true,
            requires_boltz: true,
            requires_ark_bridge: true,
            testnet_only: true,
            reason: "Sender has Ark and receiver has on-chain; requires offboard path.".into(),
        });
    }

    if sender.has_onchain && receiver_ark.is_some() {
        return Some(ArkRoutePlan {
            kind: ArkRouteKind::OnchainToArk,
            requires_swap: true,
            requires_boltz: true,
            requires_ark_bridge: true,
            testnet_only: true,
            reason: "Sender has on-chain and receiver has Ark; requires onboard path.".into(),
        });
    }

    None
}

fn first_ark(profile: &SignedPaymentProfile) -> Option<(&str, &str)> {
    profile
        .profile
        .methods
        .iter()
        .find_map(|method| match method {
            PaymentMethod::Ark { server, pubkey, .. } => Some((server.as_str(), pubkey.as_str())),
            _ => None,
        })
}

fn has_lightning(profile: &SignedPaymentProfile) -> bool {
    profile
        .profile
        .methods
        .iter()
        .any(|method| matches!(method, PaymentMethod::Lightning { .. }))
}

fn has_onchain(profile: &SignedPaymentProfile) -> bool {
    profile
        .profile
        .methods
        .iter()
        .any(|method| matches!(method, PaymentMethod::Onchain { .. }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use satspath_core::{PaymentProfile, SignedPaymentProfile};

    const PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

    fn signed(methods: Vec<PaymentMethod>) -> SignedPaymentProfile {
        SignedPaymentProfile {
            profile: PaymentProfile {
                alias: "ark_user".into(),
                identity_pubkey: "03pubkey".into(),
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
            },
            signature: "sig".into(),
            hybrid_signature: None,
        }
    }

    fn ark(server: &str) -> PaymentMethod {
        PaymentMethod::Ark {
            label: "Ark".into(),
            server: server.into(),
            pubkey: PUBKEY.into(),
            opaque_uri: None,
            vtxo_pointer: None,
            proof: None,
            expires_at: None,
        }
    }

    fn lightning() -> PaymentMethod {
        PaymentMethod::Lightning {
            label: "LN".into(),
            lightning_address: Some("alice@example.com".into()),
            lnurl: None,
            bolt12: None,
            receiver_pubkey: None,
        }
    }

    fn onchain() -> PaymentMethod {
        PaymentMethod::Onchain {
            label: "BTC".into(),
            network: satspath_core::BitcoinNetwork::Mainnet,
            address: Some("1BoatSLRHtKNngkdXEeobR76b53LETtpyT".into()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        }
    }

    #[test]
    fn ark_to_ark_same_server() {
        let plan = plan_ark_route(
            &SenderCapabilities {
                ark_server: Some("https://ark.example.com".into()),
                ..SenderCapabilities::default()
            },
            &signed(vec![ark("https://ark.example.com")]),
        )
        .unwrap();
        assert_eq!(plan.kind, ArkRouteKind::ArkToArk);
        assert!(!plan.requires_swap);
    }

    #[test]
    fn ark_to_lightning_requires_swap() {
        let plan = plan_ark_route(
            &SenderCapabilities {
                ark_server: Some("https://ark.example.com".into()),
                ..SenderCapabilities::default()
            },
            &signed(vec![lightning()]),
        )
        .unwrap();
        assert_eq!(plan.kind, ArkRouteKind::ArkToLightning);
        assert!(plan.requires_swap);
    }

    #[test]
    fn lightning_to_ark_requires_onboard_or_reverse_path() {
        let plan = plan_ark_route(
            &SenderCapabilities {
                has_lightning: true,
                ..SenderCapabilities::default()
            },
            &signed(vec![ark("https://ark.example.com")]),
        )
        .unwrap();
        assert_eq!(plan.kind, ArkRouteKind::LightningToArk);
        assert!(plan.requires_boltz);
    }

    #[test]
    fn ark_to_onchain_requires_offboard() {
        let plan = plan_ark_route(
            &SenderCapabilities {
                ark_server: Some("https://ark.example.com".into()),
                ..SenderCapabilities::default()
            },
            &signed(vec![onchain()]),
        )
        .unwrap();
        assert_eq!(plan.kind, ArkRouteKind::ArkToOnchain);
        assert!(plan.requires_ark_bridge);
    }

    #[test]
    fn onchain_to_ark_requires_onboard() {
        let plan = plan_ark_route(
            &SenderCapabilities {
                has_onchain: true,
                ..SenderCapabilities::default()
            },
            &signed(vec![ark("https://ark.example.com")]),
        )
        .unwrap();
        assert_eq!(plan.kind, ArkRouteKind::OnchainToArk);
        assert!(plan.requires_swap);
    }

    #[test]
    fn unsupported_route_fails_closed() {
        assert!(
            plan_ark_route(&SenderCapabilities::default(), &signed(vec![lightning()])).is_none()
        );
    }
}
