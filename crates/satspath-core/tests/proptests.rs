use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use satspath_core::crypto::{canonical_profile_bytes, sign_profile, verify_signed_profile};
use satspath_core::ssrf::{is_private_or_reserved_ip, validate_url};
use satspath_core::transparency::{inclusion_proof, verify_inclusion_proof};
use satspath_core::{
    canonicalize_identifier, BitcoinNetwork, Bolt12Offer, PaymentMethod, PaymentProfile,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

// ── Strategies ─────────────────────────────────────────────────────────────

fn arb_secret_key() -> impl Strategy<Value = SecretKey> {
    any::<[u8; 32]>().prop_filter_map("valid secp256k1 secret key", |bytes| {
        SecretKey::from_slice(&bytes).ok()
    })
}

fn arb_bitcoin_network() -> impl Strategy<Value = BitcoinNetwork> {
    prop_oneof![
        Just(BitcoinNetwork::Mainnet),
        Just(BitcoinNetwork::Testnet),
        Just(BitcoinNetwork::Regtest),
    ]
}

fn arb_payment_method() -> impl Strategy<Value = PaymentMethod> {
    prop_oneof![
        (
            "[a-zA-Z0-9_-]{1,16}",
            arb_bitcoin_network(),
            proptest::option::of("bc1q[a-z0-9]{20,40}"),
            proptest::option::of("sp1q[a-z0-9]{30,50}"),
        )
            .prop_map(|(label, network, address, silent_payment_pubkey)| {
                PaymentMethod::Onchain {
                    label,
                    network,
                    address,
                    silent_payment_pubkey,
                    pubkey_hint: None,
                    descriptor_hint: None,
                    address_list: vec![],
                }
            }),
        (
            "[a-zA-Z0-9_-]{1,16}",
            proptest::option::of("[a-z0-9_]{1,15}@[a-z0-9_]{1,10}\\.com"),
            proptest::option::of("https://[a-z0-9.]+/lnurl"),
            proptest::option::of("lno1[a-z0-9]{20,50}"),
        )
            .prop_map(|(label, lightning_address, lnurl, bolt12)| {
                PaymentMethod::Lightning {
                    label,
                    lightning_address,
                    lnurl,
                    bolt12,
                    receiver_pubkey: None,
                }
            }),
        (
            "[a-zA-Z0-9_-]{1,16}",
            "https://[a-z0-9.]+/ark",
            "[0-9a-f]{66}",
        )
            .prop_map(|(label, server, pubkey)| {
                PaymentMethod::Ark {
                    label,
                    server,
                    pubkey,
                    vtxo_pointer: None,
                    proof: None,
                    expires_at: None,
                    opaque_uri: None,
                }
            }),
        (
            "[a-zA-Z0-9_-]{1,16}",
            "lno1[a-z0-9]{20,50}",
            arb_bitcoin_network(),
            proptest::option::of(100u64..10_000_000u64),
            "[0-9a-f]{66}",
        )
            .prop_map(|(label, offer, network, min_amt, issuer)| {
                PaymentMethod::Bolt12(Bolt12Offer {
                    label,
                    offer,
                    network,
                    minimum_amount_sats: min_amt,
                    expires_at: None,
                    issuer_pubkey: issuer,
                })
            }),
    ]
}

fn arb_valid_profile_and_key() -> impl Strategy<Value = (SecretKey, PaymentProfile)> {
    (
        arb_secret_key(),
        "[a-z0-9_]{1,15}@[a-z0-9_]{1,10}\\.com",
        proptest::collection::vec(arb_payment_method(), 0..4),
        0i64..2_000_000_000i64,
        proptest::option::of(0i64..3_000_000_000i64),
        proptest::option::of(0u64..1_000_000u64),
        proptest::collection::vec(
            prop_oneof![
                Just("lightning".to_string()),
                Just("onchain".to_string()),
                Just("ark".to_string())
            ],
            0..3,
        ),
        proptest::bool::ANY,
    )
        .prop_map(
            |(sk, alias, methods, updated_at, expires_at, sequence, preferences, revoked)| {
                let secp = Secp256k1::new();
                let pk = PublicKey::from_secret_key(&secp, &sk);
                let profile = PaymentProfile {
                    alias,
                    identity_pubkey: hex::encode(pk.serialize()),
                    methods,
                    updated_at,
                    expires_at,
                    sequence,
                    preferences,
                    nonce: None,
                    rotation: None,
                    method_verifications: vec![],
                    hybrid_pubkey: None,
                    pqc_required: false,
                    revoked,
                    recovery_policy: None,
                    recovery: None,
                };
                (sk, profile)
            },
        )
}

fn arb_json_value() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i64>().prop_map(|n| serde_json::Value::Number(n.into())),
        "[a-zA-Z0-9_ -]{0,32}".prop_map(serde_json::Value::String),
    ];
    leaf.prop_recursive(3, 16, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(serde_json::Value::Array),
            proptest::collection::vec(("[a-zA-Z0-9_]{1,16}", inner), 0..4).prop_map(|entries| {
                let map = entries
                    .into_iter()
                    .collect::<serde_json::Map<String, serde_json::Value>>();
                serde_json::Value::Object(map)
            }),
        ]
    })
}

prop_compose! {
    fn arb_tree_and_index()(
        leaves in proptest::collection::vec(any::<[u8; 32]>(), 1..=64)
    )(
        index in 0..leaves.len(),
        leaves in Just(leaves)
    ) -> (Vec<[u8; 32]>, usize) {
        (leaves, index)
    }
}

fn arb_private_ipv4() -> impl Strategy<Value = Ipv4Addr> {
    prop_oneof![
        // 127.0.0.0/8 (Loopback)
        (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(b, c, d)| Ipv4Addr::new(127, b, c, d)),
        // 10.0.0.0/8 (RFC 1918 Private)
        (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(b, c, d)| Ipv4Addr::new(10, b, c, d)),
        // 172.16.0.0/12 (RFC 1918 Private)
        (16u8..=31u8, any::<u8>(), any::<u8>()).prop_map(|(b, c, d)| Ipv4Addr::new(172, b, c, d)),
        // 192.168.0.0/16 (RFC 1918 Private)
        (any::<u8>(), any::<u8>()).prop_map(|(c, d)| Ipv4Addr::new(192, 168, c, d)),
        // 169.254.0.0/16 (Link-local & cloud metadata)
        (any::<u8>(), any::<u8>()).prop_map(|(c, d)| Ipv4Addr::new(169, 254, c, d)),
        // 100.64.0.0/10 (Carrier-grade NAT)
        (64u8..=127u8, any::<u8>(), any::<u8>()).prop_map(|(b, c, d)| Ipv4Addr::new(100, b, c, d)),
        // Documentation & benchmark ranges
        (any::<u8>()).prop_map(|d| Ipv4Addr::new(192, 0, 2, d)),
        (any::<u8>()).prop_map(|d| Ipv4Addr::new(198, 51, 100, d)),
        (any::<u8>()).prop_map(|d| Ipv4Addr::new(203, 0, 113, d)),
        (18u8..=19u8, any::<u8>(), any::<u8>()).prop_map(|(b, c, d)| Ipv4Addr::new(198, b, c, d)),
        // Broadcast / multicast / unspecified
        (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(b, c, d)| Ipv4Addr::new(0, b, c, d)),
        (224u8..=255u8, any::<u8>(), any::<u8>(), any::<u8>())
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d)),
    ]
}

fn arb_private_ipv6() -> impl Strategy<Value = Ipv6Addr> {
    prop_oneof![
        // Loopback & unspecified
        Just(Ipv6Addr::LOCALHOST),
        Just(Ipv6Addr::UNSPECIFIED),
        // ULA fc00::/7
        (0xfc00u16..=0xfdffu16, any::<[u16; 7]>()).prop_map(|(prefix, segs)| {
            Ipv6Addr::new(
                prefix, segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6],
            )
        }),
        // Link-local fe80::/10
        (0xfe80u16..=0xfebfu16, any::<[u16; 7]>()).prop_map(|(prefix, segs)| {
            Ipv6Addr::new(
                prefix, segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6],
            )
        }),
        // Multicast ff00::/8
        (0xff00u16..=0xffffu16, any::<[u16; 7]>()).prop_map(|(prefix, segs)| {
            Ipv6Addr::new(
                prefix, segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6],
            )
        }),
        // Documentation 2001:0db8::/32
        any::<[u16; 6]>().prop_map(|segs| {
            Ipv6Addr::new(
                0x2001, 0x0db8, segs[0], segs[1], segs[2], segs[3], segs[4], segs[5],
            )
        }),
        // IPv4-mapped private IPv4
        arb_private_ipv4().prop_map(|v4| v4.to_ipv6_mapped()),
        // NAT64 embedded private IPv4 (64:ff9b::a.b.c.d)
        arb_private_ipv4().prop_map(|v4| {
            let o = v4.octets();
            let seg6 = ((o[0] as u16) << 8) | (o[1] as u16);
            let seg7 = ((o[2] as u16) << 8) | (o[3] as u16);
            Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, seg6, seg7)
        }),
    ]
}

// ── Property Tests ─────────────────────────────────────────────────────────

proptest! {
    // ── 1. Canonicalize Identifier & JSON Invariants ───────────────────────

    #[test]
    fn test_canonicalize_identifier_does_not_panic(s in "\\PC*") {
        let _ = canonicalize_identifier(&s);
    }

    #[test]
    fn test_canonicalize_identifier_is_idempotent(s in "\\PC*") {
        let id1 = canonicalize_identifier(&s);
        let id2 = canonicalize_identifier(&id1);
        prop_assert_eq!(id1, id2, "canonicalize_identifier must be idempotent");
    }

    #[test]
    fn test_canonical_json_idempotency_on_arbitrary_json(val in arb_json_value()) {
        if let Ok(c1) = canonical_json::to_string(&val) {
            let val2: serde_json::Value = serde_json::from_str(&c1).expect("reparse canonical JSON");
            let c2 = canonical_json::to_string(&val2).expect("re-canonicalize parsed JSON");
            prop_assert_eq!(c1, c2, "canonical_json(canonical_json(x)) == canonical_json(x)");
        }
    }

    #[test]
    fn test_canonical_profile_bytes_is_idempotent((_, profile) in arb_valid_profile_and_key()) {
        let bytes1 = canonical_profile_bytes(&profile).expect("serialize profile");
        let val: serde_json::Value = serde_json::from_slice(&bytes1).expect("parse back into JSON Value");
        let bytes2 = canonical_json::to_string(&val).expect("re-canonicalize").into_bytes();
        prop_assert_eq!(bytes1, bytes2, "canonical_profile_bytes must be strictly idempotent");
    }

    // ── 2. Profile Signing & Verification Roundtrip ────────────────────────

    #[test]
    fn test_signed_profile_always_verifies_roundtrip((sk, profile) in arb_valid_profile_and_key()) {
        let signed = sign_profile(profile, &sk).expect("signing valid profile must succeed");
        let verified = verify_signed_profile(&signed).expect("verification call must not error");
        prop_assert!(verified, "any valid profile signed with its private key must verify");
    }

    // ── 3. Tampered Profile Fails Verification (No False Positives) ────────

    #[test]
    fn test_tampered_profile_always_fails_verification(
        (sk, profile) in arb_valid_profile_and_key(),
        tamper_mode in 0..7u8,
        tamper_byte in 1..=255u8
    ) {
        let signed = sign_profile(profile, &sk).expect("signing succeeds");
        let mut tampered = signed.clone();

        match tamper_mode {
            0 => {
                // Tamper with alias
                tampered.profile.alias.push_str("_tampered");
            }
            1 => {
                // Tamper with identity_pubkey
                let mut pk_bytes = hex::decode(&tampered.profile.identity_pubkey).unwrap();
                pk_bytes[0] ^= tamper_byte;
                tampered.profile.identity_pubkey = hex::encode(pk_bytes);
            }
            2 => {
                // Tamper with sequence number
                let cur = tampered.profile.sequence.unwrap_or(0);
                tampered.profile.sequence = Some(cur.wrapping_add(1));
            }
            3 => {
                // Tamper with updated_at timestamp
                tampered.profile.updated_at = tampered.profile.updated_at.wrapping_add(1);
            }
            4 => {
                // Tamper with revoked flag
                tampered.profile.revoked = !tampered.profile.revoked;
            }
            5 => {
                // Tamper with payment methods list
                tampered.profile.methods.push(PaymentMethod::Onchain {
                    label: "adversary-method".into(),
                    network: BitcoinNetwork::Mainnet,
                    address: Some("bc1qadversary000000000000000000000000000000".into()),
                    silent_payment_pubkey: None,
                    pubkey_hint: None,
                    descriptor_hint: None,
                    address_list: vec![],
                });
            }
            _ => {
                // Tamper with signature bytes
                if let Ok(mut sig_bytes) = hex::decode(&tampered.signature) {
                    if !sig_bytes.is_empty() {
                        sig_bytes[0] ^= tamper_byte;
                        tampered.signature = hex::encode(sig_bytes);
                    }
                }
            }
        }

        // Must fail verification: if verification succeeded, that is an invalid false positive
        if let Ok(verified) = verify_signed_profile(&tampered) {
            prop_assert!(!verified, "tampered profile must never verify as valid");
        }
    }

    // ── 4. Merkle Inclusion Proof Roundtrip & Tamper Rejection ─────────────

    #[test]
    fn test_merkle_inclusion_proof_for_any_leaf_always_verifies(
        (leaves, index) in arb_tree_and_index()
    ) {
        let proof = inclusion_proof(&leaves, index).expect("inclusion proof generation");
        let verified = verify_inclusion_proof(&proof).expect("proof verification");
        prop_assert!(verified, "inclusion proof for leaf {index} in tree of size {} must verify", leaves.len());
    }

    #[test]
    fn test_tampered_merkle_inclusion_proof_fails_verification(
        (leaves, index) in arb_tree_and_index(),
        tamper_mode in 0..4u8,
        mutation_byte in 1..=255u8
    ) {
        let proof = inclusion_proof(&leaves, index).expect("inclusion proof generation");
        let mut tampered = proof.clone();

        match tamper_mode {
            0 => {
                // Mutate leaf_hash
                if let Ok(mut h) = hex::decode(&tampered.leaf_hash) {
                    h[0] ^= mutation_byte;
                    tampered.leaf_hash = hex::encode(h);
                }
            }
            1 => {
                // Mutate root_hash
                if let Ok(mut h) = hex::decode(&tampered.root_hash) {
                    h[0] ^= mutation_byte;
                    tampered.root_hash = hex::encode(h);
                }
            }
            2 => {
                // Mutate audit path sibling or tree size
                if !tampered.audit_path.is_empty() {
                    if let Ok(mut h) = hex::decode(&tampered.audit_path[0]) {
                        h[0] ^= mutation_byte;
                        tampered.audit_path[0] = hex::encode(h);
                    }
                } else {
                    tampered.tree_size = tampered.tree_size.wrapping_add(1);
                }
            }
            _ => {
                // Mutate leaf index
                tampered.leaf_index = (tampered.leaf_index + 1) % (tampered.tree_size + 1);
            }
        }

        if let Ok(verified) = verify_inclusion_proof(&tampered) {
            prop_assert!(!verified, "tampered Merkle proof must not verify");
        }
    }

    // ── 5. SSRF Validation Never Allows Private IPs Regardless of Encoding ──

    #[test]
    fn test_ssrf_rejects_private_ipv4(ip in arb_private_ipv4()) {
        prop_assert!(
            is_private_or_reserved_ip(IpAddr::V4(ip)),
            "IP {ip} must be identified as private/reserved"
        );
        let url_https = format!("https://{ip}/profile");
        prop_assert!(
            validate_url(&url_https, false).is_err(),
            "validate_url must reject private IPv4 URL: {url_https}"
        );
    }

    #[test]
    fn test_ssrf_rejects_private_ipv6(ip in arb_private_ipv6()) {
        prop_assert!(
            is_private_or_reserved_ip(IpAddr::V6(ip)),
            "IPv6 {ip} must be identified as private/reserved"
        );
        let url_https = format!("https://[{ip}]/profile");
        prop_assert!(
            validate_url(&url_https, false).is_err(),
            "validate_url must reject private IPv6 URL: {url_https}"
        );
    }

    #[test]
    fn test_ssrf_rejects_blocked_hostnames(
        host in prop_oneof![
            Just("localhost"),
            Just("localhost.localdomain"),
            Just("ip6-localhost"),
            Just("ip6-loopback"),
            Just("metadata.google.internal"),
            Just("169.254.169.254"),
            Just("sub.metadata.google.internal"),
            Just("app.localhost"),
        ]
    ) {
        let url = format!("https://{host}/profile");
        prop_assert!(
            validate_url(&url, false).is_err(),
            "validate_url must reject internal host: {url}"
        );
    }

    #[test]
    fn test_ssrf_rejects_forbidden_schemes_and_ports(
        scheme in prop_oneof![Just("http"), Just("ftp"), Just("file"), Just("gopher")],
        port in prop_oneof![Just(22u16), Just(25u16), Just(3306u16), Just(6379u16)]
    ) {
        let url = format!("{scheme}://satspath.example.com:{port}/profile");
        prop_assert!(
            validate_url(&url, false).is_err(),
            "validate_url must reject unsafe scheme/port combination: {url}"
        );
    }
}
