use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use satspath_core::crypto::{canonical_profile_bytes, sign_profile, verify_signed_profile};
use satspath_core::ssrf::{is_private_or_reserved_ip, validate_url};
use satspath_core::transparency::{
    inclusion_proof, leaf_hash, merkle_root, node_hash, verify_inclusion_proof,
};
use satspath_core::{
    canonicalize_identifier, BitcoinNetwork, Bolt12Offer, PaymentMethod, PaymentProfile,
    SatsPathError, TransparencyError,
};
use secp256k1::{PublicKey, Secp256k1, SecretKey};

// ── Strategies ─────────────────────────────────────────────────────────────

/// Generate identity signing keys for profile tests.
fn arb_secret_key() -> impl Strategy<Value = SecretKey> {
    any::<[u8; 32]>().prop_filter_map("valid secp256k1 secret key", |bytes| {
        SecretKey::from_slice(&bytes).ok()
    })
}

/// Sample the Bitcoin networks represented by payment profiles.
fn arb_bitcoin_network() -> impl Strategy<Value = BitcoinNetwork> {
    prop_oneof![
        Just(BitcoinNetwork::Mainnet),
        Just(BitcoinNetwork::Testnet),
        Just(BitcoinNetwork::Regtest),
    ]
}

/// Generate payment-method fields for property tests, including malformed pointers.
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

/// Generate a signable profile and its matching identity key; pointers need not be payable.
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

/// Generate bounded nested JSON values with integer numbers for canonicalization.
fn arb_json_value() -> impl Strategy<Value = serde_json::Value> {
    let leaf = prop_oneof![
        Just(serde_json::Value::Null),
        any::<bool>().prop_map(serde_json::Value::Bool),
        any::<i64>().prop_map(|n| serde_json::Value::Number(n.into())),
        proptest::collection::vec(any::<char>(), 0..32)
            .prop_map(|chars| serde_json::Value::String(chars.into_iter().collect())),
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
    /// Generate a nonempty tree of leaf hashes and an index within that tree.
    fn arb_tree_and_index()(
        leaves in proptest::collection::vec(any::<[u8; 32]>(), 1..=64)
    )(
        index in 0..leaves.len(),
        leaves in Just(leaves)
    ) -> (Vec<[u8; 32]>, usize) {
        (leaves, index)
    }
}

/// Sample private and reserved IPv4 ranges rejected by the SSRF policy.
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
        (any::<u8>()).prop_map(|d| Ipv4Addr::new(192, 0, 0, d)),
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

/// Sample blocked IPv6 ranges, including embedded private IPv4 addresses.
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
        // Discard-only 100::/64, benchmarking 2001:2::/48, and site-local fec0::/10
        any::<[u16; 4]>().prop_map(|segs| {
            Ipv6Addr::new(0x0100, 0, 0, 0, segs[0], segs[1], segs[2], segs[3])
        }),
        any::<[u16; 5]>().prop_map(|segs| {
            Ipv6Addr::new(0x2001, 2, 0, segs[0], segs[1], segs[2], segs[3], segs[4])
        }),
        (0xfec0u16..=0xfeffu16, any::<[u16; 7]>()).prop_map(|(prefix, segs)| {
            Ipv6Addr::new(
                prefix, segs[0], segs[1], segs[2], segs[3], segs[4], segs[5], segs[6],
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

    /// Check that arbitrary Unicode identifiers can be canonicalized without panicking.
    #[test]
    fn test_canonicalize_identifier_does_not_panic(s in "\\PC*") {
        let _ = canonicalize_identifier(&s);
    }

    /// Check that canonicalizing an identifier twice leaves it unchanged.
    #[test]
    fn test_canonicalize_identifier_is_idempotent(s in "\\PC*") {
        let id1 = canonicalize_identifier(&s);
        let id2 = canonicalize_identifier(&id1);
        prop_assert_eq!(id1, id2, "canonicalize_identifier must be idempotent");
    }

    /// Check that parsing and canonicalizing canonical JSON preserves its bytes.
    #[test]
    fn test_canonical_json_idempotency_on_arbitrary_json(val in arb_json_value()) {
        let c1 = canonical_json::to_string(&val).expect("canonicalize generated JSON");
        let val2: serde_json::Value = serde_json::from_str(&c1).expect("reparse canonical JSON");
        prop_assert_eq!(&val2, &val, "canonicalization must preserve JSON values");
        let c2 = canonical_json::to_string(&val2).expect("re-canonicalize parsed JSON");
        prop_assert_eq!(c1, c2, "canonical_json(canonical_json(x)) == canonical_json(x)");
    }

    /// Check that profile serialization agrees with canonicalization of the parsed JSON.
    #[test]
    fn test_canonical_profile_bytes_is_idempotent((_, profile) in arb_valid_profile_and_key()) {
        let bytes1 = canonical_profile_bytes(&profile).expect("serialize profile");
        let val: serde_json::Value = serde_json::from_slice(&bytes1).expect("parse back into JSON Value");
        let bytes2 = canonical_json::to_string(&val).expect("re-canonicalize").into_bytes();
        prop_assert_eq!(bytes1, bytes2, "canonical_profile_bytes must be strictly idempotent");
    }

    // ── 2. Profile Signing & Verification Roundtrip ────────────────────────

    /// Check that profiles signed with their matching identity key verify successfully.
    #[test]
    fn test_signed_profile_always_verifies_roundtrip((sk, profile) in arb_valid_profile_and_key()) {
        let signed = sign_profile(profile, &sk).expect("signing valid profile must succeed");
        let verified = verify_signed_profile(&signed).expect("verification call must not error");
        prop_assert!(verified, "any valid profile signed with its private key must verify");
    }

    /// Exercise numeric limits that are outside the ordinary profile generator's ranges.
    #[test]
    fn test_signed_profile_roundtrip_at_numeric_limits((sk, mut profile) in arb_valid_profile_and_key()) {
        for (timestamp, sequence) in [(i64::MIN, 0), (i64::MAX, u64::MAX)] {
            profile.updated_at = timestamp;
            profile.expires_at = Some(timestamp);
            profile.sequence = Some(sequence);
            let bytes = canonical_profile_bytes(&profile).expect("serialize boundary profile");
            let decoded: PaymentProfile = serde_json::from_slice(&bytes).expect("deserialize boundary profile");
            prop_assert_eq!(decoded.updated_at, timestamp);
            prop_assert_eq!(decoded.expires_at, Some(timestamp));
            prop_assert_eq!(decoded.sequence, Some(sequence));
            let signed = sign_profile(profile.clone(), &sk).expect("sign boundary profile");
            prop_assert!(verify_signed_profile(&signed).expect("verify boundary profile"));
        }
    }

    /// Optional signed fields must be authenticated even when the generator leaves them absent.
    #[test]
    fn test_tampered_optional_profile_fields_fail_verification((sk, profile) in arb_valid_profile_and_key()) {
        let signed = sign_profile(profile, &sk).expect("sign profile");
        prop_assert!(verify_signed_profile(&signed).expect("verify original profile"));
        for field in ["expires_at", "preferences", "nonce"] {
            let mut tampered = signed.clone();
            match field {
                "expires_at" => tampered.profile.expires_at = if tampered.profile.expires_at.is_some() {
                    None
                } else {
                    Some(0)
                },
                "preferences" => tampered.profile.preferences.push("tampered".into()),
                "nonce" => tampered.profile.nonce = Some("tampered-nonce".into()),
                _ => unreachable!(),
            }
            prop_assert!(
                matches!(verify_signed_profile(&tampered), Ok(false)),
                "modifying {field} must invalidate the signature"
            );
        }
    }

    /// Malformed encodings are errors, distinct from well-formed signatures that do not verify.
    #[test]
    fn test_malformed_profile_signature_and_key_return_errors((sk, profile) in arb_valid_profile_and_key()) {
        let signed = sign_profile(profile, &sk).expect("sign profile");
        for signature in [String::new(), "zz".into(), "00".repeat(63), "00".repeat(65)] {
            let mut malformed = signed.clone();
            malformed.signature = signature;
            prop_assert!(matches!(verify_signed_profile(&malformed), Err(SatsPathError::CryptoError(_))));
        }
        for pubkey in [String::new(), "zz".into(), "00".repeat(33)] {
            let mut malformed = signed.clone();
            malformed.profile.identity_pubkey = pubkey;
            prop_assert!(matches!(verify_signed_profile(&malformed), Err(SatsPathError::InvalidPublicKey(_))));
        }
    }

    // ── 3. Tampered Profile Fails Verification (No False Positives) ────────

    /// Check that mutations to signed fields or signature bytes fail verification.
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
                // Tamper with identity_pubkey: replace with a distinct valid public key
                let mut key_bytes = [0u8; 32];
                key_bytes[0] = tamper_byte;
                let other = SecretKey::from_slice(&key_bytes).unwrap();
                let pk = PublicKey::from_secret_key(&Secp256k1::new(), &other);
                let pk_hex = hex::encode(pk.serialize());
                prop_assume!(pk_hex != tampered.profile.identity_pubkey);
                tampered.profile.identity_pubkey = pk_hex;
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
                let mut sig_bytes = hex::decode(&tampered.signature).expect("signed signature is hex");
                let first = sig_bytes.first_mut().expect("signed signature is nonempty");
                *first ^= tamper_byte;
                tampered.signature = hex::encode(sig_bytes);
            }
        }

        let result = verify_signed_profile(&tampered);
        prop_assert!(
            matches!(result, Ok(false)),
            "tampered profile must return Ok(false), got {:?}",
            result
        );
    }

    // ── 4. Merkle Inclusion Proof Roundtrip & Tamper Rejection ─────────────

    /// Check inclusion proofs for generated leaf hashes at arbitrary valid positions.
    #[test]
    fn test_merkle_inclusion_proof_for_any_leaf_always_verifies(
        (leaves, index) in arb_tree_and_index()
    ) {
        let proof = inclusion_proof(&leaves, index).expect("inclusion proof generation");
        prop_assert_eq!(proof.leaf_index, index as u64);
        prop_assert_eq!(proof.tree_size, leaves.len() as u64);
        prop_assert_eq!(&proof.leaf_hash, &hex::encode(leaves[index]));
        prop_assert_eq!(&proof.root_hash, &hex::encode(merkle_root(&leaves)));
        let verified = verify_inclusion_proof(&proof).expect("proof verification");
        prop_assert!(verified, "inclusion proof for leaf {index} in tree of size {} must verify", leaves.len());
    }

    /// Proofs must consume exactly the required siblings, including singleton trees.
    #[test]
    fn test_merkle_proof_rejects_truncated_and_extended_paths((leaves, index) in arb_tree_and_index()) {
        let proof = inclusion_proof(&leaves, index).expect("generate proof");
        let mut extended = proof.clone();
        extended.audit_path.push(hex::encode([0u8; 32]));
        prop_assert!(matches!(verify_inclusion_proof(&extended), Ok(false)));
        if !proof.audit_path.is_empty() {
            let mut truncated = proof;
            truncated.audit_path.pop();
            prop_assert!(matches!(verify_inclusion_proof(&truncated), Ok(false)));
        }
    }

    /// Check that altered Merkle hashes, paths, sizes, or indices fail verification.
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
                // Mutate leaf index to another in-range index
                prop_assume!(tampered.tree_size > 1);
                let next_index = (index + 1) % leaves.len();
                prop_assume!(leaves[next_index] != leaves[index]);
                tampered.leaf_index = next_index as u64;
            }
        }

        let result = verify_inclusion_proof(&tampered);
        prop_assert!(
            matches!(result, Ok(false)),
            "tampered Merkle proof must return Ok(false), got {:?}",
            result
        );
    }

    // ── 5. SSRF Validation Never Allows Private IPs Regardless of Encoding ──

    /// Check that blocked IPv4 literals are rejected by both IP and URL validation.
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

    /// Check that alternate numeric IPv4 URL encodings cannot bypass SSRF validation.
    #[test]
    fn test_ssrf_rejects_private_ipv4_alternate_encodings(ip in arb_private_ipv4()) {
        let n = u32::from(ip);
        let o = ip.octets();
        let encodings = [
            format!("https://{n}/profile"),
            format!("https://0x{n:08x}/profile"),
            format!("https://0{n:o}/profile"),
            format!("https://{}.{}/profile", o[0], (u32::from(o[1]) << 16) | (u32::from(o[2]) << 8) | u32::from(o[3])),
            format!("https://0x{:02x}.0{:o}.{}.{}/profile", o[0], o[1], o[2], o[3]),
        ];
        for url in encodings {
            prop_assert!(validate_url(&url, false).is_err(), "validate_url must reject encoded private IPv4 URL: {url}");
        }
    }

    /// Check that blocked IPv6 literals are rejected by both IP and URL validation.
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

    /// Check that localhost and metadata hostnames are rejected before fetching.
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

    /// Check rejection of forbidden URL schemes independently of port validation.
    #[test]
    fn test_ssrf_rejects_forbidden_schemes(
        scheme in prop_oneof![Just("http"), Just("ftp"), Just("file"), Just("gopher")]
    ) {
        let url = format!("{scheme}://satspath.example.com/profile");
        let result = validate_url(&url, false);
        prop_assert!(
            matches!(&result, Err(satspath_core::SatsPathError::ValidationError(message))
                if message.starts_with(&format!("Blocked scheme '{scheme}'"))),
            "validate_url must reject forbidden scheme: {url}, got {result:?}"
        );
    }

    /// The HTTP test flag only relaxes the scheme check, never the private-address check.
    #[test]
    fn test_ssrf_http_flag_does_not_allow_private_ips(v4 in arb_private_ipv4(), v6 in arb_private_ipv6()) {
        for url in [
            format!("http://{v4}/profile"),
            format!("http://[{v6}]/profile"),
            // The metadata IP is also a blocked hostname, so that check rejects it first.
            "http://169.254.169.254/profile".into(),
        ] {
            let result = validate_url(&url, true);
            prop_assert!(
                matches!(&result, Err(SatsPathError::ValidationError(message))
                    if message.starts_with("Blocked IP:") || message.starts_with("Blocked host:")),
                "private IP must remain blocked with HTTP enabled: {url}, got {result:?}"
            );
        }
    }

    /// Check every generated port against the policy, using a public host to isolate port validation.
    #[test]
    fn test_ssrf_port_allowlist(port in any::<u16>()) {
        let url = format!("https://example.com:{port}/profile");
        let result = validate_url(&url, false);
        if [80, 443, 8080, 8443].contains(&port) {
            prop_assert!(result.is_ok(), "allowed port {port}: {result:?}");
        } else {
            prop_assert!(
                matches!(&result, Err(SatsPathError::ValidationError(message)) if message.starts_with(&format!("Blocked port {port}"))),
                "disallowed port {port}: {result:?}"
            );
        }
    }
}

#[test]
/// Verify that inclusion proof public exports handle singleton tree.
fn test_inclusion_proof_public_exports_handle_singleton_tree() {
    let leaf = leaf_hash(b"only leaf");
    let proof = satspath_core::inclusion_proof(&[leaf], 0).expect("crate-root export");
    assert_eq!(proof, inclusion_proof(&[leaf], 0).expect("module export"));
    assert_eq!(proof.leaf_index, 0);
    assert_eq!(proof.tree_size, 1);
    assert_eq!(proof.leaf_hash, hex::encode(leaf));
    assert_eq!(proof.root_hash, proof.leaf_hash);
    assert!(proof.audit_path.is_empty());
    assert!(verify_inclusion_proof(&proof).expect("verify singleton proof"));
}

#[test]
/// Verify that inclusion proof public exports reject invalid indices.
fn test_inclusion_proof_public_exports_reject_invalid_indices() {
    let leaves = [leaf_hash(b"a"), leaf_hash(b"b")];
    for (tree, index) in [
        (&[][..], 0),
        (&[][..], usize::MAX),
        (&leaves[..], leaves.len()),
        (&leaves[..], usize::MAX),
    ] {
        assert_eq!(
            inclusion_proof(tree, index),
            Err(TransparencyError::InvalidInclusionProof)
        );
        assert_eq!(
            satspath_core::inclusion_proof(tree, index),
            Err(TransparencyError::InvalidInclusionProof)
        );
    }
}

#[test]
/// Verify that inclusion proof paths for three leaf tree.
fn test_inclusion_proof_paths_for_three_leaf_tree() {
    let leaves = [leaf_hash(b"a"), leaf_hash(b"b"), leaf_hash(b"c")];
    // RFC 6962 splits this tree into a two-leaf left subtree and one right leaf.
    let left_root = node_hash(&leaves[0], &leaves[1]);
    let root = node_hash(&left_root, &leaves[2]);
    let paths = [
        vec![hex::encode(leaves[1]), hex::encode(leaves[2])],
        vec![hex::encode(leaves[0]), hex::encode(leaves[2])],
        vec![hex::encode(left_root)],
    ];
    for (index, expected_path) in paths.into_iter().enumerate() {
        let proof = inclusion_proof(&leaves, index).expect("generate three-leaf proof");
        assert_eq!(proof.audit_path, expected_path, "leaf {index}");
        assert_eq!(proof.root_hash, hex::encode(root));
        assert_eq!(proof.leaf_hash, hex::encode(leaves[index]));
        assert_eq!(proof.leaf_index, index as u64);
        assert_eq!(proof.tree_size, 3);
        assert!(verify_inclusion_proof(&proof).expect("verify three-leaf proof"));
    }
}

#[test]
/// Verify that inclusion proof duplicate leaves at tree size boundaries.
fn test_inclusion_proof_duplicate_leaves_at_tree_size_boundaries() {
    for size in [1, 2, 3, 7, 8, 9, 63, 64, 65] {
        let leaves = vec![leaf_hash(b"repeated leaf"); size];
        for index in 0..size {
            let proof = inclusion_proof(&leaves, index).expect("prove repeated leaf");
            assert_eq!(proof.leaf_index, index as u64);
            assert_eq!(proof.tree_size, size as u64);
            assert!(
                verify_inclusion_proof(&proof).expect("verify repeated leaf"),
                "size {size}, index {index}"
            );
        }
    }
}

#[test]
/// Verify that canonical json preserves unicode escapes and integer limits.
fn test_canonical_json_preserves_unicode_escapes_and_integer_limits() {
    let value = serde_json::json!({
        "unicode": "\u{1f680} e\u{301} \u{e9}",
        "escaped": "\"\\\n\r\t\u{0}",
        "nested": {"z": [], "a": {}},
        "limits": [i64::MIN, i64::MAX, u64::MAX, 0, -1],
        "scalars": [null, true, false],
    });
    let canonical = canonical_json::to_string(&value).expect("canonicalize boundary JSON");
    let parsed: serde_json::Value = serde_json::from_str(&canonical).expect("parse boundary JSON");
    assert_eq!(parsed, value);
    assert_eq!(canonical_json::to_string(&parsed).unwrap(), canonical);
}

#[test]
/// Verify that ssrf port boundaries on public host.
fn test_ssrf_port_boundaries_on_public_host() {
    for port in [80, 443, 8080, 8443] {
        assert!(validate_url(&format!("https://example.com:{port}/profile"), false).is_ok());
    }
    for port in [
        0, 79, 81, 442, 444, 1023, 1024, 8079, 8081, 8442, 8444, 65535,
    ] {
        let result = validate_url(&format!("https://example.com:{port}/profile"), false);
        assert!(
            matches!(&result, Err(SatsPathError::ValidationError(message)) if message.starts_with(&format!("Blocked port {port}"))),
            "port {port}: {result:?}"
        );
    }
}

#[test]
/// Verify that ssrf blocked hostnames with case and trailing dot.
fn test_ssrf_blocked_hostnames_with_case_and_trailing_dot() {
    for host in [
        "LOCALHOST.",
        "App.LocalHost.",
        "METADATA.GOOGLE.INTERNAL.",
        "sub.METADATA.GOOGLE.INTERNAL.",
        "IP6-LOOPBACK.",
    ] {
        let result = validate_url(&format!("https://{host}/profile"), false);
        assert!(
            matches!(&result, Err(SatsPathError::ValidationError(message)) if message.starts_with("Blocked host:")),
            "host {host}: {result:?}"
        );
    }
}

#[test]
/// Verify that ssrf allows public ipv4 and embedded ipv6 addresses.
fn test_ssrf_allows_public_ipv4_and_embedded_ipv6_addresses() {
    // Positive controls prevent a reject-everything policy from satisfying the SSRF properties.
    for literal in [
        "8.8.8.8",
        "[::ffff:8.8.8.8]",
        "[64:ff9b::808:808]",
        "[2606:4700:4700::1111]",
    ] {
        let ip: IpAddr = literal.trim_matches(['[', ']']).parse().expect("public IP");
        assert!(!is_private_or_reserved_ip(ip), "{ip}");
        assert!(validate_url(&format!("https://{literal}/profile"), false).is_ok());
        assert!(validate_url(&format!("http://{literal}/profile"), true).is_ok());
    }
}
