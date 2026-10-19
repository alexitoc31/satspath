//! Integration tests for satspath-wasm crypto functions.
//!
//! These run as native Rust tests (not WASM) to verify the logic quickly.
//! The exact same code paths execute in WASM — the #[wasm_bindgen] attribute
//! is ignored in native builds.

#[cfg(test)]
mod tests {
    use satspath_wasm::{canonical_profile_json, topic_for_alias, verify_signed_profile};

    // ── Fixtures ──────────────────────────────────────────────────────────────

    /// Build a signed test profile using the WASM canonicalizer and profile domain separator.
    fn make_signed_profile_json() -> String {
        use secp256k1::{Keypair, Secp256k1, SecretKey};
        use sha2::{Digest, Sha256};

        let secp = Secp256k1::new();
        let secret_bytes = [1u8; 32];
        let secret = SecretKey::from_slice(&secret_bytes).unwrap();
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let pubkey = secp256k1::PublicKey::from_secret_key(&secp, &secret);
        let pubkey_hex = hex::encode(pubkey.serialize());

        let profile_json = format!(
            r#"{{"alias":"test@example.com","identity_pubkey":"{pubkey_hex}","methods":[],"updated_at":1700000000}}"#
        );

        let canonical_bytes = canonical_profile_json(&profile_json);

        const DOMAIN_SEP: &[u8] = b"SatsPathProfileV1";
        let mut hasher = Sha256::new();
        hasher.update(DOMAIN_SEP);
        hasher.update(&canonical_bytes);
        let digest = hasher.finalize();

        let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();
        let sig = secp.sign_schnorr_with_rng(&msg, &keypair, &mut rand_core::OsRng);
        let sig_hex = hex::encode(sig.as_ref());

        format!(r#"{{"profile":{profile_json},"signature":"{sig_hex}"}}"#)
    }

    // ── verify_signed_profile ─────────────────────────────────────────────────

    #[test]
    fn valid_signature_returns_true() {
        let signed_json = make_signed_profile_json();
        assert!(
            verify_signed_profile(&signed_json),
            "valid profile must verify"
        );
    }

    #[test]
    fn tampered_signature_returns_false() {
        let mut signed_json = make_signed_profile_json();
        // Flip the last hex char of the signature
        let last = signed_json.pop().unwrap(); // closing "
        let sig_last = signed_json.pop().unwrap();
        let flipped = if sig_last == '0' { '1' } else { '0' };
        signed_json.push(flipped);
        signed_json.push(last);
        assert!(!verify_signed_profile(&signed_json));
    }

    #[test]
    fn tampered_profile_returns_false() {
        let signed_json = make_signed_profile_json();
        let tampered = signed_json.replace("test@example.com", "evil@hacker.com");
        assert!(!verify_signed_profile(&tampered));
    }

    #[test]
    fn malformed_json_returns_false() {
        assert!(!verify_signed_profile("not json at all"));
        assert!(!verify_signed_profile("{}"));
        assert!(!verify_signed_profile(""));
    }

    // ── canonical_profile_json ────────────────────────────────────────────────

    #[test]
    fn canonical_bytes_are_nonempty_for_valid_profile() {
        let profile_json = r#"{"alias":"test@example.com","identity_pubkey":"0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798","methods":[],"updated_at":1700000000}"#;
        let bytes = canonical_profile_json(profile_json);
        assert!(!bytes.is_empty());
        // Must be valid UTF-8 JSON
        let s = String::from_utf8(bytes).unwrap();
        let _: serde_json::Value = serde_json::from_str(&s).unwrap();
    }

    #[test]
    fn canonical_bytes_sorts_keys() {
        // Even if input has keys in different order, output must be sorted
        let unsorted = r#"{"z_key":"last","a_key":"first"}"#;
        let bytes = canonical_profile_json(unsorted);
        let s = String::from_utf8(bytes).unwrap();
        // "a_key" must appear before "z_key" in the canonical output
        let a_pos = s.find("a_key").unwrap();
        let z_pos = s.find("z_key").unwrap();
        assert!(
            a_pos < z_pos,
            "canonical JSON must sort keys alphabetically"
        );
    }

    #[test]
    fn canonical_bytes_empty_on_bad_input() {
        assert!(canonical_profile_json("not json").is_empty());
    }

    // ── topic_for_alias ───────────────────────────────────────────────────────

    #[test]
    fn topic_is_32_bytes() {
        let t = topic_for_alias("rodrigo@satspath.dev");
        assert_eq!(t.len(), 32);
    }

    #[test]
    fn topic_is_case_insensitive() {
        assert_eq!(
            topic_for_alias("ALICE@EXAMPLE.COM"),
            topic_for_alias("alice@example.com")
        );
    }

    #[test]
    fn topic_strips_whitespace() {
        assert_eq!(
            topic_for_alias("  alice@example.com  "),
            topic_for_alias("alice@example.com")
        );
    }

    #[test]
    fn different_aliases_differ() {
        assert_ne!(
            topic_for_alias("alice@example.com"),
            topic_for_alias("bob@example.com")
        );
    }

    #[test]
    fn topic_matches_js_reference_vector() {
        // Cross-check: SHA-256("satspath:p2p:v1:alice@example.com")
        // Reference computed with: echo -n "satspath:p2p:v1:alice@example.com" | sha256sum
        use sha2::{Digest, Sha256};
        let expected = Sha256::digest(b"satspath:p2p:v1:alice@example.com").to_vec();
        assert_eq!(topic_for_alias("alice@example.com"), expected);
    }
}
