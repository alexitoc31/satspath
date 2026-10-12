//! Integration tests for BIP-353 local DNSSEC validation (Issue #106).
//!
//! Validates:
//! 1. Real cryptographic local chain validation against bundled root trust anchors
//!    for known DNSSEC-signed domains.
//! 2. Fail-closed rejection of domains with intentionally broken DNSSEC signatures.
//! 3. Rejection of unsigned domains under Strict DNSSEC policy.
//! 4. Presence and integrity of bundled ICANN root trust anchors (KSK 20326 and KSK 38696).
//! 5. Refusal to fabricate synthetic profiles in the resolver chain.
//! 6. Deterministic BIP-353 protocol invariants (chunked TXT, ambiguous records, private material screening).

use std::sync::Arc;

use satspath_core::bip353::{DnsTxtRecord, DnsTxtResolver, MockDnsTxtResolver};
use satspath_core::resolver::{ChainResolver, ProfileResolver};
use satspath_core::resolvers::bip353::{
    root_trust_anchors, Bip353Resolver, HickoryDnssecTxtResolver,
};
use satspath_core::SatsPathError;

// ─── Live DNSSEC Integration Tests ──────────────────────────────────────────────

#[tokio::test]
#[ignore = "Live external network DNS test; run explicitly with -- --ignored"]
async fn test_dnssec_local_chain_validation_for_signed_domain() {
    let resolver = HickoryDnssecTxtResolver::new();

    // cloudflare.com is signed with valid DNSSEC up to the ICANN root anchor
    let records = resolver
        .query_txt("cloudflare.com")
        .await
        .expect("cloudflare.com must pass local DNSSEC chain validation");

    assert!(
        !records.is_empty(),
        "cloudflare.com must return TXT records"
    );
    for r in &records {
        assert!(
            r.dnssec_validated,
            "all returned records must be cryptographically DNSSEC-validated"
        );
    }
}

#[tokio::test]
#[ignore = "Live external network DNS test; run explicitly with -- --ignored"]
async fn test_dnssec_known_bogus_signature_fails_closed() {
    let resolver = HickoryDnssecTxtResolver::new();

    // dnssec-failed.org is a standard test domain with an invalid/bogus DNSSEC signature
    let res = resolver.query_txt("dnssec-failed.org").await;

    assert!(
        res.is_err(),
        "known invalid DNSSEC domain must be rejected (fail closed)"
    );
    let err_str = res.unwrap_err().to_string();
    assert!(
        err_str.contains("DNSSEC validation failed"),
        "error message should indicate DNSSEC validation failure: {err_str}"
    );
}

#[tokio::test]
#[ignore = "Live external network DNS test; run explicitly with -- --ignored"]
async fn test_dnssec_unsigned_domain_rejected_in_strict_mode() {
    let resolver = HickoryDnssecTxtResolver::new();

    // google.com TXT is not DNSSEC signed
    let res = resolver.query_txt("google.com").await;

    assert!(
        res.is_err(),
        "unsigned domain google.com must fail DNSSEC validation in Strict mode"
    );
}

#[test]
fn test_root_trust_anchors_bundle_active_ksk() {
    let anchor = root_trust_anchors();
    // Default Hickory TrustAnchor has historical keys (19036 and 20326).
    // Our bundle adds the active ICANN KSK 38696 (3 keys total).
    assert!(
        anchor.len() >= 3,
        "trust anchor bundle must contain at least 3 root keys, found {}",
        anchor.len()
    );

    // Verify specifically that active ICANN KSK 38696 is contained in the trust anchor set
    const KSK_38696_B64: &str = "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=";
    let ksk_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, KSK_38696_B64).unwrap();
    assert!(
        anchor.contains_dnskey_bytes(&ksk_bytes),
        "trust anchor bundle must contain active KSK 38696 key bytes"
    );
}

// ─── Deterministic Protocol Invariant Tests ─────────────────────────────────────

const TEST_NAME: &str = "₿rodrigo@satspath.dev";
const TEST_FQDN: &str = "rodrigo.user._bitcoin-payment.satspath.dev";
const TEST_URI: &str = "bitcoin:?lno=lno1qgflx63rhq546e8w8q55h65v3298h";

fn mock_resolver_with(records: Vec<DnsTxtRecord>) -> Bip353Resolver {
    let mut dns = MockDnsTxtResolver::new();
    for r in records {
        dns.insert(TEST_FQDN, r);
    }
    Bip353Resolver::with_dns_resolver(Arc::new(dns))
}

#[tokio::test]
async fn test_bip353_refuses_to_fabricate_synthetic_profiles() {
    let record = DnsTxtRecord {
        strings: vec![TEST_URI.to_string()],
        dnssec_validated: true,
        ttl_seconds: Some(1800),
    };
    let resolver = mock_resolver_with(vec![record]);

    // 1. As a ProfileResolver, it must NOT return a forged signature for a direct instruction
    let alias_res = resolver.resolve_alias(TEST_NAME).await;
    assert!(
        matches!(alias_res, Err(SatsPathError::AliasNotFound(_))),
        "resolve_alias must return AliasNotFound instead of fabricating a synthetic profile: {:?}",
        alias_res
    );

    // 2. But resolve_instruction returns the authentic DNSSEC-authenticated instruction
    let instr_res = resolver.resolve_instruction(TEST_NAME).await.unwrap();
    assert!(instr_res.dnssec_validated);
    assert_eq!(instr_res.bitcoin_uri, TEST_URI);
}

#[tokio::test]
async fn test_bip353_in_chain_resolver_does_not_poison_chain() {
    let record = DnsTxtRecord {
        strings: vec![TEST_URI.to_string()],
        dnssec_validated: true,
        ttl_seconds: Some(1800),
    };
    let resolver = mock_resolver_with(vec![record]);
    let chain = ChainResolver::new().push(resolver);

    // ChainResolver must surface AliasNotFound (allowing other resolvers to proceed or report)
    let res = chain.resolve_alias(TEST_NAME).await;
    assert!(matches!(res, Err(SatsPathError::AliasNotFound(_))));
}

#[tokio::test]
async fn test_bip353_unvalidated_dnssec_fails_closed_in_strict() {
    let record = DnsTxtRecord {
        strings: vec![TEST_URI.to_string()],
        dnssec_validated: false, // Not validated
        ttl_seconds: Some(1800),
    };
    let resolver = mock_resolver_with(vec![record]);

    let res = resolver.resolve_instruction(TEST_NAME).await;
    assert!(
        matches!(res, Err(SatsPathError::DnssecUnavailable)),
        "unvalidated DNSSEC must fail closed in Strict mode: {:?}",
        res
    );
}

#[tokio::test]
async fn test_bip353_multiple_bitcoin_records_rejected_as_ambiguous() {
    let r1 = DnsTxtRecord {
        strings: vec!["bitcoin:?lno=lno1first".into()],
        dnssec_validated: true,
        ttl_seconds: Some(1800),
    };
    let r2 = DnsTxtRecord {
        strings: vec!["bitcoin:?lno=lno1second".into()],
        dnssec_validated: true,
        ttl_seconds: Some(1800),
    };
    let resolver = mock_resolver_with(vec![r1, r2]);

    let res = resolver.resolve_instruction(TEST_NAME).await;
    assert!(
        matches!(res, Err(SatsPathError::Bip353(_))),
        "multiple bitcoin: records must be rejected: {:?}",
        res
    );
}

#[tokio::test]
async fn test_bip353_chunked_txt_reconstruction() {
    let (part1, part2) = TEST_URI.split_at(15);
    let record = DnsTxtRecord {
        strings: vec![part1.into(), part2.into()],
        dnssec_validated: true,
        ttl_seconds: Some(1800),
    };
    let resolver = mock_resolver_with(vec![record]);

    let res = resolver.resolve_instruction(TEST_NAME).await.unwrap();
    assert_eq!(res.bitcoin_uri, TEST_URI);
}

#[tokio::test]
async fn test_bip353_private_material_in_txt_is_rejected() {
    let record = DnsTxtRecord {
        strings: vec!["bitcoin:?lno=lno1&note=xprv9s21msecret".into()],
        dnssec_validated: true,
        ttl_seconds: Some(1800),
    };
    let resolver = mock_resolver_with(vec![record]);

    let res = resolver.resolve_instruction(TEST_NAME).await;
    assert!(
        matches!(res, Err(SatsPathError::PrivateMaterialRejected(_))),
        "private material in TXT record must be rejected: {:?}",
        res
    );
}
