//! Integration tests for BIP-353 local cryptographic DNSSEC validation (Issue #152).
//!
//! Validates:
//! 1. Presence, decoding, and RFC 4034 key-tag verification of bundled ICANN root trust anchors
//!    (active KSK `38696`, standby KSK `20326`, and historical KSK `19036`).
//! 2. Deterministic offline cryptographic chain validation (`verify_dnssec_zone_chain`) across
//!    `. -> dev. -> satspath.dev. -> rodrigo.user._bitcoin-payment.satspath.dev.`.
//! 3. Deterministic in-process authoritative DNSSEC server fixture wrapped by
//!    [`HickoryDnssecTxtResolver::with_dns_handle`] verifying:
//!    - Valid signed DNSSEC zone hierarchy succeeds under [`DnssecPolicy::Strict`].
//!    - Tampered / bogus `RRSIG` signature fails closed.
//!    - Tampered `DS` delegation digest fails closed.
//!    - Unsigned zone (missing `RRSIG`) fails closed with [`SatsPathError::DnssecUnavailable`].
//! 4. End-to-end [`Bip353Resolver`] `sp-profile` ownership verification and refusal to
//!    synthesize profiles when no `sp-profile` pointer is present.

use std::pin::Pin;
use std::sync::Arc;

use futures_util::{future, stream, Stream};
use hickory_resolver::proto::error::ProtoError;
use hickory_resolver::proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_resolver::proto::rr::dnssec::rdata::{DNSSECRData, DNSKEY, DS, RRSIG};
use hickory_resolver::proto::rr::dnssec::{
    tbs, Algorithm, DigestType, KeyFormat, KeyPair, Private, PublicKeyBuf, TrustAnchor, Verifier,
};
use hickory_resolver::proto::rr::rdata::TXT;
use hickory_resolver::proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_resolver::proto::xfer::{DnsHandle, DnsRequest, DnsResponse};

use satspath_core::bip353::{
    resolve_bip353_with, DnsTxtRecord, DnsTxtResolver, DnssecPolicy, MockDnsTxtResolver,
};
use satspath_core::crypto::{generate_identity_keypair, sign_profile};
use satspath_core::pointer::BitcoinNetwork;
use satspath_core::profile::{PaymentMethod, PaymentProfile};
use satspath_core::resolver::{ChainResolver, ProfileResolver};
use satspath_core::resolvers::bip353::{
    root_trust_anchors, verify_dnssec_zone_chain, Bip353Resolver, DnssecZoneLink,
    HickoryDnssecTxtResolver, ICANN_ROOT_KSK_20326_TAG, ICANN_ROOT_KSK_38696_B64,
    ICANN_ROOT_KSK_38696_TAG,
};
use satspath_core::SatsPathError;

// ─── Helper: Sign an RRset with an ECDSA P-256 KeyPair ──────────────────────────

/// Construct a signed `RRSIG` record covering `records` using `keypair` and `dnskey`.
#[allow(clippy::too_many_arguments)]
fn sign_rrset(
    owner_name: &Name,
    signer_name: &Name,
    record_type: RecordType,
    records: &[Record],
    keypair: &KeyPair<Private>,
    dnskey: &DNSKEY,
    inception: u32,
    expiration: u32,
) -> (RRSIG, Record) {
    let key_tag = dnskey.calculate_key_tag().expect("valid key tag");
    let num_labels = owner_name.num_labels();
    let orig_ttl = records.first().map(Record::ttl).unwrap_or(300);

    let pre_rrsig = RRSIG::new(
        record_type,
        Algorithm::ECDSAP256SHA256,
        num_labels,
        orig_ttl,
        expiration,
        inception,
        key_tag,
        signer_name.clone(),
        Vec::new(),
    );

    let tbs_bytes =
        tbs::rrset_tbs_with_sig(owner_name, DNSClass::IN, &pre_rrsig, records).expect("rrset_tbs");
    let sig_bytes = keypair
        .sign(Algorithm::ECDSAP256SHA256, &tbs_bytes)
        .expect("ecdsa sign");

    let rrsig = RRSIG::new(
        record_type,
        Algorithm::ECDSAP256SHA256,
        num_labels,
        orig_ttl,
        expiration,
        inception,
        key_tag,
        signer_name.clone(),
        sig_bytes,
    );

    // Sanity check: DNSKEY must verify the RRSIG we just created
    dnskey
        .verify_rrsig(owner_name, DNSClass::IN, &rrsig, records)
        .expect("self-check verify_rrsig");

    let rrsig_record = Record::from_rdata(
        owner_name.clone(),
        orig_ttl,
        RData::DNSSEC(DNSSECRData::RRSIG(rrsig.clone())),
    );
    (rrsig, rrsig_record)
}

/// Complete signed DNSSEC fixture across `. -> dev. -> satspath.dev. -> rodrigo.user._bitcoin-payment.satspath.dev.`.
struct SignedDnssecFixture {
    trust_anchor: TrustAnchor,
    chain: Vec<DnssecZoneLink>,
    zone_keypairs: Vec<KeyPair<Private>>,
    txt_owner: Name,
    txt_records: Vec<Record>,
    txt_rrsigs: Vec<RRSIG>,
    txt_rrsig_records: Vec<Record>,
    now: u32,
}

impl SignedDnssecFixture {
    /// Generate an ephemeral DNS signing key for the offline fixture.
    fn gen_ecdsa_keypair() -> KeyPair<Private> {
        let pkcs8 = KeyPair::<Private>::generate_pkcs8(Algorithm::ECDSAP256SHA256)
            .expect("generate pkcs8 ecdsa keypair");
        KeyFormat::Pkcs8
            .decode_key(&pkcs8, None, Algorithm::ECDSAP256SHA256)
            .expect("parse pkcs8 ecdsa keypair")
    }

    /// Build a complete signed root-to-leaf chain for the supplied TXT payload.
    fn build(uri_payload: &str) -> Self {
        Self::build_at(uri_payload, 1_700_000_000)
    }

    /// Build a complete signed root-to-leaf chain for the supplied TXT payload at an explicit timestamp.
    fn build_at(uri_payload: &str, now: u32) -> Self {
        Self::build_txt_records_at(
            vec![TXT::new(vec![uri_payload.to_string()])],
            DigestType::SHA256,
            now,
        )
    }

    /// Build an expired signed root-to-leaf chain whose validity window expired before `now`.
    fn build_expired(uri_payload: &str, now: u32) -> Self {
        let inception = now.saturating_sub(7200);
        let expiration = now.saturating_sub(3600);
        Self::build_with_window(
            vec![TXT::new(vec![uri_payload.to_string()])],
            DigestType::SHA256,
            now,
            inception,
            expiration,
        )
    }

    /// Sign arbitrary TXT bytes and delegation digests without using network services.
    fn build_txt_records(txts: Vec<TXT>, digest_type: DigestType) -> Self {
        Self::build_txt_records_at(txts, digest_type, 1_700_000_000)
    }

    /// Sign arbitrary TXT bytes and delegation digests at an explicit timestamp.
    fn build_txt_records_at(txts: Vec<TXT>, digest_type: DigestType, now: u32) -> Self {
        let inception = now.saturating_sub(3600);
        let expiration = now.saturating_add(86400);
        Self::build_with_window(txts, digest_type, now, inception, expiration)
    }

    /// Sign arbitrary TXT bytes and delegation digests with an explicit validity window.
    fn build_with_window(
        txts: Vec<TXT>,
        digest_type: DigestType,
        now: u32,
        inception: u32,
        expiration: u32,
    ) -> Self {
        // 1. Root zone (.)
        let root_name = Name::from_ascii(".").unwrap();
        let root_kp = Self::gen_ecdsa_keypair();
        let root_dnskey = root_kp.to_dnskey(Algorithm::ECDSAP256SHA256).unwrap();
        let root_dnskey_rec = Record::from_rdata(
            root_name.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::DNSKEY(root_dnskey.clone())),
        );
        let (root_dnskey_rrsig, _) = sign_rrset(
            &root_name,
            &root_name,
            RecordType::DNSKEY,
            std::slice::from_ref(&root_dnskey_rec),
            &root_kp,
            &root_dnskey,
            inception,
            expiration,
        );

        let mut trust_anchor = TrustAnchor::new();
        let root_pk_buf = PublicKeyBuf::new(root_dnskey.public_key().to_vec());
        trust_anchor.insert_trust_anchor(&root_pk_buf);

        // 2. TLD zone (dev.)
        let tld_name = Name::from_ascii("dev.").unwrap();
        let tld_kp = Self::gen_ecdsa_keypair();
        let tld_dnskey = tld_kp.to_dnskey(Algorithm::ECDSAP256SHA256).unwrap();
        let tld_dnskey_rec = Record::from_rdata(
            tld_name.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::DNSKEY(tld_dnskey.clone())),
        );
        let (tld_dnskey_rrsig, _) = sign_rrset(
            &tld_name,
            &tld_name,
            RecordType::DNSKEY,
            std::slice::from_ref(&tld_dnskey_rec),
            &tld_kp,
            &tld_dnskey,
            inception,
            expiration,
        );

        let tld_ds_digest = tld_dnskey
            .to_digest(&tld_name, digest_type)
            .expect("tld digest");
        let tld_ds = DS::new(
            tld_dnskey.calculate_key_tag().unwrap(),
            Algorithm::ECDSAP256SHA256,
            digest_type,
            tld_ds_digest.as_ref().to_vec(),
        );
        let tld_ds_rec = Record::from_rdata(
            tld_name.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::DS(tld_ds)),
        );
        let (tld_ds_rrsig, _) = sign_rrset(
            &tld_name,
            &root_name,
            RecordType::DS,
            std::slice::from_ref(&tld_ds_rec),
            &root_kp,
            &root_dnskey,
            inception,
            expiration,
        );

        // 3. Domain zone (satspath.dev.)
        let domain_name = Name::from_ascii("satspath.dev.").unwrap();
        let domain_kp = Self::gen_ecdsa_keypair();
        let domain_dnskey = domain_kp.to_dnskey(Algorithm::ECDSAP256SHA256).unwrap();
        let domain_dnskey_rec = Record::from_rdata(
            domain_name.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::DNSKEY(domain_dnskey.clone())),
        );
        let (domain_dnskey_rrsig, _) = sign_rrset(
            &domain_name,
            &domain_name,
            RecordType::DNSKEY,
            std::slice::from_ref(&domain_dnskey_rec),
            &domain_kp,
            &domain_dnskey,
            inception,
            expiration,
        );

        let domain_ds_digest = domain_dnskey
            .to_digest(&domain_name, digest_type)
            .expect("domain digest");
        let domain_ds = DS::new(
            domain_dnskey.calculate_key_tag().unwrap(),
            Algorithm::ECDSAP256SHA256,
            digest_type,
            domain_ds_digest.as_ref().to_vec(),
        );
        let domain_ds_rec = Record::from_rdata(
            domain_name.clone(),
            3600,
            RData::DNSSEC(DNSSECRData::DS(domain_ds)),
        );
        let (domain_ds_rrsig, _) = sign_rrset(
            &domain_name,
            &tld_name,
            RecordType::DS,
            std::slice::from_ref(&domain_ds_rec),
            &tld_kp,
            &tld_dnskey,
            inception,
            expiration,
        );

        // 4. Leaf TXT record (rodrigo.user._bitcoin-payment.satspath.dev.)
        let txt_owner = Name::from_ascii("rodrigo.user._bitcoin-payment.satspath.dev.").unwrap();
        let txt_records: Vec<_> = txts
            .into_iter()
            .map(|txt| Record::from_rdata(txt_owner.clone(), 1800, RData::TXT(txt)))
            .collect();
        let (txt_rrsig, txt_rrsig_rec) = sign_rrset(
            &txt_owner,
            &domain_name,
            RecordType::TXT,
            &txt_records,
            &domain_kp,
            &domain_dnskey,
            inception,
            expiration,
        );

        let chain = vec![
            DnssecZoneLink {
                zone_name: root_name,
                dnskey_records: vec![root_dnskey_rec],
                dnskey_rrsigs: vec![root_dnskey_rrsig],
                parent_ds_records: Vec::new(),
                parent_ds_rrsigs: Vec::new(),
            },
            DnssecZoneLink {
                zone_name: tld_name,
                dnskey_records: vec![tld_dnskey_rec],
                dnskey_rrsigs: vec![tld_dnskey_rrsig],
                parent_ds_records: vec![tld_ds_rec],
                parent_ds_rrsigs: vec![tld_ds_rrsig],
            },
            DnssecZoneLink {
                zone_name: domain_name,
                dnskey_records: vec![domain_dnskey_rec],
                dnskey_rrsigs: vec![domain_dnskey_rrsig],
                parent_ds_records: vec![domain_ds_rec],
                parent_ds_rrsigs: vec![domain_ds_rrsig],
            },
        ];

        Self {
            trust_anchor,
            chain,
            zone_keypairs: vec![root_kp, tld_kp, domain_kp],
            txt_owner,
            txt_records,
            txt_rrsigs: vec![txt_rrsig],
            txt_rrsig_records: vec![txt_rrsig_rec],
            now,
        }
    }

    /// Validate this fixture at an explicit time, independent of the wall clock.
    fn verify_at(&self, now: u32) -> satspath_core::Result<Vec<DnsTxtRecord>> {
        verify_dnssec_zone_chain(
            &self.trust_anchor,
            &self.chain,
            &self.txt_owner,
            &self.txt_records,
            &self.txt_rrsigs,
            now,
        )
    }
}

// ─── In-Process Authoritative DNSSEC Fixture Handle ─────────────────────────────

/// Deterministic in-process [`DnsHandle`] serving signed, bogus, and unsigned zones.
#[derive(Clone)]
struct InProcessAuthoritativeDnssecServer {
    records: Arc<Vec<(Name, RecordType, Vec<Record>)>>,
}

impl InProcessAuthoritativeDnssecServer {
    /// Serve fixture records and deliberate invalid variants through a DNS handle.
    fn from_fixture(fixture: &SignedDnssecFixture) -> Self {
        let mut entries = Vec::new();

        for link in &fixture.chain {
            let mut dnskey_ans = link.dnskey_records.clone();
            for sig in &link.dnskey_rrsigs {
                dnskey_ans.push(Record::from_rdata(
                    link.zone_name.clone(),
                    3600,
                    RData::DNSSEC(DNSSECRData::RRSIG(sig.clone())),
                ));
            }
            entries.push((link.zone_name.clone(), RecordType::DNSKEY, dnskey_ans));

            if !link.parent_ds_records.is_empty() {
                let mut ds_ans = link.parent_ds_records.clone();
                for sig in &link.parent_ds_rrsigs {
                    ds_ans.push(Record::from_rdata(
                        link.zone_name.clone(),
                        3600,
                        RData::DNSSEC(DNSSECRData::RRSIG(sig.clone())),
                    ));
                }
                entries.push((link.zone_name.clone(), RecordType::DS, ds_ans));
            }
        }

        // Valid signed TXT record
        let mut valid_txt = fixture.txt_records.clone();
        valid_txt.extend(fixture.txt_rrsig_records.clone());
        entries.push((fixture.txt_owner.clone(), RecordType::TXT, valid_txt));

        // Bogus TXT record (signature corrupted)
        let bogus_name = Name::from_ascii("bogus.user._bitcoin-payment.satspath.dev.").unwrap();
        let bogus_txt_rec = Record::from_rdata(
            bogus_name.clone(),
            1800,
            RData::TXT(TXT::new(vec![
                "bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
            ])),
        );
        let mut corrupted_sig_bytes = fixture.txt_rrsigs[0].sig().to_vec();
        corrupted_sig_bytes[0] ^= 0xff;
        let bogus_rrsig = RRSIG::new(
            RecordType::TXT,
            Algorithm::ECDSAP256SHA256,
            bogus_name.num_labels(),
            1800,
            fixture.txt_rrsigs[0].sig_expiration(),
            fixture.txt_rrsigs[0].sig_inception(),
            fixture.txt_rrsigs[0].key_tag(),
            fixture.txt_rrsigs[0].signer_name().clone(),
            corrupted_sig_bytes,
        );
        let bogus_rrsig_rec = Record::from_rdata(
            bogus_name.clone(),
            1800,
            RData::DNSSEC(DNSSECRData::RRSIG(bogus_rrsig)),
        );
        entries.push((
            bogus_name,
            RecordType::TXT,
            vec![bogus_txt_rec, bogus_rrsig_rec],
        ));

        // Unsigned TXT record (no RRSIG attached)
        let unsigned_name =
            Name::from_ascii("unsigned.user._bitcoin-payment.satspath.dev.").unwrap();
        let unsigned_txt_rec = Record::from_rdata(
            unsigned_name.clone(),
            1800,
            RData::TXT(TXT::new(vec![
                "bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq".to_string(),
            ])),
        );
        entries.push((unsigned_name, RecordType::TXT, vec![unsigned_txt_rec]));

        Self {
            records: Arc::new(entries),
        }
    }
}

impl DnsHandle for InProcessAuthoritativeDnssecServer {
    type Response =
        Pin<Box<dyn Stream<Item = std::result::Result<DnsResponse, ProtoError>> + Send>>;
    type Error = ProtoError;

    /// Answer a query directly from the fixture record set.
    fn send<R: Into<DnsRequest>>(&self, request: R) -> Self::Response {
        let req = request.into();
        let query = req.queries().first().cloned().expect("query present");
        let qname = query.name().clone();
        let qtype = query.query_type();

        let mut msg = Message::new();
        msg.set_id(req.id());
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.set_response_code(ResponseCode::NoError);
        msg.add_query(query);

        for (name, rtype, recs) in self.records.iter() {
            if name == &qname && *rtype == qtype {
                for r in recs {
                    msg.add_answer(r.clone());
                }
            }
        }

        let resp = DnsResponse::from_message(msg).expect("valid DnsResponse");
        Box::pin(stream::once(future::ok(resp)))
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────────

/// Verify bundled trust anchors include the expected ICANN keys.
#[test]
fn test_root_trust_anchors_bundle_active_and_historical_ksks() {
    let anchor = root_trust_anchors();
    assert!(
        anchor.len() >= 3,
        "trust anchor bundle must contain at least 3 root keys (19036, 20326, 38696), found {}",
        anchor.len()
    );

    let ksk_38696_bytes = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        ICANN_ROOT_KSK_38696_B64,
    )
    .unwrap();
    assert!(
        anchor.contains_dnskey_bytes(&ksk_38696_bytes),
        "trust anchor bundle must contain active KSK 38696 key bytes"
    );

    let dnskey_38696 = DNSKEY::new(true, true, false, Algorithm::RSASHA256, ksk_38696_bytes);
    assert_eq!(
        dnskey_38696.calculate_key_tag().unwrap(),
        ICANN_ROOT_KSK_38696_TAG
    );

    // Verify historical/standby KSK 20326 is also present in the default anchor set
    let mut found_20326 = false;
    let mut found_19036 = false;
    for idx in 0..anchor.len() {
        let key_bytes = anchor.get(idx).to_vec();
        let dnskey = DNSKEY::new(true, true, false, Algorithm::RSASHA256, key_bytes);
        if let Ok(tag) = dnskey.calculate_key_tag() {
            if tag == ICANN_ROOT_KSK_20326_TAG {
                found_20326 = true;
            }
            if tag == 19036 {
                found_19036 = true;
            }
        }
    }
    assert!(found_20326, "KSK 20326 must be present in trust anchors");
    assert!(found_19036, "KSK 19036 must be present in trust anchors");
}

/// Validate signed chains and reject tampered data and unsigned delegations.
#[test]
fn test_embedded_dnssec_zone_chain_valid_tampered_and_unsigned() {
    let uri = "bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    let fixture = SignedDnssecFixture::build(uri);

    // 1. Valid 3-zone chain (Root -> dev. -> satspath.dev. -> TXT) succeeds
    let records = verify_dnssec_zone_chain(
        &fixture.trust_anchor,
        &fixture.chain,
        &fixture.txt_owner,
        &fixture.txt_records,
        &fixture.txt_rrsigs,
        fixture.now,
    )
    .expect("valid DNSSEC zone chain must pass cryptographic verification");

    assert_eq!(records.len(), 1);
    assert!(records[0].dnssec_validated);
    assert_eq!(records[0].reconstruct(), uri);

    // 2. Tampered TXT RDATA fails cryptographic RRSIG check
    let tampered_txt = vec![Record::from_rdata(
        fixture.txt_owner.clone(),
        1800,
        RData::TXT(TXT::new(vec![
            "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT".to_string()
        ])),
    )];
    let err = verify_dnssec_zone_chain(
        &fixture.trust_anchor,
        &fixture.chain,
        &fixture.txt_owner,
        &tampered_txt,
        &fixture.txt_rrsigs,
        fixture.now,
    )
    .unwrap_err();
    assert!(matches!(err, SatsPathError::NetworkError(_)));

    // 3. Expired RRSIG fails closed
    let expired_now = fixture.now + 200_000;
    let err_exp = verify_dnssec_zone_chain(
        &fixture.trust_anchor,
        &fixture.chain,
        &fixture.txt_owner,
        &fixture.txt_records,
        &fixture.txt_rrsigs,
        expired_now,
    )
    .unwrap_err();
    assert!(matches!(err_exp, SatsPathError::NetworkError(_)));

    // 4. Unsigned delegation (missing DS record at child zone) fails closed with DnssecUnavailable
    let mut unsigned_chain = fixture.chain.clone();
    unsigned_chain[2].parent_ds_records.clear();
    let err_unsigned = verify_dnssec_zone_chain(
        &fixture.trust_anchor,
        &unsigned_chain,
        &fixture.txt_owner,
        &fixture.txt_records,
        &fixture.txt_rrsigs,
        fixture.now,
    )
    .unwrap_err();
    assert!(matches!(err_unsigned, SatsPathError::DnssecUnavailable));
}

/// Exercise Hickory validation against signed, bogus and unsigned fixture zones.
#[tokio::test]
async fn test_in_process_hickory_dnssec_valid_bogus_and_unsigned() {
    let uri = "bitcoin:bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    const FIXED_TEST_TIME: u32 = 1_700_000_000;
    let fixture = SignedDnssecFixture::build_at(uri, FIXED_TEST_TIME);
    let server = InProcessAuthoritativeDnssecServer::from_fixture(&fixture);
    let resolver = HickoryDnssecTxtResolver::with_dns_handle(server, fixture.trust_anchor.clone());

    // 1. Valid DNSSEC-signed domain resolves and passes Strict mode
    let res = resolve_bip353_with(
        &resolver,
        "₿rodrigo@satspath.dev",
        DnssecPolicy::Strict,
        FIXED_TEST_TIME as i64,
    )
    .await
    .expect("valid signed domain in fixture must resolve in Strict mode");
    assert!(res.dnssec_validated);
    assert_eq!(res.bitcoin_uri, uri);

    // 2. Bogus / tampered RRSIG domain fails closed
    let bogus_err = resolve_bip353_with(
        &resolver,
        "₿bogus@satspath.dev",
        DnssecPolicy::Strict,
        FIXED_TEST_TIME as i64,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(bogus_err, SatsPathError::NetworkError(ref msg) if msg.contains("DNSSEC validation failed")),
        "expected DNSSEC validation failure for bogus domain, got: {bogus_err:?}"
    );

    // 3. Unsigned domain specifically fails with DnssecUnavailable
    let unsigned_err = resolve_bip353_with(
        &resolver,
        "₿unsigned@satspath.dev",
        DnssecPolicy::Strict,
        FIXED_TEST_TIME as i64,
    )
    .await
    .unwrap_err();
    assert!(
        matches!(unsigned_err, SatsPathError::DnssecUnavailable),
        "expected DnssecUnavailable for unsigned domain, got: {unsigned_err:?}"
    );

    // 4. Expired RRSIG domain fails closed under Strict mode
    let expired_fixture = SignedDnssecFixture::build_expired(uri, FIXED_TEST_TIME);
    let expired_err = expired_fixture.verify_at(FIXED_TEST_TIME).unwrap_err();
    assert!(
        matches!(expired_err, SatsPathError::NetworkError(ref msg) if msg.contains("DNSSEC") && (msg.contains("verification failed") || msg.contains("validation failed") || msg.contains("no valid RRSIG verified"))),
        "expected expired RRSIG to fail validation under Strict policy, got: {expired_err:?}"
    );
}

/// Accept authenticated profile pointers and reject instructions without a profile.
#[tokio::test]
async fn test_bip353_resolver_sp_profile_ownership_and_unauthenticated_fallback() {
    let mut server = mockito::Server::new_async().await;
    let kp = generate_identity_keypair();
    let pubkey_hex = hex::encode(kp.public_key.serialize());
    let onchain_addr = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";

    let profile = PaymentProfile {
        alias: "rodrigo@satspath.dev".to_string(),
        identity_pubkey: pubkey_hex,
        methods: vec![PaymentMethod::Onchain {
            label: "Primary".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some(onchain_addr.to_string()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: Vec::new(),
        }],
        updated_at: 1_700_000_000,
        expires_at: None,
        sequence: Some(1),
        preferences: Vec::new(),
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
    let body = serde_json::to_string(&signed).unwrap();

    let mock = server
        .mock("GET", "/.well-known/satspath/rodrigo")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(body)
        .create_async()
        .await;

    let sp_profile_url = format!("{}/.well-known/satspath/rodrigo", server.url());
    let uri_with_profile = format!("bitcoin:{onchain_addr}?sp-profile={sp_profile_url}");

    let mut dns = MockDnsTxtResolver::new();
    dns.insert(
        "rodrigo.user._bitcoin-payment.satspath.dev",
        DnsTxtRecord {
            strings: vec![uri_with_profile],
            dnssec_validated: true,
            ttl_seconds: Some(600),
        },
    );
    // Default resolver (allow_private = false) rejects loopback / private sp-profile with SsrfViolation
    let continuity_ssrf = tempfile::tempdir().unwrap();
    let resolver_ssrf =
        Bip353Resolver::with_dns_resolver(Arc::new(dns.clone()), continuity_ssrf.path());
    let ssrf_err = resolver_ssrf
        .resolve_alias("₿rodrigo@satspath.dev")
        .await
        .unwrap_err();
    assert!(
        matches!(ssrf_err, SatsPathError::ValidationError(_)),
        "expected ValidationError for unconfigured private sp-profile, got: {ssrf_err:?}"
    );

    let continuity = tempfile::tempdir().unwrap();
    let resolver = Bip353Resolver::with_dns_resolver(Arc::new(dns), continuity.path())
        .with_allow_private_profile_url(true);
    let resolved_profile = resolver
        .resolve_alias("₿rodrigo@satspath.dev")
        .await
        .expect("sp-profile with valid signature and ownership must resolve");
    assert_eq!(resolved_profile.profile.alias, "rodrigo@satspath.dev");
    mock.assert_async().await;

    // With matching sp-profile-hash, resolution succeeds
    let profile_hash = satspath_core::signed_profile_hash(&signed).unwrap();
    let uri_with_matching_hash = format!(
        "bitcoin:{onchain_addr}?sp-profile={sp_profile_url}&sp-profile-hash={profile_hash}"
    );
    let mut dns_hash_match = MockDnsTxtResolver::new();
    dns_hash_match.insert(
        "rodrigo.user._bitcoin-payment.satspath.dev",
        DnsTxtRecord {
            strings: vec![uri_with_matching_hash],
            dnssec_validated: true,
            ttl_seconds: Some(600),
        },
    );
    let continuity_match = tempfile::tempdir().unwrap();
    let resolver_hash_match =
        Bip353Resolver::with_dns_resolver(Arc::new(dns_hash_match), continuity_match.path())
            .with_allow_private_profile_url(true);
    let res_hash = resolver_hash_match
        .resolve_alias("₿rodrigo@satspath.dev")
        .await
        .expect("matching sp-profile-hash must succeed");
    assert_eq!(res_hash.profile.alias, "rodrigo@satspath.dev");

    // With mismatched sp-profile-hash, resolution fails closed with OwnershipProofInvalid
    let mismatched_hash = "0000000000000000000000000000000000000000000000000000000000000000";
    let uri_with_mismatched_hash = format!(
        "bitcoin:{onchain_addr}?sp-profile={sp_profile_url}&sp-profile-hash={mismatched_hash}"
    );
    let mut dns_hash_mismatch = MockDnsTxtResolver::new();
    dns_hash_mismatch.insert(
        "rodrigo.user._bitcoin-payment.satspath.dev",
        DnsTxtRecord {
            strings: vec![uri_with_mismatched_hash],
            dnssec_validated: true,
            ttl_seconds: Some(600),
        },
    );
    let continuity_mismatch = tempfile::tempdir().unwrap();
    let resolver_hash_mismatch =
        Bip353Resolver::with_dns_resolver(Arc::new(dns_hash_mismatch), continuity_mismatch.path())
            .with_allow_private_profile_url(true);
    let mismatch_err = resolver_hash_mismatch
        .resolve_alias("₿rodrigo@satspath.dev")
        .await
        .unwrap_err();
    assert!(
        matches!(mismatch_err, SatsPathError::OwnershipProofInvalid(_)),
        "expected OwnershipProofInvalid for mismatched sp-profile-hash, got: {mismatch_err:?}"
    );

    // Without sp-profile pointer, resolve_alias must return Bip353Unauthenticated (never a synthetic profile)
    let mut dns_no_profile = MockDnsTxtResolver::new();
    dns_no_profile.insert(
        "rodrigo.user._bitcoin-payment.satspath.dev",
        DnsTxtRecord {
            strings: vec![format!("bitcoin:{onchain_addr}")],
            dnssec_validated: true,
            ttl_seconds: Some(600),
        },
    );
    let resolver_no_profile =
        Bip353Resolver::with_dns_resolver(Arc::new(dns_no_profile), continuity.path());
    let unauth_err = resolver_no_profile
        .resolve_alias("₿rodrigo@satspath.dev")
        .await
        .unwrap_err();
    assert!(matches!(unauth_err, SatsPathError::Bip353Unauthenticated));

    // ChainResolver must also surface Bip353Unauthenticated or AliasNotFound cleanly without synthetic keys
    let chain = ChainResolver::new().push(resolver_no_profile);
    assert!(chain.resolve_alias("₿rodrigo@satspath.dev").await.is_err());
}

/// Each signature window includes both endpoints and excludes adjacent seconds.
#[test]
fn signature_validity_window_boundaries() {
    let fixture = SignedDnssecFixture::build("bitcoin:?lno=offer");
    let inception = fixture.txt_rrsigs[0].sig_inception();
    let expiration = fixture.txt_rrsigs[0].sig_expiration();
    for now in [inception, fixture.now, expiration] {
        assert!(fixture.verify_at(now).is_ok(), "valid time: {now}");
    }
    for now in [inception - 1, expiration + 1] {
        assert!(matches!(
            fixture.verify_at(now),
            Err(SatsPathError::NetworkError(_))
        ));
    }
}

/// No zone may omit its DNSKEY RRset, self-signature, or authenticated delegation.
#[test]
fn missing_authentication_at_every_zone_fails_closed() {
    let mut fixture = SignedDnssecFixture::build("bitcoin:?lno=offer");
    let original = fixture.chain.clone();
    for zone in 0..original.len() {
        for component in ["dnskeys", "dnskey signatures", "ds", "ds signatures"] {
            if zone == 0 && component.starts_with("ds") {
                continue;
            }
            fixture.chain = original.clone();
            let link = &mut fixture.chain[zone];
            match component {
                "dnskeys" => link.dnskey_records.clear(),
                "dnskey signatures" => link.dnskey_rrsigs.clear(),
                "ds" => link.parent_ds_records.clear(),
                "ds signatures" => link.parent_ds_rrsigs.clear(),
                _ => unreachable!(),
            }
            assert!(
                matches!(
                    fixture.verify_at(fixture.now),
                    Err(SatsPathError::DnssecUnavailable)
                ),
                "zone {zone} missing {component} must fail closed"
            );
        }
    }
}

/// An empty chain or missing leaf data cannot authenticate a TXT answer.
#[test]
fn missing_chain_or_leaf_records_fails_closed() {
    for missing in ["chain", "records", "signatures"] {
        let mut fixture = SignedDnssecFixture::build("bitcoin:?lno=offer");
        match missing {
            "chain" => fixture.chain.clear(),
            "records" => fixture.txt_records.clear(),
            "signatures" => fixture.txt_rrsigs.clear(),
            _ => unreachable!(),
        }
        assert!(matches!(
            fixture.verify_at(fixture.now),
            Err(SatsPathError::DnssecUnavailable)
        ));
    }
}

/// A self-consistent chain is insufficient unless the root key is trusted.
#[test]
fn untrusted_root_is_rejected() {
    let mut fixture = SignedDnssecFixture::build("bitcoin:?lno=offer");
    fixture.trust_anchor = TrustAnchor::new();
    assert!(matches!(
        fixture.verify_at(fixture.now),
        Err(SatsPathError::NetworkError(message)) if message.contains("root DNSKEY")
    ));
}

/// A child key must match the authenticated DS before its self-signature is trusted.
#[test]
fn substituted_child_dnskey_is_rejected_at_each_delegation() {
    for zone in [1, 2] {
        let mut fixture = SignedDnssecFixture::build("bitcoin:?lno=offer");
        let replacement = SignedDnssecFixture::gen_ecdsa_keypair()
            .to_dnskey(Algorithm::ECDSAP256SHA256)
            .unwrap();
        fixture.chain[zone].dnskey_records[0]
            .set_data(Some(RData::DNSSEC(DNSSECRData::DNSKEY(replacement))));
        assert!(matches!(
            fixture.verify_at(fixture.now),
            Err(SatsPathError::NetworkError(message)) if message.contains("matches parent DS")
        ));
    }
}

/// A correctly signed DS RRset still fails if its digest does not cover the child key.
#[test]
fn authenticated_but_mismatched_ds_digest_is_rejected() {
    for zone in [1, 2] {
        let mut fixture = SignedDnssecFixture::build("bitcoin:?lno=offer");
        let record = &mut fixture.chain[zone].parent_ds_records[0];
        let Some(RData::DNSSEC(DNSSECRData::DS(ds))) = record.data() else {
            panic!("fixture must contain a DS record");
        };
        let mut digest = ds.digest().to_vec();
        digest[0] ^= 0xff;
        let wrong_ds = DS::new(ds.key_tag(), ds.algorithm(), ds.digest_type(), digest);
        record.set_data(Some(RData::DNSSEC(DNSSECRData::DS(wrong_ds))));

        let parent = &fixture.chain[zone - 1];
        let Some(RData::DNSSEC(DNSSECRData::DNSKEY(parent_key))) = parent.dnskey_records[0].data()
        else {
            panic!("fixture must contain a parent DNSKEY");
        };
        let child = &fixture.chain[zone];
        let (signature, _) = sign_rrset(
            &child.zone_name,
            &parent.zone_name,
            RecordType::DS,
            &child.parent_ds_records,
            &fixture.zone_keypairs[zone - 1],
            parent_key,
            fixture.now - 3600,
            fixture.now + 86400,
        );
        fixture.chain[zone].parent_ds_rrsigs = vec![signature];
        assert!(matches!(
            fixture.verify_at(fixture.now),
            Err(SatsPathError::NetworkError(message)) if message.contains("matches parent DS")
        ));
    }
}

/// Preserve metadata while corrupting the cryptographic proof itself.
fn corrupt_signature(sig: &RRSIG) -> RRSIG {
    let mut bytes = sig.sig().to_vec();
    bytes[0] ^= 0xff;
    RRSIG::new(
        sig.type_covered(),
        sig.algorithm(),
        sig.num_labels(),
        sig.original_ttl(),
        sig.sig_expiration(),
        sig.sig_inception(),
        sig.key_tag(),
        sig.signer_name().clone(),
        bytes,
    )
}

/// Corruption at any DNSKEY or DS link must not be masked by a valid leaf signature.
#[test]
fn corrupt_signatures_at_every_zone_fail_closed() {
    for zone in 0..3 {
        for delegation in [false, true] {
            if zone == 0 && delegation {
                continue;
            }
            let mut fixture = SignedDnssecFixture::build("bitcoin:?lno=offer");
            let signatures = if delegation {
                &mut fixture.chain[zone].parent_ds_rrsigs
            } else {
                &mut fixture.chain[zone].dnskey_rrsigs
            };
            signatures[0] = corrupt_signature(&signatures[0]);
            assert!(matches!(
                fixture.verify_at(fixture.now),
                Err(SatsPathError::NetworkError(_))
            ));
        }
    }
}

/// During rollover, a bad candidate must not hide another valid signature.
#[test]
fn valid_signature_after_invalid_candidate_is_accepted() {
    let mut fixture = SignedDnssecFixture::build("bitcoin:?lno=offer");
    for link in &mut fixture.chain {
        link.dnskey_rrsigs
            .insert(0, corrupt_signature(&link.dnskey_rrsigs[0]));
        if !link.parent_ds_rrsigs.is_empty() {
            link.parent_ds_rrsigs
                .insert(0, corrupt_signature(&link.parent_ds_rrsigs[0]));
        }
    }
    fixture
        .txt_rrsigs
        .insert(0, corrupt_signature(&fixture.txt_rrsigs[0]));
    assert!(fixture.verify_at(fixture.now).is_ok());
}

/// SHA-384 delegations must work as well as the fixture's default SHA-256 digests.
#[test]
fn sha384_delegations_preserve_txt_chunks_records_and_ttls() {
    let fixture = SignedDnssecFixture::build_txt_records(
        vec![
            TXT::new(vec!["bit".into(), "coin:?lno=".into(), "offer".into()]),
            TXT::new(vec!["unrelated TXT record".into()]),
        ],
        DigestType::SHA384,
    );
    let records = fixture.verify_at(fixture.now).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].strings, ["bit", "coin:?lno=", "offer"]);
    assert_eq!(records[0].reconstruct(), "bitcoin:?lno=offer");
    assert_eq!(records[1].reconstruct(), "unrelated TXT record");
    assert!(records
        .iter()
        .all(|record| record.dnssec_validated && record.ttl_seconds == Some(1800)));
}

/// DNSSEC authentication does not make binary TXT data valid UTF-8.
#[test]
fn signed_non_utf8_txt_is_rejected() {
    let fixture = SignedDnssecFixture::build_txt_records(
        vec![TXT::from_bytes(vec![b"bitcoin:", &[0xff]])],
        DigestType::SHA256,
    );
    assert!(matches!(
        fixture.verify_at(fixture.now),
        Err(SatsPathError::Bip353(message)) if message.contains("UTF-8")
    ));
}

// ─── Optional Live Network DNSSEC Smoke Tests (Ignored in Offline CI) ───────────

/// Optionally verify a live signed domain against the bundled root anchors.
#[tokio::test]
#[ignore = "Live external network DNS test; run explicitly with -- --ignored"]
async fn test_live_dnssec_signed_domain() {
    let resolver = HickoryDnssecTxtResolver::new();
    let records = resolver
        .query_txt("cloudflare.com")
        .await
        .expect("cloudflare.com must pass local DNSSEC validation");
    assert!(!records.is_empty());
    assert!(records.iter().all(|r| r.dnssec_validated));
}

/// Optionally confirm a live bogus DNSSEC domain fails closed.
#[tokio::test]
#[ignore = "Live external network DNS test; run explicitly with -- --ignored"]
async fn test_live_dnssec_bogus_domain_fails_closed() {
    let resolver = HickoryDnssecTxtResolver::new();
    let res = resolver.query_txt("dnssec-failed.org").await;
    assert!(res.is_err());
}
