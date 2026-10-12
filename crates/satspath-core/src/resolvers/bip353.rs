//! BIP-353 DNSSEC validating resolver and adapter for SatsPath.
//!
//! Provides local cryptographic DNSSEC chain validation rooted in bundled
//! ICANN root trust anchors (KSK 19036, 20326, and active 38696), guaranteeing
//! that payment instructions are verified locally rather than trusting
//! an upstream resolver's AD (Authenticated Data) bit.
//!
//! BIP-353 names (`₿user@domain`) resolve to authenticated DNS payment
//! instructions, NOT cryptographic SatsPath profile identities (unless
//! explicitly linked via an `sp-profile` pointer verified by ownership proofs).
//! This resolver strictly preserves this boundary and never synthesizes
//! fake profile signatures.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use async_trait::async_trait;
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::{GenericConnector, NameServerPool, TokioRuntimeProvider};
use hickory_resolver::proto::op::Query;
use hickory_resolver::proto::rr::dnssec::public_key::Rsa;
use hickory_resolver::proto::rr::dnssec::TrustAnchor;
use hickory_resolver::proto::rr::{Name, RecordType};
use hickory_resolver::proto::xfer::{
    DnsHandle, DnsRequestOptions, DnssecDnsHandle, FirstAnswer, RetryDnsHandle,
};

use crate::bip353::{
    resolve_bip353_with, Bip353Resolution, DnsTxtRecord, DnsTxtResolver, DnssecPolicy,
};
use crate::resolver::ProfileResolver;
use crate::{Result, SatsPathError, SignedPaymentProfile};

/// Return the set of trusted DNSSEC root trust anchors.
///
/// Combines Hickory's default historical trust anchors (including KSK 19036 and 20326)
/// with the explicitly bundled active ICANN KSK (Key tag 38696) to enable autonomous
/// validation of the root zone `.` without relying on upstream server trust.
pub fn root_trust_anchors() -> TrustAnchor {
    let mut anchor = TrustAnchor::default();
    // ICANN Root Key Signing Key (KSK 2024-2026, Key Tag 38696)
    // RFC 3110 format RSA public key bytes (exponent + modulus).
    const KSK_38696_B64: &str = "AwEAAa96jeuknZlaeSrvyAJj6ZHv28hhOKkx3rLGXVaC6rXTsDc449/cidltpkyGwCJNnOAlFNKF2jBosZBU5eeHspaQWOmOElZsjICMQMC3aeHbGiShvZsx4wMYSjH8e7Vrhbu6irwCzVBApESjbUdpWWmEnhathWu1jo+siFUiRAAxm9qyJNg/wOZqqzL/dL/q8PkcRU5oUKEpUge71M3ej2/7CPqpdVwuMoTvoB+ZOT4YeGyxMvHmbrxlFzGOHOijtzN+u1TQNatX2XBuzZNQ1K+s2CXkPIZo7s6JgZyvaBevYtxPvYLw4z9mR7K2vaF18UYH9Z9GNUUeayffKC73PYc=";
    let ksk_bytes =
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, KSK_38696_B64)
            .expect("embedded ICANN root KSK base64 must decode");
    let rsa = Rsa::from_public_bytes(&ksk_bytes)
        .expect("embedded ICANN root KSK must parse as valid RSA public key");
    anchor.insert_trust_anchor(&rsa);
    anchor
}

/// Construct a resilient multi-provider recursive resolver configuration.
///
/// Configures Cloudflare (1.0.0.1, 1.1.1.1), Quad9 (9.9.9.9, 149.112.112.112),
/// and Google (8.8.8.8, 8.8.4.4) over both TCP and UDP. TCP support is
/// essential to handle DNSSEC responses that exceed UDP buffer sizes and to
/// survive restrictive networks where UDP port 53 is filtered or blocked.
pub fn default_resolver_config() -> ResolverConfig {
    let mut config = ResolverConfig::new();
    let servers = [
        // Cloudflare (1.0.0.1 prioritized over 1.1.1.1 to avoid local IP routing conflicts)
        (IpAddr::V4(Ipv4Addr::new(1, 0, 0, 1)), 53),
        (IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
        // Quad9 (Security & DNSSEC focused)
        (IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53),
        (IpAddr::V4(Ipv4Addr::new(149, 112, 112, 112)), 53),
        // Google Public DNS
        (IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
        (IpAddr::V4(Ipv4Addr::new(8, 8, 4, 4)), 53),
    ];
    for (ip, port) in servers {
        config.add_name_server(NameServerConfig {
            socket_addr: SocketAddr::new(ip, port),
            protocol: Protocol::Tcp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        });
        config.add_name_server(NameServerConfig {
            socket_addr: SocketAddr::new(ip, port),
            protocol: Protocol::Udp,
            tls_dns_name: None,
            trust_negative_responses: false,
            bind_addr: None,
        });
    }
    config
}

/// A local DNSSEC-validating DNS TXT resolver.
///
/// Performs full cryptographic signature and trust chain verification locally
/// using Hickory DNS and bundled root trust anchors.
#[derive(Clone)]
pub struct HickoryDnssecTxtResolver {
    handle: DnssecDnsHandle<RetryDnsHandle<NameServerPool<GenericConnector<TokioRuntimeProvider>>>>,
}

impl Default for HickoryDnssecTxtResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl HickoryDnssecTxtResolver {
    /// Construct a resolver with the default multi-provider pool and bundled trust anchors.
    pub fn new() -> Self {
        Self::with_config(default_resolver_config(), root_trust_anchors())
    }

    /// Construct a resolver with custom server configuration and trust anchors.
    pub fn with_config(config: ResolverConfig, anchor: TrustAnchor) -> Self {
        let mut opts = ResolverOpts::default();
        opts.validate = true;
        opts.attempts = 3;
        opts.timeout = std::time::Duration::from_secs(5);
        let conn_provider = GenericConnector::new(TokioRuntimeProvider::new());
        let pool = NameServerPool::from_config(
            NameServerConfigGroup::from(config.name_servers().to_vec()),
            opts.clone(),
            conn_provider,
        );
        let client = RetryDnsHandle::new(pool, opts.attempts);
        let handle = DnssecDnsHandle::with_trust_anchor(client, anchor);
        Self { handle }
    }
}

#[async_trait]
impl DnsTxtResolver for HickoryDnssecTxtResolver {
    async fn query_txt(&self, fqdn: &str) -> Result<Vec<DnsTxtRecord>> {
        let name_str = if fqdn.ends_with('.') {
            fqdn.to_string()
        } else {
            format!("{fqdn}.")
        };
        let name = Name::from_ascii(&name_str)
            .map_err(|e| SatsPathError::Bip353(format!("invalid DNS name `{fqdn}`: {e}")))?;

        let query = Query::query(name, RecordType::TXT);
        let stream = self.handle.lookup(query, DnsRequestOptions::default());
        let response = stream.first_answer().await.map_err(|e| {
            SatsPathError::NetworkError(format!("DNSSEC validation failed for `{fqdn}`: {e}"))
        })?;

        if response.response_code() != hickory_resolver::proto::op::ResponseCode::NoError {
            return Err(SatsPathError::NetworkError(format!(
                "DNSSEC validation failed for `{fqdn}`: response code {:?}",
                response.response_code()
            )));
        }

        let mut out = Vec::new();
        for record in response.answers() {
            if let Some(txt) = record.data().and_then(|d| d.as_txt()) {
                let strings = txt
                    .iter()
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();
                out.push(DnsTxtRecord {
                    strings,
                    // Record was verified cryptographically by DnssecDnsHandle
                    dnssec_validated: true,
                    ttl_seconds: Some(record.ttl()),
                });
            }
        }
        Ok(out)
    }
}

/// BIP-353 payment instruction resolver and adapter for the SatsPath resolver chain.
pub struct Bip353Resolver {
    dns: Arc<dyn DnsTxtResolver + Send + Sync>,
}

impl Default for Bip353Resolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Bip353Resolver {
    /// Construct a BIP-353 resolver backed by `HickoryDnssecTxtResolver`.
    pub fn new() -> Self {
        Self::with_dns_resolver(Arc::new(HickoryDnssecTxtResolver::new()))
    }

    /// Construct a BIP-353 resolver backed by a caller-supplied TXT backend (e.g. for testing).
    pub fn with_dns_resolver(dns: Arc<dyn DnsTxtResolver + Send + Sync>) -> Self {
        Self { dns }
    }

    /// DNSSEC is mandatory for trustworthy operation.
    pub fn dnssec_required(&self) -> bool {
        true
    }

    /// Resolve a BIP-353 name to its DNSSEC-validated payment instruction.
    /// Fails closed if DNSSEC cannot be validated.
    pub async fn resolve_instruction(&self, name: &str) -> Result<Bip353Resolution> {
        let now = chrono::Utc::now().timestamp();
        resolve_bip353_with(self.dns.as_ref(), name, DnssecPolicy::Strict, now).await
    }
}

#[async_trait]
impl ProfileResolver for Bip353Resolver {
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
        if !alias.trim_start().starts_with('₿') {
            return Err(SatsPathError::AliasNotFound(alias.to_string()));
        }

        // Attempt resolving the BIP-353 DNS instruction
        let resolution = self.resolve_instruction(alias).await?;

        // If the instruction contains an `sp-profile` pointer, fetch and verify
        // the SatsPath profile signature.
        let parsed = crate::bip321::parse_bip321(&resolution.bitcoin_uri)?;
        if let Some(profile_url) = parsed.sp_profile {
            #[cfg(feature = "std")]
            {
                crate::ssrf::validate_url(&profile_url, false)?;

                // Resolve hostname and verify no private or reserved IPs (prevent DNS rebinding)
                let parsed_url = url::Url::parse(&profile_url).map_err(|e| {
                    SatsPathError::ValidationError(format!("invalid sp-profile URL: {e}"))
                })?;
                if let Some(host) = parsed_url.host_str() {
                    let port = parsed_url.port_or_known_default().unwrap_or(443);
                    let addrs: Vec<std::net::SocketAddr> =
                        tokio::net::lookup_host(format!("{host}:{port}"))
                            .await
                            .map_err(|e| {
                                SatsPathError::NetworkError(format!(
                                    "DNS resolution failed for {host}: {e}"
                                ))
                            })?
                            .collect();
                    for addr in &addrs {
                        if crate::ssrf::is_private_or_reserved_ip(addr.ip()) {
                            return Err(SatsPathError::ValidationError(format!(
                                "Blocked resolved IP for {host}: {} (private/reserved range)",
                                addr.ip()
                            )));
                        }
                    }
                }

                // Fetch using HttpResolver (enforces redirect=none, 50KB DoS bound, signature & expiry check)
                let http_resolver = crate::resolvers::http::HttpResolver::new();
                let signed = http_resolver.resolve_from_url(&profile_url).await?;

                if signed.profile.revoked {
                    return Err(SatsPathError::RegistryError("profile is revoked".into()));
                }

                if crate::bip353::verify_bip353_ownership(&resolution, &signed)? {
                    return Ok(signed);
                } else {
                    return Err(SatsPathError::OwnershipProofInvalid(
                        "BIP-353 sp-profile ownership verification failed".into(),
                    ));
                }
            }
        }

        // BIP-353 names without an sp-profile pointer authenticate payment methods
        // for a domain, not a cryptographic profile identity key. We never fabricate
        // synthetic profiles with random keypairs.
        // Return AliasNotFound so callers or ChainResolver can continue or report.
        Err(SatsPathError::AliasNotFound(format!(
            "BIP-353 name `{alias}` resolved to a DNS payment instruction without an sp-profile pointer; \
             resolve with `satspath dns resolve`"
        )))
    }
}
