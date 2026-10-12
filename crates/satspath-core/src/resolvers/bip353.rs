use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;

use crate::bip353::{parse_bip353_name, validated_bitcoin_record, DnsTxtRecord, DnsTxtResolver};
use crate::resolver::ProfileResolver;
use crate::{Result, SatsPathError, SignedPaymentProfile};

/// DNS discovery adapter. DNS payment instructions alone cannot authenticate a
/// SatsPath profile, so `resolve_alias` fails with `Bip353Unauthenticated` after
/// validating the records. Use `resolve_bip353_with` for policy-controlled previews.
pub struct Bip353Resolver {
    dnssec_required: bool,
    resolver: TokioAsyncResolver,
}

impl Default for Bip353Resolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Bip353Resolver {
    pub fn new() -> Self {
        let mut opts = ResolverOpts::default();
        opts.validate = true; // Enable Hickory validation; this is not DnssecPolicy.
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts);
        Self {
            dnssec_required: true,
            resolver,
        }
    }

    pub fn dnssec_required(&self) -> bool {
        self.dnssec_required
    }
}

#[async_trait]
impl DnsTxtResolver for Bip353Resolver {
    async fn query_txt(&self, fqdn: &str) -> Result<Vec<DnsTxtRecord>> {
        let lookup = self
            .resolver
            .lookup(fqdn, RecordType::TXT)
            .await
            .map_err(|e| SatsPathError::NetworkError(format!("BIP-353 DNS lookup failed: {e}")))?;

        lookup
            .iter()
            .filter_map(|rdata| rdata.as_txt())
            .map(|txt| {
                // Decode only after joining the bytes: a UTF-8 sequence may span
                // character-strings. Never join separate resource records.
                let bytes = txt.iter().flat_map(|part| part.iter().copied()).collect();
                let payload = String::from_utf8(bytes)
                    .map_err(|_| SatsPathError::Bip353("TXT record is not UTF-8".into()))?;
                Ok(DnsTxtRecord {
                    strings: vec![payload],
                    // This adapter does not expose per-record DNSSEC proof.
                    dnssec_validated: false,
                    ttl_seconds: None,
                })
            })
            .collect()
    }
}

async fn resolve_alias_with(
    resolver: &(impl DnsTxtResolver + Sync),
    alias: &str,
) -> Result<SignedPaymentProfile> {
    if !alias.starts_with('₿') {
        return Err(SatsPathError::AliasNotFound(alias.to_string()));
    }
    let name =
        parse_bip353_name(alias).map_err(|_| SatsPathError::AliasNotFound(alias.to_string()))?;
    let records = resolver.query_txt(&name.dns_name).await?;
    validated_bitcoin_record(&records)?;

    // ProfileResolver cannot represent unsigned payment instructions. A local
    // signature would invent an identity and reset profile continuity on every
    // lookup. Fail closed until authenticated profile retrieval is supported.
    Err(SatsPathError::Bip353Unauthenticated)
}

#[async_trait]
impl ProfileResolver for Bip353Resolver {
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
        resolve_alias_with(self, alias).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bip353::MockDnsTxtResolver;

    fn resolver(records: &[&[&str]]) -> MockDnsTxtResolver {
        let mut resolver = MockDnsTxtResolver::new();
        for strings in records {
            resolver.insert(
                "alice.user._bitcoin-payment.example.com",
                DnsTxtRecord {
                    strings: strings.iter().map(|s| s.to_string()).collect(),
                    dnssec_validated: true,
                    ttl_seconds: Some(60),
                },
            );
        }
        resolver
    }

    #[tokio::test]
    async fn invalid_aliases_remain_not_found() {
        let resolver = Bip353Resolver::new();
        for alias in [
            "alice@example.com",
            "₿@example.com",
            "₿alice@",
            "₿alice@example.com@other.com",
            "₿₿alice@example.com",
            "₿ali.ce@example.com",
            "₿alice@-example.com",
            "₿alice@example..com",
            "₿álîce@example.com",
        ] {
            assert!(matches!(
                resolver.resolve_alias(alias).await,
                Err(SatsPathError::AliasNotFound(value)) if value == alias
            ));
        }
    }

    #[tokio::test]
    async fn chunked_dns_instructions_never_become_a_signed_profile() {
        let resolver = resolver(&[&["unrelated TXT"], &["bit", "coin:?lno=lno1", "offer"]]);
        // The mock only answers the validated DNS name, including trimmed parts.
        for alias in ["₿alice@example.com", "₿alice @ example.com"] {
            for _ in 0..2 {
                assert!(matches!(
                    resolve_alias_with(&resolver, alias).await,
                    Err(SatsPathError::Bip353Unauthenticated)
                ));
            }
        }
    }

    #[tokio::test]
    async fn rejects_ambiguous_records_including_chunked_schemes() {
        let resolver = resolver(&[
            &["bitcoin:?lno=lno1first"],
            &["bit", "coin:?lno=lno1second"],
        ]);
        assert!(matches!(
            resolve_alias_with(&resolver, "₿alice@example.com").await,
            Err(SatsPathError::Bip353(message)) if message.contains("multiple")
        ));
    }

    #[tokio::test]
    async fn does_not_join_separate_resource_records() {
        let resolver = resolver(&[&["bit"], &["coin:?lno=lno1offer"]]);
        assert!(matches!(
            resolve_alias_with(&resolver, "₿alice@example.com").await,
            Err(SatsPathError::Bip353(message)) if message.contains("no bitcoin:")
        ));
    }

    #[tokio::test]
    async fn validates_reconstructed_payload_before_profile_resolution() {
        let required = resolver(&[&["bitcoin:?lno=lno1offer&req-", "future=1"]]);
        assert!(matches!(
            resolve_alias_with(&required, "₿alice@example.com").await,
            Err(SatsPathError::InvalidPaymentUri(_))
        ));
        let private = resolver(&[&["bitcoin:?lno=lno1offer&note=x", "prv123"]]);
        assert!(matches!(
            resolve_alias_with(&private, "₿alice@example.com").await,
            Err(SatsPathError::PrivateMaterialRejected(_))
        ));
    }
}
