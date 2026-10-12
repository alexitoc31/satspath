//! HTTP Host validation independent of CORS and forwarded client-IP headers.

use std::net::{IpAddr, SocketAddr};

use anyhow::{bail, Result};
use tiny_http::Header;
use url::{Host, Url};

fn normalized_host(host: Host<&str>) -> Host<String> {
    match host {
        Host::Domain(name) => Host::Domain(name.trim_end_matches('.').to_ascii_lowercase()),
        Host::Ipv4(ip) => Host::Ipv4(ip),
        Host::Ipv6(ip) => Host::Ipv6(ip),
    }
}

pub(crate) fn parse_authority(authority: &str) -> Result<Host<String>> {
    if authority.is_empty()
        || authority
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
        || authority.contains(['/', '\\', '@', '?', '#', ',', '*', '%'])
    {
        bail!("invalid HTTP Host");
    }
    let url = Url::parse(&format!("http://{authority}"))?;
    let host = url
        .host()
        .ok_or_else(|| anyhow::anyhow!("missing HTTP Host"))?;
    Ok(normalized_host(host))
}

/// Explicit public names for native TLS or a reverse proxy preserving Host.
/// Forwarded headers and --behind-proxy never authorize arbitrary hostnames.
pub(crate) fn configured_hosts(
    domain: Option<&str>,
    authority_url: Option<&str>,
) -> Result<Vec<String>> {
    let mut hosts = Vec::new();
    if let Some(domain) = domain {
        for part in domain.split(',') {
            let trimmed = part.trim();
            if !trimmed.is_empty() {
                hosts.push(parse_authority(trimmed)?.to_string());
            }
        }
    }
    if let Some(authority_url) = authority_url {
        let url = Url::parse(authority_url)?;
        if !matches!(url.scheme(), "http" | "https")
            || !url.username().is_empty()
            || url.password().is_some()
        {
            bail!("SATSPATH_AUTHORITY_URL must be an HTTP(S) URL without credentials");
        }
        let host = url
            .host()
            .ok_or_else(|| anyhow::anyhow!("authority URL has no host"))?;
        hosts.push(normalized_host(host).to_string());
    }
    Ok(hosts)
}

pub(crate) fn is_allowed_host(
    headers: &[Header],
    bind: SocketAddr,
    allowed_hosts: &[String],
) -> bool {
    let mut headers = headers.iter().filter(|header| header.field.equiv("Host"));
    let Some(header) = headers.next() else {
        return false;
    };
    if headers.next().is_some() {
        return false;
    }
    let Ok(host) = parse_authority(header.value.as_str()) else {
        return false;
    };
    if allowed_hosts.contains(&host.to_string()) {
        return true;
    }
    let ip = match host {
        Host::Domain(name) => {
            return name == "localhost" && (bind.ip().is_loopback() || bind.ip().is_unspecified());
        }
        Host::Ipv4(ip) => IpAddr::V4(ip),
        Host::Ipv6(ip) => IpAddr::V6(ip),
    };
    // A wildcard listener serves literal IPs on its interfaces, never arbitrary
    // DNS names. Named deployments must use the explicit authority configuration.
    bind.ip().is_unspecified() || ip == bind.ip() || (bind.ip().is_loopback() && ip.is_loopback())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(host: &str) -> Vec<Header> {
        vec![Header::from_bytes("Host", host).unwrap()]
    }

    #[test]
    fn loopback_and_wildcard_binds_reject_rebinding_names() {
        for bind in ["127.0.0.1:9737", "[::1]:9737", "0.0.0.0:9737", "[::]:9737"] {
            let bind = bind.parse().unwrap();
            for host in [
                "localhost:9737",
                "LOCALHOST.",
                "127.0.0.1:9737",
                "[::1]:9737",
            ] {
                assert!(is_allowed_host(&headers(host), bind, &[]), "{bind}: {host}");
            }
            for host in [
                "rebind.example",
                "localhost.attacker.test",
                "127.0.0.1.attacker.test",
                "user@localhost",
                "localhost/path",
                "localhost\\evil",
                "localhost:bad",
                "localhost,evil.test",
                "*",
            ] {
                assert!(
                    !is_allowed_host(&headers(host), bind, &[]),
                    "{bind}: {host}"
                );
            }
        }
        let bind = "192.0.2.1:9737".parse().unwrap();
        assert!(is_allowed_host(&headers("192.0.2.1:9737"), bind, &[]));
        assert!(!is_allowed_host(&headers("192.0.2.2:9737"), bind, &[]));
        assert!(is_allowed_host(
            &headers("192.0.2.1:9737"),
            "0.0.0.0:9737".parse().unwrap(),
            &[]
        ));
    }

    #[test]
    fn missing_duplicate_and_forwarded_hosts_do_not_bypass_validation() {
        let bind = "127.0.0.1:9737".parse().unwrap();
        assert!(!is_allowed_host(&[], bind, &[]));
        let mut duplicate = headers("localhost");
        duplicate.extend(headers("rebind.example"));
        assert!(!is_allowed_host(&duplicate, bind, &[]));
        let mut forwarded = headers("rebind.example");
        forwarded.push(Header::from_bytes("X-Forwarded-Host", "localhost").unwrap());
        assert!(!is_allowed_host(&forwarded, bind, &[]));
    }

    #[test]
    fn explicit_authority_names_support_proxies_and_native_tls() {
        let allowed =
            configured_hosts(Some("node.example"), Some("https://proxy.example/v2")).unwrap();
        for bind in ["127.0.0.1:9737", "0.0.0.0:9737", "192.0.2.1:443"] {
            for host in ["node.example", "NODE.EXAMPLE:443", "proxy.example:8443"] {
                assert!(is_allowed_host(
                    &headers(host),
                    bind.parse().unwrap(),
                    &allowed
                ));
            }
            assert!(!is_allowed_host(
                &headers("rebind.example"),
                bind.parse().unwrap(),
                &allowed
            ));
        }
        assert!(configured_hosts(Some("*"), None).is_err());
        assert!(configured_hosts(None, Some("https://user:password@node.example")).is_err());
        assert!(configured_hosts(None, Some("file:///tmp/node")).is_err());
    }
}
