//! SSRF (Server-Side Request Forgery) protection for SatsPath resolvers.
//!
//! All outbound HTTP/HTTPS requests from resolvers MUST pass through
//! [`pinned_http_client`] before being issued. This prevents a malicious alias
//! (e.g. `attacker@127.0.0.1`) from tricking the resolver into contacting
//! internal services.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{Result, SatsPathError};

/// Domains that are always blocked regardless of IP resolution.
const BLOCKED_HOSTS: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal", // GCP metadata
    "169.254.169.254",          // AWS/GCP/Azure metadata endpoint
    "metadata.google.internal.",
];

/// Validate URL syntax and literal destinations. DNS names additionally require
/// [`resolve_public_endpoint`] and connection pinning.
///
/// Checks performed:
/// 1. Scheme must be HTTPS (or HTTP only if `allow_http` is true — for tests).
/// 2. Host must not be a known internal/metadata hostname.
/// 3. If the host is an IP literal, it must not be in a private/reserved range.
/// 4. Port must be 80, 443, 8080, or 8443.
pub fn validate_url(url: &str, allow_http: bool) -> Result<()> {
    let parsed = url::Url::parse(url)
        .map_err(|e| SatsPathError::ValidationError(format!("Invalid URL: {e}")))?;

    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err(SatsPathError::ValidationError(
            "URL credentials and fragments are forbidden".into(),
        ));
    }

    // ── Scheme ────────────────────────────────────────────────────────────
    match parsed.scheme() {
        "https" => {}
        "http" if allow_http => {}
        other => {
            return Err(SatsPathError::ValidationError(format!(
                "Blocked scheme '{other}' — only HTTPS is allowed"
            )));
        }
    }

    // ── Host ──────────────────────────────────────────────────────────────
    let host = parsed
        .host_str()
        .ok_or_else(|| SatsPathError::ValidationError("URL has no host".to_string()))?;

    let host_lower = host.to_ascii_lowercase();
    let host_clean = host_lower.strip_suffix('.').unwrap_or(&host_lower);

    // Block known internal hostnames
    if BLOCKED_HOSTS.iter().any(|blocked| {
        let blocked_clean = blocked.strip_suffix('.').unwrap_or(blocked);
        host_clean == blocked_clean || host_clean.ends_with(&format!(".{blocked_clean}"))
    }) {
        return Err(SatsPathError::ValidationError(format!(
            "Blocked host: {host} (internal/metadata endpoint)"
        )));
    }

    // If the host is an IP literal, check the range
    let ip_str = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        if is_private_or_reserved_ip(ip) {
            return Err(SatsPathError::ValidationError(format!(
                "Blocked IP: {ip} (private/reserved range)"
            )));
        }
    }

    // ── Port ──────────────────────────────────────────────────────────────
    if let Some(port) = parsed.port() {
        // Allowlist: a public profile endpoint only needs standard web ports.
        match port {
            80 | 443 | 8080 | 8443 => {}
            _ => {
                return Err(SatsPathError::ValidationError(format!(
                    "Blocked port {port} — only 80, 443, 8080 and 8443 are allowed"
                )));
            }
        }
    }

    Ok(())
}

/// Resolve once and validate every answer before creating any connection.
pub async fn resolve_public_endpoint(
    url: &str,
    allow_http: bool,
) -> Result<(url::Url, Vec<std::net::SocketAddr>)> {
    validate_url(url, allow_http)?;
    let parsed = url::Url::parse(url).map_err(|e| SatsPathError::ValidationError(e.to_string()))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| SatsPathError::ValidationError("missing host".into()))?;
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| SatsPathError::ValidationError("missing port".into()))?;
    let addresses = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::net::lookup_host((host.trim_matches(['[', ']']), port)),
    )
    .await
    .map_err(|_| SatsPathError::NetworkError("DNS timeout".into()))?
    .map_err(|e| SatsPathError::NetworkError(e.to_string()))?
    .collect::<Vec<_>>();
    validate_resolved_addresses(&addresses)?;
    Ok((parsed, addresses))
}

fn validate_resolved_addresses(addresses: &[std::net::SocketAddr]) -> Result<()> {
    if addresses.is_empty() || addresses.iter().any(|a| is_private_or_reserved_ip(a.ip())) {
        return Err(SatsPathError::ValidationError(
            "DNS returned an empty or non-public address set".into(),
        ));
    }
    Ok(())
}

/// HTTP client pinned to the validated DNS snapshot. The URL hostname remains
/// intact for Host/SNI and certificate verification. Proxies and redirects are
/// disabled so neither can resolve a different destination behind our back.
pub async fn pinned_http_client(url: &str, allow_http: bool) -> Result<reqwest::Client> {
    let (parsed, addresses) = resolve_public_endpoint(url, allow_http).await?;
    pinned_client_builder(&parsed, &addresses)
        .build()
        .map_err(|e| SatsPathError::NetworkError(e.to_string()))
}

fn pinned_client_builder(
    url: &url::Url,
    addresses: &[std::net::SocketAddr],
) -> reqwest::ClientBuilder {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .resolve_to_addrs(url.host_str().expect("validated host"), addresses)
}

/// Connect the TCP socket to a validated address, then perform the WebSocket
/// and TLS handshakes using the original hostname. No second DNS lookup occurs.
pub async fn pinned_websocket(
    url: &str,
) -> Result<(
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    tokio_tungstenite::tungstenite::handshake::client::Response,
)> {
    let mut http_url =
        url::Url::parse(url).map_err(|e| SatsPathError::ValidationError(e.to_string()))?;
    let scheme = match http_url.scheme() {
        "wss" => "https",
        _ => return Err(SatsPathError::ValidationError("relay requires wss".into())),
    };
    http_url
        .set_scheme(scheme)
        .map_err(|_| SatsPathError::ValidationError("invalid relay URL".into()))?;
    let (_, addresses) = resolve_public_endpoint(http_url.as_str(), false).await?;
    let stream = tokio::net::TcpStream::connect(addresses.as_slice())
        .await
        .map_err(|e| SatsPathError::NetworkError(e.to_string()))?;
    tokio_tungstenite::client_async_tls(url, stream)
        .await
        .map_err(|e| SatsPathError::NetworkError(e.to_string()))
}

/// Returns `true` if the IP address is in a private, loopback, link-local,
/// or otherwise reserved range that should never be contacted by a resolver.
/// Reject literal or DNS-resolved addresses that must never be contacted by
/// untrusted network clients. Call this on the IP used by the actual socket.
pub fn is_private_or_reserved_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_private_v4(v4),
        IpAddr::V6(v6) => is_private_v6(v6),
    }
}

/// Exclude internal, documentation, multicast and reserved IPv4 ranges.
fn is_private_v4(ip: Ipv4Addr) -> bool {
    let octets = ip.octets();
    // This host, multicast and reserved-use space cannot be relay endpoints.
    if octets[0] == 0 || octets[0] >= 224 {
        return true;
    }
    // Loopback: 127.0.0.0/8
    if octets[0] == 127 {
        return true;
    }
    // Private: 10.0.0.0/8
    if octets[0] == 10 {
        return true;
    }
    // Private: 172.16.0.0/12
    if octets[0] == 172 && (16..=31).contains(&octets[1]) {
        return true;
    }
    // Private: 192.168.0.0/16
    if octets[0] == 192 && octets[1] == 168 {
        return true;
    }
    // Link-local: 169.254.0.0/16 (includes AWS/GCP metadata 169.254.169.254)
    if octets[0] == 169 && octets[1] == 254 {
        return true;
    }
    // Broadcast / unspecified
    if ip.is_broadcast() || ip.is_unspecified() {
        return true;
    }
    // Documentation ranges (RFC 5737)
    if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
        return true;
    }
    if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
        return true;
    }
    if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
        return true;
    }
    // Benchmark networks 198.18.0.0/15 and IETF protocol assignments.
    if (octets[0] == 198 && (octets[1] == 18 || octets[1] == 19))
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0)
    {
        return true;
    }
    // Carrier-grade NAT: 100.64.0.0/10
    if octets[0] == 100 && (64..=127).contains(&octets[1]) {
        return true;
    }
    false
}

/// Exclude loopback, internal, multicast and reserved IPv6 ranges.
fn is_private_v6(ip: Ipv6Addr) -> bool {
    // Loopback: ::1
    if ip.is_loopback() {
        return true;
    }
    // Unspecified: ::
    if ip.is_unspecified() {
        return true;
    }
    let segments = ip.segments();
    if segments[0] & 0xff00 == 0xff00 {
        return true; // multicast
    }
    // Link-local: fe80::/10
    if segments[0] & 0xffc0 == 0xfe80 {
        return true;
    }
    // Unique local: fc00::/7 (RFC 4193)
    if segments[0] & 0xfe00 == 0xfc00 {
        return true;
    }
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return true; // documentation
    }
    // Discard-only (RFC 6666), benchmarking (RFC 5180), and deprecated
    // site-local addresses cannot be publicly reachable relay endpoints.
    if (segments[0] == 0x0100 && segments[1..4] == [0, 0, 0])
        || (segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0)
        || (segments[0] & 0xffc0 == 0xfec0)
    {
        return true;
    }
    // RFC 6052 well-known NAT64 prefix 64:ff9b::/96 embeds the IPv4
    // destination in the final 32 bits. Do not block public NAT64 targets.
    if segments[..6] == [0x0064, 0xff9b, 0, 0, 0, 0] {
        let embedded = Ipv4Addr::new(
            (segments[6] >> 8) as u8,
            segments[6] as u8,
            (segments[7] >> 8) as u8,
            segments[7] as u8,
        );
        return is_private_v4(embedded);
    }
    // IPv4-mapped: ::ffff:0:0/96 — check the embedded v4
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_private_v4(v4);
    }
    false
}

/// Builds a reqwest client pinned to the pre-validated IP address of `url`.
#[cfg(feature = "std")]
pub async fn build_pinned_http_client(
    url: &str,
    timeout: std::time::Duration,
    allow_http: bool,
) -> Result<reqwest::Client> {
    validate_url(url, allow_http)?;
    let parsed = url::Url::parse(url)
        .map_err(|e| SatsPathError::ValidationError(format!("Invalid URL: {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| SatsPathError::ValidationError("URL has no host".to_string()))?;
    let port = parsed.port_or_known_default().unwrap_or(443);

    let ip_str = host.trim_start_matches('[').trim_end_matches(']');
    let mut builder = reqwest::Client::builder()
        .timeout(timeout)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());

    if let Ok(ip) = ip_str.parse::<IpAddr>() {
        if is_private_or_reserved_ip(ip) {
            return Err(SatsPathError::ValidationError(format!(
                "Blocked IP: {ip} (private/reserved range)"
            )));
        }
    } else {
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .map_err(|e| {
                SatsPathError::NetworkError(format!("DNS resolution failed for {host}: {e}"))
            })?
            .collect();
        if addrs.is_empty() {
            return Err(SatsPathError::NetworkError(format!(
                "DNS resolution returned no addresses for {host}"
            )));
        }
        for addr in &addrs {
            if is_private_or_reserved_ip(addr.ip()) {
                return Err(SatsPathError::ValidationError(format!(
                    "Blocked resolved IP for {host}: {} (private/reserved range)",
                    addr.ip()
                )));
            }
        }
        builder = pin_http_host(builder, &parsed, &addrs);
    }

    builder
        .build()
        .map_err(|e| SatsPathError::NetworkError(e.to_string()))
}

/// Key the override by the exact URL host reqwest will resolve, including a final dot.
#[cfg(feature = "std")]
fn pin_http_host(
    builder: reqwest::ClientBuilder,
    url: &url::Url,
    addrs: &[std::net::SocketAddr],
) -> reqwest::ClientBuilder {
    builder.resolve_to_addrs(url.host_str().expect("validated URL has a host"), addrs)
}

/// Read an HTTP response body up to `max_bytes`, failing closed if the stream exceeds the bound.
#[cfg(feature = "std")]
pub async fn read_bounded_response(
    mut resp: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>> {
    if let Some(len) = resp.content_length() {
        if len > max_bytes as u64 {
            return Err(SatsPathError::NetworkError(format!(
                "Response content-length ({len} bytes) exceeds limit of {max_bytes} bytes"
            )));
        }
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| SatsPathError::NetworkError(format!("Error reading response stream: {e}")))?
    {
        if bytes.len() + chunk.len() > max_bytes {
            return Err(SatsPathError::NetworkError(format!(
                "Response payload exceeded size limit of {max_bytes} bytes"
            )));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reject_any_unsafe_dns_answer_before_connecting() {
        assert!(validate_resolved_addresses(&[]).is_err());
        for blocked in [
            "127.0.0.1",
            "10.0.0.1",
            "169.254.169.254",
            "192.0.2.1",
            "::1",
            "fc00::1",
        ] {
            let mixed = [
                "8.8.8.8:443".parse().unwrap(),
                std::net::SocketAddr::new(blocked.parse().unwrap(), 443),
            ];
            assert!(validate_resolved_addresses(&mixed).is_err(), "{blocked}");
        }
    }

    #[tokio::test]
    async fn pinned_snapshot_prevents_second_dns_lookup_and_preserves_host() {
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };
        struct RebindingDns(Arc<AtomicUsize>);
        impl reqwest::dns::Resolve for RebindingDns {
            fn resolve(&self, _: reqwest::dns::Name) -> reqwest::dns::Resolving {
                self.0.fetch_add(1, Ordering::SeqCst);
                // A changed answer must never be consulted by the connection.
                Box::pin(async {
                    Ok(Box::new(std::iter::once("127.0.0.2:80".parse().unwrap()))
                        as reqwest::dns::Addrs)
                })
            }
        }
        let mut server = mockito::Server::new_async().await;
        let port = url::Url::parse(&server.url()).unwrap().port().unwrap();
        let url = url::Url::parse(&format!("http://rebind.invalid:{port}/")).unwrap();
        let expected = server
            .mock("GET", "/")
            .match_header("host", format!("rebind.invalid:{port}").as_str())
            .with_status(302)
            .with_header("location", "http://127.0.0.2/")
            .create_async()
            .await;
        let calls = Arc::new(AtomicUsize::new(0));
        // Use a local fixture as the already-validated snapshot only inside this
        // test; the public helper always rejects loopback before building it.
        let snapshot = [format!("127.0.0.1:{port}").parse().unwrap()];
        let client = pinned_client_builder(&url, &snapshot)
            .dns_resolver(Arc::new(RebindingDns(calls.clone())))
            .build()
            .unwrap();
        let response = client.get(url).send().await.unwrap();
        assert_eq!(response.status(), 302); // Redirect destination is not contacted.
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        expected.assert_async().await;
    }

    /// NAT64 must inherit the public/private status of the embedded IPv4 host.
    #[test]
    fn nat64_rejects_private_embedded_ipv4_but_allows_public() {
        for ip in [
            "64:ff9b::a00:1",     // 10.0.0.1
            "64:ff9b::7f00:1",    // 127.0.0.1
            "64:ff9b::a9fe:a9fe", // 169.254.169.254 metadata
            "64:ff9b::c0a8:101",  // 192.168.1.1
        ] {
            assert!(is_private_or_reserved_ip(ip.parse().unwrap()), "{ip}");
        }
        assert!(!is_private_or_reserved_ip(
            "64:ff9b::808:808".parse().unwrap()
        ));
        assert!(!is_private_or_reserved_ip(
            "64:ff9b::101:101".parse().unwrap()
        ));
    }

    /// DNS answer validation rejects special-use IPv6 outside NAT64 and ULA.
    #[test]
    fn nonpublic_ipv6_discard_benchmark_and_site_local_ranges_are_blocked() {
        for ip in [
            "100::1",
            "100::ffff:1",
            "2001:2::1",
            "2001:2:0:ffff::1",
            "fec0::1",
            "feff::1",
        ] {
            assert!(is_private_or_reserved_ip(ip.parse().unwrap()), "{ip}");
        }
        for ip in ["64:ff9b::808:808", "2606:4700:4700::1111"] {
            assert!(!is_private_or_reserved_ip(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn https_public_allowed() {
        assert!(validate_url("https://example.com/.well-known/satspath/alice", false).is_ok());
    }

    #[test]
    fn http_blocked_by_default() {
        assert!(validate_url("http://example.com/test", false).is_err());
    }

    #[test]
    fn http_allowed_when_flagged() {
        assert!(validate_url("http://example.com/test", true).is_ok());
    }

    #[test]
    fn localhost_blocked() {
        assert!(validate_url("https://localhost/profile", false).is_err());
        assert!(validate_url("https://localhost:8080/profile", false).is_err());
    }

    #[test]
    fn loopback_ip_blocked() {
        assert!(validate_url("https://127.0.0.1/profile", false).is_err());
        assert!(validate_url("https://[::1]/profile", false).is_err());
    }

    #[test]
    fn private_ip_blocked() {
        assert!(validate_url("https://10.0.0.1/profile", false).is_err());
        assert!(validate_url("https://192.168.1.1/profile", false).is_err());
        assert!(validate_url("https://172.16.0.1/profile", false).is_err());
    }

    #[test]
    fn aws_metadata_blocked() {
        assert!(validate_url("https://169.254.169.254/latest/meta-data/", false).is_err());
        assert!(validate_url("https://metadata.google.internal/", false).is_err());
    }

    #[test]
    fn low_and_internal_service_ports_blocked() {
        assert!(validate_url("https://example.com:22/profile", false).is_err());
        assert!(validate_url("https://example.com:25/profile", false).is_err());
        // High-risk internal database / caching / search service ports
        for port in [3306, 5432, 6379, 9200, 11211, 27017] {
            assert!(
                validate_url(&format!("https://example.com:{port}/profile"), false).is_err(),
                "port {port} must be blocked"
            );
        }
    }

    #[test]
    fn allowed_ports_pass() {
        assert!(validate_url("https://example.com:443/profile", false).is_ok());
        assert!(validate_url("https://example.com:8443/profile", false).is_ok());
        assert!(validate_url("http://example.com:80/profile", true).is_ok());
        assert!(validate_url("http://example.com:8080/profile", true).is_ok());
    }

    #[test]
    fn encoded_ips_canonicalized_and_blocked() {
        // WHATWG URL parser canonicalizes these to 127.0.0.1 which is caught by loopback IP check
        assert!(validate_url("https://0x7f000001/profile", false).is_err());
        assert!(validate_url("https://2130706433/profile", false).is_err());
        assert!(validate_url("https://127.1/profile", false).is_err());
        assert!(validate_url("https://localhost./profile", false).is_err());
    }

    #[test]
    fn ftp_scheme_blocked() {
        assert!(validate_url("ftp://example.com/profile", false).is_err());
    }

    #[test]
    fn carrier_grade_nat_blocked() {
        assert!(validate_url("https://100.100.100.100/profile", false).is_err());
    }
}
