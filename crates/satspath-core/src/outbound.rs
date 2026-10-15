//! Shared outbound transport: validate every DNS answer used by the connector.
use crate::{
    ssrf::{is_private_or_reserved_ip, validate_url},
    Result, SatsPathError,
};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::{sync::Arc, time::Duration};

pub(crate) struct SystemDnsResolver;

impl Resolve for SystemDnsResolver {
    /// Resolve the hostname at the connector boundary.
    fn resolve(&self, name: Name) -> Resolving {
        Box::pin(async move {
            let addrs: Vec<_> = tokio::net::lookup_host((name.as_str(), 0)).await?.collect();
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// Validate the exact DNS answers passed to the HTTP connector, without a second lookup.
pub(crate) struct ValidatingDnsResolver(pub(crate) Arc<dyn Resolve>);

impl Resolve for ValidatingDnsResolver {
    /// Resolve the hostname at the connector boundary.
    fn resolve(&self, name: Name) -> Resolving {
        // Match resolve_from_url's explicit localhost exemption for mock servers.
        let allow_loopback = cfg!(test) && name.as_str() == "localhost";
        let resolving = self.0.resolve(name);
        Box::pin(async move {
            let addrs: Vec<_> = resolving.await?.collect();
            if addrs.is_empty() {
                return Err(SatsPathError::NetworkError("DNS returned no addresses".into()).into());
            }
            for addr in &addrs {
                if is_private_or_reserved_ip(addr.ip())
                    && !(allow_loopback && addr.ip().is_loopback())
                {
                    return Err(SatsPathError::ValidationError(format!(
                        "Blocked IP: {} (private/reserved DNS answer)",
                        addr.ip()
                    ))
                    .into());
                }
            }
            Ok(Box::new(addrs.into_iter()) as Addrs)
        })
    }
}

/// Construct an HTTP client with protected DNS, no redirects, and no proxies.
pub fn http_client(timeout: Duration) -> reqwest::Client {
    http_client_with_resolver(timeout, Arc::new(SystemDnsResolver))
}

/// Inject DNS at the connector boundary so validation and connection use one answer set.
pub(crate) fn http_client_with_resolver(
    timeout: Duration,
    resolver: Arc<dyn Resolve>,
) -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .dns_resolver(Arc::new(ValidatingDnsResolver(resolver)))
        .build()
        .expect("failed to build SSRF-protected HTTP client")
}

/// Validate a secure WebSocket URL using the same host and port policy as HTTPS.
pub fn validate_relay_url(relay: &str) -> Result<url::Url> {
    let mut url =
        url::Url::parse(relay).map_err(|e| SatsPathError::ValidationError(e.to_string()))?;
    if url.scheme() != "wss" {
        return Err(SatsPathError::ValidationError("relay must use wss".into()));
    }
    url.set_scheme("https")
        .map_err(|_| SatsPathError::ValidationError("invalid relay scheme".into()))?;
    validate_url(url.as_str(), false)?;
    url.set_scheme("wss")
        .map_err(|_| SatsPathError::ValidationError("invalid relay scheme".into()))?;
    Ok(url)
}

/// Connect to validated socket addresses, retaining the URL host for TLS and HTTP.
pub async fn connect_relay(
    relay: &str,
) -> Result<(
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>,
    tokio_tungstenite::tungstenite::handshake::client::Response,
)> {
    let url = validate_relay_url(relay)?;
    let host = url
        .host_str()
        .ok_or_else(|| SatsPathError::ValidationError("relay has no host".into()))?;
    let port = url.port_or_known_default().unwrap_or(443);
    let addrs = resolve_socket_addresses(
        host.trim_matches(['[', ']']),
        port,
        Arc::new(SystemDnsResolver),
    )
    .await?;
    let stream = connect_pinned(&addrs).await?;
    tokio_tungstenite::client_async_tls(relay, stream)
        .await
        .map_err(|e| SatsPathError::NetworkError(e.to_string()))
}

/// Validate a request URL unconditionally against production SSRF policy.
pub fn validate_request_url(value: &str) -> Result<()> {
    validate_url(value, false)
}

/// Resolve once and validate the full answer set before any socket is opened.
async fn resolve_socket_addresses(
    host: &str,
    port: u16,
    resolver: Arc<dyn Resolve>,
) -> Result<Vec<std::net::SocketAddr>> {
    let addrs = if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        if is_private_or_reserved_ip(ip) {
            return Err(SatsPathError::ValidationError("blocked relay IP".into()));
        }
        vec![std::net::SocketAddr::new(ip, port)]
    } else {
        let name = host
            .parse::<Name>()
            .map_err(|e| SatsPathError::ValidationError(e.to_string()))?;
        ValidatingDnsResolver(resolver)
            .resolve(name)
            .await
            .map_err(|e| SatsPathError::NetworkError(e.to_string()))?
            .map(|mut addr| {
                addr.set_port(port);
                addr
            })
            .collect()
    };
    Ok(addrs)
}

/// Only accept resolved socket addresses; this connector cannot perform another DNS lookup.
async fn connect_pinned(addrs: &[std::net::SocketAddr]) -> Result<tokio::net::TcpStream> {
    tokio::net::TcpStream::connect(addrs)
        .await
        .map_err(|e| SatsPathError::NetworkError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::SocketAddr,
        sync::atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct RebindingResolver {
        first: Vec<SocketAddr>,
        calls: AtomicUsize,
    }
    impl Resolve for RebindingResolver {
        /// Return the approved fixture once and a forbidden answer on every later lookup.
        fn resolve(&self, _: Name) -> Resolving {
            let addrs = if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                self.first.clone()
            } else {
                vec!["10.0.0.1:0".parse().unwrap()]
            };
            Box::pin(async move { Ok(Box::new(addrs.into_iter()) as Addrs) })
        }
    }

    /// The HTTP connector uses its approved answer directly and retains the original host.
    #[tokio::test]
    async fn http_connects_to_validated_socket_without_reresolving_or_redirecting() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let resolver = Arc::new(RebindingResolver {
            first: vec![address],
            calls: AtomicUsize::new(0),
        });
        let client = http_client_with_resolver(Duration::from_secs(2), resolver.clone());
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = [0; 4096];
            let len = socket.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..len])
                .to_ascii_lowercase()
                .contains(&format!("host: localhost:{}", address.port())));
            socket
                .write_all(
                    b"HTTP/1.1 302 Found
Location: http://10.0.0.1/secret
Content-Length: 0
Connection: close

",
                )
                .await
                .unwrap();
        });
        let response = client
            .get(format!("http://localhost:{}/profile", address.port()))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 302);
        server.await.unwrap();
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
    }

    /// The relay's TCP connector uses the same validated SocketAddr after DNS changes.
    #[tokio::test]
    async fn relay_socket_is_pinned_to_one_validated_resolution() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let resolver = Arc::new(RebindingResolver {
            first: vec![address],
            calls: AtomicUsize::new(0),
        });
        // localhost loopback is permitted only in test builds; public hostnames have no exemption.
        let approved = resolve_socket_addresses("localhost", address.port(), resolver.clone())
            .await
            .unwrap();
        let stream = connect_pinned(&approved).await.unwrap();
        assert_eq!(stream.peer_addr().unwrap(), address);
        assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        assert!(
            resolve_socket_addresses("localhost", address.port(), resolver.clone())
                .await
                .is_err()
        );
    }

    /// Reject every private or mixed answer set before either transport can connect.
    #[tokio::test]
    async fn reject_empty_private_and_mixed_dns_answers() {
        for addresses in [
            vec![],
            vec!["127.0.0.1:0"],
            vec!["8.8.8.8:0", "10.0.0.1:0"],
            vec!["10.0.0.1:0", "8.8.8.8:0"],
        ] {
            let resolver = Arc::new(RebindingResolver {
                first: addresses.into_iter().map(|a| a.parse().unwrap()).collect(),
                calls: AtomicUsize::new(0),
            });
            assert!(
                resolve_socket_addresses("relay.example", 443, resolver.clone())
                    .await
                    .is_err()
            );
            assert_eq!(resolver.calls.load(Ordering::SeqCst), 1);
        }
    }

    /// Literal IPs and unsafe URL forms cannot bypass relay host validation.
    #[test]
    fn reject_unsafe_relay_urls() {
        for url in [
            "ws://relay.example",
            "wss://127.0.0.1",
            "wss://[::1]",
            "wss://10.0.0.1",
            "wss://relay.example:22",
            "wss://user@relay.example",
            "wss://relay.example/#fragment",
        ] {
            assert!(validate_relay_url(url).is_err(), "{url}");
        }
        assert!(validate_relay_url("wss://relay.example").is_ok());
    }
}
