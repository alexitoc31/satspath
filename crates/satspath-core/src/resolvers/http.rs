use async_trait::async_trait;
use reqwest::dns::Resolve;
#[cfg(test)]
use reqwest::dns::{Addrs, Name, Resolving};
use reqwest::Client;
use std::sync::Arc;
use std::time::Duration;

use crate::crypto::{check_profile_expiry, verify_signed_profile};
#[cfg(test)]
use crate::outbound::ValidatingDnsResolver;
use crate::outbound::{http_client_with_resolver, SystemDnsResolver};
use crate::resolver::ProfileResolver;
use crate::ssrf::validate_url;
use crate::{Result, SatsPathError, SignedPaymentProfile};

/// Resolves a profile by making an HTTP GET request to the domain of the alias.
///
/// If the alias is `rodrigo@satspath.dev`, it fetches:
/// `https://satspath.dev/.well-known/satspath/rodrigo`
///
/// After fetching, the resolver:
/// 1. **SSRF validation** — blocks requests to private/loopback/metadata IPs.
/// 2. Verifies the profile signature (ECDSA secp256k1 over canonical JSON).
/// 3. Checks the profile expiry (`expires_at` field).
///
/// Both checks must pass. Fail-closed: unsigned or expired profiles are
/// rejected with a hard error, never passed through.
pub struct HttpResolver {
    client: Client,
}

impl HttpResolver {
    /// Construct the resolver with its configured transport policy.
    pub fn new() -> Self {
        Self::with_dns_resolver(Arc::new(SystemDnsResolver))
    }

    /// Build a resolver with injectable DNS for controlled connection tests.
    fn with_dns_resolver<R: Resolve + 'static>(resolver: Arc<R>) -> Self {
        Self {
            client: http_client_with_resolver(Duration::from_secs(10), resolver),
        }
    }

    /// Build with a custom base URL (for testing with a mock server).
    #[cfg(test)]
    pub fn new_with_base_url(_base_url: &str) -> Self {
        // The base_url override is handled by rewriting the resolution URL in tests.
        Self::new()
    }
}

impl Default for HttpResolver {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProfileResolver for HttpResolver {
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
        let parts: Vec<&str> = alias.split('@').collect();
        if parts.len() != 2 {
            return Err(SatsPathError::AliasNotFound(alias.to_string()));
        }

        let username = parts[0];
        let domain = parts[1];

        // Always HTTPS in production.
        let url = format!("https://{}/.well-known/satspath/{}", domain, username);

        // SSRF-01: validate URL before fetching
        validate_url(&url, false)?;

        self.resolve_from_url(&url).await
    }
}

impl HttpResolver {
    /// Fetch, verify, and return a signed profile from an explicit URL.
    ///
    /// The URL must satisfy all production SSRF constraints unconditionally.
    pub async fn resolve_from_url(&self, url: &str) -> Result<SignedPaymentProfile> {
        validate_url(url, false)?;
        self.fetch_from_validated_url(url).await
    }

    /// Test-only resolution path for mock servers without production SSRF checks.
    #[cfg(test)]
    pub(crate) async fn resolve_from_mock_url(&self, url: &str) -> Result<SignedPaymentProfile> {
        self.fetch_from_validated_url(url).await
    }

    /// Construct a resolver with a custom HTTP client (for test dependency injection).
    #[cfg(test)]
    pub(crate) fn with_client(client: Client) -> Self {
        Self { client }
    }

    async fn fetch_from_validated_url(&self, url: &str) -> Result<SignedPaymentProfile> {
        let mut resp = self.client.get(url).send().await.map_err(|e| {
            SatsPathError::NetworkError(format!("Failed to connect to {}: {}", url, e))
        })?;

        if resp.status() == 404 {
            return Err(SatsPathError::AliasNotFound(url.to_string()));
        }

        if !resp.status().is_success() {
            return Err(SatsPathError::NetworkError(format!(
                "HTTP error {} fetching profile",
                resp.status()
            )));
        }

        let mut bytes = Vec::new();
        let max_size = 50 * 1024; // 50 KB Limit (DoS Protection)

        while let Some(chunk) = resp.chunk().await.map_err(|e| {
            SatsPathError::NetworkError(format!("Error reading response stream: {}", e))
        })? {
            if bytes.len() + chunk.len() > max_size {
                return Err(SatsPathError::NetworkError(
                    "Payload exceeded size limit of 50KB (DoS protection)".to_string(),
                ));
            }
            bytes.extend_from_slice(&chunk);
        }

        let signed: SignedPaymentProfile = serde_json::from_slice(&bytes).map_err(|e| {
            SatsPathError::SerializationError(format!("Failed to parse profile JSON: {}", e))
        })?;

        // RESOLVE-02: verify signature — fail closed.
        let valid = verify_signed_profile(&signed)?;
        if !valid {
            return Err(SatsPathError::InvalidSignature);
        }

        // SEC-01: enforce expiry — fail closed.
        check_profile_expiry(&signed.profile)?;

        // Enforce revocation — fail closed. Revoked profiles must never be returned to callers.
        if signed.profile.revoked {
            return Err(SatsPathError::RegistryError(format!(
                "Alias {} has been revoked",
                signed.profile.alias
            )));
        }

        Ok(signed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_identity_keypair, sign_profile};
    use crate::profile::{PaymentMethod, PaymentProfile};
    use mockito::Server;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    struct StubResolver {
        addrs: Vec<std::net::SocketAddr>,
        calls: AtomicUsize,
    }

    impl StubResolver {
        /// Return the supplied socket addresses and track DNS lookup calls.
        fn new(addrs: Vec<std::net::SocketAddr>) -> Self {
            Self {
                addrs,
                calls: AtomicUsize::new(0),
            }
        }
    }

    impl Resolve for StubResolver {
        /// Resolve the hostname at the connector boundary.
        fn resolve(&self, name: Name) -> Resolving {
            assert_eq!(name.as_str(), "profile.example");
            self.calls.fetch_add(1, Ordering::Relaxed);
            let addrs = self.addrs.clone();
            Box::pin(async move { Ok(Box::new(addrs.into_iter()) as Addrs) })
        }
    }

    #[tokio::test]
    /// Verify that hostname resolving to private ip is rejected before connect.
    async fn hostname_resolving_to_private_ip_is_rejected_before_connect() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let stub = Arc::new(StubResolver::new(vec![listener.local_addr().unwrap()]));
        let resolver = HttpResolver::with_dns_resolver(stub.clone());
        let url = "https://profile.example/profile";
        assert!(validate_url(url, false).is_ok());

        let result = resolver.resolve_from_url(url).await;

        assert!(matches!(result, Err(SatsPathError::NetworkError(_))));
        assert_eq!(stub.calls.load(Ordering::Relaxed), 1);
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "the resolver must reject the DNS answer before opening a socket"
        );
    }

    #[tokio::test]
    /// Verify that dns resolver rejects disallowed and mixed answers.
    async fn dns_resolver_rejects_disallowed_and_mixed_answers() {
        let public = "8.8.8.8:0".parse().unwrap();
        for blocked in [
            "10.0.0.1:0",
            "127.0.0.1:0",
            "169.254.169.254:0",
            "192.0.2.1:0",
            "[::1]:0",
            "[fc00::1]:0",
            "[::ffff:192.168.1.1]:0",
            "[64:ff9b::a00:1]:0",
        ] {
            let blocked = blocked.parse().unwrap();
            for addrs in [vec![blocked], vec![public, blocked], vec![blocked, public]] {
                let resolver = ValidatingDnsResolver(Arc::new(StubResolver::new(addrs)));
                let error = resolver
                    .resolve("profile.example".parse().unwrap())
                    .await
                    .err()
                    .expect("a disallowed DNS answer must reject the entire result");
                assert!(matches!(
                    error.downcast_ref::<SatsPathError>(),
                    Some(SatsPathError::ValidationError(message)) if message.starts_with("Blocked IP:")
                ));
            }
        }
    }

    #[tokio::test]
    /// Verify that dns resolver preserves public answers.
    async fn dns_resolver_preserves_public_answers() {
        let addrs = vec![
            "8.8.8.8:0".parse().unwrap(),
            "[2606:4700:4700::1111]:0".parse().unwrap(),
        ];
        let resolver = ValidatingDnsResolver(Arc::new(StubResolver::new(addrs.clone())));
        let resolved = resolver
            .resolve("profile.example".parse().unwrap())
            .await
            .expect("public DNS answers must remain usable");
        assert_eq!(resolved.collect::<Vec<_>>(), addrs);
    }

    /// Build a valid signed profile.
    fn make_valid_signed(alias: &str, expires_at: Option<i64>) -> SignedPaymentProfile {
        let kp = generate_identity_keypair();
        let pubkey_hex = hex::encode(kp.public_key.serialize());
        let profile = PaymentProfile {
            alias: alias.to_string(),
            identity_pubkey: pubkey_hex,
            methods: vec![PaymentMethod::Lightning {
                label: "LN".into(),
                lnurl: None,
                lightning_address: Some(alias.to_string()),
                bolt12: None,
                receiver_pubkey: None,
            }],
            updated_at: 1_700_000_000,
            expires_at,
            sequence: None,
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: vec![],
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
            recovery_policy: None,
            recovery: None,
        };
        sign_profile(profile, &kp.secret_key).unwrap()
    }

    // ── Test 1: Valid profile — success ───────────────────────────────────────

    #[tokio::test]
    async fn valid_profile_resolves_ok() {
        let mut server = Server::new_async().await;
        let signed = make_valid_signed("alice@test.com", None);
        let body = serde_json::to_string(&signed).unwrap();

        let _mock = server
            .mock("GET", "/profile")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&body)
            .create_async()
            .await;

        let resolver = HttpResolver::new();
        let url = format!("{}/profile", server.url());
        let result = resolver.resolve_from_mock_url(&url).await;

        assert!(
            result.is_ok(),
            "valid profile should resolve successfully: {:?}",
            result.err()
        );
        assert_eq!(result.unwrap().profile.alias, "alice@test.com");
    }

    // ── Test 2: Invalid signature — rejected ──────────────────────────────────

    #[tokio::test]
    async fn invalid_signature_rejected() {
        let mut server = Server::new_async().await;
        let mut signed = make_valid_signed("bob@test.com", None);
        // Tamper: flip last hex char of the signature
        let last = signed.signature.pop().unwrap();
        signed.signature.push(if last == '0' { '1' } else { '0' });
        let body = serde_json::to_string(&signed).unwrap();

        let _mock = server
            .mock("GET", "/profile")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&body)
            .create_async()
            .await;

        let resolver = HttpResolver::new();
        let url = format!("{}/profile", server.url());
        let result = resolver.resolve_from_mock_url(&url).await;

        assert!(result.is_err(), "tampered signature must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid signature") || err.contains("crypto") || err.contains("Invalid"),
            "error must mention signature: {err}"
        );
    }

    // ── Test 3: Expired profile — rejected ────────────────────────────────────

    #[tokio::test]
    async fn expired_profile_rejected() {
        let mut server = Server::new_async().await;
        // expires_at 1 hour in the past
        let past = chrono::Utc::now().timestamp() - 3_600;
        let signed = make_valid_signed("carol@test.com", Some(past));
        let body = serde_json::to_string(&signed).unwrap();

        let _mock = server
            .mock("GET", "/profile")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(&body)
            .create_async()
            .await;

        let resolver = HttpResolver::new();
        let url = format!("{}/profile", server.url());
        let result = resolver.resolve_from_mock_url(&url).await;

        assert!(result.is_err(), "expired profile must be rejected");
        let err = result.unwrap_err().to_string();
        assert!(err.contains("expired"), "error must mention expiry: {err}");
    }

    // ── Test 4: 404 → AliasNotFound ───────────────────────────────────────────

    #[tokio::test]
    async fn not_found_404() {
        let mut server = Server::new_async().await;

        let _mock = server
            .mock("GET", "/profile")
            .with_status(404)
            .create_async()
            .await;

        let resolver = HttpResolver::new();
        let url = format!("{}/profile", server.url());
        let result = resolver.resolve_from_mock_url(&url).await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), SatsPathError::AliasNotFound(_)),
            "404 must map to AliasNotFound"
        );
    }

    // ── Test 5: 5xx server error → NetworkError ───────────────────────────────

    #[tokio::test]
    async fn server_error_5xx() {
        let mut server = Server::new_async().await;

        let _mock = server
            .mock("GET", "/profile")
            .with_status(503)
            .create_async()
            .await;

        let resolver = HttpResolver::new();
        let url = format!("{}/profile", server.url());
        let result = resolver.resolve_from_mock_url(&url).await;

        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), SatsPathError::NetworkError(_)),
            "5xx must map to NetworkError"
        );
    }

    // ── Test 6: Malformed JSON → SerializationError ───────────────────────────

    #[tokio::test]
    async fn malformed_json_rejected() {
        let mut server = Server::new_async().await;

        let _mock = server
            .mock("GET", "/profile")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"not": "a signed profile at all"}"#)
            .create_async()
            .await;

        let resolver = HttpResolver::new();
        let url = format!("{}/profile", server.url());
        let result = resolver.resolve_from_mock_url(&url).await;

        assert!(result.is_err(), "malformed JSON must be rejected");
        assert!(
            matches!(result.unwrap_err(), SatsPathError::SerializationError(_)),
            "malformed JSON must map to SerializationError"
        );
    }

    // ── Test 7: Loopback URLs unconditionally rejected in resolve_from_url ────

    #[tokio::test]
    async fn resolve_from_url_unconditionally_rejects_loopback() {
        let resolver = HttpResolver::new();
        let loopback_urls = [
            "http://127.0.0.1:8080/profile",
            "https://127.0.0.1:8080/profile",
            "http://localhost:8080/profile",
            "https://localhost:8080/profile",
        ];
        for url in loopback_urls {
            let result = resolver.resolve_from_url(url).await;
            assert!(
                matches!(result, Err(SatsPathError::ValidationError(_))),
                "expected ValidationError for {url}, got: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn test_attack_memory_exhaustion_dos() {
        use tokio_rustls::rustls::{pki_types::PrivatePkcs8KeyDer, ServerConfig};

        // Route a public-looking hostname to a local TLS mock through a test-only client.
        // Production construction retains DNS answer validation and cannot inject this client.
        let cert = rcgen::generate_simple_self_signed(vec!["profile.example".into()]).unwrap();
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.cert.der().clone()],
                PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
            )
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = acceptor.accept(stream).await.unwrap();
            let mut request = [0; 4096];
            let len = stream.read(&mut request).await.unwrap();
            assert!(String::from_utf8_lossy(&request[..len]).contains("GET /profile"));
            // One byte past the cap exercises the same boundary without a multi-MB buffer.
            let body = "x".repeat(50 * 1024 + 1);
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).await.unwrap();
            // The client intentionally stops reading after 50 KiB.
            let _ = stream.write_all(body.as_bytes()).await;
        });

        let client = Client::builder()
            .resolve("profile.example", address)
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .add_root_certificate(reqwest::Certificate::from_der(cert.cert.der()).unwrap())
            .build()
            .unwrap();
        let resolver = HttpResolver::with_client(client);
        let result = resolver
            .resolve_from_url("https://profile.example/profile")
            .await;
        assert!(result.is_err(), "Node must reject an oversized payload");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("DoS protection"),
            "Expected DoS protection error, got: {err_msg}"
        );
        server.await.unwrap();
    }
}
