//! Offline unit tests for bounded response reads and pinned-client validation.
#![cfg(feature = "std")]

use std::time::Duration;

use satspath_core::ssrf::{build_pinned_http_client, read_bounded_response};
use satspath_core::SatsPathError;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Serve exact HTTP framing so Content-Length and chunked limits are independent.
async fn response(raw: &[u8]) -> reqwest::Response {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let raw = raw.to_vec();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 1024];
        while !request.windows(4).any(|bytes| bytes == b"\r\n\r\n") {
            let len = socket.read(&mut buffer).await.unwrap();
            assert!(len > 0, "client closed before sending headers");
            request.extend_from_slice(&buffer[..len]);
            assert!(request.len() < 16 * 1024);
        }
        socket.write_all(&raw).await.unwrap();
        socket.shutdown().await.unwrap();
    });
    let response = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap()
        .get(format!("http://{address}/"))
        .send()
        .await
        .unwrap();
    server.await.unwrap();
    response
}

/// Exactly the advertised limit is valid; one byte less must fail closed.
#[tokio::test]
async fn content_length_limit_is_inclusive() {
    let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nhello";
    assert_eq!(
        read_bounded_response(response(raw).await, 5).await.unwrap(),
        b"hello"
    );
    assert!(matches!(
        read_bounded_response(response(raw).await, 4).await,
        Err(SatsPathError::NetworkError(message)) if message.contains("content-length")
    ));
}

/// Streaming bodies must respect the cumulative limit even without Content-Length.
#[tokio::test]
async fn chunked_response_cannot_bypass_size_limit() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n2\r\nhe\r\n3\r\nllo\r\n0\r\n\r\n";
    let accepted = response(raw).await;
    assert_eq!(accepted.content_length(), None);
    assert_eq!(read_bounded_response(accepted, 5).await.unwrap(), b"hello");
    assert!(matches!(
        read_bounded_response(response(raw).await, 4).await,
        Err(SatsPathError::NetworkError(message)) if message.contains("size limit")
    ));
}

/// Zero is a useful boundary: empty responses succeed and any payload fails.
#[tokio::test]
async fn zero_limit_only_accepts_empty_response() {
    let empty = response(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n").await;
    assert!(read_bounded_response(empty, 0).await.unwrap().is_empty());
    let nonempty = response(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nx").await;
    assert!(matches!(
        read_bounded_response(nonempty, 0).await,
        Err(SatsPathError::NetworkError(_))
    ));
}

/// A connection ending early must not return a successful partial body.
#[tokio::test]
async fn truncated_response_is_a_network_error() {
    let truncated =
        response(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nabc").await;
    assert!(matches!(
        read_bounded_response(truncated, 10).await,
        Err(SatsPathError::NetworkError(message)) if message.contains("reading response stream")
    ));
}

/// HTTP opt-in never exempts private addresses, encoded IPs, or internal ports.
#[tokio::test]
async fn pinned_client_rejects_unsafe_urls_before_connecting() {
    for url in [
        "https://127.0.0.1/",
        "https://[::1]/",
        "https://[::ffff:127.0.0.1]/",
        "https://169.254.169.254/latest/meta-data/",
        "https://10.0.0.1/",
        "http://2130706433/",
        "http://localhost./",
        "https://1.1.1.1:6379/",
        "file:///etc/passwd",
    ] {
        assert!(
            matches!(
                build_pinned_http_client(url, Duration::from_secs(1), true).await,
                Err(SatsPathError::ValidationError(_))
            ),
            "unsafe endpoint was accepted: {url}"
        );
    }
}

/// Public literals need no DNS lookup; plaintext still requires explicit opt-in.
#[tokio::test]
async fn pinned_client_accepts_public_literals_and_enforces_https_policy() {
    for url in ["https://1.1.1.1/", "https://[2606:4700:4700::1111]/"] {
        assert!(build_pinned_http_client(url, Duration::from_secs(1), false)
            .await
            .is_ok());
    }
    assert!(matches!(
        build_pinned_http_client("http://1.1.1.1/", Duration::from_secs(1), false).await,
        Err(SatsPathError::ValidationError(_))
    ));
    assert!(
        build_pinned_http_client("http://1.1.1.1/", Duration::from_secs(1), true)
            .await
            .is_ok()
    );
}
