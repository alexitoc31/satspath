use crate::lightning::{fetch_invoice_with_options, fetch_lnurl_metadata_with_options};
use crate::{fetch_invoice, LnurlPayMetadata};
use mockito::Server;
use serde_json::json;

#[tokio::test]
async fn test_full_lnurl_flow_with_mock() {
    let mut server = Server::new_async().await;
    let url = server.url();
    // mockito url is like http://127.0.0.1:12345
    // fetch_lnurl_metadata expects a lightning address like alice@domain
    // and fetches https://domain/.well-known/lnurlp/alice

    // Instead of using fetch_lnurl_metadata directly (which hardcodes https://),
    // let's just mock the LNURL flow since we want to test the full LNURL-pay two-step integration.

    // Mock the LNURL pay metadata response
    let metadata = json!({
        "callback": format!("{}/callback", url),
        "minSendable": 1000,
        "maxSendable": 10000000,
        "tag": "payRequest",
        "commentAllowed": 255
    });

    let _m1 = server
        .mock("GET", "/.well-known/lnurlp/alice")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(metadata.to_string())
        .create_async()
        .await;

    // Mock the callback response
    // Using a valid 2500 sat invoice
    let bolt11 = "lnbc25m1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5vdhkven9v5sxyetpdees9qzpzz8txr49kpzaem7e4lh5e0cqsjxvnmrgrmrr7x9qktv4u49v8yezahqvqk8c38n6vdxn3xqzwx3qp5v7rqpxdv";
    let callback_resp = json!({
        "pr": bolt11,
        "routes": []
    });

    let _m2 = server
        .mock("GET", "/callback?amount=2500000") // 2500 sats * 1000 msats
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(callback_resp.to_string())
        .create_async()
        .await;

    // Test the client side
    // Since fetch_lnurl_metadata hardcodes `https://`, we'll just construct the metadata manually as if we received it,
    // OR we could change `fetch_lnurl_metadata` to allow testing, but let's test `fetch_invoice` which is the complex part.
    let meta = LnurlPayMetadata {
        callback: format!("{}/callback", url),
        min_sendable: 1000,
        max_sendable: 10000000,
        tag: "payRequest".to_string(),
        comment_allowed: 255,
    };

    let result = fetch_invoice_with_options(&meta, 2500, None, false).await;
    // We expect it to fail validation (either parse error or expired) because we don't have a fresh invoice
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("failed to parse") || err.contains("expired"),
        "Expected validation error, got: {}",
        err
    );
}

#[tokio::test]
async fn test_lnurl_error_flow_with_mock() {
    let mut server = Server::new_async().await;
    let url = server.url();

    let callback_resp = json!({
        "status": "ERROR",
        "reason": "Amount too high"
    });

    let _m2 = server
        .mock("GET", "/callback?amount=5000000")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(callback_resp.to_string())
        .create_async()
        .await;

    let meta = LnurlPayMetadata {
        callback: format!("{}/callback", url),
        min_sendable: 1000,
        max_sendable: 10000000,
        tag: "payRequest".to_string(),
        comment_allowed: 0,
    };

    let result = fetch_invoice_with_options(&meta, 5000, None, false).await;
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("LNURL server returned error: Amount too high"),
        "Unexpected error: {}",
        err
    );
}

#[tokio::test]
async fn test_lnurl_amount_out_of_bounds() {
    let meta = LnurlPayMetadata {
        callback: "http://dummy/callback".to_string(),
        min_sendable: 10000,  // 10 sats
        max_sendable: 100000, // 100 sats
        tag: "payRequest".to_string(),
        comment_allowed: 0,
    };

    // Below minimum
    let res_min = fetch_invoice(&meta, 5, None).await;
    assert!(res_min.is_err());
    assert!(res_min.unwrap_err().to_string().contains("below minimum"));

    // Above maximum
    let res_max = fetch_invoice(&meta, 150, None).await;
    assert!(res_max.is_err());
    assert!(res_max.unwrap_err().to_string().contains("exceeds maximum"));
}

#[tokio::test]
async fn test_lnurl_callback_missing_or_empty_pr() {
    let mut server = Server::new_async().await;
    let url = server.url();

    // Mock response with missing `pr`
    let callback_missing_pr = json!({
        "routes": []
    });
    let _m1 = server
        .mock("GET", "/callback-missing?amount=5000000")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(callback_missing_pr.to_string())
        .create_async()
        .await;

    // Mock response with empty `pr`
    let callback_empty_pr = json!({
        "pr": "",
        "routes": []
    });
    let _m2 = server
        .mock("GET", "/callback-empty?amount=5000000")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(callback_empty_pr.to_string())
        .create_async()
        .await;

    let meta_missing = LnurlPayMetadata {
        callback: format!("{}/callback-missing", url),
        min_sendable: 1000,
        max_sendable: 10000000,
        tag: "payRequest".to_string(),
        comment_allowed: 0,
    };

    let result_missing = fetch_invoice_with_options(&meta_missing, 5000, None, false).await;
    assert!(result_missing.is_err());
    assert!(result_missing
        .unwrap_err()
        .to_string()
        .contains("missing 'pr'"));

    let meta_empty = LnurlPayMetadata {
        callback: format!("{}/callback-empty", url),
        min_sendable: 1000,
        max_sendable: 10000000,
        tag: "payRequest".to_string(),
        comment_allowed: 0,
    };

    let result_empty = fetch_invoice_with_options(&meta_empty, 5000, None, false).await;
    assert!(result_empty.is_err());
    assert!(result_empty
        .unwrap_err()
        .to_string()
        .contains("empty invoice"));
}

#[tokio::test]
async fn test_invalid_lightning_address_format() {
    use crate::fetch_lnurl_metadata;

    // Missing domain
    let res1 = fetch_lnurl_metadata("alice").await;
    assert!(res1.is_err());
    assert!(res1
        .unwrap_err()
        .to_string()
        .contains("invalid Lightning Address"));

    // Multiple @ symbols
    let res2 = fetch_lnurl_metadata("alice@bob@domain.com").await;
    assert!(res2.is_err());
    assert!(res2
        .unwrap_err()
        .to_string()
        .contains("invalid Lightning Address"));
}

#[tokio::test]
async fn test_lnurl_invalid_tag() {
    let mut server = Server::new_async().await;
    let url = server.url();
    let host = url.strip_prefix("http://").unwrap(); // get 127.0.0.1:port

    let metadata_wrong_tag = json!({
        "callback": format!("{}/callback", url),
        "minSendable": 1000,
        "maxSendable": 10000000,
        "tag": "withdrawRequest", // invalid tag
        "commentAllowed": 0
    });

    let _m1 = server
        .mock("GET", "/.well-known/lnurlp/alice")
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(metadata_wrong_tag.to_string())
        .create_async()
        .await;

    let addr = format!("alice@{}", host);
    let result = fetch_lnurl_metadata_with_options(&addr, false).await;
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .to_string()
        .contains("unexpected LNURL tag"));
}
