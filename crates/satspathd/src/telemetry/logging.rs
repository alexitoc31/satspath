//! Structured logging and tracing subscriber configuration for `satspathd`.

use anyhow::Result;
use tiny_http::Header;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

/// Initializes the global tracing subscriber.
///
/// Supports JSON formatted logs (for structured ingestion by Vector/Fluentd/Loki)
/// or human-friendly text format.
pub fn init_telemetry(format_override: Option<&str>) -> Result<()> {
    let log_format = format_override
        .map(String::from)
        .or_else(|| std::env::var("SATSPATH_LOG_FORMAT").ok())
        .unwrap_or_else(|| "text".to_string());

    let filter = std::env::var("SATSPATH_LOG_LEVEL")
        .ok()
        .and_then(|lvl| EnvFilter::try_new(lvl).ok())
        .or_else(|| EnvFilter::try_from_default_env().ok())
        .unwrap_or_else(|| EnvFilter::new("info"));

    if log_format.eq_ignore_ascii_case("json") {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .json()
            .flatten_event(true)
            .with_current_span(true)
            .with_span_list(true);

        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .try_init()
            .ok();
    } else if log_format.eq_ignore_ascii_case("text") {
        let fmt_layer = tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_thread_ids(false);

        tracing_subscriber::registry()
            .with(filter)
            .with(fmt_layer)
            .try_init()
            .ok();
    } else {
        anyhow::bail!(
            "unsupported log format '{log_format}': supported formats are 'text' and 'json'"
        );
    }

    Ok(())
}

/// Extracts an existing `X-Request-Id` from HTTP headers or generates a new UUID v4.
pub fn get_or_generate_request_id(headers: &[Header]) -> String {
    for header in headers {
        if header.field.equiv("x-request-id") {
            let val = header.value.as_str().trim();
            if !val.is_empty()
                && val.len() <= 128
                && val
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
            {
                return val.to_string();
            }
        }
    }
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_or_generate_request_id_from_header() {
        let header = "X-Request-Id: test-req-12345".parse::<Header>().unwrap();
        let id = get_or_generate_request_id(&[header]);
        assert_eq!(id, "test-req-12345");
    }

    #[test]
    fn test_get_or_generate_request_id_fallback_uuid() {
        let id = get_or_generate_request_id(&[]);
        assert_eq!(id.len(), 36);
        assert!(uuid::Uuid::parse_str(&id).is_ok());
    }

    #[test]
    fn test_reject_malformed_request_id() {
        let header = "X-Request-Id: invalid/injection\nheader"
            .parse::<Header>()
            .unwrap();
        let id = get_or_generate_request_id(&[header]);
        assert_ne!(id, "invalid/injection\nheader");
        assert_eq!(id.len(), 36);
    }

    #[test]
    fn test_init_telemetry_rejects_unsupported_format() {
        let res = init_telemetry(Some("jsno"));
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("unsupported log format"));
    }
}
