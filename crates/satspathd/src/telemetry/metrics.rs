//! Prometheus metrics collection and exposition for `satspathd`.

use anyhow::Result;
use prometheus::{
    register_counter_vec, register_gauge, register_histogram_vec, CounterVec, Encoder, Gauge,
    HistogramVec, TextEncoder,
};
use std::sync::LazyLock;

pub static HTTP_REQUESTS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "satspathd_http_requests_total",
        "Total number of HTTP requests processed by satspathd",
        &["method", "endpoint", "status"]
    )
    .expect("metric registration failed: satspathd_http_requests_total")
});

pub static HTTP_REQUEST_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    let buckets = vec![
        0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ];
    register_histogram_vec!(
        "satspathd_http_request_duration_seconds",
        "HTTP request latency in seconds",
        &["method", "endpoint"],
        buckets
    )
    .expect("metric registration failed: satspathd_http_request_duration_seconds")
});

pub static PROFILE_RESOLUTION_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "satspathd_profile_resolution_total",
        "Total count of receiver profile resolutions",
        &["status", "cache_hit"]
    )
    .expect("metric registration failed: satspathd_profile_resolution_total")
});

pub static PROFILE_RESOLUTION_DURATION_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    let buckets = vec![0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0];
    register_histogram_vec!(
        "satspathd_profile_resolution_duration_seconds",
        "Duration of receiver profile resolution in seconds",
        &["status"],
        buckets
    )
    .expect("metric registration failed: satspathd_profile_resolution_duration_seconds")
});

pub static FEE_API_REQUESTS_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "satspathd_fee_api_requests_total",
        "Total count of external fee API requests",
        &["source", "status"]
    )
    .expect("metric registration failed: satspathd_fee_api_requests_total")
});

pub static FEE_API_LATENCY_SECONDS: LazyLock<HistogramVec> = LazyLock::new(|| {
    let buckets = vec![0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];
    register_histogram_vec!(
        "satspathd_fee_api_latency_seconds",
        "Latency of external fee API requests in seconds",
        &["source", "status"],
        buckets
    )
    .expect("metric registration failed: satspathd_fee_api_latency_seconds")
});

pub static TRANSPARENCY_CHECKPOINT_AGE_SECONDS: LazyLock<Gauge> = LazyLock::new(|| {
    register_gauge!(
        "satspathd_transparency_checkpoint_age_seconds",
        "Age of the latest transparency log checkpoint in seconds"
    )
    .expect("metric registration failed: satspathd_transparency_checkpoint_age_seconds")
});

pub static RATE_LIMIT_DROPPED_TOTAL: LazyLock<CounterVec> = LazyLock::new(|| {
    register_counter_vec!(
        "satspathd_rate_limit_dropped_total",
        "Total requests dropped due to rate limiting or body size bounds",
        &["reason"]
    )
    .expect("metric registration failed: satspathd_rate_limit_dropped_total")
});

/// Records an incoming HTTP request execution.
pub fn record_http_request(method: &str, endpoint: &str, status: u16, duration_secs: f64) {
    let status_str = status.to_string();
    HTTP_REQUESTS_TOTAL
        .with_label_values(&[method, endpoint, &status_str])
        .inc();
    HTTP_REQUEST_DURATION_SECONDS
        .with_label_values(&[method, endpoint])
        .observe(duration_secs);
}

/// Records a profile resolution event.
pub fn record_profile_resolution(status: &str, cache_hit: bool, duration_secs: f64) {
    let cache_hit_str = if cache_hit { "true" } else { "false" };
    PROFILE_RESOLUTION_TOTAL
        .with_label_values(&[status, cache_hit_str])
        .inc();
    PROFILE_RESOLUTION_DURATION_SECONDS
        .with_label_values(&[status])
        .observe(duration_secs);
}

/// Records a fee API request.
pub fn record_fee_api_request(source: &str, status: &str, latency_secs: f64) {
    FEE_API_REQUESTS_TOTAL
        .with_label_values(&[source, status])
        .inc();
    FEE_API_LATENCY_SECONDS
        .with_label_values(&[source, status])
        .observe(latency_secs);
}

/// Updates the recorded checkpoint age gauge.
pub fn set_checkpoint_age(age_secs: f64) {
    TRANSPARENCY_CHECKPOINT_AGE_SECONDS.set(age_secs);
}

/// Records a rate-limited or payload-too-large dropped request.
pub fn record_rate_limit_dropped(reason: &str) {
    RATE_LIMIT_DROPPED_TOTAL.with_label_values(&[reason]).inc();
}

/// Serializes all registered Prometheus metrics into text exposition format.
pub fn gather_metrics() -> Result<String> {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)?;
    String::from_utf8(buffer).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_gather_metrics() {
        record_http_request("GET", "/v1/health", 200, 0.005);
        record_profile_resolution("success", false, 0.025);
        record_fee_api_request("mempool", "success", 0.08);
        set_checkpoint_age(42.0);
        record_rate_limit_dropped("rate_limited");

        let gathered = gather_metrics().expect("gathering metrics failed");
        assert!(gathered.contains("satspathd_http_requests_total"));
        assert!(gathered.contains("endpoint=\"/v1/health\""));
        assert!(gathered.contains("satspathd_profile_resolution_total"));
        assert!(gathered.contains("satspathd_transparency_checkpoint_age_seconds"));
        assert!(gathered.contains("satspathd_rate_limit_dropped_total"));
    }
}
