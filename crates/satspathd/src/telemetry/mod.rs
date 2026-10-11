//! Telemetry and observability: Prometheus metrics, structured logging, OpenTelemetry tracing, and health checks.

pub mod health;
pub mod logging;
pub mod metrics;

pub use health::{perform_deep_health_check, DeepHealthResponse};
pub use logging::{get_or_generate_request_id, init_telemetry};
pub use metrics::{gather_metrics, record_http_request, record_profile_resolution};
