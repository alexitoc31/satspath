//! Dependency health checks for `satspathd`: SQLite writability, Fee API reachability, and Transparency log health.

use satspath_core::TransactionalTransparencyStore;
use serde::Serialize;
use std::path::Path;
use std::time::Instant;

#[derive(Debug, Serialize, Clone)]
pub struct DependencyHealth {
    pub status: String,
    pub latency_ms: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(flatten)]
    pub details: serde_json::Value,
}

#[derive(Debug, Serialize, Clone)]
pub struct DeepHealthResponse {
    pub ok: bool,
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub timestamp: i64,
    pub dependencies: HealthDependencies,
}

#[derive(Debug, Serialize, Clone)]
pub struct HealthDependencies {
    pub sqlite: DependencyHealth,
    pub fee_api: DependencyHealth,
    pub transparency_log: DependencyHealth,
}

static START_TIME: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);

pub fn uptime_seconds() -> u64 {
    START_TIME.elapsed().as_secs()
}

/// Checks SQLite database connectivity and writability.
pub fn check_sqlite_health(home: &Path) -> DependencyHealth {
    let start = Instant::now();
    match TransactionalTransparencyStore::open(home) {
        Ok(store) => {
            let log_id = store.log_id().to_string();
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            DependencyHealth {
                status: "healthy".to_string(),
                latency_ms,
                error: None,
                details: serde_json::json!({
                    "writable": true,
                    "log_id": log_id,
                }),
            }
        }
        Err(e) => {
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            DependencyHealth {
                status: "unhealthy".to_string(),
                latency_ms,
                error: Some(e.to_string()),
                details: serde_json::json!({
                    "writable": false,
                }),
            }
        }
    }
}

/// Checks external Bitcoin Fee API reachability and latency.
pub async fn check_fee_api_health() -> DependencyHealth {
    let start = Instant::now();

    // 1. Check if a recent fee estimate is already cached
    if let Some(cached) = satspath_router::fees::get_cached_fee() {
        let now_secs = satspath_router::fees::current_time_secs();
        let age_secs = now_secs.saturating_sub(cached.timestamp_secs);
        let is_stale = age_secs > 1800;
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        return DependencyHealth {
            status: if is_stale {
                "degraded".to_string()
            } else {
                "healthy".to_string()
            },
            latency_ms,
            error: if is_stale {
                Some("cached fee estimate is stale".to_string())
            } else {
                None
            },
            details: serde_json::json!({
                "reachable": true,
                "cached": true,
                "age_secs": age_secs,
                "fastest_sat_vb": cached.estimate.fastest_fee,
                "half_hour_sat_vb": cached.estimate.half_hour_fee,
                "hour_sat_vb": cached.estimate.hour_fee,
                "sources_used": cached.sources_used,
            }),
        };
    }

    // 2. Perform an on-demand probe with a short timeout to prevent slow health endpoints
    let estimator = satspath_router::fees::MultiSourceFeeEstimator::default_from_env();
    let probe =
        tokio::time::timeout(std::time::Duration::from_millis(500), estimator.estimate()).await;

    match probe {
        Ok(Ok(report)) => {
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            crate::telemetry::metrics::record_fee_api_request(
                "combined",
                "success",
                latency_ms / 1000.0,
            );
            DependencyHealth {
                status: "healthy".to_string(),
                latency_ms,
                error: None,
                details: serde_json::json!({
                    "reachable": true,
                    "fastest_sat_vb": report.estimate.fastest_fee,
                    "half_hour_sat_vb": report.estimate.half_hour_fee,
                    "hour_sat_vb": report.estimate.hour_fee,
                    "sources_queried": report.sources_queried,
                    "sources_succeeded": report.sources_succeeded,
                    "source_names": report.source_names,
                    "is_from_cache": report.is_from_cache,
                }),
            }
        }
        Ok(Err(e)) => {
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            crate::telemetry::metrics::record_fee_api_request(
                "combined",
                "error",
                latency_ms / 1000.0,
            );
            DependencyHealth {
                status: "degraded".to_string(),
                latency_ms,
                error: Some(e.to_string()),
                details: serde_json::json!({
                    "reachable": false,
                    "cached": false,
                }),
            }
        }
        Err(_) => {
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            crate::telemetry::metrics::record_fee_api_request(
                "combined",
                "timeout",
                latency_ms / 1000.0,
            );
            DependencyHealth {
                status: "degraded".to_string(),
                latency_ms,
                error: Some("fee API probe timed out after 500ms".to_string()),
                details: serde_json::json!({
                    "reachable": false,
                    "timed_out": true,
                }),
            }
        }
    }
}

/// Checks the state and checkpoint age of the local Transparency Log.
pub fn check_transparency_health(home: &Path) -> DependencyHealth {
    let start = Instant::now();
    match crate::handlers::transparency::transparency_log_at(home) {
        Ok(log) => {
            let latest_ts = log.checkpoints().last().map(|c| c.created_at).unwrap_or(0);
            let now = chrono::Utc::now().timestamp();
            let age_secs = if latest_ts == 0 {
                0
            } else {
                (now - latest_ts).max(0)
            };
            crate::telemetry::metrics::set_checkpoint_age(age_secs as f64);
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            let status = if age_secs > 86400 && latest_ts > 0 {
                "degraded"
            } else {
                "healthy"
            };
            DependencyHealth {
                status: status.to_string(),
                latency_ms,
                error: None,
                details: serde_json::json!({
                    "checkpoint_count": log.checkpoints().len(),
                    "latest_checkpoint_age_secs": age_secs,
                    "is_stale": age_secs > 86400 && latest_ts > 0,
                }),
            }
        }
        Err(e) => {
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            DependencyHealth {
                status: "unhealthy".to_string(),
                latency_ms,
                error: Some(e.to_string()),
                details: serde_json::json!({
                    "checkpoint_count": 0,
                }),
            }
        }
    }
}

/// Performs a comprehensive health check across all daemon dependencies.
pub async fn perform_deep_health_check(home: &Path) -> DeepHealthResponse {
    let sqlite = check_sqlite_health(home);
    let fee_api = check_fee_api_health().await;
    let transparency_log = check_transparency_health(home);

    let overall_status = if sqlite.status == "unhealthy" || transparency_log.status == "unhealthy" {
        "unhealthy"
    } else if fee_api.status == "unhealthy"
        || fee_api.status == "degraded"
        || transparency_log.status == "degraded"
    {
        "degraded"
    } else {
        "healthy"
    };

    let ok = overall_status == "healthy" || overall_status == "degraded";

    DeepHealthResponse {
        ok,
        status: overall_status.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: uptime_seconds(),
        timestamp: chrono::Utc::now().timestamp(),
        dependencies: HealthDependencies {
            sqlite,
            fee_api,
            transparency_log,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_deep_health_check_with_tempdir() {
        let dir = tempfile::tempdir().unwrap();
        // Initialize identity and transparency store in tempdir
        crate::handlers::wallet::load_or_create_identity(dir.path()).unwrap();
        crate::handlers::transparency::transparency_log_at(dir.path()).unwrap();

        let health = perform_deep_health_check(dir.path()).await;
        assert!(health.ok);
        assert_eq!(health.dependencies.sqlite.status, "healthy");
        assert_eq!(health.dependencies.transparency_log.status, "healthy");
        assert!(health.status == "healthy" || health.status == "degraded");
    }
}
