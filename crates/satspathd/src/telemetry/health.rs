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

const TRANSPARENCY_DB_FILE: &str = "satspath-transparency-v1.sqlite3";

/// Checks SQLite database connectivity and writability.
pub fn check_sqlite_health(home: &Path) -> DependencyHealth {
    let start = Instant::now();
    let db_path = home.join(TRANSPARENCY_DB_FILE);
    if !db_path.exists() {
        let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
        return DependencyHealth {
            status: "unhealthy".to_string(),
            latency_ms,
            error: Some("transparency database not initialized".to_string()),
            details: serde_json::json!({
                "writable": false,
                "initialized": false,
            }),
        };
    }

    match TransactionalTransparencyStore::open_read_only(home) {
        Ok(store) => {
            let log_id = store.log_id().to_string();
            let is_writable = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&db_path)
                .is_ok();
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            if is_writable {
                DependencyHealth {
                    status: "healthy".to_string(),
                    latency_ms,
                    error: None,
                    details: serde_json::json!({
                        "writable": true,
                        "log_id": log_id,
                    }),
                }
            } else {
                DependencyHealth {
                    status: "unhealthy".to_string(),
                    latency_ms,
                    error: Some("transparency database file is not writable".to_string()),
                    details: serde_json::json!({
                        "writable": false,
                        "log_id": log_id,
                    }),
                }
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

    // 1. Check if a recent fee estimate is already cached and still fresh
    if let Some(cached) = satspath_router::fees::get_cached_fee() {
        let now_secs = satspath_router::fees::current_time_secs();
        let age_secs = now_secs.saturating_sub(cached.timestamp_secs);
        let max_staleness_secs =
            satspath_router::fees::FeeEstimatorConfig::from_env().max_staleness_secs;
        if age_secs < max_staleness_secs {
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            return DependencyHealth {
                status: "healthy".to_string(),
                latency_ms,
                error: None,
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
    }

    // 2. Perform an on-demand probe with a short timeout to prevent slow health endpoints
    let estimator = satspath_router::fees::MultiSourceFeeEstimator::default_from_env();
    let probe =
        tokio::time::timeout(std::time::Duration::from_millis(500), estimator.estimate()).await;

    match probe {
        Ok(Ok(report)) => {
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;
            let is_fallback = !report.is_from_cache && report.sources_succeeded == 0;
            let status = if is_fallback { "error" } else { "success" };
            crate::telemetry::metrics::record_fee_api_request(
                "combined",
                status,
                latency_ms / 1000.0,
            );
            if is_fallback {
                DependencyHealth {
                    status: "degraded".to_string(),
                    latency_ms,
                    error: Some("all fee API sources failed, using fallback fees".to_string()),
                    details: serde_json::json!({
                        "reachable": false,
                        "fastest_sat_vb": report.estimate.fastest_fee,
                        "half_hour_sat_vb": report.estimate.half_hour_fee,
                        "hour_sat_vb": report.estimate.hour_fee,
                        "sources_queried": report.sources_queried,
                        "sources_succeeded": report.sources_succeeded,
                        "source_names": report.source_names,
                        "is_from_cache": report.is_from_cache,
                    }),
                }
            } else {
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
    match TransactionalTransparencyStore::open_read_only(home).and_then(|store| store.load_log()) {
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

static CACHED_DEEP_HEALTH: std::sync::RwLock<
    Option<std::collections::HashMap<std::path::PathBuf, (Instant, DeepHealthResponse)>>,
> = std::sync::RwLock::new(None);
const DEEP_HEALTH_CACHE_TTL_SECS: u64 = 5;

/// Performs a comprehensive health check across all daemon dependencies.
/// Caches result for 5 seconds per home path to prevent outbound request amplification and SQLite thrashing.
pub async fn perform_deep_health_check(home: &Path) -> DeepHealthResponse {
    let home_buf = home.to_path_buf();
    if let Ok(guard) = CACHED_DEEP_HEALTH.read() {
        if let Some(map) = guard.as_ref() {
            if let Some((cached_at, ref resp)) = map.get(&home_buf) {
                if cached_at.elapsed().as_secs() < DEEP_HEALTH_CACHE_TTL_SECS {
                    return resp.clone();
                }
            }
        }
    }

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

    let resp = DeepHealthResponse {
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
    };

    if let Ok(mut guard) = CACHED_DEEP_HEALTH.write() {
        let map = guard.get_or_insert_with(std::collections::HashMap::new);
        map.insert(home_buf, (Instant::now(), resp.clone()));
    }

    resp
}

/// Spawns a background task that periodically refreshes checkpoint-age and fee metrics
/// so Prometheus scrapes always have fresh samples even without separate health check calls.
pub fn spawn_metrics_refresher(home: std::path::PathBuf) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(30));
        loop {
            interval.tick().await;
            check_transparency_health(&home);
            let _ = check_fee_api_health().await;
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transparency_health_does_not_initialize_missing_state() {
        let dir = tempfile::tempdir().unwrap();
        let missing_home = dir.path().join("missing");
        for home in [dir.path(), missing_home.as_path()] {
            let health = check_transparency_health(home);
            assert_eq!(health.status, "unhealthy");
            assert!(health.error.is_some());
        }
        assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    #[test]
    fn transparency_health_preserves_existing_database() {
        let dir = tempfile::tempdir().unwrap();
        TransactionalTransparencyStore::open(dir.path()).unwrap();
        let db_path = dir.path().join(TRANSPARENCY_DB_FILE);
        let before = std::fs::read(&db_path).unwrap();

        let health = check_transparency_health(dir.path());

        assert_eq!(health.status, "healthy");
        assert_eq!(health.details["checkpoint_count"], 0);
        assert_eq!(std::fs::read(db_path).unwrap(), before);
    }

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
