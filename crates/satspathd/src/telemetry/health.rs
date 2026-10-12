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
                    "sources_used": fee_source_types(&cached.sources_used),
                }),
            };
        }
    }

    // 2. Perform an on-demand probe with a short timeout to prevent slow health endpoints
    let estimator = satspath_router::fees::MultiSourceFeeEstimator::default_from_env();
    let probe =
        tokio::time::timeout(std::time::Duration::from_millis(500), estimator.estimate()).await;

    match probe {
        Ok(Ok(report)) => fee_report_health(report, start.elapsed().as_secs_f64() * 1000.0),
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

// Only expose known source types; URLs and unrecognized names may contain credentials.
fn fee_source_types(names: &[String]) -> Vec<&'static str> {
    names
        .iter()
        .map(|name| match name.split('(').next().unwrap_or_default() {
            "BitcoinCore" => "BitcoinCore",
            "MempoolSpace" => "MempoolSpace",
            "Esplora" => "Esplora",
            "Static" => "Static",
            "FallbackFees" => "FallbackFees",
            _ => "Unknown",
        })
        .collect()
}

fn fee_report_health(
    report: satspath_router::fees::ConsensusFeeReport,
    latency_ms: f64,
) -> DependencyHealth {
    // A successful consensus can happen to match the fallback rates.
    let is_fallback = !report.is_from_cache
        && report.estimate == satspath_router::fees::FALLBACK_FEES
        && report
            .source_names
            .iter()
            .any(|name| name == "FallbackFees");
    let status = if is_fallback { "error" } else { "success" };
    crate::telemetry::metrics::record_fee_api_request("combined", status, latency_ms / 1000.0);
    DependencyHealth {
        status: if is_fallback { "degraded" } else { "healthy" }.to_string(),
        latency_ms,
        error: is_fallback
            .then(|| "insufficient fee API sources for consensus, using fallback fees".to_string()),
        details: serde_json::json!({
            "reachable": !is_fallback,
            "fastest_sat_vb": report.estimate.fastest_fee,
            "half_hour_sat_vb": report.estimate.half_hour_fee,
            "hour_sat_vb": report.estimate.hour_fee,
            "sources_queried": report.sources_queried,
            "sources_succeeded": report.sources_succeeded,
            "source_names": fee_source_types(&report.source_names),
            "is_from_cache": report.is_from_cache,
        }),
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

    #[tokio::test]
    async fn fee_health_is_degraded_when_consensus_minimum_is_not_met() {
        use satspath_router::fees::{
            FeeEstimatorConfig, FeeSource, MultiSourceFeeEstimator, FALLBACK_FEES,
        };

        let mut live_estimate = FALLBACK_FEES;
        live_estimate.fastest_fee = 30;
        for sources in [vec![], vec![FeeSource::Static(live_estimate)]] {
            let sources_succeeded = sources.len();
            let estimator = MultiSourceFeeEstimator::new(
                FeeEstimatorConfig {
                    sources,
                    min_sources_for_consensus: 2,
                    max_staleness_secs: 1800,
                    request_timeout_ms: 100,
                    cache: None,
                }
                .with_isolated_cache(),
            );
            let report = estimator.estimate().await.unwrap();
            assert_eq!(report.sources_succeeded, sources_succeeded);
            assert_eq!(report.estimate, FALLBACK_FEES);
            assert!(!report.is_from_cache);

            let health = fee_report_health(report, 1.0);
            assert_eq!(health.status, "degraded");
            assert_eq!(health.details["reachable"], false);
            assert_eq!(health.details["sources_succeeded"], sources_succeeded);
            assert!(health.error.unwrap().contains("insufficient"));
        }
    }

    #[tokio::test]
    async fn fee_health_is_healthy_when_consensus_matches_fallback_rates() {
        use satspath_router::fees::{
            FeeEstimatorConfig, FeeSource, MultiSourceFeeEstimator, FALLBACK_FEES,
        };

        let estimator = MultiSourceFeeEstimator::new(
            FeeEstimatorConfig {
                sources: vec![FeeSource::Static(FALLBACK_FEES)],
                min_sources_for_consensus: 1,
                max_staleness_secs: 1800,
                request_timeout_ms: 100,
                cache: None,
            }
            .with_isolated_cache(),
        );
        let report = estimator.estimate().await.unwrap();
        assert!(!report.is_from_cache);
        let health = fee_report_health(report, 1.0);
        assert_eq!(health.status, "healthy");
        assert_eq!(health.details["reachable"], true);
        assert!(health.error.is_none());
    }

    #[test]
    fn fee_health_preserves_cached_fallback_status() {
        let health = fee_report_health(
            satspath_router::fees::ConsensusFeeReport {
                estimate: satspath_router::fees::FALLBACK_FEES,
                timestamp_secs: 0,
                sources_queried: 2,
                sources_succeeded: 0,
                source_names: vec!["Static".into()],
                is_from_cache: true,
                is_decayed: true,
            },
            1.0,
        );
        assert_eq!(health.status, "healthy");
        assert_eq!(health.details["reachable"], true);
        assert_eq!(health.details["is_from_cache"], true);
        assert!(health.error.is_none());
    }

    #[test]
    fn fee_health_exposes_only_source_types() {
        let source_names: Vec<String> = [
            "BitcoinCore(https://user:password@rpc.example/wallet/secret?token=secret#secret)",
            "MempoolSpace(https://user:password@fees.example/secret?token=secret)",
            "Esplora(http://user:password@[::1]:3000/secret?token=secret)",
            "MempoolSpace(invalid URL with secret)",
            "Static",
            "FallbackFees",
            "https://user:password@unknown.example/secret?token=secret",
            "secret",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        let expected = serde_json::json!([
            "BitcoinCore",
            "MempoolSpace",
            "Esplora",
            "MempoolSpace",
            "Static",
            "FallbackFees",
            "Unknown",
            "Unknown",
        ]);
        assert_eq!(serde_json::json!(fee_source_types(&source_names)), expected);
        for is_from_cache in [false, true] {
            let report = satspath_router::fees::ConsensusFeeReport {
                estimate: satspath_router::fees::FALLBACK_FEES,
                timestamp_secs: 0,
                sources_queried: 2,
                sources_succeeded: 1,
                source_names: source_names.clone(),
                is_from_cache,
                is_decayed: false,
            };
            let health = fee_report_health(report, 1.0);
            assert_eq!(
                health.status,
                if is_from_cache { "healthy" } else { "degraded" }
            );
            assert_eq!(health.details["source_names"], expected);
            let serialized = serde_json::to_string(&health).unwrap();
            for sensitive in ["user", "password", "secret", "token", "https://", "http://"] {
                assert!(!serialized.contains(sensitive), "leaked {sensitive}");
            }
        }
    }

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
