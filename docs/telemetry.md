# SatsPath Daemon Telemetry & Observability

`satspathd` includes built-in observability across three pillars (`crates/satspathd/src/telemetry/`):

1. **Prometheus Metrics (`GET /metrics`)**
2. **Deep Dependency Health Probes (`GET /health`, `GET /v1/health`, `GET /v2/health`)**
3. **Structured Request Tracing (`X-Request-ID`)**

---

## 1. Prometheus Metrics (`GET /metrics`)

`satspathd` exposes Prometheus text exposition format (`0.0.4`) at `GET /metrics`.

### Exported Metric Families

| Metric Name | Type | Labels | Description |
| :--- | :--- | :--- | :--- |
| `satspathd_http_requests_total` | Counter | `method`, `endpoint`, `status` | Total number of HTTP requests processed by `satspathd`. |
| `satspathd_http_request_duration_seconds` | Histogram | `method`, `endpoint` | HTTP request latency in seconds (`0.005` to `10.0`s buckets). |
| `satspathd_profile_resolution_total` | Counter | `status`, `cache_hit` | Total count of receiver profile resolutions. |
| `satspathd_profile_resolution_duration_seconds` | Histogram | `status` | Duration of receiver profile resolution in seconds. |
| `satspathd_fee_api_requests_total` | Counter | `source`, `status` | Total count of external fee API requests (`mempool`, `esplora`, `bitcoind`). |
| `satspathd_fee_api_latency_seconds` | Histogram | `source`, `status` | Latency of external fee API requests in seconds. |
| `satspathd_transparency_checkpoint_age_seconds` | Gauge | *(none)* | Age of the latest transparency log checkpoint in seconds. |
| `satspathd_rate_limit_dropped_total` | Counter | `reason` | Total requests dropped due to rate limiting (`rate_limited`) or payload cap (`payload_too_large`). |

---

## 2. Deep Health Endpoints (`GET /health`, `/v1/health`, `/v2/health`)

Health endpoints evaluate three live subsystem dependencies and return `HTTP 200 OK` when healthy or `HTTP 503 Service Unavailable` when a critical dependency (`sqlite` or `transparency_log`) is unhealthy:

- **`sqlite`**: Verifies that `satspath-transparency-v1.sqlite3` exists, opens cleanly, and is writable.
- **`fee_api`**: Checks freshness of the multi-source fee cache or executes a bounded `500ms` probe.
- **`transparency_log`**: Verifies checkpoint integrity, tree size, and updates `satspathd_transparency_checkpoint_age_seconds`.

### Example Response

```json
{
  "ok": true,
  "status": "healthy",
  "version": "0.1.0",
  "uptime_seconds": 3612,
  "timestamp": 1782810400,
  "dependencies": {
    "sqlite": {
      "status": "healthy",
      "latency_ms": 0.42,
      "writable": true,
      "log_id": "satspath-log-v1"
    },
    "fee_api": {
      "status": "healthy",
      "latency_ms": 0.05,
      "reachable": true,
      "cached": true,
      "fastest_sat_vb": 6
    },
    "transparency_log": {
      "status": "healthy",
      "latency_ms": 0.81,
      "log_size": 128,
      "consistency_status": "valid"
    }
  }
}
```

---

## 3. Structured Tracing & Request Correlation

Every incoming HTTP request is assigned a correlation ID (`X-Request-ID` header if valid ASCII `<= 128` chars, or a freshly generated UUIDv4) and echoed back in the response `X-Request-ID` header.

### Configuration Environment Variables

| Variable | Values | Default | Description |
| :--- | :--- | :--- | :--- |
| `RUST_LOG` | `info`, `debug`, `satspathd=debug` | `info` | Standard `tracing_subscriber::EnvFilter` directive. |
| `SATSPATH_LOG_FORMAT` | `text`, `pretty`, `json` | `text` | Set to `json` for structured JSON log lines in production containers (`--log-format` CLI flag). |
