# SatsPath -- Docker Guide

> **Status:** Ready for development and CI builds.
> Mainnet execution of payments is intentionally disabled by design.

---

## Architecture

```
+-----------------------------------------------------------------+
|  docker-compose services                                        |
|                                                                 |
|  +----------------------+     +----------------------------+   |
|  |  satspath-cli        |     |  satspathd (port 9737)     |   |
|  |  Rust / Debian Slim  |     |  Rust / Debian Slim        |   |
|  |  non-root uid:10001  |     |  non-root uid:10002        |   |
|  |  read-only rootfs    |     |  read-only rootfs          |   |
|  |  cap_drop: ALL       |     |  cap_drop: ALL             |   |
|  +----------------------+     +----------------------------+   |
|          |                                 |                    |
|          |                    +------------+                    |
|          |                    | (internal network)              |
|          |            +-------------------+                     |
|          |            |  caddy (TLS proxy)|                     |
|          |            |  ports 80 & 443   |                     |
|          |            +-------------------+                     |
|          |                                                      |
|          v                                                      |
|  +--------------------------------------------------------+     |
|  |  satspath_data (Docker volume)                         |     |
|  |  Named volume: .satspath/ registry survives containers |     |
|  +--------------------------------------------------------+     |
+-----------------------------------------------------------------+
```

## Images & Services

| Service / Image       | Base                    | Size target | Binary / Role             |
| --------------------- | ----------------------- | ----------- | ------------------------- |
| `satspath-cli`        | `debian:bookworm-slim`  | ~25 MB      | `/usr/local/bin/satspath` |
| `satspathd`           | `debian:bookworm-slim`  | ~30 MB      | `/usr/local/bin/satspathd`|
| `caddy`               | `caddy:2-alpine`        | ~45 MB      | TLS reverse proxy sidecar |

Both SatsPath images use:

- **Non-root user** (UID 10001 for CLI, UID 10002 for daemon)
- **Read-only root filesystem** (`read_only: true`)
- **All capabilities dropped** (`cap_drop: ALL`)
- **`no-new-privileges`** security option
- **OCI image labels** for provenance

---

## Quick Start

### Prerequisites

- Docker >= 24 (or Podman >= 4) with BuildKit enabled
- `docker compose` v2 plugin (or `docker-compose` v1)

### 1. Build the image

```bash
make build
# or manually:
docker build -t satspath-cli:latest .
```

### 2. Initialize the registry

```bash
make init
# equivalent to:
docker compose run --rm satspath-cli init
```

This creates `.satspath/` inside the `satspath_data` named volume.

### 3. Register a profile

```bash
# With Lightning Address only:
docker compose run --rm satspath-cli register user@example.com \
  --lightning-address user@example.com

# With Arkade receive pointer (public-only, manual wallet):
docker compose run --rm satspath-cli register user@example.com \
  --arkade-uri "ark:ark1q..."

# With full Ark server + pubkey:
docker compose run --rm satspath-cli register user@example.com \
  --ark-server "https://ark.server.example" \
  --ark-pubkey "02..."
```

### 4. Get a routing quote

```bash
docker compose run --rm satspath-cli quote user@example.com 21000
```

### 5. Start the SatsPath Daemon & Reverse Proxy

To start `satspathd` alongside the Caddy TLS reverse proxy:

```bash
docker compose up -d
docker compose logs -f satspathd caddy
```

---

## TLS Termination & Reverse Proxy

In production environments, `satspathd` must NEVER be exposed as cleartext HTTP to the public internet. SatsPath provides two supported options for TLS:

### Option 1: Reverse Proxy Sidecar (Recommended)

Run `satspathd` behind an industry-standard reverse proxy such as Caddy, Nginx, or Cloudflare.

The provided `docker-compose.yml` configures a Caddy sidecar:
- `satspathd` binds to `127.0.0.1:9737` on the host and exposes `9737` internally to Docker.
- The `caddy` service listens on ports `80` (redirecting to HTTPS) and `443` (terminating TLS).
- Caddy automatically requests and renews certificates from Let's Encrypt or ZeroSSL.
- To configure for your public domain, update `docker/Caddyfile` with your domain (e.g. `node.example.com`).

Set `SATSPATHD_BEHIND_PROXY=1` (or pass `--behind-proxy`) so `satspathd` properly trusts and extracts client IPs from `X-Forwarded-For` / `X-Real-IP`.

When preserving the public `Host` header, also set
`SATSPATH_AUTHORITY_DOMAIN=node.example.com` in the daemon environment, or set
`SATSPATH_AUTHORITY_URL=https://node.example.com/v2`. The daemon rejects
unconfigured DNS hosts even behind a proxy to prevent DNS rebinding. Native TLS
deployments using a DNS hostname need the same explicit hostname configuration.

### Option 2: Native TLS in satspathd

`satspathd` can also terminate TLS natively using Rustls:

```bash
satspathd --bind 0.0.0.0:9737 \
  --tls-cert /path/to/fullchain.pem \
  --tls-key /path/to/privkey.pem
```

Or via environment variables:
- `SATSPATHD_TLS_CERT=/path/to/fullchain.pem`
- `SATSPATHD_TLS_KEY=/path/to/privkey.pem`

### Cleartext Binding Security Audit & Enforcement

When `satspathd` binds to a non-loopback interface (such as `0.0.0.0`, `::`, or an external IP) without `--tls-cert`/`--tls-key` or `--behind-proxy`:
- By default, it logs a prominent warning warning of insecure cleartext exposure.
- When `--require-tls-or-proxy` is set (or `SATSPATHD_REQUIRE_TLS_OR_PROXY=1`), `satspathd` **fails fast** on startup with an error, preventing accidental deployment of cleartext HTTP endpoints.

Localhost / loopback bindings (`127.0.0.1`, `::1`) remain allowed for zero-friction local development.

### Production Configuration Flags & Environment Variables

| Flag / Environment Variable | Default | Production Requirement |
| :--- | :--- | :--- |
| `--behind-proxy` / `SATSPATHD_BEHIND_PROXY=1` | `false` | Enable when running behind Caddy/Nginx so `satspathd` trusts `X-Forwarded-For` / `X-Real-IP`. |
| `--require-tls-or-proxy` / `SATSPATHD_REQUIRE_TLS_OR_PROXY=1` | `false` | **Recommended in production.** Fails closed on startup if bound to a non-loopback address without TLS or `--behind-proxy`. |
| `SATSPATH_AUTHORITY_DOMAIN` | *(none)* | Set to your public domain (e.g. `node.example.com`) to allow incoming `Host` headers and prevent DNS rebinding. |
| `SATSPATHD_AUTH_TOKEN` | `<home>/admin.macaroon` | 64-character hex Bearer token for admin/mutating `/v1/*` endpoints (auto-generated in `<home>/admin.macaroon` if unset). |
| `--log-format` / `SATSPATH_LOG_FORMAT` | `text` | Set to `json` for structured JSON logs in Docker/Kubernetes (`text` or `pretty` for human-readable output). |
| `GET /health` & `GET /metrics` | Enabled | Liveness probe (`/health`), deep dependency health probe (`/v1/health`), and Prometheus scrape endpoint (`/metrics`). |

---

## Make targets

```bash
make help          # Show all targets
make build         # Build CLI image
make build-cli     # Build CLI image
make run CMD="--help"  # Run any CLI command
make shell         # Open a debug shell in the CLI container
make up            # Start daemon service in background
make down          # Stop all services
make logs          # Tail all service logs
make scan          # Run Trivy vulnerability scan on CLI & daemon
make clean         # Remove built images and dangling layers
make smoke         # Build + verify --help output
```

---

## Security design

### What is protected

| Concern                 | Mitigation                                                 |
| ----------------------- | ---------------------------------------------------------- |
| Insecure Cleartext HTTP | Native TLS (rustls) or Caddy reverse proxy; audit check    |
| Private keys in image   | `.dockerignore` blocks `*.key`, `.satspath/`, `.env`       |
| Root escalation         | `no-new-privileges`, `cap_drop: ALL`, non-root users       |
| Container escape        | Read-only root filesystem + tmpfs for `/tmp` only          |
| Dependency supply chain | `npm ci --ignore-scripts` (no postinstall scripts)         |
| Secret injection        | `.env` is gitignored; use Docker secrets or env at runtime |
| Vulnerability tracking  | Trivy scan in CI via `.github/workflows/docker.yml`        |

### What is intentionally not in Docker

- No wallet seed phrases
- No private spending keys
- No Arkade session tokens
- No mainnet payment execution

### Layer caching strategy (Rust)

The Rust build uses [`cargo-chef`](https://github.com/LukeMathWalker/cargo-chef):

```
Layer 1: cargo-chef planner  -> only re-runs when Cargo.toml/Cargo.lock change
Layer 2: cargo-chef cacher   -> pre-builds all deps (very slow, cached)
Layer 3: builder             -> compiles src/ (fast, re-runs on src change)
Layer 4: runtime             -> copies single binary (~25 MB)
```

This means typical CI rebuilds take **~30 seconds** instead of 10+ minutes.

---

## Production checklist

- [ ] Ensure TLS is configured (either Caddy sidecar or native `--tls-cert` / `--tls-key`)
- [ ] Set `SATSPATHD_REQUIRE_TLS_OR_PROXY=1` in production container environment
- [ ] Push to a private registry (GHCR, ECR, etc.) -- see `docker.yml` CI workflow
- [ ] Pin base image digests (replace `bookworm-slim` tags with `sha256:...`)
- [ ] Set `RUST_LOG` to `warn` in production
- [ ] Configure backup for `satspath_data` volume (e.g. `docker run --rm -v satspath_data:/data -v $(pwd):/backup debian:bookworm-slim tar czf /backup/satspath_data_$(date +%F).tar.gz -C /data .`)
- [ ] Run `make scan` before each release to check for CVEs
- [ ] Review CI SARIF reports in GitHub Security tab

---

## Troubleshooting

**`cargo: command not found` in CI**
-> The build runs inside the container; you do not need Cargo on the host.

**`Permission denied: /data`**
-> The `satspath_data` volume ownership may be wrong. Run an entrypoint override as root:

```bash
# For CLI container (UID 10001):
docker compose run --rm --entrypoint /bin/sh --user root satspath-cli -c "chown -R 10001:10001 /data && chmod -R 770 /data"

# For Daemon container (UID 10002):
docker compose run --rm --entrypoint /bin/sh --user root satspathd -c "chown -R 10002:10002 /data && chmod -R 770 /data"
```
