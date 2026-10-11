//! Configuration types: CLI args, AppState, WalletState, and constants.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use clap::Parser;
use serde::{Deserialize, Serialize};

use crate::rate_limit;

pub(crate) const DEFAULT_BIND: &str = "127.0.0.1:9737";
pub(crate) const DEFAULT_NETWORK: &str = "devnet";
pub(crate) const WALLET_FILE: &str = "wallet.json";
pub(crate) const IDENTITY_SUBDIR: &str = "identity";

#[derive(Parser)]
#[command(
    name = "satspathd",
    about = "Local SatsPath receiver-profile daemon",
    version = "0.1.0"
)]
pub(crate) struct Cli {
    /// Enable experimental public-profile Hyperswarm transport (requires Node >=20 and SDK npm ci).
    #[arg(long)]
    pub(crate) p2p: bool,
    /// HTTP bind address. Defaults to SATSPATHD_BIND or 127.0.0.1:9737.
    #[arg(long)]
    pub(crate) bind: Option<String>,
    /// SatsPath network label. Defaults to SATSPATH_NETWORK or devnet.
    #[arg(long)]
    pub(crate) network: Option<String>,
    /// SatsPath home directory. Defaults to SATSPATH_HOME or ~/.satspath.
    #[arg(long)]
    pub(crate) home: Option<PathBuf>,
    /// Do not open the wallet UI in a browser on startup.
    #[arg(long)]
    pub(crate) no_open: bool,
    /// Trust reverse proxy headers (X-Forwarded-For, X-Real-IP) for rate limiting.
    #[arg(long)]
    pub(crate) behind_proxy: bool,
    /// Rate limiter burst capacity per IP (default: 60).
    #[arg(long)]
    pub(crate) rate_limit_burst: Option<u32>,
    /// Rate limiter refill rate in requests/sec per IP (default: 10.0).
    #[arg(long)]
    pub(crate) rate_limit_rate: Option<f64>,
    /// Path to PEM-encoded TLS certificate file for native HTTPS.
    #[arg(long)]
    pub(crate) tls_cert: Option<PathBuf>,
    /// Path to PEM-encoded TLS private key file for native HTTPS.
    #[arg(long)]
    pub(crate) tls_key: Option<PathBuf>,
    /// Refuse to start if binding to non-loopback address without TLS or reverse proxy.
    #[arg(long)]
    pub(crate) require_tls_or_proxy: bool,
    /// Comma-separated prioritized list of fee estimation sources (e.g. "core,mempool,esplora").
    #[arg(long)]
    pub(crate) fee_sources: Option<String>,
    /// Maximum age in seconds before a cached fee estimate is considered stale (default: 1800).
    #[arg(long)]
    pub(crate) fee_max_staleness: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct WalletState {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) alias: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) identity_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) lightning_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) onchain_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) onchain_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ark_server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) ark_pubkey: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) created_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) updated_at: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_policy: Option<satspath_core::recovery::RecoveryPolicy>,
}

#[derive(Clone)]
pub(crate) struct AppState {
    pub(crate) p2p: Arc<crate::p2p::Bridge>,
    pub(crate) home: PathBuf,
    pub(crate) bind: SocketAddr,
    pub(crate) allowed_hosts: Vec<String>,
    pub(crate) network: String,
    pub(crate) open_ui: bool,
    pub(crate) auth_token: String,
    pub(crate) mutation_lock: Arc<tokio::sync::Mutex<()>>,
    pub(crate) rate_limiter: Arc<rate_limit::RateLimiter>,
    pub(crate) is_tls: bool,
}

pub(crate) fn wallet_path(home: &Path) -> PathBuf {
    home.join(WALLET_FILE)
}

pub(crate) fn default_home() -> PathBuf {
    // Prefer a `.satspath/` in the current directory (e.g. a wallet created with
    // `satspath wallet ...`) so the daemon serves the same profile seamlessly;
    // otherwise fall back to the per-user `~/.satspath`.
    let local = PathBuf::from(".satspath");
    if local.is_dir() {
        return local;
    }
    if let Some(home) = std::env::var_os("HOME") {
        PathBuf::from(home).join(".satspath")
    } else {
        local
    }
}
