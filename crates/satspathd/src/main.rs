//! `satspathd` is a local receiver-profile daemon.
//!
//! It manages SatsPath profile identity and public receive pointers only. It
//! does not move funds, sign Bitcoin transactions, broadcast transactions, or
//! store Bitcoin wallet seeds/spending keys.

mod auth;
mod config;
mod handlers;
mod host;
mod http;
mod p2p;
mod rate_limit;
mod router;
mod server;
mod types;
mod ui;
mod v2_api;

use std::fs;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::Parser;

use config::{default_home, AppState, Cli, DEFAULT_BIND, DEFAULT_NETWORK};
use handlers::status::print_startup_status;
use http::write_owner_only_file;
use server::{audit_binding_security, serve};

fn main() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(run());
    // tiny_http request bodies use synchronous socket reads. A stalled client
    // must not keep runtime teardown (and thus SIGTERM/Ctrl+C) waiting forever.
    runtime.shutdown_timeout(std::time::Duration::from_secs(3));
    result
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let bind = cli
        .bind
        .or_else(|| std::env::var("SATSPATHD_BIND").ok())
        .unwrap_or_else(|| DEFAULT_BIND.to_string())
        .parse::<std::net::SocketAddr>()
        .context("invalid bind address")?;
    let network = cli
        .network
        .or_else(|| std::env::var("SATSPATH_NETWORK").ok())
        .unwrap_or_else(|| DEFAULT_NETWORK.to_string());
    let home = cli
        .home
        .or_else(|| std::env::var_os("SATSPATH_HOME").map(std::path::PathBuf::from))
        .unwrap_or_else(default_home);

    fs::create_dir_all(&home).context("creating SATSPATH_HOME")?;

    if let Some(ref sources) = cli.fee_sources {
        std::env::set_var("SATSPATH_FEE_SOURCES", sources);
    }
    if let Some(staleness) = cli.fee_max_staleness {
        std::env::set_var("SATSPATH_FEE_MAX_STALENESS_SECS", staleness.to_string());
    }

    // SEC-04: Daemon API Authorization
    let macaroon_path = home.join("admin.macaroon");
    let auth_token = if let Ok(token) = std::env::var("SATSPATHD_AUTH_TOKEN") {
        let t = token.trim().to_string();
        if t.len() != 64 || hex::decode(&t).is_err() {
            anyhow::bail!(
                "SATSPATHD_AUTH_TOKEN must be a valid 64-character hex string (32 bytes)"
            );
        }
        t
    } else if !macaroon_path.exists() {
        use secp256k1::rand::RngCore;
        let mut token = [0u8; 32];
        secp256k1::rand::thread_rng().fill_bytes(&mut token);
        let token_hex = hex::encode(token);
        write_owner_only_file(&macaroon_path, token_hex.as_bytes())
            .context("writing admin.macaroon")?;
        token_hex
    } else {
        let content = fs::read_to_string(&macaroon_path).context("reading admin.macaroon")?;
        let t = content.trim().to_string();
        if t.len() != 64 || hex::decode(&t).is_err() {
            anyhow::bail!("admin.macaroon must be a valid 64-character hex string (32 bytes)");
        }
        t
    };

    handlers::wallet::load_or_create_identity(&home)?;

    let behind_proxy = cli.behind_proxy
        || std::env::var("SATSPATHD_BEHIND_PROXY")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    let tls_cert_path = cli.tls_cert.or_else(|| {
        std::env::var("SATSPATHD_TLS_CERT")
            .ok()
            .map(std::path::PathBuf::from)
    });
    let tls_key_path = cli.tls_key.or_else(|| {
        std::env::var("SATSPATHD_TLS_KEY")
            .ok()
            .map(std::path::PathBuf::from)
    });

    let require_tls_or_proxy = cli.require_tls_or_proxy
        || std::env::var("SATSPATHD_REQUIRE_TLS_OR_PROXY")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

    let is_tls = tls_cert_path.is_some() && tls_key_path.is_some();
    if (tls_cert_path.is_some() && tls_key_path.is_none())
        || (tls_cert_path.is_none() && tls_key_path.is_some())
    {
        anyhow::bail!(
            "Both --tls-cert and --tls-key must be provided together to enable native TLS"
        );
    }

    audit_binding_security(bind, is_tls, behind_proxy, require_tls_or_proxy)?;

    let burst_capacity = cli
        .rate_limit_burst
        .or_else(|| {
            std::env::var("SATSPATHD_RATE_LIMIT_BURST")
                .ok()
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(rate_limit::DEFAULT_BURST_CAPACITY);

    let refill_rate = cli
        .rate_limit_rate
        .or_else(|| {
            std::env::var("SATSPATHD_RATE_LIMIT_RATE")
                .ok()
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(rate_limit::DEFAULT_REFILL_RATE);

    let rate_limiter_config = rate_limit::RateLimiterConfig {
        burst_capacity,
        refill_rate_per_sec: refill_rate,
        max_body_bytes: rate_limit::DEFAULT_MAX_BODY_BYTES,
        trust_proxy_headers: behind_proxy,
        cleanup_interval_secs: rate_limit::DEFAULT_CLEANUP_INTERVAL_SECS,
    };
    let rate_limiter = Arc::new(rate_limit::RateLimiter::new(rate_limiter_config));

    let state = AppState {
        p2p: p2p::Bridge::new(cli.p2p),
        home,
        bind,
        allowed_hosts: host::configured_hosts(
            std::env::var("SATSPATH_AUTHORITY_DOMAIN").ok().as_deref(),
            std::env::var("SATSPATH_AUTHORITY_URL").ok().as_deref(),
        )?,
        network,
        open_ui: !cli.no_open,
        auth_token,
        mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
        rate_limiter,
        is_tls,
    };

    let tls_config = if let (Some(cert), Some(key)) = (tls_cert_path, tls_key_path) {
        Some((cert, key))
    } else {
        None
    };

    print_startup_status(&state)?;
    let (stop_tx, stop_rx) = tokio::sync::oneshot::channel();
    let bridge = cli
        .p2p
        .then(|| tokio::spawn(p2p::supervise(state.clone(), stop_rx)));
    let result = serve(state, tls_config).await;
    let _ = stop_tx.send(());
    if let Some(task) = bridge {
        task.await?;
    }
    result
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::path::Path;
    use std::sync::Arc;

    use satspath_core::{
        crypto::{generate_identity_keypair, sign_profile, verify_signed_profile},
        PaymentMethod, PaymentProfile, TransactionalTransparencyStore,
    };
    use satspath_router::QuoteResponse;
    use tiny_http::Server;

    use crate::config::AppState;
    use crate::handlers::{
        profile::{recover_profile_key, rotate_profile_key, sign_and_store},
        quote::{pay_response, quote_response},
        resolve::resolve_v2_envelope,
        send::send_response,
        wallet::{load_or_create_identity, save_identity_key, save_wallet},
    };
    use crate::rate_limit;
    use crate::server::{audit_binding_security, serve_server};
    use crate::types::{now, PayRequest, PayResponse, QuoteRequest, SendRequest, SendResponse};

    fn test_state(home: &Path) -> AppState {
        AppState {
            p2p: crate::p2p::Bridge::new(false),
            home: home.to_owned(),
            bind: "127.0.0.1:0".parse().unwrap(),
            allowed_hosts: Vec::new(),
            network: "devnet".into(),
            open_ui: false,
            auth_token: "test_auth_token".into(),
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            rate_limiter: Arc::new(rate_limit::RateLimiter::new(
                rate_limit::RateLimiterConfig::default(),
            )),
            is_tls: false,
        }
    }

    #[test]
    fn identity_creation_persists_public_wallet_state_only() {
        let dir = tempfile::tempdir().unwrap();
        let wallet = load_or_create_identity(dir.path()).unwrap();
        assert!(wallet.identity_pubkey.is_some());
        let raw = std::fs::read_to_string(crate::config::wallet_path(dir.path())).unwrap();
        assert!(!raw.contains("xprv"));
        assert!(!raw.contains("mnemonic"));
        assert!(!raw.contains("secret_key"));
    }

    #[tokio::test]
    async fn p2p_lifecycle_and_control_preserve_separate_trust_states() {
        let dir = tempfile::tempdir().unwrap();
        let mut state = test_state(dir.path());
        load_or_create_identity(&state.home).unwrap();
        assert_eq!(state.p2p.status.lock().await.state, "disabled");
        assert!(crate::p2p::resolve_candidate(&state, "alice@example.com")
            .await
            .is_err());
        state.p2p = crate::p2p::Bridge::new(true);
        let (tx, rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(crate::p2p::supervise(state.clone(), rx));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(state.p2p.status.lock().await.announcements, 0);
        let summary = crate::p2p::local_summary(&state).unwrap();
        assert!(!summary.to_string().contains("signed_profile"));
        assert!(!summary.to_string().contains("payment_method_states"));
        assert_eq!(summary["active_aliases"], 0);
        tx.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(state.p2p.status.lock().await.state, "stopped");
    }

    #[test]
    fn control_does_not_promote_a_signed_domain_claim_to_authority() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let mut wallet = load_or_create_identity(&state.home).unwrap();
        wallet.alias = Some("truja@binance.com".into());
        wallet.lightning_address = Some("alice@example.com".into());
        sign_and_store(&state.home, &mut wallet, &state.network).unwrap();
        save_wallet(&state.home, &wallet).unwrap();
        let summary = crate::p2p::local_summary(&state).unwrap();
        assert_eq!(summary["verification"]["profile_signature_verified"], true);
        assert_eq!(summary["verification"]["identifier_verified"], false);
        assert_eq!(summary["identifier_authority"], "unverified");
        assert_eq!(summary["verification"]["payment_methods_verified"], false);
        assert!(!summary.to_string().contains("binance.com"));
        assert!(!summary.to_string().contains("alice@example.com"));
    }

    #[tokio::test]
    async fn idle_p2p_supervisor_recovers_from_publication_failure() {
        async fn wait_for(state: &AppState, expected: &str) {
            tokio::time::timeout(std::time::Duration::from_secs(4), async {
                loop {
                    if state.p2p.status.lock().await.state == expected {
                        break;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(state.p2p.status.lock().await.announcements, 0);
        }

        let dir = tempfile::tempdir().unwrap();
        let mut state = test_state(dir.path());
        state.p2p = crate::p2p::Bridge::new(true);
        let wallet = load_or_create_identity(dir.path()).unwrap();
        let path = crate::config::wallet_path(dir.path());
        std::fs::write(&path, b"{").unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(crate::p2p::supervise(state.clone(), stopped));
        wait_for(&state, "degraded").await;
        tokio::time::sleep(std::time::Duration::from_millis(2100)).await;
        assert_eq!(state.p2p.status.lock().await.state, "degraded");
        save_wallet(dir.path(), &wallet).unwrap();
        wait_for(&state, "active").await;
        std::fs::write(&path, b"{").unwrap();
        wait_for(&state, "degraded").await;
        save_wallet(dir.path(), &wallet).unwrap();
        wait_for(&state, "active").await;
        stop.send(()).unwrap();
        task.await.unwrap();
    }

    #[tokio::test]
    async fn control_get_is_read_only_with_missing_existing_and_advancing_pins() {
        struct StopServer(Arc<Server>);
        impl Drop for StopServer {
            fn drop(&mut self) {
                self.0.unblock();
            }
        }
        fn snapshot(home: &Path) -> std::collections::BTreeMap<std::path::PathBuf, Vec<u8>> {
            let mut files = std::collections::BTreeMap::new();
            for entry in std::fs::read_dir(home).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    files.extend(snapshot(&path));
                } else {
                    // SQLite readers may create WAL coordination sidecars; these
                    // are not profile, checkpoint or trust-state persistence.
                    let name = path.file_name().unwrap().to_string_lossy();
                    if name.ends_with(".sqlite3-shm") || name.ends_with(".sqlite3-wal") {
                        continue;
                    }
                    files.insert(path.clone(), std::fs::read(&path).unwrap());
                }
            }
            files
        }
        let dir = tempfile::tempdir().unwrap();
        let mut state = test_state(dir.path());
        let server = Arc::new(Server::http("127.0.0.1:0").unwrap());
        let _stop = StopServer(server.clone());
        state.bind = server.server_addr().to_ip().unwrap();
        let url = format!("http://{}/v1/control", state.bind);
        let mut wallet = load_or_create_identity(&state.home).unwrap();
        wallet.alias = Some("alice@example.test".into());
        wallet.lightning_address = Some("alice@example.test".into());
        save_wallet(&state.home, &wallet).unwrap();
        let handle = tokio::spawn(serve_server(Arc::new(state.clone()), server.clone()));
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(2))
            .build()
            .unwrap();
        for stage in 0..4 {
            if stage == 1 || stage == 3 {
                sign_and_store(&state.home, &mut wallet, &state.network).unwrap();
                save_wallet(&state.home, &wallet).unwrap();
            }
            if stage == 2 {
                crate::handlers::resolve::resolve_profile(&state, wallet.alias.as_deref().unwrap())
                    .unwrap();
            }
            let before = snapshot(&state.home);
            for _ in 0..2 {
                let response = client.get(&url).send().await.unwrap();
                assert_eq!(response.status(), reqwest::StatusCode::OK);
                let body: serde_json::Value = response.json().await.unwrap();
                if stage > 0 {
                    assert_eq!(
                        body["identity"]["verification"]["profile_signature_verified"],
                        true
                    );
                }
            }
            assert!(
                snapshot(&state.home) == before,
                "GET modified persistent state at stage {stage}"
            );
        }
        // A missing database/home must not be initialized by a read-only opener.
        let missing = state.home.join("missing");
        assert!(satspath_core::TransactionalTransparencyStore::open_read_only(&missing).is_err());
        assert!(!missing.exists());
        let store =
            satspath_core::TransactionalTransparencyStore::open_read_only(&state.home).unwrap();
        let checkpoint = store
            .load_log()
            .unwrap()
            .checkpoints()
            .last()
            .unwrap()
            .clone();
        assert!(store
            .replace_latest_checkpoint(&checkpoint.checkpoint_hash().unwrap(), &checkpoint)
            .is_err());
        server.unblock();
        handle.abort();
    }

    #[tokio::test]
    async fn shutdown_listener_survives_requests_and_a_signal_between_iterations() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        struct Registration(Arc<AtomicUsize>);
        impl Drop for Registration {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }
        let dir = tempfile::tempdir().unwrap();
        let state = Arc::new(test_state(dir.path()));
        let server = Arc::new(Server::http("127.0.0.1:0").unwrap());
        let url = format!("http://{}/health", server.server_addr().to_ip().unwrap());
        let (signal, receiver) = tokio::sync::oneshot::channel();
        let drops = Arc::new(AtomicUsize::new(0));
        let registration = Registration(drops.clone());
        let shutdown = async move {
            let _registration = registration;
            receiver.await?;
            Ok(())
        };
        let handle = tokio::spawn(crate::server::serve_server_with_shutdown(
            state,
            server.clone(),
            shutdown,
        ));
        let client = reqwest::Client::new();
        for _ in 0..8 {
            assert_eq!(
                client.get(&url).send().await.unwrap().status(),
                reqwest::StatusCode::OK
            );
            assert_eq!(
                drops.load(Ordering::SeqCst),
                0,
                "listener was dropped during traffic"
            );
        }
        // Queue shutdown while the request branch is also ready.
        let request = client.get(&url).send();
        signal.send(()).unwrap();
        let (_, stopped) = tokio::join!(
            tokio::time::timeout(std::time::Duration::from_millis(100), request),
            tokio::time::timeout(std::time::Duration::from_secs(2), handle)
        );
        stopped.unwrap().unwrap().unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn quote_rejects_profile_without_transparency() {
        use satspath_core::registry::Registry;
        let dir = tempfile::tempdir().unwrap();
        let key = generate_identity_keypair();
        let profile = PaymentProfile {
            alias: "alice@example.com".into(),
            identity_pubkey: hex::encode(key.public_key.serialize()),
            methods: vec![PaymentMethod::Lightning {
                label: "LN".into(),
                lightning_address: Some("alice@example.com".into()),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: None,
            }],
            updated_at: now(),
            expires_at: None,
            sequence: Some(0),
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: vec![],
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
            recovery_policy: None,
            recovery: None,
        };
        Registry::open(dir.path())
            .unwrap()
            .register_profile(sign_profile(profile, &key.secret_key).unwrap())
            .unwrap();
        let response = quote_response(
            &test_state(dir.path()),
            QuoteRequest {
                recipient: "alice@example.com".into(),
                amount_sats: 1_000,
            },
        )
        .await;
        assert!(
            matches!(response, QuoteResponse::NoRoute { ref reason } if reason.contains("transparency verification failed"))
        );
    }

    #[tokio::test]
    async fn quote_pay_and_preview_use_transparent_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.lightning_address = Some("alice@example.com".into());
        sign_and_store(dir.path(), &mut wallet, "devnet").unwrap();
        let state = test_state(dir.path());
        let quote = quote_response(
            &state,
            QuoteRequest {
                recipient: "alice@example.com".into(),
                amount_sats: 1_000,
            },
        )
        .await;
        assert!(
            matches!(quote, QuoteResponse::NoRoute { ref reason } if reason.contains("ownership proof"))
        );
        let preview = quote_response(
            &state,
            QuoteRequest {
                recipient: "alice@example.com".into(),
                amount_sats: 1_000,
            },
        )
        .await;
        assert!(matches!(preview, QuoteResponse::NoRoute { .. }));
        let pay = pay_response(
            &state,
            PayRequest {
                recipient: "alice@example.com".into(),
                amount_sats: 1_000,
                memo: None,
            },
        )
        .await;
        assert!(matches!(pay, PayResponse::NoRoute { .. }));
    }

    #[test]
    fn rotation_sequence_is_consistent_across_profile_event_and_registry() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.lightning_address = Some("alice@example.com".into());
        sign_and_store(dir.path(), &mut wallet, "devnet").unwrap();
        save_wallet(dir.path(), &wallet).unwrap();
        let response = rotate_profile_key(&test_state(dir.path())).unwrap();
        let store = TransactionalTransparencyStore::open(dir.path()).unwrap();
        let profile = store.profile("alice@example.com").unwrap().unwrap();
        let log = store.load_log().unwrap();
        let latest = log.events().last().unwrap();
        assert_eq!(response.sequence, 1);
        assert_eq!(profile.profile.sequence, Some(latest.sequence));
        assert_eq!(latest.rotation.as_ref().unwrap().sequence, latest.sequence);
    }

    #[test]
    fn update_profile_configures_and_commits_recovery_policy() {
        use satspath_core::recovery::RecoveryPolicy;

        let dir = tempfile::tempdir().unwrap();
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.lightning_address = Some("alice@example.com".into());
        sign_and_store(dir.path(), &mut wallet, "devnet").unwrap();
        save_wallet(dir.path(), &wallet).unwrap();

        let g1 = generate_identity_keypair();
        let g2 = generate_identity_keypair();
        let policy = RecoveryPolicy::new(
            2,
            vec![
                hex::encode(g1.public_key.serialize()),
                hex::encode(g2.public_key.serialize()),
            ],
        )
        .unwrap();

        let state = test_state(dir.path());
        let update_req = crate::types::ProfileUpdateRequest {
            alias: Some("alice@example.com".into()),
            lightning_address: None,
            onchain_address: None,
            onchain_pubkey: None,
            ark_server: None,
            ark_pubkey: None,
            remove_methods: vec![],
            recovery_policy: Some(policy.clone()),
        };

        let response = crate::handlers::profile::update_profile(&state, update_req).unwrap();
        assert_eq!(
            response.wallet.recovery_policy.as_ref().unwrap().threshold,
            2
        );

        let store = TransactionalTransparencyStore::open(dir.path()).unwrap();
        let profile = store.profile("alice@example.com").unwrap().unwrap();
        assert_eq!(profile.profile.recovery_policy, Some(policy.clone()));

        let log = store.load_log().unwrap();
        let latest = log.events().last().unwrap();
        assert_eq!(latest.action, satspath_core::NameAction::UpdateProfile);
        assert_eq!(latest.recovery_policy, Some(policy));
    }

    #[test]
    fn key_recovery_with_guardian_threshold_succeeds_and_updates_transparency_log() {
        use satspath_core::recovery::{
            sign_guardian_authorization, KeyRecoveryProof, RecoveryPolicy,
        };

        let dir = tempfile::tempdir().unwrap();
        let key = generate_identity_keypair();
        let pubkey_hex = hex::encode(key.public_key.serialize());

        let g1 = generate_identity_keypair();
        let g2 = generate_identity_keypair();
        let g3 = generate_identity_keypair();
        let g1_pk = hex::encode(g1.public_key.serialize());
        let g2_pk = hex::encode(g2.public_key.serialize());
        let g3_pk = hex::encode(g3.public_key.serialize());

        let policy = RecoveryPolicy::new(2, vec![g1_pk.clone(), g2_pk.clone(), g3_pk]).unwrap();

        let initial_profile = PaymentProfile {
            alias: "alice@example.com".into(),
            identity_pubkey: pubkey_hex.clone(),
            methods: vec![PaymentMethod::Lightning {
                label: "LN".into(),
                lightning_address: Some("alice@example.com".into()),
                lnurl: None,
                bolt12: None,
                receiver_pubkey: None,
            }],
            updated_at: 1_700_000_000,
            expires_at: None,
            sequence: Some(0),
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: vec![],
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
            recovery_policy: Some(policy.clone()),
            recovery: None,
        };
        let signed_initial = sign_profile(initial_profile, &key.secret_key).unwrap();

        let store = TransactionalTransparencyStore::open(dir.path()).unwrap();
        let log = store.load_log().unwrap();
        let id_hash = satspath_core::privacy::identifier_hash("alice@example.com");
        let mut initial_event = satspath_core::NameEvent {
            version: 1,
            identifier_hash: id_hash.clone(),
            action: satspath_core::NameAction::Register,
            identity_pubkey: pubkey_hex.clone(),
            profile_hash: satspath_core::transparency::profile_hash(&signed_initial).unwrap(),
            sequence: 0,
            previous_event_hash: None,
            created_at: 1_700_000_000,
            identifier_attestation_hash: None,
            removed_method_hashes: vec![],
            rotation: None,
            recovery_policy: Some(policy),
            recovery: None,
            owner_signature: String::new(),
        };
        initial_event.sign(&key.secret_key).unwrap();
        let candidate = log
            .prepare_append(initial_event.clone(), &signed_initial)
            .unwrap();
        let operator =
            crate::handlers::transparency::load_or_create_transparency_operator(dir.path())
                .unwrap();
        let checkpoint = candidate.prepare_checkpoint(&operator).unwrap();
        store
            .commit_profile_event_checkpoint(
                "alice@example.com",
                &signed_initial,
                &initial_event,
                &checkpoint,
            )
            .unwrap();

        // Simulate recovery
        let new_key = generate_identity_keypair();
        let new_pk_hex = hex::encode(new_key.public_key.serialize());
        let prev_hash = initial_event.signed_event_hash().unwrap();
        let now_ts = chrono::Utc::now().timestamp();

        let sig1 = sign_guardian_authorization(
            &id_hash,
            &pubkey_hex,
            &new_pk_hex,
            &prev_hash,
            1,
            now_ts,
            &g1.secret_key,
        );
        let sig2 = sign_guardian_authorization(
            &id_hash,
            &pubkey_hex,
            &new_pk_hex,
            &prev_hash,
            1,
            now_ts,
            &g2.secret_key,
        );

        let proof = KeyRecoveryProof::create(
            id_hash,
            pubkey_hex,
            new_pk_hex.clone(),
            &new_key.secret_key,
            prev_hash,
            1,
            now_ts,
            vec![sig1, sig2],
        )
        .unwrap();

        let mut recovered_profile = signed_initial.profile.clone();
        recovered_profile.identity_pubkey = new_pk_hex.clone();
        recovered_profile.sequence = Some(1);
        recovered_profile.recovery = Some(proof.clone());
        let signed_recovered = sign_profile(recovered_profile, &new_key.secret_key).unwrap();

        save_identity_key(dir.path(), &new_key.secret_key).unwrap();

        let state = test_state(dir.path());
        let request = crate::types::ProfileRecoverRequest {
            alias: "alice@example.com".into(),
            proof,
            signed_profile: signed_recovered,
            event_created_at: None,
            event_signature: None,
        };
        let response = recover_profile_key(&state, request).unwrap();
        assert_eq!(response.alias, "alice@example.com");
        assert_eq!(response.sequence, 1);

        let updated_store = TransactionalTransparencyStore::open(dir.path()).unwrap();
        let current_profile = updated_store.profile("alice@example.com").unwrap().unwrap();
        assert_eq!(current_profile.profile.identity_pubkey, new_pk_hex);
        assert_eq!(current_profile.profile.sequence, Some(1));
    }

    #[test]
    fn key_recovery_remote_event_signature_with_mismatched_timestamp_is_rejected() {
        use satspath_core::recovery::{
            sign_guardian_authorization, KeyRecoveryProof, RecoveryPolicy,
        };
        use satspath_core::transparency::{NameAction, NameEvent, TransparencyError};
        use satspath_core::SatsPathError;

        let dir = tempfile::tempdir().unwrap();
        let key = generate_identity_keypair();
        let pubkey_hex = hex::encode(key.public_key.serialize());

        let g1 = generate_identity_keypair();
        let g2 = generate_identity_keypair();
        let g1_pk = hex::encode(g1.public_key.serialize());
        let g2_pk = hex::encode(g2.public_key.serialize());

        let policy = RecoveryPolicy::new(1, vec![g1_pk.clone(), g2_pk.clone()]).unwrap();
        let initial_profile = PaymentProfile {
            sequence: Some(0),
            alias: "bob@example.com".into(),
            identity_pubkey: pubkey_hex.clone(),
            methods: vec![],
            updated_at: 1_700_000_000,
            expires_at: None,
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: vec![],
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
            recovery_policy: Some(policy.clone()),
            recovery: None,
        };
        let signed_initial = sign_profile(initial_profile, &key.secret_key).unwrap();

        let store = TransactionalTransparencyStore::open(dir.path()).unwrap();
        let log = store.load_log().unwrap();
        let genesis_event = NameEvent {
            version: 1,
            identifier_hash: satspath_core::privacy::identifier_hash("bob@example.com"),
            action: NameAction::Register,
            identity_pubkey: pubkey_hex.clone(),
            profile_hash: satspath_core::transparency::profile_hash(&signed_initial).unwrap(),
            sequence: 0,
            previous_event_hash: None,
            created_at: 1_700_000_000,
            identifier_attestation_hash: None,
            removed_method_hashes: Vec::new(),
            rotation: None,
            recovery_policy: Some(policy),
            recovery: None,
            owner_signature: String::new(),
        };
        let mut signed_genesis = genesis_event;
        signed_genesis.sign(&key.secret_key).unwrap();

        let candidate = log
            .prepare_append(signed_genesis.clone(), &signed_initial)
            .unwrap();
        let operator =
            crate::handlers::transparency::load_or_create_transparency_operator(dir.path())
                .unwrap();
        let cp = candidate.prepare_checkpoint(&operator).unwrap();
        store
            .commit_profile_event_checkpoint(
                "bob@example.com",
                &signed_initial,
                &signed_genesis,
                &cp,
            )
            .unwrap();

        let new_key = generate_identity_keypair();
        let new_pk_hex = hex::encode(new_key.public_key.serialize());
        let sig1 = sign_guardian_authorization(
            &satspath_core::privacy::identifier_hash("bob@example.com"),
            &pubkey_hex,
            &new_pk_hex,
            &signed_genesis.event_hash().unwrap(),
            1,
            1_700_000_100,
            &g1.secret_key,
        );

        let proof = KeyRecoveryProof::create(
            satspath_core::privacy::identifier_hash("bob@example.com"),
            pubkey_hex,
            new_pk_hex.clone(),
            &new_key.secret_key,
            signed_genesis.event_hash().unwrap(),
            1,
            1_700_000_100,
            vec![sig1],
        )
        .unwrap();

        let mut recovered_profile = signed_initial.profile.clone();
        recovered_profile.identity_pubkey = new_pk_hex.clone();
        recovered_profile.sequence = Some(1);
        recovered_profile.recovery = Some(proof.clone());
        let signed_recovered = sign_profile(recovered_profile, &new_key.secret_key).unwrap();

        // Sign the event remotely with signed_time
        let signed_time = chrono::Utc::now().timestamp();
        let mut remote_event = NameEvent {
            version: 1,
            identifier_hash: satspath_core::privacy::identifier_hash("bob@example.com"),
            action: NameAction::RecoverKey,
            identity_pubkey: new_pk_hex.clone(),
            profile_hash: satspath_core::transparency::profile_hash(&signed_recovered).unwrap(),
            sequence: 1,
            previous_event_hash: Some(signed_genesis.event_hash().unwrap()),
            created_at: signed_time,
            identifier_attestation_hash: None,
            removed_method_hashes: Vec::new(),
            rotation: None,
            recovery_policy: signed_recovered.profile.recovery_policy.clone(),
            recovery: Some(proof.clone()),
            owner_signature: String::new(),
        };
        remote_event.sign(&new_key.secret_key).unwrap();
        let valid_remote_sig = remote_event.owner_signature.clone();

        let state = test_state(dir.path());

        // 1. Submit with mismatched created_at timestamp -> must fail with InvalidEventSignature
        let bad_request = crate::types::ProfileRecoverRequest {
            alias: "bob@example.com".into(),
            proof: proof.clone(),
            signed_profile: signed_recovered.clone(),
            event_created_at: Some(signed_time + 10),
            event_signature: Some(valid_remote_sig.clone()),
        };
        let err = recover_profile_key(&state, bad_request).unwrap_err();
        let is_invalid_sig = err.downcast_ref::<SatsPathError>().is_some_and(|e| {
            matches!(
                e,
                SatsPathError::Transparency(TransparencyError::InvalidEventSignature)
            )
        });
        assert!(
            is_invalid_sig,
            "expected InvalidEventSignature, got: {err:?}"
        );

        // 2. Submit with event_signature but missing event_created_at -> must fail immediately
        let missing_time_request = crate::types::ProfileRecoverRequest {
            alias: "bob@example.com".into(),
            proof: proof.clone(),
            signed_profile: signed_recovered.clone(),
            event_created_at: None,
            event_signature: Some(valid_remote_sig.clone()),
        };
        let err = recover_profile_key(&state, missing_time_request).unwrap_err();
        assert!(err.to_string().contains("event_created_at is required"));

        // 3. Submit with matching created_at timestamp -> must succeed
        let good_request = crate::types::ProfileRecoverRequest {
            alias: "bob@example.com".into(),
            proof,
            signed_profile: signed_recovered,
            event_created_at: Some(signed_time),
            event_signature: Some(valid_remote_sig),
        };
        let response = recover_profile_key(&state, good_request).unwrap();
        assert_eq!(response.alias, "bob@example.com");
        assert_eq!(response.sequence, 1);
    }

    #[test]
    fn profile_signing_writes_resolvable_signed_profile() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.lightning_address = Some("alice@example.com".into());
        sign_and_store(dir.path(), &mut wallet, "devnet").unwrap();

        let signed = TransactionalTransparencyStore::open(dir.path())
            .unwrap()
            .profile("alice@example.com")
            .unwrap()
            .unwrap();
        assert!(verify_signed_profile(&signed).unwrap());
        assert_eq!(signed.profile.methods.len(), 1);
    }

    #[test]
    fn onchain_pubkey_is_saved_as_pubkey_hint() {
        let dir = tempfile::tempdir().unwrap();
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.onchain_address = Some("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn".into());
        wallet.onchain_pubkey =
            Some("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into());
        sign_and_store(dir.path(), &mut wallet, "devnet").unwrap();

        let signed = TransactionalTransparencyStore::open(dir.path())
            .unwrap()
            .profile("alice@example.com")
            .unwrap()
            .unwrap();
        match &signed.profile.methods[0] {
            PaymentMethod::Onchain { pubkey_hint, .. } => {
                assert_eq!(pubkey_hint.as_deref(), wallet.onchain_pubkey.as_deref());
            }
            other => panic!("expected on-chain method, got {other:?}"),
        }
    }

    #[test]
    fn v2_resolve_envelope_success_and_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        let mut wallet = load_or_create_identity(dir.path()).unwrap();
        wallet.alias = Some("alice@example.com".into());
        wallet.lightning_address = Some("alice@example.com".into());
        sign_and_store(dir.path(), &mut wallet, "devnet").unwrap();
        save_wallet(dir.path(), &wallet).unwrap();

        let env = resolve_v2_envelope(&state, "alice@example.com").unwrap();
        assert_eq!(env.version, 2);
        assert_eq!(env.identifier, "alice@example.com");
        assert_eq!(env.signed_profile.profile.alias, "alice@example.com");
        assert_eq!(env.namespace_descriptor.version, 2);
        assert!(!env.name_events.is_empty());

        let not_found = resolve_v2_envelope(&state, "bob@example.com");
        assert!(not_found.is_err());
    }

    async fn start_test_daemon(
        config: rate_limit::RateLimiterConfig,
    ) -> (String, Arc<Server>, tokio::task::JoinHandle<()>) {
        start_test_daemon_full(config, None).await
    }

    async fn start_test_daemon_full(
        config: rate_limit::RateLimiterConfig,
        ssl_config: Option<tiny_http::SslConfig>,
    ) -> (String, Arc<Server>, tokio::task::JoinHandle<()>) {
        let dir = tempfile::tempdir().unwrap();
        let home = Box::leak(Box::new(dir)).path().to_path_buf();
        let (server, scheme) = if let Some(ssl) = ssl_config {
            let srv = Server::https("127.0.0.1:0", ssl).unwrap();
            (Arc::new(srv), "https")
        } else {
            let srv = Server::http("127.0.0.1:0").unwrap();
            (Arc::new(srv), "http")
        };
        let addr = server.server_addr().to_ip().unwrap();
        let state = Arc::new(AppState {
            p2p: crate::p2p::Bridge::new(false),
            home,
            bind: addr,
            allowed_hosts: Vec::new(),
            network: "devnet".into(),
            open_ui: false,
            auth_token: "test_token".into(),
            mutation_lock: Arc::new(tokio::sync::Mutex::new(())),
            rate_limiter: Arc::new(rate_limit::RateLimiter::new(config)),
            is_tls: scheme == "https",
        });
        let srv_clone = Arc::clone(&server);
        let handle = tokio::spawn(async move {
            let _ = serve_server(state, srv_clone).await;
        });
        (format!("{scheme}://{addr}"), server, handle)
    }

    #[tokio::test]
    async fn dashboard_auth_preserves_private_and_public_boundaries() {
        let config = rate_limit::RateLimiterConfig {
            burst_capacity: 100,
            refill_rate_per_sec: 100.0,
            max_body_bytes: 65_536,
            trust_proxy_headers: false,
            cleanup_interval_secs: 300,
        };
        let (base_url, server, handle) = start_test_daemon(config).await;
        let client = reqwest::Client::new();
        for path in ["/", "/dashboard-auth.mjs", "/health", "/v1/control"] {
            let response = client
                .get(format!("{base_url}{path}"))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK, "{path}");
            assert!(!response.text().await.unwrap().contains("test_token"));
        }
        for (method, path) in [
            (reqwest::Method::POST, "/v1/dashboard/auth"),
            (reqwest::Method::POST, "/v1/profile/challenge"),
            (reqwest::Method::POST, "/v1/profile/verify"),
            (reqwest::Method::PUT, "/v1/profile"),
            (reqwest::Method::POST, "/v1/profile/methods"),
            (reqwest::Method::POST, "/v1/profile/rotate-key"),
            (reqwest::Method::POST, "/v1/broadcast"),
            (reqwest::Method::POST, "/v1/p2p/resolve"),
            (
                reqwest::Method::POST,
                "/v1/invites/notifications/example/read",
            ),
        ] {
            for credential in [None, Some("invalid_dashboard_token")] {
                let mut request = client.request(method.clone(), format!("{base_url}{path}"));
                if let Some(token) = credential {
                    request = request.bearer_auth(token);
                }
                let response = request.json(&serde_json::json!({})).send().await.unwrap();
                assert_eq!(
                    response.status(),
                    reqwest::StatusCode::UNAUTHORIZED,
                    "{path}"
                );
                let body = response.text().await.unwrap();
                assert!(!body.contains("test_token"));
                assert!(!body.contains("invalid_dashboard_token"));
            }
        }
        for path in ["/v1/dashboard/auth", "/v1/profile/challenge"] {
            let response = client
                .post(format!("{base_url}{path}"))
                .bearer_auth("test_token")
                .json(&serde_json::json!({"alias": "alice@example.com"}))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK, "{path}");
            assert!(response.headers().get("set-cookie").is_none());
            assert!(!response.text().await.unwrap().contains("test_token"));
        }
        server.unblock();
        handle.abort();
    }

    #[tokio::test]
    async fn http_host_guard_precedes_public_views_and_authenticated_mutations() {
        for trust_proxy_headers in [false, true] {
            let config = rate_limit::RateLimiterConfig {
                trust_proxy_headers,
                ..Default::default()
            };
            let (base_url, server, handle) = start_test_daemon(config).await;
            let client = reqwest::Client::new();
            for path in ["/v1/control", "/", "/health"] {
                let response = client
                    .get(format!("{base_url}{path}"))
                    .header("Host", "rebind.example")
                    .header("X-Forwarded-Host", "localhost")
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
                let body = response.text().await.unwrap();
                assert!(!body.contains("fingerprint"));
                assert!(!body.contains("test_token"));
            }
            let response = client
                .post(format!("{base_url}/v1/dashboard/auth"))
                .header("Host", "rebind.example")
                .bearer_auth("test_token")
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::BAD_REQUEST);
            for host in ["localhost", "127.0.0.1", "[::1]"] {
                let response = client
                    .get(format!("{base_url}/v1/control"))
                    .header("Host", host)
                    .send()
                    .await
                    .unwrap();
                assert_eq!(response.status(), reqwest::StatusCode::OK);
            }
            server.unblock();
            handle.abort();
        }
    }

    #[tokio::test]
    async fn test_http_rate_limit_and_burst_protection() {
        let config = rate_limit::RateLimiterConfig {
            burst_capacity: 3,
            refill_rate_per_sec: 0.1,
            max_body_bytes: 65_536,
            trust_proxy_headers: false,
            cleanup_interval_secs: 300,
        };
        let (base_url, server, _handle) = start_test_daemon(config).await;
        let client = reqwest::Client::new();

        // 3 requests should succeed within burst
        for i in 1..=3 {
            let res = client
                .get(format!("{base_url}/health"))
                .send()
                .await
                .expect("send request");
            assert_eq!(
                res.status(),
                reqwest::StatusCode::OK,
                "request {i} within burst limit should succeed"
            );
        }

        // 4th request must be rejected with 429 Too Many Requests
        let res4 = client
            .get(format!("{base_url}/health"))
            .send()
            .await
            .expect("send request");
        assert_eq!(
            res4.status(),
            reqwest::StatusCode::TOO_MANY_REQUESTS,
            "4th request exceeding burst should return 429"
        );

        let retry_header = res4.headers().get("Retry-After");
        assert!(
            retry_header.is_some(),
            "429 response must contain Retry-After header"
        );
        let retry_secs: u64 = retry_header
            .unwrap()
            .to_str()
            .unwrap()
            .parse()
            .expect("parse retry-after header value");
        assert!(retry_secs >= 1, "retry_after must be >= 1 second");

        let body: serde_json::Value = res4.json().await.expect("parse 429 json body");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("Too Many Requests"),
            "body must contain error description"
        );

        server.unblock();
    }

    #[tokio::test]
    async fn test_http_payload_too_large_rejection_413() {
        let config = rate_limit::RateLimiterConfig {
            burst_capacity: 10,
            refill_rate_per_sec: 10.0,
            max_body_bytes: 1024, // 1 KB max for testing
            trust_proxy_headers: false,
            cleanup_interval_secs: 300,
        };
        let (base_url, server, _handle) = start_test_daemon(config).await;
        let client = reqwest::Client::new();

        // Send a request with a body of 2048 bytes (> 1024 bytes)
        let large_body = vec![b'a'; 2048];
        let res = client
            .post(format!("{base_url}/v1/receive"))
            .header("Content-Type", "application/json")
            .body(large_body)
            .send()
            .await
            .expect("send request");

        assert_eq!(
            res.status(),
            reqwest::StatusCode::PAYLOAD_TOO_LARGE,
            "oversized body should return HTTP 413"
        );

        let body: serde_json::Value = res.json().await.expect("parse 413 json body");
        assert!(
            body["error"]
                .as_str()
                .unwrap()
                .contains("Payload Too Large"),
            "body must state Payload Too Large"
        );

        server.unblock();
    }

    #[tokio::test]
    async fn test_http_rate_limit_trusted_proxy_headers() {
        let config = rate_limit::RateLimiterConfig {
            burst_capacity: 2,
            refill_rate_per_sec: 0.1,
            max_body_bytes: 65_536,
            trust_proxy_headers: true,
            cleanup_interval_secs: 300,
        };
        let (base_url, server, _handle) = start_test_daemon(config).await;
        let client = reqwest::Client::new();

        // Client 1 (203.0.113.1) uses its 2 burst tokens
        for _ in 0..2 {
            let res = client
                .get(format!("{base_url}/health"))
                .header("X-Forwarded-For", "203.0.113.1, 10.0.0.1")
                .send()
                .await
                .unwrap();
            assert_eq!(res.status(), reqwest::StatusCode::OK);
        }

        // Client 1's 3rd request is blocked (429)
        let res_c1_blocked = client
            .get(format!("{base_url}/health"))
            .header("X-Forwarded-For", "203.0.113.1, 10.0.0.1")
            .send()
            .await
            .unwrap();
        assert_eq!(
            res_c1_blocked.status(),
            reqwest::StatusCode::TOO_MANY_REQUESTS
        );

        // Client 2 (198.51.100.5) is independent and should be allowed
        let res_c2 = client
            .get(format!("{base_url}/health"))
            .header("X-Forwarded-For", "198.51.100.5")
            .send()
            .await
            .unwrap();
        assert_eq!(res_c2.status(), reqwest::StatusCode::OK);

        server.unblock();
    }

    #[tokio::test]
    async fn test_http_diagnostics_rate_limit() {
        let config = rate_limit::RateLimiterConfig {
            burst_capacity: 5,
            refill_rate_per_sec: 1.0,
            max_body_bytes: 65_536,
            trust_proxy_headers: false,
            cleanup_interval_secs: 300,
        };
        let (base_url, server, _handle) = start_test_daemon(config).await;
        let client = reqwest::Client::new();

        // 1 successful request
        let _ = client
            .get(format!("{base_url}/health"))
            .send()
            .await
            .unwrap();

        let diag_res = client
            .get(format!("{base_url}/v1/diagnostics/rate_limit"))
            .send()
            .await
            .unwrap();
        assert_eq!(diag_res.status(), reqwest::StatusCode::OK);

        let stats: rate_limit::RateLimiterStats = diag_res.json().await.unwrap();
        assert!(stats.total_allowed >= 1);
        assert_eq!(stats.burst_capacity, 5);
        assert_eq!(stats.max_body_bytes, 65_536);

        server.unblock();
    }

    #[test]
    fn test_cleartext_audit_allows_loopback() {
        let addr: SocketAddr = "127.0.0.1:9737".parse().unwrap();
        assert!(audit_binding_security(addr, false, false, false).is_ok());
        assert!(audit_binding_security(addr, false, false, true).is_ok());
    }

    #[test]
    fn test_cleartext_audit_rejects_non_loopback_when_enforced() {
        let addr: SocketAddr = "0.0.0.0:9737".parse().unwrap();
        let err = audit_binding_security(addr, false, false, true).unwrap_err();
        assert!(err.to_string().contains("Security violation"));
    }

    #[test]
    fn test_cleartext_audit_allows_non_loopback_with_proxy_or_tls() {
        let addr: SocketAddr = "0.0.0.0:9737".parse().unwrap();
        // Allowed when behind reverse proxy
        assert!(audit_binding_security(addr, false, true, true).is_ok());
        // Allowed when native TLS is active
        assert!(audit_binding_security(addr, true, false, true).is_ok());
    }

    #[tokio::test]
    async fn test_native_tls_server_https_get_and_post() {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()])
            .unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();

        let ssl_config = tiny_http::SslConfig {
            certificate: cert_pem.into_bytes(),
            private_key: key_pem.into_bytes(),
        };

        let config = rate_limit::RateLimiterConfig::default();
        let (base_url, server, _handle) = start_test_daemon_full(config, Some(ssl_config)).await;
        assert!(base_url.starts_with("https://"));

        let client = reqwest::Client::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();

        let res = client
            .get(format!("{base_url}/health"))
            .send()
            .await
            .expect("send HTTPS request");
        assert_eq!(res.status(), reqwest::StatusCode::OK);

        let body: serde_json::Value = res.json().await.unwrap();
        assert_eq!(body["ok"], true);

        server.unblock();
    }

    #[tokio::test]
    async fn test_end_to_end_invite_claim_flow() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        load_or_create_identity(dir.path()).unwrap();

        // 1. Sender initiates send to unregistered alias
        let send_res = send_response(
            &state,
            SendRequest {
                recipient: "carol@example.com".into(),
                amount_sats: 25_000,
                routing_ok: Some(true),
            },
        )
        .await;

        let claim_url = match send_res {
            SendResponse::Invite { claim_url, .. } => claim_url,
            other => panic!("expected SendResponse::Invite, got {other:?}"),
        };

        // Extract invite_id from claim_url
        let invite_id = claim_url
            .split("invite_id=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        // 2. Receiver inspects invite
        let inspect = crate::handlers::claim::inspect_invite_handler(&state, invite_id).unwrap();
        assert_eq!(inspect.invite_id, invite_id);
        assert_eq!(inspect.amount_sats, 25_000);
        assert!(inspect.is_claimable);
        assert!(!inspect.is_expired);
        assert!(inspect.sender_verified);

        // 3. Receiver claims invite with lightning address
        let claim_res = crate::handlers::claim::claim_invite_handler(
            &state,
            crate::types::ClaimRequest {
                invite_id: invite_id.to_string(),
                alias: "carol@example.com".into(),
                signed_profile: None,
                lightning_address: Some("carol@getalby.com".into()),
                onchain_address: None,
                onchain_pubkey: None,
                ark_server: None,
                ark_pubkey: None,
            },
        )
        .unwrap();

        assert_eq!(claim_res.status, "claimed");
        assert_eq!(claim_res.alias, "carol@example.com");
        assert_eq!(claim_res.amount_sats, 25_000);
        assert!(!claim_res.profile_pubkey.is_empty());

        // 4. Verify invite is now ClaimedWithPublicProfile
        let re_inspect = crate::handlers::claim::inspect_invite_handler(&state, invite_id).unwrap();
        assert_eq!(
            re_inspect.status,
            satspath_core::InviteStatus::ClaimedWithPublicProfile
        );
        assert!(!re_inspect.is_claimable);

        // 5. Verify claim notification exists for sender
        let notifications = crate::handlers::claim::list_notifications_handler(&state).unwrap();
        assert_eq!(notifications.len(), 1);
        assert_eq!(notifications[0].invite_id, invite_id);
        assert_eq!(notifications[0].amount_sats, 25_000);
        assert!(!notifications[0].read);

        // 6. Sender marks notification as read
        crate::handlers::claim::mark_notification_read_handler(
            &state,
            &notifications[0].notification_id,
        )
        .unwrap();
        let updated_notifications =
            crate::handlers::claim::list_notifications_handler(&state).unwrap();
        assert!(updated_notifications[0].read);

        // 7. Double claiming fails with error
        let double_claim = crate::handlers::claim::claim_invite_handler(
            &state,
            crate::types::ClaimRequest {
                invite_id: invite_id.to_string(),
                alias: "carol@example.com".into(),
                signed_profile: None,
                lightning_address: Some("carol@getalby.com".into()),
                onchain_address: None,
                onchain_pubkey: None,
                ark_server: None,
                ark_pubkey: None,
            },
        );
        assert!(double_claim.is_err());
        assert!(double_claim
            .unwrap_err()
            .to_string()
            .contains("already been claimed"));

        // 8. Sender can now re-resolve carol@example.com in the transparency log
        let store = satspath_core::TransactionalTransparencyStore::open(dir.path()).unwrap();
        let profile = store.profile("carol@example.com").unwrap();
        assert!(profile.is_some());
        assert_eq!(profile.unwrap().profile.alias, "carol@example.com");
    }

    #[tokio::test]
    async fn test_expired_and_mismatched_claims() {
        let dir = tempfile::tempdir().unwrap();
        let state = test_state(dir.path());
        load_or_create_identity(dir.path()).unwrap();

        let mut store = satspath_core::InviteStore::open(dir.path()).unwrap();
        let expired_invite = satspath_core::create_invite_record(
            "alice@example.com",
            10_000,
            None,
            "sender-fp".into(),
            -10, // already expired
        );
        let expired_id = expired_invite.invite_id.clone();
        store.insert(expired_invite).unwrap();

        // Expired claim fails
        let expired_err = crate::handlers::claim::claim_invite_handler(
            &state,
            crate::types::ClaimRequest {
                invite_id: expired_id.clone(),
                alias: "alice@example.com".into(),
                signed_profile: None,
                lightning_address: Some("alice@example.com".into()),
                onchain_address: None,
                onchain_pubkey: None,
                ark_server: None,
                ark_pubkey: None,
            },
        )
        .unwrap_err();
        assert!(expired_err.to_string().contains("expired"));

        // Mismatched alias claim fails
        let valid_invite = satspath_core::create_invite_record(
            "bob@example.com",
            50_000,
            None,
            "sender-fp".into(),
            3600,
        );
        let valid_id = valid_invite.invite_id.clone();
        store.insert(valid_invite).unwrap();

        let mismatch_err = crate::handlers::claim::claim_invite_handler(
            &state,
            crate::types::ClaimRequest {
                invite_id: valid_id,
                alias: "mallory@example.com".into(),
                signed_profile: None,
                lightning_address: Some("mallory@example.com".into()),
                onchain_address: None,
                onchain_pubkey: None,
                ark_server: None,
                ark_pubkey: None,
            },
        )
        .unwrap_err();
        assert!(mismatch_err.to_string().contains("does not match"));
    }
}
