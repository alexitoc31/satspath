//! HTTP request router: dispatches (method, path) pairs to handler functions.

use anyhow::Result;
use tiny_http::{Method, Request, StatusCode};

use crate::auth::check_auth;
use crate::config::AppState;
use crate::handlers::{
    claim::{
        claim_invite_handler, inspect_invite_handler, list_invites_handler,
        list_notifications_handler, mark_all_notifications_read_handler,
        mark_notification_read_handler,
    },
    profile::{
        create_challenge, profile_response, recover_profile_key, rotate_profile_key,
        update_profile, update_profile_methods, verify_challenge,
    },
    quote::{pay_response, quote_response},
    resolve::{dns_resolve_response, resolve_profile, resolve_v2_envelope},
    send::{broadcast, receive_view, send_response},
    status::{node_response, status_response},
    transparency::{
        anchor_latest_checkpoint, catena_chain, consistency_from_query, namespace_descriptor,
        paginated, query_str, transparency_log,
    },
};
use crate::http::{
    empty_response, handle_read_error, json_error, json_response, json_result, read_json,
};
use crate::rate_limit;
use crate::types::{
    safety_warnings, AliasRequest, CatenaVerifyRequest, ClaimRequest, ConsistencyVerifyRequest,
    DnsResolveRequest, InclusionVerifyRequest, PayRequest, PreviewResponse, ProfileRecoverRequest,
    ProfileUpdateRequest, QuoteRequest, ReceiveRequest, SendRequest, VerifyRequest,
};
use crate::ui::{html_response, INDEX_HTML};
use crate::v2_api;

pub(crate) fn route_template(path: &str) -> &'static str {
    match path {
        "/" => "/",
        "/claim" => "/claim",
        "/metrics" => "/metrics",
        "/health" => "/health",
        "/v1/health" => "/v1/health",
        "/v2/health" => "/v2/health",
        "/v1/dashboard/auth" => "/v1/dashboard/auth",
        "/dashboard-auth.mjs" => "/dashboard-auth.mjs",
        "/v1/diagnostics/rate_limit" => "/v1/diagnostics/rate_limit",
        "/v1/receive" => "/v1/receive",
        "/v1/send" => "/v1/send",
        "/v1/broadcast" => "/v1/broadcast",
        "/.well-known/satspath-authority" | "/v2/namespace" => "/v2/namespace",
        "/v2/resolve" => "/v2/resolve",
        "/v1/node" => "/v1/node",
        "/v1/control" => "/v1/control",
        "/v1/p2p/resolve" => "/v1/p2p/resolve",
        "/v1/status" => "/v1/status",
        "/v1/profile" => "/v1/profile",
        "/v1/profile/challenge" => "/v1/profile/challenge",
        "/v1/profile/verify" => "/v1/profile/verify",
        "/v1/profile/rotate-key" => "/v1/profile/rotate-key",
        "/v1/profile/recover" => "/v1/profile/recover",
        "/v1/profile/methods" => "/v1/profile/methods",
        "/v1/resolve" => "/v1/resolve",
        "/v1/preview" => "/v1/preview",
        "/v1/quote" => "/v1/quote",
        "/v1/pay" => "/v1/pay",
        "/v1/dns/resolve" => "/v1/dns/resolve",
        "/v1/claim" => "/v1/claim",
        "/v1/invites" => "/v1/invites",
        "/v1/invites/notifications" => "/v1/invites/notifications",
        "/v1/invites/notifications/read-all" => "/v1/invites/notifications/read-all",
        "/v1/transparency/status" => "/v1/transparency/status",
        "/v1/transparency/checkpoints" => "/v1/transparency/checkpoints",
        "/v1/transparency/anchors" => "/v1/transparency/anchors",
        "/v1/transparency/consistency" => "/v1/transparency/consistency",
        "/v1/transparency/events" => "/v1/transparency/events",
        "/v1/transparency/catena/chain" => "/v1/transparency/catena/chain",
        "/v1/transparency/catena/anchor" => "/v1/transparency/catena/anchor",
        "/v1/transparency/verify/inclusion" => "/v1/transparency/verify/inclusion",
        "/v1/transparency/verify/consistency" => "/v1/transparency/verify/consistency",
        "/v1/transparency/verify/catena" => "/v1/transparency/verify/catena",
        p if p.starts_with("/v1/transparency/checkpoints/") => "/v1/transparency/checkpoints/:hash",
        p if p.starts_with("/v1/transparency/events/") => "/v1/transparency/events/:hash",
        p if p.starts_with("/v1/transparency/identifiers/") => "/v1/transparency/identifiers/:id",
        p if p.starts_with("/v1/transparency/inclusion/") => "/v1/transparency/inclusion/:hash",
        p if p.starts_with("/v1/transparency/anchors/") => "/v1/transparency/anchors/:txid",
        p if p.starts_with("/v1/invites/notifications/") => "/v1/invites/notifications/:id",
        p if p.starts_with("/v1/claim/") => "/v1/claim/:id",
        p if p.starts_with("/v1/invites/") => "/v1/invites/:id",
        _ => "other",
    }
}

pub(crate) fn method_label(m: &Method) -> &'static str {
    match m {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Delete => "DELETE",
        Method::Head => "HEAD",
        Method::Options => "OPTIONS",
        Method::Patch => "PATCH",
        _ => "OTHER",
    }
}

pub(crate) async fn handle_request(mut request: Request, state: &AppState) -> Result<()> {
    let req_start = std::time::Instant::now();
    let request_id = crate::telemetry::get_or_generate_request_id(request.headers());
    let method = request.method().clone();
    let method_str = method_label(&method);
    let raw_url = request.url().to_string();
    let path = raw_url.split('?').next().unwrap_or("/").to_string();
    let template = route_template(&path);

    let request_span = tracing::info_span!(
        "http_request",
        request_id = %request_id,
        method = method_str,
        endpoint = template,
    );

    use tracing::Instrument;
    async {
        let is_internal_scrape = template == "/metrics"
            && request
                .headers()
                .iter()
                .find(|h| h.field.equiv("Host"))
                .and_then(|h| crate::host::parse_authority(h.value.as_str()).ok())
                .map(|h| h.to_string() == "satspathd")
                .unwrap_or(false);

        if !crate::host::is_allowed_host(request.headers(), state.bind, &state.allowed_hosts)
            && !is_internal_scrape
        {
            let resp = json_error(StatusCode(400), anyhow::anyhow!("untrusted HTTP Host"))
                .with_header(crate::http::request_id_header(&request_id));
            let _ = request.respond(resp);
            crate::telemetry::record_http_request(
                method_str,
                template,
                400,
                req_start.elapsed().as_secs_f64(),
            );
            return Ok(());
        }

    // 1. Guard against oversized request bodies (HTTP 413 Payload Too Large)
    let max_body = state.rate_limiter.max_body_bytes();
    if let Some(body_len) = request.body_length() {
        if body_len > max_body {
            state.rate_limiter.record_payload_too_large();
            crate::telemetry::metrics::record_rate_limit_dropped("payload_too_large");
            tracing::warn!(
                body_len = body_len,
                max_body = max_body,
                "payload too large: {} bytes (limit: {}) on {} {}",
                body_len,
                max_body,
                method_str,
                template
            );
            let resp = rate_limit::payload_too_large_response(max_body)
                .with_header(crate::http::request_id_header(&request_id));
            let _ = request.respond(resp);
            crate::telemetry::record_http_request(
                method_str,
                template,
                413,
                req_start.elapsed().as_secs_f64(),
            );
            return Ok(());
        }
    }

    // 2. Client IP extraction and rate limiting (HTTP 429 Too Many Requests)
    let client_ip = rate_limit::extract_client_ip(
        request.remote_addr(),
        request.headers(),
        state.rate_limiter.trust_proxy_headers(),
    );

    match state.rate_limiter.check(&client_ip) {
        rate_limit::RateLimitResult::Allowed { remaining: _ } => {}
        rate_limit::RateLimitResult::RateLimited { retry_after_secs } => {
            crate::telemetry::metrics::record_rate_limit_dropped("rate_limited");
            tracing::warn!(
                client_ip = %client_ip,
                retry_after_secs = retry_after_secs,
                "client IP {} exceeded rate limit on {} {}, retry after {}s",
                client_ip,
                method_str,
                template,
                retry_after_secs
            );
            let resp = rate_limit::rate_limit_response(retry_after_secs)
                .with_header(crate::http::request_id_header(&request_id));
            let _ = request.respond(resp);
            crate::telemetry::record_http_request(
                method_str,
                template,
                429,
                req_start.elapsed().as_secs_f64(),
            );
            return Ok(());
        }
    }

    let is_mutation = !matches!(method, Method::Get | Method::Head | Method::Options);
    let is_public_mutation = path == "/v1/receive"
        || path == "/v1/send"
        || path == "/v1/claim"
        || path == "/v1/dns/resolve"
        || path == "/v1/transparency/verify/inclusion"
        || path == "/v1/transparency/verify/catena"
        || path == "/v1/profile/recover"
        || path == "/v2/resolve";

    if is_mutation && !is_public_mutation {
        if let Err(e) = check_auth(&request, &state.auth_token) {
            let resp = json_error(StatusCode(401), e)
                .with_header(crate::http::request_id_header(&request_id));
            let _ = request.respond(resp);
            crate::telemetry::record_http_request(
                method_str,
                template,
                401,
                req_start.elapsed().as_secs_f64(),
            );
            return Ok(());
        }
    }

    let response = match (method.clone(), path.as_str()) {
        (Method::Options, _) => empty_response(StatusCode(204)),
        (Method::Get, "/") | (Method::Get, "/claim") => html_response(INDEX_HTML),
        (Method::Get, "/dashboard-auth.mjs") => crate::ui::dashboard_auth_script(),
        // Reuses the fail-closed mutation guard above. No token or cookie is returned.
        (Method::Post, "/v1/dashboard/auth") => json_response(
            StatusCode(200),
            &serde_json::json!({ "authenticated": true }),
        ),
        (Method::Get, "/v1/diagnostics/rate_limit") => {
            json_response(StatusCode(200), &state.rate_limiter.stats())
        }
        (Method::Post, "/v1/receive") => match read_json::<ReceiveRequest>(&mut request) {
            Ok(body) => json_result(StatusCode(200), receive_view(state, body)),
            Err(e) => handle_read_error(e),
        },
        (Method::Post, "/v1/send") => match read_json::<SendRequest>(&mut request) {
            Ok(body) => json_response(StatusCode(200), &send_response(state, body).await),
            Err(e) => handle_read_error(e),
        },
        (Method::Post, "/v1/broadcast") => json_result(StatusCode(200), broadcast(state)),
        (Method::Get, "/metrics") => match crate::telemetry::gather_metrics() {
            Ok(metrics_text) => crate::http::text_response(
                StatusCode(200),
                metrics_text,
                prometheus::TEXT_FORMAT,
            ),
            Err(e) => json_error(StatusCode(500), e),
        },
        (Method::Get, "/health") => json_response(
            StatusCode(200),
            &serde_json::json!({ "ok": true, "status": "healthy" }),
        ),
        (Method::Get, "/v1/health") => {
            let health = crate::telemetry::perform_deep_health_check(&state.home).await;
            let status = if health.status == "healthy" || health.status == "degraded" {
                StatusCode(200)
            } else {
                StatusCode(503)
            };
            json_response(status, &health)
        }
        (Method::Get, v2_api::routes::HEALTH) => {
            let (checkpoint_age, log_ok) = match transparency_log(state) {
                Ok(log) => {
                    let latest = log.checkpoints().last().map(|c| c.created_at).unwrap_or(0);
                    let now = chrono::Utc::now().timestamp();
                    let age = if latest == 0 { 0 } else { now - latest };
                    (age, true)
                }
                Err(_) => (-1, false),
            };
            let resp = v2_api::build_health_response(checkpoint_age, log_ok, 1);
            let status = if resp.status == "healthy" {
                StatusCode(200)
            } else {
                StatusCode(503)
            };
            json_response(status, &resp)
        }
        (Method::Get, "/.well-known/satspath-authority")
        | (Method::Get, v2_api::routes::NAMESPACE) => {
            json_result(StatusCode(200), namespace_descriptor(state))
        }
        (Method::Get, v2_api::routes::RESOLVE) => {
            match crate::handlers::transparency::query_str(&raw_url, "identifier") {
                Some(identifier) if !identifier.trim().is_empty() => {
                    let res_start = std::time::Instant::now();
                    match resolve_v2_envelope(state, &identifier) {
                        Ok(envelope) => {
                            crate::telemetry::record_profile_resolution(
                                "success",
                                false,
                                res_start.elapsed().as_secs_f64(),
                            );
                            json_response(StatusCode(200), &envelope)
                        }
                        Err(e) => {
                            crate::telemetry::record_profile_resolution(
                                "error",
                                false,
                                res_start.elapsed().as_secs_f64(),
                            );
                            let status = if e.to_string().contains("not found") {
                                StatusCode(404)
                            } else {
                                StatusCode(400)
                            };
                            json_error(status, e)
                        }
                    }
                }
                _ => json_error(
                    StatusCode(400),
                    anyhow::anyhow!("missing or empty 'identifier' query parameter"),
                ),
            }
        }
        (Method::Post, v2_api::routes::RESOLVE) => {
            match read_json::<satspath_core::transparency::ResolutionRequest>(&mut request) {
                Ok(body) => {
                    let res_start = std::time::Instant::now();
                    match resolve_v2_envelope(state, &body.identifier) {
                        Ok(envelope) => {
                            crate::telemetry::record_profile_resolution(
                                "success",
                                false,
                                res_start.elapsed().as_secs_f64(),
                            );
                            json_response(StatusCode(200), &envelope)
                        }
                        Err(e) => {
                            crate::telemetry::record_profile_resolution(
                                "error",
                                false,
                                res_start.elapsed().as_secs_f64(),
                            );
                            let status = if e.to_string().contains("not found") {
                                StatusCode(404)
                            } else {
                                StatusCode(400)
                            };
                            json_error(status, e)
                        }
                    }
                }
                Err(e) => handle_read_error(e),
            }
        }
        (Method::Get, "/v1/node") => json_result(StatusCode(200), node_response(state)),
        (Method::Get, "/v1/control") => match crate::p2p::local_summary(state) {
            Ok(identity) => json_response(
                StatusCode(200),
                &serde_json::json!({
                    "identity": identity, "hyperswarm": state.p2p.status.lock().await.clone(),
                    "http": "active", "nostr": "on_demand_resolver", "experimental": true
                }),
            ),
            Err(_) => json_error(
                StatusCode(500),
                anyhow::anyhow!("control status unavailable"),
            ),
        },
        (Method::Post, "/v1/p2p/resolve") => match read_json::<AliasRequest>(&mut request) {
            Ok(body) => match crate::p2p::resolve_candidate(state, &body.alias).await {
                Ok(candidate) => json_response(StatusCode(200), &candidate),
                Err(_) => json_error(
                    StatusCode(400),
                    anyhow::anyhow!("P2P candidate unavailable or rejected"),
                ),
            },
            Err(e) => handle_read_error(e),
        },
        (Method::Get, "/v1/status") => json_result(StatusCode(200), status_response(state)),
        (Method::Get, "/v1/profile") => json_result(StatusCode(200), profile_response(state)),
        (Method::Get, "/v1/transparency/status") => json_result(
            StatusCode(200),
            transparency_log(state).and_then(|log| log.status().map_err(Into::into)),
        ),
        (Method::Get, "/v1/transparency/checkpoints") => json_result(
            StatusCode(200),
            transparency_log(state).map(|log| paginated(&raw_url, log.checkpoints())),
        ),
        (Method::Get, "/v1/transparency/events") => json_result(
            StatusCode(200),
            transparency_log(state).map(|log| paginated(&raw_url, log.events())),
        ),
        (Method::Get, p) if p.starts_with("/v1/transparency/checkpoints/") => {
            let hash = p.trim_start_matches("/v1/transparency/checkpoints/");
            json_result(
                StatusCode(200),
                transparency_log(state).and_then(|log| {
                    log.checkpoints()
                        .iter()
                        .find(|c| c.checkpoint_hash().ok().as_deref() == Some(hash))
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("checkpoint not found"))
                }),
            )
        }
        (Method::Get, p) if p.starts_with("/v1/transparency/events/") => {
            let hash = p.trim_start_matches("/v1/transparency/events/");
            json_result(
                StatusCode(200),
                transparency_log(state).and_then(|log| {
                    log.event(hash).map_err(Into::into).and_then(|e| {
                        e.cloned()
                            .ok_or_else(|| satspath_core::SatsPathError::AliasNotFound(hash.into()))
                            .map_err(Into::into)
                    })
                }),
            )
        }
        (Method::Get, p) if p.starts_with("/v1/transparency/identifiers/") => {
            let identifier = p.trim_start_matches("/v1/transparency/identifiers/");
            json_result(
                StatusCode(200),
                transparency_log(state).map(|log| {
                    let events: Vec<_> =
                        log.history(identifier).into_iter().cloned().collect();
                    serde_json::json!({"identifier_hash": identifier, "latest": events.last(), "history": events})
                }),
            )
        }
        (Method::Get, p) if p.starts_with("/v1/transparency/inclusion/") => {
            let hash = p.trim_start_matches("/v1/transparency/inclusion/");
            json_result(
                StatusCode(200),
                transparency_log(state)
                    .and_then(|log| log.inclusion(hash, None).map_err(Into::into)),
            )
        }
        (Method::Get, p) if p.starts_with("/v1/transparency/anchors/") => {
            let txid = p.trim_start_matches("/v1/transparency/anchors/");
            json_result(
                StatusCode(200),
                transparency_log(state).and_then(|log| {
                    log.checkpoints()
                        .iter()
                        .filter_map(|c| c.bitcoin_anchor.as_ref())
                        .find(|a| a.txid == txid)
                        .cloned()
                        .ok_or_else(|| anyhow::anyhow!("anchor not found"))
                }),
            )
        }
        (Method::Get, "/v1/transparency/anchors") => json_result(
            StatusCode(200),
            transparency_log(state).map(|log| {
                let anchors: Vec<_> = log
                    .checkpoints()
                    .iter()
                    .filter_map(|c| c.bitcoin_anchor.clone())
                    .collect();
                paginated(&raw_url, &anchors)
            }),
        ),
        (Method::Get, "/v1/transparency/catena/chain") => json_result(
            StatusCode(200),
            catena_chain(state).map(|chain| {
                serde_json::json!({
                    "chain_length": chain.len(),
                    "genesis": chain.first(),
                    "latest": chain.last(),
                    "anchors": paginated(&raw_url, &chain),
                })
            }),
        ),
        (Method::Post, "/v1/transparency/anchors") => match anchor_latest_checkpoint(state).await {
            Ok(anchor) => json_response(StatusCode(200), &anchor),
            Err(e) => json_error(StatusCode(400), e),
        },
        (Method::Get, "/v1/transparency/consistency") => {
            json_result(StatusCode(200), consistency_from_query(state, &raw_url))
        }
        (Method::Post, "/v1/transparency/verify/inclusion") => {
            match read_json::<InclusionVerifyRequest>(&mut request).and_then(|body| {
                satspath_core::transparency::verify_checkpoint_inclusion(
                    &body.event_hash,
                    &body.proof,
                    &body.checkpoint,
                )
                .map(|_| true)
                .map_err(Into::into)
            }) {
                Ok(valid) => json_response(StatusCode(200), &serde_json::json!({"valid": valid})),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Post, "/v1/transparency/verify/consistency") => {
            match read_json::<ConsistencyVerifyRequest>(&mut request).and_then(|body| {
                satspath_core::transparency::verify_consistency_proof(&body.proof)
                    .map_err(Into::into)
            }) {
                Ok(valid) => json_response(StatusCode(200), &serde_json::json!({"valid": valid})),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        // Evaluates purely in-memory structural consistency of the caller-supplied sequence of anchors
        // (linkage, sequence indices, and optional checkpoint hash commitments).
        // This endpoint does NOT query a live Bitcoin node; clients must independently verify on-chain confirmations and outpoints.
        (Method::Post, "/v1/transparency/verify/catena") => {
            match read_json::<CatenaVerifyRequest>(&mut request).and_then(|body| {
                if let Some(genesis) = body.anchors.first() {
                    if genesis.continuation_vout
                        != Some(satspath_core::transparency::CATENA_CONTINUATION_VOUT)
                    {
                        return Err(
                            satspath_core::transparency::TransparencyError::InvalidCatenaChain(
                                format!(
                                    "genesis continuation_vout is {:?}, expected Some({})",
                                    genesis.continuation_vout,
                                    satspath_core::transparency::CATENA_CONTINUATION_VOUT
                                ),
                            )
                            .into(),
                        );
                    }
                }
                let structurally_consistent =
                    satspath_core::transparency::verify_catena_links(&body.anchors)?;
                let commitments_valid = match &body.checkpoint_hashes {
                    Some(hashes) => {
                        let str_hashes: Vec<&str> = hashes.iter().map(String::as_str).collect();
                        Some(satspath_core::transparency::verify_catena_commitments(
                            &body.anchors,
                            &str_hashes,
                        )?)
                    }
                    None => None,
                };
                Ok((structurally_consistent, commitments_valid))
            }) {
                Ok((structurally_consistent, commitments_valid)) => {
                    let mut resp = serde_json::json!({
                        "structurally_consistent": structurally_consistent
                    });
                    if let Some(valid) = commitments_valid {
                        resp["commitments_valid"] = serde_json::json!(valid);
                    }
                    json_response(StatusCode(200), &resp)
                }
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Put, "/v1/profile") | (Method::Post, "/v1/profile") => {
            let _guard = state.mutation_lock.lock().await;
            match read_json::<ProfileUpdateRequest>(&mut request)
                .and_then(|body| update_profile(state, body))
            {
                Ok(resp) => json_response(StatusCode(200), &resp),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Post, "/v1/profile/challenge") => {
            match read_json::<AliasRequest>(&mut request)
                .and_then(|body| create_challenge(state, body))
            {
                Ok(resp) => json_response(StatusCode(200), &resp),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Post, "/v1/profile/verify") => {
            let _guard = state.mutation_lock.lock().await;
            match read_json::<VerifyRequest>(&mut request)
                .and_then(|body| verify_challenge(state, body))
            {
                Ok(resp) => json_response(StatusCode(200), &resp),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Post, "/v1/profile/methods") => {
            let _guard = state.mutation_lock.lock().await;
            match read_json::<ProfileUpdateRequest>(&mut request)
                .and_then(|body| update_profile_methods(state, body))
            {
                Ok(resp) => json_response(StatusCode(200), &resp),
                Err(e) => json_error(StatusCode(400), e),
            }
        }
        (Method::Post, "/v1/profile/rotate-key") => {
            let _guard = state.mutation_lock.lock().await;
            match rotate_profile_key(state) {
                Ok(response) => json_response(StatusCode(200), &response),
                Err(error) => json_error(StatusCode(400), error),
            }
        }
        (Method::Post, "/v1/profile/recover") => {
            match read_json::<ProfileRecoverRequest>(&mut request) {
                Ok(body) => {
                    let precheck = || -> Result<()> {
                        crate::handlers::profile::validate_recovery_request_shape(&body)?;
                        let alias = satspath_core::privacy::canonical_identifier(&body.alias);
                        let store = satspath_core::TransactionalTransparencyStore::open_read_only(
                            &state.home,
                        )?;
                        let existing = store
                            .profile(&alias)?
                            .ok_or(satspath_core::SatsPathError::AliasNotFound(alias))?;
                        if !satspath_core::recovery::verify_key_recovery(
                            &existing,
                            &body.signed_profile,
                        )? {
                            anyhow::bail!("recovery proof failed verification against existing profile/policy");
                        }
                        Ok(())
                    };
                    if let Err(error) = precheck() {
                        json_error(StatusCode(400), error)
                    } else {
                        let _guard = state.mutation_lock.lock().await;
                        match recover_profile_key(state, body) {
                            Ok(response) => json_response(StatusCode(200), &response),
                            Err(error) => json_error(StatusCode(400), error),
                        }
                    }
                }
                Err(error) => json_error(StatusCode(400), error),
            }
        }
        (Method::Post, "/v1/resolve") => {
            match read_json::<AliasRequest>(&mut request)
                .and_then(|body| resolve_profile(state, &body.alias))
            {
                Ok(profile) => json_response(StatusCode(200), &profile),
                Err(e) => json_error(StatusCode(404), e),
            }
        }
        (Method::Post, "/v1/quote") => match read_json::<QuoteRequest>(&mut request) {
            Ok(body) => json_response(StatusCode(200), &quote_response(state, body).await),
            Err(e) => json_error(StatusCode(400), e),
        },
        (Method::Post, "/v1/pay") => match read_json::<PayRequest>(&mut request) {
            Ok(body) => json_response(StatusCode(200), &pay_response(state, body).await),
            Err(e) => json_error(StatusCode(400), e),
        },
        (Method::Post, "/v1/dns/resolve") => match read_json::<DnsResolveRequest>(&mut request) {
            Ok(body) => json_response(StatusCode(200), &dns_resolve_response(body).await),
            Err(e) => handle_read_error(e),
        },
        (Method::Post, "/v1/preview") => match read_json::<QuoteRequest>(&mut request) {
            Ok(body) => {
                let quote = quote_response(state, body).await;
                json_response(
                    StatusCode(200),
                    &PreviewResponse {
                        mode: "preview_only",
                        warnings: safety_warnings(),
                        quote,
                    },
                )
            }
            Err(e) => json_error(StatusCode(400), e),
        },
        (Method::Get, p) if p.starts_with("/v1/claim") => {
            let invite_id = query_str(&raw_url, "invite_id").or_else(|| {
                let sub = p.trim_start_matches("/v1/claim").trim_start_matches('/');
                if !sub.is_empty() {
                    Some(sub.to_string())
                } else {
                    None
                }
            });
            match invite_id {
                Some(id) => json_result(StatusCode(200), inspect_invite_handler(state, &id)),
                None => json_error(
                    StatusCode(400),
                    anyhow::anyhow!("missing 'invite_id' query parameter or path segment"),
                ),
            }
        }
        (Method::Post, "/v1/claim") => {
            let _guard = state.mutation_lock.lock().await;
            match read_json::<ClaimRequest>(&mut request) {
                Ok(body) => match claim_invite_handler(state, body) {
                    Ok(resp) => json_response(StatusCode(200), &resp),
                    Err(e) => {
                        let err_str = e.to_string();
                        let status = if err_str.contains("not found") {
                            StatusCode(404)
                        } else if err_str.contains("already been claimed") {
                            StatusCode(409)
                        } else {
                            StatusCode(400)
                        };
                        json_error(status, e)
                    }
                },
                Err(e) => handle_read_error(e),
            }
        }
        (Method::Get, "/v1/invites") => json_result(StatusCode(200), list_invites_handler(state)),
        (Method::Get, "/v1/invites/notifications") => {
            json_result(StatusCode(200), list_notifications_handler(state))
        }
        (Method::Post, "/v1/invites/notifications/read-all") => {
            json_result(StatusCode(200), mark_all_notifications_read_handler(state))
        }
        (Method::Post, p) if p.starts_with("/v1/invites/notifications/") => {
            let id = p
                .trim_start_matches("/v1/invites/notifications/")
                .trim_end_matches("/read");
            json_result(StatusCode(200), mark_notification_read_handler(state, id))
        }
        _ => json_error(StatusCode(404), anyhow::anyhow!("endpoint not found")),
    };
    let status_code = response.status_code().0;
    let duration_secs = req_start.elapsed().as_secs_f64();
    crate::telemetry::record_http_request(method_str, template, status_code, duration_secs);
    tracing::info!(
        endpoint = template,
        status = status_code,
        duration_ms = duration_secs * 1000.0,
        "request completed"
    );
    let response = response.with_header(crate::http::request_id_header(&request_id));
    request.respond(response)?;
    Ok(())
    }
    .instrument(request_span)
    .await
}

#[cfg(test)]
mod tests {
    use super::route_template;

    #[test]
    fn templates_cover_dispatched_routes_without_identifier_labels() {
        for path in [
            "/v1/profile/rotate-key",
            "/v1/resolve",
            "/v1/preview",
            "/v1/transparency/anchors",
            "/v1/transparency/consistency",
            "/v1/claim",
        ] {
            assert_eq!(route_template(path), path);
        }
        for id in ["invite-one", "invite-two"] {
            assert_eq!(route_template(&format!("/v1/claim/{id}")), "/v1/claim/:id");
        }
        assert_eq!(route_template("/v1/profile/rotate"), "other");
        assert_eq!(route_template("/unknown"), "other");
    }
}
