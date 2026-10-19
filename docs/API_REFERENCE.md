# satspathd HTTP API Reference

Human-readable companion to the machine-readable OpenAPI 3.0.3 specification in
[`openapi.yaml`](openapi.yaml). The spec is the source of truth for request and
response schemas; this page explains behavior that a schema cannot express
(authentication model, request pipeline, error conventions, and known quirks).

> **Non-custodial boundary.** `satspathd` never moves funds, signs Bitcoin
> transactions, broadcasts payments, or stores seeds or spending keys.
> `POST /v1/pay` returns a wallet-handoff payload only; the host wallet signs
> and executes.

Maturity labels follow the [README taxonomy](../README.md#maturity-taxonomy):
BIP-353 and BOLT12 primitives are IMPLEMENTED; Ark payment routing is PREVIEW;
Silent Payments, P2P, and invites are EXPERIMENTAL; the post-quantum profile
fields are RESEARCH. Note that the daemon's quote, pay, send, and receive
handoff endpoints still enforce strict on-chain BIP-21 validation. SatsPath has
not had an independent third-party security audit.

---

## 1. Using the specification

The file is plain OpenAPI 3.0.3 YAML. Any compatible tool can render or consume it.

```bash
# Interactive Swagger UI on http://localhost:8081 (requires Docker)
docker run --rm -p 8081:8080 \
  -e SWAGGER_JSON=/spec/openapi.yaml \
  -v "$(pwd)/docs:/spec:ro" swaggerapi/swagger-ui

# Lint the spec (requires Node)
npx @redocly/cli lint docs/openapi.yaml
```

You can also paste the file into <https://editor.swagger.io>, or import it into
Postman or Insomnia to generate a request collection. Generated clients should be
treated as a convenience: review the "Errors returned with HTTP 200" section below
before relying on status codes.

Example values in the spec (hashes, signatures, fingerprints) are synthetic and
are **not** cryptographically valid.

---

## 2. Connection basics

| Item | Value |
| :--- | :--- |
| Default bind | `127.0.0.1:9737` (`--bind` or `SATSPATHD_BIND`) |
| Transport | HTTP; HTTPS via `--tls-cert`/`--tls-key` or a reverse proxy |
| Content type | `application/json` for all JSON bodies and responses |
| Default network | `devnet` (`--network` or `SATSPATH_NETWORK`) |
| Correlation id | Send `X-Request-Id`; the daemon echoes it or generates one |
| Max request body | 64 KiB (65,536 bytes) for declared `Content-Length` values and JSON request readers |

A production deployment must not expose cleartext HTTP. See
[`docker.md`](docker.md) and
[`security/REVERSE_PROXY_RATE_LIMITING.md`](security/REVERSE_PROXY_RATE_LIMITING.md).

### Host header allow-list

Requests normally require exactly one trusted `Host` header before routing.
Requests to `/metrics` are an exception when the parsed `Host` is `satspathd`:
the router may allow them even if the normal Host allow-list check fails. This
Host-based exception does not restrict `/metrics` to internal callers. Loopback
binds accept `localhost` and loopback IP literals. For a DNS name (proxy or
native TLS), set `SATSPATH_AUTHORITY_DOMAIN=node.example.com` or
`SATSPATH_AUTHORITY_URL=https://node.example.com/v2`. Missing, duplicate,
malformed, or untrusted hosts on other requests receive
`400 {"error":"untrusted HTTP Host"}`.
`X-Forwarded-Host` and `--behind-proxy` do not bypass this check. See
[`dashboard_authentication.md`](dashboard_authentication.md).

---

## 3. Authentication

Protected routes require a Bearer token:

```bash
TOKEN=$(cat ~/.satspath/admin.macaroon)   # 64 hex characters
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:9737/v1/dashboard/auth
```

* The token is created on first start in `<home>/admin.macaroon` (mode 0600 on
  Unix) or supplied through `SATSPATHD_AUTH_TOKEN` (must be 64 hex characters).
* Comparison is constant-time and fail-closed: an unconfigured token rejects
  every protected request.
* The token grants full daemon administration. Never log it, put it in URLs, or
  share it. No endpoint returns it.

### Which routes are protected

The rule is method-based, not route-based:

1. Any request that is **not** `GET`, `HEAD`, or `OPTIONS` requires the Bearer
   token, **except** this public allow-list:
   `POST /v1/receive`, `POST /v1/send`, `POST /v1/claim`, `POST /v1/dns/resolve`,
   `POST /v1/transparency/verify/inclusion`, `POST /v1/transparency/verify/catena`,
   `POST /v1/profile/recover`, and `POST /v2/resolve`.
2. `GET`, `HEAD`, and `OPTIONS` requests are never authenticated.

Consequences worth knowing:

* `POST /v1/resolve`, `/v1/quote`, `/v1/preview`, and `/v1/pay` **require the
  token** even though they only read and compute.
* `POST /v1/transparency/verify/consistency` requires the token, while the
  inclusion and Catena verifiers are public.
* Read-only `GET` endpoints such as `/v1/status`, `/v1/profile`, `/v1/node`,
  `/v1/invites`, and `/v1/diagnostics/rate_limit` are open to anyone who can
  reach the port. `/v1/status` includes the daemon home path. Bind to loopback
  or restrict access at the proxy.

---

## 4. Request pipeline and global errors

Checks run in this order; the first failure wins.

| Order | Check | Response |
| :--- | :--- | :--- |
| 1 | `Host` allow-list (except `/metrics` with parsed `Host: satspathd`) | `400` `{"error":"untrusted HTTP Host"}` |
| 2 | Declared `Content-Length` over limit | `413` `{"error":"...","max_bytes":65536}` |
| 3 | Per-IP token bucket (burst 60, refill 10/s) | `429` with `Retry-After` header and `{"error":"...","retry_after":N}` |
| 4 | Bearer token (protected routes) | `401` `{"error":"Unauthorized: ..."}` |
| 5 | Route dispatch | Handler response, or `404` `{"error":"endpoint not found"}` |

Rate limiting keys on the peer socket address. Behind a trusted proxy, start the
daemon with `--behind-proxy` (or `SATSPATHD_BEHIND_PROXY=1`) so
`X-Forwarded-For` and `X-Real-IP` are honored. Tune with `--rate-limit-burst` and
`--rate-limit-rate`.

### Error body

All failures include an `error` field. Some responses also include metadata
such as `max_bytes` or `retry_after`:

```json
{ "error": "human-readable message" }
```

### CORS

Responses built by the JSON, text, and empty-response helpers carry
`Access-Control-Allow-Origin` set to the **first** entry of
`SATSPATHD_CORS_ORIGIN` (default `http://localhost:5173`), plus
`Access-Control-Allow-Methods: GET, POST, OPTIONS` and
`Access-Control-Allow-Headers: Content-Type, Authorization, X-Request-Id`.
The HTML UI (`GET /` and `/claim`) sends only `Access-Control-Allow-Origin`;
`GET /dashboard-auth.mjs` sends none of these CORS headers.
After Host validation, the declared body-size check, and rate limiting pass,
`OPTIONS` on any path returns `204`. Because `PUT` is not in the allowed methods,
browsers cannot call `PUT /v1/profile` cross-origin; use `POST /v1/profile`
instead. For multiple origins, use a reverse proxy.

### Errors returned with HTTP 200

Handlers wired through the daemon's `json_result(StatusCode(200), ...)` helper
reuse the success status for failures. The body is still `{"error":"..."}`, but
the HTTP status is **200**. Always check for an `error` key before parsing a
success payload on these operations:

* `GET /v1/status`, `/v1/node`, `/v1/profile`
* `POST /v1/receive` after a successful body read and parse, `POST /v1/broadcast`
* `GET /v1/transparency/status`, `/checkpoints`, `/checkpoints/{hash}`,
  `/events`, `/events/{hash}`, `/identifiers/{id}`, `/inclusion/{hash}`,
  `/consistency`, `/anchors`, `/anchors/{txid}`, `/catena/chain`
* `GET /v1/claim?invite_id=...`, `GET /v1/claim/{id}`, `GET /v1/invites`,
  `GET /v1/invites/notifications`
* `POST /v1/invites/notifications/read-all` and `.../{id}/read`

The OpenAPI file models these as `oneOf [success schema, Error]`.
`GET /v1/claim` without an invite ID instead returns HTTP 400.

### Status-code conventions for the other operations

| Operation | Behavior |
| :--- | :--- |
| `POST /v1/quote`, `/v1/preview`, `/v1/pay`, `/v1/send`, `/v1/dns/resolve` | Protocol outcomes (`no_route`, `invalid_signature`, `not_registered`, `invite`, DNS `error`) are `status` values inside an HTTP 200 body. `400` is only an unparsable body. |
| `POST /v1/resolve` | **Any** failure, including a bad body, returns `404`. |
| `GET`/`POST /v2/resolve` | `404` when the error message contains "not found", otherwise `400`. |
| `POST /v1/claim` | `404` unknown invite, `409` already claimed, `400` otherwise. |
| `POST /v1/p2p/resolve` | Candidate-resolution failures return a generic `400`; body-read failures return `400`, or `413` for an oversized body. |
| `GET /v1/health` | `200` for `healthy`/`degraded`, `503` for `unhealthy`. |
| `GET /v2/health` | `200` for `healthy`, `503` for `degraded`. |

---

## 5. Endpoint index

Access is **Public** (no token) or **Bearer** (token required). 55 operations
across 50 paths.

### UI

| Method | Path | Access | Summary |
| :--- | :--- | :--- | :--- |
| `GET` | `/` | Public | Dashboard (wallet UI) |
| `GET` | `/claim` | Public | Dashboard (claim view) |
| `GET` | `/dashboard-auth.mjs` | Public | Dashboard auth helper script |

### Health and diagnostics

| Method | Path | Access | Summary |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Public | Liveness probe |
| `GET` | `/v1/health` | Public | Deep health check (SQLite, fee API, log) |
| `GET` | `/v2/health` | Public | S2S v2 readiness |
| `GET` | `/metrics` | Public | Prometheus metrics |
| `GET` | `/v1/diagnostics/rate_limit` | Public | Rate-limiter statistics |

### Node

| Method | Path | Access | Summary |
| :--- | :--- | :--- | :--- |
| `GET` | `/v1/status` | Public | Daemon status |
| `GET` | `/v1/node` | Public | Status plus local profile |
| `GET` | `/v1/control` | Public | Node control summary (EXPERIMENTAL) |
| `POST` | `/v1/dashboard/auth` | Bearer | Validate Bearer token |

### Profile

| Method | Path | Access | Summary |
| :--- | :--- | :--- | :--- |
| `GET` | `/v1/profile` | Public | Get local profile |
| `PUT` | `/v1/profile` | Bearer | Create or update profile |
| `POST` | `/v1/profile` | Bearer | Same as `PUT` (CORS-friendly) |
| `POST` | `/v1/profile/methods` | Bearer | Update receive methods |
| `POST` | `/v1/profile/challenge` | Bearer | Start alias verification (DEV MOCK) |
| `POST` | `/v1/profile/verify` | Bearer | Complete alias verification (DEV MOCK) |
| `POST` | `/v1/profile/rotate-key` | Bearer | Rotate identity key |
| `POST` | `/v1/profile/recover` | Public | Recover key with guardian quorum |
| `POST` | `/v1/broadcast` | Bearer | Save profile for publication |

### Resolution and routing

| Method | Path | Access | Summary |
| :--- | :--- | :--- | :--- |
| `POST` | `/v1/resolve` | Bearer | Resolve with full transparency verification |
| `POST` | `/v1/quote` | Bearer | Quote the best rail |
| `POST` | `/v1/preview` | Bearer | Quote plus safety warnings |
| `POST` | `/v1/pay` | Bearer | Wallet handoff (never executes payment) |
| `POST` | `/v1/send` | Public | Preview send via legacy resolver chain |
| `POST` | `/v1/receive` | Public | Receive payload and QR for own profile |
| `POST` | `/v1/dns/resolve` | Public | Resolve a BIP-353 name (local DNSSEC) |
| `POST` | `/v1/p2p/resolve` | Bearer | Resolve a P2P candidate (EXPERIMENTAL) |

### S2S v2

| Method | Path | Access | Summary |
| :--- | :--- | :--- | :--- |
| `GET` | `/.well-known/satspath-authority` | Public | Namespace descriptor |
| `GET` | `/v2/namespace` | Public | Namespace descriptor (same handler) |
| `GET` | `/v2/resolve?identifier=` | Public | Proof-carrying resolution |
| `POST` | `/v2/resolve` | Public | Proof-carrying resolution (body) |

### Transparency

| Method | Path | Access | Summary |
| :--- | :--- | :--- | :--- |
| `GET` | `/v1/transparency/status` | Public | Log status |
| `GET` | `/v1/transparency/checkpoints` | Public | List checkpoints (paginated) |
| `GET` | `/v1/transparency/checkpoints/{hash}` | Public | Checkpoint by hash |
| `GET` | `/v1/transparency/events` | Public | List name events (paginated) |
| `GET` | `/v1/transparency/events/{hash}` | Public | Event by hash |
| `GET` | `/v1/transparency/identifiers/{id}` | Public | History of one identifier hash |
| `GET` | `/v1/transparency/inclusion/{hash}` | Public | Inclusion proof for an event |
| `GET` | `/v1/transparency/consistency?from=&to=` | Public | Consistency proof |
| `GET` | `/v1/transparency/anchors` | Public | List Bitcoin anchors (paginated) |
| `POST` | `/v1/transparency/anchors` | Bearer | Anchor latest checkpoint (regtest) |
| `GET` | `/v1/transparency/anchors/{txid}` | Public | Anchor by txid |
| `GET` | `/v1/transparency/catena/chain` | Public | Catena anchor chain |
| `POST` | `/v1/transparency/verify/inclusion` | Public | Verify an inclusion proof |
| `POST` | `/v1/transparency/verify/consistency` | Bearer | Verify a consistency proof |
| `POST` | `/v1/transparency/verify/catena` | Public | Verify anchor-chain structure |

List endpoints accept `offset` (default 0) and `limit` (default 50, clamped to
1-200) and return `{"items":[...],"offset":0,"limit":50,"total":N}`.

### Invites

| Method | Path | Access | Summary |
| :--- | :--- | :--- | :--- |
| `GET` | `/v1/claim?invite_id=` | Public | Inspect an invite |
| `GET` | `/v1/claim/{id}` | Public | Inspect an invite (path form) |
| `POST` | `/v1/claim` | Public | Claim an invite and publish a profile |
| `GET` | `/v1/invites` | Public | List invites |
| `GET` | `/v1/invites/notifications` | Public | List claim notifications |
| `POST` | `/v1/invites/notifications/read-all` | Bearer | Mark all read |
| `POST` | `/v1/invites/notifications/{id}/read` | Bearer | Mark one read |

---

## 6. Worked examples

All examples assume a local daemon and `TOKEN` set as above. Output is abbreviated.

### Check the node

```bash
curl -s http://127.0.0.1:9737/v1/status
```

```json
{
  "daemon": "satspathd",
  "version": "0.1.0",
  "network": "devnet",
  "wallet_initialized": true,
  "alias": "alice@example.com",
  "identity_fingerprint": "a8fdac91",
  "methods": ["Lightning", "Onchain"],
  "safety": {
    "moves_funds": false,
    "signs_bitcoin_transactions": false,
    "broadcasts_transactions": false,
    "stores_wallet_seeds_or_spending_keys": false,
    "manages_signed_profiles": true
  }
}
```

### Publish a receiving profile

The alias must be verified before methods can be saved. The daemon ships no
production alias verifier yet, so `/v1/profile/challenge` and `/v1/profile/verify`
**fail closed (`HTTP 400`) by default**. For local development on a non-mainnet
network, start `satspathd` with `--dev-mock-alias-verification` (or
`SATSPATH_DEV_MOCK_ALIAS_VERIFICATION=1`) to enable the mock verifier where the
token equals the email address itself (refused on `mainnet`).

```bash
curl -s -X POST http://127.0.0.1:9737/v1/profile/challenge \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"alias":"alice@example.com"}'

curl -s -X POST http://127.0.0.1:9737/v1/profile/verify \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"alias":"alice@example.com","token":"alice@example.com"}'

curl -s -X PUT http://127.0.0.1:9737/v1/profile \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"lightning_address":"alice@getalby.com","onchain_address":"tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"}'
```

Each save re-signs the profile (`SHA256("SatsPathProfileV1" || RFC8785(profile))`)
with the next `sequence` and a 30-day expiry, appends a `register` or
`update_profile` `NameEvent` to the transparency log, and signs a new operator
checkpoint.

### Rotate or recover an identity key

* **Key rotation (`POST /v1/profile/rotate-key`)**: requires Bearer auth and an
  empty request body. The daemon generates a new identity key and embeds a
  dual-signed `profile.rotation` object where the previous key signs under
  `SatsPathKeyRotationAuthorizationV1`, the new key signs under
  `SatsPathKeyRotationAcceptanceV1`, and the previous key signs the `rotate_key`
  `NameEvent`.
* **Guardian key recovery (`POST /v1/profile/recover`)**: public (no Bearer
  token). Accepts `alias`, `proof` (`KeyRecoveryProof`), and `signed_profile`
  (where `signed_profile.profile.recovery` must equal `proof`, retain a
  `recovery_policy`, and contain no `rotation`). Guardians sign under
  `SatsPathKeyRecoveryAuthorizationV1` and the new key signs acceptance under
  `SatsPathKeyRecoveryAcceptanceV1`. When the new key is not in the daemon's
  local keystore, also supply `event_signature` (over the `recover_key`
  `NameEvent`) and `event_created_at` (within ±300 seconds of server time). See
  [`key_recovery.md`](key_recovery.md).

### Resolve a BIP-353 DNS name

```bash
curl -s -X POST http://127.0.0.1:9737/v1/dns/resolve \
  -H 'Content-Type: application/json' \
  -d '{"name":"alice@example.com"}'
```

By default (`allow_insecure_dns_for_dev: false`), `/v1/dns/resolve` queries DNS
with `HickoryDnssecTxtResolver` under `DnssecPolicy::Strict`, validating the
RRSIG/DNSKEY/DS chain locally against the embedded ICANN root KSKs (`38696`,
`20326`, `19036`) and failing closed if DNSSEC validation fails. Passing
`"allow_insecure_dns_for_dev": true` switches to `DohTxtResolver` under
`DnssecPolicy::DevInsecure` for local testing.

### Quote and hand off to a wallet

```bash
curl -s -X POST http://127.0.0.1:9737/v1/quote \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"recipient":"alice@example.com","amount_sats":50000}'
```

After global checks and JSON parsing pass, `/v1/quote` returns HTTP 200 and is
tagged by `status`:

| `status` | Meaning |
| :--- | :--- |
| `ok` | Route selected; `qr` holds a validated, amount-bound on-chain BIP-21 URI for the configured network. |
| `no_route` | Profile resolution failed (including lookup or signature verification), no usable route was found, or the selected payload failed handoff validation. Resolution failures have a `reason` starting with `transparency verification failed:`. |

`/v1/quote`, `/v1/preview`, and `/v1/pay` route only through the mandatory
transparency composition (signature, identifier history, key continuity,
inclusion, checkpoint consistency, operator continuity). They then **keep only
payment methods that carry a valid ownership proof**; self-asserted methods are
dropped, so a profile with no proofs yields `no_route`. `/v1/send` uses the legacy
resolver chain and does not apply that filter, so the two can disagree for the
same recipient.

After the wallet-handoff gate in [#159](https://github.com/satspath/satspath/pull/159),
`/v1/quote`, `/v1/preview`, `/v1/pay`, and successful `/v1/send` responses emit
only on-chain BIP-21 payloads whose address, network, and exact amount pass
final validation. A BOLT11 invoice can be validated against its payee, network,
amount, and expiry, but these quote paths do not generate one. Lightning
Addresses and LNURL links remain **amount-less receive pointers**; BOLT12, Ark,
and Silent Payment handoffs return `no_route` or an explicit receive error until
protocol-aware validation is wired into the daemon quote endpoints. On
`/v1/receive`, an omitted rail prefers on-chain when `amount_sats` is set and
Lightning otherwise; explicitly selecting an unsupported rail does not bypass
validation.

`POST /v1/pay` wraps an `ok` quote as `status: wallet_handoff` with
`payment_payload`, `qr_svg`, and `handoff.daemon_executes_payment: false`.

### Verify a name with proofs (S2S v2)

```bash
curl -s -X POST http://127.0.0.1:9737/v2/resolve \
  -H 'Content-Type: application/json' -d '{"identifier":"alice@example.com"}'
```

Prefer `POST` so identifiers stay out of URLs and access logs. The
`ResolutionEnvelope` carries `signed_profile`, `name_events`, `inclusion_proof`,
and `checkpoint`. On this daemon `consistency_proof` is always `null` and
`witness_cosignatures` is always empty.

### Audit the transparency log

```bash
curl -s 'http://127.0.0.1:9737/v1/transparency/checkpoints?limit=10'
curl -s 'http://127.0.0.1:9737/v1/transparency/consistency?from=1&to=3'
```

---

## 7. Mapping from the original issue

Issue 104 listed eleven endpoints. The implemented surface is larger, and two
names differ:

| Issue listed | Reality |
| :--- | :--- |
| `GET /v1/status`, `/v1/node` | Implemented as listed. |
| `POST /v1/resolve`, `/quote`, `/preview`, `/pay`, `/send` | Implemented. First four need the Bearer token; `/v1/send` is public. |
| `POST /v1/register` | **Does not exist.** Unauthenticated requests return `401`; authenticated requests reach the `404` fallback. Profiles are created through `/v1/profile/challenge`, `/verify`, then `PUT /v1/profile`. `POST /v1/receive` builds a receive payload and does not register anything. |
| `GET /v1/transparency/events`, `/checkpoints` | Implemented, paginated. |
| `POST /v1/transparency/anchors` | Implemented, Bearer, regtest only. |

### Declared but not served

These appear in code or older docs but have no working handler. GET requests
return `404`; protected mutation requests pass through authentication first:

* `GET /v2/checkpoint/latest` is listed in [`s2s/server-v2.md`](s2s/server-v2.md)
  and defined as a route constant, but the router does not dispatch it. Use
  `GET /v1/transparency/checkpoints?limit=1` or the `checkpoint` field of
  `/v2/resolve`.
* `/v1/transparency/catena/anchor` is recognized for metrics labelling only.

---

## 8. Maintaining the spec

The spec is currently maintained by hand against
[`router.rs`](../crates/satspathd/src/router.rs),
[`types.rs`](../crates/satspathd/src/types.rs), and the handlers. When you add or
change a route:

1. Update `docs/openapi.yaml` (path, schemas, `security`, error responses).
2. Update the tables in this page.
3. Re-validate: `npx @redocly/cli lint docs/openapi.yaml`.

### Not yet implemented (needs Rust changes)

The remaining items from issue 104 require code in the daemon and are out of scope
for this documentation-only change:

* Serving Swagger UI and the spec from the daemon (for example `/docs` and
  `/openapi.json`). `tiny_http` has no built-in support; assets would be embedded
  with `include_str!`/`include_bytes!`, and the page CSP
  (`default-src 'self'`) must allow them. Unauthenticated `GET` routes mean the
  docs would be public unless gated.
* A CI test that boots a test daemon and validates real responses against the
  schemas in `openapi.yaml`. The HTTP test harness in `crates/satspathd/src/main.rs`
  already provides `start_test_daemon`.
* Deciding whether to fix the HTTP-200-on-error behavior described in section 4,
  which would change the contract documented here.
