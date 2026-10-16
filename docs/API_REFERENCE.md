# `satspathd` REST API Reference (`/v1` & `/v2`)

This reference documents the HTTP endpoints served by `satspathd` (`crates/satspathd/src/router.rs`). For the machine-readable OpenAPI 3.0 specification, see [`docs/openapi.yaml`](openapi.yaml).

---

## 1. Security, Authentication & Rate Limiting

### Authentication

- **Public Read Endpoints** (`/v2/resolve`, `/v2/namespace`, `/v2/health`, `/v1/health`, `/metrics`, `/v1/diagnostics/rate_limit`, `/.well-known/satspath-authority`, `/health`, `/v1/transparency/*` GET endpoints) do not require authentication.
- **Admin / Mutating Endpoints** (`/v1/resolve`, `/v1/quote`, `/v1/preview`, `/v1/profile`, `/v1/profile/rotate-key`, `/v1/transparency/anchors`) require a Bearer token matching `SATSPATH_API_TOKEN`:

  ```http
  Authorization: Bearer <SATSPATH_API_TOKEN>
  ```

- **Public POST Endpoints**: `/v1/dns/resolve` and `/v2/resolve` require no Bearer token. `/v1/profile/recover` also requires no Bearer token; authorization comes from the committed guardian policy and signed recovery proof.
- **Control Status**: `GET /v1/control` is public.

### Rate Limiting & Payload Guards

- **Per-IP Token Bucket:** Default burst capacity of `60` requests and refill rate of `10.0` requests/sec per IP (`crates/satspathd/src/rate_limit.rs`).
- **Response Headers:**
  - `X-Request-ID`: Correlation UUID for structured logs.
  - `Retry-After`: Seconds to wait before retrying when `HTTP 429 Too Many Requests` is returned.
- **Payload Cap:** Request bodies exceeding `65,536` bytes (`64 KB`) are rejected with `HTTP 413 Payload Too Large`.

---

## 2. S2S v2 Authoritative Endpoints

| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/.well-known/satspath-authority` | Public | Returns the signed `NamespaceDescriptor` for domain authority discovery. |
| `GET` | `/v2/namespace` | Public | Alias for `/.well-known/satspath-authority`. |
| `GET` | `/v2/resolve?identifier=<alias>` | Public | Returns a `ResolutionEnvelope` containing the signed profile, name events, RFC 6962 inclusion proof, optional `StateMapProof`, and signed `TransparencyCheckpoint`. Currently `consistency_proof` is null and `witness_cosignatures` is empty. |
| `POST` | `/v2/resolve` | Public | Resolves `{"identifier":"alice@example.com"}` to the same `ResolutionEnvelope`. Optional `pinned_tree_size` and `include_history` fields are currently ignored by the handler. |
| `GET` | `/v2/health` | Public | Deep dependency health check (`sqlite`, `fee_api`, `transparency_log`). |

---

## 3. Core Discovery, Quote & Transparency Endpoints (`/v1`)

| Method | Path | Auth | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/health`, `/v1/health` | Public | Deep health status (`200 OK` or `503 Service Unavailable`). |
| `GET` | `/metrics` | Public | Prometheus metrics exposition (`text/plain; version=0.0.4`). |
| `GET` | `/v1/diagnostics/rate_limit` | Public | Returns `RateLimiterStats` (`tracked_ips`, `total_allowed`, `total_blocked`). |
| `POST` | `/v1/resolve` | Bearer | Resolves an `{"alias": "alice@example.com"}` through the mandatory transparency + ownership verifier. |
| `POST` | `/v1/quote` | Bearer | Resolves recipient, verifies transparency & method ownership, and returns a `QuoteResponse` (`{"recipient": "alice@example.com", "amount_sats": 21000}`). |
| `POST` | `/v1/preview` | Bearer | Mainnet-safe route and handoff preview without moving funds. |
| `POST` | `/v1/dns/resolve` | Public | Resolves a BIP-353 DNS name (`₿user@domain`) under `DnssecPolicy::Strict`. |
| `GET` | `/v1/transparency/status` | Public | Returns `TransparencyStatus` (`log_size`, `log_root`, `map_root`, `consistency_status`). |
| `GET` | `/v1/transparency/checkpoints` | Public | Paginated list of signed operator checkpoints (`?offset=0&limit=50`). |
| `GET` | `/v1/transparency/events` | Public | Paginated list of append-only `NameEvent` entries. |
| `GET` | `/v1/transparency/inclusion/:hash` | Public | Returns the RFC 6962 `MerkleInclusionProof` for an event hash. |
| `GET` | `/v1/transparency/consistency?from=M&to=N` | Public | Returns compact RFC 6962 `MerkleConsistencyProof` between tree sizes `M` and `N`. |
| `GET` | `/v1/transparency/catena/chain` | Public | Returns the `CatenaChainProof` of UTXO-linked Bitcoin `OP_RETURN` anchors. |
| `POST` | `/v1/transparency/anchors` | Bearer | Anchors the latest checkpoint on Bitcoin Core regtest (`SATSPATH_BITCOIN_NETWORK=regtest`). |
| `POST` | `/v1/profile` | Bearer | Updates local profile methods and signs a `PaymentProfile` into the transparency log (alias must already be verified). |
| `POST` | `/v1/profile/rotate-key` | Bearer | Creates a dual-signed `RotateKey` transition locally; no request body. |
| `POST` | `/v1/profile/recover` | Public | Submits an $M$-of-$N$ guardian `RecoverKey` transition event. |

---

`/v1/transparency/catena/anchor` has no dispatched handler; use `POST /v1/transparency/anchors` for anchoring.

## 4. Profile Registration, Rotation & Recovery

### Registration / profile update

`POST /v1/profile` accepts `ProfileUpdateRequest`, not a client-signed profile.
First verify the alias using `/v1/profile/challenge` and `/v1/profile/verify`
(Bearer auth required; the current verifier is a development mock).
The daemon signs with its local identity key and appends a `register` or
`update_profile` event. Optional request fields are `alias`, `lightning_address`,
`onchain_address`, `onchain_pubkey`, `ark_server`, `ark_pubkey`, `remove_methods`
(an array of `lightning`, `onchain`, or `ark`), and `recovery_policy`
(`version: 1`, `threshold`, and distinct compressed guardian `guardians`).
`ark_server` and `ark_pubkey` must be supplied together.

```http
POST /v1/profile HTTP/1.1
Authorization: Bearer <SATSPATH_API_TOKEN>
Content-Type: application/json

{"alias":"alice@example.com","lightning_address":"alice@example.com"}
```

The generated `SignedPaymentProfile` has `profile` and a hex BIP-340 `signature`
(plus an optional `hybrid_signature`). Required profile data includes `alias`,
`identity_pubkey` (compressed secp256k1 hex), `methods`, and `updated_at` (Unix
seconds). The daemon assigns the next `sequence`; optional signed fields include
`expires_at`, `preferences`, `nonce`, `method_verifications`, `rotation`,
`recovery_policy`, `recovery`, and `hybrid_pubkey`, with `pqc_required` and `revoked`
booleans defaulting to false. The signature covers
`SHA256("SatsPathProfileV1" || RFC8785(profile))`; use the core signing helpers to
preserve the exact serialized fields.

### Key rotation

`POST /v1/profile/rotate-key` requires Bearer auth and **no request body**.
The daemon generates a new identity key and signs the resulting profile locally.
The embedded `profile.rotation` contains `version`, `identifier_hash`,
`previous_pubkey`, `new_pubkey`, `previous_event_hash`, `sequence`, `rotated_at`,
`authorization_signature` (old key), and `acceptance_signature` (new key).
Both signatures bind the identifier, keys, previous event, sequence, and timestamp
under their respective `SatsPathKeyRotationAuthorizationV1` and
`SatsPathKeyRotationAcceptanceV1` domains. The old key signs the `rotate_key`
NameEvent. This endpoint does not accept an externally signed rotation payload.

```http
POST /v1/profile/rotate-key HTTP/1.1
Authorization: Bearer <SATSPATH_API_TOKEN>
Content-Length: 0
```

### Guardian key recovery

`POST /v1/profile/recover` accepts `alias`, `proof`, and `signed_profile`.
No Bearer token is required. `proof` must equal `signed_profile.profile.recovery`.
It contains `version: 1`, `identifier_hash`, `previous_pubkey`, `new_pubkey`,
`previous_event_hash`, the next `sequence`, `recovered_at`, `guardian_signatures`
(`guardian_pubkey` and `signature` for each), and `acceptance_signature`.
The committed recovery policy must authorize the guardian threshold, and the
recovered profile must retain a recovery policy and contain no `rotation`.
Guardians sign the recovery fields under `SatsPathKeyRecoveryAuthorizationV1`;
the new key signs acceptance under `SatsPathKeyRecoveryAcceptanceV1` and signs the
new profile. Use the core recovery helpers to construct these messages.

If the new key is absent from the daemon's local keystore, also supply
`event_signature` (the new key's signature over the `recover_key` NameEvent) and
`event_created_at` (Unix seconds within 300 seconds of server time).
`event_created_at` is required whenever `event_signature` is supplied.
The proof's previous event hash and sequence must match the current history.

The following template uses placeholders for public keys, hashes, and signatures;
replace them with values produced by the signing helpers. The identical proof
must appear at both locations.

```http
POST /v1/profile/recover HTTP/1.1
Content-Type: application/json

{
  "alias": "alice@example.com",
  "proof": {
    "version": 1,
    "identifier_hash": "<identifier-hash>",
    "previous_pubkey": "<old-compressed-pubkey>",
    "new_pubkey": "<new-compressed-pubkey>",
    "previous_event_hash": "<latest-event-hash>",
    "sequence": 3,
    "guardian_signatures": [
      {"guardian_pubkey": "<guardian-pubkey>", "signature": "<guardian-signature>"}
    ],
    "acceptance_signature": "<new-key-acceptance-signature>",
    "recovered_at": 1800000000
  },
  "signed_profile": {
    "profile": {
      "alias": "alice@example.com",
      "identity_pubkey": "<new-compressed-pubkey>",
      "methods": [{"type": "Lightning", "label": "Lightning", "lightning_address": "alice@example.com"}],
      "updated_at": 1800000000,
      "sequence": 3,
      "pqc_required": false,
      "revoked": false,
      "recovery_policy": {"version": 1, "threshold": 1, "guardians": ["<guardian-pubkey>"]},
      "recovery": {
        "version": 1,
        "identifier_hash": "<identifier-hash>",
        "previous_pubkey": "<old-compressed-pubkey>",
        "new_pubkey": "<new-compressed-pubkey>",
        "previous_event_hash": "<latest-event-hash>",
        "sequence": 3,
        "guardian_signatures": [
          {"guardian_pubkey": "<guardian-pubkey>", "signature": "<guardian-signature>"}
        ],
        "acceptance_signature": "<new-key-acceptance-signature>",
        "recovered_at": 1800000000
      }
    },
    "signature": "<new-key-profile-signature>"
  },
  "event_created_at": 1800000000,
  "event_signature": "<new-key-name-event-signature>"
}
```

---

## 5. Standard Error Codes

| HTTP Status | Meaning | Common Cause |
| :--- | :--- | :--- |
| `400 Bad Request` | Malformed request or validation failure | Invalid signature, untrusted `Host` header, or failed proof verification. |
| `401 Unauthorized` | Missing or invalid Bearer token | Mutating `/v1/*` call without valid `Authorization: Bearer <token>`. |
| `404 Not Found` | Resource or identifier not found | Unknown route or unregistered identifier. |
| `413 Payload Too Large` | Request body exceeds `64 KB` | Oversized JSON body blocked by `rate_limit.rs`. |
| `429 Too Many Requests` | IP token bucket exhausted | Client exceeded burst/refill limits; inspect `Retry-After` header. |
| `503 Service Unavailable` | Subsystem unhealthy | SQLite store unwritable or transparency log corrupted. |
