# Interim local dashboard authentication

The built-in dashboard requires entering the daemon's local `admin.macaroon`
token once per tab. The password field is cleared immediately. The token stays
only in a JavaScript closure, with no cookies, localStorage or sessionStorage.
Lock, navigation, reload, tab closure and an authenticated 401 discard it.
Obtain the token locally; no server endpoint retrieves it or includes it in HTML.
Never share it: it grants the existing daemon administration permissions.

This deliberately small MVP reuses the existing fail-closed Bearer guard rather
than introducing a second server session credential and cookie lifecycle.
`POST /v1/dashboard/auth` validates a supplied Bearer token and returns only
`{"authenticated":true}`. It neither changes state nor issues a token or cookie.

`dashboard-auth.mjs` centralizes every dashboard request. Only private mutations
carry the token. Requests must stay on the same origin, redirects are rejected,
and ambient browser credentials are omitted. Authentication requires HTTPS,
except for HTTP on `localhost`, `127.0.0.1` or `[::1]` for local development.
No ambient cookie authentication exists, so cross-site form submissions cannot
authenticate mutations; the backend still requires the explicit Bearer header.
An unrelated origin cannot read the in-memory credential. This assumes the
daemon's own page and scripts are trusted; it is not isolation against same-origin
script compromise or a privileged browser extension.

## HTTP Host and reverse proxies

Every route, including public `/v1/control`, validates a single trusted HTTP `Host`
header before routing (with an internal-scrape exception for `GET /metrics` when
the parsed `Host` is `satspathd`). Loopback binds allow `localhost` and loopback IP literals;
specific interface binds allow their IP, and wildcard binds allow IP literals.
Other DNS names must be explicitly configured through `SATSPATH_AUTHORITY_DOMAIN`
or the hostname of `SATSPATH_AUTHORITY_URL`. Missing, duplicate, malformed and
untrusted hosts receive HTTP 400.

For a proxy preserving the public hostname, set for example
`SATSPATH_AUTHORITY_DOMAIN=node.example.com` in the daemon's environment. Native
TLS deployments using DNS names use the same configuration. Neither
`--behind-proxy` nor `X-Forwarded-Host` bypasses this allowlist. CORS and Bearer
authentication remain independent checks.

## Dashboard request audit

| Requests used by the dashboard | Classification |
| --- | --- |
| GET /v1/control | Public |
| GET /v1/transparency/status, /events, /checkpoints, /inclusion/{hash} | Public |
| GET /v1/invites/notifications | Public |
| GET /v1/claim?invite_id=… | Public |
| POST /v1/send, /v1/receive, /v1/claim | Public under existing backend rules |
| POST /v1/transparency/verify/inclusion | Public proof verification |
| POST /v1/profile/challenge, /v1/profile/verify | Authenticated (also requires `--dev-mock-alias-verification` on non-mainnet) |
| PUT /v1/profile | Authenticated |
| POST /v1/broadcast | Authenticated |
| POST /v1/invites/notifications/{id}/read (both notification actions) | Authenticated |
| POST /v1/dashboard/auth (sign-in helper) | Authenticated |

GET /health remains public. The helper also mirrors the existing public mutation
exceptions for /v1/dns/resolve, /v1/profile/recover and /v2/resolve. All other mutations default to
authenticated, including /v1/profile/methods, /v1/profile/rotate-key and
/v1/p2p/resolve, which currently have no dashboard fetch call. Backend rules,
profile verification and P2P trust boundaries are unchanged.

Validation: `node --test crates/satspathd/tests/dashboard-auth.test.mjs` covers
request classification, credential lifetime, origin and redirect restrictions,
and credential-safe failures. Rust HTTP tests exercise the actual guard,
successful authenticated profile challenges, public views and secret-free
responses.
