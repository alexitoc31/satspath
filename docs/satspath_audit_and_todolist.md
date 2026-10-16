# SatsPath Codebase Audit & Implementation Status

**Repository:** `satspath/satspath`  
**Architecture:** Non-Custodial Payment Capability Discovery, Cryptographic Identity Verification & Multi-Rail Routing

---

## 1. Repository Consolidation Summary

All core Rust crates (`satspath-core`, `satspath-router`, `satspath-cli`, `satspathd`, `satspath-witness`, `satspath-wasm`, `satspath-swaps`, `satspath-pqc`) and TypeScript packages are unified on `main`.

---

## 2. Implemented Capabilities (Verified on `main`)

### Protocol Core — [`satspath-core`](../crates/satspath-core/src)

| Feature | File(s) | Status |
| :--- | :--- | :--- |
| `PaymentProfile` (Lightning, On-chain, Ark, BOLT12, Silent Payments) | [`profile.rs`](../crates/satspath-core/src/profile.rs) | Complete |
| `SignedPaymentProfile` with BIP-340 Schnorr signatures | [`profile.rs`](../crates/satspath-core/src/profile.rs) | Complete |
| Deterministic `secp256k1` key derivation (`m/9737'/0'`) | [`crypto.rs`](../crates/satspath-core/src/crypto.rs) | Complete |
| Domain-separated signing (`SatsPathProfileV1`) & RFC 8785 Canonical JSON | [`crypto.rs`](../crates/satspath-core/src/crypto.rs) | Complete |
| Dual-signed key rotation & $M$-of-$N$ guardian key recovery | [`crypto.rs`](../crates/satspath-core/src/crypto.rs), [`recovery.rs`](../crates/satspath-core/src/recovery.rs) | Complete |
| RFC 6962 Merkle tree transparency log & compact `O(log n)` consistency proofs | [`transparency/tree.rs`](../crates/satspath-core/src/transparency/tree.rs), [`transparency/log.rs`](../crates/satspath-core/src/transparency/log.rs) | Complete |
| Authenticated current-state map (256-bit Sparse Merkle Tree inclusion & non-inclusion proofs) | [`transparency/state_map.rs`](../crates/satspath-core/src/transparency/state_map.rs) | Complete |
| Catena-style Bitcoin `OP_RETURN` single-history UTXO anchor chain (`SatsPathCatenaAnchorV1`) | [`transparency/catena.rs`](../crates/satspath-core/src/transparency/catena.rs), [`transparency/anchor.rs`](../crates/satspath-core/src/transparency/anchor.rs) | Complete (Regtest RPC + Offline Verifier) |
| Checkpoint gossip & split-view equivocation evidence | [`transparency/gossip.rs`](../crates/satspath-core/src/transparency/gossip.rs) | Complete |
| SQLite WAL transactional store (`satspath-transparency-v1.sqlite3`) | [`transparency/database.rs`](../crates/satspath-core/src/transparency/database.rs) | Complete |
| Public profile validation & private material rejection (`xprv`, seeds, macaroons) | [`validation.rs`](../crates/satspath-core/src/validation.rs) | Complete |
| SSRF defensive filtering, DNS IP pinning & bounded response streams | [`ssrf.rs`](../crates/satspath-core/src/ssrf.rs) | Complete |
| Cryptographic payment-method ownership proofs | [`ownership.rs`](../crates/satspath-core/src/ownership.rs) | Complete |

### Resolver Chain — [`satspath-core/src/resolvers`](../crates/satspath-core/src/resolvers)

| Resolver | File | Status |
| :--- | :--- | :--- |
| `ChainResolver` (compositor with anti-substitution verification) | [`resolver.rs`](../crates/satspath-core/src/resolver.rs) | Complete |
| `HttpResolver` (HTTPS `.well-known/satspath-authority` + S2S v2) | [`http.rs`](../crates/satspath-core/src/resolvers/http.rs) | Complete (SSRF-hardened) |
| `Bip353Resolver` (BIP-353 DNS TXT with `DnssecPolicy::Strict` fail-closed default) | [`bip353.rs`](../crates/satspath-core/src/resolvers/bip353.rs) | Preview — authenticated signed-profile retrieval pending |
| `NostrResolver` (NIP-05 + kind `30078` author binding) | [`nostr.rs`](../crates/satspath-core/src/resolvers/nostr.rs) | Complete |
| `PearResolver` (Optional Hyperswarm P2P sidecar bridge) | [`pear.rs`](../crates/satspath-core/src/resolvers/pear.rs) | Optional / Legacy |

### Router Engine — [`satspath-router`](../crates/satspath-router/src)

| Feature | File | Status |
| :--- | :--- | :--- |
| `select_route()` & `select_route_with_fees()` (Lightning → On-chain → Ark) | [`router.rs`](../crates/satspath-router/src/router.rs) | Complete |
| Multi-source fee estimation (Bitcoin Core RPC, Esplora, Mempool.space median consensus) | [`fees.rs`](../crates/satspath-router/src/fees.rs) | Complete |
| Multi-factor scoring engine (`score_routes`) | [`scoring.rs`](../crates/satspath-router/src/scoring.rs) | Complete |
| LNURL-pay 2-step metadata & BOLT11 verification | [`lightning.rs`](../crates/satspath-router/src/lightning.rs) | Complete |
| Stable `QuoteResponse` UX JSON contract | [`quote_response.rs`](../crates/satspath-router/src/quote_response.rs) | Complete |
| BOLT12 offer/invoice-request/blinded-path primitives | [`bolt12.rs`](../crates/satspath-router/src/bolt12.rs) | Experimental |
| Silent Payments (BIP-352) ECDH output derivation | [`silent_payments.rs`](../crates/satspath-router/src/silent_payments.rs) | Experimental |

### Server Daemon (`satspathd`) & Witness (`satspath-witness`)

| Feature | File(s) | Status |
| :--- | :--- | :--- |
| Modular HTTP server, TLS audit & route dispatcher | [`server.rs`](../crates/satspathd/src/server.rs), [`router.rs`](../crates/satspathd/src/router.rs), [`handlers/`](../crates/satspathd/src/handlers) | Complete |
| S2S v2 Authoritative API (`/v2/resolve`, `/v2/namespace`, `/.well-known/satspath-authority`) | [`v2_api.rs`](../crates/satspathd/src/v2_api.rs), [`handlers/resolve.rs`](../crates/satspathd/src/handlers/resolve.rs) | Complete |
| Per-IP token-bucket rate limiter & 64 KB body cap | [`rate_limit.rs`](../crates/satspathd/src/rate_limit.rs) | Complete |
| Prometheus metrics (`/metrics`), structured tracing & deep health checks (`/health`, `/v1/health`, `/v2/health`) | [`telemetry/`](../crates/satspathd/src/telemetry) | Complete |
| Standalone $K$-of-$N$ witness cosigning daemon | [`crates/satspath-witness`](../crates/satspath-witness/src) | Complete |
