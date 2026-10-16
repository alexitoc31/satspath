# SatsPath: Current Architecture & Roadmap v0.2

This document summarizes the verified implementation status of SatsPath on `main` and outlines the remaining engineering milestones for v0.2 production readiness.

---

## 1. Verified Capability Status

The current codebase (`crates/`) implements and tests the following capabilities:

* **Core Protocol Specification & Cryptography (IMPLEMENTED):** Canonical JSON serialization (RFC 8785), domain-separated `secp256k1` Schnorr signatures (BIP-340), monotonic sequence tracking, dual-signed key rotation, and $M$-of-$N$ guardian key recovery (`crates/satspath-core/src/recovery.rs`).
* **Multi-Transport Resolver Chain (IMPLEMENTED):** Local registry, HTTPS `.well-known/satspath-authority` (`v2`), and Nostr (NIP-05 and kind `30078`).
* **S2S v2 Transparency, Sparse Merkle State Map & Catena Anchoring (IMPLEMENTED):**
  * Append-only RFC 6962 Merkle log with compact `O(log n)` v2 consistency proofs (`crates/satspath-core/src/transparency/tree.rs`).
  * 256-bit Sparse Merkle Tree (`SparseMerkleTree` in `crates/satspath-core/src/transparency/state_map.rs`) committed via `map_root` in signed checkpoints for cryptographic inclusion and non-inclusion proofs.
  * Catena-style Bitcoin `OP_RETURN` UTXO anchor chains (`SatsPathCatenaAnchorV1` in `crates/satspath-core/src/transparency/catena.rs`) verified against Bitcoin Core regtest.
  * Checkpoint gossip and split-view equivocation detection (`crates/satspath-core/src/transparency/gossip.rs`).
* **Modular Authoritative Daemon & Observability (IMPLEMENTED):**
  * Refactored `satspathd` architecture (`crates/satspathd/src/handlers/`, `router.rs`, `server.rs`, `rate_limit.rs`, `telemetry/`).
  * Per-IP token-bucket rate limiting (`HTTP 429` + `Retry-After`) and `64 KB` payload caps (`HTTP 413`).
  * Prometheus metrics (`/metrics`), structured JSON/pretty request tracing (`X-Request-ID`), and deep dependency health probes (`/health`, `/v1/health`, `/v2/health`).
* **Witness Quorum Cosigning (IMPLEMENTED):** Standalone witness node daemon (`crates/satspath-witness`) performing $K$-of-$N$ Schnorr cosigning, consistency proof verification, and local rollback/equivocation detection.
* **Multi-Source Fee Estimation (IMPLEMENTED):** Concurrent queries to Bitcoin Core RPC, Esplora, and Mempool.space with median consensus filtering and decaying cache fallback (`crates/satspath-router/src/fees.rs`).
* **BIP-353 DNS Resolution (PREVIEW):** Record parsing and strict DNSSEC policy enforcement (`DnssecPolicy::Strict`) are implemented, failing closed whenever cryptographic DNSSEC validation is unavailable.
* **BOLT12 Handling (EXPERIMENTAL / PARTIAL):** TLV, offer-handling, and blinded-path primitives exist (`crates/satspath-router/src/bolt12.rs`).
* **Silent Payments BIP-352 (EXPERIMENTAL):** BIP-352 ECDH shared-secret and output derivation primitives (`crates/satspath-router/src/silent_payments.rs`).
* **Ark Payment Routing (PREVIEW):** Receive pointer parsing, ownership proofs, and route scoring (`crates/satspath-router/src/ark.rs`, `ark_routes.rs`).
* **Submarine / Reverse Swaps (EXPERIMENTAL):** Boltz Exchange v2 client, encrypted store (AES-256-GCM), and claim/refund tx builders for testnet/regtest only (`crates/satspath-swaps`).
* **Post-Quantum Cryptography (RESEARCH):** Feature-gated hybrid signature and KEM research module (`secp256k1` + ML-DSA-65 / X25519 + ML-KEM-768) in `crates/satspath-pqc`.

---

## 2. Completed vs Pending v0.2 Milestones

### Completed in Recent Releases

- [x] **Authenticated Current-State Map (`SparseMerkleTree`):** 256-bit Sparse Merkle Tree inclusion/non-inclusion proofs bound to `TransparencyCheckpoint.map_root`.
- [x] **Catena-Style Bitcoin On-Chain Anchoring:** UTXO-chained `OP_RETURN` commitments (`SatsPathCatenaAnchorV1`) with equivocation detection and bounded chain verification.
- [x] **Checkpoint Gossip Protocol:** Nostr/P2P gossip observation comparison (`GOSSIP_KIND = 3978`) and `SplitViewEvidence` generation.
- [x] **Modular `satspathd` Refactor, Rate Limiting & Telemetry:** Split daemon into `handlers/`, `rate_limit.rs`, `server.rs`, and `telemetry/` with Prometheus `/metrics` and deep health checks.
- [x] **Protocol Parser Fuzzing Suite:** `cargo-fuzz` targets for profiles, BIP-321 URIs, BOLT12 TLVs, and Merkle proofs (`.github/workflows/fuzz.yml`).

### Active / Pending v0.2 Targets

- [ ] **Embedded Cryptographic DNSSEC Validator (#152):** Perform in-process RFC 4034/4035 `DNSKEY`/`RRSIG`/`DS` chain verification anchored to the root KSK in `satspath-core`.
- [ ] **Standards-Compliant BOLT12 & CLN/LDK Interoperability (#153):** Full checksumless Bech32 decoding, all-TLV Merkle root signing, and Onion Message invoice requests.
- [ ] **Official BIP-352 Test Vector Conformance (#154):** Validate full input filtering, Taproot parity, NUMS exclusion, and label derivation against the official BIP-352 JSON test vectors.
- [ ] **Live Ark ASP Connector & Settlement Handoffs (#155):** Connect `satspath-router` to live `arkd` `/v1/info` endpoints, VTXO tree DAG verification, and Boarding/Forfeit/OOR handoff payloads.
- [ ] **Standardized Non-Custodial `WalletExecutor` Bridges (#156):** Provide reference BDK, LDK, and Boltz testnet swap execution bridges.
- [ ] **External Third-Party Cryptographic Audit:** Independent review per [`docs/audit/EXTERNAL_CRYPTO_REVIEW_SPEC.md`](audit/EXTERNAL_CRYPTO_REVIEW_SPEC.md).

---

## 3. Architectural Boundary Reminder

SatsPath remains firmly committed to a **non-custodial, wallet-agnostic architecture**. SatsPath never stores seed phrases, never requests private spending keys (`xprv`/`tprv`), and never takes custody of user funds. Payment execution and transaction signing remain sovereign responsibilities of the host wallet.
