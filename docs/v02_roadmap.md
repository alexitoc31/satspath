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
* **BIP-353 DNS Resolution (IMPLEMENTED):** Embedded local DNSSEC cryptographic validation engine (`HickoryDnssecTxtResolver` in `crates/satspath-core/src/bip353.rs`) verifying `DNSKEY`/`RRSIG`/`DS` chains anchored at ICANN root KSKs (`38696`, `20326`, `19036`) under `DnssecPolicy::Strict`, plus persistent `sp-profile` continuity tracking.
* **BOLT12 Offers & Blinded Paths (IMPLEMENTED):** Checksumless Bech32 (`NoChecksum`) decoding with `+` continuation, all-TLV Merkle root hashing (`LnLeaf`, `LnNonce` + `all-tlvs`, `LnBranch`), BOLT #4 wire-format blinded paths, and `OnionMessageTransport` `invoice_request` flow (`crates/satspath-router/src/bolt12.rs`).
* **Silent Payments BIP-352 (EXPERIMENTAL):** Public-key address encoding, input validation, NUMS exclusion, and output verification checked against public projections of all 28 official BIP-352 test vector groups (`crates/satspath-router/src/silent_payments.rs`); host wallets retain private keys and ECDH.
* **Ark Payment Routing (PREVIEW):** Receive pointer parsing, ownership proofs, live `arkd` `/v1/info` client (`LiveArkAspClient`), VTXO tree DAG verification (`verify_ark_vtxo_dag`), and Boarding/Forfeit/OOR handoff structs (`crates/satspath-router/src/ark.rs`, `ark_routes.rs`).
* **Standardized Wallet Handoff & Bridges (IMPLEMENTED):** Canonical `PaymentIntent` envelope (`crates/satspath-core/src/intent.rs`) and non-custodial `WalletExecutor` bridges (`BdkWalletBridge`, `LdkNodeBridge`, `BoltzSwapBridge` in `crates/satspath-core/src/bridges.rs`).
* **Submarine / Reverse Swaps (EXPERIMENTAL):** Boltz Exchange v2 client, encrypted store (AES-256-GCM), and claim/refund tx builders for testnet/regtest only (`crates/satspath-swaps`).
* **Post-Quantum Cryptography (RESEARCH):** Feature-gated hybrid signature and KEM research module (`secp256k1` + ML-DSA-65 / X25519 + ML-KEM-768) in `crates/satspath-pqc`.

---

## 2. Completed vs Pending v0.2 Milestones

### Completed in Recent Releases

- [x] **Authenticated Current-State Map (`SparseMerkleTree`):** 256-bit Sparse Merkle Tree inclusion/non-inclusion proofs bound to `TransparencyCheckpoint.map_root`.
- [x] **Catena-Style Bitcoin On-Chain Anchoring:** UTXO-chained `OP_RETURN` commitments (`SatsPathCatenaAnchorV1`) with equivocation detection and bounded chain verification.
- [x] **Checkpoint Gossip Protocol:** Nostr/P2P gossip observation comparison (`GOSSIP_KIND = 3978`), standalone `satspath-gossip` monitor, and `SplitViewEvidence` generation.
- [x] **Modular `satspathd` Refactor, Rate Limiting & Telemetry:** Split daemon into `handlers/`, `rate_limit.rs`, `server.rs`, and `telemetry/` with Prometheus `/metrics` and deep health checks.
- [x] **Protocol Parser & Differential Fuzzing Suite (#172):** `cargo-fuzz` targets and proptest suites for profiles, BIP-321 URIs, BOLT12 TLVs, RFC 8785 canonical JSON, and Merkle proofs (`.github/workflows/fuzz.yml`).
- [x] **Embedded Cryptographic DNSSEC Validator (#152):** In-process RFC 4034/4035 `DNSKEY`/`RRSIG`/`DS` chain verification (`HickoryDnssecTxtResolver`) anchored to the ICANN root KSKs in `satspath-core`.
- [x] **Standards-Compliant BOLT12 & CLN/LDK Interoperability (#153):** Checksumless Bech32 decoding, all-TLV Merkle root signing, BOLT #4 wire-format blinded paths, and Onion Message invoice requests.
- [x] **Official BIP-352 Public Vector Verification (#154):** Public-key address, input eligibility, NUMS exclusion, and output checks validated against public projections of all 28 official BIP-352 test vector groups.
- [x] **Live Ark ASP Connector & Settlement Handoffs (#155):** `LiveArkAspClient` (`/v1/info`), VTXO tree DAG verification (`verify_ark_vtxo_dag`), and Boarding/Forfeit/OOR handoff structs.
- [x] **Standardized Non-Custodial `WalletExecutor` Bridges & `PaymentIntent` (#156, #173):** Canonical `PaymentIntent` handoff envelope and reference `BdkWalletBridge`, `LdkNodeBridge`, and `BoltzSwapBridge` adapters.

### Active / Pending Release Gates

- [ ] **External Third-Party Cryptographic Audit:** Independent review per [`docs/audit/EXTERNAL_CRYPTO_REVIEW_SPEC.md`](audit/EXTERNAL_CRYPTO_REVIEW_SPEC.md).
- [ ] **Decentralized Multi-Operator Witness Federation:** Production deployment of independent, geographically distributed witness nodes and gossip monitors.
- [ ] **Live End-to-End Mainnet Wallet Interoperability:** Live end-to-end validation with external BOLT12, BIP-352 Silent Payment, and Ark wallets before removing experimental handoff gates in `satspathd`.

---

## 3. Architectural Boundary Reminder

SatsPath remains firmly committed to a **non-custodial, wallet-agnostic architecture**. SatsPath never stores seed phrases, never requests private spending keys (`xprv`/`tprv`), and never takes custody of user funds. Payment execution and transaction signing remain sovereign responsibilities of the host wallet.
