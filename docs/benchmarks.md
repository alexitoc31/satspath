# SatsPath Performance Benchmarks

This document records reference performance measurements for SatsPath's cryptographic primitives, canonical serialization, Key Transparency Merkle / Sparse Merkle Tree proofs, multi-rail route selection, and WebAssembly (`satspath-wasm`) vs native execution.

## Running Benchmarks

### Native Rust (`criterion`)

```bash
# Core cryptography, RFC 8785 canonical JSON, Merkle & Sparse Merkle Tree proofs
cargo bench -p satspath-core --bench core_benches

# Multi-rail route selection and route scoring
cargo bench -p satspath-router --bench router_benches
```

### Browser WebAssembly (`satspath-wasm`)

```bash
cd crates/satspath-wasm
wasm-pack build --target web --release
# Serve crates/satspath-wasm and open benches/browser_bench.html in Chromium/Firefox
```

---

## Reference Results (x86_64 Linux, Release Profile)

### 1. Cryptography & Canonical Serialization (`satspath-core`)

| Benchmark | Median Latency | Throughput / Notes |
| :--- | :--- | :--- |
| `canonical_profile_bytes` | **~4.8 µs** | RFC 8785 deterministic JSON serialization (3-rail profile) |
| `sign_profile_schnorr` | **~38.5 µs** | Canonical JSON + SHA-256 (`SatsPathProfileV1`) + BIP-340 Schnorr sign |
| `verify_signed_profile_schnorr` | **~44.2 µs** | Canonical JSON + SHA-256 (`SatsPathProfileV1`) + BIP-340 Schnorr verify |

### 2. Transparency Log & Merkle Operations (`satspath-core`)

| Benchmark | Median Latency | Tree / Proof Parameters |
| :--- | :--- | :--- |
| `merkle_root_256_leaves` | **~68.0 µs** | RFC 6962 SHA-256 Merkle root over 256 leaves |
| `merkle_inclusion_proof_gen_256` | **~69.5 µs** | Audit path generation (`log2(256) = 8` sibling hashes) |
| `merkle_inclusion_proof_verify_256` | **~2.1 µs** | 8 SHA-256 interior node hashes + root comparison |
| `merkle_consistency_proof_gen_128_to_256` | **~68.8 µs** | Append-only consistency proof (`128 -> 256` leaves) |
| `merkle_consistency_proof_verify_128_to_256` | **~1.4 µs** | Subtree root verification |
| `sparse_merkle_tree_insert_and_prove` | **~195 µs** | 256-level Sparse Merkle Tree leaf insert + inclusion/non-inclusion proof |

### 3. Multi-Rail Route Selection (`satspath-router`)

| Benchmark | Median Latency | Selected Rail & Scenario |
| :--- | :--- | :--- |
| `select_route_lightning_under_threshold` | **~180 ns** | Amount `< 100,000` sats selects Lightning immediately |
| `select_route_onchain_low_fee` | **~260 ns** | Amount `250,000` sats at `4 sat/vB` selects On-Chain |
| `select_route_ark_fallback_high_fee` | **~275 ns** | Amount `250,000` sats at `45 sat/vB` falls back to Ark VTXO |
| `score_routes_multi_rail` | **~640 ns** | Evaluates and ranks Lightning, On-Chain, and Ark candidates |

### 4. WASM (`wasm32-unknown-unknown`) vs Native

**Ratio is WASM latency divided by native latency**, using the same units.
For example, `2.0x` means WASM takes twice as long per operation.

#### Original comparison (unverified)

The original comparison figures are retained below. Their measured revision,
hardware, browser build, raw samples, and correctness-check status were not
recorded. The `lowmemory` configuration and V8 tier labels were reported with
these figures but cannot be confirmed from measurement evidence. These values
should not be treated as verified measurements.

| Operation | Native (`x86_64`) | Browser WASM (V8 Liftoff/TurboFan) | Ratio (WASM / Native) |
| :--- | :--- | :--- | :--- |
| `canonical_profile_json` | `4.8 µs` | `~9.5 µs` | `~2.0x` |
| `sign_profile` (Schnorr) | `38.5 µs` | `~145 µs` | `~3.8x` (`secp256k1` `lowmemory` table trade-off) |
| `verify_signed_profile` (Schnorr) | `44.2 µs` | `~160 µs` | `~3.6x` |
| `topic_for_alias` (SHA-256) | `0.35 µs` | `~0.90 µs` | `~2.6x` |

#### Auditable measurement (2026-10-16)

The [results artifact](benchmark-results/2026-10-16/README.md) contains the exact
commands, shared fixture, native and browser runners, and calculation method.
Its [raw results](benchmark-results/2026-10-16/results.json) identify measured
revision `80d9c20dbea6a36bee2ade168598400414709334`, source hashes, an Intel Xeon
2.90 GHz / 4-vCPU KVM sandbox running Amazon Linux 2023, Chromium
`140.0.7339.16`, and Rust `1.99.1`. Both targets passed correctness checks before
timing. All seven raw batches per operation are retained.

This run compares the same `satspath-wasm` Rust functions on native and browser
targets with a two-rail JSON fixture; the browser timings include the JS/WASM
boundary. It uses Cargo release defaults without `lowmemory` or wasm-opt and is
a separate measurement from the original table and the typed, three-rail
`satspath-core` benchmarks above. Latencies below are medians of batch averages.

| Operation | Native (`x86_64`) | Browser WASM | Ratio (WASM / Native) |
| :--- | :--- | :--- | :--- |
| `canonical_profile_json` | `23.79 µs` | `34.60 µs` | `1.45x` |
| `sign_profile_json` | `227.20 µs` | `540.60 µs` | `2.38x` |
| `verify_signed_profile` | `84.62 µs` | `611.40 µs` | `7.23x` |
| `topic_for_alias` | `0.16 µs` | `1.62 µs` | `9.90x` |
