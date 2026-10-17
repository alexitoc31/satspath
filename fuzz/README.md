# Fuzzing

## BIP321 URI length boundary

```sh
cargo +nightly fuzz run fuzz_bip321 fuzz/corpus/fuzz_bip321 -- -max_len=65537
```

The tracked `seed-uri-65536` and `seed-uri-65537` inputs are ASCII
`bitcoin:?message=` URIs padded with `x` to exactly 65,536 and 65,537 bytes,
without trailing newlines. They exercise acceptance at the URI length limit
and rejection one byte above it. CI sets `-max_len=65537` to retain both seeds
and allow mutations across the boundary.

## BOLT12

Run the BOLT12 target with its tracked corpus from the repository root:

```sh
cargo +nightly fuzz run fuzz_bolt12 fuzz/corpus/fuzz_bolt12
rustup component add llvm-tools-preview --toolchain nightly
cargo +nightly fuzz coverage --target-dir fuzz/target/coverage fuzz_bolt12 fuzz/corpus/fuzz_bolt12
```

The `seed-*` files use the prototype parser's checksummed Bech32m encoding
(the same encoding as the router's unit tests), rather than interoperable BOLT12
wire vectors. They contain synthetic TLV fields:

- `seed-offer-node`: node destination, no amount or expiry, no blinded path.
- `seed-offer-blinded`: one blinded hop, amount 100,000 msats, expiry
  1,600,000,000, description, currency, issuer, quantity and a dummy signature.
  This reaches the parsed-offer operations with a path, an expired offer and an
  amount above the target's 50,000 msat probe.
- `seed-invoice-request`: offer ID, amount, quantity, payer ID, note and dummy signature.
- `seed-invoice`: creation time, relative expiry, payment hash, amount, node ID,
  fallback text and dummy signature.

Keep these seeds tracked; generated corpus entries remain ignored. CI replays
this corpus for source coverage and uploads the merged profile and instrumented
binary in `fuzz-coverage-fuzz_bolt12`, suitable for inspection with the matching
Rust toolchain's `llvm-cov`.

## Security boundaries (#172)

The nightly and PR matrix also exercises `fuzz_nostr_event`, `fuzz_merkle_proof`,
`fuzz_capability_handoff` and `fuzz_schnorr_profile`. The Nostr target uses the
same event parser as the live relay resolver, and signs a real test profile for
positive coverage. The Merkle target validates a constructed proof and rejects
a modified root. Schnorr mutations must never verify; capability parsing must
not bypass the handoff validator. Tracked seeds in `fuzz/corpus/<target>/` are
replayed in CI. For a local bounded reproduction, run:

```sh
cargo +nightly fuzz run fuzz_nostr_event fuzz/corpus/fuzz_nostr_event -- -max_total_time=60
```

`PaymentIntent` and the wallet dispatcher belong to #173/#156 and need their
own fuzz targets after those branches merge; this PR does not claim the host
wallet or Nostr transport is an authenticated payment implementation.
