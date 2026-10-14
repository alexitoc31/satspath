# Fuzzing

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
