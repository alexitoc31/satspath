# WASM/native measurement artifact — 2026-10-16

This directory records a new measurement; it does not establish the provenance of
the original figures in [benchmarks.md](../../benchmarks.md). No original raw
samples, measured revision, hardware details, browser build, or correctness-check
results were committed with those figures. Their measurement status is unverified.

## Scope and method

See [results.json](results.json) for the full measured revision, source and fixture
hashes, machine, browser build, compiler/dependency versions, correctness status,
raw samples, and derived medians. Both targets execute the same functions from
`satspath-wasm/src/{crypto,topic}.rs` against [fixture.json](fixture.json), a fixed
two-rail profile. The native runner includes those source modules directly so it
can also call the signing function, which is not re-exported by the Rust library.
This comparison differs from the three-rail typed `satspath-core` Criterion suite.

Each operation has 20 warmup iterations followed by seven timed batches. Batch
sizes are 2,000 canonicalizations, 500 signatures, 500 verifications, or 5,000 topic
derivations. All seven elapsed times are retained. Native uses `Instant` in
nanoseconds; Chromium uses `performance.now()` in milliseconds. Per-operation
latency in microseconds is `elapsed_ns / iterations / 1000` for native and
`elapsed_ms * 1000 / iterations` for WASM. The reported latency is the median of
those seven batch averages. **Ratio = WASM latency divided by native latency.**
For example, `2.0x` means WASM takes twice as long per operation.

The browser measurement includes JS string/array conversion and the WASM boundary;
native passes Rust strings and consumes each result through `black_box`. Neither
measurement includes module loading, fixture loading, key generation, or correctness
assertions. Signing includes OS/browser randomness and uses a public synthetic test
key. Signatures vary between runs. Before timing, both runners check canonical
bytes, sign/verify success, changed-profile and malformed-profile rejection, and
the expected SHA-256 topic digest. These are benchmark sanity checks, not a protocol
audit. Samples come from a shared KVM sandbox without CPU pinning; scheduling,
timer resolution, and V8 tiering can affect them. No samples were discarded.

## Exact commands

Run from the repository root with Rust 1.99.1, clang 15.0.7, and wasm-bindgen-cli
0.2.129 available. The captured run used `mise exec rust@stable --` to select that
Rust toolchain. Root `Cargo.lock` is ignored by this repository; its SHA-256 and
relevant resolved dependency versions are recorded in the result. A future lock
resolution may differ. Release uses Cargo defaults, without extra `RUSTFLAGS`,
`target-cpu`, LTO, or wasm-opt passes.

```bash
mise exec rust@stable -- rustup target add wasm32-unknown-unknown
mise exec rust@stable -- cargo install wasm-bindgen-cli --version 0.2.129 --locked
mkdir -p crates/satspath-wasm/examples
cp docs/benchmark-results/2026-10-16/native.rs crates/satspath-wasm/examples/benchmark_comparison.rs
mise exec rust@stable -- cargo build -p satspath-wasm --example benchmark_comparison --release --locked
mise exec rust@stable -- cargo build -p satspath-wasm --target wasm32-unknown-unknown --release --locked
mise exec rust@stable -- wasm-bindgen target/wasm32-unknown-unknown/release/satspath_wasm.wasm --out-dir crates/satspath-wasm/pkg --target web
# Wait for builds to finish before measuring.
mise exec rust@stable -- cargo run -p satspath-wasm --example benchmark_comparison --release --locked -- docs/benchmark-results/2026-10-16/fixture.json > /tmp/satspath-native-samples.json
python3 -m http.server 8000 --bind 0.0.0.0
```

In a second terminal, the captured browser command was:

```bash
coderabbit-agent-browser open http://localhost:8000/docs/benchmark-results/2026-10-16/browser.html
coderabbit-agent-browser get text '#output' > /tmp/satspath-browser-samples.json
```

The same page can be opened manually in Chromium. Wait for its JSON output before
saving the contents of `#output`. The native/browser JSON is retained verbatim as
objects in `results.json`; the artifact also contains the full browser build from
`navigator.userAgentData.getHighEntropyValues(["fullVersionList"])`. Stop the HTTP server and remove the
copied temporary example after collecting results:

```bash
rm crates/satspath-wasm/examples/benchmark_comparison.rs
```


## Independently recompute the comparison

```bash
python3 - <<'PYTHON'
import json, statistics
with open("docs/benchmark-results/2026-10-16/results.json") as f:
    result = json.load(f)
for name, native in result["native"]["operations"].items():
    wasm = result["wasm"]["operations"][name]
    n = statistics.median(native["elapsed_ns"]) / native["iterations_per_sample"] / 1000
    w = statistics.median(wasm["elapsed_ms"]) * 1000 / wasm["iterations_per_sample"]
    assert result["summary"][name] == {
        "native_median_us": n, "wasm_median_us": w, "wasm_divided_by_native": w / n,
    }
    print(f"{name}: native={n:.2f} us, WASM={w:.2f} us, WASM/native={w/n:.2f}x")
PYTHON
```
