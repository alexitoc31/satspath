#!/usr/bin/env bash
set -euo pipefail

# SatsPath Cryptographic & Vulnerability Audit Script
# Validates cryptographic primitives, anti-patterns, stubs, and security tests.

WORKSPACE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
cd "$WORKSPACE_ROOT"

echo "=== [1/4] Scanning for Cryptographic Stubs & Insecure Anti-Patterns ==="

ERRORS_FOUND=0
WARNINGS_FOUND=0

# 1. Check for dummy signatures/keys in production crates (excluding test fixtures)
echo "Checking for dummy keys/signatures in production crates..."
DUMMY_MATCHES=$(grep -rnE '(dummy_pubkey|dummy_sig|dummy_hash)' crates/*/src/ || true)
if [ -n "$DUMMY_MATCHES" ]; then
    echo "⚠️  STUBS FOUND:"
    echo "$DUMMY_MATCHES"
    WARNINGS_FOUND=$((WARNINGS_FOUND + 1))
else
    echo "✅ No dummy keys or signatures found in crates/*/src/"
fi

# 2. Check for private material leakage in log macros
echo "Checking for private key leakage in tracing/log calls..."
LEAK_MATCHES=$(grep -rnE '(info!|warn!|error!|debug!|trace!).*(xprv|mnemonic|spending_key|macaroon|seed)' crates/*/src/ || true)
if [ -n "$LEAK_MATCHES" ]; then
    echo "❌ POTENTIAL SECRET LEAK IN LOGS:"
    echo "$LEAK_MATCHES"
    ERRORS_FOUND=$((ERRORS_FOUND + 1))
else
    echo "✅ No private material patterns detected in logging statements"
fi

# 3. Check for execution gate status (Issue #10)
echo "Checking swap execution gate status..."
GATE_MATCHES=$(grep -rn "SwapKind::Submarine | SwapKind::Reverse | SwapKind::Chain => false" crates/ || true)
if [ -n "$GATE_MATCHES" ]; then
    echo "ℹ️  Execution gate is CLOSED (Preview mode active - Issue #10):"
    echo "$GATE_MATCHES"
fi

echo "=== [2/4] Running Security & Cryptographic Simulation Test Suites ==="
cargo test --workspace --test advanced_security_simulations
cargo test --workspace --test attack_simulations
cargo test --workspace --test adversarial_security
cargo test --workspace --test extreme_security_simulations
cargo test --workspace --test state_map_non_inclusion

echo "=== [3/4] Running Key Transparency & DNSSEC Invariant Tests ==="
cargo test --workspace --test transparency
cargo test --workspace --test transparency_blockers
cargo test --workspace --test regtest_anchor

echo "=== [4/4] Verifying Clippy & Compiler Security Invariants ==="
cargo clippy --workspace --all-targets -- -D warnings

echo ""
echo "=== AUDIT SUMMARY ==="
echo "Errors: $ERRORS_FOUND"
echo "Warnings (Known stubs / open issues): $WARNINGS_FOUND"

if [ "$ERRORS_FOUND" -gt 0 ]; then
    echo "❌ Crypto audit FAILED with critical issues."
    exit 1
else
    echo "✅ Cryptographic audit passed all security invariant tests."
    exit 0
fi
