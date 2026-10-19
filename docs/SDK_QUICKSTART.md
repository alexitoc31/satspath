# SatsPath SDK Quickstart Guide

Quickstart guide for sovereign Bitcoin wallet developers, PWAs, and native Rust/TypeScript applications integrating `@satspath/wasm` and `satspath-router`.

---

## 1. Installation

### Web / PWA / React Native (`pnpm`)

```bash
pnpm add @satspath/wasm bip39 react-qr-code
# or modular TypeScript packages:
pnpm add @satspath/resolvers @satspath/router
```

> **Building `@satspath/wasm` locally from source:**
>
> ```bash
> cd crates/satspath-wasm
> wasm-pack build --target web --release --out-dir ../../pkg/satspath-wasm
> ```

### Native Rust (`Cargo.toml`)

```toml
[dependencies]
satspath-core = { path = "crates/satspath-core" }
satspath-router = { path = "crates/satspath-router" }
```

---

## 2. Non-Custodial 3-Step Flow

```text
┌─────────────────────────┐     ┌─────────────────────────┐     ┌─────────────────────────┐
│ 1. DERIVE IDENTITY      │ ──> │ 2. RESOLVE & QUOTE      │ ──> │ 3. WALLET HANDOFF       │
│ Seed (in host wallet)   │     │ "user@domain" + sats    │     │ BIP-21 / BOLT11 / Ark   │
│ m/9737'/0' (identity)   │     │ Signature + Route Score │     │ Host wallet signs & pays│
└─────────────────────────┘     └─────────────────────────┘     └─────────────────────────┘
```

---

## 3. Browser / TypeScript Integration (`@satspath/wasm`)

### Step 1: Initialize WASM & Derive Identity Keypair

Deterministically derive an identity keypair inside the trusted wallet boundary without exposing Bitcoin spending keys (`xprv`/`tprv`):

```typescript
import init, {
  derive_identity_keypair_from_seed,
  sign_profile_json,
  verify_signed_profile,
} from "@satspath/wasm";
import * as bip39 from "bip39";

await init();

// TEST ONLY: This public BIP-39 test vector is not a real identity seed.
// Never register an identity derived from this phrase.
// Production: use the host wallet seed source inside its trusted boundary.
const mnemonic =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const seed = bip39.mnemonicToSeedSync(mnemonic);

const identity = derive_identity_keypair_from_seed(seed, 0);
if (!identity) {
  throw new Error("Failed to derive SatsPath identity keypair");
}

console.log("SatsPath Identity Pubkey:", identity.pubkey_hex);
```

### Step 2: Resolve, Verify & Quote (`quote`)

```typescript
import { quote, verify_signed_profile } from "@satspath/wasm";

export async function resolveAndQuote(recipientAlias: string, amountSats: bigint) {
  const quoteResult = await quote(recipientAlias, amountSats);

  switch (quoteResult.status) {
    case "ok": {
      if (!quoteResult.recipient.profile_signature_verified) {
        throw new Error("Recipient profile signature failed verification");
      }
      console.log("Selected Method:", quoteResult.selected_method.type);
      console.log("Estimated Fee (sats):", quoteResult.fee_sats);
      console.log("Validated Handoff Payload:", quoteResult.qr);
      return quoteResult;
    }
    case "invalid_signature":
      throw new Error(`Invalid profile signature for ${quoteResult.recipient.alias}`);
    case "no_route":
      throw new Error(`No viable payment rail: ${quoteResult.reason}`);
    case "not_registered":
      console.log("Recipient not registered; invite token:", quoteResult.invite.invite_id);
      return null;
  }
}
```

---

## 4. Native Rust Integration (`satspath-router` + `satspath-core`)

Host wallets written in Rust (such as BDK or LDK mobile/desktop wallets) can resolve aliases, verify cryptographic signatures, and consume `QuoteResponse` handoffs directly. This example returns `Some(payload)` for BIP-21 and Ark handoffs; the caller must pass that payload to its wallet flow. `None` means Lightning was paid or an invite was returned:

```rust
use satspath_core::crypto::verify_signed_profile;
use satspath_core::execution::{ExecutionGatePolicy, WalletExecutor};
use satspath_core::resolver::ChainResolver;
use satspath_router::quote_response::{quote_with_resolver, QuoteResponse};

pub async fn prepare_wallet_handoff(
    resolver: &ChainResolver,
    recipient_alias: &str,
    amount_sats: u64,
    wallet: &dyn WalletExecutor,
) -> satspath_core::Result<Option<String>> {
    // 1. Resolve alias, verify Schnorr signature + expiry, and select optimal rail
    let response = quote_with_resolver(resolver, recipient_alias, amount_sats).await;

    match response {
        QuoteResponse::Ok {
            recipient,
            selected_method,
            qr,
            fee_sats,
            ..
        } => {
            assert!(recipient.profile_signature_verified);
            println!(
                "Verified {} ({}) -> {:?} (est. fee: {:?} sats)",
                recipient.alias, recipient.pubkey_fingerprint, selected_method, fee_sats
            );

            // 2. Enforce ExecutionGatePolicy before invoking host wallet signing
            let policy = ExecutionGatePolicy::testnet_default();
            policy.check_execution_safety(wallet.network(), amount_sats, true)?;

            if qr.starts_with("lnbc") || qr.starts_with("lntb") || qr.starts_with("lnbcrt") {
                let _receipt = wallet.pay_bolt11(&qr, Some(amount_sats * 1_000)).await?;
                Ok(None)
            } else if qr.starts_with("bitcoin:") || qr.starts_with("ark:") || qr.starts_with("ark1") {
                // Return BIP-21 / Ark payloads to the caller's host wallet flow.
                Ok(Some(qr))
            } else {
                Err(satspath_core::SatsPathError::ValidationError(
                    "Unsupported payment payload".into(),
                ))
            }
        }
        QuoteResponse::InvalidSignature { recipient } => Err(
            satspath_core::SatsPathError::ValidationError(format!(
                "Invalid signature for {}",
                recipient.alias
            )),
        ),
        QuoteResponse::NoRoute { reason } => {
            Err(satspath_core::SatsPathError::NoRouteFound(reason))
        }
        QuoteResponse::NotRegistered { invite } => {
            println!("Recipient not registered; share invite URL: {}", invite.claim_url);
            Ok(None)
        }
    }
}
```

---

## 5. Main SDK Functions Reference

| Function | Layer | Parameters | Return Type | Description |
| :--- | :--- | :--- | :--- | :--- |
| `derive_identity_keypair_from_seed` | `@satspath/wasm` | `seed: Uint8Array, index: number` | `IdentityKeypair \| undefined` | Derives `secp256k1` identity keypair under `m/9737'/0'`. |
| `quote` | `@satspath/wasm` | `recipient: string, amount_sats: bigint` | `QuoteResponse` | Resolves alias, verifies signature, and selects best rail. |
| `verify_signed_profile` | `@satspath/wasm` | `profile_json: string` | `boolean` | Verifies RFC 8785 canonical JSON + BIP-340 Schnorr signature. |
| `quote_with_resolver` | `satspath-router` | `resolver, recipient, amount_sats` | `QuoteResponse` | Native Rust end-to-end resolution, verification, and routing. |
| `select_route_with_fees` | `satspath-router` | `&RouteRequest, &FeeEstimate` | `Result<RouteQuote>` | Deterministic rail selection (Lightning → On-chain → Ark). |
