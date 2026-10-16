# Mainnet Safety & Architectural Boundaries

> **Safety Notice:** SatsPath is non-custodial software designed for Bitcoin payment discovery, profile verification, and route selection. SatsPath **does not execute mainnet payments**, **does not broadcast transactions**, and **does not sign transactions**. All transaction signing and fund execution are strictly delegated to host wallets.

---

## 1. Architectural Non-Custodial Principle

**SatsPath is an identity and capability discovery layer, NOT a wallet.**

* **Zero Spending Authority:** The `Identity Key` (used to sign profiles) has no access to funds. It cannot sign Bitcoin transactions, open Lightning channels, or authorize Ark transfers.
* **Separation of Concerns:** SatsPath leaves spending keys, seeds (BIP-39), xprv/tprv keys, and node credentials entirely inside the user's sovereign wallet.
* **Why SatsPath Delegates Execution:**
  1. *Preserves self-custody:* Eliminates the risk of SatsPath becoming a custodial honeypot.
  2. *Avoids redundant wallet engineering:* Integrates with existing, battle-tested Bitcoin wallets rather than competing with them.
  3. *Custody Risk vs. Payment Redirection Risk:* Compromising SatsPath does not directly expose wallet spending keys or authorize Bitcoin transactions. However, a compromised discovery or handoff component may attempt payment redirection, which is why authenticated profiles, key continuity, resolver verification, and wallet-side confirmation of destination details remain security-critical.

---

## 2. Mainnet Discovery vs Mainnet Execution Matrix

| Capability | Current Status in SatsPath | Architectural Owner |
| :--- | :--- | :--- |
| **Mainnet Profile Resolution** | **Supported** | SatsPath (Core / Resolvers) |
| **Mainnet Lightning Discovery (LNURL/LN Address)** | **Supported** | SatsPath (Router) |
| **BOLT12 Handling & Blinded Paths** | **Prototype / Experimental (Partial)** (Prototype primitives; standards-conformant string parsing & CLN/LDK interop unverified) | SatsPath (Router) |
| **Mainnet On-Chain Address Discovery (BIP-21)** | **Supported** | SatsPath (Router) |
| **Silent Payments (BIP-352) Primitives** | **Experimental** (Public operations checked against projections of 28 official vector groups; wallet interoperability unverified) | SatsPath (public routing/detection); host wallet (ECDH, private derivation, signing) |
| **Mainnet Ark Receive Pointer Discovery** | **Supported (Preview)** | SatsPath (Router) |
| **Wallet Handoff Generation (URIs, QR codes)** | **Supported** | SatsPath (Router / CLI) |
| **Mainnet Payment Execution by SatsPath** | **Unsupported / Out of Scope** | **Host Wallet Only** |
| **Transaction Signing (PSBT / Schnorr / ECDSA)** | **Unsupported / Out of Scope** | **Host Wallet Only** |
| **Mempool Transaction Broadcast** | **Unsupported / Out of Scope** | **Host Wallet Only** |
| **Post-Quantum Cryptography (ML-DSA / ML-KEM)** | **Experimental (Feature-Gated)** (Optional `pqc` feature flag; not part of production safety claim; classical-only verification is the default production path) | SatsPath (Core / PQC) |
| **Mainnet Swaps Execution** | **Unsupported** | Scaffolding in `satspath-swaps` is testnet/regtest only |

---

## 3. Mainnet Preview Flows

SatsPath operates strictly on **public payment data** to generate wallet handoffs:

1. **Resolve:** Fetches the signed profile for the given identifier.
2. **Verify:** Validates cryptographic signatures, sequence freshness, and expiration.
3. **Route:** Evaluates fees and policies across available receiving methods.
4. **Handoff:** Formats the selected method into a wallet handoff payload (`bitcoin:` URI, BOLT11 invoice, experimental BOLT12 structure, Ark pointer, or QR code), subject to the capability-specific maturity and interoperability limits documented above.
5. **Execution:** The host wallet scans or receives the handoff payload, prompts the user for confirmation, signs with the user's spending key, and broadcasts to the Bitcoin or Lightning network.

Safe CLI preview commands:

```bash
# Preview payment routes on mainnet (touches public data only; returns handoff payload)
satspath preview alice@satspath.dev 21000 --mainnet
satspath preview alice@satspath.dev 21000 --mainnet --json

# Query quote without executing
satspath quote alice@satspath.dev 21000 --mainnet-preview --json
```

---

## 4. BIP-353 DNS Resolution (Mainnet Preview)

BIP-353 resolution is a preview layer: SatsPath resolves and displays DNSSEC-backed payment instructions but never pays, signs, or broadcasts.

* **DNSSEC Policy Enforcement:** In the core `resolve_bip353` / `resolve_bip353_with` preview flow, the default `Strict` policy fails closed and does not trust an unvalidated upstream resolver's AD bit. The default DoH backend does not independently validate the DNSSEC chain; Strict mode therefore requires authenticated DNSSEC results and fails closed otherwise. `DevInsecure` mode is for local testing only, requires `--allow-insecure-dns-for-dev`, and prints a loud warning. `Bip353Resolver::resolve_alias` is a separate profile-resolution path and does not apply `DnssecPolicy`. It now returns `Bip353Unauthenticated` for otherwise valid DNS payment instructions because they do not authenticate a SatsPath profile. Its former locally signed synthetic profiles did not establish authenticated DNSSEC results or alias ownership; the preview flow’s Strict-mode guarantee must not be attributed to this resolver.
* **Ambiguity is Invalid:** More than one `bitcoin:` TXT record at a single name, or an unknown `req-*` parameter, causes resolution to fail closed.
* **Zero Private Material:** No private material may ever appear in a published or resolved DNS payload (`seed`, `xprv`, `mnemonic`, `macaroon`, `cert`, `api_key`, `claim_key`, `refund_key`, `preimage`) — screened on both publish and resolve.
* **Cryptographic Authorization:** DNSSEC cryptographically authorizes the DNS record, while the signed profile (including its `secp256k1` identity-key signature) remains strictly required for profile-based payments. Email inbox access alone never authorizes a payment-instruction change.
* **Consumer Domains:** Consumer email domains (e.g. `gmail.com`) cannot use direct BIP-353 DNS; they fall back to platform verification or the invite flow.

---

## 5. Post-Quantum Cryptography (PQC) Boundaries

* **Experimental Classification:** The `satspath-pqc` crate and post-quantum hybrid verification primitives (ML-DSA-65, ML-KEM-768) are experimental research code and are strictly feature-gated behind the optional `pqc` Cargo feature flag in `satspath-core`.
* **Exclusion from Production Safety Claim:** Production mainnet profile resolution and validation rely exclusively on classical, battle-tested `secp256k1` BIP-340 Schnorr signatures. PQC is not part of the production mainnet safety claim.
* **Fail-Closed Default:** When the `pqc` feature is not enabled (the default for production builds), any profile specifying `pqc_required: true` or supplying `hybrid_pubkey` or `hybrid_signature` (even when `pqc_required` is false) is rejected (`Ok(false)`). In builds with the `pqc` feature disabled, this guarantees that verifiers never accept unverified post-quantum assertions, unverified hybrid extensions, or false security guarantees.

## BIP-352 wallet boundary

The router accepts public prevout data, scan/spend public keys, labeled spend
public keys, and ECDH curve points computed by the host wallet. The host wallet
must derive each ECDH point from the exact transaction inputs and recipient scan
key. Sender points use `input_hash * a * B_scan`; receiver points use
`b_scan * input_hash * A`. `bip352_input_context` exposes the public input hash,
aggregate public key, and receiver tweak point. Prevouts must be authenticated by
the wallet; the router does not execute scripts or verify transaction signatures.

`create_bip352_outputs` and `scan_bip352_transaction` require an explicit network.
Regtest uses `sprt`; Testnet, Testnet4, and Signet share `tsp`. Scanning returns
public output keys, derivation indices, and optional label identifiers. The wallet
retains private label derivation, output spending-key derivation, transaction
construction, amount/destination confirmation, signing, and broadcasting.

The former router key generation, private-key extraction/aggregation, spending-key
derivation, and `SilentPayment` session APIs have been removed. Integrations must
perform those operations within their host wallet and supply only public data to
the router. Public ECDH points are not proofs of correct wallet computation;
the host wallet must verify final outputs before signing.
