---
name: satspath-crypto-audit
description: "Exhaustive cryptographic, protocol safety, and vulnerability audit skill for SatsPath. Use when auditing, analyzing, or verifying cryptographic primitives (BIP-340 Schnorr, ECDSA, RFC 8785 canonical serialization, BIP-353 DNSSEC, hybrid Kyber/KEM), state transition safeguards (key rotation, sequence continuity, Catena OP_RETURN anchors), SSRF/DoS defenses, or resolving security findings from CodeRabbit to formulate verified patches and pull requests."
---

# SatsPath Cryptographic & Protocol Safety Audit Skill

This skill guides the auditing, verification, and hardening of cryptographic primitives, protocol safety invariants, and vulnerability remediation across the SatsPath workspace.

---

## 1. Architectural Guardrails & Invariants

Before analyzing any code or reviewing findings, enforce these non-negotiable protocol invariants:

1. **Strict Non-Custodial Boundary:**
   - SatsPath is an identity, capability discovery, and quote routing layer.
   - SatsPath **never** holds private spending keys (BIP-39 seeds, `xprv`, Lightning node macaroons).
   - SatsPath **never** signs Bitcoin transactions, creates PSBTs, opens channels, or broadcasts to mempools.
   - Any proposed change introducing fund custody or synthetic profile keys is **strictly forbidden**.

2. **Authentic Cryptographic Proofs Only:**
   - Never fabricate synthetic profiles, simulated signatures, or temporary keypairs to satisfy a pipeline.
   - BIP-353 resolution without an `sp-profile` pointer authenticates payment instructions for a domain, not an identity key. It must return `AliasNotFound` in `ProfileResolver` rather than forging signatures.

3. **Multi-Rail Router Invariance:**
   - Payment handoffs and quotes must flow through `select_route` and `QuoteResponse`.
   - Never create ad-hoc payment execution or bypass router scoring.

---

## 2. Cryptographic Audit Vectors & Checklists

### A. Digital Signatures & Curve Operations
- **secp256k1 Operations:**
  - Verify signatures over 32-byte SHA256 hashes of canonical payloads (`secp256k1::Message::from_digest`).
  - Schnorr signatures (BIP-340) must use 32-byte x-only public keys (`XOnlyPublicKey`) and strict 64-byte signatures.
  - ECDSA signatures must enforce Low-S malleability checks (standard in `secp256k1` crate).
  - Verify that verification functions never silently ignore empty public keys, zero points, or uncompressed/compressed mismatches.
  - Check that secret keys are zeroized on drop (`zeroize` crate / `SecretKey` drop).

### B. Canonical JSON Serialization (RFC 8785)
- All signed payloads (e.g. `PaymentProfile`, `IdentityClaim`, `ProfileEvent`, `WitnessCheckpoint`) MUST be canonicalized according to RFC 8785 before hashing.
- Verify:
  - Lexicographical sorting of object keys.
  - No extraneous whitespace between tokens (`:`, `,`).
  - Floating point numbers are either strictly banned or formatted in strict IEEE 754 canonical form.
  - No key collisions or duplicate map keys during deserialization.

### C. BIP-353 DNSSEC & Trust Anchor Verification
- **Local Validation:**
  - `HickoryDnssecTxtResolver` must perform cryptographic chain validation using `DnssecDnsHandle`.
  - **Never trust upstream AD (Authentic Data) bits.**
  - Fail closed on missing RRSIG, expired signatures, or unsigned zones when in `Strict` mode.
- **Trust Anchors:**
  - Bundled root trust anchors in `root_trust_anchors()` must contain active ICANN KSKs (including key tag `38696` and `20326`).
  - Anchor decoding must fail loudly (`expect`) instead of silently ignoring key insertion.
- **Payload Safety:**
  - Strictly screen for and reject private material (`seed`, `xprv`, `mnemonic`, `macaroon`, `preimage`, `claim_key`, `refund_key`).
  - Reject ambiguous records (multiple `bitcoin:` URIs at the same name).
  - Reconstruct chunked TXT strings (<=255 bytes) without separators.

### D. Identity Continuity, Rotation & Revocation
- **Sequence Monotonicity:**
  - Profile updates must enforce strictly increasing sequence numbers (`new_seq > current_seq`).
  - Reject missing, repeating, or decreasing sequences.
- **Key Rotation Proofs:**
  - Replacing an identity key requires a valid `RotationProof` signed by the *previous* active key.
  - TOFU (Trust-On-First-Use) pinning must prevent unauthenticated key substitution.
- **Revocation Enforcement:**
  - If `profile.revoked == true`, immediately fail closed with a fatal error (`SatsPathError::RegistryError`).
  - Revoked profiles must never be returned to callers or passed to routers.

### E. Post-Quantum Hybrid KEM (PQC)
- In `satspath-pqc`:
  - Hybrid encapsulation combines classical ECDH (secp256k1/X25519) and lattice-based KEM (ML-KEM-768).
  - Shared secret derivation must use HKDF over the concatenation of both secrets (`classical_ss || pqc_ss`).
  - Decapsulation failures must return constant-time implicit rejection or constant-time error without chosen-ciphertext padding oracle leakage.

### F. SSRF & Network Transport Defenses
- For any outbound URL fetch (`sp-profile`, HTTP resolvers, Nostr relays):
  - `validate_url` must check scheme (HTTPS only), blocked hostnames (metadata endpoints, localhost).
  - Pre-resolve hostnames via DNS and verify that **every** resolved IP is checked against `is_private_or_reserved_ip` to defeat DNS rebinding.
  - Disable HTTP redirects (`redirect(Policy::none())`).
  - Enforce bounded response size (e.g. 50 KB DoS protection) before deserialization.

---

## 3. CodeRabbit Security Review Integration

When using CodeRabbit to audit SatsPath:

1. **Run Local Review:**
   ```bash
   coderabbit review --agent
   ```
   Or inspect remote PR threads:
   ```bash
   gh pr view <PR> --comments
   gh api repos/satspath/satspath/pulls/<PR>/comments
   ```

2. **Categorize CodeRabbit Findings:**
   - **Critical / Major (Security & Privacy, SSRF, Continuity):** Verify against code immediately. Formulate a patch.
   - **Minor / Code Quality:** Check if docstrings, error variants, or mock fixtures need alignment.
   - **False Positives:** Discard if suggestion attempts to violate SatsPath non-custodial boundaries or fabricate synthetic keys.

---

## 4. Remediation Workflow: From Audit to Pull Request

When a cryptographic or security flaw is discovered:

1. **Create Clean Branch:**
   ```bash
   git checkout main
   git pull origin main
   git checkout -b fix/<short-flaw-description>
   ```

2. **Reproduce with Regression Test:**
   - Write a unit or integration test exposing the vulnerability (e.g., verifying that forged signatures, replayed sequences, or private IPs are rejected).

3. **Apply Minimal Fix:**
   - Implement the fix strictly in the affected crate (`satspath-core`, `satspathd`, `satspath-router`).
   - Preserve all public API contracts and invariants.

4. **Run Full Verification & Automated Security Audit:**
   ```bash
   # Execute full automated cryptographic verification suite:
   .agents/skills/satspath-crypto-audit/scripts/audit_crypto.sh

   # Standard workspace gates:
   cargo test --workspace
   cargo clippy --workspace --all-targets -- -D warnings
   cargo fmt --all -- --check
   ```

5. **Open Pull Request & Review:**
   ```bash
   git push -u origin fix/<short-flaw-description>
   gh pr create --title "fix(security): <description>" --body "<details>"
   ```
   - Monitor CodeRabbit automated review, address findings, and verify that all CI checks turn green before merging.
