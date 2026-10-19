# 🔍 SatsPath — External Cryptographic Review Specification

> **Target Repository:** `satspath/satspath`  
> **Target Audience:** Independent Cryptographic Auditors & Security Researchers  
> **Reference Issue:** [#84 (B1)](https://github.com/satspath/satspath/issues/84)  
> **Scope:** Cryptographic Primitives, Signatures, Key Derivation, Merkle Trees & Post-Quantum Hybrids  

---

## 1. Introduction & Objectives

SatsPath relies on asymmetric cryptography and append-only transparency logs to provide verifiable, non-custodial identity-to-payment resolution over untrusted communication channels.

This specification serves as the formal briefing document for external cryptographic review teams. It specifies:
1. Exact mathematical parameters, curve operations, and derivation paths;
2. Domain separation schemes preventing cross-context and cross-protocol signature replay;
3. Append-only Merkle tree construction (RFC 6962) and consistency proof invariants;
4. Post-quantum hybrid migration architecture (ML-DSA / ML-KEM);
5. Concrete review questions and threat models for independent cryptographic verification.

---

## 2. Cryptographic Primitives & Invariants

### 2.1 Asymmetric Digital Signatures (secp256k1 BIP-340 Schnorr)
* **Curve:** `secp256k1` (Koblitz curve $y^2 = x^3 + 7 \pmod p$).
* **Signature Scheme:** BIP-340 Schnorr over 32-byte domain-separated SHA-256 digests.
* **Public Key Encoding:** 33-byte compressed format (`0x02` or `0x03` prefix) in transit, mapped to 32-byte x-only public keys for BIP-340 verification.
* **Domain Separation Tags:**
  To prevent cross-context signature replay (e.g. an attestation being replayed as a profile signature or checkpoint), each signed object prepends a constant domain tag before hashing:
  - **Payment Profiles:** `b"SatsPathProfileV1"`
  - **Transparency Events (`NameEvent`):** `b"SatsPathNameEventPayloadV1"` (leaf commitment: `b"SatsPathSignedNameEventV1"`)
  - **Transparency Checkpoints:** `b"SatsPathTransparencyCheckpointV1"`
  - **Identity Rotation Receipts:** `b"SatsPathKeyRotationAuthorizationV1"` and `b"SatsPathKeyRotationAcceptanceV1"`
  - **Guardian Recovery Receipts:** `b"SatsPathKeyRecoveryAuthorizationV1"` and `b"SatsPathKeyRecoveryAcceptanceV1"`
* **Profile Signature Construction:**
  $$\text{Digest} = \text{SHA256}\Big(\text{"SatsPathProfileV1"} \mathbin{\Vert} \text{CanonicalJSON}(\text{profile})\Big)$$
  $$\sigma = \text{SchnorrSign}(\text{sk}, \text{Digest})$$

### 2.2 Seed-Based Identity Key Derivation (`m/9737'/0'`)
* **Objective:** Enable deterministic recovery of identity keys from standard BIP-39 wallet seeds without exposing spending keys or requiring centralized backup.
* **Algorithm:** HMAC-SHA512.
* **Formula:**
  $$\text{PRK} = \text{HMAC-SHA512}\Big(\text{Key} = \text{"SatsPath Identity Key m/9737'/0'"}, \; \text{Data} = \text{seed} \mathbin{\Vert} \text{to\_be\_bytes}(\text{account\_index})\Big)$$
  $$\text{sk} = \text{PRK}_{0..32} \pmod n \quad (n = \text{secp256k1 group order})$$
* **Security Requirements:**
  - Strict validation that derived scalar lies in the range $1 \le \text{scalar} < n$.
  - Complete isolation between account indices ($\text{account}_0 \neq \text{account}_1$).
  - Zero leakage of master wallet root keys or on-chain transaction graph.

### 2.3 RFC 6962 Merkle Tree Construction
* **Hash Primitive:** SHA-256.
* **Leaf Node Hashing:**
  $$H(\text{leaf}) = \text{SHA256}(0x00 \mathbin{\Vert} \text{payload})$$
* **Interior Node Hashing:**
  $$H(\text{parent}) = \text{SHA256}(0x01 \mathbin{\Vert} \text{left\_child} \mathbin{\Vert} \text{right\_child})$$
* **Second-Preimage Resistance:** The one-byte prefix (`0x00` vs `0x01`) guarantees that no interior node hash can be interpreted as a leaf, and vice versa.
* **Tree Balancing:** Balanced binary tree using largest power of 2 less than $N$ ($k = 2^{\lfloor \log_2(N-1) \rfloor}$).
* **Consistency Proofs (RFC 6962 §2.1.2):**
  - Proves that log of size $m$ is an exact prefix of log of size $n$ ($m \le n$).
  - Prevents history rewriting, branch deletion, or retroactive event alteration.

### 2.4 Dual-Signed Identity Key Rotation
* **Threat Model:** Attacker with compromised server access attempting to replace Alice's key.
* **Invariant:** An identity key transition from $K_{\text{old}}$ to $K_{\text{new}}$ is invalid unless accompanied by a rotation receipt satisfying:
  1. Signed by $K_{\text{old}}$ (authorizing departure from previous key);
  2. Signed by $K_{\text{new}}$ (accepting ownership under new key);
  3. Bound to sequence number $S$ and previous event hash $H_{S-1}$.

### 2.5 Post-Quantum Hybrid Migration (`satspath-pqc`)
* **Design Strategy:** "Hybrid-first" (combining classical + post-quantum algorithms). If either primitive is broken, security is preserved by the other.
* **Hybrid Signatures:**
  - Classical: secp256k1 BIP-340 Schnorr.
  - Post-Quantum: NIST FIPS 204 **ML-DSA** (Dilithium).
  - Validation: Profile signature is valid iff both classical and ML-DSA signatures verify against their respective public keys.
* **Hybrid Key Encapsulation (P2P):**
  - Classical: X25519 Diffie-Hellman.
  - Post-Quantum: NIST FIPS 203 **ML-KEM** (Kyber).
  - Shared Secret: $K = \text{HKDF-SHA256}(\text{SS}_{\text{X25519}} \mathbin{\Vert} \text{SS}_{\text{ML-KEM}})$.

---

## 3. Targeted Review Questions for External Auditors

Cryptographic reviewers are invited to analyze and report on:

1. **Schnorr BIP-340 Verification & Nonce Handling:**
   - Are there any potential nonce-reuse, bias, or malleability issues in `satspath_core::crypto`?
2. **Canonical JSON Determinism (RFC 8785):**
   - Does `canonical_profile_bytes` guarantee bit-for-bit equivalence across all target architectures (x86_64, aarch64, wasm32-unknown-unknown)?
3. **Consistency Proof Edge Cases:**
   - Are all tree size transitions ($m \to n$, specifically when $m$ or $n$ are powers of two) properly bounded against arithmetic overflow and path indexing errors?
4. **Post-Quantum Hybrid State Transitions:**
   - Does the optional/mandatory transition rule for `pqc_required` allow any downgrade attacks from a quantum-resistant profile back to classical-only?

---

## 4. Source File Reference Map

| Component | Repository Path | Primary Functions / Types |
|---|---|---|
| Schnorr Signing & Derivation | [`crates/satspath-core/src/crypto.rs`](../../crates/satspath-core/src/crypto.rs) | `sign_profile`, `verify_signed_profile`, `derive_identity_key_from_seed`, `canonical_profile_bytes` |
| Merkle Tree Primitives | [`crates/satspath-core/src/transparency/tree.rs`](../../crates/satspath-core/src/transparency/tree.rs) | `leaf_hash`, `node_hash`, `merkle_root`, `inclusion_proof`, `consistency_proof` |
| Checkpoint Verification | [`crates/satspath-core/src/transparency/verifier.rs`](../../crates/satspath-core/src/transparency/verifier.rs) | `verify_checkpoint_transition`, `verify_checkpoint_inclusion`, `verify_identifier_history` |
| Post-Quantum Hybrid Engine | [`crates/satspath-pqc/src/`](../../crates/satspath-pqc/src/) | `hybrid_sig::hybrid_sign`, `hybrid_sig::hybrid_verify`, `hybrid_kem` |
| Adversarial Test Suite | [`crates/satspath-core/tests/adversarial_security.rs`](../../crates/satspath-core/tests/adversarial_security.rs) | 12 automated adversarial test vectors |
