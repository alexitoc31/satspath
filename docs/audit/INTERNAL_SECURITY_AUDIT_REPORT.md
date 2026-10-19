# 🛡️ SatsPath — Internal Security Penetration & Vulnerability Audit Report

> **Target Repository:** `satspath/satspath`  
> **Auditor Role:** Ethical Hacker / Internal Security Reviewer  
> **Reference Issue:** [#84 (B1)](https://github.com/satspath/satspath/issues/84)  
> **Audit Date:** September 2026  
> **Classification:** Security Engineering Report & Mainnet Gate Evaluation  

---

## 1. Executive Summary

This manual security audit evaluated the defensive architecture, network entry boundaries, cryptographic verification pipelines, adversarial input resilience, and state machine integrity of the **SatsPath** protocol stack.

As an internal ethical hacker review, testing was conducted from an adversarial perspective. The objective was to attempt:
1. Coercing the system into server-side network requests against internal infrastructure (SSRF);
2. Forging or replaying digital signatures across identities and domains;
3. Bypassing identity key rotation and transparency log append checks;
4. Inducing split-view or history rollback attacks in the append-only Merkle log;
5. Injecting forged payment method ownership proofs;
6. Crashing parsers or leaking sensitive keys via malformed or private inputs.

The audit established and automated a dedicated adversarial security test suite:
📁 [`crates/satspath-core/tests/adversarial_security.rs`](../../crates/satspath-core/tests/adversarial_security.rs)

### Overall Assessment & Security Posture
The SatsPath core stack exhibits a **strict fail-closed architecture**:
- **SSRF Defenses:** Validate URLs across schemes, ports, IP ranges, and automatically unpack IPv6-mapped IPv4 addresses (`::ffff:x.x.x.x`).
- **Signature & Serialization Binding:** BIP-340 Schnorr signatures enforce RFC-8785 Canonical JSON and a 17-byte domain tag (`SatsPathProfileV1`).
- **Append-Only Transparency:** State transitions enforce monotonic sequences, dual-signed key rotation proofs, predecessor checkpoint linking, and RFC-6962 Merkle second-preimage isolation.
- **Fail-Safe Sanitization:** Proactively filters and rejects any private key material (`xprv`, mnemonic seed phrases, secret keys).

---

## 2. Threat Vector Assessment & Test Matrix

| Vector ID | Target Subsystem | Attack Vector / Description | Test Function | Test Result | Severity Rating |
|---|---|---|---|---|---|
| **VEC-SSRF-01** | `ssrf.rs` | IPv6-mapped loopback (`::ffff:127.0.0.1`) and cloud metadata (`::ffff:169.254.169.254`) | `test_ssrf_adversarial_ipv6_mapped_loopback` | **PASSED (Blocked)** | Critical (Mitigated) |
| **VEC-SSRF-02** | `ssrf.rs` | Port smuggling / probing non-standard ports (SSH 22, SMTP 25, Redis 6379, etc.) | `test_ssrf_adversarial_port_smuggling` | **PASSED (Blocked)** | High (Mitigated) |
| **VEC-SSRF-03** | `ssrf.rs` | Disallowed schemes (`file://`, `gopher://`, `dict://`, `ldap://`) | `test_ssrf_adversarial_schemes` | **PASSED (Blocked)** | Critical (Mitigated) |
| **VEC-CRYPTO-01** | `crypto.rs` | Identity pubkey substitution without valid signer re-attestation | `test_crypto_signature_transplant_attack` | **PASSED (Rejected)** | Critical (Mitigated) |
| **VEC-CRYPTO-02** | `crypto.rs` | Payment method recipient tampering to redirect funds | `test_crypto_signature_transplant_attack` | **PASSED (Rejected)** | Critical (Mitigated) |
| **VEC-JSON-01** | `crypto.rs` | Canonical JSON serialization variance / whitespace invariance | `test_canonical_json_determinism` | **PASSED (Deterministic)** | Medium (Verified) |
| **VEC-STATE-01** | `transparency/` | Unauthorized key rotation without predecessor key dual-signed authorization | `test_unauthorized_key_rotation_rejection` | **PASSED (Rejected)** | Critical (Mitigated) |
| **VEC-STATE-02** | `transparency/` | Transparency log split-view / equivocation (conflicting root at same tree size) | `test_transparency_log_split_view_and_equivocation_defense` | **PASSED (Rejected)** | Critical (Mitigated) |
| **VEC-STATE-03** | `transparency/` | Checkpoint tree size rollback attack | `test_transparency_log_split_view_and_equivocation_defense` | **PASSED (Rejected)** | Critical (Mitigated) |
| **VEC-OWN-01** | `ownership.rs` | Replaying legitimate ownership proof to a different user identity | `test_payment_method_ownership_proof_forgery_rejection` | **PASSED (Rejected)** | Critical (Mitigated) |
| **VEC-OWN-02** | `ownership.rs` | Forged message signature inside ownership proof | `test_payment_method_ownership_proof_forgery_rejection` | **PASSED (Rejected)** | High (Mitigated) |
| **VEC-OWN-03** | `ownership.rs` | Attempting to generate proof with key that does not control target address | `test_payment_method_ownership_proof_forgery_rejection` | **PASSED (Rejected)** | High (Mitigated) |
| **VEC-INPUT-01** | `validation.rs`, `bip321.rs` | Malformed BOLT12 offers, invalid BIP-321 URIs, bad Lightning addresses | `test_input_boundary_bolt12_bip321_and_lightning` | **PASSED (Rejected)** | Medium (Mitigated) |
| **VEC-LEAK-01** | `validation.rs` | Accidental or malicious private material submission (`xprv`, seed phrases, secret keys) | `test_private_material_rejection` | **PASSED (Rejected)** | Critical (Mitigated) |
| **VEC-TREE-01** | `transparency/tree.rs` | Second-preimage attack against Merkle tree interior vs leaf nodes | `test_rfc6962_merkle_tree_prefix_isolation` | **PASSED (Isolated)** | High (Mitigated) |
| **VEC-SEED-01** | `crypto.rs` | Reproducible deterministic identity derivation from wallet seed (`m/9737'/0'`) | `test_deterministic_seed_key_derivation` | **PASSED (Verified)** | High (Verified) |

---

## 3. Detailed Technical Analysis & Findings

### 3.1 Network Boundary & SSRF Prevention
* **Analysis:** SatsPath resolvers fetch `.well-known/satspath/{alias}` endpoints over HTTP/HTTPS. A malicious peer or registration could supply addresses targeting `127.0.0.1`, cloud metadata services (`169.254.169.254`), or private VPC ranges.
* **Tested Defense:**
  - `validate_url` explicitly extracts hostnames and IP addresses.
  - Detects and unpacks IPv6-mapped IPv4 representations (e.g. `::ffff:127.0.0.1`).
  - Strict scheme whitelist (`https` mandatory in production).
  - Port allowlist restricting connections exclusively to standard web ports (`80`, `443`, `8080`, `8443`).

### 3.2 Canonical Serialization & Signature Integrity
* **Analysis:** Standard JSON serializers do not guarantee key order. If keys are ordered arbitrarily, signatures cannot be reliably validated across different runtime environments (Rust native vs WASM in browsers).
* **Tested Defense:**
  - `canonical_profile_bytes` enforces RFC 8785 JSON canonicalization.
  - Prefixing with `SatsPathProfileV1` guarantees cryptographic domain separation against cross-protocol replay.
  - Tests confirm that any mutation in profile fields (such as substituting a Bitcoin address or altering sequence) immediately causes signature verification to return false.

### 3.3 Append-Only Transparency Log & State Invariants
* **Analysis:** Key transparency protects users against rogue server operators substituting identities. An attacker might attempt to overwrite an existing identity without possessing the original private key, or serve differing log checkpoints to different users (split-view attack).
* **Tested Defense:**
  - `verify_identifier_history` strictly enforces that key rotation requires dual cryptographic proof (authorization from the predecessor key + acceptance by the successor key).
  - `verify_checkpoint_transition` and `verify_checkpoint_inclusion` verify RFC-6962 Merkle tree consistency. Rollback in tree size or conflicting roots for the same tree size are rejected fail-closed.

### 3.4 Cryptographic Ownership Proofs
* **Analysis:** A user might publish payment pointers they do not own.
* **Tested Defense:**
  - `build_signature_attestation` and `verify_method_verification` bind the payment method descriptor to the identity's public key with a timestamp challenge.
  - Replay of an ownership proof across identities fails because the challenge message explicitly commits to the identity pubkey.
  - Proof creation verifies that the signing key matches the on-chain address or Ark pubkey.

### 3.5 Private Material Filtering
* **Analysis:** Users or compromised clients could mistakenly paste backup seed phrases, BIP-32 extended private keys (`xprv`/`tprv`), or API secrets into profile fields.
* **Tested Defense:**
  - `assert_no_private_material` scans input strings for private key prefixes, secret token labels, and 12/24-word seed patterns, failing closed with `SatsPathError::PrivateMaterialRejected`.

---

## 4. Mainnet Deployment Recommendations

Before transitioning to an unconstrained mainnet deployment, the following security measures should be verified:

1. **DNS Rebinding Protection (Issue #87):**
   - Even though `validate_url` rejects private IP literals, DNS rebinding attacks can theoretically resolve a public hostname to a safe IP during validation and then resolve to `127.0.0.1` at TCP connection time.
   - *Recommendation:* Pin resolved socket addresses directly during connection establishment.
2. **Mutation API Rate Limiting & DoS Protection (Issue #91):**
   - The transparency log append endpoint should be rate-limited and protected by proof-of-work or authentication tokens to prevent denial-of-service and state bloat.
3. **Multi-Witness Cosigning Quorum (Issues #85 & #86):**
   - Independent witness monitors should cross-verify checkpoints via gossip protocol before wallets trust unanchored checkpoints.

---

## 5. Auditor Sign-Off & Conclusion

All threat vectors specified in **Issue #84 (B1)** have been evaluated, mitigated, and verified with automated test suites in continuous integration. The implementation is robust, adheres to fail-closed security best practices, and satisfies the acceptance criteria for the in-house security audit.
