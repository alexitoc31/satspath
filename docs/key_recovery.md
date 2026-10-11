# Sovereign Key Recovery Architecture (Issue #97)

## Sovereign Security Posture & Non-Custodial Boundaries

SatsPath adheres to the Bitcoin-grade sovereign security model:
1. **Strict Rejection of Email / SMS / Phone Recovery:**
   Identity keys in SatsPath control sovereign payment profiles, routing preferences, and recipient ownership. Delegating key recovery to email verification or SMS codes introduces custodian risk, SIM-swapping vulnerability, and third-party censorship vectors. Neither the SatsPath daemon nor any third-party infrastructure may unilaterally reset or replace an identity key.
2. **Fail-Closed Guarantee:**
   Until an owner-signed event commits a `RecoveryPolicy` into the identifier's transparency log history, guardian recovery is disabled (`TransparencyError::RecoveryDisabled`). A `RecoverKey` event cannot supply the policy that authorizes it. Once committed, a policy can be replaced by a later owner-signed event or a verified `RecoverKey` event (which installs the recoverer's profile policy without guardian approval of that new policy), but cannot currently be removed. No default or backdoor recovery exists.

---

## Recovery Mechanisms

### 1. Deterministic Seed-Based Derivation (Local Sovereign Recovery)

Users with a dedicated SatsPath identity seed can deterministically derive their SatsPath identity key. Convert any BIP-39 mnemonic outside SatsPath, and never provide a wallet master seed:
- **Derivation Algorithm:** HMAC-SHA512
- **Domain Separator:** `b"SatsPath Identity Key m/9737'/0'"`
- **Derivation Note:** This is a non-standard flat HMAC namespace, not BIP-32 child-key derivation.
- **Inputs:** `seed_bytes` (16..=64 bytes per BIP-32 bounds) + `account_index` (big-endian `u32`)

```text
HMAC-SHA512(key = "SatsPath Identity Key m/9737'/0'", data = seed || account_index)
Candidate scalar = first 32 bytes (must be valid secp256k1 scalar)
```

**Key Isolation Invariant:** This derivation is strictly isolated from Bitcoin spending keys (e.g., `m/84'/0'/0'` or `m/86'/0'/0'`). The identity key is purely a `secp256k1` Schnorr identity signing key; it never signs transactions, touches UTXOs, or exposes wallet funds. Within `derive_identity_key_from_seed`, derived HMAC output and candidate scalar buffers are explicitly zeroized immediately after use.

**Non-Custodial CLI Boundary:** SatsPath is a universal payment discovery router and never prompts for or manages seed phrases or spending keys in its user interface. The `derive_identity_key_from_seed` HMAC primitive remains available in `satspath-core` for offline or external tooling, but CLI recovery is performed via sovereign, pre-committed guardian threshold proofs ([`KeyRecoveryProof`](../crates/satspath-core/src/recovery.rs)).

### 2. M-of-N Threshold Guardian Recovery (Social / Multi-Device Recovery)

For users wishing to guard against total key and seed loss, SatsPath supports pre-committed threshold guardian recovery.

#### Fail-Closed Pre-Commitment Rule
Key recovery cannot be retroactively claimed:
- A user must have committed a `RecoveryPolicy` in their profile and transparency log events *prior* to losing access.
- If an identifier has no active `RecoveryPolicy` (either never configured, or no prior event in replayed history established one), any attempt to execute `NameAction::RecoverKey` fails immediately with `TransparencyError::RecoveryDisabled`. Note that publishing an event with `recovery_policy: None` does *not* disable an existing active policy; it retains the previously committed policy in replayed history.
- A recovery event cannot supply its own policy to authorize itself; the policy must be pre-committed in prior log history.

#### Policy Structure
```rust
pub struct RecoveryPolicy {
    pub version: u16,          // 1
    pub threshold: u8,          // M, where 1 <= M <= N <= 32
    pub guardians: Vec<String>, // N unique compressed 33-byte secp256k1 pubkeys (hex)
}
```

#### Two-Phase Cryptographic Binding & Domain Separation
Recovery authorization requires distinct domain-separated signatures over newline-separated tuples:

1. **Guardian Authorization (`SatsPathKeyRecoveryAuthorizationV1`):**
   Each guardian signs:
   ```text
   SatsPathKeyRecoveryAuthorizationV1
   <identifier_hash>
   <previous_pubkey>
   <new_pubkey>
   <previous_event_hash>
   <sequence>
   <recovered_at>
   ```

2. **New Key Acceptance (`SatsPathKeyRecoveryAcceptanceV1`):**
   The new identity key signs:
   ```text
   SatsPathKeyRecoveryAcceptanceV1
   <identifier_hash>
   <previous_pubkey>
   <new_pubkey>
   <previous_event_hash>
   <sequence>
   <recovered_at>
   ```

3. **Log Event Commitment (`NameEvent::owner_signature`):**
   The new identity key also signs `NameEvent::signing_message()`, authenticating the complete log event including sequence, previous event hash, and any updated profile or policy.

Both authorization and acceptance commit to the exact `previous_event_hash`, monotonic `sequence`, and `recovered_at` timestamp, preventing replay attacks across rotations or forks.

---

## Log Verification Rules for `NameAction::RecoverKey`

When an identifier transition occurs via `RecoverKey`:
1. **Active Pre-Committed Policy Presence:** The replayed predecessor history MUST hold an active `RecoveryPolicy`. The recovery event cannot supply the policy used to authorize itself.
2. **Predecessor Binding:** The proof's `previous_pubkey` must match the current active identity key.
3. **Threshold Quorum:** The proof must include at least $M$ valid, distinct signatures from guardian pubkeys registered in the active policy.
4. **Acceptance Signature:** The proof must include a valid acceptance signature from `new_pubkey`.
5. **Sequence & Continuity:** `sequence == predecessor.sequence + 1`, and `previous_event_hash == predecessor.signed_event_hash()`.
6. **Full Event Authentication:** `event.owner_signature` must be a valid Schnorr signature over `event.signing_message()` produced by `new_pubkey`.
7. **Policy Continuation:** If the recovery event does not specify a new `recovery_policy`, the previous policy remains active; if specified, the new policy is validated and becomes active for subsequent events (allowing the holder of the recovered key to install a replacement policy without requiring guardian approval of that new policy).

---

## CLI & Daemon Interface

### CLI Commands
```bash
# Recover an alias identity key using a pre-committed guardian threshold proof.
# NOTE: The CLI does not yet commit a new RecoveryPolicy during `satspath register` (which writes
# `recovery_policy: None`). These commands succeed only if the local registry entry already carries
# a policy (for example, an imported profile or one updated via daemon API).
satspath alias recover --proof-file proof.json --alias alice@example.com

# Alternatively via the wallet subcommand:
satspath wallet recover --proof-file proof.json --alias alice@example.com
```

### Daemon Endpoint
`POST /v1/profile/recover`

Payload:
```json
{
  "alias": "alice@example.com",
  "proof": {
    "version": 1,
    "identifier_hash": "a1b2...",
    "previous_pubkey": "02...",
    "new_pubkey": "03...",
    "previous_event_hash": "e3b0...",
    "sequence": 1,
    "guardian_signatures": [
      { "guardian_pubkey": "02...", "signature": "..." },
      { "guardian_pubkey": "03...", "signature": "..." }
    ],
    "acceptance_signature": "...",
    "recovered_at": 1700000000
  },
  "signed_profile": { ... },
  "event_created_at": 1700000005,
  "event_signature": "..."
}
```

> **Note on Remote Signing:** When the new private key is held off-daemon (e.g., in a cold signer), `event_signature` MUST be provided alongside `event_created_at`. `event_created_at` must be within ±300 s of daemon server time, and it is used verbatim as the event's `created_at`, so the client signature must cover exactly that value. Requests omitting `event_created_at` while supplying `event_signature` are rejected immediately.

Response:
```json
{
  "alias": "alice@example.com",
  "sequence": 1,
  "previous_fingerprint": "...",
  "new_fingerprint": "...",
  "event_hash": "...",
  "checkpoint_hash": "..."
}
```
