# Invite and Claim Flow

Unknown receiver flow:

```txt
identifier -> no signed profile -> create invite -> receiver verifies email -> receiver wallet generates keys locally -> receiver publishes signed public profile -> sender re-resolves -> payment can proceed
```

## Security & Non-Custodial Invariants

- **Unknown receiver means invite only.** No payment route exists until the receiver publishes a valid, cryptographically signed profile.
- **No funds move on invite creation.** The daemon only returns an invitation preview and records a non-custodial invite record.
- **No private keys or seeds:** SatsPath never generates seed phrases, never generates private keys for users, and never transmits or emails private material.
- **Local key custody:** All keys are generated and held locally within the receiver's client/wallet.
- **Authenticated sender attribution:** An invite may carry a Schnorr signature (`sender_signature`) bound to `sender_pubkey`. Unsigned invites are treated as unauthenticated.
- **Strict expiry:** Reject any invite whose `expires_at` has passed. Do not extend the expiry on claim.

---

## State Machine & Lifecycle

```txt
       [ Create Invite ]
               |
               v
           +-------+
           |Created| <------+ (waiting for claim)
           +-------+        |
            /     \         | (delivery)
           /       \        |
(email sent)        \       v
    v                +-----------+
+---------+          | EmailSent |
|Claimed  |<---------+-----------+
|(public  |
|profile) |
+---------+
    |
(expiry)
    +-------------------> [ Expired ]
(user cancel)
    +-------------------> [ Cancelled ]
```

- **`Created`:** The invite is generated and stored in `InviteStore`. Waiting for receiver to claim.
- **`EmailSent`:** Delivery occurred via email or messaging channel.
- **`ClaimedWithPublicProfile`:** The receiver has generated their local keys, configured receive methods, signed their profile, and published it to the Transparency Log.
- **`Expired`:** Current timestamp exceeds `expires_at`. The invite is locked and cannot be claimed.
- **`Cancelled`:** The sender explicitly cancelled the pending invite before claim.

---

## End-to-End Claim Protocol

1. **Sender initiates payment:** Sender calls `POST /v1/send` with recipient identifier and amount. If the identifier has no registered profile, the daemon creates a signed `InviteRecord` with a UUID `invite_id` in `InviteStore`.
2. **Receiver receives claim link:** The claim URL format is `https://satspath.local/claim?invite_id=<UUID>&alias_hash=<HASH>&amount=<SATS>`.
3. **Receiver inspects invite:** The receiver wallet or web UI calls `GET /v1/claim?invite_id=<UUID>`. The daemon validates sender signatures and expiry, returning amount, display hint, and verification status.
4. **Local key generation & method setup:** The receiver generates their identity keypair locally and inputs their public receive methods (Lightning Address, Onchain address, Ark).
5. **Receiver claims and publishes profile:** The receiver wallet calls `POST /v1/claim` with `invite_id`, `alias`, and receive methods. The daemon validates the claim, updates the invite status to `ClaimedWithPublicProfile`, commits the new profile to the Merkle Transparency Log, and queues a `ClaimNotification`.
6. **Sender notification & settlement loop:** The sender daemon polls or receives notifications via `GET /v1/invites/notifications`. When notified, the sender's UI offers an immediate "Send Payment Now" handoff. Re-resolving the recipient now succeeds with full cryptographic proof.

---

## API Specification

### 1. Inspect Invite
- **Endpoint:** `GET /v1/claim?invite_id=<UUID>`
- **Auth:** None (Public)
- **Response:**
  ```json
  {
    "invite_id": "c1f7b8a0-...",
    "identifier_hash": "a4b2c1...",
    "display_hint": "c***@example.com",
    "amount_sats": 25000,
    "memo": "Dinner",
    "status": "waiting_for_claim",
    "is_expired": false,
    "is_claimable": true,
    "created_at": 1727092800,
    "expires_at": 1727179200,
    "sender_verified": true,
    "sender_pubkey": "02..."
  }
  ```

### 2. Claim Invite
- **Endpoint:** `POST /v1/claim`
- **Auth:** None (Public mutation guarded by invite token)
- **Request:**
  ```json
  {
    "invite_id": "c1f7b8a0-...",
    "alias": "carol@example.com",
    "lightning_address": "carol@getalby.com",
    "onchain_address": "bc1q..."
  }
  ```
- **Response:**
  ```json
  {
    "status": "claimed",
    "invite_id": "c1f7b8a0-...",
    "alias": "carol@example.com",
    "amount_sats": 25000,
    "profile_pubkey": "03...",
    "claimed_at": 1727093400,
    "message": "Invite successfully claimed and receiver profile published to transparency log"
  }
  ```

### 3. List Invites
- **Endpoint:** `GET /v1/invites`
- **Auth:** None (Public `GET`)
- **Response:** Array of `InviteRecord` objects.

### 4. List Claim Notifications
- **Endpoint:** `GET /v1/invites/notifications`
- **Auth:** None (Public `GET`)
- **Response:** Array of `ClaimNotification` objects.

### 5. Mark Notification Read
- **Endpoint:** `POST /v1/invites/notifications/<ID>/read` (or `POST /v1/invites/notifications/read-all`)
- **Auth:** Bearer token (`admin.macaroon` / `SATSPATHD_AUTH_TOKEN`)
- **Response:** `{"status": "ok", "notification_id": "...", "read": true}` (or `{"status": "ok", "all_read": true}`)

