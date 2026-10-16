# Ark Routes

SatsPath treats Ark as a public payment rail and keeps execution separate from
route planning.

## Direct Ark Receive

An Ark receiver can publish an Ark public pointer:

- Ark server URL,
- compressed receiver public key,
- optional VTXO pointer,
- optional ownership proof.

If the sender is compatible with the same Ark server, the route planner can
produce an `ArkToArk` intent. This does not require Boltz, Lightning, or an
on-chain swap. Current SatsPath CLI output is preview/intents unless explicitly
testnet-executed and supported by the local bridge.

## Ark Swap Routes

Ark swaps are different from direct Ark receive:

- `ArkToLightning` requires an offboard/submarine-style path.
- `LightningToArk` requires an onboard/reverse path.
- `ArkToOnchain` requires Ark offboard support.
- `OnchainToArk` requires Ark onboard support.

SatsPath does not call a normal Bitcoin address an Ark receive. If the Ark bridge
cannot create or claim the required Ark-side object, the route is intent-only and
fails closed for execution.

## Current Status

- Ark route planning and scoring are implemented.
- Live Ark ASP client connector (`LiveArkAspClient`) queries ASP signer public keys, unilateral exit delays, and dust limits (`/v1/info`).
- VTXO covenant tree DAG verification (`verify_ark_vtxo_dag`) and non-custodial host-wallet settlement handoff structures (`ArkBoardingHandoff`, `ArkForfeitHandoff`, `ArkOorPaymentRequest`) are implemented in `crates/satspath-router/src/ark.rs`.
- Ownership proof verification exists.
- The client requires an intended `ArkNetwork`, rejects ASP network mismatches, and rejects mainnet (`bitcoin` / `mainnet`) unless the caller explicitly opts in with `with_mainnet_execution(true)`. Boarding addresses and BIP-21 amounts are checked against the handoff and ASP network.
- All signing and transaction construction belong to the host wallet. Submission requires a wallet-prepared transaction and checkpoints (`/v1/tx/submit`) or BIP-322 intent proof and message (`/v1/batch/registerIntent`); handoff metadata is not an arkd request. Signed response data is returned to the wallet for subsequent protocol steps.
- Discovery and submission wire types are pinned to [arkd v0.9.16](https://github.com/arkade-os/arkd/tree/e2d9ed443df7a0dfb3aa1e5c824de9541ff71047/api-spec/protobuf/ark/v1). The discovery mapper leaves round interval, VTXO expiry, and the fixed/ppm fee schedule unavailable: `sessionDuration` defines neither timing value, and arkd intent fee expressions and transaction fee rates do not define that schedule. `build_oor_handoff` fails until an actual expiry and compatible fee schedule are available. Containerized arkd interoperability has not been verified, so Ark remains Preview.
- DAG verification checks structure, receiver ownership metadata, and amounts; it does not verify transaction hashes or cosigning scripts.
