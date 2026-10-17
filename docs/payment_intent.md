# PaymentIntent and host-wallet approval (#173)

The host obtains a `QuoteResponse` via SatsPath resolution/routing, then calls
`prepare_payment_intent` with its current transparency store, witness and gossip
evidence, wallet network, amount, maximum fee and the actual resolver sources.
The returned `PaymentIntent` contains the identity key, selected signed method,
destination, amount, fee limits, expiry, verification state and provenance.
Show those fields to the payer before calling `PaymentIntent::approve(true)`.
Approval yields a non-deserializable, single-use token. Pass it to
`execute_quote_handoff`: it re-reads the signed profile and evidence, compares
the RFC 8785 canonical intent and refuses modified amounts, destinations,
networks, fees or identity state. No spending keys enter SatsPath.
Canonical bytes follow RFC 8785 JCS; numeric fields outside the exact
ECMAScript integer range (±(2^53−1)) are rejected rather than rounded, so
distinct payment terms cannot produce the same approval digest.

Host adapters must implement fee-bound `WalletExecutor` methods. The default
implementations reject execution. BDK calculates the actual PSBT input/output
fee before asking the host to sign; LDK passes a maximum fee to the host node
and checks the returned payment hash, amount and fee. Legacy low-level wallet
methods remain available to existing integrations, but **must not** be used to
execute SatsPath quotes. A custom adapter must enforce the cap before spend.

Resolver sources are provided by the caller performing resolution because the
current `QuoteResponse` does not carry authenticated transport provenance.
Do not invent provenance or set `identifier_verified` based only on a signed
profile. Unsupported BOLT12, Ark, Silent Payments and swaps fail closed until
their wallet-specific approval and confirmation paths exist.
