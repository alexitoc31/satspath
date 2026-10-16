# BIP-352 public test vectors

`bip352_send_and_receive_test_vectors.json` is a public projection of all 28
[official BIP-352 vector groups](https://github.com/bitcoin/bips/blob/master/bip-0352/send_and_receive_test_vectors.json).
The original imported fixture at SatsPath PR #160 revision
`6e5ef41ce06557f5e8d4593f6a78f5b84d31d7a3` has SHA-256
`f5f9ed4afd76a1b76f3c70b1cbe67532f89abbe559f8e02d7fc3d8ecb93af4a1`.

The projection removes input private keys, private-key sums, receiver private
keys, private tweaks, and spending signatures. Receiver public keys and labeled
spend public keys are decoded from the original expected addresses. ECDH points
are taken from the original expected shared secrets and supplied as host-wallet
inputs. Public transaction data, expected addresses, output keys, aggregate input
public keys, and input tweak points are retained.

Tests cover the router's public operations. They do not claim to validate wallet
ECDH computation, secret-key aggregation, label-secret derivation, or signing.

This coverage is partial progress toward [issue #154](https://github.com/satspath/satspath/issues/154).
The issue remains incomplete: passing these public projections does not establish
full official-vector conformance or wallet interoperability. Silent Payments stays
`EXPERIMENTAL` in both README capability entries until the remaining requirements
are verified with a host wallet.

The official final-point-at-infinity case supplies an all-zero x-only output key.
The router skips that invalid curve point and returns no detected outputs.
The tests also assert that its aggregate input point is at infinity.
The sender reports an error when a recipient group exceeds `K_max`.
