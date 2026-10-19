# SatsPath v2: Witness Deployment Guide

## Overview

A SatsPath Transparency Witness is a lightweight node designed to protect against split-view attacks. It acts as an independent auditor for Transparency Log operators, ensuring they do not equivocate by presenting different valid trees to different clients.

> **Note:** Standalone witness cosigning (`crates/satspath-witness`) and checkpoint gossip monitoring (`crates/satspath-gossip`) are implemented in the workspace; production deployment requires operating independent witnesses across separate administrative and infrastructure domains.

The witness holds minimal but **durable** state: for each audited log it persists the pinned `log_id`, `tree_size`, `root_hash`, and any recorded equivocation evidence. This state MUST survive restarts. A witness deployed on ephemeral storage loses its pins and stops detecting rollback and equivocation.

## Deployment Topology

Witnesses MUST be deployed in separate administrative and cryptographic domains from the log operators they audit. A typical deployment topology includes:

1. **The Log Operator**: Hosts the primary Transparency Log and resolves identities.
2. **Independent Witnesses (N)**: Operated by different entities across diverse infrastructure providers (e.g. one on AWS, one on GCP, one self-hosted).
3. **The Resolving Client**: Enforces a `K-of-N` witness policy defined in the namespace's DNS descriptor.

## Split-View Detection

If a log operator equivocates, it must present two different `root_hash` values for the same `log_id` and `tree_size`. When a witness encounters a checkpoint whose size matches its pinned state but the root differs, it halts and persistently records the permanent evidence of cryptographic failure. The witness will never sign a checkpoint for that log again until a manual operator-key rotation resets trust.

## Security Guarantees (v0.2 Architecture)

- **Non-equivocation**: In the v0.2 production specification with cryptographic cosigning, as long as at least one witness in the threshold set is honest, an operator cannot conduct a split-view attack without generating permanent, cryptographic proof of fraud. In the current reference prototype, witness state pinning provides local rollback detection.
- **No Resolution-Time Liveness Requirement**: Witnesses are not required to be online for every resolution. At least K of N witnesses MUST, however, be reachable by the operator when a new checkpoint is published in order to satisfy the quorum policy for that checkpoint.
