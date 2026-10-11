use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{BitcoinAnchor, TransparencyError};
use crate::BitcoinNetwork;

/// Domain separator for Catena OP_RETURN commitments.
pub const CATENA_COMMITMENT_DOMAIN: &[u8] = b"SatsPathCatenaAnchorV1";

/// Standard value of the continuation UTXO in satoshis (1,000 sats, above dust).
pub const CONTINUATION_SATOSHIS: u64 = 1000;

/// Standard value of the continuation UTXO in BTC.
pub const CONTINUATION_BTC: f64 = 0.00001000;

/// Canonical continuation output index in Catena transactions.
/// Output 0 is always OP_RETURN, output 1 is always the 1,000-sat continuation UTXO.
pub const CATENA_CONTINUATION_VOUT: u32 = 1;

/// Represents the public genesis of a Catena anchoring chain on Bitcoin.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatenaGenesis {
    pub network: BitcoinNetwork,
    pub txid: String,
    pub continuation_vout: u32,
    pub commitment: String,
    pub block_hash: Option<String>,
    pub block_height: Option<u64>,
}

/// An authenticated, verifiable chain proof tracing a checkpoint back to genesis.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatenaChainProof {
    pub genesis: CatenaGenesis,
    pub anchors: Vec<BitcoinAnchor>,
    pub latest_txid: String,
    pub verified: bool,
}

/// Candidate conflict evidence indicating two conflicting anchor records claim to spend the same continuation UTXO.
///
/// NOTE: This proof compares record fields. Full on-chain transaction verification with a Bitcoin node
/// is required to verify that both conflicting transactions are confirmed on-chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CatenaEquivocationProof {
    pub chain_index: u64,
    pub spent_txid: String,
    pub spent_vout: u32,
    pub first_anchor: BitcoinAnchor,
    pub second_anchor: BitcoinAnchor,
    pub evidence: String,
}

/// Compute a domain-separated, sequential Catena commitment for a checkpoint hash.
///
/// Commitment format: SHA-256("SatsPathCatenaAnchorV1" || chain_index (8 bytes big-endian) || checkpoint_hash (32 bytes raw))
pub fn catena_commitment(
    checkpoint_hash: &str,
    chain_index: u64,
) -> Result<String, hex::FromHexError> {
    let mut h = Sha256::new();
    h.update(CATENA_COMMITMENT_DOMAIN);
    h.update(chain_index.to_be_bytes());
    h.update(hex::decode(checkpoint_hash)?);
    Ok(hex::encode(h.finalize()))
}

/// Maximum number of hops allowed when traversing or verifying a Catena chain backwards.
pub const MAX_CATENA_HOPS: usize = 1000;

/// Pure in-memory structural verification of a bounded sequence of Catena anchors
/// starting at `expected_start_index`.
///
/// NOTE: This function trusts the caller-supplied `verified` and `confirmations` fields and
/// does not query a Bitcoin node. Use `RegtestAnchorClient::verify_catena_chain_bounded`
/// for blockchain-backed verification.
pub fn verify_catena_links_bounded(
    anchors: &[BitcoinAnchor],
    expected_start_index: u64,
    max_hops: usize,
) -> Result<bool, TransparencyError> {
    if anchors.is_empty() {
        return Err(TransparencyError::InvalidCatenaChain(
            "empty anchor sequence".into(),
        ));
    }
    if anchors.len() > max_hops {
        return Err(TransparencyError::InvalidCatenaChain(format!(
            "anchor sequence length ({}) exceeds maximum allowed hops ({max_hops})",
            anchors.len()
        )));
    }

    let first = &anchors[0];
    if first.chain_index != Some(expected_start_index) {
        return Err(TransparencyError::InvalidCatenaChain(format!(
            "first anchor must have chain_index {expected_start_index}, got {:?}",
            first.chain_index
        )));
    }
    if expected_start_index == 0 && (first.prev_txid.is_some() || first.prev_vout.is_some()) {
        return Err(TransparencyError::InvalidCatenaChain(
            "genesis anchor cannot have a predecessor UTXO".into(),
        ));
    }
    if first.continuation_vout != Some(CATENA_CONTINUATION_VOUT) {
        return Err(TransparencyError::InvalidCatenaChain(format!(
            "first anchor continuation_vout is {:?}, expected Some({CATENA_CONTINUATION_VOUT})",
            first.continuation_vout
        )));
    }
    if !first.verified || first.confirmations == 0 {
        return Err(TransparencyError::InvalidCatenaChain(
            "first anchor must be verified with at least 1 confirmation".into(),
        ));
    }

    for (i, pair) in anchors.windows(2).enumerate() {
        let prev = &pair[0];
        let curr = &pair[1];
        let expected_index = prev.chain_index.unwrap_or(expected_start_index) + 1;

        if curr.chain_index != Some(expected_index) {
            return Err(TransparencyError::InvalidCatenaChain(format!(
                "anchor at step {} has chain_index {:?}, expected {}",
                i + 1,
                curr.chain_index,
                expected_index
            )));
        }

        if curr.prev_txid.as_deref() != Some(prev.txid.as_str()) {
            return Err(TransparencyError::InvalidCatenaChain(format!(
                "anchor at step {} prev_txid ({:?}) does not match predecessor txid ({})",
                i + 1,
                curr.prev_txid,
                prev.txid
            )));
        }

        if curr.prev_vout != Some(CATENA_CONTINUATION_VOUT) {
            return Err(TransparencyError::InvalidCatenaChain(format!(
                "anchor at step {} prev_vout ({:?}) does not match fixed continuation_vout ({CATENA_CONTINUATION_VOUT})",
                i + 1,
                curr.prev_vout
            )));
        }

        if curr.continuation_vout != Some(CATENA_CONTINUATION_VOUT) {
            return Err(TransparencyError::InvalidCatenaChain(format!(
                "anchor at step {} continuation_vout is {:?}, expected Some({CATENA_CONTINUATION_VOUT})",
                i + 1,
                curr.continuation_vout
            )));
        }

        if !curr.verified || curr.confirmations == 0 {
            return Err(TransparencyError::InvalidCatenaChain(format!(
                "anchor at step {} is unverified or has 0 confirmations",
                i + 1
            )));
        }
    }

    Ok(true)
}

/// Pure cryptographic verification of an in-memory Catena anchor chain.
///
/// Ensures:
/// 1. The chain is non-empty and bounded by `MAX_CATENA_HOPS`.
/// 2. The first anchor is a valid genesis anchor (`chain_index == 0`, `prev_txid == None`, valid `continuation_vout`).
/// 3. For each consecutive pair `(A_{i-1}, A_i)`:
///    - `A_i.chain_index == A_{i-1}.chain_index + 1`
///    - `A_i.prev_txid == Some(A_{i-1}.txid)`
///    - `A_i.prev_vout == A_{i-1}.continuation_vout == CATENA_CONTINUATION_VOUT`
///    - `A_i.continuation_vout == Some(CATENA_CONTINUATION_VOUT)`
///    - `A_i.verified == true`
///    - `A_i.confirmations > 0`
pub fn verify_catena_links(anchors: &[BitcoinAnchor]) -> Result<bool, TransparencyError> {
    verify_catena_links_bounded(anchors, 0, MAX_CATENA_HOPS)
}

/// Verifies that each anchor in the sequence correctly commits to the corresponding checkpoint hash,
/// starting at `expected_start_index`.
pub fn verify_catena_commitments_bounded(
    anchors: &[BitcoinAnchor],
    checkpoint_hashes: &[&str],
    expected_start_index: u64,
) -> Result<bool, TransparencyError> {
    if anchors.len() != checkpoint_hashes.len() {
        return Err(TransparencyError::InvalidCatenaChain(format!(
            "anchor count ({}) does not match checkpoint hash count ({})",
            anchors.len(),
            checkpoint_hashes.len()
        )));
    }

    for (i, (anchor, &cp_hash)) in anchors.iter().zip(checkpoint_hashes.iter()).enumerate() {
        let expected_index = expected_start_index + i as u64;
        if anchor.chain_index != Some(expected_index) {
            return Err(TransparencyError::InvalidCatenaChain(format!(
                "anchor at step {} has unexpected chain index {:?}, expected Some({})",
                i, anchor.chain_index, expected_index
            )));
        }
        let expected_commitment = catena_commitment(cp_hash, expected_index)
            .map_err(|e| TransparencyError::InvalidCatenaChain(e.to_string()))?;

        if anchor.commitment != expected_commitment {
            return Err(TransparencyError::InvalidCatenaChain(format!(
                "anchor at step {} commitment ({}) does not match expected commitment ({}) for checkpoint hash {}",
                i, anchor.commitment, expected_commitment, cp_hash
            )));
        }
    }

    Ok(true)
}

/// Verifies that each anchor in the sequence correctly commits to the corresponding checkpoint hash.
///
/// Ensures:
/// 1. The number of anchors matches the number of checkpoint hashes.
/// 2. For each anchor `A_i` with `chain_index == i`, its commitment matches `catena_commitment(checkpoint_hash[i], i)`.
pub fn verify_catena_commitments(
    anchors: &[BitcoinAnchor],
    checkpoint_hashes: &[&str],
) -> Result<bool, TransparencyError> {
    verify_catena_commitments_bounded(anchors, checkpoint_hashes, 0)
}

/// Detect whether two anchors represent a candidate continuation conflict or equivocation attempt
/// (two conflicting transactions claiming to spend the same predecessor continuation UTXO).
pub fn detect_catena_equivocation(
    a1: &BitcoinAnchor,
    a2: &BitcoinAnchor,
) -> Option<CatenaEquivocationProof> {
    // Both must spend the same previous output
    let p_tx1 = a1.prev_txid.as_ref()?;
    let p_tx2 = a2.prev_txid.as_ref()?;
    let p_vout1 = a1.prev_vout?;
    let p_vout2 = a2.prev_vout?;

    if p_tx1 == p_tx2 && p_vout1 == p_vout2 && a1.txid != a2.txid {
        let index = a1.chain_index.or(a2.chain_index)?;
        return Some(CatenaEquivocationProof {
            chain_index: index,
            spent_txid: p_tx1.clone(),
            spent_vout: p_vout1,
            first_anchor: a1.clone(),
            second_anchor: a2.clone(),
            evidence: format!(
                "Candidate double-spend detected on continuation UTXO {p_tx1}:{p_vout1}: tx1={} (commitment={}) vs tx2={} (commitment={})",
                a1.txid, a1.commitment, a2.txid, a2.commitment
            ),
        });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_anchor(
        txid_byte: u8,
        chain_index: Option<u64>,
        prev_txid: Option<String>,
        prev_vout: Option<u32>,
        continuation_vout: Option<u32>,
        verified: bool,
        confirmations: u32,
    ) -> BitcoinAnchor {
        let hex_byte = format!("{txid_byte:02x}");
        let txid = hex_byte.repeat(32);
        let checkpoint_hash = "42".repeat(32);
        let commitment = catena_commitment(&checkpoint_hash, chain_index.unwrap_or(0)).unwrap();
        BitcoinAnchor {
            network: BitcoinNetwork::Regtest,
            txid,
            block_hash: Some("aa".repeat(32)),
            block_height: Some(100 + chain_index.unwrap_or(0)),
            confirmations,
            commitment,
            verified,
            prev_txid,
            prev_vout,
            continuation_vout,
            chain_index,
        }
    }

    #[test]
    fn test_catena_commitment_domain_separation_and_indexing() {
        let cp_a = "11".repeat(32);
        let cp_b = "22".repeat(32);

        let com_a0 = catena_commitment(&cp_a, 0).unwrap();
        let com_a1 = catena_commitment(&cp_a, 1).unwrap();
        let com_b0 = catena_commitment(&cp_b, 0).unwrap();

        // Same checkpoint hash at different indices MUST differ
        assert_ne!(com_a0, com_a1);
        // Different checkpoint hashes at same index MUST differ
        assert_ne!(com_a0, com_b0);
        // Deterministic
        assert_eq!(com_a0, catena_commitment(&cp_a, 0).unwrap());
    }

    #[test]
    fn test_valid_catena_chain_verification() {
        let a0 = make_test_anchor(0x10, Some(0), None, None, Some(1), true, 1);
        let a1 = make_test_anchor(
            0x11,
            Some(1),
            Some(a0.txid.clone()),
            Some(1),
            Some(1),
            true,
            1,
        );
        let a2 = make_test_anchor(
            0x12,
            Some(2),
            Some(a1.txid.clone()),
            Some(1),
            Some(1),
            true,
            2,
        );

        let chain = vec![a0, a1, a2];
        assert!(verify_catena_links(&chain).unwrap());
    }

    #[test]
    fn test_catena_verification_rejects_empty_chain() {
        let res = verify_catena_links(&[]);
        assert!(matches!(res, Err(TransparencyError::InvalidCatenaChain(_))));
    }

    #[test]
    fn test_catena_verification_rejects_non_zero_genesis() {
        let a0 = make_test_anchor(0x10, Some(1), None, None, Some(1), true, 1);
        let res = verify_catena_links(&[a0]);
        assert!(matches!(res, Err(TransparencyError::InvalidCatenaChain(_))));
    }

    #[test]
    fn test_catena_verification_rejects_index_gap() {
        let a0 = make_test_anchor(0x10, Some(0), None, None, Some(1), true, 1);
        // Index jumps from 0 to 2
        let a2 = make_test_anchor(
            0x12,
            Some(2),
            Some(a0.txid.clone()),
            Some(1),
            Some(1),
            true,
            1,
        );
        let res = verify_catena_links(&[a0, a2]);
        assert!(matches!(res, Err(TransparencyError::InvalidCatenaChain(_))));
    }

    #[test]
    fn test_catena_verification_rejects_mismatched_prev_txid() {
        let a0 = make_test_anchor(0x10, Some(0), None, None, Some(1), true, 1);
        let a1 = make_test_anchor(
            0x11,
            Some(1),
            Some("99".repeat(32)),
            Some(1),
            Some(1),
            true,
            1,
        );
        let res = verify_catena_links(&[a0, a1]);
        assert!(matches!(res, Err(TransparencyError::InvalidCatenaChain(_))));
    }

    #[test]
    fn test_catena_verification_rejects_mismatched_prev_vout() {
        let a0 = make_test_anchor(0x10, Some(0), None, None, Some(1), true, 1);
        let a1 = make_test_anchor(
            0x11,
            Some(1),
            Some(a0.txid.clone()),
            Some(2),
            Some(1),
            true,
            1,
        );
        let res = verify_catena_links(&[a0, a1]);
        assert!(matches!(res, Err(TransparencyError::InvalidCatenaChain(_))));
    }

    #[test]
    fn test_catena_verification_rejects_unverified_or_zero_confirmations() {
        let a0 = make_test_anchor(0x10, Some(0), None, None, Some(1), true, 1);
        let a1_unverified = make_test_anchor(
            0x11,
            Some(1),
            Some(a0.txid.clone()),
            Some(1),
            Some(1),
            false,
            1,
        );
        assert!(verify_catena_links(&[a0.clone(), a1_unverified]).is_err());

        let a1_unconfirmed = make_test_anchor(
            0x11,
            Some(1),
            Some(a0.txid.clone()),
            Some(1),
            Some(1),
            true,
            0,
        );
        assert!(verify_catena_links(&[a0, a1_unconfirmed]).is_err());
    }

    #[test]
    fn test_detect_catena_equivocation() {
        let a0 = make_test_anchor(0x10, Some(0), None, None, Some(1), true, 1);
        // Fork 1 at step 1
        let a1_fork1 = make_test_anchor(
            0x21,
            Some(1),
            Some(a0.txid.clone()),
            Some(1),
            Some(1),
            true,
            1,
        );
        // Fork 2 at step 1 (spending same a0 outpoint)
        let a1_fork2 = make_test_anchor(
            0x22,
            Some(1),
            Some(a0.txid.clone()),
            Some(1),
            Some(1),
            true,
            1,
        );

        let equivocation = detect_catena_equivocation(&a1_fork1, &a1_fork2);
        assert!(equivocation.is_some());
        let proof = equivocation.unwrap();
        assert_eq!(proof.chain_index, 1);
        assert_eq!(proof.spent_txid, a0.txid);
        assert_eq!(proof.spent_vout, 1);
        assert!(proof.evidence.contains("Candidate double-spend detected"));
    }

    #[test]
    fn test_verify_catena_commitments() {
        let cp0 = "00".repeat(32);
        let cp1 = "11".repeat(32);
        let cp2 = "22".repeat(32);

        let mut a0 = make_test_anchor(0x10, Some(0), None, None, Some(1), true, 1);
        a0.commitment = catena_commitment(&cp0, 0).unwrap();

        let mut a1 = make_test_anchor(
            0x11,
            Some(1),
            Some(a0.txid.clone()),
            Some(1),
            Some(1),
            true,
            1,
        );
        a1.commitment = catena_commitment(&cp1, 1).unwrap();

        let mut a2 = make_test_anchor(
            0x12,
            Some(2),
            Some(a1.txid.clone()),
            Some(1),
            Some(1),
            true,
            2,
        );
        a2.commitment = catena_commitment(&cp2, 2).unwrap();

        let chain = vec![a0, a1, a2];

        // Valid matching commitments
        assert!(verify_catena_commitments(&chain, &[&cp0, &cp1, &cp2]).unwrap());

        // Length mismatch
        assert!(verify_catena_commitments(&chain, &[&cp0, &cp1]).is_err());

        // Mismatched checkpoint hash
        let bad_cp2 = "33".repeat(32);
        assert!(verify_catena_commitments(&chain, &[&cp0, &cp1, &bad_cp2]).is_err());

        // Mismatched chain index
        let mut bad_index_chain = chain.clone();
        bad_index_chain[1].chain_index = Some(5);
        assert!(verify_catena_commitments(&bad_index_chain, &[&cp0, &cp1, &cp2]).is_err());
    }

    #[test]
    fn test_catena_verification_rejects_non_canonical_continuation_vout() {
        let a0 = make_test_anchor(0x10, Some(0), None, None, Some(1), true, 1);
        // Step 1 parent has continuation_vout 2 instead of canonical 1
        let a1_bad_parent = make_test_anchor(
            0x11,
            Some(1),
            Some(a0.txid.clone()),
            Some(1),
            Some(2),
            true,
            1,
        );
        let res = verify_catena_links(&[a0.clone(), a1_bad_parent]);
        assert!(matches!(res, Err(TransparencyError::InvalidCatenaChain(_))));

        // Step 2 attempts to spend prev_vout 2 instead of canonical 1
        let a1 = make_test_anchor(
            0x11,
            Some(1),
            Some(a0.txid.clone()),
            Some(1),
            Some(1),
            true,
            1,
        );
        let a2_bad_spend = make_test_anchor(
            0x12,
            Some(2),
            Some(a1.txid.clone()),
            Some(2),
            Some(1),
            true,
            1,
        );
        let res2 = verify_catena_links(&[a0, a1, a2_bad_spend]);
        assert!(matches!(
            res2,
            Err(TransparencyError::InvalidCatenaChain(_))
        ));
    }

    #[test]
    fn test_catena_bounded_verification() {
        let cp1 = "11".repeat(32);
        let cp2 = "22".repeat(32);

        let mut a1 = make_test_anchor(
            0x11,
            Some(1),
            Some("10".repeat(32)),
            Some(1),
            Some(1),
            true,
            1,
        );
        a1.commitment = catena_commitment(&cp1, 1).unwrap();

        let mut a2 = make_test_anchor(
            0x12,
            Some(2),
            Some(a1.txid.clone()),
            Some(1),
            Some(1),
            true,
            1,
        );
        a2.commitment = catena_commitment(&cp2, 2).unwrap();

        let subchain = vec![a1.clone(), a2.clone()];

        // Valid bounded link verification starting at index 1 with max_hops 2
        assert!(verify_catena_links_bounded(&subchain, 1, 2).unwrap());

        // Max hops exceeded
        assert!(matches!(
            verify_catena_links_bounded(&subchain, 1, 1),
            Err(TransparencyError::InvalidCatenaChain(_))
        ));

        // Wrong start index
        assert!(matches!(
            verify_catena_links_bounded(&subchain, 0, 5),
            Err(TransparencyError::InvalidCatenaChain(_))
        ));

        // Valid bounded commitment verification
        assert!(verify_catena_commitments_bounded(&subchain, &[&cp1, &cp2], 1).unwrap());

        // Wrong start index for commitments
        assert!(matches!(
            verify_catena_commitments_bounded(&subchain, &[&cp1, &cp2], 0),
            Err(TransparencyError::InvalidCatenaChain(_))
        ));
    }
}
