#![no_main]

use libfuzzer_sys::fuzz_target;
use satspath_core::transparency::{
    inclusion_proof, leaf_hash, verify_consistency_proof, verify_inclusion_proof,
    MerkleConsistencyProof, MerkleInclusionProof,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(proof) = serde_json::from_slice::<MerkleInclusionProof>(data) {
        let _ = verify_inclusion_proof(&proof);
    }
    if let Ok(proof) = serde_json::from_slice::<MerkleConsistencyProof>(data) {
        let _ = verify_consistency_proof(&proof);
    }
    // Construct *valid* Merkle proofs from arbitrary leaves, then mutate the
    // root. The mutated proof may never be accepted as inclusion evidence.
    let leaves: Vec<_> = data.chunks(32).take(16).map(leaf_hash).collect();
    if !leaves.is_empty() {
        let index = usize::from(data[0]) % leaves.len();
        let proof = inclusion_proof(&leaves, index).unwrap();
        assert!(verify_inclusion_proof(&proof).unwrap());
        let mut corrupted = proof;
        let mut root = hex::decode(&corrupted.root_hash).unwrap();
        root[0] ^= 1;
        corrupted.root_hash = hex::encode(root);
        assert!(!verify_inclusion_proof(&corrupted).unwrap_or(false));
    }
});
