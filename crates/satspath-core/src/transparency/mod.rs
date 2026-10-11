mod anchor;
mod api;
mod attestation;
mod checkpoint;
#[cfg(feature = "std")]
mod database;
mod event;
mod gossip;
mod log;
mod migration;
mod proof;
mod protocol;
mod replication;
mod resolver;
mod state_map;
mod status;
mod store;
mod tree;
mod verifier;

#[cfg(test)]
mod consistency_tests;

#[cfg(feature = "std")]
pub use anchor::RegtestAnchorClient;
pub use anchor::{anchor_commitment, BitcoinAnchor, MockAnchorClient};
pub use api::{
    MutationChallengeRequest, MutationChallengeResponse, MutationResponse, MutationStatus,
    MutationSubmitRequest,
};
pub use attestation::{
    verify_attestation_binding, IdentifierAttestation, IdentifierVerificationMethod,
    TrustedVerifier,
};
pub use checkpoint::{
    CheckpointComparison, OperatorKeyRotation, PinnedCheckpoint, TransparencyCheckpoint,
    TransparencyLogIdentity,
};
#[cfg(feature = "std")]
pub use database::TransactionalTransparencyStore;
pub use event::{payment_method_descriptor_hash, profile_hash, NameAction, NameEvent};
pub use gossip::{
    compare_gossip_observations, gossip_topic, GossipComparison, GossipObservation,
    SplitViewEvidence, GOSSIP_FUTURE_SKEW_SECS, GOSSIP_KIND, GOSSIP_MAX_AGE_SECS, MAX_GOSSIP_BYTES,
};
pub use log::{ConsistencyStatus, TransparencyLog, TransparencyStatus};
pub use migration::{verify_migration_statement, MigrationExport, MigrationStatement};
pub use proof::{MerkleConsistencyProof, MerkleInclusionProof};
pub use protocol::{
    witness_cosignature_message, EndpointRole, NamespaceDescriptor, ReplicaEndpoint,
    ResolutionEnvelope, ResolutionRequest, WitnessCosignature,
};
pub use replication::{
    detect_equivocation, select_endpoint, validate_no_rollback, ReplicaHealth,
    MAX_STALENESS_WINDOW_SECS,
};
pub use resolver::{
    verify_namespace_binding, verify_witness_quorum, verify_witness_quorum_against_checkpoint,
    DimensionStatus, VerificationDimensions, VerifiedResolution,
};
pub use state_map::{
    empty_hash, smt_leaf_hash, smt_node_hash, IdentifierStatus, SparseMerkleTree, StateMapProof,
    StateMapValue,
};
pub use status::{S2SErrorCode, VerificationStatus};
pub use store::CheckpointStore;
pub use tree::{consistency_proof, leaf_hash, merkle_root, node_hash, verify_consistency};
pub use verifier::{
    next_identifier_sequence, verify_checkpoint, verify_checkpoint_inclusion,
    verify_checkpoint_state_binding, verify_checkpoint_transition, verify_consistency_proof,
    verify_event_profile, verify_event_transition, verify_event_transition_with_policy,
    verify_identifier_history, verify_inclusion_proof, verify_key_continuity,
    verify_state_map_proof,
};

use thiserror::Error;

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TransparencyError {
    #[error("conflicting checkpoint for the same operator and tree size")]
    ConflictingCheckpoint,
    #[error("checkpoint rollback detected")]
    CheckpointRollback,
    #[error("invalid checkpoint signature")]
    InvalidCheckpointSignature,
    #[error("invalid consistency proof")]
    InvalidConsistencyProof,
    #[error("invalid inclusion proof")]
    InvalidInclusionProof,
    #[error("inclusion proof is not bound to the signed checkpoint")]
    CheckpointInclusionMismatch,
    #[error("unexpected transparency operator key")]
    UnexpectedOperatorKey,
    #[error("invalid transparency operator rotation")]
    InvalidOperatorRotation,
    #[error("corrupt checkpoint chain: {0}")]
    CorruptCheckpointChain(String),
    #[error("broken identifier history: {0}")]
    BrokenIdentifierHistory(String),
    #[error("unauthorized key replacement")]
    UnauthorizedKeyReplacement,
    #[error("invalid rotation: {0}")]
    InvalidRotation(String),
    #[error("profile hash mismatch")]
    ProfileHashMismatch,
    #[error("invalid event signature")]
    InvalidEventSignature,
    #[error("duplicate registration")]
    DuplicateRegistration,
    #[error("identifier is revoked")]
    IdentifierRevoked,
    #[error("recovery is disabled")]
    RecoveryDisabled,
    #[error("invalid key recovery: {0}")]
    InvalidRecovery(String),
    #[error("corrupt transparency store: {0}")]
    CorruptStore(String),
    #[error("invalid identifier attestation: {0}")]
    InvalidAttestation(String),
    #[error("invalid checkpoint gossip observation or evidence")]
    InvalidGossipObservation,
}
