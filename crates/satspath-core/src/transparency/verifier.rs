use crate::crypto::{verify_message_signature, verify_signed_profile};
use crate::{Result, SignedPaymentProfile};

use super::event::profile_hash;
use super::tree::{leaf_hash, merkle_root, node_hash};
use super::{
    MerkleConsistencyProof, MerkleInclusionProof, NameAction, NameEvent, PinnedCheckpoint,
    TransparencyCheckpoint, TransparencyError,
};

fn decode_hash(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).map_err(|_| TransparencyError::InvalidInclusionProof)?;
    bytes
        .try_into()
        .map_err(|_| TransparencyError::InvalidInclusionProof.into())
}

pub fn verify_inclusion_proof(proof: &MerkleInclusionProof) -> Result<bool> {
    if proof.tree_size == 0 || proof.leaf_index >= proof.tree_size {
        return Err(TransparencyError::InvalidInclusionProof.into());
    }
    let mut hash = decode_hash(&proof.leaf_hash)?;
    let mut index = proof.leaf_index;
    let mut last = proof.tree_size - 1;
    for sibling_hex in &proof.audit_path {
        let sibling = decode_hash(sibling_hex)?;
        if index % 2 == 1 || index == last {
            hash = node_hash(&sibling, &hash);
            while index.is_multiple_of(2) && index != 0 {
                index /= 2;
                last /= 2;
            }
        } else {
            hash = node_hash(&hash, &sibling);
        }
        index /= 2;
        last /= 2;
    }
    Ok(hex::encode(hash) == proof.root_hash && last == 0)
}

pub fn verify_consistency_proof(proof: &MerkleConsistencyProof) -> Result<bool> {
    if proof.old_tree_size == 0 || proof.old_tree_size > proof.new_tree_size {
        return Err(TransparencyError::InvalidConsistencyProof.into());
    }

    let leaves_or_nodes: Vec<[u8; 32]> = proof
        .audit_path
        .iter()
        .map(|h| decode_hash(h))
        .collect::<Result<_>>()?;

    let old_root_bytes = decode_hash(&proof.old_root)?;
    let new_root_bytes = decode_hash(&proof.new_root)?;

    if proof.version == 1 {
        if proof.new_tree_size > super::log::MAX_V1_CONSISTENCY_LEAVES {
            return Err(TransparencyError::InvalidConsistencyProof.into());
        }
        if proof.audit_path.len() != proof.new_tree_size as usize {
            return Err(TransparencyError::InvalidConsistencyProof.into());
        }
        Ok(
            merkle_root(&leaves_or_nodes[..proof.old_tree_size as usize]) == old_root_bytes
                && merkle_root(&leaves_or_nodes) == new_root_bytes,
        )
    } else if proof.version == 2 {
        super::tree::verify_consistency(
            proof.old_tree_size,
            proof.new_tree_size,
            &old_root_bytes,
            &new_root_bytes,
            &leaves_or_nodes,
        )
        .map_err(Into::into)
    } else {
        Err(TransparencyError::InvalidConsistencyProof.into())
    }
}

pub fn verify_checkpoint(checkpoint: &TransparencyCheckpoint) -> Result<bool> {
    if checkpoint.version != 1
        || checkpoint.log_id.is_empty()
        || checkpoint.log_size == 0
        || decode_hash(&checkpoint.log_root).is_err()
        || checkpoint.operator_pubkey.len() != 66
    {
        return Ok(false);
    }
    if let Some(map_root) = &checkpoint.map_root {
        if decode_hash(map_root).is_err() {
            return Ok(false);
        }
    }
    verify_message_signature(
        &checkpoint.signing_message()?,
        &checkpoint.operator_signature,
        &checkpoint.operator_pubkey,
    )
}

pub fn verify_state_map_proof(proof: &super::StateMapProof, expected_root: &str) -> Result<bool> {
    proof.verify(expected_root)
}

pub fn verify_checkpoint_state_binding(
    proof: &super::StateMapProof,
    checkpoint: &TransparencyCheckpoint,
) -> Result<()> {
    if !verify_checkpoint(checkpoint)? {
        return Err(TransparencyError::InvalidCheckpointSignature.into());
    }
    let map_root = checkpoint
        .map_root
        .as_deref()
        .ok_or_else(|| TransparencyError::CorruptStore("checkpoint missing map_root".into()))?;

    if !proof.verify(map_root)? {
        return Err(TransparencyError::CheckpointInclusionMismatch.into());
    }
    Ok(())
}

pub fn verify_checkpoint_inclusion(
    event_hash: &str,
    proof: &MerkleInclusionProof,
    checkpoint: &TransparencyCheckpoint,
) -> Result<()> {
    let event =
        decode_hash(event_hash).map_err(|_| TransparencyError::CheckpointInclusionMismatch)?;
    let expected_leaf = hex::encode(leaf_hash(&event));
    if !verify_checkpoint(checkpoint)?
        || proof.root_hash != checkpoint.log_root
        || proof.tree_size != checkpoint.log_size
        || proof.leaf_hash != expected_leaf
        || !verify_inclusion_proof(proof)?
    {
        return Err(TransparencyError::CheckpointInclusionMismatch.into());
    }
    Ok(())
}

pub fn verify_checkpoint_transition(
    pinned: &PinnedCheckpoint,
    current: &TransparencyCheckpoint,
    consistency: Option<&MerkleConsistencyProof>,
) -> Result<()> {
    if !verify_checkpoint(current)? || current.log_id != pinned.log_id {
        return Err(TransparencyError::InvalidCheckpointSignature.into());
    }
    if current.operator_pubkey != pinned.operator_pubkey {
        let rotation = current
            .operator_rotation
            .as_ref()
            .ok_or(TransparencyError::UnexpectedOperatorKey)?;
        if rotation.log_id != pinned.log_id
            || rotation.previous_operator_pubkey != pinned.operator_pubkey
            || rotation.new_operator_pubkey != current.operator_pubkey
            || rotation.previous_checkpoint_hash != pinned.checkpoint_hash
            || rotation.sequence != pinned.operator_sequence.saturating_add(1)
            || current.operator_sequence != rotation.sequence
            || !rotation.verify()?
        {
            return Err(TransparencyError::InvalidOperatorRotation.into());
        }
    } else if current.operator_sequence != pinned.operator_sequence
        || current.operator_rotation.is_some()
    {
        return Err(TransparencyError::InvalidOperatorRotation.into());
    }
    if current.log_size < pinned.tree_size {
        return Err(TransparencyError::CheckpointRollback.into());
    }
    if current.log_size == pinned.tree_size {
        if current.log_root != pinned.root_hash {
            return Err(TransparencyError::ConflictingCheckpoint.into());
        }
        return Ok(());
    }
    let proof = consistency.ok_or(TransparencyError::InvalidConsistencyProof)?;
    if proof.old_tree_size != pinned.tree_size
        || proof.new_tree_size != current.log_size
        || proof.old_root != pinned.root_hash
        || proof.new_root != current.log_root
        || !verify_consistency_proof(proof)?
    {
        return Err(TransparencyError::InvalidConsistencyProof.into());
    }
    Ok(())
}

pub fn verify_identifier_history(events: &[NameEvent]) -> Result<()> {
    if events.is_empty() || events[0].action != NameAction::Register || events[0].sequence != 0 {
        return Err(TransparencyError::BrokenIdentifierHistory(
            "history must start at registration sequence 0".into(),
        )
        .into());
    }
    let identifier = &events[0].identifier_hash;
    let mut authorized_key = events[0].identity_pubkey.clone();
    let mut active_recovery_policy: Option<crate::recovery::RecoveryPolicy> = None;
    let mut previous_hash: Option<String> = None;
    let mut revoked = false;
    for (index, event) in events.iter().enumerate() {
        if &event.identifier_hash != identifier || event.sequence != index as u64 {
            return Err(TransparencyError::BrokenIdentifierHistory(
                "identifier substitution or sequence rollback".into(),
            )
            .into());
        }
        if event.previous_event_hash != previous_hash {
            return Err(TransparencyError::BrokenIdentifierHistory(
                "previous event hash mismatch".into(),
            )
            .into());
        }
        if revoked {
            return Err(TransparencyError::IdentifierRevoked.into());
        }
        if event.action == NameAction::RecoverKey && event.rotation.is_some() {
            return Err(TransparencyError::InvalidRecovery(
                "recovery event must not contain a key rotation".into(),
            )
            .into());
        }
        if event.action != NameAction::RecoverKey && event.recovery.is_some() {
            return Err(TransparencyError::InvalidRecovery(
                "recovery proof is only permitted on RecoverKey events".into(),
            )
            .into());
        }
        if event.action != NameAction::RotateKey && event.rotation.is_some() {
            return Err(TransparencyError::InvalidRotation(
                "rotation proof is only permitted on RotateKey events".into(),
            )
            .into());
        }
        let signing_key = if event.action == NameAction::RecoverKey {
            let policy = active_recovery_policy
                .as_ref()
                .ok_or(TransparencyError::RecoveryDisabled)?;
            let recovery = event.recovery.as_ref().ok_or_else(|| {
                TransparencyError::InvalidRecovery("missing recovery proof".into())
            })?;
            if recovery.previous_pubkey != authorized_key
                || recovery.new_pubkey != event.identity_pubkey
                || recovery.identifier_hash != event.identifier_hash
                || recovery.previous_event_hash
                    != event.previous_event_hash.clone().unwrap_or_default()
                || recovery.sequence != event.sequence
                || !recovery.verify(policy)?
            {
                return Err(TransparencyError::InvalidRecovery(
                    "guardian authorization or new acceptance failed".into(),
                )
                .into());
            }
            event.identity_pubkey.clone()
        } else if event.action == NameAction::RotateKey {
            let rotation = event
                .rotation
                .as_ref()
                .ok_or_else(|| TransparencyError::InvalidRotation("missing dual proof".into()))?;
            if rotation.previous_pubkey != authorized_key
                || rotation.new_pubkey != event.identity_pubkey
                || rotation.identifier_hash != event.identifier_hash
                || rotation.previous_event_hash
                    != event.previous_event_hash.clone().unwrap_or_default()
                || rotation.sequence != event.sequence
                || !rotation.verify()?
            {
                return Err(TransparencyError::InvalidRotation(
                    "old authorization or new acceptance failed".into(),
                )
                .into());
            }
            authorized_key.clone()
        } else {
            if event.identity_pubkey != authorized_key {
                return Err(TransparencyError::UnauthorizedKeyReplacement.into());
            }
            authorized_key.clone()
        };
        if !verify_message_signature(
            &event.signing_message()?,
            &event.owner_signature,
            &signing_key,
        )? {
            return Err(TransparencyError::InvalidEventSignature.into());
        }
        if let Some(policy) = &event.recovery_policy {
            policy.validate()?;
            active_recovery_policy = Some(policy.clone());
        }
        if event.action == NameAction::RotateKey || event.action == NameAction::RecoverKey {
            authorized_key = event.identity_pubkey.clone();
        }
        revoked = event.action == NameAction::Revoke;
        previous_hash = Some(event.event_hash()?);
    }
    Ok(())
}

pub fn verify_key_continuity(events: &[NameEvent]) -> Result<bool> {
    verify_identifier_history(events)?;
    Ok(true)
}

/// Validate an incremental transition between two adjacent events for an identifier,
/// with an explicit active recovery policy.
///
/// NOTE: Full historical validation including recovery policy retention across
/// updates that set `recovery_policy: None` must use `verify_identifier_history`
/// (or `TransparencyLog::prepare_append`).
pub fn verify_event_transition_with_policy(
    head: Option<&NameEvent>,
    proposed: &NameEvent,
    active_recovery_policy: Option<&crate::recovery::RecoveryPolicy>,
) -> Result<()> {
    if proposed.action == NameAction::RecoverKey && proposed.rotation.is_some() {
        return Err(TransparencyError::InvalidRecovery(
            "recovery event must not contain a key rotation".into(),
        )
        .into());
    }
    if proposed.action != NameAction::RecoverKey && proposed.recovery.is_some() {
        return Err(TransparencyError::InvalidRecovery(
            "recovery proof is only permitted on RecoverKey events".into(),
        )
        .into());
    }
    if proposed.action != NameAction::RotateKey && proposed.rotation.is_some() {
        return Err(TransparencyError::InvalidRotation(
            "rotation proof is only permitted on RotateKey events".into(),
        )
        .into());
    }

    match head {
        None => {
            if proposed.action != NameAction::Register || proposed.sequence != 0 {
                return Err(TransparencyError::BrokenIdentifierHistory(
                    "genesis event must be a Register action with sequence 0".into(),
                )
                .into());
            }
            if proposed.previous_event_hash.is_some() {
                return Err(TransparencyError::BrokenIdentifierHistory(
                    "genesis event cannot have a previous_event_hash".into(),
                )
                .into());
            }
        }
        Some(head_event) => {
            if proposed.identifier_hash != head_event.identifier_hash {
                return Err(TransparencyError::BrokenIdentifierHistory(
                    "identifier substitution".into(),
                )
                .into());
            }
            if proposed.sequence != head_event.sequence + 1 {
                return Err(TransparencyError::BrokenIdentifierHistory(
                    "sequence must advance exactly once".into(),
                )
                .into());
            }
            if proposed.previous_event_hash != Some(head_event.event_hash()?) {
                return Err(TransparencyError::BrokenIdentifierHistory(
                    "previous event hash mismatch (compare-and-set violation)".into(),
                )
                .into());
            }
            if head_event.action == NameAction::Revoke {
                return Err(TransparencyError::IdentifierRevoked.into());
            }

            let signing_key = if proposed.action == NameAction::RecoverKey {
                let policy = active_recovery_policy.ok_or(TransparencyError::RecoveryDisabled)?;
                let recovery = proposed.recovery.as_ref().ok_or_else(|| {
                    TransparencyError::InvalidRecovery("missing recovery proof".into())
                })?;

                if recovery.previous_pubkey != head_event.identity_pubkey
                    || recovery.new_pubkey != proposed.identity_pubkey
                    || recovery.identifier_hash != proposed.identifier_hash
                    || recovery.previous_event_hash
                        != proposed.previous_event_hash.clone().unwrap_or_default()
                    || recovery.sequence != proposed.sequence
                    || !recovery.verify(policy)?
                {
                    return Err(TransparencyError::InvalidRecovery(
                        "guardian authorization or new acceptance failed".into(),
                    )
                    .into());
                }
                proposed.identity_pubkey.clone()
            } else if proposed.action == NameAction::RotateKey {
                let rotation = proposed.rotation.as_ref().ok_or_else(|| {
                    TransparencyError::InvalidRotation("missing dual proof".into())
                })?;

                if rotation.previous_pubkey != head_event.identity_pubkey
                    || rotation.new_pubkey != proposed.identity_pubkey
                    || rotation.identifier_hash != proposed.identifier_hash
                    || rotation.previous_event_hash
                        != proposed.previous_event_hash.clone().unwrap_or_default()
                    || rotation.sequence != proposed.sequence
                    || !rotation.verify()?
                {
                    return Err(TransparencyError::InvalidRotation(
                        "old authorization or new acceptance failed".into(),
                    )
                    .into());
                }
                head_event.identity_pubkey.clone()
            } else {
                if proposed.identity_pubkey != head_event.identity_pubkey {
                    return Err(TransparencyError::UnauthorizedKeyReplacement.into());
                }
                head_event.identity_pubkey.clone()
            };

            if !verify_message_signature(
                &proposed.signing_message()?,
                &proposed.owner_signature,
                &signing_key,
            )? {
                return Err(TransparencyError::InvalidEventSignature.into());
            }

            if let Some(policy) = &proposed.recovery_policy {
                policy.validate()?;
            }
        }
    }

    if head.is_none() {
        if proposed.action == NameAction::RecoverKey {
            return Err(TransparencyError::RecoveryDisabled.into());
        }
        if let Some(policy) = &proposed.recovery_policy {
            policy.validate()?;
        }
        if !verify_message_signature(
            &proposed.signing_message()?,
            &proposed.owner_signature,
            &proposed.identity_pubkey,
        )? {
            return Err(TransparencyError::InvalidEventSignature.into());
        }
    }

    Ok(())
}

/// Validate an incremental transition between two adjacent events for an identifier.
///
/// NOTE: Full historical validation including recovery policy retention across
/// updates that set `recovery_policy: None` must use `verify_identifier_history`
/// (or `TransparencyLog::prepare_append`). When checking an isolated single-step
/// transition, `head.recovery_policy` is evaluated as the active policy.
pub fn verify_event_transition(head: Option<&NameEvent>, proposed: &NameEvent) -> Result<()> {
    let active_policy = head.and_then(|h| h.recovery_policy.as_ref());
    verify_event_transition_with_policy(head, proposed, active_policy)
}

pub fn next_identifier_sequence(
    existing_profile: Option<&SignedPaymentProfile>,
    history: &[NameEvent],
) -> Result<u64> {
    match (existing_profile, history.last()) {
        (None, None) => Ok(0),
        (None, Some(_)) | (Some(_), None) => Err(TransparencyError::BrokenIdentifierHistory(
            "registry profile and transparency history are misaligned".into(),
        )
        .into()),
        (Some(profile), Some(latest)) => {
            verify_identifier_history(history)?;
            let profile_sequence = profile.profile.sequence.ok_or_else(|| {
                TransparencyError::BrokenIdentifierHistory("profile sequence is missing".into())
            })?;
            if profile_sequence != latest.sequence
                || latest.profile_hash != profile_hash(profile)?
                || latest.identity_pubkey != profile.profile.identity_pubkey
            {
                return Err(TransparencyError::BrokenIdentifierHistory(
                    "latest profile does not match latest event sequence/hash/key".into(),
                )
                .into());
            }
            latest.sequence.checked_add(1).ok_or_else(|| {
                TransparencyError::BrokenIdentifierHistory("sequence overflow".into()).into()
            })
        }
    }
}

pub fn verify_event_profile(event: &NameEvent, profile: &SignedPaymentProfile) -> Result<bool> {
    if event.profile_hash != profile_hash(profile)?
        || event.identity_pubkey != profile.profile.identity_pubkey
    {
        return Err(TransparencyError::ProfileHashMismatch.into());
    }
    verify_signed_profile(profile)
}
