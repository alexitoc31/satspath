use std::collections::{HashMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};

use secp256k1::{PublicKey, Secp256k1, SecretKey};
use serde::{Deserialize, Serialize};

use crate::transparency::event::profile_hash;
use crate::{Result, SignedPaymentProfile};

use super::tree::inclusion_proof;
use super::{
    anchor_commitment, leaf_hash, merkle_root, verify_identifier_history, BitcoinAnchor,
    MerkleConsistencyProof, MerkleInclusionProof, NameAction, NameEvent, TransparencyCheckpoint,
    TransparencyError,
};

const EVENTS_FILE: &str = "transparency-events-v1.jsonl";
const CHECKPOINTS_FILE: &str = "transparency-checkpoints-v1.json";
const LOG_ID_FILE: &str = "transparency-log-id-v1";
pub const MAX_V1_CONSISTENCY_LEAVES: u64 = 16_384;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransparencyStatus {
    pub log_size: u64,
    pub log_root: String,
    pub latest_checkpoint_hash: Option<String>,
    pub registered_identifiers: u64,
    pub key_rotations: u64,
    #[serde(default)]
    pub key_recoveries: u64,
    pub revocations: u64,
    pub map_root: Option<String>,
    pub consistency_status: ConsistencyStatus,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsistencyStatus {
    Empty,
    Valid,
    Invalid,
    Unanchored,
}

#[derive(Clone)]
pub struct TransparencyLog {
    dir: PathBuf,
    log_id: String,
    events: Vec<NameEvent>,
    checkpoints: Vec<TransparencyCheckpoint>,
}

impl TransparencyLog {
    pub(crate) fn from_parts(
        dir: PathBuf,
        log_id: String,
        events: Vec<NameEvent>,
        checkpoints: Vec<TransparencyCheckpoint>,
    ) -> Result<Self> {
        let log = Self {
            dir,
            log_id,
            events,
            checkpoints,
        };
        log.verify_full_replay()?;
        Ok(log)
    }

    pub fn prepare_append(&self, event: NameEvent, profile: &SignedPaymentProfile) -> Result<Self> {
        if event.version != 1
            || event.profile_hash != profile_hash(profile)?
            || profile.profile.sequence != Some(event.sequence)
            || event.identity_pubkey != profile.profile.identity_pubkey
            || event.recovery_policy != profile.profile.recovery_policy
            || event.recovery != profile.profile.recovery
            || !crate::crypto::verify_signed_profile(profile)?
        {
            return Err(TransparencyError::ProfileHashMismatch.into());
        }
        let mut history: Vec<NameEvent> = self
            .history(&event.identifier_hash)
            .into_iter()
            .cloned()
            .collect();
        history.push(event.clone());
        verify_identifier_history(&history)?;
        let mut candidate = self.clone();
        candidate.events.push(event);
        Ok(candidate)
    }

    pub fn prepare_checkpoint(&self, operator_key: &SecretKey) -> Result<TransparencyCheckpoint> {
        if self.events.is_empty() {
            return Err(
                TransparencyError::CorruptStore("cannot checkpoint an empty log".into()).into(),
            );
        }
        let secp = Secp256k1::new();
        let operator_pubkey =
            hex::encode(PublicKey::from_secret_key(&secp, operator_key).serialize());
        let mut checkpoint = TransparencyCheckpoint {
            version: 1,
            log_id: self.log_id.clone(),
            log_size: self.events.len() as u64,
            log_root: hex::encode(merkle_root(&self.leaf_hashes(self.events.len())?)),
            map_root: Some(self.state_map_root()?),
            previous_checkpoint_hash: self
                .checkpoints
                .last()
                .map(TransparencyCheckpoint::checkpoint_hash)
                .transpose()?,
            created_at: chrono::Utc::now().timestamp(),
            operator_pubkey,
            operator_sequence: self.checkpoints.last().map_or(0, |c| c.operator_sequence),
            operator_rotation: None,
            operator_signature: String::new(),
            bitcoin_anchor: None,
        };
        checkpoint.sign(operator_key)?;
        Ok(checkpoint)
    }

    pub fn prepare_operator_rotation_checkpoint(
        &self,
        old_operator_key: &SecretKey,
        new_operator_key: &SecretKey,
    ) -> Result<TransparencyCheckpoint> {
        let previous = self
            .checkpoints
            .last()
            .ok_or(TransparencyError::InvalidOperatorRotation)?;
        if self.events.len() as u64 <= previous.log_size {
            return Err(TransparencyError::InvalidOperatorRotation.into());
        }
        let secp = Secp256k1::new();
        let expected_old =
            hex::encode(PublicKey::from_secret_key(&secp, old_operator_key).serialize());
        if expected_old != previous.operator_pubkey {
            return Err(TransparencyError::InvalidOperatorRotation.into());
        }
        let sequence = previous
            .operator_sequence
            .checked_add(1)
            .ok_or(TransparencyError::InvalidOperatorRotation)?;
        let previous_hash = previous.checkpoint_hash()?;
        let created_at = chrono::Utc::now().timestamp().max(previous.created_at);
        let rotation = super::OperatorKeyRotation::create(
            self.log_id.clone(),
            old_operator_key,
            new_operator_key,
            previous_hash.clone(),
            sequence,
            created_at,
        );
        let mut checkpoint = TransparencyCheckpoint {
            version: 1,
            log_id: self.log_id.clone(),
            log_size: self.events.len() as u64,
            log_root: self.prepare_checkpoint_pub_root()?,
            map_root: Some(self.state_map_root()?),
            previous_checkpoint_hash: Some(previous_hash),
            created_at,
            operator_pubkey: rotation.new_operator_pubkey.clone(),
            operator_sequence: sequence,
            operator_rotation: Some(rotation),
            operator_signature: String::new(),
            bitcoin_anchor: None,
        };
        checkpoint.sign(new_operator_key)?;
        Ok(checkpoint)
    }
    pub fn open(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let log_id_path = dir.join(LOG_ID_FILE);
        let log_id = if log_id_path.exists() {
            std::fs::read_to_string(&log_id_path)?.trim().to_owned()
        } else {
            let value = format!("satspath:local:{}", uuid::Uuid::new_v4());
            let tmp = log_id_path.with_extension("tmp");
            std::fs::write(&tmp, &value)?;
            std::fs::rename(tmp, &log_id_path)?;
            value
        };
        if log_id.is_empty() {
            return Err(TransparencyError::CorruptStore("empty log id".into()).into());
        }
        let events_path = dir.join(EVENTS_FILE);
        let events = if events_path.exists() {
            let raw = std::fs::read_to_string(&events_path)?;
            raw.lines()
                .enumerate()
                .filter(|(_, line)| !line.trim().is_empty())
                .map(|(i, line)| {
                    serde_json::from_str(line).map_err(|e| {
                        TransparencyError::CorruptStore(format!("event line {}: {e}", i + 1)).into()
                    })
                })
                .collect::<Result<Vec<_>>>()?
        } else {
            Vec::new()
        };
        let checkpoints_path = dir.join(CHECKPOINTS_FILE);
        let checkpoints = if checkpoints_path.exists() {
            serde_json::from_slice(&std::fs::read(checkpoints_path)?)
                .map_err(|e| TransparencyError::CorruptStore(format!("checkpoints: {e}")))?
        } else {
            Vec::new()
        };
        let log = Self {
            dir: dir.to_owned(),
            log_id,
            events,
            checkpoints,
        };
        log.verify_full_replay()?;
        Ok(log)
    }

    pub fn events(&self) -> &[NameEvent] {
        &self.events
    }
    pub fn checkpoints(&self) -> &[TransparencyCheckpoint] {
        &self.checkpoints
    }
    pub fn log_id(&self) -> &str {
        &self.log_id
    }
    pub(crate) fn prepare_checkpoint_pub_root(&self) -> Result<String> {
        Ok(hex::encode(merkle_root(
            &self.leaf_hashes(self.events.len())?,
        )))
    }

    pub fn event(&self, hash: &str) -> Result<Option<&NameEvent>> {
        for event in &self.events {
            if event.event_hash()? == hash {
                return Ok(Some(event));
            }
        }
        Ok(None)
    }

    pub fn history(&self, identifier_hash: &str) -> Vec<&NameEvent> {
        self.events
            .iter()
            .filter(|e| e.identifier_hash == identifier_hash)
            .collect()
    }

    pub fn append(&mut self, event: NameEvent, profile: &SignedPaymentProfile) -> Result<String> {
        let candidate = self.prepare_append(event.clone(), profile)?;
        let event_hash = event.event_hash()?;
        let encoded = serde_json::to_vec(&event)?;
        let path = self.dir.join(EVENTS_FILE);
        let mut file = OpenOptions::new().create(true).append(true).open(path)?;
        file.write_all(&encoded)?;
        file.write_all(b"\n")?;
        file.sync_all()?;
        self.events = candidate.events;
        Ok(event_hash)
    }

    pub fn leaf_hashes(&self, size: usize) -> Result<Vec<[u8; 32]>> {
        if size > self.events.len() {
            return Err(TransparencyError::InvalidConsistencyProof.into());
        }
        self.events[..size]
            .iter()
            .map(|e| {
                Ok(leaf_hash(&hex::decode(e.event_hash()?).map_err(|_| {
                    TransparencyError::CorruptStore("event hash".into())
                })?))
            })
            .collect()
    }

    pub fn inclusion(
        &self,
        event_hash: &str,
        tree_size: Option<u64>,
    ) -> Result<MerkleInclusionProof> {
        let size_u64 = tree_size.unwrap_or(self.events.len() as u64);
        if size_u64 == 0 || size_u64 > self.events.len() as u64 {
            return Err(TransparencyError::InvalidInclusionProof.into());
        }
        let size =
            usize::try_from(size_u64).map_err(|_| TransparencyError::InvalidInclusionProof)?;
        let index = self.events[..size]
            .iter()
            .position(|e| e.event_hash().ok().as_deref() == Some(event_hash))
            .ok_or(TransparencyError::InvalidInclusionProof)?;
        inclusion_proof(&self.leaf_hashes(size)?, index).map_err(Into::into)
    }

    pub fn consistency(&self, old_size: u64, new_size: u64) -> Result<MerkleConsistencyProof> {
        if old_size == 0 || old_size > new_size || new_size > self.events.len() as u64 {
            return Err(TransparencyError::InvalidConsistencyProof.into());
        }
        let leaves = self.leaf_hashes(new_size as usize)?;
        let path = super::tree::consistency_proof(&leaves, old_size as usize)?;
        Ok(MerkleConsistencyProof {
            version: 2,
            old_tree_size: old_size,
            new_tree_size: new_size,
            old_root: hex::encode(merkle_root(&leaves[..old_size as usize])),
            new_root: hex::encode(merkle_root(&leaves)),
            audit_path: path.iter().map(hex::encode).collect(),
        })
    }

    pub fn state_map(&self) -> Result<super::SparseMerkleTree> {
        let mut tree = super::SparseMerkleTree::new();
        for event in &self.events {
            let event_hash = event.event_hash()?;
            let status = match event.action {
                NameAction::Register
                | NameAction::UpdateProfile
                | NameAction::RotateKey
                | NameAction::RecoverKey => super::IdentifierStatus::Registered,
                NameAction::Revoke => super::IdentifierStatus::Revoked,
            };
            let value = super::StateMapValue {
                latest_event_hash: event_hash,
                sequence: event.sequence,
                status,
            };
            tree.insert_hex(&event.identifier_hash, value)?;
        }
        Ok(tree)
    }

    pub fn state_map_root(&self) -> Result<String> {
        Ok(self.state_map()?.root_hex())
    }

    pub fn prove_state(&self, identifier_hash: &str) -> Result<super::StateMapProof> {
        self.state_map()?.prove_hex(identifier_hash)
    }

    pub fn create_checkpoint(
        &mut self,
        operator_key: &SecretKey,
    ) -> Result<TransparencyCheckpoint> {
        let checkpoint = self.prepare_checkpoint(operator_key)?;
        self.checkpoints.push(checkpoint.clone());
        self.save_checkpoints()?;
        Ok(checkpoint)
    }

    pub fn attach_latest_anchor(
        &mut self,
        anchor: BitcoinAnchor,
        operator_key: &SecretKey,
    ) -> Result<TransparencyCheckpoint> {
        let checkpoint = self
            .checkpoints
            .last_mut()
            .ok_or_else(|| TransparencyError::CorruptStore("no checkpoint to anchor".into()))?;
        if anchor.network != crate::BitcoinNetwork::Regtest
            || anchor.commitment
                != anchor_commitment(&checkpoint.checkpoint_hash()?)
                    .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?
        {
            return Err(TransparencyError::CorruptStore(
                "anchor commitment or network mismatch".into(),
            )
            .into());
        }
        checkpoint.bitcoin_anchor = Some(anchor);
        checkpoint.sign(operator_key)?;
        let result = checkpoint.clone();
        self.save_checkpoints()?;
        Ok(result)
    }

    pub fn status(&self) -> Result<TransparencyStatus> {
        let leaves = self.leaf_hashes(self.events.len())?;
        let registered: HashSet<_> = self
            .events
            .iter()
            .filter(|e| e.action == NameAction::Register)
            .map(|e| &e.identifier_hash)
            .collect();
        Ok(TransparencyStatus {
            log_size: self.events.len() as u64,
            log_root: hex::encode(merkle_root(&leaves)),
            latest_checkpoint_hash: self
                .checkpoints
                .last()
                .map(TransparencyCheckpoint::checkpoint_hash)
                .transpose()?,
            registered_identifiers: registered.len() as u64,
            key_rotations: self
                .events
                .iter()
                .filter(|e| e.action == NameAction::RotateKey)
                .count() as u64,
            key_recoveries: self
                .events
                .iter()
                .filter(|e| e.action == NameAction::RecoverKey)
                .count() as u64,
            revocations: self
                .events
                .iter()
                .filter(|e| e.action == NameAction::Revoke)
                .count() as u64,
            map_root: Some(self.state_map_root()?),
            consistency_status: if self.checkpoints.is_empty() {
                ConsistencyStatus::Empty
            } else if self
                .checkpoints
                .last()
                .is_some_and(|c| c.bitcoin_anchor.is_none())
            {
                ConsistencyStatus::Unanchored
            } else {
                ConsistencyStatus::Valid
            },
        })
    }

    pub fn verify_full_replay(&self) -> Result<()> {
        let mut histories: HashMap<&str, Vec<NameEvent>> = HashMap::new();
        for event in &self.events {
            histories
                .entry(&event.identifier_hash)
                .or_default()
                .push(event.clone());
        }
        for history in histories.values() {
            verify_identifier_history(history)?;
        }
        let mut previous: Option<&TransparencyCheckpoint> = None;
        let mut seen_sizes: HashMap<u64, String> = HashMap::new();
        for checkpoint in &self.checkpoints {
            if checkpoint.log_id != self.log_id
                || !super::verify_checkpoint(checkpoint)?
                || checkpoint.log_size > self.events.len() as u64
            {
                return Err(TransparencyError::CorruptCheckpointChain(
                    "invalid checkpoint structure, signature, log id, or size".into(),
                )
                .into());
            }
            let leaves = self.leaf_hashes(checkpoint.log_size as usize)?;
            if checkpoint.log_root != hex::encode(merkle_root(&leaves)) {
                return Err(TransparencyError::CorruptCheckpointChain(
                    "checkpoint root does not match exact event prefix".into(),
                )
                .into());
            }
            let hash = checkpoint.checkpoint_hash()?;
            if let Some(other) = seen_sizes.insert(checkpoint.log_size, hash.clone()) {
                if other != hash {
                    return Err(TransparencyError::CorruptCheckpointChain(
                        "conflicting checkpoint at same tree size".into(),
                    )
                    .into());
                }
            }
            match previous {
                None if checkpoint.previous_checkpoint_hash.is_some()
                    || checkpoint.operator_sequence != 0 =>
                {
                    return Err(TransparencyError::CorruptCheckpointChain(
                        "invalid initial checkpoint".into(),
                    )
                    .into());
                }
                Some(prior) => {
                    let prior_hash = prior.checkpoint_hash()?;
                    if checkpoint.log_size < prior.log_size
                        || checkpoint.created_at < prior.created_at
                        || checkpoint.previous_checkpoint_hash.as_deref()
                            != Some(prior_hash.as_str())
                    {
                        return Err(TransparencyError::CorruptCheckpointChain(
                            "rollback, timestamp rollback, or broken predecessor".into(),
                        )
                        .into());
                    }
                    let pin = super::PinnedCheckpoint {
                        log_id: prior.log_id.clone(),
                        operator_pubkey: prior.operator_pubkey.clone(),
                        operator_sequence: prior.operator_sequence,
                        tree_size: prior.log_size,
                        root_hash: prior.log_root.clone(),
                        checkpoint_hash: prior_hash,
                        first_seen_at: prior.created_at,
                        last_seen_at: prior.created_at,
                    };
                    let consistency = if prior.log_size < checkpoint.log_size {
                        Some(self.consistency(prior.log_size, checkpoint.log_size)?)
                    } else {
                        None
                    };
                    super::verify_checkpoint_transition(&pin, checkpoint, consistency.as_ref())?;
                }
                _ => {}
            }
            if let Some(anchor) = &checkpoint.bitcoin_anchor {
                if anchor.network != crate::BitcoinNetwork::Regtest
                    || anchor.commitment
                        != anchor_commitment(&checkpoint.checkpoint_hash()?)
                            .map_err(|e| TransparencyError::CorruptCheckpointChain(e.to_string()))?
                {
                    return Err(TransparencyError::CorruptCheckpointChain(
                        "invalid anchor commitment or disallowed network".into(),
                    )
                    .into());
                }
            }
            previous = Some(checkpoint);
        }
        Ok(())
    }

    fn save_checkpoints(&self) -> Result<()> {
        let path = self.dir.join(CHECKPOINTS_FILE);
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(&self.checkpoints)?)?;
        std::fs::rename(tmp, path)?;
        Ok(())
    }
}
