use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};

use crate::privacy::{canonical_identifier, identifier_hash};
use crate::registry::Registry;
use crate::{Result, SatsPathError, SignedPaymentProfile};

use super::{
    IdentifierAttestation, NameEvent, TransparencyCheckpoint, TransparencyError, TransparencyLog,
};

const DB_FILE: &str = "satspath-transparency-v1.sqlite3";

fn db_error(error: impl std::fmt::Display) -> SatsPathError {
    SatsPathError::RegistryError(format!("transparency database: {error}"))
}

pub struct TransactionalTransparencyStore {
    home: PathBuf,
    path: PathBuf,
    log_id: String,
    read_only: bool,
}

impl TransactionalTransparencyStore {
    pub fn open(home: &Path) -> Result<Self> {
        std::fs::create_dir_all(home)?;
        let path = home.join(DB_FILE);
        let mut connection = Connection::open(&path).map_err(db_error)?;
        connection
            .pragma_update(None, "journal_mode", "WAL")
            .map_err(db_error)?;
        connection
            .pragma_update(None, "synchronous", "FULL")
            .map_err(db_error)?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        transaction.execute_batch(
            "CREATE TABLE IF NOT EXISTS schema_migrations(version INTEGER PRIMARY KEY);
             CREATE TABLE IF NOT EXISTS profiles(identifier_hash TEXT PRIMARY KEY, alias TEXT NOT NULL, profile_json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS name_events(event_index INTEGER PRIMARY KEY, signed_event_hash TEXT NOT NULL UNIQUE, identifier_hash TEXT NOT NULL, event_json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS checkpoints(checkpoint_index INTEGER PRIMARY KEY, checkpoint_hash TEXT NOT NULL UNIQUE, log_size INTEGER NOT NULL, checkpoint_json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS pins(log_id TEXT PRIMARY KEY, pin_json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS anchors(txid TEXT PRIMARY KEY, anchor_json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS identifier_attestations(attestation_hash TEXT PRIMARY KEY, attestation_json TEXT NOT NULL);
             CREATE TABLE IF NOT EXISTS operator_state(log_id TEXT PRIMARY KEY, operator_pubkey TEXT, operator_sequence INTEGER NOT NULL DEFAULT 0);
             INSERT OR IGNORE INTO schema_migrations(version) VALUES (1);"
        ).map_err(db_error)?;
        let log_id: Option<String> = transaction
            .query_row("SELECT log_id FROM operator_state LIMIT 1", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(db_error)?;
        let log_id = log_id.unwrap_or_else(|| format!("satspath:local:{}", uuid::Uuid::new_v4()));
        transaction
            .execute(
                "INSERT OR IGNORE INTO operator_state(log_id, operator_sequence) VALUES (?1, 0)",
                [&log_id],
            )
            .map_err(db_error)?;
        transaction.commit().map_err(db_error)?;
        let store = Self {
            home: home.to_owned(),
            path,
            log_id,
            read_only: false,
        };
        store.load_log()?;
        Ok(store)
    }

    pub fn log_id(&self) -> &str {
        &self.log_id
    }

    /// Open existing state without migrations, directory creation or write access.
    pub fn open_read_only(home: &Path) -> Result<Self> {
        let path = home.join(DB_FILE);
        let connection =
            Connection::open_with_flags(&path, rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY)
                .map_err(db_error)?;
        let log_id = connection
            .query_row("SELECT log_id FROM operator_state LIMIT 1", [], |row| {
                row.get(0)
            })
            .map_err(db_error)?;
        let store = Self {
            home: home.to_owned(),
            path,
            log_id,
            read_only: true,
        };
        store.load_log()?;
        Ok(store)
    }

    /// Look up a local pin without initializing missing state. Existing corrupt
    /// or unreadable state is an error, not an absent profile.
    pub fn profile_read_only(home: &Path, alias: &str) -> Result<Option<SignedPaymentProfile>> {
        if !home.join(DB_FILE).try_exists()? {
            return Ok(None);
        }
        Self::open_read_only(home)?.profile(alias)
    }

    fn connection(&self) -> Result<Connection> {
        if self.read_only {
            return Connection::open_with_flags(
                &self.path,
                rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
            )
            .map_err(db_error);
        }
        Connection::open(&self.path).map_err(db_error)
    }

    pub fn profile(&self, alias: &str) -> Result<Option<SignedPaymentProfile>> {
        let connection = self.connection()?;
        let key = identifier_hash(&canonical_identifier(alias));
        let raw: Option<String> = connection
            .query_row(
                "SELECT profile_json FROM profiles WHERE identifier_hash=?1",
                [key],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?;
        raw.map(|value| serde_json::from_str(&value).map_err(Into::into))
            .transpose()
    }

    pub fn identifier_attestation(&self, hash: &str) -> Result<Option<IdentifierAttestation>> {
        let connection = self.connection()?;
        let raw: Option<String> = connection
            .query_row(
                "SELECT attestation_json FROM identifier_attestations WHERE attestation_hash=?1",
                [hash],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?;
        raw.map(|value| serde_json::from_str(&value).map_err(Into::into))
            .transpose()
    }

    pub fn store_identifier_attestation(&self, attestation: &IdentifierAttestation) -> Result<()> {
        let hash = attestation.attestation_hash()?;
        let json = serde_json::to_string(attestation)?;
        self.connection()?.execute(
            "INSERT OR REPLACE INTO identifier_attestations(attestation_hash,attestation_json) VALUES (?1,?2)",
            params![hash, json],
        ).map_err(db_error)?;
        Ok(())
    }
    fn load_log_from_connection(&self, connection: &Connection) -> Result<TransparencyLog> {
        let mut event_statement = connection
            .prepare("SELECT event_json FROM name_events ORDER BY event_index")
            .map_err(db_error)?;
        let events = event_statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(db_error)?
            .map(|row| {
                row.map_err(db_error)
                    .and_then(|raw| serde_json::from_str(&raw).map_err(Into::into))
            })
            .collect::<Result<Vec<NameEvent>>>()?;
        let mut checkpoint_statement = connection
            .prepare("SELECT checkpoint_json FROM checkpoints ORDER BY checkpoint_index")
            .map_err(db_error)?;
        let checkpoints = checkpoint_statement
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(db_error)?
            .map(|row| {
                row.map_err(db_error)
                    .and_then(|raw| serde_json::from_str(&raw).map_err(Into::into))
            })
            .collect::<Result<Vec<TransparencyCheckpoint>>>()?;
        let log = TransparencyLog::from_parts(
            self.home.join("transparency"),
            self.log_id.clone(),
            events,
            checkpoints,
        )?;
        let mut profile_statement = connection
            .prepare("SELECT identifier_hash,profile_json FROM profiles")
            .map_err(db_error)?;
        let profiles = profile_statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(db_error)?;
        for row in profiles {
            let (identifier, raw) = row.map_err(db_error)?;
            let profile: SignedPaymentProfile = serde_json::from_str(&raw)?;
            let latest = log.history(&identifier).last().copied().ok_or_else(|| {
                TransparencyError::BrokenIdentifierHistory(
                    "profile exists without event history".into(),
                )
            })?;
            if !super::verify_event_profile(latest, &profile)?
                || profile.profile.sequence != Some(latest.sequence)
            {
                return Err(TransparencyError::ProfileHashMismatch.into());
            }
        }
        Ok(log)
    }

    pub fn load_log(&self) -> Result<TransparencyLog> {
        let connection = self.connection()?;
        self.load_log_from_connection(&connection)
    }

    /// Atomically commits the complete security state. SQLite's WAL recovers
    /// committed transactions and discards partial transactions after crashes.
    pub fn commit_profile_event_checkpoint(
        &self,
        alias: &str,
        profile: &SignedPaymentProfile,
        event: &NameEvent,
        checkpoint: &TransparencyCheckpoint,
    ) -> Result<()> {
        Registry::validate_profile_write(alias, profile)?;
        let current = self.load_log()?;
        let candidate = current.prepare_append(event.clone(), profile)?;
        if checkpoint.log_id != self.log_id
            || checkpoint.log_size != candidate.events().len() as u64
            || checkpoint.log_root != candidate.prepare_checkpoint_pub_root()?
            || !super::verify_checkpoint(checkpoint)?
        {
            return Err(TransparencyError::CorruptCheckpointChain(
                "candidate checkpoint does not commit candidate event prefix".into(),
            )
            .into());
        }
        let expected_previous = current
            .checkpoints()
            .last()
            .map(TransparencyCheckpoint::checkpoint_hash)
            .transpose()?;
        if checkpoint.previous_checkpoint_hash != expected_previous {
            return Err(TransparencyError::CorruptCheckpointChain(
                "candidate checkpoint predecessor mismatch".into(),
            )
            .into());
        }
        if let Some(previous) = current.checkpoints().last() {
            let pin = super::PinnedCheckpoint {
                log_id: previous.log_id.clone(),
                operator_pubkey: previous.operator_pubkey.clone(),
                operator_sequence: previous.operator_sequence,
                tree_size: previous.log_size,
                root_hash: previous.log_root.clone(),
                checkpoint_hash: previous.checkpoint_hash()?,
                first_seen_at: previous.created_at,
                last_seen_at: previous.created_at,
            };
            let consistency = candidate.consistency(previous.log_size, checkpoint.log_size)?;
            super::verify_checkpoint_transition(&pin, checkpoint, Some(&consistency))?;
        } else if checkpoint.operator_sequence != 0 || checkpoint.operator_rotation.is_some() {
            return Err(TransparencyError::InvalidOperatorRotation.into());
        }
        let key = identifier_hash(&canonical_identifier(alias));
        let event_hash = event.signed_event_hash()?;
        let checkpoint_hash = checkpoint.checkpoint_hash()?;
        let profile_json = serde_json::to_string(profile)?;
        let event_json = serde_json::to_string(event)?;
        let checkpoint_json = serde_json::to_string(checkpoint)?;
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let event_index: i64 = transaction
            .query_row("SELECT COUNT(*) FROM name_events", [], |row| row.get(0))
            .map_err(db_error)?;
        let checkpoint_index: i64 = transaction
            .query_row("SELECT COUNT(*) FROM checkpoints", [], |row| row.get(0))
            .map_err(db_error)?;
        if event_index != current.events().len() as i64
            || checkpoint_index != current.checkpoints().len() as i64
        {
            return Err(TransparencyError::CorruptStore(
                "concurrent transparency transaction; retry required".into(),
            )
            .into());
        }
        let stored_previous: Option<String> = transaction
            .query_row(
                "SELECT checkpoint_hash FROM checkpoints ORDER BY checkpoint_index DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?;
        if stored_previous != expected_previous {
            return Err(
                TransparencyError::CorruptStore("checkpoint changed concurrently".into()).into(),
            );
        }
        transaction.execute("INSERT INTO name_events(event_index,signed_event_hash,identifier_hash,event_json) VALUES (?1,?2,?3,?4)", params![event_index, event_hash, event.identifier_hash, event_json]).map_err(db_error)?;
        transaction.execute("INSERT INTO profiles(identifier_hash,alias,profile_json) VALUES (?1,?2,?3) ON CONFLICT(identifier_hash) DO UPDATE SET alias=excluded.alias,profile_json=excluded.profile_json", params![key, canonical_identifier(alias), profile_json]).map_err(db_error)?;
        transaction.execute("INSERT INTO checkpoints(checkpoint_index,checkpoint_hash,log_size,checkpoint_json) VALUES (?1,?2,?3,?4)", params![checkpoint_index, checkpoint_hash, checkpoint.log_size, checkpoint_json]).map_err(db_error)?;
        transaction
            .execute(
                "UPDATE operator_state SET operator_pubkey=?1,operator_sequence=?2 WHERE log_id=?3",
                params![
                    checkpoint.operator_pubkey,
                    checkpoint.operator_sequence,
                    self.log_id
                ],
            )
            .map_err(db_error)?;
        transaction.commit().map_err(db_error)
    }

    pub fn replace_latest_checkpoint(
        &self,
        previous_hash: &str,
        checkpoint: &TransparencyCheckpoint,
    ) -> Result<()> {
        if !super::verify_checkpoint(checkpoint)? {
            return Err(TransparencyError::InvalidCheckpointSignature.into());
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let latest: Option<(i64, String)> = transaction.query_row(
            "SELECT checkpoint_index,checkpoint_hash FROM checkpoints ORDER BY checkpoint_index DESC LIMIT 1",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).optional().map_err(db_error)?;
        let (index, stored_hash) = latest.ok_or_else(|| {
            TransparencyError::CorruptCheckpointChain("no checkpoint to replace".into())
        })?;
        if stored_hash != previous_hash {
            return Err(TransparencyError::CorruptCheckpointChain(
                "checkpoint changed concurrently".into(),
            )
            .into());
        }
        let stored_json: String = transaction
            .query_row(
                "SELECT checkpoint_json FROM checkpoints WHERE checkpoint_index=?1",
                params![index],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        let stored: TransparencyCheckpoint = serde_json::from_str(&stored_json)?;
        validate_replacement_anchor(previous_hash, &stored, checkpoint)?;

        // Validate the candidate log to ensure full replay and Catena integrity before committing
        let mut candidate = self.load_log_from_connection(&transaction)?;
        candidate.replace_checkpoint_by_hash_in_memory(previous_hash, checkpoint.clone())?;
        candidate.verify_checkpoint_chain_integrity()?;

        let new_hash = checkpoint.checkpoint_hash()?;
        if new_hash != previous_hash {
            return Err(TransparencyError::CorruptCheckpointChain(
                "replacement may only change the Bitcoin receipt and signature".into(),
            )
            .into());
        }
        let json = serde_json::to_string(checkpoint)?;
        transaction.execute("UPDATE checkpoints SET checkpoint_hash=?1,checkpoint_json=?2 WHERE checkpoint_index=?3", params![new_hash, json, index]).map_err(db_error)?;
        upsert_anchor(&transaction, checkpoint.bitcoin_anchor.as_ref())?;
        transaction.commit().map_err(db_error)
    }

    pub fn replace_checkpoint_by_hash(
        &self,
        target_hash: &str,
        checkpoint: &TransparencyCheckpoint,
    ) -> Result<()> {
        if !super::verify_checkpoint(checkpoint)? {
            return Err(TransparencyError::InvalidCheckpointSignature.into());
        }
        let mut connection = self.connection()?;
        let transaction = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let row: Option<i64> = transaction
            .query_row(
                "SELECT checkpoint_index FROM checkpoints WHERE checkpoint_hash=?1",
                params![target_hash],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_error)?;
        let index = row.ok_or_else(|| {
            TransparencyError::CorruptCheckpointChain(format!(
                "checkpoint with hash {target_hash} not found to replace"
            ))
        })?;
        let new_hash = checkpoint.checkpoint_hash()?;
        if new_hash != target_hash {
            return Err(TransparencyError::CorruptCheckpointChain(
                "replacement may only change the Bitcoin receipt and signature".into(),
            )
            .into());
        }
        let stored_json: String = transaction
            .query_row(
                "SELECT checkpoint_json FROM checkpoints WHERE checkpoint_index=?1",
                params![index],
                |r| r.get(0),
            )
            .map_err(db_error)?;
        let stored: TransparencyCheckpoint = serde_json::from_str(&stored_json)?;
        validate_replacement_anchor(target_hash, &stored, checkpoint)?;

        // Validate the candidate log to ensure full replay and Catena integrity before committing
        let mut candidate = self.load_log_from_connection(&transaction)?;
        candidate.replace_checkpoint_by_hash_in_memory(target_hash, checkpoint.clone())?;
        candidate.verify_checkpoint_chain_integrity()?;

        let json = serde_json::to_string(checkpoint)?;
        transaction
            .execute(
                "UPDATE checkpoints SET checkpoint_hash=?1,checkpoint_json=?2 WHERE checkpoint_index=?3",
                params![new_hash, json, index],
            )
            .map_err(db_error)?;
        upsert_anchor(&transaction, checkpoint.bitcoin_anchor.as_ref())?;
        transaction.commit().map_err(db_error)
    }
}

fn validate_replacement_anchor(
    target_hash: &str,
    stored: &TransparencyCheckpoint,
    replacement: &TransparencyCheckpoint,
) -> Result<()> {
    match (&stored.bitcoin_anchor, &replacement.bitcoin_anchor) {
        (Some(_), None) => {
            return Err(TransparencyError::CorruptCheckpointChain(
                "replacement may not remove an existing Bitcoin anchor".into(),
            )
            .into());
        }
        (Some(old), Some(new)) => {
            if old.txid != new.txid {
                return Err(TransparencyError::CorruptCheckpointChain(
                    "checkpoint already carries a different Bitcoin anchor".into(),
                )
                .into());
            }
            if old.network != new.network
                || old.commitment != new.commitment
                || old.chain_index != new.chain_index
                || old.prev_txid != new.prev_txid
                || old.prev_vout != new.prev_vout
                || old.continuation_vout != new.continuation_vout
            {
                return Err(TransparencyError::CorruptCheckpointChain(
                    "replacement anchor may not alter immutable chain metadata".into(),
                )
                .into());
            }
        }
        _ => {}
    }
    if let Some(anchor) = &replacement.bitcoin_anchor {
        let expected = match anchor.chain_index {
            Some(idx) => super::catena_commitment(target_hash, idx),
            None => super::anchor_commitment(target_hash),
        }
        .map_err(|e| TransparencyError::CorruptCheckpointChain(e.to_string()))?;
        if anchor.network != crate::BitcoinNetwork::Regtest || anchor.commitment != expected {
            return Err(TransparencyError::CorruptCheckpointChain(
                "replacement anchor commitment or network mismatch".into(),
            )
            .into());
        }
        if anchor.chain_index.is_some()
            && anchor.continuation_vout != Some(super::CATENA_CONTINUATION_VOUT)
        {
            return Err(TransparencyError::CorruptCheckpointChain(format!(
                "replacement Catena anchor continuation_vout is {:?}, expected Some({})",
                anchor.continuation_vout,
                super::CATENA_CONTINUATION_VOUT
            ))
            .into());
        }
    }
    Ok(())
}

fn upsert_anchor(
    transaction: &rusqlite::Transaction,
    anchor: Option<&super::BitcoinAnchor>,
) -> Result<()> {
    let Some(anchor) = anchor else {
        return Ok(());
    };
    transaction
        .execute(
            "INSERT OR REPLACE INTO anchors(txid,anchor_json) VALUES (?1,?2)",
            params![anchor.txid.as_str(), serde_json::to_string(anchor)?],
        )
        .map_err(db_error)?;
    Ok(())
}
