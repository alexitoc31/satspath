//! Durable BIP-353 identity pins, serialized across threads and processes by SQLite.

use std::path::Path;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};

use crate::privacy::identifier_hash;
use crate::registry::Registry;
use crate::{Result, SatsPathError, SignedPaymentProfile};

/// Atomically check and persist a fetched profile using the registry's update policy.
/// A verified revocation is committed as a tombstone and then returned as an error.
///
/// `dir` holds the continuity database and is created if missing. Propagates
/// profile-write and transition validation errors; storage failures return
/// `RegistryError`, and JSON errors propagate as `JsonError`.
pub(super) fn accept_profile(dir: &Path, signed: &SignedPaymentProfile) -> Result<()> {
    Registry::validate_profile_write(&signed.profile.alias, signed)?;
    let mut connection = open_store(dir)?;
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(storage_error)?;
    let key = identifier_hash(&signed.profile.alias);
    let previous: Option<String> = tx
        .query_row(
            "SELECT signed FROM profiles WHERE alias_hash = ?1",
            [&key],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage_error)?;
    let previous: Option<SignedPaymentProfile> = previous
        .map(|json| serde_json::from_str(&json))
        .transpose()?;
    Registry::validate_profile_transition(&signed.profile.alias, signed, previous.as_ref())?;
    let json = serde_json::to_string(signed)?;
    tx.execute(
        "INSERT INTO profiles (alias_hash, signed) VALUES (?1, ?2)
         ON CONFLICT(alias_hash) DO UPDATE SET signed = excluded.signed",
        rusqlite::params![key, json],
    )
    .map_err(storage_error)?;
    tx.commit().map_err(storage_error)?;
    if signed.profile.revoked {
        return Err(SatsPathError::RegistryError(
            "BIP-353 identity has been revoked".into(),
        ));
    }
    Ok(())
}

/// Check durable tombstones before any network error could trigger resolver fallback.
///
/// `alias` must be the canonical profile alias. Opens or creates the store in
/// `dir`; an unknown or unrevoked alias succeeds. Revocations and storage failures
/// return `RegistryError`; malformed stored profiles return `JsonError`.
pub(super) fn check_revocation(dir: &Path, alias: &str) -> Result<()> {
    let connection = open_store(dir)?;
    let previous: Option<String> = connection
        .query_row(
            "SELECT signed FROM profiles WHERE alias_hash = ?1",
            [identifier_hash(alias)],
            |row| row.get(0),
        )
        .optional()
        .map_err(storage_error)?;
    if let Some(json) = previous {
        let signed: SignedPaymentProfile = serde_json::from_str(&json)?;
        if signed.profile.revoked {
            return Err(SatsPathError::RegistryError(
                "BIP-353 identity has been revoked".into(),
            ));
        }
    }
    Ok(())
}

/// Open the persistent store and configure a bounded wait for concurrent writers.
/// Creates `dir` and the table if needed, with a five-second SQLite busy timeout.
/// Filesystem and SQLite failures
/// return `RegistryError`.
fn open_store(dir: &Path) -> Result<Connection> {
    std::fs::create_dir_all(dir).map_err(|e| SatsPathError::RegistryError(e.to_string()))?;
    let connection =
        Connection::open(dir.join("bip353-continuity.sqlite3")).map_err(storage_error)?;
    connection
        .busy_timeout(std::time::Duration::from_secs(5))
        .map_err(storage_error)?;
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS profiles (alias_hash TEXT PRIMARY KEY, signed TEXT NOT NULL);",
    ).map_err(storage_error)?;
    Ok(connection)
}

/// Storage failures must stop the resolver chain instead of permitting fallback.
fn storage_error(error: rusqlite::Error) -> SatsPathError {
    SatsPathError::RegistryError(format!("BIP-353 continuity storage failed: {error}"))
}
