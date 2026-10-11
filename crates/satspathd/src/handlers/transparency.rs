//! Transparency log handlers: checkpoints, events, proofs, anchors, namespace.

use std::fs;
use std::path::Path;

use anyhow::Result;
use satspath_core::{MerkleConsistencyProof, TransactionalTransparencyStore, TransparencyLog};
use serde::{Deserialize, Serialize};

use crate::config::AppState;
use crate::http::write_owner_only_file;

pub(crate) fn transparency_log(state: &AppState) -> Result<TransparencyLog> {
    transparency_log_at(&state.home)
}

pub(crate) fn transparency_log_at(home: &Path) -> Result<TransparencyLog> {
    Ok(TransactionalTransparencyStore::open(home)?.load_log()?)
}

pub(crate) fn load_or_create_transparency_operator(home: &Path) -> Result<secp256k1::SecretKey> {
    let dir = home.join("transparency");
    fs::create_dir_all(&dir)?;
    let path = dir.join("operator.key");
    if path.exists() {
        let bytes = hex::decode(fs::read_to_string(path)?.trim())?;
        return secp256k1::SecretKey::from_slice(&bytes).map_err(Into::into);
    }
    let key = satspath_core::crypto::generate_identity_keypair().secret_key;
    write_owner_only_file(&path, hex::encode(key.secret_bytes()).as_bytes())?;
    Ok(key)
}

pub(crate) fn query_u64(url: &str, name: &str) -> Option<u64> {
    url.split_once('?')?.1.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        (key == name).then(|| value.parse().ok()).flatten()
    })
}

pub(crate) fn query_str(url: &str, name: &str) -> Option<String> {
    url.split_once('?')?.1.split('&').find_map(|part| {
        let (key, value) = part.split_once('=')?;
        if key == name {
            url::form_urlencoded::parse(part.as_bytes())
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.into_owned())
                .or_else(|| Some(value.to_string()))
        } else {
            None
        }
    })
}

pub(crate) fn paginated<T: Clone + Serialize>(url: &str, items: &[T]) -> serde_json::Value {
    let offset = query_u64(url, "offset")
        .unwrap_or(0)
        .min(items.len() as u64) as usize;
    let limit = query_u64(url, "limit").unwrap_or(50).clamp(1, 200) as usize;
    let page: Vec<_> = items.iter().skip(offset).take(limit).cloned().collect();
    serde_json::json!({"items": page, "offset": offset, "limit": limit, "total": items.len()})
}

pub(crate) fn consistency_from_query(
    state: &AppState,
    url: &str,
) -> Result<MerkleConsistencyProof> {
    let from = query_u64(url, "from").ok_or_else(|| anyhow::anyhow!("missing from tree size"))?;
    let to = query_u64(url, "to").ok_or_else(|| anyhow::anyhow!("missing to tree size"))?;
    Ok(transparency_log(state)?.consistency(from, to)?)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PendingCatenaAnchor {
    checkpoint_hash: String,
    anchor: satspath_core::TransparencyBitcoinAnchor,
}

pub(crate) async fn anchor_latest_checkpoint(
    state: &AppState,
) -> Result<satspath_core::TransparencyBitcoinAnchor> {
    let _anchor_guard = state.anchor_lock.lock().await;
    let log = transparency_log(state)?;
    let checkpoint = log
        .checkpoints()
        .last()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no checkpoint to anchor"))?;
    if checkpoint.bitcoin_anchor.is_some() {
        anyhow::bail!("latest checkpoint is already anchored");
    }
    let checkpoint_hash = checkpoint.checkpoint_hash()?;
    let client = satspath_core::transparency::RegtestAnchorClient::from_env()?;

    // Find the latest Catena anchor by selecting the anchor with the maximum chain_index
    let mut prev_anchor = log
        .checkpoints()
        .iter()
        .filter_map(|c| c.bitcoin_anchor.as_ref())
        .filter(|a| a.chain_index.is_some() && a.continuation_vout.is_some())
        .max_by_key(|a| a.chain_index.unwrap_or(0))
        .cloned();

    // Crash resilience: check if a pending anchor was broadcast before an uncommitted shutdown
    let pending_file = state.home.join("catena_pending_anchor.json");
    if pending_file.exists() {
        let bytes = fs::read(&pending_file)
            .map_err(|e| anyhow::anyhow!("failed to read pending anchor file: {e}"))?;
        let pending: PendingCatenaAnchor = serde_json::from_slice(&bytes)
            .map_err(|e| anyhow::anyhow!("failed to parse pending anchor file: {e}"))?;

        // Query whether transaction is in mempool or blockchain
        let maybe_tx = client.get_raw_transaction(&pending.anchor.txid).await?;
        match maybe_tx {
            None => {
                // The transaction was never broadcast or was rejected from the mempool.
                let can_discard = match &prev_anchor {
                    Some(tip) => {
                        let tip_vout = tip.continuation_vout.unwrap_or(1);
                        client
                            .is_tx_out_unspent(&tip.txid, tip_vout)
                            .await
                            .unwrap_or(false)
                    }
                    None => match client.get_wallet_transaction(&pending.anchor.txid).await {
                        Ok(None) => true,
                        Ok(Some(wtx)) => {
                            let confs = wtx["confirmations"].as_i64().unwrap_or(0);
                            confs < 0
                        }
                        Err(_) => false,
                    },
                };

                if can_discard {
                    eprintln!(
                        "satspathd: discarding stale pending Catena anchor transaction {}: never broadcast",
                        pending.anchor.txid
                    );
                    let _ = fs::remove_file(&pending_file);
                    // Fall through to build and broadcast a fresh anchor
                } else {
                    anyhow::bail!(
                        "pending anchor {} was not found via getrawtransaction, but wallet or predecessor indicates it may exist",
                        pending.anchor.txid
                    );
                }
            }
            Some(mut tx) => {
                let target_checkpoint = if pending.checkpoint_hash == checkpoint_hash {
                    Some(checkpoint.clone())
                } else {
                    log.checkpoints()
                        .iter()
                        .find(|c| {
                            c.checkpoint_hash().ok().as_deref() == Some(&pending.checkpoint_hash)
                        })
                        .cloned()
                };

                let Some(mut target_cp) = target_checkpoint else {
                    anyhow::bail!(
                        "pending anchor is for checkpoint {}, which is not in the transparency log",
                        pending.checkpoint_hash
                    );
                };

                // If the target checkpoint was already anchored with this txid, clear stale pending file and continue
                if target_cp.bitcoin_anchor.as_ref().map(|a| a.txid.as_str())
                    == Some(&pending.anchor.txid)
                {
                    let _ = fs::remove_file(&pending_file);
                    if pending.checkpoint_hash == checkpoint_hash {
                        return Ok(pending.anchor);
                    }
                    prev_anchor = target_cp.bitcoin_anchor.clone();
                } else {
                    // If unconfirmed, mine a block on regtest to confirm it
                    let mut confirmations = tx["confirmations"].as_u64().unwrap_or(0) as u32;
                    if confirmations == 0 {
                        client.mine_blocks(1).await?;
                        if let Some(updated_tx) =
                            client.get_raw_transaction(&pending.anchor.txid).await?
                        {
                            tx = updated_tx;
                            confirmations = tx["confirmations"].as_u64().unwrap_or(0) as u32;
                        }
                    }

                    if confirmations == 0 {
                        anyhow::bail!(
                            "pending anchor {} is not yet confirmed on Bitcoin",
                            pending.anchor.txid
                        );
                    }

                    // Verify vout[0] has the expected commitment
                    let expected_script = format!("6a20{}", pending.anchor.commitment);
                    let vout_valid = tx["vout"]
                        .as_array()
                        .and_then(|vouts| vouts.first())
                        .and_then(|v0| v0["scriptPubKey"]["hex"].as_str())
                        == Some(&expected_script);
                    if !vout_valid {
                        anyhow::bail!(
                            "pending anchor {} vout[0] does not match commitment",
                            pending.anchor.txid
                        );
                    }

                    // Verify continuation output exists, holds 1,000 sats, and lock it persistently
                    let cont_vout = pending
                        .anchor
                        .continuation_vout
                        .ok_or_else(|| anyhow::anyhow!("pending anchor lacks continuation_vout"))?;
                    let vouts = tx["vout"]
                        .as_array()
                        .ok_or_else(|| anyhow::anyhow!("missing vouts in tx"))?;
                    let cont_out = vouts.get(cont_vout as usize).ok_or_else(|| {
                        anyhow::anyhow!("continuation vout {cont_vout} out of bounds")
                    })?;
                    let sats =
                        satspath_core::transparency::parse_sats(&cont_out["value"]).unwrap_or(0);
                    if sats != 1000 {
                        anyhow::bail!("continuation output holds {sats} sats, expected 1000");
                    }
                    client
                        .lock_continuation(&pending.anchor.txid, cont_vout)
                        .await?;

                    // Validate linkage against the recorded predecessor
                    if let Some(prev_txid) = &pending.anchor.prev_txid {
                        let vin_spends_prev = tx["vin"]
                            .as_array()
                            .and_then(|vins| vins.first())
                            .map(|vin| {
                                vin["txid"].as_str() == Some(prev_txid)
                                    && vin["vout"].as_u64()
                                        == pending.anchor.prev_vout.map(|v| v as u64)
                            })
                            .unwrap_or(false);
                        if !vin_spends_prev {
                            anyhow::bail!(
                                "pending anchor {} vin[0] does not spend predecessor outpoint ({}, {:?})",
                                pending.anchor.txid,
                                prev_txid,
                                pending.anchor.prev_vout
                            );
                        }
                    } else if pending.anchor.prev_vout.is_some()
                        || pending.anchor.chain_index != Some(0)
                    {
                        anyhow::bail!("pending anchor is not a valid genesis anchor");
                    }

                    let mut reconciled_anchor = pending.anchor;
                    reconciled_anchor.confirmations = confirmations;
                    reconciled_anchor.block_hash = tx["blockhash"].as_str().map(str::to_owned);
                    reconciled_anchor.verified = true;

                    let operator = load_or_create_transparency_operator(&state.home)?;
                    target_cp.bitcoin_anchor = Some(reconciled_anchor.clone());
                    target_cp.sign(&operator)?;
                    let _mutation_guard = state.mutation_lock.lock().await;
                    if pending.checkpoint_hash == checkpoint_hash {
                        TransactionalTransparencyStore::open(&state.home)?
                            .replace_latest_checkpoint(&checkpoint_hash, &target_cp)?;
                        let _ = fs::remove_file(&pending_file);
                        return Ok(reconciled_anchor);
                    } else {
                        TransactionalTransparencyStore::open(&state.home)?
                            .replace_checkpoint_by_hash(&pending.checkpoint_hash, &target_cp)?;
                        let _ = fs::remove_file(&pending_file);
                        prev_anchor = Some(reconciled_anchor);
                    }
                }
            }
        }
    }

    let pre_broadcast =
        |pre_anchor: &satspath_core::transparency::BitcoinAnchor| -> anyhow::Result<()> {
            let current_log = TransactionalTransparencyStore::open(&state.home)?.load_log()?;
            let current_latest_hash = current_log
                .checkpoints()
                .last()
                .map(|c| c.checkpoint_hash())
                .transpose()?;
            if current_latest_hash.as_deref() != Some(&checkpoint_hash) {
                anyhow::bail!("checkpoint changed concurrently before anchor broadcast");
            }

            let pending = PendingCatenaAnchor {
                checkpoint_hash: checkpoint_hash.clone(),
                anchor: pre_anchor.clone(),
            };
            let data = serde_json::to_vec(&pending)?;
            write_owner_only_file(&pending_file, &data)?;
            Ok(())
        };

    let anchor = match prev_anchor {
        Some(prev) => {
            client
                .anchor_catena_next_with_hook(&checkpoint_hash, &prev, |pre| {
                    pre_broadcast(pre)
                        .map_err(|e| satspath_core::SatsPathError::ValidationError(e.to_string()))
                })
                .await?
        }
        None => {
            let allow_genesis = log.checkpoints().iter().all(|c| c.bitcoin_anchor.is_none())
                || std::env::var("SATSPATH_ALLOW_CATENA_GENESIS")
                    .map(|v| v == "1" || v == "true")
                    .unwrap_or(false);
            if !allow_genesis {
                anyhow::bail!(
                    "no previous Catena anchor found in log; set SATSPATH_ALLOW_CATENA_GENESIS=1 to initialize a new Catena genesis chain"
                );
            }
            client
                .anchor_catena_genesis_with_hook(&checkpoint_hash, |pre| {
                    pre_broadcast(pre)
                        .map_err(|e| satspath_core::SatsPathError::ValidationError(e.to_string()))
                })
                .await?
        }
    };

    if !anchor.verified {
        anyhow::bail!("regtest anchor could not be verified after confirmation");
    }

    let operator = load_or_create_transparency_operator(&state.home)?;
    let mut anchored = checkpoint;
    anchored.bitcoin_anchor = Some(anchor.clone());
    anchored.sign(&operator)?;

    let _mutation_guard = state.mutation_lock.lock().await;
    let store = TransactionalTransparencyStore::open(&state.home)?;
    if store
        .replace_latest_checkpoint(&checkpoint_hash, &anchored)
        .is_err()
    {
        store.replace_checkpoint_by_hash(&checkpoint_hash, &anchored)?;
    }
    let _ = fs::remove_file(&pending_file);
    Ok(anchor)
}

pub(crate) fn catena_chain(
    state: &AppState,
) -> Result<Vec<satspath_core::TransparencyBitcoinAnchor>> {
    let log = transparency_log(state)?;
    let anchors: Vec<_> = log
        .checkpoints()
        .iter()
        .filter_map(|c| c.bitcoin_anchor.clone())
        .filter(|a| a.chain_index.is_some())
        .collect();
    Ok(anchors)
}

pub(crate) fn namespace_descriptor(
    state: &AppState,
) -> Result<satspath_core::transparency::NamespaceDescriptor> {
    let domain =
        std::env::var("SATSPATH_AUTHORITY_DOMAIN").unwrap_or_else(|_| "localhost".to_string());
    let wallet = crate::handlers::wallet::load_wallet(&state.home)?;
    let authority_pubkey = wallet.identity_pubkey.clone().unwrap_or_else(|| {
        "0000000000000000000000000000000000000000000000000000000000000000".to_string()
    });
    let log = transparency_log(state).ok();
    let log_id = log
        .as_ref()
        .map(|l| l.log_id().to_string())
        .unwrap_or_else(|| format!("satspath:{domain}"));
    let endpoint_urls = if let Ok(custom_url) = std::env::var("SATSPATH_AUTHORITY_URL") {
        vec![custom_url]
    } else if domain != "localhost" {
        vec![format!("https://{domain}/v2")]
    } else {
        vec![format!("http://{}/v2", state.bind)]
    };
    let quorum = std::env::var("SATSPATH_WITNESS_QUORUM")
        .ok()
        .and_then(|q| q.parse::<u8>().ok())
        .unwrap_or(1);
    let now = chrono::Utc::now().timestamp();

    Ok(satspath_core::transparency::NamespaceDescriptor {
        version: 2,
        domain,
        log_id,
        authority_pubkey,
        endpoint_urls,
        witness_quorum: quorum,
        witness_pubkeys: vec![],
        valid_from: now,
        expires_at: now + 30 * 86400,
        signature: String::new(),
    })
}
