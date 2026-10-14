use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::catena::{catena_commitment, CONTINUATION_BTC, CONTINUATION_SATOSHIS, MAX_CATENA_HOPS};
use crate::BitcoinNetwork;

#[cfg(feature = "std")]
use serde_json::{json, Value};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BitcoinAnchor {
    pub network: BitcoinNetwork,
    pub txid: String,
    pub block_hash: Option<String>,
    pub block_height: Option<u64>,
    pub confirmations: u32,
    pub commitment: String,
    pub verified: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_txid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prev_vout: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub continuation_vout: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_index: Option<u64>,
}

pub fn anchor_commitment(checkpoint_hash: &str) -> Result<String, hex::FromHexError> {
    let mut h = Sha256::new();
    h.update(b"SatsPathCheckpointAnchorV1");
    h.update(hex::decode(checkpoint_hash)?);
    Ok(hex::encode(h.finalize()))
}

#[cfg(feature = "std")]
pub fn parse_sats(val: &Value) -> Option<u64> {
    val.as_u64()
        .or_else(|| val.as_f64().map(|btc| (btc * 100_000_000.0).round() as u64))
}

#[cfg(feature = "std")]
fn find_continuation_vout_for_address(tx: &Value, addr: &str) -> Option<u32> {
    tx["vout"].as_array().and_then(|outputs| {
        outputs.iter().find_map(|out| {
            let matched_addr = out["scriptPubKey"]["address"].as_str() == Some(addr)
                || out["scriptPubKey"]["addresses"]
                    .as_array()
                    .is_some_and(|arr| arr.iter().any(|a| a.as_str() == Some(addr)));
            let sats = parse_sats(&out["value"]).unwrap_or(0);
            if matched_addr && sats == CONTINUATION_SATOSHIS {
                out["n"].as_u64().map(|n| n as u32)
            } else {
                None
            }
        })
    })
}

#[cfg(feature = "std")]
pub struct RegtestAnchorClient {
    rpc_url: String,
    rpc_user: String,
    rpc_password: String,
    client: reqwest::Client,
}

#[cfg(feature = "std")]
impl RegtestAnchorClient {
    /// Build an explicitly enabled local regtest RPC client from operator configuration.
    pub fn from_env() -> crate::Result<Self> {
        let network = std::env::var("SATSPATH_BITCOIN_NETWORK").unwrap_or_default();
        if network != "regtest" {
            return Err(crate::SatsPathError::ValidationError(
                "Bitcoin checkpoint anchoring is disabled unless SATSPATH_BITCOIN_NETWORK=regtest"
                    .into(),
            ));
        }
        let required = |name: &str| {
            std::env::var(name)
                .map_err(|_| crate::SatsPathError::ValidationError(format!("missing {name}")))
        };
        let rpc_url = required("SATSPATH_BITCOIN_RPC_URL")?;
        // Regtest is an operator-configured local service, never a profile URL.
        // Require a literal loopback address: no DNS or rebinding is possible.
        let parsed = url::Url::parse(&rpc_url)
            .map_err(|e| crate::SatsPathError::ValidationError(e.to_string()))?;
        let loopback = parsed
            .host_str()
            .and_then(|host| {
                host.trim_matches(['[', ']'])
                    .parse::<std::net::IpAddr>()
                    .ok()
            })
            .is_some_and(|ip| ip.is_loopback());
        if !loopback
            || !matches!(parsed.scheme(), "http" | "https")
            || !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.fragment().is_some()
        {
            return Err(crate::SatsPathError::ValidationError("regtest RPC requires a literal loopback HTTP(S) URL without credentials or fragment".into()));
        }
        let client = crate::outbound::http_client(std::time::Duration::from_secs(15));
        Ok(Self {
            rpc_url,
            rpc_user: required("SATSPATH_BITCOIN_RPC_USER")?,
            rpc_password: required("SATSPATH_BITCOIN_RPC_PASSWORD")?,
            client,
        })
    }

    async fn rpc(&self, method: &str, params: Value) -> crate::Result<Value> {
        let response = self
            .client
            .post(&self.rpc_url)
            .basic_auth(&self.rpc_user, Some(&self.rpc_password))
            .json(
                &json!({"jsonrpc":"2.0","id":"satspath-anchor-v1","method":method,"params":params}),
            )
            .send()
            .await
            .map_err(|e| crate::SatsPathError::NetworkError(e.to_string()))?;
        let status = response.status();
        let value: Value = response
            .json()
            .await
            .map_err(|e| crate::SatsPathError::NetworkError(e.to_string()))?;
        if !status.is_success() || !value["error"].is_null() {
            return Err(crate::SatsPathError::NetworkError(format!(
                "Bitcoin RPC {method}: {}",
                value["error"]
            )));
        }
        Ok(value["result"].clone())
    }

    /// Bitcoin Core only serves confirmed non-mempool transactions via
    /// `getrawtransaction` when `-txindex` is enabled and synced.
    pub async fn ensure_txindex(&self) -> crate::Result<()> {
        let info = self.rpc("getindexinfo", json!(["txindex"])).await?;
        if info["txindex"]["synced"].as_bool() != Some(true) {
            return Err(crate::SatsPathError::ValidationError(
                "Catena anchoring requires a synced Bitcoin Core -txindex".into(),
            ));
        }
        Ok(())
    }

    /// Create, fund, sign, broadcast and mine a legacy standalone OP_RETURN commitment.
    pub async fn anchor_checkpoint(&self, checkpoint_hash: &str) -> crate::Result<BitcoinAnchor> {
        let commitment = anchor_commitment(checkpoint_hash)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?;
        let raw = self
            .rpc("createrawtransaction", json!([[], [{"data": commitment}]] ))
            .await?;
        let funded = self.rpc("fundrawtransaction", json!([raw])).await?;
        let signed = self
            .rpc("signrawtransactionwithwallet", json!([funded["hex"]]))
            .await?;
        if signed["complete"] != true {
            return Err(crate::SatsPathError::NetworkError(
                "Bitcoin Core did not fully sign anchor transaction".into(),
            ));
        }
        let txid = self
            .rpc("sendrawtransaction", json!([signed["hex"]]))
            .await?
            .as_str()
            .ok_or_else(|| crate::SatsPathError::NetworkError("missing anchor txid".into()))?
            .to_owned();
        let address = self.rpc("getnewaddress", json!([])).await?;
        self.rpc("generatetoaddress", json!([1, address])).await?;
        self.verify_anchor(&txid, &commitment).await
    }

    /// Create, fund, sign, broadcast and mine a Catena Genesis anchor transaction.
    ///
    /// Outputs:
    /// - Output 0: OP_RETURN with Catena commitment at index 0.
    /// - Output 1: Continuation UTXO of 1,000 satoshis locked to a new address.
    pub async fn anchor_catena_genesis(
        &self,
        checkpoint_hash: &str,
    ) -> crate::Result<BitcoinAnchor> {
        self.anchor_catena_genesis_with_hook(checkpoint_hash, |_| Ok(()))
            .await
    }

    /// Create, fund, sign, broadcast and mine a Catena Genesis anchor transaction with a pre-broadcast hook.
    pub async fn anchor_catena_genesis_with_hook<F>(
        &self,
        checkpoint_hash: &str,
        on_pre_broadcast: F,
    ) -> crate::Result<BitcoinAnchor>
    where
        F: FnOnce(&BitcoinAnchor) -> crate::Result<()>,
    {
        self.ensure_txindex().await?;
        let commitment = catena_commitment(checkpoint_hash, 0)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?;
        let continuation_addr = self
            .rpc("getnewaddress", json!([]))
            .await?
            .as_str()
            .ok_or_else(|| {
                crate::SatsPathError::NetworkError("missing continuation address".into())
            })?
            .to_owned();

        let outputs = json!([
            {"data": commitment},
            {&continuation_addr: CONTINUATION_BTC}
        ]);
        let raw = self
            .rpc("createrawtransaction", json!([[], outputs]))
            .await?;
        let funded = self
            .rpc("fundrawtransaction", json!([raw, {"changePosition": 2}]))
            .await?;
        let signed = self
            .rpc("signrawtransactionwithwallet", json!([funded["hex"]]))
            .await?;
        if signed["complete"] != true {
            return Err(crate::SatsPathError::NetworkError(
                "Bitcoin Core did not fully sign genesis anchor transaction".into(),
            ));
        }
        let signed_hex = signed["hex"]
            .as_str()
            .ok_or_else(|| crate::SatsPathError::NetworkError("missing signed hex".into()))?;

        // Pre-broadcast validation: verify continuation UTXO output and commitment exist before broadcasting
        let decoded = self
            .rpc("decoderawtransaction", json!([signed_hex]))
            .await?;

        let expected_commitment_script = format!("6a20{commitment}");
        let commitment_valid = decoded["vout"]
            .as_array()
            .and_then(|vouts| vouts.first())
            .and_then(|v0| v0["scriptPubKey"]["hex"].as_str())
            == Some(&expected_commitment_script);
        if !commitment_valid {
            return Err(crate::SatsPathError::ValidationError(
                "vout[0] is not the expected Catena OP_RETURN commitment".into(),
            ));
        }

        let continuation_vout = find_continuation_vout_for_address(&decoded, &continuation_addr)
            .ok_or_else(|| {
                crate::SatsPathError::NetworkError(
                    "could not locate 1000-sat continuation UTXO in decoded genesis tx".into(),
                )
            })?;
        if continuation_vout != super::catena::CATENA_CONTINUATION_VOUT {
            return Err(crate::SatsPathError::ValidationError(format!(
                "continuation_vout is {continuation_vout}, expected fixed index {}",
                super::catena::CATENA_CONTINUATION_VOUT
            )));
        }
        let decoded_txid = decoded["txid"].as_str().ok_or_else(|| {
            crate::SatsPathError::NetworkError("missing txid in decoded genesis tx".into())
        })?;

        let pre_anchor = BitcoinAnchor {
            network: BitcoinNetwork::Regtest,
            txid: decoded_txid.to_string(),
            block_hash: None,
            block_height: None,
            confirmations: 0,
            commitment: commitment.clone(),
            verified: false,
            prev_txid: None,
            prev_vout: None,
            continuation_vout: Some(continuation_vout),
            chain_index: Some(0),
        };
        on_pre_broadcast(&pre_anchor)?;

        let txid = self.broadcast_raw_transaction(signed_hex).await?;

        // Lock the continuation output persistently so wallet coin selection cannot accidentally spend it
        self.lock_continuation(&txid, continuation_vout).await?;

        let miner_address = self.rpc("getnewaddress", json!([])).await?;
        self.rpc("generatetoaddress", json!([1, miner_address]))
            .await?;

        let tx = self.rpc("getrawtransaction", json!([txid, true])).await?;
        let confirmations = tx["confirmations"].as_u64().unwrap_or(0) as u32;
        let block_hash = tx["blockhash"].as_str().map(str::to_owned);

        Ok(BitcoinAnchor {
            network: BitcoinNetwork::Regtest,
            txid,
            block_hash,
            block_height: None,
            confirmations,
            commitment,
            verified: confirmations > 0,
            prev_txid: None,
            prev_vout: None,
            continuation_vout: Some(continuation_vout),
            chain_index: Some(0),
        })
    }

    /// Create, fund, sign, broadcast and mine the next Catena anchor transaction in sequence.
    ///
    /// Spends the previous continuation UTXO `(prev_anchor.txid, prev_anchor.continuation_vout)`.
    /// Creates a new continuation UTXO of 1,000 satoshis and an OP_RETURN with the next commitment.
    pub async fn anchor_catena_next(
        &self,
        checkpoint_hash: &str,
        prev_anchor: &BitcoinAnchor,
    ) -> crate::Result<BitcoinAnchor> {
        self.anchor_catena_next_with_hook(checkpoint_hash, prev_anchor, |_| Ok(()))
            .await
    }

    /// Create, fund, and sign the next Catena anchor transaction without broadcasting it.
    ///
    /// Returns the signed transaction hex and the unbroadcasted `BitcoinAnchor` candidate.
    pub async fn create_signed_catena_next(
        &self,
        checkpoint_hash: &str,
        prev_anchor: &BitcoinAnchor,
    ) -> crate::Result<(String, BitcoinAnchor)> {
        let prev_continuation_vout = prev_anchor.continuation_vout.ok_or_else(|| {
            crate::SatsPathError::ValidationError(
                "previous anchor is missing continuation_vout for chaining".into(),
            )
        })?;

        let next_index = prev_anchor.chain_index.unwrap_or(0) + 1;
        let commitment = catena_commitment(checkpoint_hash, next_index)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?;

        let continuation_addr = self
            .rpc("getnewaddress", json!([]))
            .await?
            .as_str()
            .ok_or_else(|| {
                crate::SatsPathError::NetworkError("missing continuation address".into())
            })?
            .to_owned();

        let inputs = json!([
            {"txid": prev_anchor.txid, "vout": prev_continuation_vout}
        ]);
        let outputs = json!([
            {"data": commitment},
            {&continuation_addr: CONTINUATION_BTC}
        ]);
        let raw = self
            .rpc("createrawtransaction", json!([inputs, outputs]))
            .await?;
        let funded = self
            .rpc("fundrawtransaction", json!([raw, {"changePosition": 2}]))
            .await?;
        let signed = self
            .rpc("signrawtransactionwithwallet", json!([funded["hex"]]))
            .await?;
        if signed["complete"] != true {
            return Err(crate::SatsPathError::NetworkError(
                "Bitcoin Core did not fully sign chained anchor transaction".into(),
            ));
        }
        let signed_hex = signed["hex"]
            .as_str()
            .ok_or_else(|| crate::SatsPathError::NetworkError("missing signed hex".into()))?;

        // Pre-broadcast validation: verify vin[0], vout[0] commitment, and continuation output before broadcast
        let decoded = self
            .rpc("decoderawtransaction", json!([signed_hex]))
            .await?;

        let expected_commitment_script = format!("6a20{commitment}");
        let commitment_valid = decoded["vout"]
            .as_array()
            .and_then(|vouts| vouts.first())
            .and_then(|v0| v0["scriptPubKey"]["hex"].as_str())
            == Some(&expected_commitment_script);
        if !commitment_valid {
            return Err(crate::SatsPathError::ValidationError(
                "vout[0] is not the expected Catena OP_RETURN commitment".into(),
            ));
        }

        let inputs_spent = decoded["vin"]
            .as_array()
            .and_then(|vins| vins.first())
            .map(|vin| {
                vin["txid"].as_str() == Some(&prev_anchor.txid)
                    && vin["vout"].as_u64() == Some(prev_continuation_vout as u64)
            })
            .unwrap_or(false);

        if !inputs_spent {
            return Err(crate::SatsPathError::ValidationError(
                "Chained anchor transaction vin[0] does not spend the required predecessor continuation UTXO".into(),
            ));
        }

        let next_continuation_vout =
            find_continuation_vout_for_address(&decoded, &continuation_addr).ok_or_else(|| {
                crate::SatsPathError::NetworkError(
                    "could not locate 1000-sat continuation UTXO in decoded chained tx".into(),
                )
            })?;
        if next_continuation_vout != super::catena::CATENA_CONTINUATION_VOUT {
            return Err(crate::SatsPathError::ValidationError(format!(
                "continuation_vout is {next_continuation_vout}, expected fixed index {}",
                super::catena::CATENA_CONTINUATION_VOUT
            )));
        }
        let decoded_txid = decoded["txid"].as_str().ok_or_else(|| {
            crate::SatsPathError::NetworkError("missing txid in decoded chained tx".into())
        })?;

        let pre_anchor = BitcoinAnchor {
            network: BitcoinNetwork::Regtest,
            txid: decoded_txid.to_string(),
            block_hash: None,
            block_height: None,
            confirmations: 0,
            commitment,
            verified: false,
            prev_txid: Some(prev_anchor.txid.clone()),
            prev_vout: Some(prev_continuation_vout),
            continuation_vout: Some(next_continuation_vout),
            chain_index: Some(next_index),
        };

        Ok((signed_hex.to_string(), pre_anchor))
    }

    /// Broadcast a raw signed transaction to the Bitcoin network.
    pub async fn broadcast_raw_transaction(&self, tx_hex: &str) -> crate::Result<String> {
        let txid = self
            .rpc("sendrawtransaction", json!([tx_hex]))
            .await?
            .as_str()
            .ok_or_else(|| crate::SatsPathError::NetworkError("missing anchor txid".into()))?
            .to_owned();
        Ok(txid)
    }

    /// Create, fund, sign, broadcast and mine the next Catena anchor transaction with a pre-broadcast hook.
    pub async fn anchor_catena_next_with_hook<F>(
        &self,
        checkpoint_hash: &str,
        prev_anchor: &BitcoinAnchor,
        on_pre_broadcast: F,
    ) -> crate::Result<BitcoinAnchor>
    where
        F: FnOnce(&BitcoinAnchor) -> crate::Result<()>,
    {
        self.ensure_txindex().await?;
        let (signed_hex, pre_anchor) = self
            .create_signed_catena_next(checkpoint_hash, prev_anchor)
            .await?;
        on_pre_broadcast(&pre_anchor)?;

        let txid = self.broadcast_raw_transaction(&signed_hex).await?;

        let continuation_vout = pre_anchor.continuation_vout.ok_or_else(|| {
            crate::SatsPathError::ValidationError("missing continuation_vout in pre-anchor".into())
        })?;
        self.lock_continuation(&txid, continuation_vout).await?;

        let miner_address = self.rpc("getnewaddress", json!([])).await?;
        self.rpc("generatetoaddress", json!([1, miner_address]))
            .await?;

        let tx = self.rpc("getrawtransaction", json!([&txid, true])).await?;
        let confirmations = tx["confirmations"].as_u64().unwrap_or(0) as u32;
        let block_hash = tx["blockhash"].as_str().map(str::to_owned);

        Ok(BitcoinAnchor {
            network: BitcoinNetwork::Regtest,
            txid,
            block_hash,
            block_height: None,
            confirmations,
            commitment: pre_anchor.commitment,
            verified: confirmations > 0,
            prev_txid: pre_anchor.prev_txid,
            prev_vout: pre_anchor.prev_vout,
            continuation_vout: pre_anchor.continuation_vout,
            chain_index: pre_anchor.chain_index,
        })
    }

    /// Trace backwards through Bitcoin transactions from `latest_txid` to pinned `(trusted_txid, trusted_vout)` at `trusted_index`,
    /// verifying that each anchor spent the previous continuation UTXO.
    ///
    /// The parent transaction fetched in step `i` is cached and used as the child transaction in step `i+1`,
    /// reducing RPC calls from 2N to N+1.
    pub async fn verify_catena_chain_bounded(
        &self,
        latest_txid: &str,
        trusted_txid: &str,
        trusted_vout: u32,
        trusted_index: u64,
        max_hops: usize,
    ) -> crate::Result<Vec<BitcoinAnchor>> {
        self.ensure_txindex().await?;
        if trusted_vout != super::catena::CATENA_CONTINUATION_VOUT {
            return Err(crate::SatsPathError::ValidationError(format!(
                "trusted_vout is {trusted_vout}, expected fixed index {}",
                super::catena::CATENA_CONTINUATION_VOUT
            )));
        }
        let mut chain = Vec::new();
        let mut curr_txid = latest_txid.to_string();
        let mut successor_continuation_vout: Option<u32> = None;
        let mut cached_tx: Option<Value> = None;

        loop {
            if chain.len() >= max_hops {
                return Err(crate::SatsPathError::ValidationError(format!(
                    "Catena chain traversal exceeded maximum allowed hops ({max_hops})"
                )));
            }

            let tx = match cached_tx.take() {
                Some(t) => t,
                None => {
                    self.rpc("getrawtransaction", json!([curr_txid, true]))
                        .await?
                }
            };
            let confirmations = tx["confirmations"].as_u64().unwrap_or(0) as u32;
            if confirmations == 0 {
                return Err(crate::SatsPathError::ValidationError(format!(
                    "Catena anchor tx {curr_txid} is unconfirmed"
                )));
            }

            let vouts = tx["vout"].as_array().ok_or_else(|| {
                crate::SatsPathError::ValidationError(format!("missing vout in tx {curr_txid}"))
            })?;
            let vout_0 = vouts.first().ok_or_else(|| {
                crate::SatsPathError::ValidationError(format!("empty vout in tx {curr_txid}"))
            })?;
            let hex_0 = vout_0["scriptPubKey"]["hex"].as_str().unwrap_or("");
            let stripped = hex_0.strip_prefix("6a20").ok_or_else(|| {
                crate::SatsPathError::ValidationError(format!(
                    "tx {curr_txid} vout[0] is not a Catena OP_RETURN commitment starting with 6a20"
                ))
            })?;
            if stripped.len() != 64 {
                return Err(crate::SatsPathError::ValidationError(format!(
                    "tx {curr_txid} vout[0] commitment payload is not 32 bytes (64 hex characters)"
                )));
            }
            let commitment = stripped.to_string();

            let op_return_count = vouts
                .iter()
                .filter(|out| {
                    out["scriptPubKey"]["hex"]
                        .as_str()
                        .map(|h| h.starts_with("6a"))
                        .unwrap_or(false)
                })
                .count();
            if op_return_count > 1 {
                return Err(crate::SatsPathError::ValidationError(format!(
                    "tx {curr_txid} contains multiple OP_RETURN outputs ({op_return_count})"
                )));
            }

            // Verify continuation output exists at canonical index 1 with 1,000 sats
            let cont_out = vouts
                .get(super::catena::CATENA_CONTINUATION_VOUT as usize)
                .ok_or_else(|| {
                    crate::SatsPathError::ValidationError(format!(
                        "tx {curr_txid} is missing continuation output at index {}",
                        super::catena::CATENA_CONTINUATION_VOUT
                    ))
                })?;
            let cont_sats = parse_sats(&cont_out["value"]).unwrap_or(0);
            if cont_sats != CONTINUATION_SATOSHIS {
                return Err(crate::SatsPathError::ValidationError(format!(
                    "tx {curr_txid} continuation outpoint at index {} has {cont_sats} sats, expected {CONTINUATION_SATOSHIS}",
                    super::catena::CATENA_CONTINUATION_VOUT
                )));
            }

            let block_hash = tx["blockhash"].as_str().map(str::to_owned);

            if curr_txid == trusted_txid {
                let trusted_out = vouts.get(trusted_vout as usize).ok_or_else(|| {
                    crate::SatsPathError::ValidationError(format!(
                        "trusted_vout {trusted_vout} out of bounds in trusted tx {curr_txid}"
                    ))
                })?;
                let trusted_sats = parse_sats(&trusted_out["value"]).unwrap_or(0);
                if trusted_sats != CONTINUATION_SATOSHIS {
                    return Err(crate::SatsPathError::ValidationError(format!(
                        "Trusted outpoint {curr_txid}:{trusted_vout} has {trusted_sats} sats, expected {CONTINUATION_SATOSHIS}"
                    )));
                }
                if let Some(successor_vout) = successor_continuation_vout {
                    if successor_vout != trusted_vout {
                        return Err(crate::SatsPathError::ValidationError(format!(
                            "Successor anchor vin[0] spent vout {successor_vout}, but pinned trusted_vout is {trusted_vout}"
                        )));
                    }
                }
                let (prev_txid, prev_vout) = if trusted_index == 0 {
                    (None, None)
                } else {
                    let vin_0 = tx["vin"].as_array().and_then(|v| v.first());
                    let p_txid = vin_0.and_then(|v| v["txid"].as_str()).map(str::to_owned);
                    let p_vout = vin_0.and_then(|v| v["vout"].as_u64()).map(|v| v as u32);
                    (p_txid, p_vout)
                };
                chain.push(BitcoinAnchor {
                    network: BitcoinNetwork::Regtest,
                    txid: curr_txid,
                    block_hash,
                    block_height: None,
                    confirmations,
                    commitment,
                    verified: true,
                    prev_txid,
                    prev_vout,
                    continuation_vout: Some(trusted_vout),
                    chain_index: Some(trusted_index),
                });
                break;
            }

            // In Catena, vin[0] MUST spend the predecessor's continuation UTXO
            let vins = tx["vin"].as_array().ok_or_else(|| {
                crate::SatsPathError::ValidationError(format!("missing vin in tx {curr_txid}"))
            })?;
            let vin_0 = vins.first().ok_or_else(|| {
                crate::SatsPathError::ValidationError(format!("empty vin in tx {curr_txid}"))
            })?;
            let vin_txid = vin_0["txid"].as_str().ok_or_else(|| {
                crate::SatsPathError::ValidationError(format!(
                    "missing txid in vin[0] of tx {curr_txid}"
                ))
            })?;
            let vin_vout = vin_0["vout"].as_u64().ok_or_else(|| {
                crate::SatsPathError::ValidationError(format!(
                    "missing vout in vin[0] of tx {curr_txid}"
                ))
            })? as u32;

            if vin_vout != super::catena::CATENA_CONTINUATION_VOUT {
                return Err(crate::SatsPathError::ValidationError(format!(
                    "tx {curr_txid} vin[0] spent vout {vin_vout}, expected fixed index {}",
                    super::catena::CATENA_CONTINUATION_VOUT
                )));
            }

            let parent_tx = self
                .rpc("getrawtransaction", json!([vin_txid, true]))
                .await?;

            // Verify parent transaction contains a valid Catena OP_RETURN output (6a20 + 32-byte hash)
            let parent_has_op_return = parent_tx["vout"].as_array().is_some_and(|outputs| {
                outputs.iter().any(|out| {
                    out["scriptPubKey"]["hex"]
                        .as_str()
                        .map(|h| h.starts_with("6a20") && h.len() == 68)
                        .unwrap_or(false)
                })
            });
            if !parent_has_op_return {
                return Err(crate::SatsPathError::ValidationError(format!(
                    "Parent tx {vin_txid} does not contain a valid Catena OP_RETURN output (6a20 + 32-byte hash)"
                )));
            }

            // Verify parent output vin_0.vout is the 1000-sat continuation UTXO
            let parent_vouts = parent_tx["vout"].as_array().ok_or_else(|| {
                crate::SatsPathError::ValidationError(format!(
                    "missing vout in parent tx {vin_txid}"
                ))
            })?;
            let parent_out = parent_vouts.get(vin_vout as usize).ok_or_else(|| {
                crate::SatsPathError::ValidationError(format!(
                    "vout {vin_vout} out of bounds in parent tx {vin_txid}"
                ))
            })?;
            let sats = parse_sats(&parent_out["value"]).unwrap_or(0);
            if sats != CONTINUATION_SATOSHIS {
                return Err(crate::SatsPathError::ValidationError(format!(
                    "Tx {curr_txid} vin[0] spent output {vin_txid}:{vin_vout} with {sats} sats, expected continuation UTXO of {CONTINUATION_SATOSHIS} sats"
                )));
            }

            let prev_txid = vin_txid.to_string();
            let prev_vout = vin_vout;

            chain.push(BitcoinAnchor {
                network: BitcoinNetwork::Regtest,
                txid: curr_txid.clone(),
                block_hash,
                block_height: None,
                confirmations,
                commitment,
                verified: true,
                prev_txid: Some(prev_txid.clone()),
                prev_vout: Some(prev_vout),
                continuation_vout: Some(super::catena::CATENA_CONTINUATION_VOUT),
                chain_index: None,
            });

            curr_txid = prev_txid;
            successor_continuation_vout = Some(prev_vout);
            cached_tx = Some(parent_tx);
        }

        chain.reverse();
        for (idx, anchor) in chain.iter_mut().enumerate() {
            anchor.chain_index = Some(trusted_index + idx as u64);
        }

        Ok(chain)
    }

    /// Trace backwards through Bitcoin transactions from `latest_txid` to pinned `(genesis_txid, genesis_vout)`,
    /// verifying that each anchor spent the previous continuation UTXO.
    pub async fn verify_catena_chain(
        &self,
        latest_txid: &str,
        genesis_txid: &str,
        genesis_vout: u32,
    ) -> crate::Result<Vec<BitcoinAnchor>> {
        self.verify_catena_chain_bounded(
            latest_txid,
            genesis_txid,
            genesis_vout,
            0,
            MAX_CATENA_HOPS,
        )
        .await
    }

    /// Trace backwards through Bitcoin transactions from `latest_txid` to pinned `(genesis_txid, genesis_vout)`,
    /// verifying continuation UTXO spends and cryptographic binding to `checkpoint_hashes`.
    pub async fn verify_catena_chain_with_checkpoints(
        &self,
        latest_txid: &str,
        genesis_txid: &str,
        genesis_vout: u32,
        checkpoint_hashes: &[&str],
    ) -> crate::Result<Vec<BitcoinAnchor>> {
        self.verify_catena_chain_with_checkpoints_bounded(
            latest_txid,
            genesis_txid,
            genesis_vout,
            0,
            MAX_CATENA_HOPS,
            checkpoint_hashes,
        )
        .await
    }

    /// Trace backwards through Bitcoin transactions from `latest_txid` to pinned `(trusted_txid, trusted_vout)` at `trusted_index`,
    /// verifying continuation UTXO spends and cryptographic binding to `checkpoint_hashes`.
    pub async fn verify_catena_chain_with_checkpoints_bounded(
        &self,
        latest_txid: &str,
        trusted_txid: &str,
        trusted_vout: u32,
        trusted_index: u64,
        max_hops: usize,
        checkpoint_hashes: &[&str],
    ) -> crate::Result<Vec<BitcoinAnchor>> {
        let chain = self
            .verify_catena_chain_bounded(
                latest_txid,
                trusted_txid,
                trusted_vout,
                trusted_index,
                max_hops,
            )
            .await?;
        super::catena::verify_catena_commitments_bounded(&chain, checkpoint_hashes, trusted_index)
            .map_err(|e| crate::SatsPathError::ValidationError(e.to_string()))?;
        Ok(chain)
    }

    pub async fn verify_anchor(
        &self,
        txid: &str,
        commitment: &str,
    ) -> crate::Result<BitcoinAnchor> {
        let tx = self.rpc("getrawtransaction", json!([txid, true])).await?;
        let expected_script = format!("6a20{commitment}");
        let matched = tx["vout"].as_array().is_some_and(|outputs| {
            outputs
                .iter()
                .any(|out| out["scriptPubKey"]["hex"].as_str() == Some(&expected_script))
        });
        let confirmations = tx["confirmations"].as_u64().unwrap_or(0) as u32;
        Ok(BitcoinAnchor {
            network: BitcoinNetwork::Regtest,
            txid: txid.to_owned(),
            block_hash: tx["blockhash"].as_str().map(str::to_owned),
            block_height: None,
            confirmations,
            commitment: commitment.to_owned(),
            verified: matched && confirmations > 0,
            prev_txid: None,
            prev_vout: None,
            continuation_vout: None,
            chain_index: None,
        })
    }

    /// Retrieve decoded transaction if present in mempool or blockchain, returning None if unknown.
    pub async fn get_raw_transaction(&self, txid: &str) -> crate::Result<Option<Value>> {
        match self.rpc("getrawtransaction", json!([txid, true])).await {
            Ok(tx) => Ok(Some(tx)),
            Err(crate::SatsPathError::NetworkError(ref msg))
                if msg.contains("No such mempool or blockchain transaction")
                    || msg.contains("code\":-5")
                    || msg.contains("code: -5") =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Retrieve in-wallet transaction if tracked by the Bitcoin Core wallet, returning None if unknown to the wallet.
    pub async fn get_wallet_transaction(&self, txid: &str) -> crate::Result<Option<Value>> {
        match self.rpc("gettransaction", json!([txid])).await {
            Ok(tx) => Ok(Some(tx)),
            Err(crate::SatsPathError::NetworkError(ref msg))
                if msg.contains("Invalid or non-wallet transaction id")
                    || msg.contains("code\":-5")
                    || msg.contains("code: -5") =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// Check if a specific outpoint is currently unspent on the blockchain (via gettxout).
    pub async fn is_tx_out_unspent(&self, txid: &str, vout: u32) -> crate::Result<bool> {
        let res = self.rpc("gettxout", json!([txid, vout])).await?;
        Ok(!res.is_null())
    }

    /// Mine a given number of blocks to a new address.
    pub async fn mine_blocks(&self, count: u32) -> crate::Result<()> {
        let miner_address = self.rpc("getnewaddress", json!([])).await?;
        self.rpc("generatetoaddress", json!([count, miner_address]))
            .await?;
        Ok(())
    }

    /// Persistently lock a continuation outpoint to protect it from wallet coin selection.
    pub async fn lock_continuation(&self, txid: &str, vout: u32) -> crate::Result<()> {
        let lock_res = self
            .rpc(
                "lockunspent",
                json!([false, [{"txid": txid, "vout": vout}], true]),
            )
            .await?;
        if lock_res.as_bool() != Some(true) {
            return Err(crate::SatsPathError::NetworkError(
                "lockunspent failed to lock continuation output".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Default)]
pub struct MockAnchorClient;

impl MockAnchorClient {
    pub fn confirmed(checkpoint_hash: &str) -> crate::Result<BitcoinAnchor> {
        Ok(BitcoinAnchor {
            network: BitcoinNetwork::Regtest,
            txid: "11".repeat(32),
            block_hash: Some("22".repeat(32)),
            block_height: Some(101),
            confirmations: 1,
            commitment: anchor_commitment(checkpoint_hash)
                .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?,
            verified: true,
            prev_txid: None,
            prev_vout: None,
            continuation_vout: None,
            chain_index: None,
        })
    }

    pub fn catena_genesis(checkpoint_hash: &str) -> crate::Result<BitcoinAnchor> {
        let commitment = catena_commitment(checkpoint_hash, 0)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?;
        Ok(BitcoinAnchor {
            network: BitcoinNetwork::Regtest,
            txid: "10".repeat(32),
            block_hash: Some("20".repeat(32)),
            block_height: Some(101),
            confirmations: 1,
            commitment,
            verified: true,
            prev_txid: None,
            prev_vout: None,
            continuation_vout: Some(1),
            chain_index: Some(0),
        })
    }

    pub fn catena_next(
        checkpoint_hash: &str,
        prev: &BitcoinAnchor,
    ) -> crate::Result<BitcoinAnchor> {
        let chain_index = prev.chain_index.unwrap_or(0) + 1;
        let commitment = catena_commitment(checkpoint_hash, chain_index)
            .map_err(|e| crate::SatsPathError::SerializationError(e.to_string()))?;
        let txid = format!("{:064x}", chain_index + 0x10);
        Ok(BitcoinAnchor {
            network: BitcoinNetwork::Regtest,
            txid,
            block_hash: Some("20".repeat(32)),
            block_height: Some(101 + chain_index),
            confirmations: 1,
            commitment,
            verified: true,
            prev_txid: Some(prev.txid.clone()),
            prev_vout: prev.continuation_vout,
            continuation_vout: Some(1),
            chain_index: Some(chain_index),
        })
    }
}
