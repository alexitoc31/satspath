#[tokio::test]
#[ignore = "requires an explicitly configured Bitcoin Core regtest node"]
async fn checkpoint_op_return_round_trip_on_bitcoin_core_regtest() {
    let checkpoint_hash = "42".repeat(32);
    let client = satspath_core::transparency::RegtestAnchorClient::from_env().unwrap();
    let receipt = client.anchor_checkpoint(&checkpoint_hash).await.unwrap();
    assert_eq!(receipt.network, satspath_core::BitcoinNetwork::Regtest);
    assert!(receipt.verified);
    assert!(receipt.confirmations > 0);
    let fetched = client
        .verify_anchor(&receipt.txid, &receipt.commitment)
        .await
        .unwrap();
    assert!(fetched.verified);
    assert_eq!(fetched.commitment, receipt.commitment);
}

#[tokio::test]
#[ignore = "requires an explicitly configured Bitcoin Core regtest node"]
async fn catena_chain_anchoring_and_backward_verification_on_regtest() {
    let client = satspath_core::transparency::RegtestAnchorClient::from_env().unwrap();

    let cp0 = "00".repeat(32);
    let cp1 = "11".repeat(32);
    let cp2 = "22".repeat(32);

    // 1. Create Catena Genesis anchor
    let a0 = client.anchor_catena_genesis(&cp0).await.unwrap();
    assert_eq!(a0.chain_index, Some(0));
    assert!(a0.prev_txid.is_none());
    assert!(a0.prev_vout.is_none());
    assert!(a0.continuation_vout.is_some());
    assert!(a0.confirmations > 0);
    assert!(a0.verified);

    // 2. Create Catena step 1 anchor spending genesis continuation UTXO
    let a1 = client.anchor_catena_next(&cp1, &a0).await.unwrap();
    assert_eq!(a1.chain_index, Some(1));
    assert_eq!(a1.prev_txid, Some(a0.txid.clone()));
    assert_eq!(a1.prev_vout, a0.continuation_vout);
    assert!(a1.continuation_vout.is_some());
    assert!(a1.confirmations > 0);
    assert!(a1.verified);

    // 3. Create Catena step 2 anchor spending step 1 continuation UTXO
    let a2 = client.anchor_catena_next(&cp2, &a1).await.unwrap();
    assert_eq!(a2.chain_index, Some(2));
    assert_eq!(a2.prev_txid, Some(a1.txid.clone()));
    assert_eq!(a2.prev_vout, a1.continuation_vout);
    assert!(a2.continuation_vout.is_some());
    assert!(a2.confirmations > 0);
    assert!(a2.verified);

    // 4. Verify chain backwards via Bitcoin Core RPC
    let verified_chain = client
        .verify_catena_chain(&a2.txid, &a0.txid, a0.continuation_vout.unwrap())
        .await
        .unwrap();
    assert_eq!(verified_chain.len(), 3);
    assert_eq!(verified_chain[0].txid, a0.txid);
    assert_eq!(verified_chain[1].txid, a1.txid);
    assert_eq!(verified_chain[2].txid, a2.txid);

    // 5. Verify chain pure links in-memory
    assert!(satspath_core::transparency::verify_catena_links(&verified_chain).unwrap());

    // 6. Verify chain commitments against expected checkpoints
    assert!(satspath_core::transparency::verify_catena_commitments(
        &verified_chain,
        &[&cp0, &cp1, &cp2]
    )
    .unwrap());

    // 7. Verify full chain backwards with checkpoint binding via RPC
    let verified_with_cps = client
        .verify_catena_chain_with_checkpoints(
            &a2.txid,
            &a0.txid,
            a0.continuation_vout.unwrap(),
            &[&cp0, &cp1, &cp2],
        )
        .await
        .unwrap();
    assert_eq!(verified_with_cps.len(), 3);
}

#[tokio::test]
#[ignore = "requires an explicitly configured Bitcoin Core regtest node"]
async fn catena_double_spend_equivocation_rejected_by_bitcoin_core() {
    let client = satspath_core::transparency::RegtestAnchorClient::from_env().unwrap();

    let cp_genesis = "aa".repeat(32);
    let cp_branch1 = "bb".repeat(32);
    let cp_branch2 = "cc".repeat(32);

    // 1. Create Genesis
    let genesis = client.anchor_catena_genesis(&cp_genesis).await.unwrap();

    // 2. Pre-sign both branch 1 and branch 2 while genesis continuation UTXO is still unspent
    let (branch1_hex, branch1_pre) = client
        .create_signed_catena_next(&cp_branch1, &genesis)
        .await
        .unwrap();
    let (branch2_hex, branch2_pre) = client
        .create_signed_catena_next(&cp_branch2, &genesis)
        .await
        .unwrap();

    // 3. Broadcast and mine branch 1 (confirmed)
    let branch1_txid = client
        .broadcast_raw_transaction(&branch1_hex)
        .await
        .unwrap();
    client.mine_blocks(1).await.unwrap();

    let branch1_tx = client
        .get_raw_transaction(&branch1_txid)
        .await
        .unwrap()
        .expect("branch1 tx must be in blockchain");
    assert!(branch1_tx["confirmations"].as_u64().unwrap_or(0) > 0);

    // Verify genesis continuation UTXO is now spent
    assert!(!client
        .is_tx_out_unspent(&genesis.txid, genesis.continuation_vout.unwrap())
        .await
        .unwrap());

    // 4. Attempt to equivocate by broadcasting branch 2 spending the SAME genesis continuation UTXO
    // Bitcoin Core must reject this transaction via native consensus/mempool rules because genesis continuation UTXO is already spent!
    let equivocation_attempt = client.broadcast_raw_transaction(&branch2_hex).await;
    assert!(
        equivocation_attempt.is_err(),
        "Bitcoin Core must reject double-spending a continuation UTXO"
    );
    let err_msg = equivocation_attempt.unwrap_err().to_string();
    assert!(
        err_msg.contains("bad-txns-inputs-missingorspent")
            || err_msg.contains("txn-mempool-conflict")
            || err_msg.contains("Missing inputs")
            || err_msg.contains("missing-inputs"),
        "Bitcoin Core error must indicate input conflict or spent inputs: {err_msg}"
    );

    // 5. In-memory equivocation detector verification
    let mut branch1_anchor = branch1_pre;
    branch1_anchor.txid = branch1_txid;
    branch1_anchor.confirmations = branch1_tx["confirmations"].as_u64().unwrap_or(1) as u32;
    branch1_anchor.verified = true;

    let equivocation_evidence =
        satspath_core::transparency::detect_catena_equivocation(&branch1_anchor, &branch2_pre);
    assert!(equivocation_evidence.is_some());
    let proof = equivocation_evidence.unwrap();
    assert_eq!(proof.spent_txid, genesis.txid);
    assert!(proof.evidence.contains("Candidate double-spend detected"));
}
