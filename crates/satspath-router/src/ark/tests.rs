//! Unit tests with HTTP mocks for the Ark ASP connector, VTXO covenant tree DAG
//! verification, and settlement handoff structures (Issue #155).

use super::*;

const ASP_PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const RECEIVER_PUBKEY: &str = "03c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5";

fn sample_asp_info() -> ArkAspInfo {
    ArkAspInfo {
        pubkey: ASP_PUBKEY.to_string(),
        network: "signet".to_string(),
        round_interval_secs: Some(10),
        vtxo_tree_expiry: Some(604_800),
        unilateral_exit_delay: 512,
        dust_limit_sats: 330,
        boarding_descriptor_template: Some(
            "tr(ASP_KEY,{and_v(v:pk(ASP_KEY),pk(USER_KEY)),older(512)})".to_string(),
        ),
        fees: Some(ArkFeeSchedule {
            base_fee_sats: 15,
            ppm_rate: 500, // 0.05%
            onboard_fee_sats: 250,
            offboard_fee_sats: 350,
        }),
    }
}

fn arkd_info() -> serde_json::Value {
    serde_json::json!({
        "signerPubkey": ASP_PUBKEY,
        "network": "signet",
        "sessionDuration": "10",
        "unilateralExitDelay": "512",
        "dust": "330",
        "fees": {
            "intentFee": {
                "offchainInput": "0",
                "offchainOutput": "amount * 0.001",
                "onchainInput": "250",
                "onchainOutput": "350",
            },
            "txFeeRate": "1.5",
        },
    })
}

#[tokio::test]
async fn arkd_discovery_maps_known_fields_and_rejects_oor_without_expiry() {
    for (as_strings, include_duration) in [(true, true), (false, true), (true, false)] {
        let mut wire = arkd_info();
        if !as_strings {
            wire["unilateralExitDelay"] = serde_json::json!(512);
            wire["dust"] = serde_json::json!(330);
            wire["sessionDuration"] = serde_json::json!(604_800);
        }
        if !include_duration {
            wire.as_object_mut().unwrap().remove("sessionDuration");
        }
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/info")
            .with_status(200)
            .with_body(wire.to_string())
            .expect(2)
            .create_async()
            .await;
        let client = LiveArkAspClient::new_for_test(server.url(), ArkNetwork::Signet);
        let info = client.get_asp_info().await.unwrap();
        assert_eq!(info.pubkey, ASP_PUBKEY);
        assert_eq!(info.network, "signet");
        assert_eq!(info.unilateral_exit_delay, 512);
        assert_eq!(info.dust_limit_sats, 330);
        assert_eq!(info.round_interval_secs, None);
        assert_eq!(info.vtxo_tree_expiry, None);
        assert_eq!(info.boarding_descriptor_template, None);
        assert_eq!(info.fees, None);
        assert!(info.estimate_transfer_fee(100_000).is_err());
        let error = client
            .build_oor_handoff(&format!("{}:0", "aa".repeat(32)), RECEIVER_PUBKEY, 100_000)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("expiry unavailable"), "{error}");
        mock.assert_async().await;
    }
}

#[tokio::test]
async fn arkd_discovery_rejects_invalid_wire_data() {
    let mut cases = vec![serde_json::to_value(sample_asp_info()).unwrap()];
    for (field, value) in [
        ("signerPubkey", serde_json::json!("invalid")),
        ("unilateralExitDelay", serde_json::json!(0)),
        ("unilateralExitDelay", serde_json::json!("-1")),
        (
            "unilateralExitDelay",
            serde_json::json!("9223372036854775808"),
        ),
        ("dust", serde_json::json!(-1)),
        ("dust", serde_json::json!(1.5)),
        ("dust", serde_json::json!("invalid")),
        (
            "fees",
            serde_json::json!({"base_fee_sats": 0, "ppm_rate": 0}),
        ),
    ] {
        let mut wire = arkd_info();
        wire[field] = value;
        cases.push(wire);
    }
    for field in ["signerPubkey", "unilateralExitDelay", "dust", "fees"] {
        let mut wire = arkd_info();
        wire.as_object_mut().unwrap().remove(field);
        cases.push(wire);
    }
    for wire in cases {
        let mut server = mockito::Server::new_async().await;
        let mock = server
            .mock("GET", "/v1/info")
            .with_status(200)
            .with_body(wire.to_string())
            .create_async()
            .await;
        let client = LiveArkAspClient::new_for_test(server.url(), ArkNetwork::Signet);
        assert!(client.get_asp_info().await.is_err(), "{wire}");
        mock.assert_async().await;
    }
}

#[test]
fn asp_info_validates_optional_timing_and_explicit_fee_schedule() {
    let mut info = sample_asp_info();
    assert_eq!(info.estimate_transfer_fee(100_000).unwrap(), 65);
    info.round_interval_secs = None;
    info.vtxo_tree_expiry = None;
    info.validate().unwrap();
    info.round_interval_secs = Some(0);
    assert!(info.validate().is_err());
    info.round_interval_secs = Some(10);
    info.vtxo_tree_expiry = Some(0);
    assert!(info.validate().is_err());
}

#[tokio::test]
async fn test_live_ark_asp_connector_oor_and_forfeit_round_submission() {
    let mut server = mockito::Server::new_async().await;
    let info = sample_asp_info();

    let oor_response = ArkSubmitTxResponse {
        ark_txid: "11".repeat(32),
        final_ark_tx: "wallet-cosigned-ark-tx".to_string(),
        signed_checkpoint_txs: vec!["wallet-cosigned-checkpoint".to_string()],
    };
    let tx_request = ArkSettlementSubmission::Transaction(ArkSubmitTxRequest {
        signed_ark_tx: "wallet-signed-ark-tx".to_string(),
        checkpoint_txs: vec!["wallet-checkpoint".to_string()],
    });
    let oor_mock = server
        .mock("POST", "/v1/tx/submit")
        .match_body(mockito::Matcher::Json(serde_json::json!({
            "signedArkTx": "wallet-signed-ark-tx",
            "checkpointTxs": ["wallet-checkpoint"],
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&oor_response).unwrap())
        .create_async()
        .await;

    let round_response = ArkRegisterIntentResponse {
        intent_id: "intent_42".to_string(),
    };
    let intent_request = ArkSettlementSubmission::Intent(ArkRegisterIntentRequest {
        intent: ArkIntent {
            proof: "wallet-bip322-proof".to_string(),
            message: "wallet-intent-message".to_string(),
        },
    });
    let round_mock = server
        .mock("POST", "/v1/batch/registerIntent")
        .match_body(mockito::Matcher::Json(serde_json::json!({
            "intent": {"proof": "wallet-bip322-proof", "message": "wallet-intent-message"},
        })))
        .with_status(200)
        .with_header("content-type", "application/json")
        .with_body(serde_json::to_string(&round_response).unwrap())
        .expect(2)
        .create_async()
        .await;

    let client = LiveArkAspClient::new_for_test(server.url(), ArkNetwork::Signet);

    // Submit a wallet-provided OOR handoff with independently known parameters.
    let sender_vtxo = format!("{}:0", "aa".repeat(32));
    let oor_handoff = sample_oor(client.server_url());
    let submitted_oor = client
        .submit_settlement_handoff(&info, &oor_handoff, &tx_request)
        .await
        .unwrap();
    assert_eq!(
        submitted_oor.receipt().unwrap().vtxo_txid,
        Some("11".repeat(32))
    );
    assert_eq!(
        submitted_oor,
        ArkSettlementSubmissionResponse::Transaction(oor_response)
    );

    // 3. Build and submit an In-Round Forfeit settlement handoff (Arkade Money compatible)
    let forfeit_handoff = ArkSettlementHandoff::InRoundForfeit(ArkForfeitHandoff {
        server_url: client.server_url().to_string(),
        round_id: "round_42".to_string(),
        input_vtxo_outpoint: sender_vtxo,
        connector_outpoint: format!("{}:1", "bb".repeat(32)),
        forfeit_psbt_base64: "cHNidP8BAHECAAAAAQ==".to_string(),
        new_vtxo_tree_root: "22".repeat(32),
        asp_pubkey: ASP_PUBKEY.to_string(),
        receiver_pubkey: RECEIVER_PUBKEY.to_string(),
        amount_sats: 50_000,
    });
    let submitted_round = client
        .submit_settlement_handoff(&info, &forfeit_handoff, &intent_request)
        .await
        .unwrap();
    assert_eq!(submitted_round.receipt().unwrap().status, "registered");
    assert_eq!(
        submitted_round,
        ArkSettlementSubmissionResponse::Intent(round_response)
    );

    // Boarding also registers a wallet-provided intent; the handoff itself is not posted.
    let mut boarding = sample_boarding();
    boarding.server_url = server.url();
    let submitted_boarding = client
        .submit_settlement_handoff(
            &info,
            &ArkSettlementHandoff::Boarding(boarding),
            &intent_request,
        )
        .await
        .unwrap();
    assert_eq!(
        submitted_boarding.receipt().unwrap().submission_id,
        "intent_42"
    );

    oor_mock.assert_async().await;
    round_mock.assert_async().await;
}

fn sample_boarding() -> ArkBoardingHandoff {
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let key = bitcoin::secp256k1::XOnlyPublicKey::from_str(&RECEIVER_PUBKEY[2..]).unwrap();
    let address = Address::p2tr(&secp, key, None, Network::Signet).to_string();
    ArkBoardingHandoff {
        server_url: "https://ark.satspath.dev".to_string(),
        boarding_address: address.clone(),
        asp_pubkey: ASP_PUBKEY.to_string(),
        user_pubkey: RECEIVER_PUBKEY.to_string(),
        exit_delay: 512,
        amount_sats: 10_000,
        bip21_uri: format!("bitcoin:{address}?amount=0.0001"),
    }
}

#[test]
fn boarding_checks_address_amount_network_delay_keys_and_dust() {
    let info = sample_asp_info();
    let valid = sample_boarding();
    assert!(ArkSettlementHandoff::Boarding(valid.clone())
        .validate(&info)
        .is_ok());

    let mut cases = Vec::new();
    let mut b = valid.clone();
    b.amount_sats = 100;
    cases.push((b, "below ASP dust limit"));
    let mut b = valid.clone();
    b.asp_pubkey = RECEIVER_PUBKEY.to_string();
    cases.push((b, "ASP pubkey mismatch"));
    let mut b = valid.clone();
    b.user_pubkey = "invalid".to_string();
    cases.push((b, "invalid boarding user_pubkey"));
    let mut b = valid.clone();
    b.boarding_address = "not-an-address".to_string();
    cases.push((b, "invalid boarding address"));
    let mut b = valid.clone();
    // Use a valid mainnet address to test the network boundary, not a checksum error.
    let secp = bitcoin::secp256k1::Secp256k1::verification_only();
    let key = bitcoin::secp256k1::XOnlyPublicKey::from_str(&RECEIVER_PUBKEY[2..]).unwrap();
    b.boarding_address = Address::p2tr(&secp, key, None, Network::Bitcoin).to_string();
    b.bip21_uri = format!("bitcoin:{}?amount=0.0001", b.boarding_address);
    cases.push((b, "boarding address network mismatch"));
    let mut b = valid.clone();
    let other_key = bitcoin::secp256k1::XOnlyPublicKey::from_str(&ASP_PUBKEY[2..]).unwrap();
    let other_address = Address::p2tr(&secp, other_key, None, Network::Signet);
    b.bip21_uri = format!("bitcoin:{other_address}?amount=0.0001");
    cases.push((b, "BIP-21 address mismatch"));
    let mut b = valid.clone();
    b.exit_delay += 1;
    cases.push((b, "exit delay mismatch"));
    for query in [
        "amount=0.0002",
        "amount=-1",
        "amount=0.000000001",
        "amount=NaN",
        "",
        "amount=0.0002&amount=0.0001",
        "amount=0.0001&req-unknown=x",
    ] {
        let mut b = valid.clone();
        b.bip21_uri = format!("bitcoin:{}?{query}", b.boarding_address);
        assert!(
            ArkSettlementHandoff::Boarding(b).validate(&info).is_err(),
            "{query}"
        );
    }
    for (b, expected) in cases {
        let error = ArkSettlementHandoff::Boarding(b)
            .validate(&info)
            .unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
    let mut regtest_info = info.clone();
    regtest_info.network = "regtest".to_string();
    assert!(ArkSettlementHandoff::Boarding(valid)
        .validate(&regtest_info)
        .is_err());
}

#[test]
fn test_ark_vtxo_covenant_tree_dag_verification() {
    let root_txid = "01".repeat(32);
    let branch_left = "02".repeat(32);
    let branch_right = "03".repeat(32);
    let leaf_alice = "04".repeat(32);
    let leaf_bob = "05".repeat(32);

    let dag = vec![
        ArkVtxoTreeNode {
            txid: root_txid.clone(),
            parent_txid: None,
            vout: 0,
            amount_sats: 100_000,
            asp_cosign_pubkey: ASP_PUBKEY.to_string(),
            receiver_pubkey: None,
            expiry_sequence: 1008,
            children: vec![branch_left.clone(), branch_right.clone()],
        },
        ArkVtxoTreeNode {
            txid: branch_left.clone(),
            parent_txid: Some(root_txid.clone()),
            vout: 0,
            amount_sats: 60_000,
            asp_cosign_pubkey: ASP_PUBKEY.to_string(),
            receiver_pubkey: None,
            expiry_sequence: 1008,
            children: vec![leaf_alice.clone(), leaf_bob.clone()],
        },
        ArkVtxoTreeNode {
            txid: branch_right.clone(),
            parent_txid: Some(root_txid.clone()),
            vout: 1,
            amount_sats: 40_000,
            asp_cosign_pubkey: ASP_PUBKEY.to_string(),
            receiver_pubkey: Some(RECEIVER_PUBKEY.to_string()),
            expiry_sequence: 1008,
            children: Vec::new(),
        },
        ArkVtxoTreeNode {
            txid: leaf_alice.clone(),
            parent_txid: Some(branch_left.clone()),
            vout: 0,
            amount_sats: 35_000,
            asp_cosign_pubkey: ASP_PUBKEY.to_string(),
            receiver_pubkey: Some(RECEIVER_PUBKEY.to_string()),
            expiry_sequence: 1008,
            children: Vec::new(),
        },
        ArkVtxoTreeNode {
            txid: leaf_bob.clone(),
            parent_txid: Some(branch_left.clone()),
            vout: 1,
            amount_sats: 25_000,
            asp_cosign_pubkey: ASP_PUBKEY.to_string(),
            receiver_pubkey: Some(RECEIVER_PUBKEY.to_string()),
            expiry_sequence: 1008,
            children: Vec::new(),
        },
    ];

    // 1. Valid path from root -> branch_left -> leaf_alice passes
    verify_ark_vtxo_dag(
        &dag,
        &root_txid,
        ASP_PUBKEY,
        RECEIVER_PUBKEY,
        &leaf_alice,
        35_000,
    )
    .expect("valid VTXO covenant tree DAG must verify");

    for receiver in [
        None,
        Some(ASP_PUBKEY.to_string()),
        Some("invalid".to_string()),
    ] {
        let mut wrong = dag.clone();
        wrong[3].receiver_pubkey = receiver;
        assert!(verify_ark_vtxo_dag(
            &wrong,
            &root_txid,
            ASP_PUBKEY,
            RECEIVER_PUBKEY,
            &leaf_alice,
            35_000
        )
        .unwrap_err()
        .to_string()
        .contains("receiver pubkey mismatch"));
    }
    assert!(
        verify_ark_vtxo_dag(&dag, &root_txid, ASP_PUBKEY, "invalid", &leaf_alice, 35_000).is_err()
    );
    let mut internal = dag.clone();
    internal[1].receiver_pubkey = Some(RECEIVER_PUBKEY.to_string());
    assert!(verify_ark_vtxo_dag(
        &internal,
        &root_txid,
        ASP_PUBKEY,
        RECEIVER_PUBKEY,
        &branch_left,
        35_000
    )
    .unwrap_err()
    .to_string()
    .contains("must be a leaf"));

    // 2. Under-funded target leaf fails closed
    assert!(verify_ark_vtxo_dag(
        &dag,
        &root_txid,
        ASP_PUBKEY,
        RECEIVER_PUBKEY,
        &leaf_alice,
        36_000
    )
    .is_err());

    // 3. Value inflation (children sum > parent amount) fails closed
    let mut inflated = dag.clone();
    inflated[4].amount_sats = 30_000; // 35_000 + 30_000 = 65_000 > 60_000
    assert!(verify_ark_vtxo_dag(
        &inflated,
        &root_txid,
        ASP_PUBKEY,
        RECEIVER_PUBKEY,
        &leaf_alice,
        35_000
    )
    .is_err());
}

#[test]
fn unavailable_fee_schedule_is_distinct_from_explicit_zero_fees() {
    let info = serde_json::to_value(sample_asp_info()).unwrap();
    assert!(serde_json::from_value::<ArkAspInfo>(info.clone()).is_ok());
    let mut missing = info.clone();
    missing.as_object_mut().unwrap().remove("fees");
    let unknown = serde_json::from_value::<ArkAspInfo>(missing).unwrap();
    assert_eq!(unknown.fees, None);
    assert!(unknown.estimate_transfer_fee(100_000).is_err());
    for field in [
        "base_fee_sats",
        "ppm_rate",
        "onboard_fee_sats",
        "offboard_fee_sats",
    ] {
        let mut missing = info.clone();
        let fees = missing["fees"].as_object_mut().unwrap();
        let value = fees.remove(field).unwrap();
        assert!(
            serde_json::from_value::<ArkAspInfo>(missing.clone()).is_err(),
            "{field}"
        );
        missing["fees"]
            .as_object_mut()
            .unwrap()
            .insert(format!("renamed_{field}"), value);
        assert!(
            serde_json::from_value::<ArkAspInfo>(missing).is_err(),
            "{field}"
        );
    }
    let mut zero = info;
    for value in zero["fees"].as_object_mut().unwrap().values_mut() {
        *value = serde_json::json!(0);
    }
    assert_eq!(
        serde_json::from_value::<ArkAspInfo>(zero)
            .unwrap()
            .estimate_transfer_fee(100_000)
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn asp_info_rejects_wrong_network_and_requires_mainnet_opt_in() {
    for (advertised, expected, opt_in, valid) in [
        ("signet", ArkNetwork::Signet, false, true),
        ("regtest", ArkNetwork::Signet, false, false),
        ("testnet", ArkNetwork::Signet, false, false),
        ("mutinynet", ArkNetwork::Signet, false, false),
        ("mutinynet", ArkNetwork::Mutinynet, false, true),
        ("bitcoin", ArkNetwork::Bitcoin, false, false),
        ("mainnet", ArkNetwork::Bitcoin, false, false),
        ("bitcoin", ArkNetwork::Bitcoin, true, true),
        ("mainnet", ArkNetwork::Bitcoin, true, true),
        ("bitcoin", ArkNetwork::Signet, true, false),
    ] {
        let mut server = mockito::Server::new_async().await;
        let mut info = arkd_info();
        info["network"] = serde_json::json!(advertised);
        let mock = server
            .mock("GET", "/v1/info")
            .with_status(200)
            .with_body(serde_json::to_string(&info).unwrap())
            .create_async()
            .await;
        let client =
            LiveArkAspClient::new_for_test(server.url(), expected).with_mainnet_execution(opt_in);
        assert_eq!(
            client.get_asp_info().await.is_ok(),
            valid,
            "{advertised}, {expected:?}, {opt_in}"
        );
        mock.assert_async().await;
    }
}

fn sample_oor(server_url: &str) -> ArkSettlementHandoff {
    ArkSettlementHandoff::OutOfRound(ArkOorPaymentRequest {
        server_url: server_url.to_string(),
        asp_pubkey: ASP_PUBKEY.to_string(),
        sender_vtxo_outpoint: format!("{}:0", "aa".repeat(32)),
        receiver_pubkey: RECEIVER_PUBKEY.to_string(),
        amount_sats: 100_000,
        fee_sats: 65,
        vtxo_tree_expiry: 604_800,
        ark_uri: "ark:wallet-handoff".to_string(),
    })
}

fn sample_forfeit(server_url: &str) -> ArkSettlementHandoff {
    ArkSettlementHandoff::InRoundForfeit(ArkForfeitHandoff {
        server_url: server_url.to_string(),
        round_id: "round_42".to_string(),
        input_vtxo_outpoint: format!("{}:0", "aa".repeat(32)),
        connector_outpoint: format!("{}:1", "bb".repeat(32)),
        forfeit_psbt_base64: "wallet-forfeit-psbt".to_string(),
        new_vtxo_tree_root: "22".repeat(32),
        asp_pubkey: ASP_PUBKEY.to_string(),
        receiver_pubkey: RECEIVER_PUBKEY.to_string(),
        amount_sats: 50_000,
    })
}

fn wallet_transaction() -> ArkSettlementSubmission {
    ArkSettlementSubmission::Transaction(ArkSubmitTxRequest {
        signed_ark_tx: "wallet-signed-ark-tx".to_string(),
        checkpoint_txs: vec!["wallet-checkpoint".to_string()],
    })
}

fn wallet_intent() -> ArkSettlementSubmission {
    ArkSettlementSubmission::Intent(ArkRegisterIntentRequest {
        intent: ArkIntent {
            proof: "wallet-bip322-proof".to_string(),
            message: "wallet-intent-message".to_string(),
        },
    })
}

#[tokio::test]
async fn submissions_reject_foreign_asp_and_network_before_posting() {
    let mut server = mockito::Server::new_async().await;
    let post = server
        .mock("POST", mockito::Matcher::Any)
        .expect(0)
        .create_async()
        .await;
    let client = LiveArkAspClient::new_for_test(server.url(), ArkNetwork::Signet);
    let mut boarding = sample_boarding();
    boarding.server_url = "https://other-asp.example".to_string();
    for (handoff, payload) in [
        (
            sample_oor("https://other-asp.example"),
            wallet_transaction(),
        ),
        (sample_forfeit("https://other-asp.example"), wallet_intent()),
        (ArkSettlementHandoff::Boarding(boarding), wallet_intent()),
    ] {
        let error = client
            .submit_settlement_handoff(&sample_asp_info(), &handoff, &payload)
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("does not match configured client ASP"),
            "{error}"
        );
    }
    for network in ["regtest", "bitcoin", "mainnet"] {
        let mut info = sample_asp_info();
        info.network = network.to_string();
        for (handoff, payload) in [
            (sample_oor(&server.url()), wallet_transaction()),
            (sample_forfeit(&server.url()), wallet_intent()),
        ] {
            assert!(client
                .submit_settlement_handoff(&info, &handoff, &payload)
                .await
                .unwrap_err()
                .to_string()
                .contains("network"));
        }
    }
    let mainnet = LiveArkAspClient::new_for_test(server.url(), ArkNetwork::Bitcoin);
    let mut info = sample_asp_info();
    info.network = "mainnet".to_string();
    for (handoff, payload) in [
        (sample_oor(&server.url()), wallet_transaction()),
        (sample_forfeit(&server.url()), wallet_intent()),
    ] {
        assert!(mainnet
            .submit_settlement_handoff(&info, &handoff, &payload)
            .await
            .unwrap_err()
            .to_string()
            .contains("explicit opt-in"));
    }
    for (handoff, payload) in [
        (sample_oor(&server.url()), wallet_intent()),
        (sample_forfeit(&server.url()), wallet_transaction()),
        (
            sample_oor(&server.url()),
            ArkSettlementSubmission::Transaction(ArkSubmitTxRequest {
                signed_ark_tx: String::new(),
                checkpoint_txs: vec!["wallet-checkpoint".to_string()],
            }),
        ),
        (
            sample_forfeit(&server.url()),
            ArkSettlementSubmission::Intent(ArkRegisterIntentRequest {
                intent: ArkIntent {
                    proof: String::new(),
                    message: "wallet-message".to_string(),
                },
            }),
        ),
    ] {
        assert!(client
            .submit_settlement_handoff(&sample_asp_info(), &handoff, &payload)
            .await
            .is_err());
    }
    post.assert_async().await;
}

#[tokio::test]
async fn submission_rejects_malformed_endpoint_responses() {
    for body in [
        serde_json::json!({"arkTxid":"zz".repeat(32), "finalArkTx":"wallet-tx", "signedCheckpointTxs":["wallet-checkpoint"]}),
        serde_json::json!({"arkTxid":"11".repeat(31), "finalArkTx":"wallet-tx", "signedCheckpointTxs":["wallet-checkpoint"]}),
        serde_json::json!({"arkTxid":"11".repeat(32), "finalArkTx":"", "signedCheckpointTxs":["wallet-checkpoint"]}),
        serde_json::json!({"submission_id":"old-api", "status":"cosigned", "vtxo_txid":"11".repeat(32)}),
    ] {
        let mut server = mockito::Server::new_async().await;
        let post = server
            .mock("POST", "/v1/tx/submit")
            .with_status(200)
            .with_body(body.to_string())
            .create_async()
            .await;
        let client = LiveArkAspClient::new_for_test(server.url(), ArkNetwork::Signet);
        assert!(client
            .submit_settlement_handoff(
                &sample_asp_info(),
                &sample_oor(&server.url()),
                &wallet_transaction()
            )
            .await
            .is_err());
        post.assert_async().await;
    }
    let mut server = mockito::Server::new_async().await;
    let post = server
        .mock("POST", "/v1/batch/registerIntent")
        .with_status(200)
        .with_body(r#"{"intentId":" "}"#)
        .create_async()
        .await;
    let client = LiveArkAspClient::new_for_test(server.url(), ArkNetwork::Signet);
    assert!(client
        .submit_settlement_handoff(
            &sample_asp_info(),
            &sample_forfeit(&server.url()),
            &wallet_intent()
        )
        .await
        .is_err());
    post.assert_async().await;
}

#[test]
fn receipt_validation_and_asp_url_normalization() {
    let mut receipt = ArkRoundSubmissionReceipt {
        submission_id: "intent_42".to_string(),
        status: "registered".to_string(),
        vtxo_txid: None,
    };
    assert!(receipt.validate().is_ok());
    receipt.status = "unknown".to_string();
    assert!(receipt.validate().is_err());
    receipt.status = "registered".to_string();
    receipt.submission_id = " ".to_string();
    assert!(receipt.validate().is_err());
    assert_eq!(
        normalized_server_url("https://ASP.example:443/path/").unwrap(),
        normalized_server_url("https://asp.example/path").unwrap()
    );
    assert_ne!(
        normalized_server_url("https://asp.example/path").unwrap(),
        normalized_server_url("https://asp.example/other").unwrap()
    );
    for url in [
        "https://asp.example/?query=1",
        "https://asp.example/#fragment",
        "https://user@asp.example",
        "file:///tmp/asp",
    ] {
        assert!(normalized_server_url(url).is_err());
    }
    let client = LiveArkAspClient::new("http://127.0.0.1", ArkNetwork::Regtest);
    assert!(client
        .validate_endpoint("http://127.0.0.1/v1/info")
        .is_err());
    assert!(client
        .validate_endpoint("https://127.0.0.1/v1/info")
        .is_err());
}
