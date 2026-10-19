#![no_main]

use libfuzzer_sys::fuzz_target;
use satspath_core::{profile::PaymentMethod, BitcoinNetwork};
use satspath_router::handoff::validate_payload;

fuzz_target!(|data: &[u8]| {
    if let Ok(method) = serde_json::from_slice::<PaymentMethod>(data) {
        let _ = method.ownership_descriptor();
        // No arbitrary method should panic while validating a bounded public
        // payload; validation errors must remain errors, not wallet calls.
        let _ = validate_payload(
            &method,
            "bitcoin:invalid?amount=0.00000001",
            "testnet",
            Some(1),
        );
        let _ = validate_payload(&method, "lntb1invalid", "regtest", Some(u64::MAX));
        if let PaymentMethod::Onchain {
            network,
            address: Some(address),
            ..
        } = &method
        {
            let network = match network {
                BitcoinNetwork::Mainnet => "mainnet",
                BitcoinNetwork::Testnet => "testnet",
                BitcoinNetwork::Signet => "signet",
                BitcoinNetwork::Regtest => "regtest",
            };
            let valid = format!("bitcoin:{address}?amount=0.00000001");
            if validate_payload(&method, &valid, network, Some(1)).is_ok() {
                let wrong_amount = format!("bitcoin:{address}?amount=0.00000002");
                assert!(validate_payload(&method, &wrong_amount, network, Some(1)).is_err());
            }
        }
    }
    // A method-compatible payload must be amount-bound, not just parseable.
    let method = PaymentMethod::Onchain {
        label: "onchain".into(),
        network: BitcoinNetwork::Mainnet,
        address: Some("1BoatSLRHtKNngkdXEeobR76b53LETtpyT".into()),
        silent_payment_pubkey: None,
        pubkey_hint: None,
        descriptor_hint: None,
        address_list: vec![],
    };
    assert!(validate_payload(
        &method,
        "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00000002",
        "mainnet",
        Some(1),
    )
    .is_err());
    assert!(validate_payload(
        &method,
        "bitcoin:1BoatSLRHtKNngkdXEeobR76b53LETtpyT?amount=0.00000001",
        "mainnet",
        Some(1),
    )
    .is_ok());
});
