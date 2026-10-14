#![no_main]

use libfuzzer_sys::fuzz_target;
use satspath_core::ownership::{
    pubkey_controls_address, validate_method_verification, validate_ownership_proof,
    verify_method_verification, MethodVerification, OwnershipProof,
};
use satspath_core::pointer::BitcoinNetwork;
use satspath_core::profile::PaymentMethod;

fuzz_target!(|data: &[u8]| {
    if let Ok(verification) = serde_json::from_slice::<MethodVerification>(data) {
        let _ = validate_method_verification(&verification);
    }

    if let Ok(proof) = serde_json::from_slice::<OwnershipProof>(data) {
        let _ = validate_ownership_proof(&proof);
    }

    if let Ok((method, verification, identity_pk, body)) =
        serde_json::from_slice::<(PaymentMethod, MethodVerification, String, Option<String>)>(data)
    {
        let _ = verify_method_verification(
            &method,
            &identity_pk,
            &verification,
            1_700_000_000,
            body.as_deref(),
        );
    }

    if let Ok((pk_hex, addr, net_byte)) = serde_json::from_slice::<(String, String, u8)>(data) {
        let net = match net_byte % 3 {
            0 => BitcoinNetwork::Mainnet,
            1 => BitcoinNetwork::Testnet,
            _ => BitcoinNetwork::Regtest,
        };
        let _ = pubkey_controls_address(&pk_hex, &addr, net);
    }
});
