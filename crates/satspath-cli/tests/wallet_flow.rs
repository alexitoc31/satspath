//! End-to-end `satspath wallet` flow through the real binary:
//! init → add-methods (signs) → show (verifies) → receive (preview JSON), plus a
//! tamper test proving a modified saved method breaks signature verification.

use std::path::Path;
use std::process::Command;
use std::{
    io::{Read, Write},
    net::TcpListener,
};

const PUBKEY: &str = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
const ONCHAIN: &str = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_satspath")
}

fn run(dir: &Path, args: &[&str]) -> (String, String, bool) {
    run_with_fees(dir, args, "mempool:http://127.0.0.1:0")
}

fn run_with_fees(dir: &Path, args: &[&str], fee_source: &str) -> (String, String, bool) {
    let out = Command::new(bin())
        .args(args)
        .current_dir(dir)
        .env("SATSPATH_PASSWORD", "")
        // Keep non-quote commands offline; the receive test supplies local cheap fees.
        .env("SATSPATH_FEE_SOURCES", fee_source)
        .output()
        .expect("failed to run satspath binary");
    (
        String::from_utf8_lossy(&out.stdout).to_string(),
        String::from_utf8_lossy(&out.stderr).to_string(),
        out.status.success(),
    )
}

fn add_all(dir: &Path, alias: &str) {
    assert!(run(dir, &["wallet", "init"]).2, "wallet init failed");
    let (out, err, ok) = run(
        dir,
        &[
            "wallet",
            "add-methods",
            alias,
            "--lightning-address",
            alias,
            "--onchain-address",
            ONCHAIN,
            "--ark-server",
            "https://ark.satspath.dev",
            "--ark-pubkey",
            PUBKEY,
        ],
    );
    assert!(ok, "add-methods failed: {err}{out}");
}

#[test]
fn wallet_init_add_show_receive_end_to_end() {
    let dir = tempfile::tempdir().unwrap();
    let alias = "rodrigodiazgt7@gmail.com";
    add_all(dir.path(), alias);

    // Identity key + wallet file exist; spending material must not.
    assert!(dir.path().join(".satspath/wallet.json").exists());
    let wallet_json = std::fs::read_to_string(dir.path().join(".satspath/wallet.json")).unwrap();
    for forbidden in [
        "xprv",
        "tprv",
        "seed",
        "mnemonic",
        "macaroon",
        "secret_key",
        "privkey",
    ] {
        assert!(
            !wallet_json.contains(forbidden),
            "wallet.json leaked '{forbidden}'"
        );
    }

    // show: all public methods preserved + signature valid.
    let (show, _e, ok) = run(dir.path(), &["wallet", "show"]);
    assert!(ok);
    assert!(show.contains("Profile signature: valid"), "show:\n{show}");
    assert!(show.contains("Lightning"));
    assert!(show.contains("On-chain"));
    assert!(show.contains("Ark"));

    // receive: preview-only JSON with the safety warnings.
    // Supply cheap fees locally so the live-fee router deterministically picks on-chain.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let fee_source = format!("mempool:http://{}/fees", listener.local_addr().unwrap());
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = [0; 1024];
        let bytes_read = stream.read(&mut request).unwrap();
        assert!(bytes_read > 0);
        let body = r#"{"fastestFee":5,"halfHourFee":4,"hourFee":3,"economyFee":2,"minimumFee":1}"#;
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .unwrap();
    });
    let (json, err, ok) = run_with_fees(
        dir.path(),
        &["wallet", "receive", alias, "100000", "--json"],
        &fee_source,
    );
    server.join().unwrap();
    assert!(ok, "receive failed: {err}{json}");
    let v: serde_json::Value = serde_json::from_str(json.trim()).expect("receive must emit JSON");
    assert_eq!(v["mode"], "preview_only");
    assert_eq!(v["alias"], alias);
    assert_eq!(v["status"], "ok", "unexpected preview status: {json}");
    assert_eq!(
        v["qr"],
        format!("bitcoin:{ONCHAIN}?amount=0.00100000"),
        "unexpected handoff: {json}"
    );
    let warnings = v["warnings"].as_array().unwrap();
    assert!(warnings.iter().any(|w| w == "No funds moved by SatsPath"));
    assert!(warnings
        .iter()
        .any(|w| w == "Payment execution happens in external wallet"));
}

#[test]
fn tampering_with_saved_method_breaks_signature() {
    let dir = tempfile::tempdir().unwrap();
    let alias = "rodrigodiazgt7@gmail.com";
    add_all(dir.path(), alias);

    // Tamper a saved method's address in the registry, without re-signing.
    let reg_path = dir.path().join(".satspath/registry.json");
    let mut reg: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(&reg_path).unwrap()).unwrap();
    let profiles = reg["profiles"].as_object_mut().unwrap();
    let entry = profiles.values_mut().next().unwrap();
    for method in entry["profile"]["methods"].as_array_mut().unwrap() {
        if method["type"] == "Onchain" {
            method["address"] = serde_json::json!("bc1qattackercontrolledaddr00000000000000000");
        }
    }
    std::fs::write(&reg_path, serde_json::to_string_pretty(&reg).unwrap()).unwrap();

    let (show, _e, ok) = run(dir.path(), &["wallet", "show"]);
    assert!(ok);
    assert!(
        show.contains("Profile signature: INVALID"),
        "tampered method must fail verification:\n{show}"
    );
    assert!(
        show.contains("tampered or stale"),
        "should show the improved guidance:\n{show}"
    );
}
