use anyhow::Result;

use satspath_core::{
    crypto::{fingerprint_pubkey, generate_identity_keypair, generate_nonce, sign_profile},
    privacy::{canonical_identifier, mask_identifier, mask_pubkey},
    validate_ark_server_url,
    validation::{
        validate_bitcoin_address, validate_compressed_pubkey, validate_lightning_address,
    },
    BitcoinNetwork, PaymentMethod, PaymentProfile,
};

use super::{keystore, open_registry, satspath_dir};

pub async fn cmd_register(
    alias: &str,
    lightning_address: Option<&str>,
    onchain_address: Option<&str>,
    ark_server: Option<&str>,
    ark_pubkey: Option<&str>,
) -> Result<()> {
    let mut registry = open_registry()?;
    let alias = canonical_identifier(alias);

    if registry.is_registered(&alias) {
        println!("Alias '{}' is already registered.", mask_identifier(&alias));
        return Ok(());
    }

    // Generate a fresh identity keypair for signing this public profile only.
    // The private key is not stored, printed, or encoded into any QR payload.
    let kp = generate_identity_keypair();
    let pubkey_hex = hex::encode(kp.public_key.serialize());

    let lightning_address = lightning_address.unwrap_or(&alias);
    validate_lightning_address(lightning_address).map_err(|e| anyhow::anyhow!("{}", e))?;

    let mut methods = vec![PaymentMethod::Lightning {
        label: "Lightning Address".into(),
        lightning_address: Some(lightning_address.to_string()),
        lnurl: None,
        bolt12: None,
        receiver_pubkey: None,
    }];

    if let Some(address) = onchain_address {
        validate_bitcoin_address(address, BitcoinNetwork::Mainnet)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        methods.push(PaymentMethod::Onchain {
            label: "Bitcoin mainnet".into(),
            network: BitcoinNetwork::Mainnet,
            address: Some(address.to_string()),
            silent_payment_pubkey: None,
            pubkey_hint: None,
            descriptor_hint: None,
            address_list: vec![],
        });
    }

    match (ark_server, ark_pubkey) {
        (Some(server), Some(pubkey)) => {
            validate_ark_server_url(server).map_err(|e| anyhow::anyhow!("{}", e))?;
            validate_compressed_pubkey(pubkey).map_err(|e| anyhow::anyhow!("{}", e))?;
            methods.push(PaymentMethod::Ark {
                label: "Ark".into(),
                server: server.to_string(),
                pubkey: pubkey.to_string(),
                vtxo_pointer: None,
                proof: None,
                expires_at: None,
                opaque_uri: None,
            });
        }
        (None, None) => {}
        _ => anyhow::bail!("--ark-server and --ark-pubkey must be provided together."),
    }

    let now = chrono::Utc::now().timestamp();
    let profile = PaymentProfile {
        alias: alias.clone(),
        identity_pubkey: pubkey_hex.clone(),
        methods: methods.clone(),
        updated_at: now,
        expires_at: Some(now + 30 * 24 * 3600), // default 30-day expiry per spec §28
        sequence: Some(1),
        preferences: vec!["lightning".into(), "ark".into(), "onchain".into()],
        nonce: Some(generate_nonce()),
        rotation: None,
        method_verifications: Vec::new(),
        hybrid_pubkey: None,
        pqc_required: false,
        revoked: false,
        recovery_policy: None,
        recovery: None,
    };

    let signed = sign_profile(profile, &kp.secret_key)?;
    let fp = fingerprint_pubkey(&pubkey_hex)?;
    registry.register_profile(signed.clone())?;

    // Persist the protocol identity key locally so the owner can attach ownership
    // proofs to (and otherwise update) this profile later. This is NOT a wallet
    // seed or spending key, and it never enters a profile or QR payload.
    let key_path = keystore::save_identity_key(&satspath_dir(), &kp.secret_key)?;

    println!("Registered: {}", mask_identifier(&alias));
    println!("Identity pubkey: {}", mask_pubkey(&pubkey_hex));
    println!("Fingerprint:     {}", fp);
    println!();
    println!("Payment methods registered:");
    for method in methods {
        println!("  - {}", method.method_name());
    }
    println!();
    println!("Profile signed and stored in .satspath/registry.json");
    println!(
        "Identity key saved to {} (gitignored, owner-only).",
        key_path.display()
    );
    println!("This is your protocol identity key — not a wallet seed or spending key.");
    println!();
    println!(
        "⚠  BACKUP WARNING: If you lose this key file, you cannot update or rotate this \
         profile. Back up {} securely.",
        key_path.display()
    );
    println!("   This randomly generated key cannot be re-derived from a seed, and no guardian recovery policy is committed for it.");
    println!("   The CLI cannot yet commit a guardian RecoveryPolicy; CLI guardian recovery is therefore unavailable for this profile. See docs/key_recovery.md.");
    println!();
    println!(
        "Prove ownership of a method:  satspath prove {} --method-index 0",
        alias
    );

    println!("Broadcasting to Nostr relays...");
    match satspath_core::resolvers::nostr::publish_profile(&signed, &kp.secret_key, None).await {
        Ok(count) => {
            println!(
                "✅ Successfully broadcasted profile to {} Nostr relays",
                count
            );
        }
        Err(e) => {
            println!("⚠  Warning: Failed to broadcast to Nostr: {}", e);
            println!("   Your profile is saved locally but may not be reachable by other peers.");
        }
    }

    Ok(())
}
