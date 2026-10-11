mod commands;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "satspath",
    about = "SatsPath — universal Bitcoin payment resolver and router",
    version = "0.1.0"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize SatsPath local state (.satspath/ directory)
    Init,

    /// Register an alias with a signed public payment profile
    Register {
        alias: String,
        /// Wire a real Lightning Address.
        #[arg(long, alias = "ln-address")]
        lightning_address: Option<String>,
        /// Wire a real mainnet Bitcoin address.
        #[arg(long, alias = "onchain")]
        onchain_address: Option<String>,
        /// Wire an Ark server URL.
        #[arg(long)]
        ark_server: Option<String>,
        /// Wire an Ark receiver compressed secp256k1 pubkey.
        #[arg(long)]
        ark_pubkey: Option<String>,
    },

    /// Show a registered profile
    Show {
        alias: String,
        /// Fetch and re-verify domain-control proofs over the network
        #[arg(long)]
        verify_online: bool,
    },

    /// Print the ownership-proof challenge to sign for one method
    Prove {
        alias: String,
        /// Index of the method in the profile (see `satspath show`)
        #[arg(long, default_value_t = 0)]
        method_index: usize,
    },

    /// Attach an ownership proof to a method and re-sign the profile
    AttachProof {
        alias: String,
        #[arg(long, default_value_t = 0)]
        method_index: usize,
        /// Proof type: onchain | ark | domain | manual
        #[arg(long = "type")]
        proof_type: String,
        /// issued_at value printed by `satspath prove` (required for onchain/ark)
        #[arg(long)]
        issued_at: Option<i64>,
        /// Compressed secp256k1 pubkey that signed the challenge (onchain/ark)
        #[arg(long)]
        pubkey: Option<String>,
        /// DER signature (hex) over the challenge (onchain/ark)
        #[arg(long)]
        signature: Option<String>,
        /// Well-known URL to fetch+verify (domain; auto-derived for Lightning)
        #[arg(long)]
        url: Option<String>,
        /// Token the served body must contain (domain; defaults to identity pubkey)
        #[arg(long)]
        nonce: Option<String>,
        /// Verify a local copy of the served content instead of fetching (domain)
        #[arg(long)]
        body_file: Option<String>,
        /// Optional validity window in seconds from issued_at
        #[arg(long)]
        expires_in: Option<i64>,
    },

    /// Encode a universal SatsPath payment URI
    Encode {
        alias: String,
        amount_sats: u64,
        #[arg(long)]
        memo: Option<String>,
    },

    /// Decode a SatsPath payment URI
    Decode { uri: String },

    /// Show routing decision with live mempool fees + scannable QR
    Quote {
        alias: String,
        amount_sats: u64,
        /// Emit the machine-readable QuoteResponse as JSON (and nothing else)
        #[arg(long)]
        json: bool,
        /// Use mainnet public-data preview rules. No execution.
        #[arg(long)]
        mainnet_preview: bool,
        /// Fetch a real LNURL BOLT11 invoice. Requires explicit opt-in.
        #[arg(long)]
        fetch_lnurl_invoice: bool,
    },

    /// Build a mainnet-compatible public payment preview. No funds move.
    Preview {
        recipient: String,
        amount_sats: u64,
        /// Use real mainnet public data, never execution.
        #[arg(long)]
        mainnet: bool,
        /// Print only valid JSON.
        #[arg(long)]
        json: bool,
        /// Fetch a real LNURL BOLT11 invoice. Requires explicit opt-in.
        #[arg(long)]
        fetch_lnurl_invoice: bool,
    },

    /// Resolve, route, and build a public QR preview. No funds move by default.
    Pay {
        alias: String,
        amount_sats: u64,
        #[arg(long)]
        memo: Option<String>,
        #[arg(long)]
        mainnet_preview: bool,
        /// Activate experimental swap engine. Requires --testnet.
        #[arg(long)]
        experimental_swaps: bool,
        /// Target testnet instead of mainnet.
        #[arg(long)]
        testnet: bool,
        /// Print full public pointer and QR payload values.
        #[arg(long)]
        debug: bool,
    },

    /// Generate an invite for an unregistered alias (no funds sent, no keys generated)
    Invite { alias: String, amount_sats: u64 },

    /// Claim an invite using a claim URL or an alias (generates local keys)
    Claim {
        claim_url_or_alias: String,
        #[arg(long)]
        lightning_address: Option<String>,
        #[arg(long)]
        onchain_address: Option<String>,
    },

    /// Export a signed profile as JSON (for manual migration or local sharing)
    Export { alias: String },

    /// Import a signed profile (verifying it) from a file, stdin, or an HTTPS URL
    Import {
        /// Path to a JSON file (omit to read from stdin)
        file: Option<String>,
        /// Fetch from an HTTPS URL instead of a file
        #[arg(long)]
        url: Option<String>,
    },

    /// Ark direct receive/send and swap intents. Testnet-gated; mainnet execution disabled.
    Ark {
        #[command(subcommand)]
        command: ArkCommand,
    },

    /// BIP-353 DNS payment-instruction resolution (mainnet preview only).
    Dns {
        #[command(subcommand)]
        command: DnsCommand,
    },

    /// Server-to-Server offline identity mutation commands
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },

    /// Server migration and identifier portability
    Migration {
        #[command(subcommand)]
        command: MigrationCommand,
    },

    /// Sovereign server and DNS operator onboarding
    Server {
        #[command(subcommand)]
        command: ServerCommand,
    },

    /// Alias management and sovereign key recovery commands
    Alias {
        #[command(subcommand)]
        command: AliasCommand,
    },

    /// Safe receiver-profile wallet: manage public receive methods, sign a
    /// profile, preview. Never moves funds or stores spending keys.
    Wallet {
        #[command(subcommand)]
        command: WalletCommand,
    },

    /// Launch the minimal, private "Receive" web UI on localhost
    Web {
        /// Port to serve on (127.0.0.1 only)
        #[arg(long, default_value_t = 4848)]
        port: u16,
    },

    /// Run the full SatsPath demo flow
    Demo,
}

#[derive(Subcommand)]
enum ServerCommand {
    /// Initialize a namespace, operator identity, and witness policy. Prints DNS records.
    Init {
        /// The domain namespace (e.g. yourdomain.com)
        domain: String,
    },
    /// Validate DNSSEC chain, operator key, and witness quorum for a domain.
    Check {
        /// The domain namespace (e.g. yourdomain.com)
        domain: String,
    },
}

#[derive(Subcommand)]
enum WalletCommand {
    /// Create or load the SatsPath identity key
    Init,
    /// Rotate the identity key and issue a KeyRotation proof
    Rotate,
    /// Recover lost identity key using a pre-committed guardian threshold proof (KeyRecoveryProof)
    Recover(WalletRecoverArgs),
    /// Set the alias + public receive methods, then sign and save the profile
    AddMethods(WalletAddMethodsArgs),
    /// Add/replace the Lightning Address (re-signs the profile)
    AddLightning { lightning_address: String },
    /// Add/replace a BOLT12 offer (re-signs the profile)
    AddBolt12 { offer: String },
    /// Add/replace the on-chain receive address (re-signs the profile)
    AddOnchain { bitcoin_address: String },
    /// Add/replace the Ark receive pointer (re-signs the profile)
    AddArk {
        #[arg(long)]
        server: String,
        #[arg(long)]
        pubkey: String,
    },
    /// Show the wallet's identity, public receive methods, and signature status
    Show {
        /// Print full (unmasked) values
        #[arg(long)]
        debug: bool,
    },
    /// Export the signed profile for manual migration or backup
    Publish { alias: Option<String> },
    /// Preview a receive for an amount (no funds moved)
    Receive {
        alias: String,
        amount_sats: u64,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Args)]
struct WalletAddMethodsArgs {
    alias: String,
    #[arg(long)]
    lightning_address: Option<String>,
    #[arg(long)]
    onchain_address: Option<String>,
    #[arg(long)]
    ark_server: Option<String>,
    #[arg(long)]
    ark_pubkey: Option<String>,
}

#[derive(Subcommand)]
enum AliasCommand {
    /// Recover an alias identity key using a pre-committed guardian threshold proof (KeyRecoveryProof)
    Recover(AliasRecoverArgs),
}

#[derive(Args)]
struct AliasRecoverArgs {
    /// Alias to recover (e.g. alice@example.com)
    #[arg(long)]
    alias: Option<String>,
    /// Path to JSON file containing KeyRecoveryProof
    #[arg(long = "proof-file", required = true)]
    proof_file: String,
}

#[derive(Args)]
struct WalletRecoverArgs {
    /// Alias to recover (e.g. alice@example.com)
    #[arg(long)]
    alias: Option<String>,
    /// Path to JSON file containing KeyRecoveryProof
    #[arg(long = "proof-file", required = true)]
    proof_file: String,
}

#[derive(Subcommand)]
enum DnsCommand {
    /// Resolve ₿user@domain (or user@domain) via DNSSEC-backed BIP-353.
    Resolve(DnsResolveArgs),
    /// Check and parse DNSSEC records for a namespace
    Check {
        /// The domain (e.g., example.com) to check the _satspath record for.
        domain: String,
    },
}

#[derive(Args)]
struct DnsResolveArgs {
    /// The name to resolve, e.g. ₿rodrigo@satspath.dev or rodrigo@satspath.dev
    name: String,
    /// Emit the machine-readable resolution as JSON (and nothing else)
    #[arg(long)]
    json: bool,
    /// DEV ONLY: skip DNSSEC validation (never use on mainnet)
    #[arg(long)]
    allow_insecure_dns_for_dev: bool,
}

#[derive(Subcommand)]
enum IdentityCommand {
    /// Fetch a challenge nonce for an offline mutation
    RequestChallenge { identifier: String },
    /// Locally sign a mutation and output the JSON envelope for inspection
    SignMutation {
        identifier: String,
        challenge_nonce: String,
        /// Optional offline signing key path (simulates hardware wallet)
        #[arg(long)]
        key_path: Option<String>,
    },
    /// Submit a signed mutation payload to the server
    SubmitMutation {
        /// JSON payload path (created by sign-mutation)
        #[arg(long)]
        payload_file: String,
    },
}

#[derive(Subcommand)]
enum MigrationCommand {
    /// Export the server state to a portable JSON file
    Export {
        /// Output file path
        #[arg(long, default_value = "satspath_migration_export.json")]
        out_file: String,
    },
    /// Verify a migration export and cross-log commitments
    Verify {
        /// Path to the migration export JSON file
        #[arg(long)]
        file: String,
    },
}

#[derive(Subcommand)]
enum ArkCommand {
    /// Preview an Ark receive pointer for a registered alias.
    Receive(ArkReceiveArgs),
    /// Preview or testnet-execute a direct Ark send intent.
    Send(ArkSendArgs),
    /// Preview or testnet-execute an Ark swap intent.
    Swap(ArkSwapArgs),
}

#[derive(Args)]
struct ArkReceiveArgs {
    #[arg(long)]
    alias: String,
    #[arg(long)]
    testnet: bool,
    #[arg(long)]
    execute_testnet: bool,
}

#[derive(Args)]
struct ArkSendArgs {
    alias: String,
    amount_sats: u64,
    #[arg(long)]
    testnet: bool,
    #[arg(long)]
    execute_testnet: bool,
    #[arg(long)]
    confirm: Option<String>,
}

#[derive(Args)]
struct ArkSwapArgs {
    alias: String,
    amount_sats: u64,
    #[arg(long)]
    from: commands::ArkSwapSide,
    #[arg(long)]
    to: commands::ArkSwapSide,
    #[arg(long)]
    testnet: bool,
    #[arg(long)]
    execute_testnet: bool,
    #[arg(long)]
    confirm: Option<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init => commands::cmd_init()?,
        Command::Register {
            alias,
            lightning_address,
            onchain_address,
            ark_server,
            ark_pubkey,
        } => {
            commands::cmd_register(
                &alias,
                lightning_address.as_deref(),
                onchain_address.as_deref(),
                ark_server.as_deref(),
                ark_pubkey.as_deref(),
            )
            .await?
        }
        Command::Show {
            alias,
            verify_online,
        } => commands::cmd_show(&alias, verify_online).await?,
        Command::Prove {
            alias,
            method_index,
        } => commands::cmd_prove(&alias, method_index)?,
        Command::AttachProof {
            alias,
            method_index,
            proof_type,
            issued_at,
            pubkey,
            signature,
            url,
            nonce,
            body_file,
            expires_in,
        } => {
            commands::cmd_attach_proof(
                &alias,
                method_index,
                &proof_type,
                issued_at,
                pubkey.as_deref(),
                signature.as_deref(),
                url.as_deref(),
                nonce.as_deref(),
                body_file.as_deref(),
                expires_in,
            )
            .await?
        }
        Command::Encode {
            alias,
            amount_sats,
            memo,
        } => commands::cmd_encode(&alias, amount_sats, memo.as_deref())?,
        Command::Decode { uri } => commands::cmd_decode(&uri)?,
        Command::Quote {
            alias,
            amount_sats,
            json,
            mainnet_preview,
            fetch_lnurl_invoice,
        } => {
            if mainnet_preview {
                commands::cmd_preview(&alias, amount_sats, true, json, fetch_lnurl_invoice).await?
            } else if json {
                commands::cmd_quote_json(&alias, amount_sats).await?
            } else {
                commands::cmd_quote(&alias, amount_sats).await?
            }
        }
        Command::Preview {
            recipient,
            amount_sats,
            mainnet,
            json,
            fetch_lnurl_invoice,
        } => {
            commands::cmd_preview(&recipient, amount_sats, mainnet, json, fetch_lnurl_invoice)
                .await?
        }
        Command::Pay {
            alias,
            amount_sats,
            memo,
            mainnet_preview,
            experimental_swaps,
            testnet,
            debug,
        } => {
            commands::cmd_pay(
                &alias,
                amount_sats,
                memo.as_deref(),
                mainnet_preview,
                experimental_swaps,
                testnet,
                debug,
            )
            .await?
        }
        Command::Invite { alias, amount_sats } => commands::cmd_invite(&alias, amount_sats).await?,
        Command::Claim {
            claim_url_or_alias,
            lightning_address,
            onchain_address,
        } => {
            commands::cmd_claim(
                &claim_url_or_alias,
                lightning_address.as_deref(),
                onchain_address.as_deref(),
            )
            .await?
        }
        Command::Export { alias } => commands::cmd_export(&alias)?,
        Command::Import { file, url } => {
            commands::cmd_import(file.as_deref(), url.as_deref()).await?
        }
        Command::Ark { command } => match command {
            ArkCommand::Receive(args) => {
                commands::cmd_ark_receive(&args.alias, args.testnet, args.execute_testnet).await?
            }
            ArkCommand::Send(args) => {
                commands::cmd_ark_send(
                    &args.alias,
                    args.amount_sats,
                    args.testnet,
                    args.execute_testnet,
                    args.confirm.as_deref(),
                )
                .await?
            }
            ArkCommand::Swap(args) => {
                commands::cmd_ark_swap(
                    &args.alias,
                    args.amount_sats,
                    args.from,
                    args.to,
                    args.testnet,
                    args.execute_testnet,
                    args.confirm.as_deref(),
                )
                .await?
            }
        },
        Command::Dns { command } => match command {
            DnsCommand::Resolve(args) => {
                commands::cmd_dns_resolve(&args.name, args.json, args.allow_insecure_dns_for_dev)
                    .await?
            }
            DnsCommand::Check { domain } => {
                println!("Validating DNSSEC delegation for domain: {}", domain);
                println!("Feature coming soon!");
            }
        },
        Command::Identity { command } => match command {
            IdentityCommand::RequestChallenge { identifier } => {
                println!("Requesting mutation challenge for {}...", identifier);
                println!("Feature coming soon!");
            }
            IdentityCommand::SignMutation {
                identifier,
                challenge_nonce,
                key_path,
            } => {
                println!(
                    "Signing mutation for {} with nonce {}...",
                    identifier, challenge_nonce
                );
                if let Some(path) = key_path {
                    println!("Using offline key path: {}", path);
                }
                println!("Feature coming soon!");
            }
            IdentityCommand::SubmitMutation { payload_file } => {
                println!(
                    "Submitting signed mutation payload from {}...",
                    payload_file
                );
                println!("Feature coming soon!");
            }
        },
        Command::Migration { command } => match command {
            MigrationCommand::Export { out_file } => {
                println!("Exporting server state to {}...", out_file);
                println!("Feature coming soon!");
            }
            MigrationCommand::Verify { file } => {
                println!("Verifying migration export from {}...", file);
                println!("Feature coming soon!");
            }
        },
        Command::Server { command } => match command {
            ServerCommand::Init { domain } => commands::cmd_server_init(&domain)?,
            ServerCommand::Check { domain } => commands::cmd_server_check(&domain).await?,
        },
        Command::Alias { command } => match command {
            AliasCommand::Recover(args) => {
                commands::cmd_alias_recover(args.alias.as_deref(), &args.proof_file)?
            }
        },
        Command::Wallet { command } => match command {
            WalletCommand::Init => commands::cmd_wallet_init()?,
            WalletCommand::Rotate => commands::cmd_wallet_rotate()?,
            WalletCommand::AddMethods(args) => commands::cmd_wallet_add_methods(
                &args.alias,
                args.lightning_address.as_deref(),
                args.onchain_address.as_deref(),
                args.ark_server.as_deref(),
                args.ark_pubkey.as_deref(),
            )?,
            WalletCommand::AddLightning { lightning_address } => {
                commands::cmd_wallet_add_lightning(&lightning_address)?
            }
            WalletCommand::AddBolt12 { offer } => commands::cmd_wallet_add_bolt12(&offer)?,
            WalletCommand::AddOnchain { bitcoin_address } => {
                commands::cmd_wallet_add_onchain(&bitcoin_address)?
            }
            WalletCommand::AddArk { server, pubkey } => {
                commands::cmd_wallet_add_ark(&server, &pubkey)?
            }
            WalletCommand::Show { debug } => commands::cmd_wallet_show(debug)?,
            WalletCommand::Publish { alias } => commands::cmd_wallet_publish(alias.as_deref())?,
            WalletCommand::Recover(args) => {
                commands::cmd_alias_recover(args.alias.as_deref(), &args.proof_file)?
            }
            WalletCommand::Receive {
                alias,
                amount_sats,
                json,
            } => commands::cmd_wallet_receive(&alias, amount_sats, json).await?,
        },
        Command::Web { port } => commands::cmd_web(port)?,
        Command::Demo => commands::cmd_demo().await?,
    }

    Ok(())
}
