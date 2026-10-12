use async_trait::async_trait;
use hickory_resolver::config::{ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioAsyncResolver;
use secp256k1::{rand, Keypair, Secp256k1};

use crate::profile::{PaymentMethod, PaymentProfile};
use crate::resolver::ProfileResolver;
use crate::{Result, SatsPathError, SignedPaymentProfile};

pub struct Bip353Resolver {
    dnssec_required: bool,
    resolver: TokioAsyncResolver,
}

impl Default for Bip353Resolver {
    fn default() -> Self {
        Self::new()
    }
}

impl Bip353Resolver {
    pub fn new() -> Self {
        let mut opts = ResolverOpts::default();
        opts.validate = true; // Enforce DNSSEC
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::cloudflare(), opts);
        Self {
            dnssec_required: true,
            resolver,
        }
    }

    pub fn dnssec_required(&self) -> bool {
        self.dnssec_required
    }
}

#[async_trait]
impl ProfileResolver for Bip353Resolver {
    async fn resolve_alias(&self, alias: &str) -> Result<SignedPaymentProfile> {
        if !alias.starts_with('₿') {
            return Err(SatsPathError::AliasNotFound(alias.to_string()));
        }

        let clean_alias = alias.trim_start_matches('₿');
        let parts: Vec<&str> = clean_alias.split('@').collect();
        if parts.len() != 2 {
            return Err(SatsPathError::AliasNotFound(alias.to_string()));
        }

        let username = parts[0];
        let domain = parts[1];
        let lookup_domain = format!("{username}.user._bitcoin-payment.{domain}");

        let lookup = self
            .resolver
            .lookup(lookup_domain, RecordType::TXT)
            .await
            .map_err(|e| SatsPathError::NetworkError(format!("BIP-353 DNS lookup failed: {e}")))?;

        // Find the first valid bitcoin: URI
        let mut payment_uri = None;
        for rdata in lookup.iter() {
            if let Some(txt) = rdata.as_txt() {
                for txt_data in txt.iter() {
                    let txt_str = String::from_utf8_lossy(txt_data);
                    if txt_str.starts_with("bitcoin:") {
                        payment_uri = Some(txt_str.to_string());
                        break;
                    }
                }
            }
            if payment_uri.is_some() {
                break;
            }
        }

        let uri = payment_uri.ok_or_else(|| {
            SatsPathError::AliasNotFound("No valid BIP-353 bitcoin URI found in TXT records".into())
        })?;

        // Parse standard BIP-353 URI into methods
        let mut methods = Vec::new();

        // Extract base address (Onchain)
        let mut uri_parts = uri.split('?');
        let base = uri_parts
            .next()
            .unwrap_or("")
            .trim_start_matches("bitcoin:");
        if !base.is_empty() && base != "bc1q" {
            methods.push(PaymentMethod::Onchain {
                label: "BIP-353 Onchain".into(),
                network: crate::pointer::BitcoinNetwork::Mainnet,
                address: Some(base.to_string()),
                silent_payment_pubkey: None,
                pubkey_hint: None,
                descriptor_hint: None,
                address_list: vec![],
            });
        }

        // Extract query parameters (Lightning)
        if let Some(query) = uri_parts.next() {
            let mut lno = None;
            let mut b12 = None;

            for param in query.split('&') {
                if let Some((k, v)) = param.split_once('=') {
                    match k {
                        "lno" => lno = Some(v.to_string()),
                        "b12" => b12 = Some(v.to_string()),
                        _ => {}
                    }
                }
            }

            let bolt12_offer = b12
                .filter(|s| !s.is_empty())
                .or_else(|| lno.filter(|s| !s.is_empty()));
            if let Some(offer) = bolt12_offer {
                methods.push(PaymentMethod::Lightning {
                    label: "BIP-353 Lightning".into(),
                    lightning_address: None,
                    lnurl: None, // technically lno could be an lnurl or LN address, but keeping simple
                    bolt12: Some(offer),
                    receiver_pubkey: None,
                });
            }
        }

        if methods.is_empty() {
            return Err(SatsPathError::AliasNotFound(
                "BIP-353 URI contained no valid methods".into(),
            ));
        }

        let secp = Secp256k1::new();
        let kp = Keypair::new(&secp, &mut rand::thread_rng());

        let profile = PaymentProfile {
            alias: alias.to_string(),
            identity_pubkey: kp.public_key().to_string(),
            methods,
            updated_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64,
            expires_at: None,
            sequence: Some(1),
            preferences: vec![],
            nonce: None,
            rotation: None,
            method_verifications: vec![],
            hybrid_pubkey: None,
            pqc_required: false,
            revoked: false,
            recovery_policy: None,
            recovery: None,
        };

        let signed = crate::crypto::sign_profile(profile, &kp.secret_key()).map_err(|e| {
            SatsPathError::SerializationError(format!("failed to sign synthetic profile: {e}"))
        })?;

        Ok(signed)
    }
}
