// Test-only host wallet. No private-key implementation is linked into the router.
pub struct TestSigner(pub secp256k1::SecretKey);
impl std::ops::Deref for TestSigner {
    type Target = secp256k1::SecretKey;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl satspath_core::bolt12::Bolt12Signer for TestSigner {
    fn public_key(&self) -> secp256k1::PublicKey {
        secp256k1::PublicKey::from_secret_key(&secp256k1::Secp256k1::new(), &self.0)
    }
    fn sign_bolt12(
        &self,
        name: &str,
        records: &[satspath_core::bolt12::TlvRecord],
    ) -> anyhow::Result<[u8; 64]> {
        use satspath_core::bolt12::{bolt12_signature_digest, compute_bolt12_merkle_root};
        let digest = bolt12_signature_digest(name, &compute_bolt12_merkle_root(records)?);
        let secp = secp256k1::Secp256k1::new();
        let keypair = secp256k1::Keypair::from_secret_key(&secp, &self.0);
        Ok(*secp
            .sign_schnorr(&secp256k1::Message::from_digest(digest), &keypair)
            .as_ref())
    }
}
