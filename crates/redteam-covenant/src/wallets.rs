//! Deterministic test keys. Every run derives the same keys from fixed labels,
//! so findings replay byte for byte.

use kaspa_consensus_core::tx::ScriptPublicKey;
use secp256k1::{Keypair, SECP256K1, SecretKey};

/// Who signs. Parties are the keys the covenant was deployed with (one per
/// pubkey constructor argument); the attacker is a key the covenant has never
/// seen.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyRef {
    Party(usize),
    Attacker,
}

#[derive(Clone)]
pub struct Wallet {
    pub label: String,
    pub keypair: Keypair,
}

impl Wallet {
    pub fn derive(label: &str) -> Self {
        use sha2::{Digest, Sha256};
        let mut counter = 0u32;
        loop {
            let mut h = Sha256::new();
            h.update(b"kaspa-redteam/wallet/");
            h.update(label.as_bytes());
            h.update(counter.to_le_bytes());
            if let Ok(sk) = SecretKey::from_slice(&h.finalize()) {
                return Self {
                    label: label.to_string(),
                    keypair: Keypair::from_secret_key(SECP256K1, &sk),
                };
            }
            counter += 1;
        }
    }

    /// 32-byte x-only key, what SilverScript calls `pubkey`.
    pub fn xonly(&self) -> [u8; 32] {
        self.keypair.x_only_public_key().0.serialize()
    }

    /// Standard pay-to-pubkey script: OP_DATA_32 <key> OP_CHECKSIG.
    pub fn p2pk(&self) -> ScriptPublicKey {
        let mut s = Vec::with_capacity(34);
        s.push(0x20);
        s.extend_from_slice(&self.xonly());
        s.push(0xac);
        ScriptPublicKey::new(0, s.into())
    }
}

#[derive(Clone)]
pub struct Wallets {
    pub parties: Vec<Wallet>,
    pub attacker: Wallet,
}

impl Wallets {
    pub fn new() -> Self {
        Self {
            parties: Vec::new(),
            attacker: Wallet::derive("attacker"),
        }
    }

    /// Returns the index of the party with this label, creating it if needed.
    pub fn party(&mut self, label: &str) -> usize {
        if let Some(i) = self.parties.iter().position(|w| w.label == label) {
            return i;
        }
        self.parties.push(Wallet::derive(label));
        self.parties.len() - 1
    }

    pub fn get(&self, k: KeyRef) -> &Wallet {
        match k {
            KeyRef::Party(i) => &self.parties[i],
            KeyRef::Attacker => &self.attacker,
        }
    }

    pub fn label(&self, k: KeyRef) -> String {
        match k {
            KeyRef::Party(i) => self.parties[i].label.clone(),
            KeyRef::Attacker => "attacker".into(),
        }
    }

    /// Recognizes a script as one of our P2PK wallets.
    pub fn owner_of(&self, spk: &ScriptPublicKey) -> Option<KeyRef> {
        if spk == &self.attacker.p2pk() {
            return Some(KeyRef::Attacker);
        }
        self.parties
            .iter()
            .position(|w| &w.p2pk() == spk)
            .map(KeyRef::Party)
    }
}

impl Default for Wallets {
    fn default() -> Self {
        Self::new()
    }
}
