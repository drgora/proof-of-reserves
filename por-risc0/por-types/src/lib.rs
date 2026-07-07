//! Wire types + canonical challenge serialization for the PoR challenge/response
//! protocol. Imported by BOTH the prover and the verifier service so the owner-signature
//! contract (`canonical_bytes` / `challenge_digest`) can never drift between the two sides.
//!
//! Protocol shape:
//!   1. relying party -> verifier: `{agent_id, threshold}`
//!   2. verifier -> prover: a [`Challenge`] (random nonce + 3 recent block numbers)
//!   3. prover -> verifier: a [`Response`] (3 self-contained proof bundles + owner sig)
//!
//! The owner signature proves the responder controls the agent's registry `owner` EOA.
//! It signs [`Challenge::challenge_digest`], which binds nonce + agent + threshold + the
//! exact block set, so a signature cannot be replayed across challenges or agents.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tiny_keccak::{Hasher, Keccak};

pub mod chains;
pub use chains::{
    chain_spec, expected_host, is_supported, resolve_chain, selectable_ids, ChainSpec, CHAINS,
};

/// Domain-separation tag prepended to the signed challenge bytes.
pub const CHALLENGE_DOMAIN: &[u8] = b"POR-CHALLENGE-v1\n";
/// `version` string stamped into a [`Response`].
pub const RESPONSE_VERSION: &str = "por-response-v1";
/// Number of blocks challenged per session.
pub const BLOCK_COUNT: usize = 3;

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    let mut o = [0u8; 32];
    k.update(data);
    k.finalize(&mut o);
    o
}

// --- per-agent marketplace identity (single source of truth) ----------------
// The guest commits two marketplace binding fields: the numeric ERC-721 `agent_token_id`
// and `identity = keccak256(agent_secret)`. Both the CLI prover (which signs with the owner
// key) and the browser flow (which signs in the wallet) derive `agent_secret` the SAME way
// here, so the on-chain commitment (`keccak256(agent_secret)`, registered set-once) matches
// whichever path proves. Kept in por-types so prover, verifier, and the offset helper agree.

/// Parse a registry agent id (`"5868"` or `"0x16ec"`) into its numeric ERC-721 token id.
/// Returns 0 when the id isn't numeric (demo / non-marketplace agents) -- an inert binding.
pub fn parse_token_id(agent_id: &str) -> u64 {
    let s = agent_id.trim();
    match s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Some(h) => u64::from_str_radix(h, 16).unwrap_or(0),
        None => s.parse::<u64>().unwrap_or(0),
    }
}

/// The message an agent OWNER signs (EIP-191 `personal_sign`) to derive its private identity
/// secret. Deterministic ECDSA (RFC 6979, low-S -- what MetaMask/Rabby/k256 all produce) means
/// the same owner key always yields the same signature, hence the same secret and the same
/// commitment. FROZEN: the commitment is registered set-once, so changing this string would
/// lock out every agent already registered under it (see the freeze test below).
pub fn identity_message(token_id: u64) -> String {
    format!(
        "Horizen Proof-of-Reserves\n\
         Agent identity binding v1\n\
         agent: {token_id}\n\
         Signing derives this agent's private proving secret. Only sign on the official prover."
    )
}

/// EIP-191 `personal_sign` digest over an arbitrary-length message -- exactly what a browser
/// wallet hashes-then-signs, so the CLI (which signs this digest with k256) matches the wallet.
pub fn eip191_digest(message: &[u8]) -> [u8; 32] {
    let mut m = Vec::with_capacity(28 + message.len());
    m.extend_from_slice(b"\x19Ethereum Signed Message:\n");
    m.extend_from_slice(message.len().to_string().as_bytes());
    m.extend_from_slice(message);
    keccak256(&m)
}

/// Derive the 32-byte agent secret from an EIP-191 signature over [`identity_message`]. Uses
/// only r‖s (the first 64 bytes), so a wallet's v=27/28 vs a recid of 0/1 -- which never change
/// r or s -- yields the same secret regardless of the signature's recovery-byte convention.
pub fn secret_from_identity_sig(sig: &[u8]) -> [u8; 32] {
    let n = sig.len().min(64);
    keccak256(&sig[..n])
}

/// A verifier-issued challenge. `nonce`/`agent_id`/`threshold`/`chain_id`/`blocks` are the
/// security-relevant fields covered by the owner signature; the rest is routing/metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Challenge {
    pub challenge_id: String,
    /// registry agent id (opaque string; hashed into journals + the signed payload)
    pub agent_id: String,
    /// minimum reserves, wei, as a decimal (or `0x`-hex) string -- u128 exceeds JS safe-int
    pub threshold: String,
    pub chain_id: u32,
    /// `0x`-hex, 32 bytes
    pub nonce: String,
    /// finalized head pinned at issue time (defines the selection window)
    pub head_block: u64,
    /// the challenged block numbers, ascending
    pub blocks: [u64; BLOCK_COUNT],
    pub issued_at: u64,
    pub expires_at: u64,
}

/// A prover's response: the three proof bundles + the owner signature over the challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    pub version: String,
    /// the challenge being answered (echoed for audit; the verifier trusts its own session)
    pub challenge: Challenge,
    /// `0x`-hex, 65 bytes (r||s||v), EIP-191 over [`Challenge::challenge_digest`]
    pub owner_sig: String,
    /// three `proof.json`-shaped bundles (`{proofType, proofOptions, proofData, tlsnPresentation?}`)
    pub bundles: Vec<Value>,
}

impl Challenge {
    /// 32-byte nonce, parsed from the `0x`-hex `nonce` field.
    pub fn nonce_bytes(&self) -> Result<[u8; 32], String> {
        let v = hex::decode(self.nonce.trim_start_matches("0x")).map_err(|e| e.to_string())?;
        if v.len() != 32 {
            return Err(format!("nonce must be 32 bytes, got {}", v.len()));
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&v);
        Ok(a)
    }

    /// Threshold as u128, from the decimal (or `0x`-hex) `threshold` string.
    pub fn threshold_u128(&self) -> Result<u128, String> {
        let s = self.threshold.trim();
        match s.strip_prefix("0x") {
            Some(h) => u128::from_str_radix(h, 16).map_err(|e| e.to_string()),
            None => s.parse::<u128>().map_err(|e| e.to_string()),
        }
    }

    /// `keccak256(agent_id)` -- the exact 32-byte value the guest commits to the journal
    /// (format-agnostic across registry id shapes; not a raw address).
    pub fn agent_id_hash(&self) -> [u8; 32] {
        keccak256(self.agent_id.as_bytes())
    }

    /// Numeric ERC-721 marketplace token id this challenge's `agent_id` denotes (the value the
    /// guest commits as `agent_token_id` and the gateway keys the identity commitment by).
    pub fn agent_token_id(&self) -> u64 {
        parse_token_id(&self.agent_id)
    }

    /// Fixed-width canonical serialization of the security-relevant challenge fields.
    /// Layout: DOMAIN ++ nonce(32) ++ agent_id_hash(32) ++ threshold_be(16) ++
    /// chain_id_be(4) ++ block[0..3]_be(8 each). Independent of JSON key ordering.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, String> {
        let mut out = Vec::with_capacity(CHALLENGE_DOMAIN.len() + 32 + 32 + 16 + 4 + 8 * BLOCK_COUNT);
        out.extend_from_slice(CHALLENGE_DOMAIN);
        out.extend_from_slice(&self.nonce_bytes()?);
        out.extend_from_slice(&self.agent_id_hash());
        out.extend_from_slice(&self.threshold_u128()?.to_be_bytes());
        out.extend_from_slice(&self.chain_id.to_be_bytes());
        for b in self.blocks {
            out.extend_from_slice(&b.to_be_bytes());
        }
        Ok(out)
    }

    /// EIP-191 `personal_sign` digest over a 32-byte prehash of [`Self::canonical_bytes`].
    /// Reuses the exact `"\x19Ethereum Signed Message:\n32"` pattern the guest/verifier
    /// already use for the in-circuit wallet signature, so recovery code is identical.
    pub fn challenge_digest(&self) -> Result<[u8; 32], String> {
        let prehash = keccak256(&self.canonical_bytes()?);
        let mut msg = Vec::with_capacity(28 + 32);
        msg.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
        msg.extend_from_slice(&prehash);
        Ok(keccak256(&msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Challenge {
        Challenge {
            challenge_id: "c-1".into(),
            agent_id: "0x1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d".into(),
            threshold: "1000000000000000000".into(),
            chain_id: 1,
            nonce: format!("0x{}", "ab".repeat(32)),
            head_block: 20_345_678,
            blocks: [20_330_011, 20_336_750, 20_344_120],
            issued_at: 1_751_328_000,
            expires_at: 1_751_331_600,
        }
    }

    #[test]
    fn challenge_serde_roundtrip() {
        let c = sample();
        let s = serde_json::to_string(&c).unwrap();
        let back: Challenge = serde_json::from_str(&s).unwrap();
        assert_eq!(c, back);
    }

    #[test]
    fn threshold_parses_decimal_and_hex() {
        let mut c = sample();
        assert_eq!(c.threshold_u128().unwrap(), 1_000_000_000_000_000_000u128);
        c.threshold = "0xde0b6b3a7640000".into();
        assert_eq!(c.threshold_u128().unwrap(), 1_000_000_000_000_000_000u128);
    }

    #[test]
    fn canonical_bytes_layout_frozen() {
        let c = sample();
        let b = c.canonical_bytes().unwrap();
        // freeze the layout: total length + field offsets
        let dom = CHALLENGE_DOMAIN.len();
        assert_eq!(b.len(), dom + 32 + 32 + 16 + 4 + 24);
        assert_eq!(&b[..dom], CHALLENGE_DOMAIN);
        assert_eq!(&b[dom..dom + 32], &c.nonce_bytes().unwrap());
        assert_eq!(&b[dom + 32..dom + 64], &c.agent_id_hash());
        assert_eq!(&b[dom + 64..dom + 80], &c.threshold_u128().unwrap().to_be_bytes());
        assert_eq!(&b[dom + 80..dom + 84], &c.chain_id.to_be_bytes());
        assert_eq!(&b[dom + 84..dom + 92], &c.blocks[0].to_be_bytes());
        assert_eq!(&b[dom + 92..dom + 100], &c.blocks[1].to_be_bytes());
        assert_eq!(&b[dom + 100..dom + 108], &c.blocks[2].to_be_bytes());
    }

    #[test]
    fn digest_is_deterministic_and_binds_fields() {
        let c = sample();
        assert_eq!(c.challenge_digest().unwrap(), c.challenge_digest().unwrap());
        // changing any signed field changes the digest
        let mut c2 = c.clone();
        c2.blocks[2] += 1;
        assert_ne!(c.challenge_digest().unwrap(), c2.challenge_digest().unwrap());
        let mut c3 = c.clone();
        c3.agent_id = "0xdeadbeef".into();
        assert_ne!(c.challenge_digest().unwrap(), c3.challenge_digest().unwrap());
    }

    #[test]
    fn token_id_parses_decimal_and_hex() {
        assert_eq!(parse_token_id("5868"), 5868);
        assert_eq!(parse_token_id("0x16ec"), 0x16ec);
        assert_eq!(parse_token_id("0x16EC"), 0x16ec);
        assert_eq!(parse_token_id(" 5868 "), 5868);
        assert_eq!(parse_token_id("not-a-number"), 0); // demo/non-marketplace -> inert
        let mut c = sample();
        c.agent_id = "5868".into();
        assert_eq!(c.agent_token_id(), 5868);
    }

    #[test]
    fn identity_message_frozen() {
        // FROZEN: this string seeds a set-once on-chain commitment. If this assertion ever needs
        // updating, every already-registered agent is locked out -- treat that as a breaking change.
        assert_eq!(
            identity_message(5868),
            "Horizen Proof-of-Reserves\n\
             Agent identity binding v1\n\
             agent: 5868\n\
             Signing derives this agent's private proving secret. Only sign on the official prover."
        );
    }

    #[test]
    fn secret_derivation_is_deterministic_and_v_agnostic() {
        let sig64: Vec<u8> = (0u8..64).collect();
        // r‖s only: appending a v byte (27/28 or 0/1) must not change the secret.
        let mut with_v27 = sig64.clone();
        with_v27.push(27);
        let mut with_v0 = sig64.clone();
        with_v0.push(0);
        assert_eq!(secret_from_identity_sig(&sig64), secret_from_identity_sig(&with_v27));
        assert_eq!(secret_from_identity_sig(&sig64), secret_from_identity_sig(&with_v0));
    }

    #[test]
    fn eip191_digest_matches_manual_prefix() {
        // Same construction the wallet uses for personal_sign of a text message.
        let msg = b"hello";
        let mut m = Vec::new();
        m.extend_from_slice(b"\x19Ethereum Signed Message:\n5hello");
        assert_eq!(eip191_digest(msg), keccak256(&m));
    }

    // Cross-implementation freeze: the CLI (k256) MUST derive the exact secret a browser wallet
    // does, or the CLI-proved and browser-proved commitments would differ. The expected value
    // was computed with viem (`privateKeyToAccount(key).signMessage`) -- representative of
    // MetaMask/Rabby -- for private key 0x00..01 signing identity_message(5868). If this ever
    // fails, deterministic/low-S ECDSA agreement between k256 and the wallet broke.
    #[test]
    fn secret_matches_browser_wallet() {
        use k256::ecdsa::SigningKey;
        let mut key = [0u8; 32];
        key[31] = 1;
        let sk = SigningKey::from_slice(&key).unwrap();
        let digest = eip191_digest(identity_message(5868).as_bytes());
        let (sig, _recid) = sk.sign_prehash_recoverable(&digest).unwrap();
        let secret = secret_from_identity_sig(sig.to_bytes().as_slice());
        assert_eq!(
            hex::encode(secret),
            "2935256a9ec8b5a5dad46717878e4e2f6b6c852e99e4ed109210a0262ab891fe",
            "k256 secret diverged from the viem/MetaMask-derived value"
        );
    }
}
