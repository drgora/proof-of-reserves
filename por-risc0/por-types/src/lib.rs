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
}
