// Shared ZK helpers and REST wire types for the proof-of-reserves service.
//
// The same `≥T` Noir circuit used by the interactive demo is reused here, but
// the commitment now comes from a NOTARY-SIGNED attestation rather than a live
// MPC session, so the proof can be verified offline by a REST endpoint.

// Shared by por_prove and por_verifier; each binary exercises a subset.
#![allow(dead_code)]

use anyhow::{Result, anyhow};
use k256::sha2::{Digest, Sha256};
use noir::{
    barretenberg::{
        prove::prove_ultra_honk,
        srs::setup_srs_from_bytecode,
        verify::{get_ultra_honk_verification_key, verify_ultra_honk},
    },
    witness::from_vec_str_to_witness_map,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MAX_BALANCE_LEN: usize = 32;
pub const BLINDER_LEN: usize = 16;
// Public inputs: threshold (1 field) + committed_hash (32 fields).
pub const EXPECTED_NUM_PUB: u32 = 1 + 32;
const PREFIX_LEN: usize = 4;

const PROGRAM_JSON: &str = include_str!("./noir/target/noir.json");

/// A serialized UltraHonk proof + its verification key.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ZKProofBundle {
    pub vk: Vec<u8>,
    pub proof: Vec<u8>,
}

/// `POST /verify` request body. Both fields are base64(bincode(..)).
#[derive(Serialize, Deserialize, Debug)]
pub struct ProofRequest {
    /// bincode(`tlsn::attestation::presentation::Presentation`)
    pub presentation_b64: String,
    /// bincode(`ZKProofBundle`)
    pub zk_proof_b64: String,
    /// Optional: minimum threshold the relying party requires (defaults applied
    /// server-side if absent).
    pub required_threshold: Option<u64>,
}

/// `POST /verify` response body.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct VerifyResponse {
    pub verified: bool,
    pub server_name: Option<String>,
    pub time: Option<String>,
    /// The threshold the proof actually attests (`balance >= threshold_proven`).
    pub threshold_proven: Option<u64>,
    /// The notary public key that signed the attestation (trust anchor).
    pub notary_key: Option<String>,
    /// The wallet the proof is about (from the revealed Zerion request path).
    pub wallet: Option<String>,
    /// Whether the bundle's SIWE proves the requester owns `wallet`.
    pub owner_verified: Option<bool>,
    pub error: Option<String>,
}

fn bytecode() -> Result<String> {
    let json: Value = serde_json::from_str(PROGRAM_JSON)?;
    Ok(json["bytecode"]
        .as_str()
        .ok_or_else(|| anyhow!("bytecode field not found in noir.json"))?
        .to_string())
}

/// Generate a ZK proof that `floor(balance) >= threshold`, bound to
/// `committed_hash = SHA256(balance ++ blinder)`. The balance never leaves here.
pub fn generate_proof(
    balance: &[u8],
    blinder: &[u8],
    committed_hash: &[u8],
    threshold: u64,
) -> Result<ZKProofBundle> {
    if balance.len() > MAX_BALANCE_LEN {
        return Err(anyhow!(
            "balance field {} bytes exceeds circuit MAX_BALANCE_LEN={MAX_BALANCE_LEN}",
            balance.len()
        ));
    }

    // Sanity: the commitment we were handed must match these bytes.
    let mut hasher = Sha256::new();
    hasher.update(balance);
    hasher.update(blinder);
    if hasher.finalize().as_slice() != committed_hash {
        return Err(anyhow!("local hash != committed hash; refusing to prove"));
    }

    // Witness in ABI order: threshold, committed_hash[32], balance[32], balance_len, blinder[16].
    let mut balance_padded = balance.to_vec();
    let balance_len = balance.len();
    balance_padded.resize(MAX_BALANCE_LEN, 0);

    let mut inputs: Vec<String> = Vec::new();
    inputs.push(threshold.to_string());
    inputs.extend(committed_hash.iter().map(|b| b.to_string()));
    inputs.extend(balance_padded.iter().map(|b| b.to_string()));
    inputs.push(balance_len.to_string());
    inputs.extend(blinder.iter().map(|b| b.to_string()));

    let bytecode = bytecode()?;
    let input_refs: Vec<&str> = inputs.iter().map(String::as_str).collect();
    let witness = from_vec_str_to_witness_map(input_refs).map_err(|e| anyhow!(e))?;

    setup_srs_from_bytecode(&bytecode, None, false).map_err(|e| anyhow!(e))?;
    let vk = get_ultra_honk_verification_key(&bytecode, false).map_err(|e| anyhow!(e))?;
    let proof = prove_ultra_honk(&bytecode, witness, vk.clone(), false).map_err(|e| anyhow!(e))?;

    Ok(ZKProofBundle { vk, proof })
}

/// Public inputs decoded from a proof: the proven threshold and committed hash.
pub struct ProofPublicInputs {
    pub threshold: u64,
    pub committed_hash: Vec<u8>,
}

/// Verify the UltraHonk proof was produced by OUR circuit and decode its public
/// inputs. The caller must still check `threshold >= policy` and that
/// `committed_hash` equals the notary-signed commitment.
pub fn verify_proof(bundle: &ZKProofBundle) -> Result<ProofPublicInputs> {
    let bytecode = bytecode()?;

    // Initialize barretenberg's global CRS for this process. The prover does
    // this before proving; the verifier runs in its own process, so it must too
    // before computing the verification key / verifying.
    setup_srs_from_bytecode(&bytecode, None, false).map_err(|e| anyhow!(e))?;

    // The prover must be using exactly our circuit.
    let vk = get_ultra_honk_verification_key(&bytecode, false).map_err(|e| anyhow!(e))?;
    if vk != bundle.vk {
        return Err(anyhow!("verification key mismatch (unexpected circuit)"));
    }

    let proof = &bundle.proof;
    let min_bytes = PREFIX_LEN + (EXPECTED_NUM_PUB as usize) * 32;
    if proof.len() < min_bytes {
        return Err(anyhow!("proof too short: {} < {min_bytes}", proof.len()));
    }
    let num_pub = u32::from_be_bytes(proof[0..PREFIX_LEN].try_into()?);
    if num_pub != EXPECTED_NUM_PUB {
        return Err(anyhow!(
            "unexpected public-input count: {num_pub} != {EXPECTED_NUM_PUB}"
        ));
    }
    let public_inputs = &proof[PREFIX_LEN..PREFIX_LEN + (num_pub as usize) * 32];

    let threshold = u64::from_be_bytes(public_inputs[24..32].try_into()?);
    let committed_hash: Vec<u8> = public_inputs
        .chunks(32)
        .skip(1)
        .take(32)
        .map(|c| *c.last().unwrap_or(&0))
        .collect();

    // Verify the proof itself.
    let ok = verify_ultra_honk(bundle.proof.clone(), bundle.vk.clone()).map_err(|e| anyhow!(e))?;
    if !ok {
        return Err(anyhow!("UltraHonk proof failed to verify"));
    }

    Ok(ProofPublicInputs {
        threshold,
        committed_hash,
    })
}
