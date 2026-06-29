// Standalone self-test for the proof-of-reserves Noir circuit, exercising the
// `noir-rs` (barretenberg/UltraHonk) prove+verify roundtrip WITHOUT any TLS or
// network. It validates that:
//   * the freshly recompiled `target/noir.json` is consumable by noir-rs,
//   * the witness layout (ABI order) is correct,
//   * the proof verifies, and
//   * the public inputs decode the way the real verifier will parse them
//     (threshold in field 0, committed hash in fields 1..33).
//
// Run from this crate:  cargo run --release --bin zk_selftest

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
use serde_json::Value;

const PROGRAM_JSON: &str = include_str!("./noir/target/noir.json");

const MAX_BALANCE_LEN: usize = 32;
const BLINDER_LEN: usize = 16;
// Public inputs: threshold (1 field) + committed_hash (32 fields).
const EXPECTED_NUM_PUB: u32 = 1 + 32;
const PREFIX_LEN: usize = 4;

fn main() -> Result<()> {
    // ---- Inputs (the prover would derive these from the TLS transcript) ----
    let balance = b"1234.56".to_vec(); // integer part 1234
    let blinder: [u8; BLINDER_LEN] = std::array::from_fn(|i| i as u8); // [0,1,..,15]
    let threshold: u64 = 1000;

    // Commitment the notary would have signed: SHA256(balance ++ blinder).
    let mut hasher = Sha256::new();
    hasher.update(&balance);
    hasher.update(blinder);
    let committed_hash = hasher.finalize().to_vec();
    println!("committed_hash = {}", hex::encode(&committed_hash));

    // ---- Build the witness in ABI order ----
    // ABI: threshold, committed_hash[32], balance[32], balance_len, blinder[16]
    let balance_len = balance.len();
    let mut balance_padded = balance.clone();
    balance_padded.resize(MAX_BALANCE_LEN, 0);

    let mut inputs: Vec<String> = Vec::new();
    inputs.push(threshold.to_string());
    inputs.extend(committed_hash.iter().map(|b| b.to_string()));
    inputs.extend(balance_padded.iter().map(|b| b.to_string()));
    inputs.push(balance_len.to_string());
    inputs.extend(blinder.iter().map(|b| b.to_string()));

    let bytecode = circuit_bytecode()?;

    let input_refs: Vec<&str> = inputs.iter().map(String::as_str).collect();
    let witness = from_vec_str_to_witness_map(input_refs).map_err(|e| anyhow!(e))?;

    setup_srs_from_bytecode(&bytecode, None, false).map_err(|e| anyhow!(e))?;
    let vk = get_ultra_honk_verification_key(&bytecode, false).map_err(|e| anyhow!(e))?;
    let proof = prove_ultra_honk(&bytecode, witness, vk.clone(), false).map_err(|e| anyhow!(e))?;
    println!("proof generated: {} bytes", proof.len());

    // ---- Decode public inputs exactly as the verifier will ----
    let num_pub = u32::from_be_bytes(proof[0..PREFIX_LEN].try_into()?);
    if num_pub != EXPECTED_NUM_PUB {
        return Err(anyhow!(
            "unexpected public-input count: got {num_pub}, expected {EXPECTED_NUM_PUB}"
        ));
    }
    let public_inputs = &proof[PREFIX_LEN..PREFIX_LEN + (num_pub as usize) * 32];

    // Field 0: threshold (last 8 bytes of the 32-byte field, big-endian).
    let threshold_in_proof = u64::from_be_bytes(public_inputs[24..32].try_into()?);
    // Fields 1..33: committed hash (one byte per field, right-aligned).
    let hash_in_proof: Vec<u8> = public_inputs
        .chunks(32)
        .skip(1)
        .take(32)
        .map(|c| *c.last().unwrap_or(&0))
        .collect();

    println!("threshold decoded from proof = {threshold_in_proof}");
    println!("hash decoded from proof       = {}", hex::encode(&hash_in_proof));

    if threshold_in_proof != threshold {
        return Err(anyhow!("threshold in proof does not match"));
    }
    if hash_in_proof != committed_hash {
        return Err(anyhow!("hash in proof does not match committed hash"));
    }

    let ok = verify_ultra_honk(proof, vk).map_err(|e| anyhow!(e))?;
    if !ok {
        return Err(anyhow!("UltraHonk proof failed to verify"));
    }

    println!("\n✅ self-test passed: ≥T proof generated, public inputs decode correctly, proof verifies.");
    Ok(())
}

fn circuit_bytecode() -> Result<String> {
    let json: Value = serde_json::from_str(PROGRAM_JSON)?;
    Ok(json["bytecode"]
        .as_str()
        .ok_or_else(|| anyhow!("bytecode field not found in noir.json"))?
        .to_string())
}
