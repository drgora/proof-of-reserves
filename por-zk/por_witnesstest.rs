// TEMPORARY test harness for the proof-of-reserves witness builder (por_witness.rs).
// Remove after de-risk.
//
// Fetches a real Ethereum account proof + raw block header from a public RPC,
// builds the circuit witness, and runs the full UltraHonk prove+verify roundtrip.
// Success = `verify_ultra_honk` returns true AND the proof's public block_hash
// equals keccak256(header_rlp).
//
// Run:  cargo run --release --bin por_witnesstest
//
// Network: uses `curl` to https://eth.drpc.org (HTTPS; the crate has no TLS HTTP
// client, and this is a throwaway harness). First run pays ~100s of SRS setup.
//
// Block selection: the as-shipped circuit only supports up to Cancun (max 20 header
// RLP fields, MAX_HEADER_FIELDS_COUNT=20). The CURRENT finalized mainnet block is
// post-Prague (21 fields: adds requestsHash) and would FAIL the circuit's field-count
// assert. So we fetch the current finalized block as instructed, detect whether it is
// circuit-compatible, and if not fall back to a known-good recent Cancun-era block.

#[path = "por_witness.rs"]
mod por_witness;

use anyhow::{Result, anyhow, bail};
use noir::{
    barretenberg::{
        prove::prove_ultra_honk,
        srs::setup_srs_from_bytecode,
        verify::{get_ultra_honk_verification_key, verify_ultra_honk},
    },
    witness::from_vec_str_to_witness_map,
};
use por_witness::{build_witness, decode_header, keccak256};
use serde_json::Value;
use std::process::Command;
use std::time::Instant;

const PROGRAM_JSON: &str = include_str!("./noir/target/noir.json");
const RPC_URL: &str = "https://eth.drpc.org";
// Beacon deposit contract (per task); falls back to an EOA if its proof overflows.
const PRIMARY_ADDR: &str = "0x00000000219ab540356cBB839Cbe05303d7705Fa";
const FALLBACK_ADDR: &str = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045";
// Known-good recent Cancun-era block (post-Cancun 19,426,587, pre-Prague ~22,431,084).
const CANCUN_FALLBACK_BLOCK: u64 = 21_000_000;
const MAX_CIRCUIT_HEADER_FIELDS: usize = 21;
const EXPECTED_NUM_PUB: u32 = 1 + 32 + 1 + 1; // threshold + block_hash[32] + chain_id + debug

fn rpc(method: &str, params: Value) -> Result<Value> {
    let body = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": method, "params": params
    })
    .to_string();
    let out = Command::new("curl")
        .args([
            "-s",
            "-X", "POST",
            "-H", "Content-Type: application/json",
            "-H", "Accept-Encoding: identity",
            "-H", "User-Agent: curl/8.0",
            "--data", &body,
            RPC_URL,
        ])
        .output()
        .map_err(|e| anyhow!("curl spawn failed: {e}"))?;
    if !out.status.success() {
        bail!("curl failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let resp: Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| anyhow!("RPC response not JSON ({e}): {}", String::from_utf8_lossy(&out.stdout)))?;
    if let Some(err) = resp.get("error") {
        bail!("RPC error from {method}: {err}");
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| anyhow!("RPC {method}: no result field"))
}

fn raw_header(block_hex: &str) -> Result<Vec<u8>> {
    let raw = rpc("debug_getRawHeader", serde_json::json!([block_hex]))?;
    let s = raw.as_str().ok_or_else(|| anyhow!("debug_getRawHeader not a string"))?;
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| anyhow!("header hex: {e}"))
}

fn circuit_bytecode() -> Result<String> {
    let json: Value = serde_json::from_str(PROGRAM_JSON)?;
    Ok(json["bytecode"]
        .as_str()
        .ok_or_else(|| anyhow!("bytecode field not found in noir.json"))?
        .to_string())
}

fn main() -> Result<()> {
    // ---- 1. Find the current finalized block (as instructed) ----
    let finalized = rpc("eth_getBlockByNumber", serde_json::json!(["finalized", false]))?;
    let fin_num_hex = finalized["number"]
        .as_str()
        .ok_or_else(|| anyhow!("finalized block has no number"))?
        .to_string();
    let fin_num = u64::from_str_radix(fin_num_hex.trim_start_matches("0x"), 16)?;
    println!("current finalized block: {fin_num} ({fin_num_hex})");

    // ---- 2. Decide which block to use: finalized if circuit-compatible, else Cancun ----
    let fin_header = raw_header(&fin_num_hex)?;
    let fin_decoded = decode_header(&fin_header);
    let (block_hex, block_num) = match &fin_decoded {
        Ok(h) if h.field_count <= MAX_CIRCUIT_HEADER_FIELDS => {
            println!(
                "finalized header has {} fields (<= {MAX_CIRCUIT_HEADER_FIELDS}); using finalized block",
                h.field_count
            );
            (fin_num_hex.clone(), fin_num)
        }
        Ok(h) => {
            println!(
                "finalized header has {} fields (> circuit max {MAX_CIRCUIT_HEADER_FIELDS}; \
                 post-Cancun fork unsupported by the as-shipped circuit) -> \
                 falling back to Cancun-era block {CANCUN_FALLBACK_BLOCK}",
                h.field_count
            );
            (format!("0x{CANCUN_FALLBACK_BLOCK:x}"), CANCUN_FALLBACK_BLOCK)
        }
        Err(e) => {
            println!(
                "could not decode finalized header ({e}) -> falling back to Cancun-era block {CANCUN_FALLBACK_BLOCK}"
            );
            (format!("0x{CANCUN_FALLBACK_BLOCK:x}"), CANCUN_FALLBACK_BLOCK)
        }
    };

    // ---- 3. Fetch the consistent header + proof for the chosen block ----
    let header_rlp = raw_header(&block_hex)?;
    let mut addr = PRIMARY_ADDR;
    let mut eth_proof = rpc(
        "eth_getProof",
        serde_json::json!([addr, Vec::<String>::new(), block_hex]),
    )?;
    let depth = eth_proof["accountProof"]
        .as_array()
        .map(|a| a.len())
        .unwrap_or(0);
    // Fall back to an EOA if the primary address overflows the circuit proof maxes.
    let max_node = eth_proof["accountProof"]
        .as_array()
        .and_then(|a| a.iter().map(|n| n.as_str().map(|s| (s.len() - 2) / 2).unwrap_or(0)).max())
        .unwrap_or(0);
    if depth == 0 || depth > 10 || max_node > 532 {
        println!("primary address proof unsuitable (depth={depth}, max_node={max_node}); using fallback EOA");
        addr = FALLBACK_ADDR;
        eth_proof = rpc(
            "eth_getProof",
            serde_json::json!([addr, Vec::<String>::new(), block_hex]),
        )?;
    }
    let depth = eth_proof["accountProof"].as_array().map(|a| a.len()).unwrap_or(0);
    println!("address: {addr}");
    println!("chosen block: {block_num} ({block_hex})");
    println!("account proof depth: {depth}");

    // ---- 4. Build the witness (debug=true: no wallet signature needed) ----
    let threshold: u128 = 1; // any account with >= 1 wei passes; balances here are huge
    let chain_id: u32 = 1;
    let witness_vec = build_witness(&eth_proof, &header_rlp, threshold, chain_id, true, None)?;
    println!("witness length: {} fields", witness_vec.len());

    // Sanity: the public block_hash we put in the witness must equal keccak256(header_rlp).
    let computed_block_hash = keccak256(&header_rlp);
    let decoded = decode_header(&header_rlp)?;
    assert_eq!(
        decoded.hash, computed_block_hash,
        "decoded header.hash != keccak256(header_rlp)"
    );
    println!("block_hash = keccak256(header_rlp) = 0x{}", hex::encode(computed_block_hash));

    // ---- 5. Prove + verify ----
    let bytecode = circuit_bytecode()?;
    let refs: Vec<&str> = witness_vec.iter().map(String::as_str).collect();
    let witness = from_vec_str_to_witness_map(refs).map_err(|e| anyhow!("witness map: {e}"))?;

    let t = Instant::now();
    setup_srs_from_bytecode(&bytecode, None, false).map_err(|e| anyhow!(e))?;
    println!("setup_srs_from_bytecode: {:?}", t.elapsed());

    let t = Instant::now();
    let vk = get_ultra_honk_verification_key(&bytecode, false).map_err(|e| anyhow!(e))?;
    println!("get_ultra_honk_verification_key: {:?} ({} bytes)", t.elapsed(), vk.len());

    let t = Instant::now();
    let proof = prove_ultra_honk(&bytecode, witness, vk.clone(), false).map_err(|e| anyhow!(e))?;
    let prove_time = t.elapsed();
    println!("prove_ultra_honk: {prove_time:?} ({} bytes)", proof.len());

    // Decode public inputs: num_pub (4 bytes BE) then 32-byte fields.
    let num_pub = u32::from_be_bytes(proof[0..4].try_into()?);
    if num_pub != EXPECTED_NUM_PUB {
        bail!("unexpected public-input count: got {num_pub}, expected {EXPECTED_NUM_PUB}");
    }
    let pubs = &proof[4..4 + (num_pub as usize) * 32];
    // Field 0 = threshold, fields 1..33 = block_hash (one byte per field, right-aligned).
    let block_hash_in_proof: Vec<u8> = pubs
        .chunks(32)
        .skip(1)
        .take(32)
        .map(|c| *c.last().unwrap_or(&0))
        .collect();
    if block_hash_in_proof != computed_block_hash {
        bail!(
            "public block_hash in proof (0x{}) != keccak256(header_rlp) (0x{})",
            hex::encode(&block_hash_in_proof),
            hex::encode(computed_block_hash)
        );
    }
    println!("public block_hash in proof matches keccak256(header_rlp): OK");

    let t = Instant::now();
    let ok = verify_ultra_honk(proof, vk).map_err(|e| anyhow!(e))?;
    println!("verify_ultra_honk: {:?} -> {ok}", t.elapsed());

    println!("\n--- SUMMARY ---");
    println!("block number : {block_num}");
    println!("proof depth  : {depth}");
    println!("proving time : {prove_time:?}");
    if ok {
        println!("RESULT: PASS (proof verifies, block_hash bound to header)");
        Ok(())
    } else {
        bail!("RESULT: FAIL (verify_ultra_honk returned false)");
    }
}
