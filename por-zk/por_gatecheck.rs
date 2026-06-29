// TEMPORARY Phase-0.2 measurement harness (not part of the product).
// Loads a nargo-compiled circuit json, runs SRS setup + UltraHonk VK generation
// via the crate's own noir-rs/Barretenberg, and times each step. VK generation
// synthesizes the full circuit, so its cost is a strong proxy for proving
// feasibility (time + memory) and reveals the real backend gate count — without
// needing a witness or oracle resolution.
//
// Run:  cargo run --release --bin por_gatecheck -- <path/to/circuit.json>

use anyhow::{anyhow, Result};
use noir::barretenberg::{srs::setup_srs_from_bytecode, verify::get_ultra_honk_verification_key};
use serde_json::Value;
use std::time::Instant;

fn main() -> Result<()> {
    let path = std::env::args()
        .nth(1)
        .ok_or_else(|| anyhow!("usage: por_gatecheck <circuit.json>"))?;
    let json: Value = serde_json::from_str(&std::fs::read_to_string(&path)?)?;
    let bytecode = json["bytecode"]
        .as_str()
        .ok_or_else(|| anyhow!("no bytecode field in {path}"))?
        .to_string();
    println!("circuit: {path}  (bytecode = {} base64 chars)", bytecode.len());

    let t = Instant::now();
    setup_srs_from_bytecode(&bytecode, None, false).map_err(|e| anyhow!(e))?;
    println!("setup_srs_from_bytecode: {:?}", t.elapsed());

    let t = Instant::now();
    let vk = get_ultra_honk_verification_key(&bytecode, false).map_err(|e| anyhow!(e))?;
    println!(
        "get_ultra_honk_verification_key: {:?}  (vk = {} bytes)",
        t.elapsed(),
        vk.len()
    );

    Ok(())
}
