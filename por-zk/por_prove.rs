// Proof-of-reserves PROVER CLI (thin wrapper over `por_core`).
//
// Runs MPC-TLS to live api.zerion.io with a SEPARATE notary, produces a
// { presentation, zk_proof } bundle proving floor(balance) >= THRESHOLD, and
// writes it to disk for submission to `por_verifier`.
//
// Run (after starting `zerion_notary` from crates/examples):
//   ZERION_API_KEY=...  ZERION_WALLET=0x...  THRESHOLD=1000000 \
//   NOTARY_ADDR=127.0.0.1:7150  RUST_LOG=info \
//     cargo run --release --bin por_prove

mod por_core;
mod por_zk;
mod types;

use std::env;

use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tracing::info;

const BUNDLE_PATH: &str = "por.bundle.json";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let notary_addr = env::var("NOTARY_ADDR").unwrap_or_else(|_| "127.0.0.1:7150".into());
    let wallet = env::var("ZERION_WALLET")
        .unwrap_or_else(|_| "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045".into());
    let threshold: u64 = env::var("THRESHOLD")
        .ok()
        .map(|t| t.parse())
        .transpose()
        .map_err(|e| anyhow!("invalid THRESHOLD: {e}"))?
        .unwrap_or(1_000_000);

    let auth_b64 = env::var("ZERION_API_KEY")
        .map(|k| BASE64.encode(format!("{k}:")))
        .unwrap_or_default();
    if auth_b64.is_empty() {
        return Err(anyhow!("set ZERION_API_KEY (need a 200 with a balance)"));
    }

    info!("connecting to notary at {notary_addr}");
    let notary_stream = tokio::net::TcpStream::connect(&notary_addr).await?;
    notary_stream.set_nodelay(true)?;

    let (presentation, zk) =
        por_core::prove(notary_stream, &wallet, threshold, auth_b64, Vec::new()).await?;

    let request = por_zk::ProofRequest {
        presentation_b64: BASE64.encode(bincode::serialize(&presentation)?),
        zk_proof_b64: BASE64.encode(bincode::serialize(&zk)?),
        required_threshold: Some(threshold),
    };
    tokio::fs::write(BUNDLE_PATH, serde_json::to_vec_pretty(&request)?).await?;

    println!("\n✅ Proof bundle written to `{BUNDLE_PATH}` (proves balance >= {threshold} USD).");
    println!("Submit it to the verifier service:\n");
    println!("  curl -s -X POST http://127.0.0.1:8080/verify \\");
    println!("       -H 'content-type: application/json' \\");
    println!("       --data @{BUNDLE_PATH} | jq\n");
    Ok(())
}
