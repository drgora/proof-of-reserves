// Proof-of-reserves PROVER CLI (thin wrapper over `por_core`).
//
// Proves that an Ethereum address holds >= THRESHOLD wei at a recent finalized
// block, via MPC-TLS `debug_getRawHeader` to an RPC (attested by a SEPARATE
// notary) + an `eth_getProof` state proof verified in zero knowledge. Writes a
// { presentation, zk_proof } bundle for `por_verifier`. Balance and address stay
// hidden.
//
// Run (after starting `zerion_notary`):
//   POR_ADDRESS=0x... THRESHOLD=1000000000000000000 \
//   NOTARY_ADDR=127.0.0.1:7150 [POR_PRIVKEY=0x..] [RPC_HOST=eth.drpc.org] \
//   RUST_LOG=info  cargo run --release --bin por_prove
//
// With POR_PRIVKEY set, the CLI signs personal_sign(block_hash) to prove ownership
// of POR_ADDRESS in-circuit; without it, the proof is generated in DEBUG mode
// (ownership check skipped — the verifier will reject it unless POR_ALLOW_DEBUG).

mod por_core;
mod por_witness;
mod por_zk;
mod types;

use std::env;

use anyhow::{Result, anyhow};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use por_core::Owner;
use tracing::{info, warn};

const BUNDLE_PATH: &str = "por.bundle.json";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let notary_addr = env::var("NOTARY_ADDR").unwrap_or_else(|_| "127.0.0.1:7150".into());
    let rpc_host = env::var("RPC_HOST").unwrap_or_else(|_| por_core::DEFAULT_RPC_HOST.into());
    let address = parse_hex_array::<20>(
        &env::var("POR_ADDRESS").map_err(|_| anyhow!("set POR_ADDRESS=0x... (20-byte account)"))?,
    )?;
    let threshold: u128 = env::var("THRESHOLD")
        .ok()
        .map(|t| t.parse())
        .transpose()
        .map_err(|e| anyhow!("invalid THRESHOLD (wei): {e}"))?
        .unwrap_or(1);

    let owner = match env::var("POR_PRIVKEY") {
        Ok(k) => Owner::LocalKey(parse_hex_array::<32>(&k)?),
        Err(_) => {
            warn!("no POR_PRIVKEY set -> DEBUG mode (ownership check skipped)");
            Owner::Debug
        }
    };

    info!("connecting to notary at {notary_addr}");
    let notary_stream = tokio::net::TcpStream::connect(&notary_addr).await?;
    notary_stream.set_nodelay(true)?;

    let (presentation, zk, block) = por_core::prove(
        notary_stream,
        &rpc_host,
        address,
        threshold,
        por_core::ETHEREUM_MAINNET_CHAIN_ID,
        owner,
        None,
    )
    .await?;

    let request = por_zk::ProofRequest {
        presentation_b64: BASE64.encode(bincode::serialize(&presentation)?),
        zk_proof_b64: BASE64.encode(bincode::serialize(&zk)?),
        required_threshold: None,
    };
    tokio::fs::write(BUNDLE_PATH, serde_json::to_vec_pretty(&request)?).await?;

    println!(
        "\n✅ Proof bundle written to `{BUNDLE_PATH}` (proves balance >= {threshold} wei at block {block})."
    );
    println!("Submit it to the verifier service:\n");
    println!("  curl -s -X POST http://127.0.0.1:8080/verify \\");
    println!("       -H 'content-type: application/json' \\");
    println!("       --data @{BUNDLE_PATH} | jq\n");
    Ok(())
}

fn parse_hex_array<const N: usize>(s: &str) -> Result<[u8; N]> {
    let bytes = hex::decode(s.trim_start_matches("0x"))?;
    if bytes.len() != N {
        return Err(anyhow!("expected {N} bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}
