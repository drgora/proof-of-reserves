// Relying-party verifier: verify the Risc0 receipt, decode its journal, and BIND it
// to the attested block header -- assert keccak256(attested_header) == journal.block_hash
// -- then enforce policy (debug==0, threshold, chain).
//
// Here the attested header is fetched by hash from the RPC. In PRODUCTION it comes
// from the verified TLSNotary presentation (which proves a NAMED operator served that
// exact header); the binding check is identical. This is the JOIN between the two
// artifacts: TLSNotary attests "a named RPC served header H"; the Risc0 receipt proves
// "balance>=threshold under H" -- block_hash is the shared anchor.
//
// Run from por-risc0/ (reads ./proof.json):
//   POR_REQUIRED_THRESHOLD=1000000000000000000 [POR_ALLOW_DEBUG=1] \
//     cargo run --release --bin por_verify
use methods::POR_GUEST_ID;
use risc0_zkvm::Receipt;
use serde_json::Value;
use std::process::Command;
use tiny_keccak::{Hasher, Keccak};

const RPC_URL: &str = "https://eth.drpc.org";

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    let mut o = [0u8; 32];
    k.update(data);
    k.finalize(&mut o);
    o
}

fn raw_header(block: &str) -> Vec<u8> {
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"debug_getRawHeader\",\"params\":[\"{block}\"]}}"
    );
    let out = Command::new("curl")
        .args(["-s", "-X", "POST", "-H", "content-type: application/json",
               "-H", "accept-encoding: identity", "-H", "user-agent: por/0.1",
               "--data", &body, RPC_URL])
        .output().expect("curl");
    let resp: Value = serde_json::from_slice(&out.stdout).expect("json");
    let hexs = resp["result"].as_str().expect("no raw header");
    hex::decode(hexs.trim_start_matches("0x")).unwrap()
}

fn main() {
    // ---- load + verify the Risc0 receipt ----
    let bundle: Value =
        serde_json::from_reader(std::fs::File::open("proof.json").expect("proof.json")).unwrap();
    let cbor = hex::decode(
        bundle["proofData"]["proof"].as_str().unwrap().trim_start_matches("0x"),
    ).unwrap();
    let receipt: Receipt = ciborium::from_reader(&cbor[..]).expect("decode receipt");
    receipt.verify(POR_GUEST_ID).expect("RECEIPT INVALID");
    println!("[1] Risc0 receipt verifies against image_id");

    // ---- decode the public journal (4 commits decode as a tuple) ----
    let (block_hash, threshold, chain_id, debug): ([u8; 32], u128, u32, bool) =
        receipt.journal.decode().expect("decode journal");
    println!(
        "[2] journal: block_hash=0x{}  threshold={}  chain_id={}  debug={}",
        hex::encode(block_hash), threshold, chain_id, debug
    );

    // ---- BINDING: journal block_hash must be the keccak of the attested header ----
    let header = raw_header(&format!("0x{}", hex::encode(block_hash)));
    assert_eq!(keccak256(&header), block_hash,
        "BINDING FAILED: keccak(attested header) != journal block_hash");
    println!("[3] BINDING OK: keccak256(attested header) == journal block_hash");

    // ---- negative control: a DIFFERENT block's header must NOT match ----
    let mismatch = keccak256(&raw_header("finalized")) != block_hash;
    println!("[3b] negative control (finalized header keccak != journal block_hash): {mismatch}");

    // ---- POLICY ----
    let allow_debug = std::env::var("POR_ALLOW_DEBUG").is_ok();
    if debug && !allow_debug {
        println!("[4] REJECTED: debug != 0 (set POR_ALLOW_DEBUG=1 to permit; never in prod)");
        std::process::exit(2);
    }
    let required: u128 = std::env::var("POR_REQUIRED_THRESHOLD")
        .ok().and_then(|s| s.parse().ok()).unwrap_or(1_000_000_000_000_000_000);
    assert!(threshold >= required, "threshold {threshold} < required {required}");
    assert_eq!(chain_id, 1, "unexpected chain_id");
    println!("[4] POLICY OK: debug={debug}, threshold {threshold} >= {required}, chain_id {chain_id}");

    println!("\nVERIFIED \u{2713} -- reserves bound to block 0x{} (balance & address hidden)", hex::encode(block_hash));
}
