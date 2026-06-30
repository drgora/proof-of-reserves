// Relying-party verifier (unified): verify the Risc0 receipt, decode its journal, and
// BIND it to the attested block header -- keccak256(attested_header) == journal.block_hash.
//
// The attested header comes from the TLSNotary presentation bundled in proof.json
// (`tlsnPresentation`): we verify the notary signature + server cert chain (Mozilla
// roots), enforce that the session was with the allowlisted RPC, and recover the header
// from the REVEALED response. TLSNotary attests "a named RPC served header H"; the Risc0
// receipt proves "balance>=threshold under H" -- block_hash is the shared anchor.
// If no presentation is present, we fall back to a dev-only by-hash re-fetch.
//
// Run from por-risc0/ (reads ./proof.json):
//   POR_REQUIRED_THRESHOLD=1000000000000000000 [POR_ALLOW_DEBUG=1] cargo run --release --bin por_verify
use methods::POR_GUEST_ID;
use risc0_zkvm::Receipt;
use serde_json::Value;
use std::process::Command;
use tiny_keccak::{Hasher, Keccak};

use base64::Engine as _;
use tlsn::{
    attestation::{
        presentation::{Presentation, PresentationOutput},
        CryptoProvider,
    },
    connection::ServerName,
    verifier::ServerCertVerifier,
};

const RPC_URL: &str = "https://eth.drpc.org";
// The RPC the notary must have witnessed (the cert identifies the operator, not the
// chain -- chain identity rests on this allowlist + the pinned block).
const EXPECTED_SERVER: &str = "eth.drpc.org";

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    let mut o = [0u8; 32];
    k.update(data);
    k.finalize(&mut o);
    o
}

fn find_sub(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() {
        return None;
    }
    hay[from..].windows(needle.len()).position(|w| w == needle).map(|p| from + p)
}

// Recover the raw header RLP from the revealed JSON-RPC response: find `result`, then
// the following `0x`, then read hex digits (robust to whitespace / chunk framing around
// the single-chunk body).
fn extract_header_rlp(recv: &[u8]) -> Option<Vec<u8>> {
    let r = find_sub(recv, b"result", 0)?;
    let zerox = find_sub(recv, b"0x", r)?;
    let mut end = zerox + 2;
    while end < recv.len() && recv[end].is_ascii_hexdigit() {
        end += 1;
    }
    hex::decode(&recv[zerox + 2..end]).ok()
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

// Verify the TLSNotary presentation and bind it to the journal's block_hash.
fn verify_presentation(b64: &str, journal_block_hash: &[u8; 32]) {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .expect("decode tlsnPresentation base64");
    let presentation: Presentation =
        bincode::deserialize(&bytes).expect("deserialize Presentation");

    let provider = CryptoProvider {
        cert: ServerCertVerifier::mozilla(),
        ..Default::default()
    };
    let notary_key = hex::encode(presentation.verifying_key().data.clone());

    let PresentationOutput {
        server_name,
        transcript,
        connection_info,
        ..
    } = presentation
        .verify(&provider)
        .expect("PRESENTATION INVALID (notary signature / cert chain)");

    let server_name = server_name.expect("server name not disclosed by presentation");
    let ServerName::Dns(ref dns) = server_name;
    assert_eq!(dns.as_str(), EXPECTED_SERVER,
        "unexpected server {} (Host allowlist requires {EXPECTED_SERVER})", dns.as_str());

    let partial = transcript.expect("transcript not disclosed");
    let received = partial.received_unsafe();
    let header = extract_header_rlp(received).expect("no header RLP in attested response");
    assert_eq!(&keccak256(&header), journal_block_hash,
        "BINDING FAILED: keccak(attested header) != journal block_hash");

    println!(
        "[3] TLSNotary OK: notary 0x{notary_key} attests {} served the header (t={}); \
         keccak256(attested header) == journal block_hash (BINDING OK)",
        dns.as_str(), connection_info.time
    );
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

    // ---- BINDING: prefer the TLSNotary presentation; dev fallback re-fetches by hash ----
    match bundle.get("tlsnPresentation").and_then(|v| v.as_str()) {
        Some(b64) => verify_presentation(b64, &block_hash),
        None => {
            let header = raw_header(&format!("0x{}", hex::encode(block_hash)));
            assert_eq!(keccak256(&header), block_hash,
                "BINDING FAILED: keccak(attested header) != journal block_hash");
            let mismatch = keccak256(&raw_header("finalized")) != block_hash;
            println!("[3] (DEV, no TLSNotary presentation) re-fetched header by hash; keccak == journal block_hash; \
                      negative control (finalized != journal): {mismatch}");
        }
    }

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
