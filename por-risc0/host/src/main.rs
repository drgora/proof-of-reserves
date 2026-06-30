// Prover host: fetch a REAL account proof + raw header from drpc, run the guest,
// prove (succinct receipt), confirm privacy, and write the zkVerify/Kurier bundle
// to proof.json.
//
// Two modes:
//   - POR_PRIVATE_KEY=<32-byte hex>: OWNERSHIP. Derive the EOA from the key, fetch
//     ITS account proof, sign EIP-191(block_hash), prove with debug=false (the guest
//     verifies in-circuit that the signer == the proven address).
//   - unset: DEMO. Prove the beacon deposit contract with debug=true (no key for a
//     contract). POR_THRESHOLD (wei) overrides the 1 ETH default in either mode.
use methods::{POR_GUEST_ELF, POR_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
use serde_json::Value;
use std::{fs::File, io::Write, process::Command, time::Instant};
use alloy_primitives::keccak256;
use k256::ecdsa::SigningKey;
use base64::Engine as _;

mod attest;

const RPC_URL: &str = "https://eth.drpc.org";
const ADDR: &str = "0x00000000219ab540356cBB839Cbe05303d7705Fa"; // beacon deposit contract

fn rpc(method: &str, params: Value) -> Value {
    let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    let out = Command::new("curl")
        .args(["-s", "-X", "POST", "-H", "content-type: application/json",
               "-H", "accept-encoding: identity", "-H", "user-agent: por/0.1",
               "--data", &body, RPC_URL])
        .output().expect("curl");
    let resp: Value = serde_json::from_slice(&out.stdout).expect("json");
    resp.get("result").cloned().expect("result")
}

fn hexb(s: &str) -> Vec<u8> {
    // eth RPC uses minimal hex, so odd-nibble values (e.g. balance "0x0", "0x1a3") are
    // common; left-pad to even length before decoding.
    let h = s.trim_start_matches("0x");
    let h = if h.len() % 2 == 1 { format!("0{h}") } else { h.to_string() };
    hex::decode(h).unwrap()
}
fn h32(s: &str) -> [u8; 32] { let v = hexb(s); let mut a = [0u8; 32]; a[32 - v.len()..].copy_from_slice(&v); a }
fn hu128(s: &str) -> u128 { let v = hexb(s); let mut a = [0u8; 16]; a[16 - v.len()..].copy_from_slice(&v); u128::from_be_bytes(a) }

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let fin = rpc("eth_getBlockByNumber", serde_json::json!(["finalized", false]));
    let block_hex = fin["number"].as_str().unwrap().to_string();
    let block_num = u64::from_str_radix(block_hex.trim_start_matches("0x"), 16).unwrap();

    let header_rlp = hexb(rpc("debug_getRawHeader", serde_json::json!([block_hex])).as_str().unwrap());

    // Mode: POR_PRIVATE_KEY set => OWNERSHIP (derive the EOA, prove + sign for it,
    // debug=false). Unset => DEMO (beacon deposit contract, debug=true; no key to sign).
    let owner_key: Option<SigningKey> = std::env::var("POR_PRIVATE_KEY").ok().map(|k| {
        SigningKey::from_slice(&hexb(&k)).expect("POR_PRIVATE_KEY must be 32-byte hex")
    });
    let addr_hex: String = match &owner_key {
        Some(sk) => {
            let enc = sk.verifying_key().to_encoded_point(false);
            let a: [u8; 20] = keccak256(&enc.as_bytes()[1..65])[12..32].try_into().unwrap();
            format!("0x{}", hex::encode(a))
        }
        None => ADDR.to_string(),
    };
    let debug = owner_key.is_none();

    let proof = rpc("eth_getProof", serde_json::json!([addr_hex, Vec::<String>::new(), block_hex]));

    let nonce = u64::from_str_radix(proof["nonce"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let balance = hu128(proof["balance"].as_str().unwrap());
    let storage_hash = h32(proof["storageHash"].as_str().unwrap());
    let code_hash = h32(proof["codeHash"].as_str().unwrap());
    let account_proof: Vec<Vec<u8>> = proof["accountProof"].as_array().unwrap()
        .iter().map(|n| hexb(n.as_str().unwrap())).collect();
    let mut address = [0u8; 20];
    address.copy_from_slice(&hexb(&addr_hex));

    // Ownership signature over EIP-191(block_hash), only when a key is provided.
    let block_hash = keccak256(&header_rlp);
    let sig: Vec<u8> = match &owner_key {
        Some(sk) => {
            let mut msg = Vec::with_capacity(60);
            msg.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
            msg.extend_from_slice(block_hash.as_slice());
            let prehash = keccak256(&msg);
            let (s, recid) = sk.sign_prehash_recoverable(prehash.as_slice()).unwrap();
            let mut v = s.to_bytes().to_vec();
            v.push(recid.to_byte());
            v
        }
        None => Vec::new(),
    };

    let threshold: u128 = std::env::var("POR_THRESHOLD").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(1_000_000_000_000_000_000); // 1 ETH
    let chain_id: u32 = 1;
    let mode = if debug { "DEMO (debug=true, ownership skipped)" } else { "OWNERSHIP (debug=false)" };
    println!("mode: {mode}\naddress {addr_hex}, block {block_num}, depth {}, balance {} ETH, threshold {} ETH",
        account_proof.len(), balance as f64 / 1e18, threshold as f64 / 1e18);
    if !debug && balance < threshold {
        eprintln!("WARNING: balance < threshold; the guest will reject this proof");
    }

    // TLSNotary attestation of the header (MPC-TLS to drpc via the notary). NOTARY_ADDR
    // set => attest debug_getRawHeader(block) and bundle the presentation; unset => dev
    // mode (proof.json without attestation; por_verify falls back to a by-hash re-fetch).
    // Done BEFORE the slow prove so a notary failure surfaces fast.
    let presentation_b64: Option<String> = match std::env::var("NOTARY_ADDR") {
        Ok(addr) => {
            println!("attesting debug_getRawHeader({block_hex}) to eth.drpc.org via notary {addr} ...");
            let bytes = attest::attest_header(&addr, "eth.drpc.org", &block_hex)
                .await
                .expect("TLSNotary attestation failed");
            println!("  attestation OK: {} byte presentation", bytes.len());
            Some(base64::engine::general_purpose::STANDARD.encode(&bytes))
        }
        Err(_) => {
            println!("NOTARY_ADDR unset -> skipping TLSNotary attestation (dev mode)");
            None
        }
    };

    // Segment size. Default po2=20 = risc0's default (CPU prover; ~265 s baseline).
    // Lower via POR_SEGMENT_PO2 for small-VRAM GPUs: the 8 GB RTX 3070 Laptop needed
    // <=15 to avoid OOM (impractically many segments) -> CPU stays the primary prover;
    // GPU (`--features cuda`) is worthwhile only on a >=16 GB card.
    let seg_po2: u32 = std::env::var("POR_SEGMENT_PO2").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(20);
    let env = ExecutorEnv::builder()
        .segment_limit_po2(seg_po2)
        .write(&header_rlp).unwrap()
        .write(&account_proof).unwrap()
        .write(&address).unwrap()
        .write(&nonce).unwrap()
        .write(&balance).unwrap()
        .write(&storage_hash).unwrap()
        .write(&code_hash).unwrap()
        .write(&sig).unwrap() // ownership sig (empty in demo mode)
        .write(&threshold).unwrap()
        .write(&chain_id).unwrap()
        .write(&debug).unwrap()
        .build().unwrap();

    let t = Instant::now();
    let receipt = default_prover()
        .prove_with_opts(env, POR_GUEST_ELF, &ProverOpts::succinct()).unwrap().receipt;
    let prove_time = t.elapsed();
    receipt.verify(POR_GUEST_ID).unwrap();
    println!("receipt verifies; proving {prove_time:?} (segment_limit_po2={seg_po2})");

    let j = &receipt.journal.bytes;
    // balance==0 serializes to 16 zero bytes, which also appears legitimately in the
    // journal (threshold can be 0; block_hash has zero runs) -> only a NONZERO balance
    // showing up is a real leak.
    let bal_leaked = balance != 0 && j.windows(16).any(|w| w == balance.to_le_bytes());
    let addr_leaked = j.windows(20).any(|w| w == address);
    println!("journal {} bytes; balance leaked? {bal_leaked}; address leaked? {addr_leaked}", j.len());
    assert!(!bal_leaked && !addr_leaked, "PRIVACY FAILURE");

    let mut cbor = Vec::new();
    ciborium::into_writer(&receipt, &mut cbor).unwrap();
    let image_id = hex::encode(POR_GUEST_ID.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>());
    let mut proof_json = serde_json::json!({
        "proofType": "risc0", "proofOptions": { "version": "V3_0" },
        "proofData": { "proof": format!("0x{}", hex::encode(&cbor)),
            "vk": format!("0x{image_id}"), "publicSignals": format!("0x{}", hex::encode(j)) }
    });
    if let Some(p) = presentation_b64 {
        proof_json["tlsnPresentation"] = serde_json::Value::String(p);
        println!("bundled TLSNotary presentation into proof.json");
    }
    File::create("proof.json").unwrap()
        .write_all(serde_json::to_string_pretty(&proof_json).unwrap().as_bytes()).unwrap();
    println!("wrote proof.json: CBOR receipt {} bytes, journal {} bytes", cbor.len(), j.len());
}
