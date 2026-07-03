// Prover: given a verifier CHALLENGE (a nonce + 3 recent block numbers + threshold +
// agent_id), fetch a REAL account proof + raw header for each block, prove one
// self-contained succinct receipt PER block, and sign the challenge with the agent's owner
// EOA -> response.json (the bundle the `verifier` service consumes).
//
// Invocation modes:
//   - CONNECTED (`--verifier <url> --agent-id <id> --threshold <wei>`): the whole agent-side
//     flow in one shot -- request the challenge, prove it, submit the response, print the verdict.
//   - FILE (`--challenge <path>` / `POR_CHALLENGE`): prove a pre-issued challenge -> response.json.
//   - LEGACY (none of the above): single finalized block -> proof.json (dev + the `por_verify` CLI).
//
// Per-block mode (unchanged):
//   - POR_PRIVATE_KEY=<32B hex>: OWNERSHIP. Derive the EOA, fetch ITS proof, sign
//     EIP-191(block_hash) in the witness, debug=false (guest verifies signer == address).
//   - unset: DEMO. Prove the beacon deposit contract with debug=true (no key for a contract).
//
// Challenge authentication (separate from the in-circuit wallet sig): the challenge is
// signed with POR_OWNER_KEY (falls back to POR_PRIVATE_KEY) -- the verifier recovers it and
// checks it against the agent's registry `owner`.
//
// Env: POR_THRESHOLD (legacy-mode wei; challenge mode uses the challenge threshold),
//   POR_SEGMENT_PO2 (segment size, default 20), NOTARY_ADDR (enables per-block attestation),
//   POR_OWNER_KEY (owner EOA for the challenge signature).
use methods::{POR_GUEST_ELF, POR_GUEST_ID};
use risc0_zkvm::{default_prover, ExecutorEnv, ProverOpts};
use serde_json::Value;
use std::{fs::File, io::Write, process::{Command, Stdio}, time::Instant};
use alloy_primitives::keccak256;
use k256::ecdsa::SigningKey;
use base64::Engine as _;

use host::attest;
use por_types::{Challenge, Response, RESPONSE_VERSION};

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

// POST a JSON body via stdin (a full response with 3 receipts can be ~1.5 MB, past ARG_MAX
// for an inline --data argv).
fn curl_post_stdin(url: &str, body: &str) -> Vec<u8> {
    let mut child = Command::new("curl")
        .args(["-s", "-X", "POST", "-H", "content-type: application/json", "--data-binary", "@-", url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("curl");
    child.stdin.take().expect("curl stdin").write_all(body.as_bytes()).expect("write curl stdin");
    child.wait_with_output().expect("curl").stdout
}

fn http_post_json(url: &str, body: &str) -> Value {
    let out = curl_post_stdin(url, body);
    serde_json::from_slice(&out)
        .unwrap_or_else(|_| panic!("non-JSON response from {url}: {}", String::from_utf8_lossy(&out)))
}

fn http_get(url: &str) -> Value {
    let out = Command::new("curl").args(["-s", url]).output().expect("curl").stdout;
    serde_json::from_slice(&out).unwrap_or(Value::Null)
}

// Witness for a single block (the private guest inputs, minus the ownership sig).
struct BlockInputs {
    header_rlp: Vec<u8>,
    account_proof: Vec<Vec<u8>>,
    address: [u8; 20],
    nonce: u64,
    balance: u128,
    storage_hash: [u8; 32],
    code_hash: [u8; 32],
}

// Fetch the raw header + account proof for `addr_hex` at `block_hex` (a hex block number).
fn fetch_block(block_hex: &str, addr_hex: &str) -> BlockInputs {
    let header_rlp = hexb(rpc("debug_getRawHeader", serde_json::json!([block_hex])).as_str().unwrap());
    let proof = rpc("eth_getProof", serde_json::json!([addr_hex, Vec::<String>::new(), block_hex]));
    let nonce = u64::from_str_radix(proof["nonce"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let balance = hu128(proof["balance"].as_str().unwrap());
    let storage_hash = h32(proof["storageHash"].as_str().unwrap());
    let code_hash = h32(proof["codeHash"].as_str().unwrap());
    let account_proof: Vec<Vec<u8>> = proof["accountProof"].as_array().unwrap()
        .iter().map(|n| hexb(n.as_str().unwrap())).collect();
    let mut address = [0u8; 20];
    address.copy_from_slice(&hexb(addr_hex));
    BlockInputs { header_rlp, account_proof, address, nonce, balance, storage_hash, code_hash }
}

// Ownership signature over EIP-191(block_hash) with the wallet key (empty when debug/no key).
fn wallet_sig(header_rlp: &[u8], key: &Option<SigningKey>) -> Vec<u8> {
    let Some(sk) = key else { return Vec::new() };
    let block_hash = keccak256(header_rlp);
    let mut msg = Vec::with_capacity(60);
    msg.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
    msg.extend_from_slice(block_hash.as_slice());
    let prehash = keccak256(&msg);
    let (s, recid) = sk.sign_prehash_recoverable(prehash.as_slice()).unwrap();
    let mut v = s.to_bytes().to_vec();
    v.push(recid.to_byte());
    v
}

// Refuse impossible proofs cleanly, before the (slow) attestation + proving. A wallet that
// can't meet the threshold -- including one that doesn't exist (balance 0, an MPT *exclusion*
// proof) -- makes the guest correctly refuse; without this that surfaces as an ugly panic +
// backtrace through prove()'s unwrap. Exit with a clear message instead.
fn ensure_can_prove(balance: u128, threshold: u128, debug: bool) {
    if !debug && balance < threshold {
        eprintln!(
            "\ncannot prove reserves: balance {balance} wei < threshold {threshold} wei{}",
            if balance == 0 {
                " (the account does not exist / holds nothing at this block)"
            } else {
                ""
            }
        );
        eprintln!(
            "hint: use a wallet funded above the threshold across the whole challenge window, \
             or run DEMO mode (unset POR_PRIVATE_KEY)."
        );
        std::process::exit(1);
    }
}

// Prove one block -> a proof.json-shaped bundle (optionally carrying a TLSNotary presentation).
#[allow(clippy::too_many_arguments)]
fn prove_block(
    inputs: &BlockInputs,
    sig: &[u8],
    threshold: u128,
    chain_id: u32,
    debug: bool,
    challenge_nonce: &[u8; 32],
    agent_id: &[u8; 32],
    seg_po2: u32,
    presentation_b64: Option<String>,
) -> Value {
    // Marketplace binding inputs (per-agent constants). Default to 0 / zero-secret when
    // unset -- legacy/demo runs don't record on the marketplace, so the values are inert.
    let agent_token_id: u64 =
        std::env::var("POR_AGENT_TOKEN_ID").ok().and_then(|s| s.parse().ok()).unwrap_or(0);
    let agent_secret: [u8; 32] = std::env::var("POR_AGENT_SECRET")
        .ok()
        .map(|h| hexb(&h).try_into().expect("POR_AGENT_SECRET must be 32-byte hex"))
        .unwrap_or([0u8; 32]);

    let env = ExecutorEnv::builder()
        .segment_limit_po2(seg_po2)
        .write(&inputs.header_rlp).unwrap()
        .write(&inputs.account_proof).unwrap()
        .write(&inputs.address).unwrap()
        .write(&inputs.nonce).unwrap()
        .write(&inputs.balance).unwrap()
        .write(&inputs.storage_hash).unwrap()
        .write(&inputs.code_hash).unwrap()
        .write(&sig.to_vec()).unwrap() // ownership sig (empty in demo mode)
        .write(&threshold).unwrap()
        .write(&chain_id).unwrap()
        .write(&debug).unwrap()
        .write(challenge_nonce).unwrap()
        .write(agent_id).unwrap()
        .write(&agent_token_id).unwrap() // marketplace ERC-721 token id
        .write(&agent_secret).unwrap()   // private agent secret (identity binding)
        .build().unwrap();

    let t = Instant::now();
    // Backstop: if the guest still refuses here (e.g. balance below threshold, or an
    // absent-account MPT exclusion proof), exit cleanly instead of unwrapping into a panic.
    let receipt = match default_prover().prove_with_opts(env, POR_GUEST_ELF, &ProverOpts::succinct()) {
        Ok(info) => info.receipt,
        Err(e) => {
            eprintln!("\ncannot prove this block: {e}");
            std::process::exit(1);
        }
    };
    receipt.verify(POR_GUEST_ID).unwrap();

    let j = &receipt.journal.bytes;
    // balance==0 serializes to zero bytes that also appear legitimately -> only a NONZERO
    // balance showing up is a real leak.
    let bal_leaked = inputs.balance != 0 && j.windows(16).any(|w| w == inputs.balance.to_le_bytes());
    let addr_leaked = j.windows(20).any(|w| w == inputs.address);
    assert!(!bal_leaked && !addr_leaked, "PRIVACY FAILURE");
    println!("    proved in {:?}; journal {} bytes; balance leaked? {bal_leaked}; address leaked? {addr_leaked}", t.elapsed(), j.len());

    let mut cbor = Vec::new();
    ciborium::into_writer(&receipt, &mut cbor).unwrap();
    let image_id = hex::encode(POR_GUEST_ID.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>());
    let mut bundle = serde_json::json!({
        "proofType": "risc0", "proofOptions": { "version": "V3_0" },
        "proofData": { "proof": format!("0x{}", hex::encode(&cbor)),
            "vk": format!("0x{image_id}"), "publicSignals": format!("0x{}", hex::encode(j)) }
    });
    if let Some(p) = presentation_b64 {
        bundle["tlsnPresentation"] = Value::String(p);
    }
    bundle
}

// MPC-TLS-attest the header via the notary (before the slow prove, so failures surface fast).
async fn maybe_attest(block_hex: &str) -> Option<String> {
    match std::env::var("NOTARY_ADDR") {
        Ok(addr) => {
            println!("    attesting debug_getRawHeader({block_hex}) via notary {addr} ...");
            let bytes = attest::attest_header(&addr, "eth.drpc.org", block_hex)
                .await
                .expect("TLSNotary attestation failed");
            println!("    attestation OK: {} byte presentation", bytes.len());
            Some(base64::engine::general_purpose::STANDARD.encode(&bytes))
        }
        Err(_) => None,
    }
}

// A challenge from `--challenge <path>` or the `POR_CHALLENGE` env (inline JSON).
fn load_challenge() -> Option<Challenge> {
    let args: Vec<String> = std::env::args().collect();
    if let Some(i) = args.iter().position(|a| a == "--challenge") {
        let p = args.get(i + 1).expect("--challenge needs a path");
        let s = std::fs::read_to_string(p).expect("read challenge file");
        return Some(serde_json::from_str(&s).expect("parse challenge json"));
    }
    std::env::var("POR_CHALLENGE")
        .ok()
        .map(|s| serde_json::from_str(&s).expect("parse POR_CHALLENGE json"))
}

fn arg_value(flag: &str) -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}

// Connected (one-shot agent) mode is triggered by `--verifier <url>` (needs --agent-id + --threshold).
fn connected_target() -> Option<(String, String, String)> {
    let verifier_url = arg_value("--verifier")?;
    let agent_id = arg_value("--agent-id").expect("--verifier requires --agent-id");
    let threshold = arg_value("--threshold").expect("--verifier requires --threshold (wei)");
    Some((verifier_url, agent_id, threshold))
}

// Sign the challenge digest with the owner EOA (POR_OWNER_KEY, falling back to POR_PRIVATE_KEY).
fn owner_sign(ch: &Challenge) -> Option<String> {
    let key = std::env::var("POR_OWNER_KEY").ok().or_else(|| std::env::var("POR_PRIVATE_KEY").ok())?;
    let sk = SigningKey::from_slice(&hexb(&key)).expect("owner key must be 32-byte hex");
    let digest = ch.challenge_digest().expect("challenge digest");
    let (s, recid) = sk.sign_prehash_recoverable(&digest).unwrap();
    let mut v = s.to_bytes().to_vec();
    v.push(recid.to_byte());
    Some(format!("0x{}", hex::encode(v)))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    // Wallet key: set => OWNERSHIP (derive the EOA, debug=false); unset => DEMO (beacon, debug=true).
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
    let chain_id: u32 = 1;
    let seg_po2: u32 = std::env::var("POR_SEGMENT_PO2").ok().and_then(|s| s.parse().ok()).unwrap_or(20);

    match connected_target() {
        // Connected: request challenge -> prove -> submit -> verdict, against a live verifier.
        Some((url, agent_id, threshold)) => {
            run_connected(url, agent_id, threshold, &owner_key, &addr_hex, debug, chain_id, seg_po2).await
        }
        None => match load_challenge() {
            // File: prove a challenge from --challenge/POR_CHALLENGE -> response.json.
            Some(ch) => run_challenge(ch, &owner_key, &addr_hex, debug, chain_id, seg_po2).await,
            // Legacy: single finalized block -> proof.json.
            None => run_legacy_single(&owner_key, &addr_hex, debug, chain_id, seg_po2).await,
        },
    }
}

// Prove every challenged block + sign the challenge -> the Response to submit.
async fn prove_challenge(
    ch: Challenge,
    owner_key: &Option<SigningKey>,
    addr_hex: &str,
    debug: bool,
    chain_id: u32,
    seg_po2: u32,
) -> Response {
    assert_eq!(ch.chain_id, chain_id, "challenge chain_id != 1");
    let threshold = ch.threshold_u128().expect("challenge threshold");
    let challenge_nonce = ch.nonce_bytes().expect("challenge nonce");
    let agent_id = ch.agent_id_hash();
    let mode = if debug { "DEMO (debug=true)" } else { "OWNERSHIP (debug=false)" };
    println!(
        "challenge {}: agent {}, threshold {} ETH, blocks {:?}, mode {mode}, wallet {addr_hex}",
        ch.challenge_id, ch.agent_id, threshold as f64 / 1e18, ch.blocks
    );

    let mut bundles = Vec::with_capacity(ch.blocks.len());
    let t_all = Instant::now();
    for (i, &blk) in ch.blocks.iter().enumerate() {
        let block_hex = format!("0x{blk:x}");
        println!("[block {}/{}] {block_hex} (#{blk})", i + 1, ch.blocks.len());
        let inputs = fetch_block(&block_hex, addr_hex);
        ensure_can_prove(inputs.balance, threshold, debug);
        let sig = wallet_sig(&inputs.header_rlp, owner_key);
        let presentation = maybe_attest(&block_hex).await;
        let bundle = prove_block(&inputs, &sig, threshold, chain_id, debug, &challenge_nonce, &agent_id, seg_po2, presentation);
        bundles.push(bundle);
    }

    let owner_sig = owner_sign(&ch).unwrap_or_else(|| {
        eprintln!("WARNING: no POR_OWNER_KEY/POR_PRIVATE_KEY -> empty owner_sig \
                   (verifier must run with POR_ALLOW_UNVERIFIED_OWNER)");
        String::new()
    });
    println!("proved {} blocks in {:?}", bundles.len(), t_all.elapsed());
    Response { version: RESPONSE_VERSION.into(), challenge: ch, owner_sig, bundles }
}

// File mode (`--challenge <file>`): prove and write response.json.
async fn run_challenge(
    ch: Challenge,
    owner_key: &Option<SigningKey>,
    addr_hex: &str,
    debug: bool,
    chain_id: u32,
    seg_po2: u32,
) {
    let response = prove_challenge(ch, owner_key, addr_hex, debug, chain_id, seg_po2).await;
    let out = arg_value("--out").unwrap_or_else(|| "response.json".into());
    File::create(&out).unwrap()
        .write_all(serde_json::to_string_pretty(&response).unwrap().as_bytes()).unwrap();
    println!("wrote {out}: {} bundles", response.bundles.len());
}

// Connected mode (`--verifier <url> --agent-id <id> --threshold <wei>`): request a challenge,
// prove it, submit the response, print the verdict -- the whole agent-side flow in one shot.
async fn run_connected(
    verifier_url: String,
    agent_id: String,
    threshold: String,
    owner_key: &Option<SigningKey>,
    addr_hex: &str,
    debug: bool,
    chain_id: u32,
    seg_po2: u32,
) {
    let base = verifier_url.trim_end_matches('/').to_string();
    println!("requesting challenge from {base} for agent {agent_id} (threshold {threshold} wei) ...");
    let req = serde_json::json!({ "agent_id": agent_id, "threshold": threshold }).to_string();
    let raw = http_post_json(&format!("{base}/v1/challenges"), &req);
    if raw.get("challenge_id").is_none() {
        eprintln!("verifier did not issue a challenge: {raw}");
        std::process::exit(1);
    }
    let ch: Challenge = serde_json::from_value(raw).expect("parse challenge from verifier");
    let cid = ch.challenge_id.clone();

    let response = prove_challenge(ch, owner_key, addr_hex, debug, chain_id, seg_po2).await;
    if let Some(out) = arg_value("--out") {
        File::create(&out).unwrap()
            .write_all(serde_json::to_string_pretty(&response).unwrap().as_bytes()).unwrap();
        println!("wrote {out} (audit copy)");
    }

    println!("submitting response for challenge {cid} ...");
    let body = serde_json::to_string(&response).unwrap();
    let verdict = http_post_json(&format!("{base}/v1/challenges/{cid}/response"), &body);
    let v = verdict.get("verdict").and_then(|x| x.as_str()).unwrap_or("?");
    println!("\nverdict: {v}");
    if let Some(r) = verdict.get("reason").and_then(|x| x.as_str()) {
        println!("reason: {r}");
    }
    let st = http_get(&format!("{base}/v1/challenges/{cid}"));
    if st != Value::Null {
        println!("final status: {st}");
    }
    if v != "verified" {
        std::process::exit(2);
    }
}

// Legacy mode: single finalized block -> proof.json (placeholder challenge fields).
async fn run_legacy_single(
    owner_key: &Option<SigningKey>,
    addr_hex: &str,
    debug: bool,
    chain_id: u32,
    seg_po2: u32,
) {
    let fin = rpc("eth_getBlockByNumber", serde_json::json!(["finalized", false]));
    let block_hex = fin["number"].as_str().unwrap().to_string();
    let block_num = u64::from_str_radix(block_hex.trim_start_matches("0x"), 16).unwrap();
    let threshold: u128 = std::env::var("POR_THRESHOLD").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(1_000_000_000_000_000_000); // 1 ETH

    let inputs = fetch_block(&block_hex, addr_hex);
    let mode = if debug { "DEMO (debug=true, ownership skipped)" } else { "OWNERSHIP (debug=false)" };
    println!(
        "legacy single-block mode: {mode}\naddress {addr_hex}, block {block_num}, depth {}, balance {} ETH, threshold {} ETH",
        inputs.account_proof.len(), inputs.balance as f64 / 1e18, threshold as f64 / 1e18
    );
    ensure_can_prove(inputs.balance, threshold, debug);

    let sig = wallet_sig(&inputs.header_rlp, owner_key);
    // No challenge in legacy mode -> placeholder journal labels.
    let challenge_nonce = [0u8; 32];
    let agent_id: [u8; 32] = keccak256(b"por-demo-agent").into();
    let presentation = maybe_attest(&block_hex).await;
    let bundle = prove_block(&inputs, &sig, threshold, chain_id, debug, &challenge_nonce, &agent_id, seg_po2, presentation);

    File::create("proof.json").unwrap()
        .write_all(serde_json::to_string_pretty(&bundle).unwrap().as_bytes()).unwrap();
    println!("wrote proof.json");
}
