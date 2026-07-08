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

use host::{attest, verify};
use por_types::{chain_spec, resolve_chain, Challenge, Response, RESPONSE_VERSION};

const ADDR: &str = "0x00000000219ab540356cBB839Cbe05303d7705Fa"; // beacon deposit contract (mainnet DEMO)

fn rpc(method: &str, params: Value, rpc_url: &str) -> Value {
    let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":method,"params":params}).to_string();
    // Public/free-tier RPCs (esp. L2 endpoints) return transient errors -- rate limits (code
    // 15/30), routing hiccups (code 19). Retry with linear backoff before giving up.
    let mut last = String::new();
    for attempt in 0u64..6 {
        let out = Command::new("curl")
            .args(["-s", "-m", "30", "-X", "POST", "-H", "content-type: application/json",
                   "-H", "accept-encoding: identity", "-H", "user-agent: por/0.1",
                   "--data", &body, rpc_url])
            .output().expect("curl");
        match serde_json::from_slice::<Value>(&out.stdout) {
            Ok(resp) => {
                if let Some(r) = resp.get("result") {
                    return r.clone();
                }
                last = resp.get("error").map(|e| e.to_string())
                    .unwrap_or_else(|| String::from_utf8_lossy(&out.stdout).to_string());
            }
            Err(_) => last = String::from_utf8_lossy(&out.stdout).to_string(),
        }
        eprintln!("    rpc {method} attempt {} failed ({last}); retrying ...", attempt + 1);
        std::thread::sleep(std::time::Duration::from_millis(1000 * (attempt + 1)));
    }
    panic!("no result from {rpc_url} for {method} after retries: {last}");
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

// Normalize a 65-byte EIP-191 wallet signature (`0x` r‖s‖v). Browser wallets return v in
// {27,28} (occasionally {0,1}); the guest + verifier's k256 `RecoveryId::from_byte` needs
// {0,1}. Returns raw 65 bytes with a normalized recid.
fn norm_sig(hex_sig: &str) -> Vec<u8> {
    let mut v = hexb(hex_sig);
    assert_eq!(v.len(), 65, "signature must be 65 bytes r||s||v, got {}", v.len());
    if v[64] >= 27 {
        v[64] -= 27;
    }
    v
}

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
// The header (debug_getRawHeader, needs no state) comes from `header_url` (the canonical drpc
// host that the attestation also uses); the account proof (eth_getProof, needs ARCHIVE state
// for the multi-day window) comes from `proof_url`, which may be a different archive endpoint.
fn fetch_block(block_hex: &str, addr_hex: &str, header_url: &str, proof_url: &str) -> BlockInputs {
    let header_rlp = hexb(rpc("debug_getRawHeader", serde_json::json!([block_hex]), header_url).as_str().unwrap());
    let proof = rpc("eth_getProof", serde_json::json!([addr_hex, Vec::<String>::new(), block_hex]), proof_url);
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
    // Marketplace binding: the numeric ERC-721 token id + the private per-agent secret (its
    // keccak256 is the set-once on-chain commitment). Both are derived per-agent by the caller
    // (from the challenge agent_id + an owner signature); 0 / zero-secret is inert (demo/legacy).
    agent_token_id: u64,
    agent_secret: &[u8; 32],
    seg_po2: u32,
    presentation_b64: Option<String>,
) -> Value {
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
        .write(agent_secret).unwrap()    // private agent secret (identity binding)
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
// `rpc_host` is the chain's attested server name -- the verifier binds it to the chain_id.
async fn maybe_attest(block_hex: &str, rpc_host: &str) -> Option<String> {
    match std::env::var("NOTARY_ADDR") {
        Ok(addr) => {
            println!("    attesting debug_getRawHeader({block_hex}) via notary {addr} -> {rpc_host} ...");
            let (bytes, stats) = attest::attest_header(&addr, rpc_host, block_hex)
                .await
                .expect("TLSNotary attestation failed");
            println!(
                "    attestation OK: {} byte presentation ({:.1} MB up / {:.1} MB down to notary)",
                bytes.len(),
                stats.up_bytes as f64 / 1e6,
                stats.down_bytes as f64 / 1e6
            );
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

// --- per-agent marketplace identity (see por_types for the derivation contract) -----------
// The guest commits `agent_token_id` (numeric ERC-721 id) + `identity = keccak256(agent_secret)`;
// the gateway keys a set-once commitment by the token id and requires the proof to present the
// matching identity. We derive both PER AGENT so no operator/human sets POR_AGENT_TOKEN_ID /
// POR_AGENT_SECRET by hand -- though both remain honored as explicit overrides (e.g. an agent
// already registered under an arbitrary secret).

/// Numeric token id: `POR_AGENT_TOKEN_ID` override, else parsed from the challenge `agent_id`.
fn resolve_token_id(agent_id_str: &str) -> u64 {
    if let Ok(v) = std::env::var("POR_AGENT_TOKEN_ID") {
        if let Ok(n) = v.trim().parse::<u64>() {
            return n;
        }
    }
    por_types::parse_token_id(agent_id_str)
}

/// The owner signing key used to derive the identity secret: `POR_OWNER_KEY`, else the wallet
/// key (`POR_PRIVATE_KEY`) -- same precedence as [`owner_sign`], so identity is tied to the
/// agent's registry owner.
fn owner_identity_key(fallback: &Option<SigningKey>) -> Option<SigningKey> {
    if let Ok(k) = std::env::var("POR_OWNER_KEY") {
        return Some(SigningKey::from_slice(&hexb(&k)).expect("POR_OWNER_KEY must be 32-byte hex"));
    }
    fallback.clone()
}

/// Deterministically derive the agent secret by signing [`por_types::identity_message`] with the
/// owner key (EIP-191, RFC-6979 -- reproduces the same secret as the browser wallet would).
fn identity_secret_from_key(sk: &SigningKey, token_id: u64) -> [u8; 32] {
    let digest = por_types::eip191_digest(por_types::identity_message(token_id).as_bytes());
    let (sig, _recid) = sk.sign_prehash_recoverable(&digest).unwrap();
    por_types::secret_from_identity_sig(sig.to_bytes().as_slice())
}

/// Parse a 32-byte `POR_AGENT_SECRET` override, if set.
fn secret_override() -> Option<[u8; 32]> {
    std::env::var("POR_AGENT_SECRET")
        .ok()
        .map(|h| hexb(&h).try_into().expect("POR_AGENT_SECRET must be 32-byte hex"))
}

/// CLI-side secret (connected/file/legacy modes have the owner key): override, else derived from
/// the owner key, else zero (demo/no key -- inert, never recorded).
fn resolve_secret_cli(owner_key: &Option<SigningKey>, token_id: u64) -> [u8; 32] {
    if let Some(s) = secret_override() {
        return s;
    }
    match owner_identity_key(owner_key) {
        Some(sk) => identity_secret_from_key(&sk, token_id),
        None => [0u8; 32],
    }
}

/// Browser-side secret (`--finalize`), highest precedence first: a per-request custom secret
/// supplied in the UI (carried in sigs.json), then the `POR_AGENT_SECRET` env override, then
/// derived from the wallet's identity signature, else zero (with a warning -- the proof still
/// verifies but recordValidation won't match a commitment).
fn resolve_secret_from_sig(custom_secret: Option<&str>, identity_sig: Option<&str>) -> [u8; 32] {
    if let Some(h) = custom_secret.filter(|s| !s.trim().is_empty()) {
        return hexb(h)
            .try_into()
            .expect("agent_secret (custom) must be 32-byte hex");
    }
    if let Some(s) = secret_override() {
        return s;
    }
    match identity_sig {
        Some(s) => por_types::secret_from_identity_sig(&hexb(s)),
        None => {
            eprintln!(
                "WARNING: no identity signature, custom secret, or POR_AGENT_SECRET -> zero identity \
                 binding; the proof will verify but recordValidation on the marketplace won't match a commitment"
            );
            [0u8; 32]
        }
    }
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
        // DEMO (no key): a funded contract to prove against. Default is the mainnet beacon
        // deposit contract; override per chain with POR_DEMO_ADDR (the default holds nothing
        // off mainnet, so the guest would correctly refuse the threshold there).
        None => std::env::var("POR_DEMO_ADDR").unwrap_or_else(|_| ADDR.to_string()),
    };
    let debug = owner_key.is_none();
    // Which chain to prove on. In challenge/connected modes the verifier's challenge is
    // authoritative (ch.chain_id -- and the verifier applies POR_TESTNET when it resolves the
    // selector we send). This is the connected request's SELECTOR and the legacy chain. Default 1.
    let req_chain_id: u32 = arg_value("--chain-id")
        .or_else(|| std::env::var("POR_CHAIN_ID").ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(1);
    // Legacy mode picks its own chain (no verifier), so it honors POR_TESTNET here.
    let testnet = std::env::var("POR_TESTNET").is_ok();
    let seg_po2: u32 = std::env::var("POR_SEGMENT_PO2").ok().and_then(|s| s.parse().ok()).unwrap_or(20);

    // Browser-wallet mode (the private key never touches the prover). Two phases:
    //   --prepare  --challenge <ch> --address <0x..> [--out prepare.json]
    //   --finalize --prepared prepare.json --sigs sigs.json [--out response.json]
    // The wallet signs the messages listed in prepare.json between the two calls.
    if std::env::args().any(|a| a == "--prepare") {
        let ch = load_challenge().expect("--prepare requires --challenge <file> (or POR_CHALLENGE)");
        let address = arg_value("--address").expect("--prepare requires --address <0x..>");
        let out = arg_value("--out").unwrap_or_else(|| "prepare.json".into());
        run_prepare(ch, &address, &out).await;
        return;
    }
    if std::env::args().any(|a| a == "--finalize") {
        let prepared = arg_value("--prepared").unwrap_or_else(|| "prepare.json".into());
        let sigs = arg_value("--sigs").expect("--finalize requires --sigs <file>");
        let out = arg_value("--out").unwrap_or_else(|| "response.json".into());
        run_finalize(&prepared, &sigs, &out, seg_po2).await;
        return;
    }

    match connected_target() {
        // Connected: request challenge -> prove -> submit -> verdict, against a live verifier.
        // We send the raw selector; the verifier (its POR_TESTNET) resolves it to the effective chain.
        Some((url, agent_id, threshold)) => {
            run_connected(url, agent_id, threshold, req_chain_id, &owner_key, &addr_hex, debug, seg_po2).await
        }
        None => match load_challenge() {
            // File: prove a challenge from --challenge/POR_CHALLENGE -> response.json.
            Some(ch) => run_challenge(ch, &owner_key, &addr_hex, debug, seg_po2).await,
            // Legacy: single finalized block -> proof.json.
            None => run_legacy_single(req_chain_id, testnet, &owner_key, &addr_hex, debug, seg_po2).await,
        },
    }
}

// Prove every challenged block + sign the challenge -> the Response to submit. The chain is
// the verifier's (ch.chain_id) -- the prover proves whatever chain the challenge pinned.
async fn prove_challenge(
    ch: Challenge,
    owner_key: &Option<SigningKey>,
    addr_hex: &str,
    debug: bool,
    seg_po2: u32,
) -> Response {
    let chain_id = ch.chain_id;
    let spec = chain_spec(chain_id)
        .unwrap_or_else(|| panic!("challenge names unsupported chain_id {chain_id}"));
    let header_url = verify::header_rpc_url(chain_id).expect("header rpc url");
    let proof_url = verify::proof_rpc_url(chain_id).expect("proof rpc url");
    let threshold = ch.threshold_u128().expect("challenge threshold");
    let challenge_nonce = ch.nonce_bytes().expect("challenge nonce");
    let agent_id = ch.agent_id_hash();
    let mode = if debug { "DEMO (debug=true)" } else { "OWNERSHIP (debug=false)" };
    println!(
        "challenge {}: agent {}, chain {}({chain_id}), threshold {} (native), blocks {:?}, mode {mode}, wallet {addr_hex}",
        ch.challenge_id, ch.agent_id, spec.name, threshold as f64 / 1e18, ch.blocks
    );
    println!("  header <- {header_url}   proof <- {proof_url}");

    // Per-agent marketplace binding (identical across the 3 blocks). Inert in DEMO (no key):
    // a demo run shouldn't bind a real agent's commitment, so token id + secret stay 0.
    let token_id = if debug { 0 } else { resolve_token_id(&ch.agent_id) };
    let agent_secret = if debug { [0u8; 32] } else { resolve_secret_cli(owner_key, token_id) };

    let mut bundles = Vec::with_capacity(ch.blocks.len());
    let t_all = Instant::now();
    for (i, &blk) in ch.blocks.iter().enumerate() {
        let block_hex = format!("0x{blk:x}");
        println!("[block {}/{}] {block_hex} (#{blk})", i + 1, ch.blocks.len());
        let inputs = fetch_block(&block_hex, addr_hex, &header_url, &proof_url);
        ensure_can_prove(inputs.balance, threshold, debug);
        let sig = wallet_sig(&inputs.header_rlp, owner_key);
        let presentation = maybe_attest(&block_hex, spec.rpc_host).await;
        let bundle = prove_block(&inputs, &sig, threshold, chain_id, debug, &challenge_nonce, &agent_id, token_id, &agent_secret, seg_po2, presentation);
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
    seg_po2: u32,
) {
    let response = prove_challenge(ch, owner_key, addr_hex, debug, seg_po2).await;
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
    req_chain_id: u32,
    owner_key: &Option<SigningKey>,
    addr_hex: &str,
    debug: bool,
    seg_po2: u32,
) {
    let base = verifier_url.trim_end_matches('/').to_string();
    println!("requesting challenge from {base} for agent {agent_id} (chain {req_chain_id}, threshold {threshold} wei) ...");
    let req = serde_json::json!({ "agent_id": agent_id, "threshold": threshold, "chain_id": req_chain_id }).to_string();
    let raw = http_post_json(&format!("{base}/v1/challenges"), &req);
    if raw.get("challenge_id").is_none() {
        eprintln!("verifier did not issue a challenge: {raw}");
        std::process::exit(1);
    }
    let ch: Challenge = serde_json::from_value(raw).expect("parse challenge from verifier");
    let cid = ch.challenge_id.clone();

    let response = prove_challenge(ch, owner_key, addr_hex, debug, seg_po2).await;
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
    selector: u32,
    testnet: bool,
    owner_key: &Option<SigningKey>,
    addr_hex: &str,
    debug: bool,
    seg_po2: u32,
) {
    // Resolve the selector under POR_TESTNET (mainnet id -> its paired testnet); the effective
    // real chain_id is what gets fetched, attested, and committed.
    let spec = resolve_chain(selector, testnet).unwrap_or_else(|e| panic!("{e}"));
    let chain_id = spec.chain_id;
    let header_url = verify::header_rpc_url(chain_id).expect("header rpc url");
    let proof_url = verify::proof_rpc_url(chain_id).expect("proof rpc url");
    // Finalized head is a cheap recent query -> the header endpoint.
    let fin = rpc("eth_getBlockByNumber", serde_json::json!(["finalized", false]), &header_url);
    let block_hex = fin["number"].as_str().unwrap().to_string();
    let block_num = u64::from_str_radix(block_hex.trim_start_matches("0x"), 16).unwrap();
    let threshold: u128 = std::env::var("POR_THRESHOLD").ok()
        .and_then(|s| s.parse().ok()).unwrap_or(1_000_000_000_000_000_000); // 1 ETH

    let inputs = fetch_block(&block_hex, addr_hex, &header_url, &proof_url);
    let mode = if debug { "DEMO (debug=true, ownership skipped)" } else { "OWNERSHIP (debug=false)" };
    println!(
        "legacy single-block mode: {mode}\nchain {}({chain_id}), address {addr_hex}, block {block_num}, depth {}, balance {} (native), threshold {}",
        spec.name, inputs.account_proof.len(), inputs.balance as f64 / 1e18, threshold as f64 / 1e18
    );
    ensure_can_prove(inputs.balance, threshold, debug);

    let sig = wallet_sig(&inputs.header_rlp, owner_key);
    // No challenge in legacy mode -> placeholder journal labels. Marketplace binding comes only
    // from explicit env overrides here (legacy has no marketplace agent id to derive from).
    let challenge_nonce = [0u8; 32];
    let agent_id: [u8; 32] = keccak256(b"por-demo-agent").into();
    let token_id = resolve_token_id("");
    let agent_secret = resolve_secret_cli(owner_key, token_id);
    let presentation = maybe_attest(&block_hex, spec.rpc_host).await;
    let bundle = prove_block(&inputs, &sig, threshold, chain_id, debug, &challenge_nonce, &agent_id, token_id, &agent_secret, seg_po2, presentation);

    File::create("proof.json").unwrap()
        .write_all(serde_json::to_string_pretty(&bundle).unwrap().as_bytes()).unwrap();
    println!("wrote proof.json");
}

// --- Browser-wallet mode: sign in the wallet, prove on the machine. Split into two phases
//     so the wallet's private key never touches the prover -- the browser signs the messages
//     emitted by `--prepare` and hands them back to `--finalize`. Always OWNERSHIP (debug=false).

// PHASE 1: fetch the account proof + raw header for `address_hex` at each challenged block,
// check balance >= T, and write prepare.json -- the witnesses plus the exact 32-byte EIP-191
// messages the wallet must personal_sign (each block_hash + the challenge prehash). No key,
// no proving. The messages are derived here (in Rust, from por-types) so the canonical
// challenge serialization stays single-source and can't drift in the browser.
async fn run_prepare(ch: Challenge, address_hex: &str, out: &str) {
    let chain_id = ch.chain_id;
    let spec = chain_spec(chain_id).unwrap_or_else(|| panic!("challenge names unsupported chain_id {chain_id}"));
    let header_url = verify::header_rpc_url(chain_id).expect("header rpc url");
    let proof_url = verify::proof_rpc_url(chain_id).expect("proof rpc url");
    let threshold = ch.threshold_u128().expect("challenge threshold");
    let mut address = [0u8; 20];
    address.copy_from_slice(&hexb(address_hex));
    let addr_norm = format!("0x{}", hex::encode(address));
    println!(
        "prepare: agent {}, chain {}({chain_id}), threshold {} (native), wallet {addr_norm}, blocks {:?}",
        ch.agent_id, spec.name, threshold as f64 / 1e18, ch.blocks
    );

    let mut blocks_json = Vec::with_capacity(ch.blocks.len());
    let mut block_hashes = Vec::with_capacity(ch.blocks.len());
    for &blk in ch.blocks.iter() {
        let block_hex = format!("0x{blk:x}");
        let inputs = fetch_block(&block_hex, &addr_norm, &header_url, &proof_url);
        ensure_can_prove(inputs.balance, threshold, false);
        let bh = keccak256(&inputs.header_rlp);
        let bh_hex = format!("0x{}", hex::encode(bh));
        println!("  block #{blk}: balance ok, block_hash {bh_hex}");
        block_hashes.push(Value::String(bh_hex.clone()));
        blocks_json.push(serde_json::json!({
            "block_number": blk,
            "block_hash": bh_hex,
            "header_rlp": format!("0x{}", hex::encode(&inputs.header_rlp)),
            "account_proof": inputs.account_proof.iter()
                .map(|n| Value::String(format!("0x{}", hex::encode(n)))).collect::<Vec<_>>(),
            "nonce": inputs.nonce,
            "balance": format!("0x{:x}", inputs.balance),
            "storage_hash": format!("0x{}", hex::encode(inputs.storage_hash)),
            "code_hash": format!("0x{}", hex::encode(inputs.code_hash)),
        }));
    }
    let challenge_prehash = keccak256(&ch.canonical_bytes().expect("canonical bytes"));
    // The wallet also signs a per-agent identity message; its signature derives the private
    // secret whose keccak256 is the (set-once) on-chain commitment. Text message (personal_sign),
    // not a raw 32-byte blob, so the wallet shows the human what they're binding.
    let token_id = resolve_token_id(&ch.agent_id);
    let identity_message = por_types::identity_message(token_id);
    let prepared = serde_json::json!({
        "version": "por-prepare-v1",
        "challenge": serde_json::to_value(&ch).unwrap(),
        "address": addr_norm,
        "debug": false,
        "agent_token_id": token_id,
        "to_sign": {
            "scheme": "EIP-191 personal_sign: each block_hash + challenge_prehash as raw 32 bytes; identity_message as text",
            "block_hashes": block_hashes,
            "challenge_prehash": format!("0x{}", hex::encode(challenge_prehash)),
            "identity_message": identity_message,
        },
        "blocks": blocks_json,
    });
    File::create(out).unwrap()
        .write_all(serde_json::to_string_pretty(&prepared).unwrap().as_bytes()).unwrap();
    println!("wrote {out}: {} block hash(es) + the challenge prehash + the identity message to sign", ch.blocks.len());
}

// PHASE 2: take the wallet's signatures (sigs.json = {block_sigs:[...], owner_sig}), verify
// each block signature recovers to the wallet address exactly as the guest will (fail fast,
// before the slow prove), then attest + prove each block and assemble response.json. The
// wallet's v (27/28) is normalized to the {0,1} recid the guest/verifier expect.
async fn run_finalize(prepared_path: &str, sigs_path: &str, out: &str, seg_po2: u32) {
    let pv: Value = serde_json::from_str(&std::fs::read_to_string(prepared_path).expect("read prepared"))
        .expect("parse prepared json");
    let sv: Value = serde_json::from_str(&std::fs::read_to_string(sigs_path).expect("read sigs"))
        .expect("parse sigs json");
    let ch: Challenge = serde_json::from_value(pv["challenge"].clone()).expect("challenge in prepared");
    let chain_id = ch.chain_id;
    let spec = chain_spec(chain_id).unwrap_or_else(|| panic!("challenge names unsupported chain_id {chain_id}"));
    let threshold = ch.threshold_u128().expect("challenge threshold");
    let challenge_nonce = ch.nonce_bytes().expect("challenge nonce");
    let agent_id = ch.agent_id_hash();
    let debug = false;

    let blocks = pv["blocks"].as_array().expect("blocks array in prepared");
    let block_sigs = sv["block_sigs"].as_array().expect("block_sigs array in sigs");
    assert_eq!(block_sigs.len(), blocks.len(), "block_sigs ({}) != blocks ({})", block_sigs.len(), blocks.len());
    let mut address = [0u8; 20];
    address.copy_from_slice(&hexb(pv["address"].as_str().expect("address in prepared")));

    // Per-agent marketplace binding: token id from the challenge agent_id, secret derived from
    // the wallet's identity signature (or POR_AGENT_SECRET override). The key never touches us.
    let token_id = resolve_token_id(&ch.agent_id);
    let agent_secret = resolve_secret_from_sig(sv["agent_secret"].as_str(), sv["identity_sig"].as_str());

    let t_all = Instant::now();
    let mut bundles = Vec::with_capacity(blocks.len());
    for (i, b) in blocks.iter().enumerate() {
        let inputs = BlockInputs {
            header_rlp: hexb(b["header_rlp"].as_str().unwrap()),
            account_proof: b["account_proof"].as_array().unwrap().iter()
                .map(|n| hexb(n.as_str().unwrap())).collect(),
            address,
            nonce: b["nonce"].as_u64().unwrap(),
            balance: hu128(b["balance"].as_str().unwrap()),
            storage_hash: h32(b["storage_hash"].as_str().unwrap()),
            code_hash: h32(b["code_hash"].as_str().unwrap()),
        };
        let sig = norm_sig(block_sigs[i].as_str().expect("block sig hex"));

        // Preflight: the wallet's ownership signature must recover to the wallet address,
        // exactly as the guest checks it -- catch a wrong/bad signature before burning minutes
        // on a proof the guest would reject.
        let block_hash = keccak256(&inputs.header_rlp);
        let mut m = Vec::with_capacity(28 + 32);
        m.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
        m.extend_from_slice(block_hash.as_slice());
        let prehash = keccak256(&m);
        let rec = verify::recover_address_from_prehash(&prehash.0, &sig)
            .unwrap_or_else(|e| panic!("block {i} signature invalid: {e}"));
        assert_eq!(rec, address, "block {i} signature recovers 0x{} != wallet 0x{}",
            hex::encode(rec), hex::encode(address));

        let block_hex = format!("0x{:x}", b["block_number"].as_u64().unwrap());
        println!("[block {}/{}] {block_hex}: signature ok, attesting + proving ...", i + 1, blocks.len());
        let presentation = maybe_attest(&block_hex, spec.rpc_host).await;
        let bundle = prove_block(&inputs, &sig, threshold, chain_id, debug, &challenge_nonce, &agent_id, token_id, &agent_secret, seg_po2, presentation);
        bundles.push(bundle);
    }

    let owner_sig = format!("0x{}", hex::encode(norm_sig(sv["owner_sig"].as_str().expect("owner_sig in sigs"))));
    let response = Response { version: RESPONSE_VERSION.into(), challenge: ch, owner_sig, bundles };
    File::create(out).unwrap()
        .write_all(serde_json::to_string_pretty(&response).unwrap().as_bytes()).unwrap();
    println!("proved {} block(s) in {:?}; wrote {out}", response.bundles.len(), t_all.elapsed());
}
