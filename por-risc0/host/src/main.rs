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

// Private per-wallet state for one block (minus the ownership sig, produced separately).
struct WalletWitness {
    address: [u8; 20],
    nonce: u64,
    balance: u128,
    storage_hash: [u8; 32],
    code_hash: [u8; 32],
    account_proof: Vec<Vec<u8>>,
}

// Witness for a single block: the shared header + one or more wallets proven against it.
struct BlockInputs {
    header_rlp: Vec<u8>,
    wallets: Vec<WalletWitness>,
}

impl BlockInputs {
    // Combined balance across all wallets (saturating: the in-circuit sum uses U256 and is
    // authoritative, this is only the pre-flight check).
    fn total_balance(&self) -> u128 {
        self.wallets.iter().fold(0u128, |a, w| a.saturating_add(w.balance))
    }
}

// A set of reserves wallets to prove in one shot. `addrs` is sorted ascending + distinct (the
// order the guest requires so a wallet can't be double-counted). In OWNERSHIP mode `keys` is
// aligned 1:1 with `addrs` (each key signs its wallet); in DEMO mode `keys` is empty and
// `debug` is true (ownership skipped).
struct WalletSet {
    addrs: Vec<[u8; 20]>,
    keys: Vec<SigningKey>,
    debug: bool,
}

fn parse_addr20(s: &str) -> [u8; 20] {
    let v = hexb(s);
    assert_eq!(v.len(), 20, "address must be 20 bytes, got {}: {s}", v.len());
    let mut a = [0u8; 20];
    a.copy_from_slice(&v);
    a
}

fn addr_of_key(sk: &SigningKey) -> [u8; 20] {
    let enc = sk.verifying_key().to_encoded_point(false);
    keccak256(&enc.as_bytes()[1..65])[12..32].try_into().unwrap()
}

// Build the reserves-wallet set for connected/file/legacy modes. `POR_PRIVATE_KEY` may be a
// COMMA-SEPARATED list of 32-byte keys (OWNERSHIP: the combined balance of their EOAs is
// proven); unset => DEMO (comma-separated `POR_DEMO_ADDR`, else the default beacon contract).
// Wallets are sorted ascending + de-duplicated to match the guest's distinct/ascending rule.
fn build_wallet_set() -> WalletSet {
    if let Ok(env) = std::env::var("POR_PRIVATE_KEY") {
        let mut pairs: Vec<([u8; 20], SigningKey)> = env
            .split(',')
            .map(str::trim)
            .filter(|k| !k.is_empty())
            .map(|k| {
                let sk = SigningKey::from_slice(&hexb(k))
                    .expect("POR_PRIVATE_KEY entries must be 32-byte hex");
                (addr_of_key(&sk), sk)
            })
            .collect();
        assert!(!pairs.is_empty(), "POR_PRIVATE_KEY set but contained no keys");
        pairs.sort_by(|a, b| a.0.cmp(&b.0));
        for w in pairs.windows(2) {
            assert_ne!(w[0].0, w[1].0, "duplicate wallet 0x{} in POR_PRIVATE_KEY", hex::encode(w[0].0));
        }
        let (addrs, keys): (Vec<_>, Vec<_>) = pairs.into_iter().unzip();
        WalletSet { addrs, keys, debug: false }
    } else {
        let raw = std::env::var("POR_DEMO_ADDR").unwrap_or_else(|_| ADDR.to_string());
        let mut addrs: Vec<[u8; 20]> = raw
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(parse_addr20)
            .collect();
        assert!(!addrs.is_empty(), "no DEMO address");
        addrs.sort();
        addrs.dedup();
        WalletSet { addrs, keys: Vec::new(), debug: true }
    }
}

impl WalletSet {
    fn addr_hexes(&self) -> Vec<String> {
        self.addrs.iter().map(|a| format!("0x{}", hex::encode(a))).collect()
    }
}

// Fetch the raw header once + one account proof per address at `block_hex`. The header
// (debug_getRawHeader, needs no state) comes from `header_url` (the canonical drpc host that
// the attestation also uses); each account proof (eth_getProof, needs ARCHIVE state for the
// multi-day window) comes from `proof_url`, which may be a different archive endpoint.
fn fetch_block(block_hex: &str, addrs: &[[u8; 20]], header_url: &str, proof_url: &str) -> BlockInputs {
    let header_rlp = hexb(rpc("debug_getRawHeader", serde_json::json!([block_hex]), header_url).as_str().unwrap());
    let wallets = addrs
        .iter()
        .map(|a| {
            let addr_hex = format!("0x{}", hex::encode(a));
            let proof = rpc("eth_getProof", serde_json::json!([addr_hex, Vec::<String>::new(), block_hex]), proof_url);
            let nonce = u64::from_str_radix(proof["nonce"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
            let balance = hu128(proof["balance"].as_str().unwrap());
            let storage_hash = h32(proof["storageHash"].as_str().unwrap());
            let code_hash = h32(proof["codeHash"].as_str().unwrap());
            let account_proof: Vec<Vec<u8>> = proof["accountProof"].as_array().unwrap()
                .iter().map(|n| hexb(n.as_str().unwrap())).collect();
            WalletWitness { address: *a, nonce, balance, storage_hash, code_hash, account_proof }
        })
        .collect();
    BlockInputs { header_rlp, wallets }
}

// Ownership signature over EIP-191(block_hash) with one wallet key.
fn sign_block(header_rlp: &[u8], sk: &SigningKey) -> Vec<u8> {
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

// One ownership signature per wallet, aligned with `ws.addrs`. Empty sigs in DEMO mode (the
// guest reads a sig per wallet but ignores it when debug=true).
fn block_sigs(header_rlp: &[u8], ws: &WalletSet) -> Vec<Vec<u8>> {
    if ws.debug {
        return vec![Vec::new(); ws.addrs.len()];
    }
    ws.keys.iter().map(|sk| sign_block(header_rlp, sk)).collect()
}

// Refuse impossible proofs cleanly, before the (slow) attestation + proving. If the wallets'
// COMBINED balance can't meet the threshold -- including accounts that don't exist (balance 0,
// MPT *exclusion* proofs) -- the guest correctly refuses; without this that surfaces as an ugly
// panic + backtrace through prove()'s unwrap. Exit with a clear message instead.
fn ensure_can_prove(total: u128, threshold: u128, debug: bool, n_wallets: usize) {
    if !debug && total < threshold {
        eprintln!(
            "\ncannot prove reserves: combined balance {total} wei across {n_wallets} wallet(s) < threshold {threshold} wei{}",
            if total == 0 {
                " (the accounts do not exist / hold nothing at this block)"
            } else {
                ""
            }
        );
        eprintln!(
            "hint: include wallets whose COMBINED native balance stays above the threshold across \
             the whole challenge window, or run DEMO mode (unset POR_PRIVATE_KEY)."
        );
        std::process::exit(1);
    }
}

// Prove one block -> a proof.json-shaped bundle (optionally carrying a TLSNotary presentation).
// `sigs` is one ownership signature per wallet, aligned with `inputs.wallets` (empty entries
// in demo mode).
#[allow(clippy::too_many_arguments)]
fn prove_block(
    inputs: &BlockInputs,
    sigs: &[Vec<u8>],
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
    assert_eq!(sigs.len(), inputs.wallets.len(), "sig count {} != wallet count {}", sigs.len(), inputs.wallets.len());
    // The guest reads: header, n_wallets, then per wallet {address, nonce, balance,
    // storage_hash, code_hash, account_proof, sig}, then the public fields.
    let mut builder = ExecutorEnv::builder();
    builder.segment_limit_po2(seg_po2);
    builder.write(&inputs.header_rlp).unwrap();
    builder.write(&(inputs.wallets.len() as u32)).unwrap();
    for (w, sig) in inputs.wallets.iter().zip(sigs) {
        builder.write(&w.address).unwrap();
        builder.write(&w.nonce).unwrap();
        builder.write(&w.balance).unwrap();
        builder.write(&w.storage_hash).unwrap();
        builder.write(&w.code_hash).unwrap();
        builder.write(&w.account_proof).unwrap();
        builder.write(sig).unwrap(); // ownership sig (empty in demo mode)
    }
    builder.write(&threshold).unwrap();
    builder.write(&chain_id).unwrap();
    builder.write(&debug).unwrap();
    builder.write(challenge_nonce).unwrap();
    builder.write(agent_id).unwrap();
    builder.write(&agent_token_id).unwrap(); // marketplace ERC-721 token id
    builder.write(agent_secret).unwrap(); // private agent secret (identity binding)
    let env = builder.build().unwrap();

    let t = Instant::now();
    // Backstop: if the guest still refuses here (e.g. combined balance below threshold, or an
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
    // Privacy: no wallet's address, and no wallet's NONZERO balance, may appear in the journal.
    // (balance==0 serializes to zero bytes that also appear legitimately -> only a NONZERO
    // balance showing up is a real leak.)
    let leaked = inputs.wallets.iter().any(|w| {
        (w.balance != 0 && j.windows(16).any(|x| x == w.balance.to_le_bytes()))
            || j.windows(20).any(|x| x == w.address)
    });
    assert!(!leaked, "PRIVACY FAILURE");
    println!("    proved in {:?}; journal {} bytes; {} wallet(s); addr+balance hidden", t.elapsed(), j.len(), inputs.wallets.len());

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

// --- marketplace identity preflight ----------------------------------------
// The ValidationGateway binds a SET-ONCE commitment per (agentId, proofType). A proof whose
// committed identity doesn't match a previously-registered commitment makes recordValidation
// revert "Identity binding mismatch" -- but only AFTER minutes of proving. Check it up front.
// The prover reads ONE fixed env contract (POR_AGENT_SECRET etc.); it does not guess aliases --
// mapping arbitrary inputs onto these names is the calling agent's job (see AGENT_GUIDE.md).

/// The set-once commitment this proof will present: `reverse(keccak256(agent_secret))` -- the
/// gateway's `_extractField(pubs, identityBindingOffset, 32, littleEndian)` cast to bytes32
/// (see `marketplace_offsets`). An all-zero secret means no binding (demo/legacy).
fn expected_commitment(agent_secret: &[u8; 32]) -> Option<[u8; 32]> {
    if agent_secret == &[0u8; 32] {
        return None;
    }
    let mut c: [u8; 32] = keccak256(agent_secret).into();
    c.reverse(); // LE journal integer -> BE bytes32, matching the gateway cast
    Some(c)
}

/// Best-effort read of `agentCommitments(agentId, proofType)` on the marketplace chain (Base
/// Sepolia). Returns None on ANY RPC/decode error -- the caller treats "unknown" as "don't
/// block". Gateway/RPC/proofType are overridable but default to the live deployment.
fn read_agent_commitment(token_id: u64, proof_type: &str) -> Option<[u8; 32]> {
    let gateway = std::env::var("POR_GATEWAY")
        .unwrap_or_else(|_| "0xbbdcb0C9C3B9ce60555fdF50cFB99802E7c33920".into());
    let rpc_url = std::env::var("POR_MARKETPLACE_RPC_URL")
        .unwrap_or_else(|_| "https://sepolia.base.org".into());
    // ABI-encode agentCommitments(uint256,string): selector ++ agentId ++ offset(0x40) ++ len ++ str
    let mut data = Vec::new();
    data.extend_from_slice(&keccak256(b"agentCommitments(uint256,string)")[..4]);
    let mut w = [0u8; 32];
    w[24..].copy_from_slice(&token_id.to_be_bytes());
    data.extend_from_slice(&w); // agentId
    let mut off = [0u8; 32];
    off[31] = 0x40;
    data.extend_from_slice(&off); // offset to the string arg
    let pt = proof_type.as_bytes();
    let mut len = [0u8; 32];
    len[24..].copy_from_slice(&(pt.len() as u64).to_be_bytes());
    data.extend_from_slice(&len);
    let mut padded = pt.to_vec();
    while padded.len() % 32 != 0 {
        padded.push(0);
    }
    data.extend_from_slice(&padded);

    let body = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_call",
        "params":[{"to":gateway,"data":format!("0x{}",hex::encode(&data))},"latest"]})
    .to_string();
    let out = Command::new("curl")
        .args(["-s", "-m", "15", "-X", "POST", "-H", "content-type: application/json",
               "-H", "accept-encoding: identity", "--data", &body, &rpc_url])
        .output()
        .ok()?;
    let resp: Value = serde_json::from_slice(&out.stdout).ok()?;
    let hexstr = resp.get("result")?.as_str()?;
    let bytes = hexb(hexstr);
    (bytes.len() == 32).then(|| h32(hexstr))
}

/// Before the (slow) prove, verify this run's identity will satisfy the marketplace's set-once
/// binding, and abort on a GUARANTEED mismatch (saves minutes of proving a bundle that
/// recordValidation would reject). Best-effort: no-op for demo/zero-secret, and never blocks on
/// an unreachable gateway. Bypass entirely with POR_SKIP_IDENTITY_PRECHECK=1.
fn preflight_identity_binding(token_id: u64, agent_secret: &[u8; 32]) {
    if std::env::var("POR_SKIP_IDENTITY_PRECHECK").is_ok() {
        return;
    }
    if token_id == 0 {
        return; // demo / non-marketplace run
    }
    let Some(expected) = expected_commitment(agent_secret) else {
        eprintln!("identity: agent_secret is zero -> no marketplace binding (recordValidation will not \
                   match a commitment). Set POR_AGENT_SECRET if this agent is registered.");
        return;
    };
    let exp_hex = format!("0x{}", hex::encode(expected));
    let proof_type = std::env::var("POR_PROOF_TYPE").unwrap_or_else(|_| "proof-of-reserves".into());
    match read_agent_commitment(token_id, &proof_type) {
        None => eprintln!("identity preflight: could not read on-chain commitment (continuing) -> \
                           this proof will present {exp_hex}"),
        Some(z) if z == [0u8; 32] => println!(
            "identity preflight: agent {token_id} has no commitment yet -> it will be bound to \
             {exp_hex} on first recordValidation"
        ),
        Some(existing) if existing == expected => {
            println!("identity preflight OK: agent {token_id} commitment matches on-chain ({exp_hex})")
        }
        Some(existing) => {
            eprintln!();
            eprintln!("ERROR: marketplace identity binding mismatch -- aborting BEFORE the (slow) prove.");
            eprintln!("  agent {token_id} is already registered (SET-ONCE) with commitment:");
            eprintln!("    0x{}", hex::encode(existing));
            eprintln!("  but this run's agent_secret derives:");
            eprintln!("    {exp_hex}");
            eprintln!("  recordValidation would revert \"Identity binding mismatch\".");
            eprintln!("  Fix: set POR_AGENT_SECRET to the ORIGINAL 32-byte secret this agent was");
            eprintln!("       registered with (exact name -- the POR_ prefix is required; a bare");
            eprintln!("       AGENT_SECRET is ignored), or prove under a fresh, unregistered agent id.");
            eprintln!("  Bypass this check: POR_SKIP_IDENTITY_PRECHECK=1");
            std::process::exit(1);
        }
    }
}

// Sign the challenge digest with the owner EOA (POR_OWNER_KEY, falling back to the FIRST
// POR_PRIVATE_KEY entry -- the reserves-wallet key list is comma-separated).
fn owner_sign(ch: &Challenge) -> Option<String> {
    let key = std::env::var("POR_OWNER_KEY").ok().or_else(|| {
        std::env::var("POR_PRIVATE_KEY")
            .ok()
            .and_then(|s| s.split(',').map(str::trim).find(|k| !k.is_empty()).map(String::from))
    })?;
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

    // Browser-wallet mode (the private keys never touch the prover). Two phases:
    //   --prepare  --challenge <ch> --address <0x..>[,0x..] [--out prepare.json]
    //   --finalize --prepared prepare.json --sigs sigs.json [--out response.json]
    // The wallet(s) sign the messages listed in prepare.json between the two calls. `--address`
    // may be a comma-separated list -> the combined balance of those wallets is proven.
    if std::env::args().any(|a| a == "--prepare") {
        let ch = load_challenge().expect("--prepare requires --challenge <file> (or POR_CHALLENGE)");
        let addresses = arg_value("--address").expect("--prepare requires --address <0x..>[,0x..]");
        let out = arg_value("--out").unwrap_or_else(|| "prepare.json".into());
        run_prepare(ch, &addresses, &out).await;
        return;
    }
    if std::env::args().any(|a| a == "--finalize") {
        let prepared = arg_value("--prepared").unwrap_or_else(|| "prepare.json".into());
        let sigs = arg_value("--sigs").expect("--finalize requires --sigs <file>");
        let out = arg_value("--out").unwrap_or_else(|| "response.json".into());
        run_finalize(&prepared, &sigs, &out, seg_po2).await;
        return;
    }

    // Reserves wallets to prove: comma-separated POR_PRIVATE_KEY => OWNERSHIP (combined balance
    // of the EOAs, debug=false); unset => DEMO (POR_DEMO_ADDR list / beacon, debug=true).
    let wallets = build_wallet_set();
    // Owner/identity fallback key = the first reserves key (POR_OWNER_KEY still overrides).
    let first_key: Option<SigningKey> = wallets.keys.first().cloned();
    println!(
        "reserves wallets ({}): {} [{}]",
        wallets.addrs.len(),
        if wallets.debug { "DEMO" } else { "OWNERSHIP" },
        wallets.addr_hexes().join(", ")
    );

    match connected_target() {
        // Connected: request challenge -> prove -> submit -> verdict, against a live verifier.
        // We send the raw selector; the verifier (its POR_TESTNET) resolves it to the effective chain.
        Some((url, agent_id, threshold)) => {
            run_connected(url, agent_id, threshold, req_chain_id, &wallets, &first_key, seg_po2).await
        }
        None => match load_challenge() {
            // File: prove a challenge from --challenge/POR_CHALLENGE -> response.json.
            Some(ch) => run_challenge(ch, &wallets, &first_key, seg_po2).await,
            // Legacy: single finalized block -> proof.json.
            None => run_legacy_single(req_chain_id, testnet, &wallets, &first_key, seg_po2).await,
        },
    }
}

// Prove every challenged block + sign the challenge -> the Response to submit. The chain is
// the verifier's (ch.chain_id) -- the prover proves whatever chain the challenge pinned.
async fn prove_challenge(
    ch: Challenge,
    ws: &WalletSet,
    first_key: &Option<SigningKey>,
    seg_po2: u32,
) -> Response {
    let debug = ws.debug;
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
        "challenge {}: agent {}, chain {}({chain_id}), threshold {} (native), blocks {:?}, mode {mode}, {} wallet(s) {}",
        ch.challenge_id, ch.agent_id, spec.name, threshold as f64 / 1e18, ch.blocks,
        ws.addrs.len(), ws.addr_hexes().join(",")
    );
    println!("  header <- {header_url}   proof <- {proof_url}");

    // Per-agent marketplace binding (identical across the 3 blocks). Inert in DEMO (no key):
    // a demo run shouldn't bind a real agent's commitment, so token id + secret stay 0.
    let token_id = if debug { 0 } else { resolve_token_id(&ch.agent_id) };
    let agent_secret = if debug { [0u8; 32] } else { resolve_secret_cli(first_key, token_id) };
    preflight_identity_binding(token_id, &agent_secret);

    let mut bundles = Vec::with_capacity(ch.blocks.len());
    let t_all = Instant::now();
    for (i, &blk) in ch.blocks.iter().enumerate() {
        let block_hex = format!("0x{blk:x}");
        println!("[block {}/{}] {block_hex} (#{blk})", i + 1, ch.blocks.len());
        let inputs = fetch_block(&block_hex, &ws.addrs, &header_url, &proof_url);
        ensure_can_prove(inputs.total_balance(), threshold, debug, ws.addrs.len());
        let sigs = block_sigs(&inputs.header_rlp, ws);
        let presentation = maybe_attest(&block_hex, spec.rpc_host).await;
        let bundle = prove_block(&inputs, &sigs, threshold, chain_id, debug, &challenge_nonce, &agent_id, token_id, &agent_secret, seg_po2, presentation);
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
async fn run_challenge(ch: Challenge, ws: &WalletSet, first_key: &Option<SigningKey>, seg_po2: u32) {
    let response = prove_challenge(ch, ws, first_key, seg_po2).await;
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
    ws: &WalletSet,
    first_key: &Option<SigningKey>,
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

    let response = prove_challenge(ch, ws, first_key, seg_po2).await;
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
    ws: &WalletSet,
    first_key: &Option<SigningKey>,
    seg_po2: u32,
) {
    let debug = ws.debug;
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

    let inputs = fetch_block(&block_hex, &ws.addrs, &header_url, &proof_url);
    let mode = if debug { "DEMO (debug=true, ownership skipped)" } else { "OWNERSHIP (debug=false)" };
    println!(
        "legacy single-block mode: {mode}\nchain {}({chain_id}), {} wallet(s) {}, block {block_num}, combined balance {} (native), threshold {}",
        spec.name, ws.addrs.len(), ws.addr_hexes().join(","), inputs.total_balance() as f64 / 1e18, threshold as f64 / 1e18
    );
    ensure_can_prove(inputs.total_balance(), threshold, debug, ws.addrs.len());

    let sigs = block_sigs(&inputs.header_rlp, ws);
    // No challenge in legacy mode -> placeholder journal labels. Marketplace binding comes only
    // from explicit env overrides here (legacy has no marketplace agent id to derive from).
    let challenge_nonce = [0u8; 32];
    let agent_id: [u8; 32] = keccak256(b"por-demo-agent").into();
    let token_id = resolve_token_id("");
    let agent_secret = resolve_secret_cli(first_key, token_id);
    let presentation = maybe_attest(&block_hex, spec.rpc_host).await;
    let bundle = prove_block(&inputs, &sigs, threshold, chain_id, debug, &challenge_nonce, &agent_id, token_id, &agent_secret, seg_po2, presentation);

    File::create("proof.json").unwrap()
        .write_all(serde_json::to_string_pretty(&bundle).unwrap().as_bytes()).unwrap();
    println!("wrote proof.json");
}

// --- Browser-wallet mode: sign in the wallet, prove on the machine. Split into two phases
//     so the wallet's private key never touches the prover -- the browser signs the messages
//     emitted by `--prepare` and hands them back to `--finalize`. Always OWNERSHIP (debug=false).

// PHASE 1: fetch the account proof + raw header for each wallet in `addresses_csv` (a comma-
// separated list) at each challenged block, check the COMBINED balance >= T, and write
// prepare.json -- the per-wallet witnesses plus the exact 32-byte EIP-191 messages the wallet(s)
// must personal_sign (each block_hash + the challenge prehash). No key, no proving. The messages
// are derived here (in Rust, from por-types) so the canonical challenge serialization stays
// single-source and can't drift in the browser. Wallets are sorted ascending + de-duplicated to
// match the guest's distinct/ascending rule; `block_sigs` in phase 2 must follow that order.
async fn run_prepare(ch: Challenge, addresses_csv: &str, out: &str) {
    let chain_id = ch.chain_id;
    let spec = chain_spec(chain_id).unwrap_or_else(|| panic!("challenge names unsupported chain_id {chain_id}"));
    let header_url = verify::header_rpc_url(chain_id).expect("header rpc url");
    let proof_url = verify::proof_rpc_url(chain_id).expect("proof rpc url");
    let threshold = ch.threshold_u128().expect("challenge threshold");
    let mut addrs: Vec<[u8; 20]> = addresses_csv
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(parse_addr20)
        .collect();
    assert!(!addrs.is_empty(), "--address needs at least one 0x address");
    addrs.sort();
    let before = addrs.len();
    addrs.dedup();
    assert_eq!(before, addrs.len(), "duplicate address in --address");
    let addr_hexes: Vec<String> = addrs.iter().map(|a| format!("0x{}", hex::encode(a))).collect();
    println!(
        "prepare: agent {}, chain {}({chain_id}), threshold {} (native), {} wallet(s) {}, blocks {:?}",
        ch.agent_id, spec.name, threshold as f64 / 1e18, addrs.len(), addr_hexes.join(","), ch.blocks
    );

    let mut blocks_json = Vec::with_capacity(ch.blocks.len());
    let mut block_hashes = Vec::with_capacity(ch.blocks.len());
    for &blk in ch.blocks.iter() {
        let block_hex = format!("0x{blk:x}");
        let inputs = fetch_block(&block_hex, &addrs, &header_url, &proof_url);
        ensure_can_prove(inputs.total_balance(), threshold, false, addrs.len());
        let bh = keccak256(&inputs.header_rlp);
        let bh_hex = format!("0x{}", hex::encode(bh));
        println!("  block #{blk}: combined balance ok, block_hash {bh_hex}");
        block_hashes.push(Value::String(bh_hex.clone()));
        let wallets_json: Vec<Value> = inputs.wallets.iter().map(|w| serde_json::json!({
            "address": format!("0x{}", hex::encode(w.address)),
            "nonce": w.nonce,
            "balance": format!("0x{:x}", w.balance),
            "storage_hash": format!("0x{}", hex::encode(w.storage_hash)),
            "code_hash": format!("0x{}", hex::encode(w.code_hash)),
            "account_proof": w.account_proof.iter()
                .map(|n| Value::String(format!("0x{}", hex::encode(n)))).collect::<Vec<_>>(),
        })).collect();
        blocks_json.push(serde_json::json!({
            "block_number": blk,
            "block_hash": bh_hex,
            "header_rlp": format!("0x{}", hex::encode(&inputs.header_rlp)),
            "wallets": wallets_json,
        }));
    }
    let challenge_prehash = keccak256(&ch.canonical_bytes().expect("canonical bytes"));
    // The owner also signs a per-agent identity message; its signature derives the private
    // secret whose keccak256 is the (set-once) on-chain commitment. Text message (personal_sign),
    // not a raw 32-byte blob, so the wallet shows the human what they're binding.
    let token_id = resolve_token_id(&ch.agent_id);
    let identity_message = por_types::identity_message(token_id);
    let prepared = serde_json::json!({
        "version": "por-prepare-v1",
        "challenge": serde_json::to_value(&ch).unwrap(),
        "address": addr_hexes[0], // back-compat: the first (single-wallet) reserves wallet
        "addresses": addr_hexes,  // all reserves wallets, ascending (the block_sigs order)
        "debug": false,
        "agent_token_id": token_id,
        "to_sign": {
            "scheme": "EIP-191 personal_sign. Each wallet in `addresses` signs EVERY block_hash (raw 32 bytes); block_sigs[i] is one signature per wallet in `addresses` order (a bare string is accepted for a single wallet). The owner signs challenge_prehash (raw 32 bytes); identity_message is signed as text.",
            "block_hashes": block_hashes,
            "challenge_prehash": format!("0x{}", hex::encode(challenge_prehash)),
            "identity_message": identity_message,
        },
        "blocks": blocks_json,
    });
    File::create(out).unwrap()
        .write_all(serde_json::to_string_pretty(&prepared).unwrap().as_bytes()).unwrap();
    println!("wrote {out}: {} block(s) x {} wallet(s) + the challenge prehash + the identity message to sign", ch.blocks.len(), addrs.len());
}

// Parse the signatures for one block: `block_sigs[i]` is either a bare hex string (single
// wallet) or an array of hex strings (one per wallet, in `addresses` order).
fn block_sig_list(v: &Value, i: usize) -> Vec<String> {
    match v {
        Value::String(s) => vec![s.clone()],
        Value::Array(a) => a.iter().map(|x| x.as_str().expect("block sig must be hex").to_string()).collect(),
        _ => panic!("block_sigs[{i}] must be a hex string or an array of hex strings"),
    }
}

// PHASE 2: take the wallet signatures (sigs.json = {block_sigs:[...], owner_sig}), verify each
// signature recovers to its wallet address exactly as the guest will (fail fast, before the slow
// prove), then attest + prove each block and assemble response.json. The wallet's v (27/28) is
// normalized to the {0,1} recid the guest/verifier expect.
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

    // Per-agent marketplace binding: token id from the challenge agent_id, secret derived from
    // the wallet's identity signature (or POR_AGENT_SECRET override). The key never touches us.
    let token_id = resolve_token_id(&ch.agent_id);
    let agent_secret = resolve_secret_from_sig(sv["agent_secret"].as_str(), sv["identity_sig"].as_str());
    preflight_identity_binding(token_id, &agent_secret);

    let t_all = Instant::now();
    let mut bundles = Vec::with_capacity(blocks.len());
    for (i, b) in blocks.iter().enumerate() {
        let header_rlp = hexb(b["header_rlp"].as_str().unwrap());
        let wallets: Vec<WalletWitness> = b["wallets"].as_array().expect("wallets array in prepared block")
            .iter().map(|w| WalletWitness {
                address: parse_addr20(w["address"].as_str().unwrap()),
                nonce: w["nonce"].as_u64().unwrap(),
                balance: hu128(w["balance"].as_str().unwrap()),
                storage_hash: h32(w["storage_hash"].as_str().unwrap()),
                code_hash: h32(w["code_hash"].as_str().unwrap()),
                account_proof: w["account_proof"].as_array().unwrap().iter()
                    .map(|n| hexb(n.as_str().unwrap())).collect(),
            }).collect();
        let inputs = BlockInputs { header_rlp, wallets };

        // One ownership sig per wallet (accepts a bare string for a single wallet), normalized.
        let raw = block_sig_list(&block_sigs[i], i);
        assert_eq!(raw.len(), inputs.wallets.len(), "block {i}: {} signature(s) != {} wallet(s)", raw.len(), inputs.wallets.len());
        let sigs: Vec<Vec<u8>> = raw.iter().map(|s| norm_sig(s)).collect();

        // Preflight: each wallet's ownership signature must recover to that wallet's address,
        // exactly as the guest checks it -- catch a wrong/bad signature before burning minutes.
        let block_hash = keccak256(&inputs.header_rlp);
        let mut m = Vec::with_capacity(28 + 32);
        m.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
        m.extend_from_slice(block_hash.as_slice());
        let prehash = keccak256(&m);
        for (w, sig) in inputs.wallets.iter().zip(&sigs) {
            let rec = verify::recover_address_from_prehash(&prehash.0, sig)
                .unwrap_or_else(|e| panic!("block {i} wallet 0x{} signature invalid: {e}", hex::encode(w.address)));
            assert_eq!(rec, w.address, "block {i} signature recovers 0x{} != wallet 0x{}",
                hex::encode(rec), hex::encode(w.address));
        }

        let block_hex = format!("0x{:x}", b["block_number"].as_u64().unwrap());
        println!("[block {}/{}] {block_hex}: {} signature(s) ok, attesting + proving ...", i + 1, blocks.len(), sigs.len());
        let presentation = maybe_attest(&block_hex, spec.rpc_host).await;
        let bundle = prove_block(&inputs, &sigs, threshold, chain_id, debug, &challenge_nonce, &agent_id, token_id, &agent_secret, seg_po2, presentation);
        bundles.push(bundle);
    }

    let owner_sig = format!("0x{}", hex::encode(norm_sig(sv["owner_sig"].as_str().expect("owner_sig in sigs"))));
    let response = Response { version: RESPONSE_VERSION.into(), challenge: ch, owner_sig, bundles };
    File::create(out).unwrap()
        .write_all(serde_json::to_string_pretty(&response).unwrap().as_bytes()).unwrap();
    println!("proved {} block(s) in {:?}; wrote {out}", response.bundles.len(), t_all.elapsed());
}
