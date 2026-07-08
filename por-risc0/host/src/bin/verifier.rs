// Remote verifier service: the interactive challenge/response endpoint.
//
// Flow:
//   1. relying party -> POST /v1/challenges {agent_id, threshold}  (T comes from here)
//        verifier looks up the agent's `owner` in the registry, draws a random nonce,
//        pins the finalized head H, derives 3 recent block numbers f(nonce,H,W), and
//        returns the challenge.
//   2. prover -> POST /v1/challenges/{id}/response {agent_id, owner_signature, bundles[3]}
//        verifier verifies all 3 receipts + their TLSNotary bindings, cross-checks they
//        answer THIS challenge, authenticates the owner signature, returns a verdict.
//   3. relying party -> GET /v1/challenges/{id}  (state + verdict)
//
// Reuses host::verify for the per-bundle Risc0/TLSNotary/policy checks (same code as the
// offline por_verify CLI). In-memory session store; single-process PoC.
//
// Env: VERIFIER_ADDR (default 127.0.0.1:7100), POR_REGISTRY_URL (default
//   http://127.0.0.1:8090), POR_WINDOW_DAYS (default 3), POR_SLOT_SECONDS (default 12),
//   POR_ALLOW_DEBUG, POR_ALLOW_UNVERIFIED_OWNER (dev: accept a placeholder registry owner),
//   POR_ALLOW_NO_PRESENTATION (dev: accept bundles without a TLSNotary presentation),
//   POR_SUBMITTER_URL (if set, e.g. http://127.0.0.1:8092 -> on a verified verdict, auto-POST
//     the verified bundles to the marketplace submitter's /submit, which drives Kurier ->
//     aggregation -> attestation relay -> recordValidation on Base Sepolia).
use std::collections::HashMap;
use std::convert::Infallible;
use std::io::Write;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Result};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use rand::RngCore;
use serde_json::{json, Value};
use tokio::net::TcpListener;

use host::verify::{self, Policy};
use methods::POR_GUEST_ID;
use por_types::{chain_spec, expected_host, resolve_chain, selectable_ids, Challenge, Response as PorResponse, BLOCK_COUNT};

const MAX_BODY: usize = 8 * 1024 * 1024;
const TTL_SECONDS: u64 = 3600;

/// Version reported by `GET /` and `GET /v1/info` (matches `openapi.json`'s `info.version`).
const SERVICE_VERSION: &str = "1.0.0";
/// The OpenAPI document, served verbatim at `GET /v1/openapi.json`. Single canonical copy in
/// `host/src/openapi.json` (the web UI serves a build-synced copy of the same file).
const OPENAPI_JSON: &str = include_str!("../openapi.json");
/// Base Sepolia marketplace facts surfaced by `GET /v1/register`. The verifier never mints on an
/// agent's behalf (it holds no keys); it only tells an agent how to self-register. See
/// hl-registry-integration: registration is `IdentityRegistry.register(agentURI)` from the agent's
/// own wallet, so `msg.sender` (== the wallet that signs challenges) becomes the ERC-721 owner.
const IDENTITY_REGISTRY: &str = "0x8004A818BFB912233c491871b3d84c89A494BD9e";
const BASE_SEPOLIA_RPC: &str = "https://sepolia.base.org";
const BASE_SEPOLIA_CHAIN_ID: u32 = 84532;
/// Default public UI base (overridable with `POR_UI_URL`) — where the guide + directory live.
const DEFAULT_UI_URL: &str = "https://ui-production-3e28.up.railway.app";

#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Issued,
    Submitted,
    Verified,
    Rejected,
    Expired,
}
impl State {
    fn as_str(&self) -> &'static str {
        match self {
            State::Issued => "issued",
            State::Submitted => "submitted",
            State::Verified => "verified",
            State::Rejected => "rejected",
            State::Expired => "expired",
        }
    }
}

// zkVerify/Kurier settle state (populated by a background task after a verified verdict).
#[derive(Clone, Default)]
struct KurierState {
    enabled: bool,
    status: String, // "" | "pending" | "settled" | "failed"
    jobs: Vec<Value>,
}

struct Session {
    challenge: Challenge,
    owner: Option<[u8; 20]>,
    threshold: u128,
    state: State,
    verdict: Option<String>,
    reason: Option<String>,
    kurier: KurierState,
}

// The bits verify_submission needs, snapshotted so we don't hold the lock across proving.
struct Snapshot {
    challenge: Challenge,
    owner: Option<[u8; 20]>,
    threshold: u128,
}

struct AppState {
    sessions: Mutex<HashMap<String, Session>>,
    registry_base: String,
    /// Challenge window in days; converted to blocks per-chain at issue time using the chain's
    /// block time (so "3 days" is the right block count on a fast L2, not a mainnet-slot count).
    window_days: u64,
    /// If set (`POR_SLOT_SECONDS`), overrides every chain's block time -- for tests / tuning.
    slot_override: Option<u64>,
    /// Global testnet mode (`POR_TESTNET`): mainnet chain selectors resolve to their paired
    /// testnet (e.g. requesting chain 1 proves Sepolia). See [`por_types::resolve_chain`].
    testnet: bool,
    allow_unverified_owner: bool,
    allow_no_presentation: bool,
}

impl AppState {
    /// Challenge window in blocks for a chain, from `window_days` and the chain's block time.
    fn window_blocks(&self, chain_id: u32) -> u64 {
        let block_time = self
            .slot_override
            .or_else(|| chain_spec(chain_id).map(|c| c.block_time_secs))
            .unwrap_or(12)
            .max(1);
        (self.window_days * 86400 / block_time).max(1)
    }
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn rand32() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

fn parse_addr(s: &str) -> Option<[u8; 20]> {
    let h = s.strip_prefix("0x").unwrap_or(s);
    if h.len() != 40 {
        return None;
    }
    let v = hex::decode(h).ok()?;
    let mut a = [0u8; 20];
    a.copy_from_slice(&v);
    Some(a)
}

// Deterministic block selection: partition [head-W, head] into thirds and draw one block per
// third from the nonce (domain-separated). Strictly increasing, distinct, all < head.
fn select_blocks(nonce: &[u8; 32], head: u64, window: u64) -> Result<[u64; BLOCK_COUNT]> {
    if head <= window {
        bail!("finalized head {head} <= window {window}");
    }
    let lo = head - window;
    let seg = window / BLOCK_COUNT as u64;
    if seg == 0 {
        bail!("window {window} too small for {BLOCK_COUNT} blocks");
    }
    let mut out = [0u64; BLOCK_COUNT];
    for (i, slot) in out.iter_mut().enumerate() {
        let mut input = Vec::with_capacity(32 + 4);
        input.extend_from_slice(nonce);
        input.extend_from_slice(b"POR");
        input.push(i as u8);
        let d = verify::keccak256(&input);
        let r = u64::from_le_bytes(d[0..8].try_into().unwrap()) % seg;
        *slot = lo + i as u64 * seg + r;
    }
    if !(out[0] < out[1] && out[1] < out[2] && out[2] < head) {
        bail!("block selection invariant violated: {out:?} (head {head})");
    }
    Ok(out)
}

// --- registry + chain reads (blocking curl; fine at PoC scale) ---

fn curl_get(url: &str) -> Vec<u8> {
    Command::new("curl")
        .args(["-s", "-m", "20", url])
        .output()
        .map(|o| o.stdout)
        .unwrap_or_default()
}

/// POST a JSON body to `url`, streaming it via stdin (`--data-binary @-`). The bundles carry
/// ~MB CBOR receipts, far over MAX_ARG_STRLEN, so the body cannot go on the argv.
fn curl_post_stdin(url: &str, body: &[u8]) -> Vec<u8> {
    let mut child = match Command::new("curl")
        .args([
            "-s", "-m", "60", "-X", "POST", "-H", "content-type: application/json",
            "--data-binary", "@-", url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    if let Some(mut sin) = child.stdin.take() {
        let _ = sin.write_all(body);
    } // stdin dropped here -> EOF
    child.wait_with_output().map(|o| o.stdout).unwrap_or_default()
}

/// (found, owner) for an agent id. `found=false` when the registry has no such agent.
fn lookup_owner(base: &str, agent_id: &str) -> (bool, Option<[u8; 20]>) {
    let out = curl_get(&format!("{base}/api/agents/{agent_id}"));
    let Ok(v) = serde_json::from_slice::<Value>(&out) else {
        return (false, None);
    };
    // server.mjs spreads the structured get_agent object, so owner is at /agent/owner.
    let owner_str = v
        .pointer("/agent/owner")
        .and_then(|x| x.as_str())
        .or_else(|| v.get("owner").and_then(|x| x.as_str()));
    let found = v.get("agent").is_some()
        || v.get("agentId").is_some()
        || v.get("name").is_some()
        || owner_str.is_some();
    (found, owner_str.and_then(parse_addr))
}

fn rpc_finalized_head(rpc_url: &str) -> Result<u64> {
    let body = r#"{"jsonrpc":"2.0","id":1,"method":"eth_getBlockByNumber","params":["finalized",false]}"#;
    let out = Command::new("curl")
        .args([
            "-s", "-m", "20", "-X", "POST", "-H", "content-type: application/json", "-H",
            "accept-encoding: identity", "--data", body, rpc_url,
        ])
        .output()?
        .stdout;
    let v: Value = serde_json::from_slice(&out)?;
    let numhex = v["result"]["number"]
        .as_str()
        .ok_or_else(|| anyhow!("no finalized block number in RPC response"))?;
    Ok(u64::from_str_radix(numhex.trim_start_matches("0x"), 16)?)
}

// --- the core: verify a submitted response against the issued challenge ---

fn verify_submission(
    snap: &Snapshot,
    resp: &PorResponse,
    policy: &Policy,
    expected_server: &str,
    allow_unverified_owner: bool,
    allow_no_presentation: bool,
) -> Result<()> {
    if resp.bundles.len() != BLOCK_COUNT {
        bail!("expected {BLOCK_COUNT} bundles, got {}", resp.bundles.len());
    }
    let expected_nonce = snap.challenge.nonce_bytes().map_err(|e| anyhow!(e))?;
    let expected_agent = snap.challenge.agent_id_hash();

    let mut seen_blocks = Vec::with_capacity(BLOCK_COUNT);
    for (i, b) in resp.bundles.iter().enumerate() {
        let receipt = verify::decode_receipt(b).map_err(|e| anyhow!("bundle {i}: {e}"))?;
        verify::verify_receipt(&receipt).map_err(|e| anyhow!("bundle {i}: {e}"))?;
        let j = verify::decode_journal(&receipt).map_err(|e| anyhow!("bundle {i}: {e}"))?;
        verify::check_policy(&j, policy).map_err(|e| anyhow!("bundle {i}: {e}"))?;

        if j.challenge_nonce != expected_nonce {
            bail!("bundle {i}: challenge_nonce != issued nonce");
        }
        if j.agent_id != expected_agent {
            bail!("bundle {i}: agent_id != keccak256(challenged agent_id)");
        }

        // TLSNotary binding: keccak(attested header) == block_hash, and the attested header's
        // own block number == the journal's committed block_number.
        match b.get("tlsnPresentation").and_then(|v| v.as_str()) {
            Some(b64) => {
                let att = verify::verify_presentation(b64, expected_server).map_err(|e| anyhow!("bundle {i}: {e}"))?;
                verify::bind_block_hash(&att.header_rlp, &j.block_hash)
                    .map_err(|e| anyhow!("bundle {i}: {e}"))?;
                let hdr_num = verify::header_block_number(&att.header_rlp)
                    .map_err(|e| anyhow!("bundle {i}: {e}"))?;
                if hdr_num != j.block_number {
                    bail!("bundle {i}: attested header number {hdr_num} != journal block_number {}", j.block_number);
                }
            }
            None => {
                if !allow_no_presentation {
                    bail!("bundle {i}: TLSNotary presentation required");
                }
                // dev: trust the journal's committed block_number without attestation.
            }
        }
        seen_blocks.push(j.block_number);
    }

    // Cross-proof: the 3 proven block numbers must equal the challenged set exactly.
    let mut got = seen_blocks.clone();
    got.sort_unstable();
    let mut want = snap.challenge.blocks.to_vec();
    want.sort_unstable();
    if got != want {
        bail!("block set mismatch: proved {seen_blocks:?}, challenged {:?}", snap.challenge.blocks);
    }

    // Owner authentication: recover the owner-challenge signature and match the registry owner.
    match snap.owner {
        Some(owner) => {
            let digest = snap.challenge.challenge_digest().map_err(|e| anyhow!(e))?;
            let sig = hex::decode(resp.owner_sig.trim_start_matches("0x"))
                .map_err(|e| anyhow!("owner_sig hex: {e}"))?;
            let recovered = verify::recover_address_from_prehash(&digest, &sig)?;
            if recovered != owner {
                bail!(
                    "owner signature recovered 0x{} != registry owner 0x{}",
                    hex::encode(recovered),
                    hex::encode(owner)
                );
            }
        }
        None => {
            if !allow_unverified_owner {
                bail!("no verified registry owner for agent (set POR_ALLOW_UNVERIFIED_OWNER=1 for dev)");
            }
        }
    }

    Ok(())
}

// --- HTTP handlers ---

// CORS: this API is called cross-origin by browser agents (the /prove page, third-party agent
// UIs) and by machine clients that preflight, so every response advertises open access. It's a
// read/challenge API with no cookies or ambient auth (agents authenticate with an owner signature
// in the body), so `*` is safe here.
fn with_cors(b: hyper::http::response::Builder) -> hyper::http::response::Builder {
    b.header("access-control-allow-origin", "*")
        .header("access-control-allow-methods", "GET, POST, OPTIONS")
        .header("access-control-allow-headers", "content-type")
        .header("access-control-max-age", "86400")
}

fn json_response(status: StatusCode, body: &Value) -> Response<Full<Bytes>> {
    with_cors(Response::builder().status(status).header("content-type", "application/json"))
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

// Serve a pre-serialized document (e.g. the embedded OpenAPI JSON) without a serde round-trip.
fn raw_response(status: StatusCode, content_type: &str, body: &'static str) -> Response<Full<Bytes>> {
    with_cors(Response::builder().status(status).header("content-type", content_type))
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

// CORS preflight — answered before the body is read.
fn preflight_response() -> Response<Full<Bytes>> {
    with_cors(Response::builder().status(StatusCode::NO_CONTENT))
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// The RISC Zero guest image_id the verifier accepts, as the same 0x-hex (LE u32 words) the
/// prover stamps into each bundle's `vk`. A prover whose image_id differs is rejected, so
/// surfacing it lets an agent confirm its build matches before spending minutes proving.
fn image_id_hex() -> String {
    format!(
        "0x{}",
        hex::encode(POR_GUEST_ID.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>())
    )
}

/// Supported chains for the current mode (machine-readable). `selector` is what a caller passes
/// as `chain_id`; `resolved_chain_id` is the effective chain committed in the proof.
fn chains_value(state: &AppState) -> Value {
    let chains: Vec<Value> = selectable_ids(state.testnet)
        .into_iter()
        .filter_map(|sel| {
            resolve_chain(sel, state.testnet).ok().map(|spec| {
                json!({
                    "selector": sel,
                    "resolved_chain_id": spec.chain_id,
                    "name": spec.name,
                    "block_time_secs": spec.block_time_secs,
                    "testnet": spec.testnet,
                    "rpc_host": spec.rpc_host,
                })
            })
        })
        .collect();
    json!({ "testnet": state.testnet, "chains": chains })
}

/// Service descriptor for `GET /` and `GET /v1/info`.
fn service_info_value(state: &AppState) -> Value {
    let ui = std::env::var("POR_UI_URL").unwrap_or_else(|_| DEFAULT_UI_URL.into());
    let ui = ui.trim_end_matches('/');
    json!({
        "service": "proof-of-reserves-verifier",
        "version": SERVICE_VERSION,
        "mode": if state.testnet { "testnet" } else { "mainnet" },
        "image_id": image_id_hex(),
        "block_count": BLOCK_COUNT,
        "window_days": state.window_days,
        "notary_hint": if state.allow_no_presentation {
            "TLSNotary presentation optional on this instance (dev mode)"
        } else {
            "TLSNotary presentation REQUIRED — set NOTARY_ADDR on your prover"
        },
        "endpoints": {
            "request_challenge": "POST /v1/challenges",
            "submit_response": "POST /v1/challenges/{id}/response",
            "challenge_status": "GET /v1/challenges/{id}",
            "chains": "GET /v1/chains",
            "register_info": "GET /v1/register",
            "openapi": "GET /v1/openapi.json"
        },
        "chains": chains_value(state),
        "links": {
            "guide": format!("{ui}/docs"),
            "openapi": "/v1/openapi.json",
            "directory": ui,
            "marketplace": "https://agent-registry.horizenlabs.io"
        }
    })
}

/// How to self-register, for `GET /v1/register`. The verifier holds no keys and cannot register
/// on the agent's behalf; it returns the exact on-chain call the agent makes itself.
fn register_info_value() -> Value {
    let selector = format!("0x{}", hex::encode(&verify::keccak256(b"register(string)")[..4]));
    json!({
        "summary": "Register once on Base Sepolia by calling IdentityRegistry.register(agentURI) from your OWN wallet. msg.sender becomes the agent owner — the wallet this verifier authenticates your challenge signatures against.",
        "self_custody": true,
        "chain": { "name": "Base Sepolia", "chain_id": BASE_SEPOLIA_CHAIN_ID, "rpc_url": BASE_SEPOLIA_RPC },
        "identity_registry": IDENTITY_REGISTRY,
        "function": "register(string agentURI) returns (uint256 agentId)",
        "selector": selector,
        "metadata_template": {
            "name": "My Agent",
            "description": "What my agent does",
            "services": [{ "name": "proof-of-reserves", "endpoint": "https://example.com", "version": "0.1.0", "skills": ["proof-of-reserves"], "domains": ["defi"] }],
            "supportedTrust": ["zkVerify-risc0"],
            "metadata": { "proofSystem": "risc0" }
        },
        "agent_uri_hint": "data:application/json;base64,<base64 of JSON.stringify(metadata)>",
        "tools": {
            "mcp_tool": "register_agent (por-mcp.mjs)",
            "cli_helper": "node app/web/register-agent.mjs --key 0x<owner key> --name \"My Agent\"",
            "browser": "Open the /prove page and use the Register step (your wallet signs; needs Base Sepolia gas)"
        },
        "note": "The verifier authenticates you via ecrecover(owner_sig) == ownerOf(agentId). Because register() sets msg.sender as owner, register from the wallet whose key you will use as POR_OWNER_KEY (CLI) or authorize with in the browser."
    })
}

fn handle_issue(state: &AppState, body: &[u8]) -> (StatusCode, Value) {
    let req: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, json!({"error": format!("bad json: {e}")})),
    };
    let Some(agent_id) = req["agent_id"].as_str().map(str::to_string) else {
        return (StatusCode::BAD_REQUEST, json!({"error": "agent_id required"}));
    };
    // threshold accepted as a decimal string or a JSON number.
    let threshold_str = match &req["threshold"] {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        _ => return (StatusCode::BAD_REQUEST, json!({"error": "threshold required (decimal string)"})),
    };
    let threshold: u128 = match threshold_str.parse() {
        Ok(t) => t,
        Err(_) => return (StatusCode::BAD_REQUEST, json!({"error": "threshold not a u128"})),
    };
    // Which chain to prove reserves on. Optional (default mainnet selector 1). The requested
    // value is a SELECTOR; resolve_chain maps it to the effective chain under the testnet flag
    // (so requesting 1 with POR_TESTNET proves Sepolia). The effective id flows into the
    // challenge/journal and is bound to its RPC host at submit time.
    let selector: u32 = match &req["chain_id"] {
        Value::Null => 1,
        Value::Number(n) => match n.as_u64().and_then(|v| u32::try_from(v).ok()) {
            Some(c) => c,
            None => return (StatusCode::BAD_REQUEST, json!({"error": "chain_id not a u32"})),
        },
        Value::String(s) => match s.trim().parse() {
            Ok(c) => c,
            Err(_) => return (StatusCode::BAD_REQUEST, json!({"error": "chain_id not a u32"})),
        },
        _ => return (StatusCode::BAD_REQUEST, json!({"error": "chain_id must be a number or string"})),
    };
    let chain_id = match resolve_chain(selector, state.testnet) {
        Ok(spec) => spec.chain_id,
        Err(e) => return (StatusCode::BAD_REQUEST, json!({"error": e, "supported": selectable_ids(state.testnet), "testnet": state.testnet})),
    };

    let (found, owner) = lookup_owner(&state.registry_base, &agent_id);
    if !found && !state.allow_unverified_owner {
        return (StatusCode::NOT_FOUND, json!({"error": "agent not found in registry", "agent_id": agent_id}));
    }
    if owner.is_none() && !state.allow_unverified_owner {
        // Issue anyway; auth will fail on submit unless the dev escape is set. Warn the caller.
        eprintln!("WARNING: agent {agent_id} has no parseable owner address; submissions will fail owner auth");
    }

    // Head-pin is a cheap recent-block query -> the header endpoint (drpc) serves it fine; the
    // verifier never needs the archive proof endpoint (it verifies receipts, doesn't fetch proofs).
    let rpc_url = verify::header_rpc_url(chain_id).expect("chain validated above");
    let head = match rpc_finalized_head(&rpc_url) {
        Ok(h) => h,
        Err(e) => return (StatusCode::BAD_GATEWAY, json!({"error": format!("finalized head fetch failed: {e}")})),
    };
    let nonce = rand32();
    let blocks = match select_blocks(&nonce, head, state.window_blocks(chain_id)) {
        Ok(b) => b,
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": format!("block selection: {e}")})),
    };
    let issued = now();
    let challenge = Challenge {
        challenge_id: hex::encode(rand32())[..32].to_string(),
        agent_id,
        threshold: threshold_str,
        chain_id,
        nonce: format!("0x{}", hex::encode(nonce)),
        head_block: head,
        blocks,
        issued_at: issued,
        expires_at: issued + TTL_SECONDS,
    };
    let id = challenge.challenge_id.clone();
    state.sessions.lock().unwrap().insert(
        id.clone(),
        Session {
            challenge: challenge.clone(),
            owner,
            threshold,
            state: State::Issued,
            verdict: None,
            reason: None,
            kurier: KurierState::default(),
        },
    );
    let chain_name = chain_spec(chain_id).map(|c| c.name).unwrap_or("?");
    println!(
        "[issue] {id}: agent {} chain {chain_name}({chain_id}) threshold {threshold} head {head} blocks {:?} owner {}",
        challenge.agent_id, challenge.blocks,
        owner.map(|o| format!("0x{}", hex::encode(o))).unwrap_or_else(|| "UNVERIFIED".into())
    );
    (StatusCode::CREATED, serde_json::to_value(&challenge).unwrap())
}

async fn handle_submit(state: &Arc<AppState>, id: &str, body: &[u8]) -> (StatusCode, Value) {
    let resp: PorResponse = match serde_json::from_slice(body) {
        Ok(r) => r,
        Err(e) => return (StatusCode::BAD_REQUEST, json!({"error": format!("bad response json: {e}")})),
    };

    // Atomically claim the challenge (Issued -> Submitted) so it can't be answered twice.
    let snap = {
        let mut map = state.sessions.lock().unwrap();
        let Some(s) = map.get_mut(id) else {
            return (StatusCode::NOT_FOUND, json!({"error": "unknown challenge"}));
        };
        if now() > s.challenge.expires_at {
            s.state = State::Expired;
            return (StatusCode::OK, json!({"challenge_id": id, "verdict": "rejected", "reason": "challenge expired"}));
        }
        if s.state != State::Issued {
            return (StatusCode::CONFLICT, json!({"challenge_id": id, "verdict": "rejected", "reason": "challenge already answered"}));
        }
        s.state = State::Submitted;
        Snapshot { challenge: s.challenge.clone(), owner: s.owner, threshold: s.threshold }
    };

    let policy = Policy {
        allow_debug: std::env::var("POR_ALLOW_DEBUG").is_ok(),
        required_threshold: snap.threshold,
        expected_chain_id: snap.challenge.chain_id,
    };
    // The attested-header host that vouches for this challenge's chain (the trust anchor that
    // stops a proof committing chain_id=X while attesting a different chain's RPC).
    let expected_server = match expected_host(snap.challenge.chain_id) {
        Ok(h) => h.to_string(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, json!({"error": e})),
    };
    let allow_unverified = state.allow_unverified_owner;
    let allow_no_pres = state.allow_no_presentation;

    // Keep the bundles for background post-processing -- Kurier settle and/or forwarding to the
    // marketplace submitter -- since `resp` is about to be moved into the verification closure.
    let kurier_on = std::env::var("KURIER_API_KEY").is_ok();
    let submitter_url = std::env::var("POR_SUBMITTER_URL").ok();
    let saved_bundles = (kurier_on || submitter_url.is_some()).then(|| resp.bundles.clone());

    // Verification (receipt.verify x3 + presentation checks) is CPU-bound: off the runtime.
    let result = tokio::task::spawn_blocking(move || {
        verify_submission(&snap, &resp, &policy, &expected_server, allow_unverified, allow_no_pres)
    })
    .await
    .unwrap();

    let mut map = state.sessions.lock().unwrap();
    let s = map.get_mut(id).expect("session vanished");
    match result {
        Ok(()) => {
            s.state = State::Verified;
            s.verdict = Some("verified".into());
            // Background post-processing on the verified bundles (the local verdict stands
            // regardless). Both paths take minutes; neither blocks the response.
            if let Some(bundles) = saved_bundles {
                if kurier_on {
                    // zkVerify settle here + (optionally) forward to the submitter for Base.
                    s.kurier = KurierState { enabled: true, status: "pending".into(), jobs: vec![] };
                    if let Some(url) = submitter_url {
                        tokio::spawn(forward_to_submitter(url, id.to_string(), bundles.clone()));
                    }
                    tokio::spawn(settle_kurier(state.clone(), id.to_string(), bundles));
                } else if let Some(url) = submitter_url {
                    // Submitter owns the whole Kurier->Base path (it submits with chainId), so no
                    // separate zkVerify settle here -- avoids submitting the same proof twice.
                    tokio::spawn(forward_to_submitter(url, id.to_string(), bundles));
                }
            }
            println!("[verify] {id}: VERIFIED");
            (StatusCode::OK, json!({"challenge_id": id, "verdict": "verified"}))
        }
        Err(e) => {
            let reason = e.to_string();
            s.state = State::Rejected;
            s.verdict = Some("rejected".into());
            s.reason = Some(reason.clone());
            println!("[verify] {id}: REJECTED ({reason})");
            (StatusCode::OK, json!({"challenge_id": id, "verdict": "rejected", "reason": reason}))
        }
    }
}

// Background: submit each verified bundle to Kurier/zkVerify, recording per-block outcomes.
async fn settle_kurier(state: Arc<AppState>, id: String, bundles: Vec<Value>) {
    let mut jobs = Vec::with_capacity(bundles.len());
    let mut all_ok = true;
    for (i, b) in bundles.into_iter().enumerate() {
        let res = tokio::task::spawn_blocking(move || verify::submit_to_kurier(&b)).await.unwrap();
        match res {
            Ok(Some(o)) => jobs.push(json!({"bundle": i, "status": o.status, "txHash": o.tx_hash, "blockHash": o.block_hash})),
            Ok(None) => jobs.push(json!({"bundle": i, "status": "skipped"})),
            Err(e) => {
                all_ok = false;
                jobs.push(json!({"bundle": i, "status": "failed", "error": e.to_string()}));
            }
        }
    }
    let mut map = state.sessions.lock().unwrap();
    if let Some(s) = map.get_mut(&id) {
        s.kurier.status = if all_ok { "settled".into() } else { "failed".into() };
        s.kurier.jobs = jobs;
        println!("[kurier] {id}: {}", s.kurier.status);
    }
}

// Background: hand the verified bundles to the marketplace submitter's /submit endpoint, which
// drives Kurier(chainId) -> aggregation -> attestation relay -> recordValidation on Base Sepolia.
// Fire-and-forget: the submitter tracks its own pipeline; the challenge verdict is independent.
async fn forward_to_submitter(url: String, id: String, bundles: Vec<Value>) {
    let n = bundles.len();
    let base = url.trim_end_matches('/').to_string();
    let submit_url = format!("{base}/submit");
    let payload = json!({ "bundles": bundles }).to_string();
    let out = tokio::task::spawn_blocking(move || curl_post_stdin(&submit_url, payload.as_bytes()))
        .await
        .unwrap();
    match serde_json::from_slice::<Value>(&out) {
        Ok(v) => println!("[submitter] {id}: forwarded {n} bundle(s) -> {v}"),
        Err(_) => eprintln!(
            "[submitter] {id}: forward to {base}/submit failed or returned non-JSON: {}",
            String::from_utf8_lossy(&out)
        ),
    }
}

fn handle_status(state: &AppState, id: &str) -> (StatusCode, Value) {
    let mut map = state.sessions.lock().unwrap();
    let Some(s) = map.get_mut(id) else {
        return (StatusCode::NOT_FOUND, json!({"error": "unknown challenge"}));
    };
    if s.state == State::Issued && now() > s.challenge.expires_at {
        s.state = State::Expired;
    }
    (
        StatusCode::OK,
        json!({
            "challenge_id": id,
            "state": s.state.as_str(),
            "agent_id": s.challenge.agent_id,
            "threshold": s.challenge.threshold,
            "chain_id": s.challenge.chain_id,
            "head_block": s.challenge.head_block,
            "blocks": s.challenge.blocks,
            "issued_at": s.challenge.issued_at,
            "expires_at": s.challenge.expires_at,
            "verdict": s.verdict,
            "reason": s.reason,
            "kurier": if s.kurier.enabled {
                json!({"status": s.kurier.status, "jobs": s.kurier.jobs})
            } else {
                Value::Null
            },
        }),
    )
}

async fn route(req: Request<Incoming>, state: Arc<AppState>) -> Result<Response<Full<Bytes>>, Infallible> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let segs: Vec<&str> = path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();

    // CORS preflight: answer before draining the body.
    if method == Method::OPTIONS {
        return Ok(preflight_response());
    }

    let body = match Limited::new(req.into_body(), MAX_BODY).collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return Ok(json_response(StatusCode::PAYLOAD_TOO_LARGE, &json!({"error": "body too large"}))),
    };

    // The OpenAPI doc is served verbatim (a static string), not via the Value tuple below.
    if method == Method::GET && matches!(segs.as_slice(), ["v1", "openapi.json"]) {
        return Ok(raw_response(StatusCode::OK, "application/json", OPENAPI_JSON));
    }

    let (status, payload) = match (&method, segs.as_slice()) {
        // Discovery (machine-readable service metadata).
        (&Method::GET, []) | (&Method::GET, ["v1", "info"]) => (StatusCode::OK, service_info_value(&state)),
        (&Method::GET, ["v1", "chains"]) => (StatusCode::OK, chains_value(&state)),
        (&Method::GET, ["v1", "register"]) => (StatusCode::OK, register_info_value()),
        // Challenge lifecycle.
        (&Method::POST, ["v1", "challenges"]) => handle_issue(&state, &body),
        (&Method::POST, ["v1", "challenges", id, "response"]) => handle_submit(&state, id, &body).await,
        (&Method::GET, ["v1", "challenges", id]) => handle_status(&state, id),
        _ => (StatusCode::NOT_FOUND, json!({"error": "not found"})),
    };
    Ok(json_response(status, &payload))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let addr: SocketAddr = std::env::var("VERIFIER_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:7100".into())
        .parse()
        .expect("VERIFIER_ADDR must be host:port");
    let window_days: u64 = std::env::var("POR_WINDOW_DAYS").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
    // Optional global block-time override; unset -> each chain's own block time is used.
    let slot_override: Option<u64> = std::env::var("POR_SLOT_SECONDS").ok().and_then(|s| s.parse().ok());
    let testnet = std::env::var("POR_TESTNET").is_ok();

    let state = Arc::new(AppState {
        sessions: Mutex::new(HashMap::new()),
        registry_base: std::env::var("POR_REGISTRY_URL").unwrap_or_else(|_| "http://127.0.0.1:8090".into()),
        window_days,
        slot_override,
        testnet,
        allow_unverified_owner: std::env::var("POR_ALLOW_UNVERIFIED_OWNER").is_ok(),
        allow_no_presentation: std::env::var("POR_ALLOW_NO_PRESENTATION").is_ok(),
    });

    // In testnet mode the selectable ids are mainnet selectors that resolve to a testnet.
    let chains: Vec<String> = selectable_ids(testnet)
        .into_iter()
        .filter_map(|id| resolve_chain(id, testnet).ok().map(|s| format!("{id}->{}({})", s.name, s.chain_id)))
        .collect();
    let listener = TcpListener::bind(addr).await.expect("bind");
    println!(
        "verifier listening on http://{addr} (registry {}, window {window_days}d, {} blocks/challenge, {})\n  chains: {}",
        state.registry_base, BLOCK_COUNT,
        if testnet { "TESTNET mode" } else { "mainnet mode" },
        chains.join(", ")
    );

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                eprintln!("accept error: {e}");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let st = state.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req| {
                let st = st.clone();
                async move { route(req, st).await }
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                eprintln!("connection error: {e}");
            }
        });
    }
}
