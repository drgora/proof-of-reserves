// Proof-of-reserves PROVING SERVICE (the agent, server-side).
//
// Serves the React UI's API:
//   GET  /api/nonce        -> issue a SIWE nonce
//   GET  /api/config       -> { admin_mode } so the UI can show the admin panel
//   POST /api/prove        -> { message, signature, threshold }
//        recover the SIWE signer (ownership), check the nonce, prove reserves for
//        that wallet (binding the signed SIWE into the attestation), submit to the
//        verifier, return its verdict.
//   POST /api/admin/prove  -> { address, threshold }   [ADMIN MODE ONLY]
//        prove reserves for ANY address with NO ownership check / no SIWE.
//        For LOCAL TESTING. Enabled only when POR_ADMIN_MODE=1 is set.
//
// The Zerion API key lives here (server-side); the separate notary is unchanged.
//
// Run (needs zerion_notary + por_verifier running):
//   ZERION_API_KEY=...  NOTARY_ADDR=127.0.0.1:7150 \
//   VERIFIER_URL=http://127.0.0.1:8080/verify  POR_LISTEN_ADDR=127.0.0.1:8090 \
//   [POR_ADMIN_MODE=1]  RUST_LOG=info  cargo run --release --bin por_service

mod por_core;
mod por_zk;
mod siwe_verify;
mod types;

use std::{
    collections::HashMap,
    env, fs,
    io::Read,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::anyhow;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;
use tracing::{info, warn};

use por_zk::VerifyResponse;
use siwe_verify::{addr_hex, recover_personal_sign};
use tlsn::attestation::Extension;

const NONCE_TTL: Duration = Duration::from_secs(600);
const SIWE_EXT_ID: &[u8] = b"por.siwe";

struct AppState {
    notary_addr: String,
    auth_b64: String,
    verifier_url: String,
    nonces: Mutex<HashMap<String, Instant>>,
    /// When true, /api/admin/prove proves any address without SIWE. Local only.
    admin: bool,
}

#[derive(Serialize)]
struct NonceResponse {
    nonce: String,
}

#[derive(Serialize)]
struct ConfigResponse {
    admin_mode: bool,
}

#[derive(Deserialize)]
struct ProveRequest {
    /// The exact EIP-4361 message the user signed.
    message: String,
    /// 65-byte personal_sign signature, hex (0x-prefixed ok).
    signature: String,
    /// USD threshold to prove (balance >= threshold).
    threshold: u64,
}

#[derive(Deserialize)]
struct AdminProveRequest {
    /// The wallet to prove reserves for (no ownership check).
    address: String,
    threshold: u64,
}

#[derive(Serialize)]
struct ProveResponse {
    wallet: String,
    requested_threshold: u64,
    /// The relying-party verifier's verdict.
    verification: VerifyResponse,
}

/// Error type that renders as a JSON `{ "error": ... }` body.
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::BAD_REQUEST, message: msg.into() }
    }
    fn forbidden(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::FORBIDDEN, message: msg.into() }
    }
    fn internal(msg: impl Into<String>) -> Self {
        Self { status: StatusCode::INTERNAL_SERVER_ERROR, message: msg.into() }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        warn!("api error: {}", self.message);
        (self.status, Json(serde_json::json!({ "error": self.message }))).into_response()
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let auth_b64 = env::var("ZERION_API_KEY")
        .map(|k| BASE64.encode(format!("{k}:")))
        .unwrap_or_default();
    if auth_b64.is_empty() {
        return Err(anyhow!("set ZERION_API_KEY (the service queries Zerion)"));
    }

    let admin = matches!(
        env::var("POR_ADMIN_MODE").ok().as_deref(),
        Some("1") | Some("true") | Some("yes")
    );

    let state = Arc::new(AppState {
        notary_addr: env::var("NOTARY_ADDR").unwrap_or_else(|_| "127.0.0.1:7150".into()),
        auth_b64,
        verifier_url: env::var("VERIFIER_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:8080/verify".into()),
        nonces: Mutex::new(HashMap::new()),
        admin,
    });

    let addr = env::var("POR_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8090".into());
    info!("proving service on http://{addr} (notary={}, verifier={})", state.notary_addr, state.verifier_url);
    if admin {
        warn!(
            "⚠️  ADMIN MODE ENABLED — POST /api/admin/prove proves ANY address with NO \
             ownership check. For LOCAL TESTING only; never enable in production."
        );
    }

    let app = Router::new()
        .route("/api/nonce", get(nonce))
        .route("/api/config", get(config))
        .route("/api/prove", post(prove))
        .route("/api/admin/prove", post(admin_prove))
        .layer(CorsLayer::permissive())
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn nonce(State(state): State<Arc<AppState>>) -> Result<Json<NonceResponse>, ApiError> {
    let nonce = random_hex().map_err(|e| ApiError::internal(format!("rng: {e}")))?;
    let mut store = state.nonces.lock().unwrap();
    prune(&mut store);
    store.insert(nonce.clone(), Instant::now());
    Ok(Json(NonceResponse { nonce }))
}

async fn config(State(state): State<Arc<AppState>>) -> Json<ConfigResponse> {
    Json(ConfigResponse { admin_mode: state.admin })
}

async fn prove(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ProveRequest>,
) -> Result<Json<ProveResponse>, ApiError> {
    // 1. Recover the signer (proves wallet ownership).
    let sig = decode_sig(&req.signature)?;
    let signer = recover_personal_sign(req.message.as_bytes(), &sig)
        .map_err(|e| ApiError::bad(format!("invalid SIWE signature: {e}")))?;
    let wallet = addr_hex(&signer);

    // 2. Consume the nonce embedded in the message (anti-replay).
    let nonce = parse_nonce(&req.message)
        .ok_or_else(|| ApiError::bad("SIWE message has no Nonce field"))?;
    {
        let mut store = state.nonces.lock().unwrap();
        prune(&mut store);
        if store.remove(&nonce).is_none() {
            return Err(ApiError::bad("unknown or expired nonce"));
        }
    }
    info!("verified SIWE ownership of {wallet}; proving balance >= {}", req.threshold);

    // 3. Prove, binding the signed SIWE into the attestation as a signed extension.
    let siwe_ext = Extension {
        id: SIWE_EXT_ID.to_vec(),
        value: bincode::serialize(&(req.message.clone(), sig))
            .map_err(|e| ApiError::internal(format!("encode siwe: {e}")))?,
    };
    let verification = run_proof(&state, wallet.clone(), req.threshold, vec![siwe_ext]).await?;

    Ok(Json(ProveResponse { wallet, requested_threshold: req.threshold, verification }))
}

async fn admin_prove(
    State(state): State<Arc<AppState>>,
    Json(req): Json<AdminProveRequest>,
) -> Result<Json<ProveResponse>, ApiError> {
    if !state.admin {
        return Err(ApiError::forbidden(
            "admin mode is disabled (start the service with POR_ADMIN_MODE=1)",
        ));
    }
    let wallet = normalize_address(&req.address)?;
    warn!("ADMIN: proving balance >= {} for {wallet} WITHOUT ownership proof", req.threshold);

    // No SIWE extension — the verifier's `owner_verified` will be absent.
    let verification = run_proof(&state, wallet.clone(), req.threshold, vec![]).await?;

    Ok(Json(ProveResponse { wallet, requested_threshold: req.threshold, verification }))
}

/// Shared proving core: MPC-TLS to Zerion via the notary, then submit the bundle
/// to the relying-party verifier and return its verdict.
async fn run_proof(
    state: &AppState,
    wallet: String,
    threshold: u64,
    exts: Vec<Extension>,
) -> Result<VerifyResponse, ApiError> {
    let notary_stream = tokio::net::TcpStream::connect(&state.notary_addr)
        .await
        .map_err(|e| ApiError::internal(format!("notary unreachable: {e}")))?;
    notary_stream.set_nodelay(true).ok();

    // por_core::prove drives the tlsn MPC, whose future is !Send; run it on a
    // blocking thread so this axum handler's future stays Send.
    let auth_b64 = state.auth_b64.clone();
    let (presentation, zk) = tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(por_core::prove(
            notary_stream,
            &wallet,
            threshold,
            auth_b64,
            exts,
        ))
    })
    .await
    .map_err(|e| ApiError::internal(format!("prover task join error: {e}")))?
    .map_err(|e| ApiError::internal(format!("proving failed: {e}")))?;

    let bundle = por_zk::ProofRequest {
        presentation_b64: BASE64.encode(
            bincode::serialize(&presentation).map_err(|e| ApiError::internal(e.to_string()))?,
        ),
        zk_proof_b64: BASE64
            .encode(bincode::serialize(&zk).map_err(|e| ApiError::internal(e.to_string()))?),
        required_threshold: Some(threshold),
    };
    submit_to_verifier(&state.verifier_url, &bundle)
        .await
        .map_err(|e| ApiError::internal(format!("verifier submit failed: {e}")))
}

async fn submit_to_verifier(
    url: &str,
    bundle: &por_zk::ProofRequest,
) -> anyhow::Result<VerifyResponse> {
    let client: Client<_, Full<Bytes>> = Client::builder(TokioExecutor::new()).build_http();
    let body = Full::new(Bytes::from(serde_json::to_vec(bundle)?));
    let request = hyper::Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/json")
        .body(body)?;
    let resp = client.request(request).await?;
    let bytes = resp.into_body().collect().await?.to_bytes();
    Ok(serde_json::from_slice(&bytes)?)
}

fn decode_sig(s: &str) -> Result<Vec<u8>, ApiError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| ApiError::bad(format!("bad signature hex: {e}")))?;
    if bytes.len() != 65 {
        return Err(ApiError::bad(format!("signature must be 65 bytes, got {}", bytes.len())));
    }
    Ok(bytes)
}

/// Validate + normalize a `0x…40hex` address to lowercase.
fn normalize_address(addr: &str) -> Result<String, ApiError> {
    let a = addr.trim();
    let hex = a.strip_prefix("0x").or_else(|| a.strip_prefix("0X")).unwrap_or(a);
    if hex.len() != 40 || hex.bytes().any(|b| !b.is_ascii_hexdigit()) {
        return Err(ApiError::bad("address must be 0x followed by 40 hex characters"));
    }
    Ok(format!("0x{}", hex.to_lowercase()))
}

/// Extract the value of the EIP-4361 `Nonce:` field.
fn parse_nonce(message: &str) -> Option<String> {
    message
        .lines()
        .find_map(|l| l.strip_prefix("Nonce: "))
        .map(|s| s.trim().to_string())
}

fn random_hex() -> std::io::Result<String> {
    let mut buf = [0u8; 16];
    fs::File::open("/dev/urandom")?.read_exact(&mut buf)?;
    Ok(hex::encode(buf))
}

fn prune(store: &mut HashMap<String, Instant>) {
    store.retain(|_, t| t.elapsed() < NONCE_TTL);
}
