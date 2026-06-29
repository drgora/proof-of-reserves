// Proof-of-reserves VERIFIER — a REST service (the relying party).
//
// Exposes `POST /verify`, which accepts a { presentation, zk_proof } bundle and
// checks it OFFLINE:
//   1. the presentation's notary signature + server cert chain (Mozilla roots),
//   2. that the session was with api.zerion.io,
//   3. that the ZK proof verifies and was produced by our exact circuit,
//   4. that the proof's committed hash equals the notary-signed commitment,
//   5. that the committed range is the `data.attributes.total.positions` value,
//   6. that the proven threshold meets the service's required minimum.
//
// It never learns the balance or the API key.
//
// Run (from crates/examples-zk):
//   POR_REQUIRED_THRESHOLD=1000000 RUST_LOG=info cargo run --release --bin por_verifier
// Then POST the bundle produced by `por_prove`.

mod por_zk;

use std::{env, time::Duration};

use anyhow::{Result, anyhow};
use axum::{Json, Router, routing::get, routing::post};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use por_zk::{ProofRequest, VerifyResponse};
use tracing::{info, warn};

use tlsn::{
    attestation::{
        CryptoProvider,
        presentation::{Presentation, PresentationOutput},
    },
    connection::ServerName,
    verifier::ServerCertVerifier,
};

const EXPECTED_SERVER: &str = "api.zerion.io";
const BALANCE_KEY_PATH: &[u8] = b"\"total\":";
const BALANCE_KEY: &[u8] = b"\"positions\":";
// Notary-signed extension carrying the received commitment hashes (+ ranges).
const COMMITMENTS_EXT_ID: &[u8] = b"por.recv_commitments";

fn required_threshold() -> u64 {
    env::var("POR_REQUIRED_THRESHOLD")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000)
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let addr = env::var("POR_LISTEN_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    info!(
        "proof-of-reserves verifier listening on http://{addr}  (requires balance >= {} USD)",
        required_threshold()
    );

    let app = Router::new()
        .route("/health", get(|| async { "ok" }))
        .route("/verify", post(verify_handler));

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

async fn verify_handler(Json(req): Json<ProofRequest>) -> Json<VerifyResponse> {
    let required = required_threshold();
    // ZK verification + presentation verification are CPU-bound; keep the async
    // runtime responsive.
    let resp = tokio::task::spawn_blocking(move || verify_bundle(req, required))
        .await
        .unwrap_or_else(|e| VerifyResponse {
            verified: false,
            error: Some(format!("internal task error: {e}")),
            ..Default::default()
        });

    if resp.verified {
        info!(
            "✅ verified: balance >= {} from {}",
            resp.threshold_proven.unwrap_or_default(),
            resp.server_name.as_deref().unwrap_or("?")
        );
    } else {
        warn!("❌ rejected: {}", resp.error.as_deref().unwrap_or("?"));
    }
    Json(resp)
}

fn verify_bundle(req: ProofRequest, required: u64) -> VerifyResponse {
    match verify_inner(req, required) {
        Ok(resp) => resp,
        Err(e) => VerifyResponse {
            verified: false,
            error: Some(e.to_string()),
            ..Default::default()
        },
    }
}

fn verify_inner(req: ProofRequest, required: u64) -> Result<VerifyResponse> {
    let presentation: Presentation =
        bincode::deserialize(&BASE64.decode(req.presentation_b64.as_bytes())?)?;
    let zk: por_zk::ZKProofBundle =
        bincode::deserialize(&BASE64.decode(req.zk_proof_b64.as_bytes())?)?;

    // --- (1) Verify the presentation: notary signature + server cert chain ---
    let crypto_provider = CryptoProvider {
        cert: ServerCertVerifier::mozilla(),
        ..Default::default()
    };
    let notary_key = hex::encode(presentation.verifying_key().data.clone());

    let PresentationOutput {
        server_name,
        connection_info,
        transcript,
        extensions,
        ..
    } = presentation
        .verify(&crypto_provider)
        .map_err(|e| anyhow!("presentation verification failed: {e:?}"))?;

    // --- (2) The session must be with the expected server ---
    let server_name = server_name.ok_or_else(|| anyhow!("server name not disclosed"))?;
    let ServerName::Dns(ref dns) = server_name;
    if dns.as_str() != EXPECTED_SERVER {
        return Err(anyhow!(
            "unexpected server: {} (want {EXPECTED_SERVER})",
            dns.as_str()
        ));
    }

    // --- (3) Verify the ZK proof and read its public inputs ---
    let proof_inputs = por_zk::verify_proof(&zk)?;

    // --- (4) The proof's committed hash MUST equal a commitment the notary
    //     signed into the `por.recv_commitments` extension. This binds the ZK
    //     proof to data that actually appeared in the session, using only the
    //     PUBLIC presentation API (no access to tlsn-internal fields). ---
    let ext = extensions
        .iter()
        .find(|e| e.id.as_slice() == COMMITMENTS_EXT_ID)
        .ok_or_else(|| anyhow!("attestation is missing the por.recv_commitments extension"))?;
    let recv_commitments: Vec<(Vec<u8>, u64, u64)> = bincode::deserialize(&ext.value)?;
    let (_, committed_start, _committed_end) = recv_commitments
        .iter()
        .find(|(hash, _, _)| hash.as_slice() == proof_inputs.committed_hash.as_slice())
        .ok_or_else(|| {
            anyhow!("no notary-signed commitment matches the ZK proof's committed hash")
        })?;

    // --- (5) The committed range must be exactly total.positions' value ---
    let partial = transcript.ok_or_else(|| anyhow!("transcript not disclosed"))?;
    let received = partial.received_unsafe();
    if !balance_location_ok(received, *committed_start as usize) {
        return Err(anyhow!(
            "committed range is not the data.attributes.total.positions value"
        ));
    }

    // --- (6) The proven threshold must meet our policy ---
    if proof_inputs.threshold < required {
        return Err(anyhow!(
            "proof attests balance >= {}, but this service requires >= {required}",
            proof_inputs.threshold
        ));
    }

    let time = chrono::DateTime::<chrono::Utc>::from(
        std::time::UNIX_EPOCH + Duration::from_secs(connection_info.time),
    );

    Ok(VerifyResponse {
        verified: true,
        server_name: Some(dns.as_str().to_string()),
        time: Some(time.to_rfc3339()),
        threshold_proven: Some(proof_inputs.threshold),
        notary_key: Some(notary_key),
        // Independent ownership re-check (reading the signed `por.siwe`
        // extension) isn't wired here yet; por_service enforces SIWE upstream.
        wallet: None,
        owner_verified: None,
        error: None,
    })
}

// Confirm `committed_start` is the first byte of the value that follows
// `"total": ... "positions":` in the (compact) revealed JSON. Robust to other
// keys appearing in `total` before `positions`, and to whitespace after the
// colon.
fn balance_location_ok(received: &[u8], committed_start: usize) -> bool {
    let Some(total_at) = find_sub(received, BALANCE_KEY_PATH, 0) else {
        return false;
    };
    let Some(pos_at) = find_sub(received, BALANCE_KEY, total_at + BALANCE_KEY_PATH.len()) else {
        return false;
    };
    let mut value_start = pos_at + BALANCE_KEY.len();
    while received.get(value_start) == Some(&b' ') {
        value_start += 1;
    }
    value_start == committed_start
}

fn find_sub(haystack: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}
