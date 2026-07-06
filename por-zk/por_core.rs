// Core proof-of-reserves proving flow, shared by the `por_prove` CLI and the
// `por_service` web service.
//
// NEW (state-proof) design:
//   * Off-channel (plain HTTPS via curl), for a PINNED finalized block N:
//       - debug_getRawHeader(N) -> the raw block-header RLP (also the ATTESTED call)
//       - eth_getProof(address, [], N) -> the account-trie Merkle proof
//   * MPC-TLS to the same RPC jointly with a SEPARATE notary, requesting
//     debug_getRawHeader(N) again and revealing the WHOLE transcript (there is no
//     API key or secret to hide). Because N is pinned, the attested header RLP is
//     byte-identical to the off-channel one, so the verifier can keccak the
//     attested response to recover block_hash and match it to the ZK proof.
//   * A Noir/UltraHonk proof that, against that header's state_root, the account
//     balance >= threshold (and, unless debug, that the prover controls the
//     address) -- WITHOUT revealing the balance or the address.
//
// Returns a portable bundle: a `Presentation` (full request + response) plus the
// ZK proof, and the block number used.

#![allow(dead_code)]

use std::future::IntoFuture;

use anyhow::{Result, anyhow, bail};
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::Full;
use hyper::{Request, StatusCode, body::Bytes};
use hyper_util::rt::TokioIo;
use serde_json::json;
use spansy::http::Requests;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{info, instrument};

use tlsn::{
    Session,
    attestation::{
        Attestation, CryptoProvider, Secrets,
        presentation::Presentation,
        request::{Request as AttestationRequest, RequestConfig},
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig,
    },
    connection::{HandshakeData, ServerName},
    hash::HashAlgId,
    prover::ProverOutput,
    rangeset::{iter::IntoRangeIterator, set::RangeSet},
    transcript::{TranscriptCommitConfig, TranscriptCommitmentKind},
    webpki::RootCertStore,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};

use crate::por_witness::{self, Ownership};
use crate::por_zk::{self, ZKProofBundle};
use crate::types::received_commitments;

pub const SERVER_PORT: u16 = 443;
/// The only operator (of our allowlist) exposing `debug_getRawHeader`, which lets
/// us attest a ~530-byte header RLP instead of a ~21 KB block.
pub const DEFAULT_RPC_HOST: &str = "eth.drpc.org";
pub const ETHEREUM_MAINNET_CHAIN_ID: u32 = 1;

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 16;

/// How the prover establishes control of the (hidden) address.
pub enum Owner {
    /// Skip the ownership check (sets the circuit's `debug` public input). For
    /// testing the state-proof/threshold path without a wallet signature.
    Debug,
    /// Sign `personal_sign(block_hash)` locally with this secp256k1 private key.
    LocalKey([u8; 32]),
    /// The caller already signed `block_hash` (e.g. a browser wallet). The caller
    /// is responsible for pinning the same block via `block_number`.
    PreSigned(Ownership),
}

/// Prove that `address` holds >= `threshold` wei at a recent finalized block on
/// `chain_id`, attested via MPC-TLS to `rpc_host` and proven in zero knowledge.
#[instrument(skip(notary_socket, owner))]
pub async fn prove<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    notary_socket: S,
    rpc_host: &str,
    address: [u8; 20],
    threshold: u128,
    chain_id: u32,
    owner: Owner,
    block_number: Option<u64>,
) -> Result<(Presentation, ZKProofBundle, u64)> {
    let rpc_url = format!("https://{rpc_host}");

    // --- 1. Pin the block (finalized unless caller specified one) ---
    let block = match block_number {
        Some(n) => n,
        None => {
            let fin = rpc_call(&rpc_url, "eth_getBlockByNumber", json!(["finalized", false]))?;
            let h = fin["number"]
                .as_str()
                .ok_or_else(|| anyhow!("finalized block has no number"))?;
            u64::from_str_radix(h.trim_start_matches("0x"), 16)?
        }
    };
    let block_hex = format!("0x{block:x}");
    info!("proving reserves at mainnet block {block}");

    // --- 2. Off-channel header RLP + account proof for the pinned block ---
    let raw = rpc_call(&rpc_url, "debug_getRawHeader", json!([block_hex]))?;
    let raw = raw
        .as_str()
        .ok_or_else(|| anyhow!("debug_getRawHeader did not return a hex string"))?;
    let header_rlp = hex::decode(raw.trim_start_matches("0x"))?;

    let addr_hex = format!("0x{}", hex::encode(address));
    let eth_proof = rpc_call(
        &rpc_url,
        "eth_getProof",
        json!([addr_hex, Vec::<String>::new(), block_hex]),
    )?;

    let block_hash = por_witness::keccak256(&header_rlp);

    // --- 3. Resolve ownership against THIS block_hash ---
    let (debug, ownership) = match owner {
        Owner::Debug => (true, None),
        Owner::LocalKey(sk) => (false, Some(sign_ownership(&sk, &block_hash)?)),
        Owner::PreSigned(o) => (false, Some(o)),
    };

    // --- 4. Build the witness and the ZK proof (balance & address stay hidden) ---
    let witness = por_witness::build_witness(
        &eth_proof,
        &header_rlp,
        threshold,
        chain_id,
        debug,
        ownership.as_ref(),
    )?;
    let zk = por_zk::prove_witness(witness)?;
    info!("✅ ZK proof generated; balance and address never leave this process");

    // --- 5. Attest debug_getRawHeader(N) over MPC-TLS with the notary ---
    let session = Session::new(notary_socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    let prover = handle
        .new_prover(ProverConfig::builder().build()?)?
        .commit(
            MpcTlsConfig::builder()
                .max_sent_data(MAX_SENT_DATA)
                .max_recv_data(MAX_RECV_DATA)
                .build()?,
        )
        .await?;

    let client_socket = tokio::net::TcpStream::connect((rpc_host, SERVER_PORT)).await?;
    client_socket.set_nodelay(true)?;
    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(rpc_host.try_into()?))
            .root_store(RootCertStore::mozilla())
            .build()?,
        client_socket.compat(),
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());
    let prover_task = tokio::spawn(prover.into_future());

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    let rpc_body = json!({
        "jsonrpc": "2.0", "id": 1, "method": "debug_getRawHeader", "params": [block_hex]
    })
    .to_string();
    let request = Request::builder()
        .uri("/")
        .method("POST")
        .header("Host", rpc_host)
        .header("content-type", "application/json")
        .header("accept-encoding", "identity")
        .header("connection", "close")
        .header("user-agent", "tlsn-por/0.2")
        .body(Full::<Bytes>::new(Bytes::from(rpc_body)))?;

    info!("MPC-TLS POST debug_getRawHeader to https://{rpc_host}");
    let response = request_sender.send_request(request).await?;
    info!("response status: {}", response.status());
    if response.status() != StatusCode::OK {
        bail!("{rpc_host} returned {} for debug_getRawHeader", response.status());
    }

    let mut prover = prover_task.await??;

    // --- Commit the whole transcript (SHA256); reveal everything ---
    let transcript = HttpTranscript::parse(prover.transcript())?;
    let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
    commit_builder.default_kind(TranscriptCommitmentKind::Hash {
        alg: HashAlgId::SHA256,
    });
    DefaultHttpCommitter::default().commit_transcript(&mut commit_builder, &transcript)?;
    let transcript_commit = commit_builder.build()?;

    let mut rc = RequestConfig::builder();
    rc.transcript_commit(transcript_commit);
    let request_config = rc.build()?;

    let mut pc = ProveConfig::builder(prover.transcript());
    if let Some(cfg) = request_config.transcript_commit() {
        pc.transcript_commit(cfg.clone());
    }
    let disclosure_config = pc.build()?;

    let ProverOutput {
        transcript_commitments,
        transcript_secrets,
        ..
    } = prover.prove(&disclosure_config).await?;

    let prover_transcript = prover.transcript().clone();
    let tls_transcript = prover.tls_transcript().clone();
    prover.close().await?;

    let received_ranges: Vec<RangeSet<usize>> = received_commitments(&transcript_commitments)
        .into_iter()
        .map(|c| c.idx.clone())
        .collect();

    // --- Notary-signed attestation ---
    let mut builder = AttestationRequest::builder(&request_config);
    builder
        .server_name(ServerName::Dns(rpc_host.try_into().unwrap()))
        .handshake_data(HandshakeData {
            certs: tls_transcript
                .server_cert_chain()
                .expect("server cert chain present")
                .to_vec(),
            sig: tls_transcript
                .server_signature()
                .expect("server signature present")
                .clone(),
            binding: tls_transcript.certificate_binding().clone(),
        })
        .transcript(prover_transcript)
        .transcript_commitments(transcript_secrets, transcript_commitments);
    let (att_request, secrets) = builder.build(&CryptoProvider::default())?;

    handle.close();
    let mut socket = driver_task.await??;
    socket.write_all(&bincode::serialize(&att_request)?).await?;
    socket.close().await?;
    let mut attestation_bytes = Vec::new();
    socket.read_to_end(&mut attestation_bytes).await?;
    let attestation: Attestation = bincode::deserialize(&attestation_bytes)?;

    let provider = CryptoProvider::default();
    att_request.validate(&attestation, &provider)?;
    info!("attestation issued by the notary and validated");

    let presentation = build_presentation(&attestation, &secrets, &received_ranges)?;
    Ok((presentation, zk, block))
}

/// Reveal the WHOLE transcript (no secrets in a debug_getRawHeader exchange).
fn build_presentation(
    attestation: &Attestation,
    secrets: &Secrets,
    received_ranges: &[RangeSet<usize>],
) -> Result<Presentation> {
    let transcript = secrets.transcript();
    let sent = transcript.sent().to_vec();

    let mut builder = secrets.transcript_proof_builder();

    // Request: reveal everything (no Authorization header to redact).
    let reqs = Requests::new_from_slice(&sent).collect::<Result<Vec<_>, _>>()?;
    let req = reqs.first().ok_or_else(|| anyhow!("no request"))?;
    builder.reveal_sent(req.into_range_iter())?;

    // Response: reveal every committed range in full.
    for range in received_ranges {
        let _ = builder.reveal_recv(range.clone());
    }

    let transcript_proof = builder.build()?;
    let provider = CryptoProvider::default();
    let mut pb = attestation.presentation_builder(&provider);
    pb.identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    Ok(pb.build()?)
}

/// Off-channel JSON-RPC via `curl` (the crate has no TLS HTTP client; these calls
/// carry no secret and their integrity is enforced cryptographically downstream:
/// the proof is checked against the header state_root, and the header is attested
/// separately over MPC-TLS).
fn rpc_call(url: &str, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).to_string();
    let out = std::process::Command::new("curl")
        .args([
            "-s",
            "-X",
            "POST",
            "-H",
            "content-type: application/json",
            "-H",
            "accept-encoding: identity",
            "-H",
            "user-agent: tlsn-por/0.2",
            "--data",
            &body,
            url,
        ])
        .output()
        .map_err(|e| anyhow!("curl spawn failed: {e}"))?;
    if !out.status.success() {
        bail!("curl failed: {}", String::from_utf8_lossy(&out.stderr));
    }
    let resp: serde_json::Value = serde_json::from_slice(&out.stdout)
        .map_err(|e| anyhow!("RPC response not JSON ({e})"))?;
    if let Some(e) = resp.get("error") {
        bail!("RPC error from {method}: {e}");
    }
    resp.get("result")
        .cloned()
        .ok_or_else(|| anyhow!("RPC {method}: no result field"))
}

/// Sign `personal_sign(block_hash)` with a local secp256k1 key, producing the
/// in-circuit ownership witness (pubkey + low-s signature).
fn sign_ownership(sk_bytes: &[u8; 32], block_hash: &[u8; 32]) -> Result<Ownership> {
    use k256::ecdsa::signature::hazmat::PrehashSigner;
    use k256::ecdsa::{Signature, SigningKey};
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    let sk = SigningKey::from_slice(sk_bytes).map_err(|e| anyhow!("bad signing key: {e}"))?;
    let pt = sk.verifying_key().to_encoded_point(false); // 0x04 || x || y
    let pb = pt.as_bytes();
    let mut pubkey_x = [0u8; 32];
    let mut pubkey_y = [0u8; 32];
    pubkey_x.copy_from_slice(&pb[1..33]);
    pubkey_y.copy_from_slice(&pb[33..65]);

    let mut msg = Vec::with_capacity(60);
    msg.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
    msg.extend_from_slice(block_hash);
    let digest = por_witness::keccak256(&msg);

    let sig: Signature = sk
        .sign_prehash(&digest)
        .map_err(|e| anyhow!("sign failed: {e}"))?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&sig.to_bytes());

    Ok(Ownership {
        pubkey_x,
        pubkey_y,
        signature,
    })
}
