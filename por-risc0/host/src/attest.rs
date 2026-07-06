// TLSNotary attestation of `debug_getRawHeader(N)` to a named RPC.
//
// MPC-TLS the request jointly with a SEPARATE notary (split session keys), then
// reveal the WHOLE transcript (there is no API key or secret in this call) and
// return a bincode-serialized `Presentation`. Because N is a pinned finalized
// block, the attested header RLP is byte-identical to the one the prover used, so
// the verifier can keccak the revealed response to recover block_hash and match it
// to the Risc0 journal. Ported from por-zk's `por_core` (Noir parts removed).
use std::future::IntoFuture;

use anyhow::{anyhow, bail, Result};
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::Full;
use hyper::{body::Bytes, Request, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::json;
use spansy::http::Requests;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};

use tlsn::{
    attestation::{
        presentation::Presentation,
        request::{Request as AttestationRequest, RequestConfig},
        Attestation, CryptoProvider, Secrets,
    },
    config::{
        prove::ProveConfig, prover::ProverConfig, tls::TlsClientConfig,
        tls_commit::mpc::MpcTlsConfig,
    },
    connection::{HandshakeData, ServerName},
    hash::HashAlgId,
    prover::ProverOutput,
    rangeset::{iter::IntoRangeIterator, set::RangeSet},
    transcript::{
        hash::PlaintextHash, Direction, TranscriptCommitConfig, TranscriptCommitment,
        TranscriptCommitmentKind,
    },
    webpki::RootCertStore,
    Session,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};

const SERVER_PORT: u16 = 443;
const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 16;

fn received_commitments(tc: &[TranscriptCommitment]) -> Vec<&PlaintextHash> {
    tc.iter()
        .filter_map(|c| match c {
            TranscriptCommitment::Hash(h) if h.direction == Direction::Received => Some(h),
            _ => None,
        })
        .collect()
}

/// MPC-TLS-attest `debug_getRawHeader(block_hex)` to `rpc_host` via the notary at
/// `notary_addr`. Returns `bincode(Presentation)`.
pub async fn attest_header(notary_addr: &str, rpc_host: &str, block_hex: &str) -> Result<Vec<u8>> {
    let notary_socket = tokio::net::TcpStream::connect(notary_addr)
        .await
        .map_err(|e| anyhow!("connect notary {notary_addr}: {e}"))?;
    notary_socket.set_nodelay(true)?;

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
        .header("user-agent", "tlsn-por-risc0/0.1")
        .body(Full::<Bytes>::new(Bytes::from(rpc_body)))?;

    let response = request_sender.send_request(request).await?;
    if response.status() != StatusCode::OK {
        bail!("{rpc_host} returned {} for debug_getRawHeader", response.status());
    }

    let mut prover = prover_task.await??;

    // Commit the whole transcript (SHA256); reveal everything.
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

    // Notary-signed attestation.
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

    let presentation = build_presentation(&attestation, &secrets, &received_ranges)?;
    Ok(bincode::serialize(&presentation)?)
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
    let reqs = Requests::new_from_slice(&sent).collect::<Result<Vec<_>, _>>()?;
    let req = reqs.first().ok_or_else(|| anyhow!("no request"))?;
    builder.reveal_sent(req.into_range_iter())?;
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
