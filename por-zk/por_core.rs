// Core proof-of-reserves proving flow, shared by the `por_prove` CLI and the
// `por_service` web service.
//
// Runs MPC-TLS to live api.zerion.io jointly with a SEPARATE notary, commits the
// transcript (SHA256), obtains a notary-signed `Attestation` (carrying any extra
// `request_extensions`, e.g. a SIWE proof), and produces a portable bundle:
// a `Presentation` (request minus API key, response minus balance) plus a ZK
// proof that floor(balance) >= threshold — without revealing the balance.

#![allow(dead_code)]

use std::future::IntoFuture;

use anyhow::{Result, anyhow};
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use http_body_util::Empty;
use hyper::{Request, StatusCode, body::Bytes, header};
use hyper_util::rt::TokioIo;
use spansy::{
    http::{BodyContent, Requests, Responses},
    json::JsonValue,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tracing::{info, instrument};

use tlsn::{
    Session,
    attestation::{
        Attestation, CryptoProvider, Extension, Secrets,
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
    rangeset::{
        iter::{IntoRangeIterator, RangeIterator},
        ops::Set,
        set::RangeSet,
    },
    transcript::{
        Direction, TranscriptCommitConfig, TranscriptCommitmentKind, TranscriptSecret,
        hash::PlaintextHashSecret,
    },
    webpki::RootCertStore,
};
use tlsn_formats::http::{DefaultHttpCommitter, HttpCommit, HttpTranscript};

use crate::por_zk::{self, ZKProofBundle};
use crate::types::received_commitments;

pub const SERVER_DOMAIN: &str = "api.zerion.io";
pub const SERVER_PORT: u16 = 443;
/// JSON path of the cross-chain USD balance in a Zerion portfolio response.
pub const BALANCE_FIELD: &str = "data.attributes.total.positions";

const MAX_SENT_DATA: usize = 1 << 12;
const MAX_RECV_DATA: usize = 1 << 16;

/// Prove that `wallet`'s Zerion portfolio holds >= `threshold` USD.
///
/// * `auth_b64` is the base64 of `"{ZERION_API_KEY}:"` (HTTP Basic).
/// * `request_extensions` are attached to the attestation request and signed by
///   the notary (e.g. a SIWE ownership proof).
#[instrument(skip(notary_socket, auth_b64, request_extensions))]
pub async fn prove<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    notary_socket: S,
    wallet: &str,
    threshold: u64,
    auth_b64: String,
    request_extensions: Vec<Extension>,
) -> Result<(Presentation, ZKProofBundle)> {
    let path = format!("/v1/wallets/{wallet}/portfolio");

    // --- Session with the (remote, independent) notary ---
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

    // --- MPC-TLS to live Zerion ---
    let client_socket = tokio::net::TcpStream::connect((SERVER_DOMAIN, SERVER_PORT)).await?;
    client_socket.set_nodelay(true)?;
    let (tls_connection, prover) = prover.connect(
        TlsClientConfig::builder()
            .server_name(ServerName::Dns(SERVER_DOMAIN.try_into()?))
            .root_store(RootCertStore::mozilla())
            .build()?,
        client_socket.compat(),
    )?;
    let tls_connection = TokioIo::new(tls_connection.compat());
    let prover_task = tokio::spawn(prover.into_future());

    let (mut request_sender, connection) =
        hyper::client::conn::http1::handshake(tls_connection).await?;
    tokio::spawn(connection);

    let request = Request::builder()
        .uri(&path)
        .header("Host", SERVER_DOMAIN)
        .header("Accept", "application/json")
        .header("Accept-Encoding", "identity")
        .header("Connection", "close")
        .header("User-Agent", "tlsn-por/0.1")
        .header(header::AUTHORIZATION, format!("Basic {auth_b64}"))
        .method("GET")
        .body(Empty::<Bytes>::new())?;

    info!("requesting https://{SERVER_DOMAIN}{path}");
    let response = request_sender.send_request(request).await?;
    info!("response status: {}", response.status());
    if response.status() != StatusCode::OK {
        return Err(anyhow!(
            "Zerion returned {} (need a 200 with a balance)",
            response.status()
        ));
    }

    let mut prover = prover_task.await??;

    let received_owned = prover.transcript().received().to_vec();
    let (balance_start, balance_end) = balance_range(&received_owned)?;

    // --- Commit the whole transcript (SHA256) + the balance field explicitly ---
    let transcript = HttpTranscript::parse(prover.transcript())?;
    let mut commit_builder = TranscriptCommitConfig::builder(prover.transcript());
    commit_builder.default_kind(TranscriptCommitmentKind::Hash {
        alg: HashAlgId::SHA256,
    });
    DefaultHttpCommitter::default().commit_transcript(&mut commit_builder, &transcript)?;
    commit_builder.commit_recv(&locate_balance(&received_owned)?)?;
    let transcript_commit = commit_builder.build()?;

    // Attestation request config: transcript commitments + caller extensions.
    let mut rc = RequestConfig::builder();
    rc.transcript_commit(transcript_commit);
    for ext in request_extensions {
        rc.extension(ext);
    }
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

    // --- Select the balance commitment (idx == total.positions value) ---
    let (balance_bytes, blinder, committed_hash) = {
        let commitment = received_commitments(&transcript_commitments)
            .into_iter()
            .find(|c| c.idx.min() == Some(balance_start) && c.idx.end() == Some(balance_end))
            .ok_or_else(|| anyhow!("no SHA256 commitment matches the balance field range"))?;
        let secret = received_secrets(&transcript_secrets)
            .into_iter()
            .find(|s| s.idx.min() == Some(balance_start) && s.idx.end() == Some(balance_end))
            .ok_or_else(|| anyhow!("no secret matches the balance field range"))?;
        (
            prover_transcript.received()[balance_start..balance_end].to_vec(),
            secret.blinder.as_bytes().to_vec(),
            commitment.hash.value.as_bytes().to_vec(),
        )
    };

    let received_ranges: Vec<RangeSet<usize>> = received_commitments(&transcript_commitments)
        .into_iter()
        .map(|c| c.idx.clone())
        .collect();
    let balance_set: RangeSet<usize> = RangeSet::from(balance_start..balance_end);

    // --- Get the signed attestation from the notary ---
    let mut builder = AttestationRequest::builder(&request_config);
    builder
        .server_name(ServerName::Dns(SERVER_DOMAIN.try_into().unwrap()))
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

    let zk = por_zk::generate_proof(&balance_bytes, &blinder, &committed_hash, threshold)?;
    info!("✅ ZK proof generated; balance value never leaves this process");

    let presentation = build_presentation(&attestation, &secrets, &received_ranges, &balance_set)?;
    Ok((presentation, zk))
}

fn balance_range(received: &[u8]) -> Result<(usize, usize)> {
    let balance = locate_balance(received)?;
    let ranges: RangeSet<usize> = (&balance).into_range_iter().collect();
    let start = ranges.min().ok_or_else(|| anyhow!("empty balance range"))?;
    let end = ranges.end().ok_or_else(|| anyhow!("empty balance range"))?;
    Ok((start, end))
}

fn locate_balance(received: &[u8]) -> Result<JsonValue> {
    let resps = Responses::new_from_slice(received).collect::<Result<Vec<_>, _>>()?;
    let response = resps.into_iter().next().ok_or_else(|| anyhow!("no response"))?;
    let body = response.body.ok_or_else(|| anyhow!("no response body"))?;
    let BodyContent::Json(doc) = body.content else {
        return Err(anyhow!("response body is not JSON"));
    };
    doc.get(BALANCE_FIELD)
        .cloned()
        .ok_or_else(|| anyhow!("field `{BALANCE_FIELD}` not found"))
}

fn build_presentation(
    attestation: &Attestation,
    secrets: &Secrets,
    received_ranges: &[RangeSet<usize>],
    balance: &RangeSet<usize>,
) -> Result<Presentation> {
    let transcript = secrets.transcript();
    let sent = transcript.sent().to_vec();

    let mut builder = secrets.transcript_proof_builder();

    // Request: reveal everything except the Authorization value.
    let reqs = Requests::new_from_slice(&sent).collect::<Result<Vec<_>, _>>()?;
    let req = reqs.first().ok_or_else(|| anyhow!("no request"))?;
    if let Some(auth) = req.headers_with_name(header::AUTHORIZATION.as_str()).next() {
        builder.reveal_sent(req.into_range_iter().difference(&auth.value))?;
    } else {
        builder.reveal_sent(req.into_range_iter())?;
    }

    // Response: open only committed ranges DISJOINT from the balance, in full.
    // (A hash commitment can only be opened wholesale; ranges overlapping the
    // balance — the whole-response commit, the balance value — are skipped.)
    let mut revealed = 0usize;
    let mut skipped = 0usize;
    for range in received_ranges {
        let without_balance: RangeSet<usize> = range.difference(balance).collect();
        if &without_balance != range {
            skipped += 1;
            continue;
        }
        match builder.reveal_recv(range.clone()) {
            Ok(_) => revealed += 1,
            Err(_) => skipped += 1,
        }
    }
    info!("revealed {revealed} committed response ranges, skipped {skipped} (balance redacted)");

    let transcript_proof = builder.build()?;

    let provider = CryptoProvider::default();
    let mut pb = attestation.presentation_builder(&provider);
    pb.identity_proof(secrets.identity_proof())
        .transcript_proof(transcript_proof);
    Ok(pb.build()?)
}

fn received_secrets(secrets: &[TranscriptSecret]) -> Vec<&PlaintextHashSecret> {
    secrets
        .iter()
        .filter_map(|s| match s {
            TranscriptSecret::Hash(h) if h.direction == Direction::Received => Some(h),
            _ => None,
        })
        .collect()
}
