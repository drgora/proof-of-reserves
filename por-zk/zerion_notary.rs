// Standalone TLSNotary *notary* process.
//
// Listens on TCP; for each prover connection it runs the verifier-as-notary
// MPC role and issues a signed `Attestation`. It holds its OWN secp256k1
// signing key (persisted to disk) that the prover never sees. THAT is what
// makes it a separate trust domain — the prover and notary are distinct
// processes with split TLS session keys.
//
// Run:  NOTARY_ADDR=127.0.0.1:7150 RUST_LOG=info \
//         cargo run --release --manifest-path por-zk/Cargo.toml --bin zerion_notary

use std::{env, fs, io::Read};

use anyhow::Result;
use futures::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_util::compat::TokioAsyncReadCompatExt;
use tracing::{info, warn};

use tlsn::{
    Session,
    attestation::{
        Attestation, AttestationConfig, CryptoProvider, Extension,
        request::Request as AttestationRequest, signing::Secp256k1Signer,
    },
    config::verifier::VerifierConfig,
    connection::{CertBinding, ConnectionInfo, TranscriptLength},
    hash::HashAlgId,
    transcript::{ContentType, Direction, TranscriptCommitment},
    verifier::{VerifierCommitStart, VerifierOutput},
    webpki::RootCertStore,
};

const KEY_PATH: &str = "notary-signing-key.bin";

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let addr = env::var("NOTARY_ADDR").unwrap_or_else(|_| "127.0.0.1:7150".into());
    let signing_key = load_or_create_key()?;
    info!("notary verifying key: {:?}", signing_key.verifying_key());
    info!("⚠️  this signing key is the notary's identity; the prover never holds it");

    let listener = TcpListener::bind(&addr).await?;
    info!("notary listening on {addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        info!("prover connected from {peer}");
        let key = signing_key.clone();
        tokio::spawn(async move {
            stream.set_nodelay(true).ok();
            match run_notary(stream, key).await {
                Ok(()) => info!("attestation issued to {peer}"),
                Err(e) => warn!("notary session with {peer} failed: {e:#}"),
            }
        });
    }
}

/// Load the notary's signing key from disk, or generate a fresh independent one.
fn load_or_create_key() -> Result<k256::ecdsa::SigningKey> {
    if let Ok(bytes) = fs::read(KEY_PATH) {
        if bytes.len() == 32 {
            if let Ok(k) = k256::ecdsa::SigningKey::from_slice(&bytes) {
                return Ok(k);
            }
        }
    }
    let mut urandom = fs::File::open("/dev/urandom")?;
    let key = loop {
        let mut buf = [0u8; 32];
        urandom.read_exact(&mut buf)?;
        if let Ok(k) = k256::ecdsa::SigningKey::from_slice(&buf) {
            break k;
        }
    };
    fs::write(KEY_PATH, key.to_bytes().as_slice())?;
    info!("generated a new notary signing key at {KEY_PATH}");
    Ok(key)
}

async fn run_notary<S: AsyncWrite + AsyncRead + Send + Sync + Unpin + 'static>(
    socket: S,
    signing_key: k256::ecdsa::SigningKey,
) -> Result<()> {
    let session = Session::new(socket.compat());
    let (driver, mut handle) = session.split();
    let driver_task = tokio::spawn(driver);

    // Verify the real server's cert chain during MPC against the public roots.
    let verifier_config = VerifierConfig::builder()
        .root_store(RootCertStore::mozilla())
        .build()?;

    let verifier = match handle.new_verifier(verifier_config)?.commit().await? {
        VerifierCommitStart::Mpc(verifier) => verifier.accept().await?.run().await?,
        VerifierCommitStart::Proxy(verifier) => {
            verifier.reject(Some("expecting to use MPC-TLS")).await?;
            return Err(anyhow::anyhow!("protocol configuration rejected"));
        }
    };

    let (
        VerifierOutput {
            transcript_commitments,
            ..
        },
        verifier,
    ) = verifier.verify().await?.accept().await?;

    let tls_transcript = verifier.tls_transcript().clone();
    verifier.close().await?;

    let sent_len = tls_transcript
        .sent()
        .iter()
        .filter_map(|record| match record.typ {
            ContentType::ApplicationData => Some(record.ciphertext.len()),
            _ => None,
        })
        .sum::<usize>();
    let recv_len = tls_transcript
        .recv()
        .iter()
        .filter_map(|record| match record.typ {
            ContentType::ApplicationData => Some(record.ciphertext.len()),
            _ => None,
        })
        .sum::<usize>();

    handle.close();
    let mut socket = driver_task.await??;

    // Receive the attestation request from the prover.
    let mut request_bytes = Vec::new();
    socket.read_to_end(&mut request_bytes).await?;
    let request: AttestationRequest = bincode::deserialize(&request_bytes)?;

    // Sign with the notary's own key.
    let signer = Box::new(Secp256k1Signer::new(&signing_key.to_bytes())?);
    let mut provider = CryptoProvider::default();
    provider.signer.set_signer(signer);

    let mut att_config_builder = AttestationConfig::builder();
    att_config_builder.supported_signature_algs(Vec::from_iter(provider.signer.supported_algs()));
    // Accept the notary's own commitment-disclosure extension (added below).
    att_config_builder.extension_validator(|_| Ok(()));
    let att_config = att_config_builder.build()?;

    // Surface the received SHA256 commitments (hash + byte range) the notary
    // witnessed, as a SIGNED extension. This lets an offline verifier bind a ZK
    // proof to a notary-vouched commitment via the PUBLIC presentation API,
    // rather than reading tlsn's internal attestation fields. The notary stays
    // content-blind: the hashes are blinded and reveal nothing about the values.
    let recv_commitments: Vec<(Vec<u8>, u64, u64)> = transcript_commitments
        .iter()
        .filter_map(|c| match c {
            TranscriptCommitment::Hash(h)
                if h.direction == Direction::Received && h.hash.alg == HashAlgId::SHA256 =>
            {
                Some((
                    h.hash.value.as_bytes().to_vec(),
                    h.idx.min()? as u64,
                    h.idx.end()? as u64,
                ))
            }
            _ => None,
        })
        .collect();
    let commitments_ext = Extension {
        id: b"por.recv_commitments".to_vec(),
        value: bincode::serialize(&recv_commitments)?,
    };

    let CertBinding::V1_2(binding) = tls_transcript.certificate_binding() else {
        return Err(anyhow::anyhow!("unsupported cert binding version"));
    };
    let mut builder = Attestation::builder(&att_config).accept_request(request)?;
    builder
        .connection_info(ConnectionInfo {
            time: tls_transcript.time(),
            version: tls_transcript.version(),
            transcript_length: TranscriptLength {
                sent: sent_len as u32,
                received: recv_len as u32,
            },
        })
        .server_ephemeral_key(binding.server_ephemeral_key.clone())
        .transcript_commitments(transcript_commitments)
        .extension(commitments_ext);

    let attestation = builder.build(&provider)?;

    // Send the signed attestation back to the prover.
    let attestation_bytes = bincode::serialize(&attestation)?;
    socket.write_all(&attestation_bytes).await?;
    socket.close().await?;

    Ok(())
}
