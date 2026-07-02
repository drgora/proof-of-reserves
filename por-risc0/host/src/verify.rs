//! Shared PoR verification: Risc0 receipt + journal decode, TLSNotary presentation
//! binding, policy enforcement, and Kurier/zkVerify submission.
//!
//! These were extracted verbatim from the old `por_verify` binary and turned into
//! `Result`-returning functions so BOTH the offline `por_verify` CLI and the `verifier`
//! HTTP service can call them (a service can't `panic!`/`process::exit` per request).

use alloy_rlp::{Decodable, Header as RlpHeader};
use anyhow::{anyhow, bail, Context, Result};
use base64::Engine as _;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use methods::POR_GUEST_ID;
use risc0_zkvm::Receipt;
use serde_json::Value;
use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;
use tiny_keccak::{Hasher, Keccak};

use tlsn::{
    attestation::{
        presentation::{Presentation, PresentationOutput},
        CryptoProvider,
    },
    connection::ServerName,
    verifier::ServerCertVerifier,
};

pub const RPC_URL: &str = "https://eth.drpc.org";
/// The RPC the notary must have witnessed (the cert identifies the operator, not the
/// chain -- chain identity rests on this allowlist + the pinned block).
pub const EXPECTED_SERVER: &str = "eth.drpc.org";

pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    let mut o = [0u8; 32];
    k.update(data);
    k.finalize(&mut o);
    o
}

/// The decoded public journal committed by the guest (125 bytes, positional).
#[derive(Debug, Clone)]
pub struct Journal {
    pub block_hash: [u8; 32],
    pub threshold: u128,
    pub chain_id: u32,
    pub debug: bool,
    pub challenge_nonce: [u8; 32],
    /// keccak256(registry agent id)
    pub agent_id: [u8; 32],
    pub block_number: u64,
    /// marketplace ERC-721 token id (HL ValidationGatewayV2 agentId binding)
    pub agent_token_id: u64,
    /// keccak256(agent_secret) as [u64;4] limbs (gateway identity binding)
    pub identity: [u64; 4],
}

/// Decode the CBOR receipt out of a `proof.json`-shaped bundle (`proofData.proof`).
pub fn decode_receipt(bundle: &Value) -> Result<Receipt> {
    let hexs = bundle["proofData"]["proof"]
        .as_str()
        .ok_or_else(|| anyhow!("proofData.proof missing / not a string"))?;
    let cbor = hex::decode(hexs.trim_start_matches("0x")).context("decode receipt hex")?;
    ciborium::from_reader(&cbor[..]).context("decode CBOR receipt")
}

/// Verify the receipt against the guest image id.
pub fn verify_receipt(receipt: &Receipt) -> Result<()> {
    receipt
        .verify(POR_GUEST_ID)
        .map_err(|e| anyhow!("receipt invalid: {e}"))
}

/// Decode the public journal (the guest's `env::commit` sequence, positional).
pub fn decode_journal(receipt: &Receipt) -> Result<Journal> {
    let (
        block_hash,
        threshold,
        chain_id,
        debug,
        challenge_nonce,
        agent_id,
        block_number,
        agent_token_id,
        identity,
    ): ([u8; 32], u128, u32, bool, [u8; 32], [u8; 32], u64, u64, [u64; 4]) = receipt
        .journal
        .decode()
        .map_err(|e| anyhow!("decode journal: {e}"))?;
    Ok(Journal {
        block_hash,
        threshold,
        chain_id,
        debug,
        challenge_nonce,
        agent_id,
        block_number,
        agent_token_id,
        identity,
    })
}

fn find_sub(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    if needle.is_empty() || from >= hay.len() {
        return None;
    }
    hay[from..]
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| from + p)
}

/// Recover the raw header RLP from the revealed JSON-RPC response: find `result`, then the
/// following `0x`, then read hex digits (robust to whitespace / chunk framing).
pub fn extract_header_rlp(recv: &[u8]) -> Option<Vec<u8>> {
    let r = find_sub(recv, b"result", 0)?;
    let zerox = find_sub(recv, b"0x", r)?;
    let mut end = zerox + 2;
    while end < recv.len() && recv[end].is_ascii_hexdigit() {
        end += 1;
    }
    hex::decode(&recv[zerox + 2..end]).ok()
}

/// A verified TLSNotary presentation: the recovered header RLP + who attested it.
pub struct AttestedHeader {
    pub header_rlp: Vec<u8>,
    pub server: String,
    pub notary_key_hex: String,
    pub time: u64,
}

/// Verify a TLSNotary presentation: notary signature + Mozilla cert chain + Host allowlist,
/// then recover the header RLP from the revealed response. Does NOT bind to a block hash --
/// call [`bind_block_hash`] with the caller's expected hash.
pub fn verify_presentation(b64: &str) -> Result<AttestedHeader> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .context("decode tlsnPresentation base64")?;
    let presentation: Presentation =
        bincode::deserialize(&bytes).context("deserialize Presentation")?;

    let provider = CryptoProvider {
        cert: ServerCertVerifier::mozilla(),
        ..Default::default()
    };
    let notary_key_hex = hex::encode(presentation.verifying_key().data.clone());

    let PresentationOutput {
        server_name,
        transcript,
        connection_info,
        ..
    } = presentation
        .verify(&provider)
        .map_err(|e| anyhow!("presentation invalid (notary signature / cert chain): {e}"))?;

    let server_name = server_name.ok_or_else(|| anyhow!("server name not disclosed"))?;
    let ServerName::Dns(ref dns) = server_name;
    if dns.as_str() != EXPECTED_SERVER {
        bail!(
            "unexpected server {} (Host allowlist requires {EXPECTED_SERVER})",
            dns.as_str()
        );
    }

    let partial = transcript.ok_or_else(|| anyhow!("transcript not disclosed"))?;
    let received = partial.received_unsafe();
    let header_rlp =
        extract_header_rlp(received).ok_or_else(|| anyhow!("no header RLP in attested response"))?;

    Ok(AttestedHeader {
        header_rlp,
        server: dns.as_str().to_string(),
        notary_key_hex,
        time: connection_info.time,
    })
}

/// Bind an attested/fetched header to a journal's committed block hash.
pub fn bind_block_hash(header_rlp: &[u8], expected_block_hash: &[u8; 32]) -> Result<()> {
    if &keccak256(header_rlp) != expected_block_hash {
        bail!("BINDING FAILED: keccak(attested header) != journal block_hash");
    }
    Ok(())
}

/// Extract the block number (RLP item index 8) from a raw header, so the verifier can check
/// which block an attested header actually is. Mirrors the guest's header walk.
pub fn header_block_number(header_rlp: &[u8]) -> Result<u64> {
    let mut buf: &[u8] = header_rlp;
    let outer = RlpHeader::decode(&mut buf).map_err(|e| anyhow!("header rlp: {e}"))?;
    if !outer.list {
        bail!("header is not an RLP list");
    }
    // skip items 0..=7 (parent_hash .. difficulty)
    for _ in 0..8 {
        let h = RlpHeader::decode(&mut buf).map_err(|e| anyhow!("skip header item: {e}"))?;
        buf = buf
            .get(h.payload_length..)
            .ok_or_else(|| anyhow!("header truncated"))?;
    }
    // item 8: number
    u64::decode(&mut buf).map_err(|e| anyhow!("decode block number: {e}"))
}

/// Recover the signer's Ethereum address from a 65-byte (r||s||v) recoverable signature over
/// a 32-byte prehash. Used to authenticate the owner-challenge signature.
pub fn recover_address_from_prehash(prehash: &[u8; 32], sig65: &[u8]) -> Result<[u8; 20]> {
    if sig65.len() != 65 {
        bail!("owner signature must be 65 bytes, got {}", sig65.len());
    }
    let signature = Signature::from_slice(&sig65[..64]).map_err(|e| anyhow!("bad signature: {e}"))?;
    let recid = RecoveryId::from_byte(sig65[64]).ok_or_else(|| anyhow!("bad recovery id"))?;
    let vk = VerifyingKey::recover_from_prehash(prehash, &signature, recid)
        .map_err(|e| anyhow!("recover failed: {e}"))?;
    let enc = vk.to_encoded_point(false);
    let h = keccak256(&enc.as_bytes()[1..65]);
    let mut a = [0u8; 20];
    a.copy_from_slice(&h[12..32]);
    Ok(a)
}

/// Dev-only fallback: re-fetch a raw header by block tag/hash over plain TLS (no notary).
pub fn raw_header(block: &str) -> Vec<u8> {
    let body = format!(
        "{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"debug_getRawHeader\",\"params\":[\"{block}\"]}}"
    );
    let out = Command::new("curl")
        .args([
            "-s", "-X", "POST", "-H", "content-type: application/json", "-H",
            "accept-encoding: identity", "-H", "user-agent: por/0.1", "--data", &body, RPC_URL,
        ])
        .output()
        .expect("curl");
    let resp: Value = serde_json::from_slice(&out.stdout).expect("json");
    let hexs = resp["result"].as_str().expect("no raw header");
    hex::decode(hexs.trim_start_matches("0x")).unwrap()
}

/// Relying-party policy applied to a decoded journal.
pub struct Policy {
    pub allow_debug: bool,
    pub required_threshold: u128,
    pub expected_chain_id: u32,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            allow_debug: false,
            required_threshold: 1_000_000_000_000_000_000, // 1 ETH
            expected_chain_id: 1,
        }
    }
}

impl Policy {
    /// Build a policy from the standard env knobs (`POR_ALLOW_DEBUG`, `POR_REQUIRED_THRESHOLD`).
    pub fn from_env() -> Self {
        Self {
            allow_debug: std::env::var("POR_ALLOW_DEBUG").is_ok(),
            required_threshold: std::env::var("POR_REQUIRED_THRESHOLD")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(1_000_000_000_000_000_000),
            expected_chain_id: 1,
        }
    }
}

pub fn check_policy(j: &Journal, p: &Policy) -> Result<()> {
    if j.debug && !p.allow_debug {
        bail!("debug != 0 (set POR_ALLOW_DEBUG=1 to permit; never in prod)");
    }
    if j.threshold < p.required_threshold {
        bail!("threshold {} < required {}", j.threshold, p.required_threshold);
    }
    if j.chain_id != p.expected_chain_id {
        bail!("unexpected chain_id {} (want {})", j.chain_id, p.expected_chain_id);
    }
    Ok(())
}

// --- Kurier / zkVerify on-chain submission ------------------------------------------------

fn curl(args: &[&str]) -> Vec<u8> {
    Command::new("curl").args(args).output().expect("curl").stdout
}

// POST a JSON body via stdin (`--data-binary @-`). The receipt bundle is ~0.5 MB, which
// blows past ARG_MAX as inline `--data` argv (E2BIG), so the body must go over stdin.
fn curl_post_json(url: &str, body: &str) -> Vec<u8> {
    let mut child = Command::new("curl")
        .args([
            "-s", "-X", "POST", "-H", "content-type: application/json", "--data-binary", "@-", url,
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("curl");
    child
        .stdin
        .take()
        .expect("curl stdin")
        .write_all(body.as_bytes())
        .expect("write curl stdin");
    child.wait_with_output().expect("curl").stdout
}

/// Outcome of an on-chain settle.
pub struct KurierOutcome {
    pub status: String,
    pub tx_hash: Option<String>,
    pub block_hash: Option<String>,
}

/// Submit a locally-verified receipt bundle to Kurier and poll to inclusion.
/// Returns `Ok(None)` when `KURIER_API_KEY` is unset (submission skipped).
///
/// NOTE: this blocks (~up to 10 min) polling job-status; callers on an async runtime must
/// run it on a blocking task. The `verifier` service backgrounds it (see P5).
pub fn submit_to_kurier(bundle: &Value) -> Result<Option<KurierOutcome>> {
    let Ok(api_key) = std::env::var("KURIER_API_KEY") else {
        return Ok(None);
    };
    let base =
        std::env::var("KURIER_API_URL").unwrap_or_else(|_| "https://api-testnet.kurier.xyz".into());

    let mut payload = serde_json::json!({
        "proofType": bundle["proofType"],       // "risc0"
        "vkRegistered": false,                   // risc0 uses the image_id directly as vk
        "proofOptions": bundle["proofOptions"],  // { "version": "V3_0" }
        "proofData": bundle["proofData"],        // { proof, vk, publicSignals }
    });
    if let Ok(chain) = std::env::var("KURIER_CHAIN_ID") {
        if let Ok(n) = chain.parse::<u64>() {
            payload["chainId"] = serde_json::json!(n);
        }
    }

    let submit_url = format!("{base}/submit-proof/{api_key}");
    let out = curl_post_json(&submit_url, &payload.to_string());
    let resp: Value = serde_json::from_slice(&out)
        .map_err(|_| anyhow!("Kurier response was not JSON: {}", String::from_utf8_lossy(&out)))?;
    let Some(job_id) = resp.get("jobId").and_then(|v| v.as_str()) else {
        bail!("Kurier rejected the submission: {resp}");
    };
    let job_id = job_id.to_string();

    let status_url = format!("{base}/job-status/{api_key}/{job_id}");
    for _ in 0..120 {
        std::thread::sleep(Duration::from_secs(5));
        let s = curl(&["-s", &status_url]);
        let sj: Value = match serde_json::from_slice(&s) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let status = sj.get("status").and_then(|v| v.as_str()).unwrap_or("?");
        match status {
            "Finalized" | "Aggregated" | "IncludedInBlock" => {
                return Ok(Some(KurierOutcome {
                    status: status.to_string(),
                    tx_hash: sj.get("txHash").and_then(|v| v.as_str()).map(String::from),
                    block_hash: sj.get("blockHash").and_then(|v| v.as_str()).map(String::from),
                }));
            }
            "Failed" | "Error" | "Invalid" => bail!("on-chain verification failed: {sj}"),
            _ => {} // Submitted / Pending / ... -> keep polling
        }
    }
    bail!("timed out waiting for on-chain inclusion (job {job_id})")
}
