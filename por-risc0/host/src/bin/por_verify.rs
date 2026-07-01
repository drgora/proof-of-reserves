// Relying-party verifier CLI (thin wrapper over `host::verify`): verify the Risc0 receipt,
// decode its journal, BIND it to the attested block header (keccak256(header) ==
// journal.block_hash) via the bundled TLSNotary presentation (or a dev-only by-hash
// re-fetch), enforce policy, and optionally settle on zkVerify via Kurier.
//
// The verification logic lives in `host::verify` so the `verifier` HTTP service reuses it.
//
// Run from por-risc0/ (reads ./proof.json):
//   POR_REQUIRED_THRESHOLD=1000000000000000000 [POR_ALLOW_DEBUG=1] cargo run --release --bin por_verify
use host::verify::{self, Policy};
use serde_json::Value;

fn main() {
    // ---- load + verify the Risc0 receipt ----
    let bundle: Value =
        serde_json::from_reader(std::fs::File::open("proof.json").expect("proof.json")).unwrap();
    let receipt = verify::decode_receipt(&bundle).expect("decode receipt");
    verify::verify_receipt(&receipt).expect("RECEIPT INVALID");
    println!("[1] Risc0 receipt verifies against image_id");

    let j = verify::decode_journal(&receipt).expect("decode journal");
    println!(
        "[2] journal: block_hash=0x{}  threshold={}  chain_id={}  debug={}",
        hex::encode(j.block_hash), j.threshold, j.chain_id, j.debug
    );

    // ---- BINDING: prefer the TLSNotary presentation; dev fallback re-fetches by hash ----
    match bundle.get("tlsnPresentation").and_then(|v| v.as_str()) {
        Some(b64) => {
            let att = verify::verify_presentation(b64).expect("PRESENTATION INVALID");
            verify::bind_block_hash(&att.header_rlp, &j.block_hash).expect("BINDING FAILED");
            println!(
                "[3] TLSNotary OK: notary 0x{} attests {} served the header (t={}); \
                 keccak256(attested header) == journal block_hash (BINDING OK)",
                att.notary_key_hex, att.server, att.time
            );
        }
        None => {
            let header = verify::raw_header(&format!("0x{}", hex::encode(j.block_hash)));
            verify::bind_block_hash(&header, &j.block_hash).expect("BINDING FAILED");
            let mismatch = verify::keccak256(&verify::raw_header("finalized")) != j.block_hash;
            println!(
                "[3] (DEV, no TLSNotary presentation) re-fetched header by hash; keccak == journal \
                 block_hash; negative control (finalized != journal): {mismatch}"
            );
        }
    }

    // ---- POLICY ----
    let policy = Policy::from_env();
    if let Err(e) = verify::check_policy(&j, &policy) {
        eprintln!("[4] REJECTED: {e}");
        std::process::exit(2);
    }
    println!(
        "[4] POLICY OK: debug={}, threshold {} >= {}, chain_id {}",
        j.debug, j.threshold, policy.required_threshold, j.chain_id
    );

    println!(
        "\nLOCAL VERIFICATION \u{2713} -- reserves bound to block 0x{} (balance & address hidden)",
        hex::encode(j.block_hash)
    );

    // The relying party settles on-chain only what it has already verified.
    match verify::submit_to_kurier(&bundle) {
        Ok(None) => {
            println!("[5] KURIER_API_KEY unset -> on-chain submission skipped (local verification only)")
        }
        Ok(Some(o)) => {
            println!("\n[5] ON-CHAIN VERIFIED on zkVerify (status={})", o.status);
            if let Some(tx) = o.tx_hash {
                println!("    txHash:    {tx}");
            }
            if let Some(bh) = o.block_hash {
                println!("    blockHash: {bh}");
            }
        }
        Err(e) => {
            eprintln!("[5] ON-CHAIN VERIFICATION FAILED: {e}");
            std::process::exit(3);
        }
    }
}
