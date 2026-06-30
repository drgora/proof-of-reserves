// Ownership self-test for the PoR guest (debug=false path).
//
// We can't exercise in-circuit ownership against the mainnet beacon contract (no
// private key for it), so this builds SYNTHETIC-but-valid state for a key we hold:
//   - generate a secp256k1 key -> derive its Ethereum address
//   - put that address in a single-leaf state trie with a chosen balance, hand-build
//     the (deterministic) MPT proof + a minimal header RLP whose item[3] is the root
//   - sign the EIP-191 personal_sign of block_hash with the key
//   - run the guest with debug=false: it MUST verify the MPT, recover the signer, and
//     assert signer == proven address, then balance >= threshold.
//
// Positive + 3 negative controls run via the (fast) executor; set POR_SELFTEST_PROVE=1
// to also produce + verify a real succinct receipt with ownership ON.
use methods::{POR_GUEST_ELF, POR_GUEST_ID};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts};

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_rlp::{Encodable, Header as RlpHeader};
use alloy_trie::{TrieAccount, EMPTY_ROOT_HASH};
use k256::ecdsa::SigningKey;
use std::time::Instant;

struct Witness {
    header_rlp: Vec<u8>,
    account_proof: Vec<Vec<u8>>,
    address: [u8; 20],
    nonce: u64,
    balance: u128,
    storage_hash: [u8; 32],
    code_hash: [u8; 32],
    block_hash: [u8; 32],
}

// Deterministic single-leaf state trie: the whole 64-nibble keccak(address) path lives
// in one terminal (leaf) node. HP-encode an even-length leaf as 0x20 ++ key(32). The
// node is RLP([compact_path, account_rlp]); root = keccak(node); proof = [node].
fn single_leaf_trie(address: &[u8; 20], account_rlp: &[u8]) -> (B256, Vec<Vec<u8>>) {
    let key = keccak256(address);
    let mut compact = Vec::with_capacity(33);
    compact.push(0x20);
    compact.extend_from_slice(key.as_slice());
    let mut payload = Vec::new();
    compact.as_slice().encode(&mut payload);
    account_rlp.encode(&mut payload);
    let mut node = Vec::new();
    RlpHeader { list: true, payload_length: payload.len() }.encode(&mut node);
    node.extend_from_slice(&payload);
    (keccak256(&node), vec![node])
}

// Minimal header: RLP list [parent(32), ommers(32), beneficiary(20), state_root(32)].
// The guest reads only item index 3 (state_root) and keccaks the whole thing.
fn header_rlp(state_root: &B256) -> Vec<u8> {
    let mut payload = Vec::new();
    B256::ZERO.encode(&mut payload);
    B256::ZERO.encode(&mut payload);
    Address::ZERO.encode(&mut payload);
    state_root.encode(&mut payload);
    let mut out = Vec::new();
    RlpHeader { list: true, payload_length: payload.len() }.encode(&mut out);
    out.extend_from_slice(&payload);
    out
}

fn eip191_prehash(block_hash: &[u8; 32]) -> [u8; 32] {
    let mut msg = Vec::with_capacity(28 + 32);
    msg.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
    msg.extend_from_slice(block_hash);
    keccak256(&msg).into()
}

fn make_env(w: &Witness, sig: &[u8], threshold: u128, chain_id: u32, debug: bool) -> ExecutorEnv<'static> {
    ExecutorEnv::builder()
        .write(&w.header_rlp).unwrap()
        .write(&w.account_proof).unwrap()
        .write(&w.address).unwrap()
        .write(&w.nonce).unwrap()
        .write(&w.balance).unwrap()
        .write(&w.storage_hash).unwrap()
        .write(&w.code_hash).unwrap()
        .write(&sig.to_vec()).unwrap()
        .write(&threshold).unwrap()
        .write(&chain_id).unwrap()
        .write(&debug).unwrap()
        .build()
        .unwrap()
}

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    // Key we control (fixed for reproducibility).
    let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
    let enc = sk.verifying_key().to_encoded_point(false);
    let address: [u8; 20] = keccak256(&enc.as_bytes()[1..65])[12..32].try_into().unwrap();

    // Synthetic EOA: 5 ETH, empty storage/code.
    let nonce = 7u64;
    let balance = 5_000_000_000_000_000_000u128; // 5 ETH
    let storage_hash: [u8; 32] = EMPTY_ROOT_HASH.into();
    let code_hash: [u8; 32] = keccak256(b"").into();
    let account = TrieAccount {
        nonce,
        balance: U256::from(balance),
        storage_root: EMPTY_ROOT_HASH,
        code_hash: B256::from(code_hash),
    };
    let account_rlp = alloy_rlp::encode(&account);

    let (state_root, account_proof) = single_leaf_trie(&address, &account_rlp);
    let header = header_rlp(&state_root);
    let block_hash: [u8; 32] = keccak256(&header).into();

    // Sign EIP-191(block_hash) -> r||s||recid (65 bytes), the guest's expected encoding.
    let prehash = eip191_prehash(&block_hash);
    let (sig, recid) = sk.sign_prehash_recoverable(&prehash).unwrap();
    let mut sig65 = sig.to_bytes().to_vec();
    sig65.push(recid.to_byte());

    let w = Witness {
        header_rlp: header,
        account_proof,
        address,
        nonce,
        balance,
        storage_hash,
        code_hash,
        block_hash,
    };
    let chain_id = 1u32;
    let threshold = 1_000_000_000_000_000_000u128; // 1 ETH (<= balance)

    println!("address 0x{} (key we hold), balance {} ETH", hex::encode(address), balance as f64 / 1e18);
    let exec = default_executor();

    // [1] POSITIVE: ownership ON, balance >= threshold.
    println!("[1] positive: debug=false, valid sig, balance>=threshold ...");
    let session = exec
        .execute(make_env(&w, &sig65, threshold, chain_id, false), POR_GUEST_ELF)
        .expect("positive ownership execution failed");
    let (jbh, jth, jcid, jdbg): ([u8; 32], u128, u32, bool) =
        session.journal.decode().expect("journal decode");
    assert_eq!(jbh, w.block_hash, "journal block_hash mismatch");
    assert_eq!(jth, threshold);
    assert_eq!(jcid, chain_id);
    assert!(!jdbg, "debug should be false");
    // privacy: address + balance must NOT be in the journal
    let jbytes = session.journal.bytes.clone();
    assert!(!jbytes.windows(20).any(|w2| w2 == address), "address leaked into journal");
    println!("    OK: in-guest ownership verified; journal {{block_hash, threshold, chain_id, debug=false}}, addr+balance hidden");

    // [2] NEGATIVE: tampered signature.
    println!("[2] negative: tampered signature ...");
    let mut bad = sig65.clone();
    bad[5] ^= 0xff;
    assert!(
        exec.execute(make_env(&w, &bad, threshold, chain_id, false), POR_GUEST_ELF).is_err(),
        "tampered signature was NOT rejected"
    );
    println!("    OK: rejected");

    // [3] NEGATIVE: signature from a different key (recovers a different address).
    println!("[3] negative: signature from a different key ...");
    let sk2 = SigningKey::from_slice(&[0x07u8; 32]).unwrap();
    let (sig2, rid2) = sk2.sign_prehash_recoverable(&prehash).unwrap();
    let mut sigw = sig2.to_bytes().to_vec();
    sigw.push(rid2.to_byte());
    assert!(
        exec.execute(make_env(&w, &sigw, threshold, chain_id, false), POR_GUEST_ELF).is_err(),
        "wrong-signer signature was NOT rejected"
    );
    println!("    OK: rejected (signer address != proven address)");

    // [4] NEGATIVE: balance below threshold.
    println!("[4] negative: balance < threshold ...");
    assert!(
        exec.execute(make_env(&w, &sig65, balance + 1, chain_id, false), POR_GUEST_ELF).is_err(),
        "below-threshold was NOT rejected"
    );
    println!("    OK: rejected");

    // [5] OPTIONAL: real succinct receipt with ownership ON.
    if std::env::var("POR_SELFTEST_PROVE").is_ok() {
        println!("[5] proving real succinct receipt (debug=false) ...");
        let t = Instant::now();
        let receipt = default_prover()
            .prove_with_opts(make_env(&w, &sig65, threshold, chain_id, false), POR_GUEST_ELF, &ProverOpts::succinct())
            .unwrap()
            .receipt;
        receipt.verify(POR_GUEST_ID).unwrap();
        println!("    OK: receipt verifies; proving {:?}", t.elapsed());
    }

    println!("\nALL OWNERSHIP SELF-TESTS PASSED");
}
