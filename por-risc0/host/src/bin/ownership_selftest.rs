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

// Minimal header: RLP list of items 0..=8. The guest reads item 3 (state_root) and item 8
// (block number) and keccaks the whole thing; items 4..7 are filler valid RLP so the walk
// reaches item 8.
fn header_rlp(state_root: &B256, number: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    B256::ZERO.encode(&mut payload); // 0 parent_hash
    B256::ZERO.encode(&mut payload); // 1 ommers_hash
    Address::ZERO.encode(&mut payload); // 2 beneficiary
    state_root.encode(&mut payload); // 3 state_root
    B256::ZERO.encode(&mut payload); // 4 transactions_root
    B256::ZERO.encode(&mut payload); // 5 receipts_root
    [0u8; 256].as_slice().encode(&mut payload); // 6 logs_bloom
    0u64.encode(&mut payload); // 7 difficulty (0 post-merge)
    number.encode(&mut payload); // 8 number
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

#[allow(clippy::too_many_arguments)]
fn make_env(
    w: &Witness,
    sig: &[u8],
    threshold: u128,
    chain_id: u32,
    debug: bool,
    challenge_nonce: &[u8; 32],
    agent_id: &[u8; 32],
) -> ExecutorEnv<'static> {
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
        .write(challenge_nonce).unwrap()
        .write(agent_id).unwrap()
        .write(&0u64).unwrap() // marketplace token id (inert in the selftest)
        .write(&[0u8; 32]).unwrap() // agent secret (inert in the selftest)
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
    let block_number = 20_345_678u64;
    let header = header_rlp(&state_root, block_number);
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
    // challenge labels echoed through the journal (P2 asserts they round-trip).
    let challenge_nonce: [u8; 32] = [0xAB; 32];
    let agent_id: [u8; 32] = keccak256(b"0xagent-selftest").into();

    println!("address 0x{} (key we hold), balance {} ETH", hex::encode(address), balance as f64 / 1e18);
    let exec = default_executor();

    // [1] POSITIVE: ownership ON, balance >= threshold.
    println!("[1] positive: debug=false, valid sig, balance>=threshold ...");
    let session = exec
        .execute(make_env(&w, &sig65, threshold, chain_id, false, &challenge_nonce, &agent_id), POR_GUEST_ELF)
        .expect("positive ownership execution failed");
    let (jbh, jth, jcid, jdbg, jnonce, jagent, jnum, _jtid, _jid): (
        [u8; 32], u128, u32, bool, [u8; 32], [u8; 32], u64, u64, [u64; 4],
    ) = session.journal.decode().expect("journal decode");
    assert_eq!(jbh, w.block_hash, "journal block_hash mismatch");
    assert_eq!(jth, threshold);
    assert_eq!(jcid, chain_id);
    assert!(!jdbg, "debug should be false");
    assert_eq!(jnonce, challenge_nonce, "challenge_nonce did not echo into journal");
    assert_eq!(jagent, agent_id, "agent_id did not echo into journal");
    assert_eq!(jnum, block_number, "journal block_number != header item 8");
    // privacy: address + balance must NOT be in the journal
    let jbytes = session.journal.bytes.clone();
    assert!(!jbytes.windows(20).any(|w2| w2 == address), "address leaked into journal");
    // risc0 serde word-expands every field (each byte of a [u8;32] -> a 4-byte LE word,
    // u64 -> 2 words), so the journal is 456 bytes, not a packed layout. 128(block_hash)+
    // 16(threshold)+4(chain_id)+4(debug)+128(nonce)+128(agent_id)+8(number)+8(agent_token_id)+
    // 32(identity [u64;4]) = 456.
    assert_eq!(jbytes.len(), 456, "journal layout changed (risc0-serde word-expanded size)");
    println!("    OK: in-guest ownership verified; journal {{block_hash, threshold, chain_id, debug=false, challenge_nonce, agent_id, block_number={jnum}}}, addr+balance hidden");

    // [2] NEGATIVE: tampered signature.
    println!("[2] negative: tampered signature ...");
    let mut bad = sig65.clone();
    bad[5] ^= 0xff;
    assert!(
        exec.execute(make_env(&w, &bad, threshold, chain_id, false, &challenge_nonce, &agent_id), POR_GUEST_ELF).is_err(),
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
        exec.execute(make_env(&w, &sigw, threshold, chain_id, false, &challenge_nonce, &agent_id), POR_GUEST_ELF).is_err(),
        "wrong-signer signature was NOT rejected"
    );
    println!("    OK: rejected (signer address != proven address)");

    // [4] NEGATIVE: balance below threshold.
    println!("[4] negative: balance < threshold ...");
    assert!(
        exec.execute(make_env(&w, &sig65, balance + 1, chain_id, false, &challenge_nonce, &agent_id), POR_GUEST_ELF).is_err(),
        "below-threshold was NOT rejected"
    );
    println!("    OK: rejected");

    // [5] OPTIONAL: real succinct receipt with ownership ON.
    if std::env::var("POR_SELFTEST_PROVE").is_ok() {
        println!("[5] proving real succinct receipt (debug=false) ...");
        let t = Instant::now();
        let receipt = default_prover()
            .prove_with_opts(make_env(&w, &sig65, threshold, chain_id, false, &challenge_nonce, &agent_id), POR_GUEST_ELF, &ProverOpts::succinct())
            .unwrap()
            .receipt;
        receipt.verify(POR_GUEST_ID).unwrap();
        println!("    OK: receipt verifies; proving {:?}", t.elapsed());
    }

    println!("\nALL OWNERSHIP SELF-TESTS PASSED");
}
