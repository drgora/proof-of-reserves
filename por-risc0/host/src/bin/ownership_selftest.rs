// Ownership self-test for the PoR guest (debug=false path), including the multi-wallet sum.
//
// We can't exercise in-circuit ownership against the mainnet beacon contract (no private key
// for it), so this builds SYNTHETIC-but-valid state for keys we hold:
//   - generate secp256k1 key(s) -> derive Ethereum address(es)
//   - put the address(es) in a state trie (single leaf, or a 2-leaf branch for multi-wallet)
//     with chosen balance(s), hand-build the (deterministic) MPT proof(s) + a minimal header
//     RLP whose item[3] is the root
//   - sign the EIP-191 personal_sign of block_hash with each key
//   - run the guest with debug=false: it MUST verify each MPT, recover each signer, assert
//     signer == proven address, then assert the COMBINED balance >= threshold.
//
// Positive + negative controls run via the (fast) executor; set POR_SELFTEST_PROVE=1 to also
// produce + verify a real succinct receipt with ownership ON.
use methods::{POR_GUEST_ELF, POR_GUEST_ID};
use risc0_zkvm::{default_executor, default_prover, ExecutorEnv, ProverOpts};

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_rlp::{Encodable, Header as RlpHeader};
use alloy_trie::{TrieAccount, EMPTY_ROOT_HASH};
use k256::ecdsa::SigningKey;
use std::time::Instant;

// One account's private witness (minus the ownership sig, supplied alongside).
struct Acct {
    address: [u8; 20],
    nonce: u64,
    balance: u128,
    storage_hash: [u8; 32],
    code_hash: [u8; 32],
    account_proof: Vec<Vec<u8>>,
}

fn wrap_list(payload: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    RlpHeader { list: true, payload_length: payload.len() }.encode(&mut out);
    out.extend_from_slice(&payload);
    out
}

// Deterministic single-leaf state trie: the whole 64-nibble keccak(address) path lives in one
// terminal (leaf) node. HP-encode an even-length leaf as 0x20 ++ key(32). The node is
// RLP([compact_path, account_rlp]); root = keccak(node); proof = [node].
fn single_leaf_trie(address: &[u8; 20], account_rlp: &[u8]) -> (B256, Vec<Vec<u8>>) {
    let key = keccak256(address);
    let mut compact = Vec::with_capacity(33);
    compact.push(0x20);
    compact.extend_from_slice(key.as_slice());
    let mut payload = Vec::new();
    compact.as_slice().encode(&mut payload);
    account_rlp.encode(&mut payload);
    let node = wrap_list(payload);
    (keccak256(&node), vec![node])
}

// keccak(address) as 64 nibbles (high nibble first).
fn key_nibbles(key: &[u8]) -> Vec<u8> {
    let mut n = Vec::with_capacity(key.len() * 2);
    for b in key {
        n.push(b >> 4);
        n.push(b & 0x0f);
    }
    n
}

// HP (hex-prefix) encode a LEAF path (terminal flag set).
fn hp_leaf(nibbles: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if nibbles.len() % 2 == 1 {
        out.push(0x30 | nibbles[0]); // odd: flag nibble carries the first path nibble
        for pair in nibbles[1..].chunks(2) {
            out.push((pair[0] << 4) | pair[1]);
        }
    } else {
        out.push(0x20); // even
        for pair in nibbles.chunks(2) {
            out.push((pair[0] << 4) | pair[1]);
        }
    }
    out
}

fn leaf_node(path_nibbles: &[u8], value_rlp: &[u8]) -> Vec<u8> {
    let compact = hp_leaf(path_nibbles);
    let mut payload = Vec::new();
    compact.as_slice().encode(&mut payload);
    value_rlp.encode(&mut payload);
    wrap_list(payload)
}

// Two-leaf trie: a root BRANCH node whose two occupied slots (the first nibbles of the two
// keccak(address) paths, which must differ) point at leaf nodes holding the remaining 63
// nibbles. proof_i = [branch, leaf_i]. Requires the two addresses' key paths to diverge at
// nibble 0 (the caller picks keys accordingly).
fn two_leaf_trie(
    a1: &[u8; 20],
    acct1_rlp: &[u8],
    a2: &[u8; 20],
    acct2_rlp: &[u8],
) -> (B256, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let n1 = key_nibbles(keccak256(a1).as_slice());
    let n2 = key_nibbles(keccak256(a2).as_slice());
    assert_ne!(n1[0], n2[0], "test keys share a first nibble; caller must pick divergent keys");
    let leaf1 = leaf_node(&n1[1..], acct1_rlp);
    let leaf2 = leaf_node(&n2[1..], acct2_rlp);
    let h1 = keccak256(&leaf1);
    let h2 = keccak256(&leaf2);
    let mut payload = Vec::new();
    for slot in 0u8..16 {
        if slot == n1[0] {
            h1.as_slice().encode(&mut payload);
        } else if slot == n2[0] {
            h2.as_slice().encode(&mut payload);
        } else {
            [0u8; 0].as_slice().encode(&mut payload); // empty child -> 0x80
        }
    }
    [0u8; 0].as_slice().encode(&mut payload); // branch value slot: empty
    let branch = wrap_list(payload);
    (keccak256(&branch), vec![branch.clone(), leaf1], vec![branch, leaf2])
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
    wrap_list(payload)
}

fn eip191_prehash(block_hash: &[u8; 32]) -> [u8; 32] {
    let mut msg = Vec::with_capacity(28 + 32);
    msg.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
    msg.extend_from_slice(block_hash);
    keccak256(&msg).into()
}

fn addr_of(sk: &SigningKey) -> [u8; 20] {
    let enc = sk.verifying_key().to_encoded_point(false);
    keccak256(&enc.as_bytes()[1..65])[12..32].try_into().unwrap()
}

fn sign_eip191(block_hash: &[u8; 32], sk: &SigningKey) -> Vec<u8> {
    let prehash = eip191_prehash(block_hash);
    let (sig, recid) = sk.sign_prehash_recoverable(&prehash).unwrap();
    let mut v = sig.to_bytes().to_vec();
    v.push(recid.to_byte());
    v
}

// A synthetic EOA account (empty storage/code).
fn eoa(address: [u8; 20], nonce: u64, balance: u128, account_proof: Vec<Vec<u8>>) -> Acct {
    Acct {
        address,
        nonce,
        balance,
        storage_hash: EMPTY_ROOT_HASH.into(),
        code_hash: keccak256(b"").into(),
        account_proof,
    }
}

fn trie_account_rlp(nonce: u64, balance: u128) -> Vec<u8> {
    alloy_rlp::encode(&TrieAccount {
        nonce,
        balance: U256::from(balance),
        storage_root: EMPTY_ROOT_HASH,
        code_hash: B256::from(keccak256(b"")),
    })
}

#[allow(clippy::too_many_arguments)]
fn make_env(
    header: &[u8],
    accts: &[Acct],
    sigs: &[Vec<u8>],
    threshold: u128,
    chain_id: u32,
    debug: bool,
    challenge_nonce: &[u8; 32],
    agent_id: &[u8; 32],
) -> ExecutorEnv<'static> {
    assert_eq!(accts.len(), sigs.len(), "acct/sig count mismatch");
    let mut b = ExecutorEnv::builder();
    b.write(&header.to_vec()).unwrap();
    b.write(&(accts.len() as u32)).unwrap();
    for (a, sig) in accts.iter().zip(sigs) {
        b.write(&a.address).unwrap();
        b.write(&a.nonce).unwrap();
        b.write(&a.balance).unwrap();
        b.write(&a.storage_hash).unwrap();
        b.write(&a.code_hash).unwrap();
        b.write(&a.account_proof).unwrap();
        b.write(sig).unwrap();
    }
    b.write(&threshold).unwrap();
    b.write(&chain_id).unwrap();
    b.write(&debug).unwrap();
    b.write(challenge_nonce).unwrap();
    b.write(agent_id).unwrap();
    b.write(&0u64).unwrap(); // marketplace token id (inert in the selftest)
    b.write(&[0u8; 32]).unwrap(); // agent secret (inert in the selftest)
    b.build().unwrap()
}

const ETH: u128 = 1_000_000_000_000_000_000;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::filter::EnvFilter::from_default_env())
        .init();

    let chain_id = 1u32;
    let challenge_nonce: [u8; 32] = [0xAB; 32];
    let agent_id: [u8; 32] = keccak256(b"0xagent-selftest").into();
    let exec = default_executor();

    // ---- single-wallet fixtures (tests 1-4, 7) ----
    let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
    let address = addr_of(&sk);
    let (nonce, balance) = (7u64, 5 * ETH);
    let (state_root, proof) = single_leaf_trie(&address, &trie_account_rlp(nonce, balance));
    let block_number = 20_345_678u64;
    let header = header_rlp(&state_root, block_number);
    let block_hash: [u8; 32] = keccak256(&header).into();
    let sig = sign_eip191(&block_hash, &sk);
    let acct = || eoa(address, nonce, balance, proof.clone());
    let threshold = 1 * ETH; // <= balance
    println!("single wallet 0x{} (key we hold), balance {} ETH", hex::encode(address), balance as f64 / 1e18);

    // [1] POSITIVE: ownership ON, balance >= threshold.
    println!("[1] positive: debug=false, valid sig, balance>=threshold ...");
    let session = exec
        .execute(make_env(&header, &[acct()], &[sig.clone()], threshold, chain_id, false, &challenge_nonce, &agent_id), POR_GUEST_ELF)
        .expect("positive ownership execution failed");
    let (jbh, jth, jcid, jdbg, jnonce, jagent, jnum, _jtid, _jid): (
        [u8; 32], u128, u32, bool, [u8; 32], [u8; 32], u64, u64, [u64; 4],
    ) = session.journal.decode().expect("journal decode");
    assert_eq!(jbh, block_hash, "journal block_hash mismatch");
    assert_eq!(jth, threshold);
    assert_eq!(jcid, chain_id);
    assert!(!jdbg, "debug should be false");
    assert_eq!(jnonce, challenge_nonce, "challenge_nonce did not echo into journal");
    assert_eq!(jagent, agent_id, "agent_id did not echo into journal");
    assert_eq!(jnum, block_number, "journal block_number != header item 8");
    let jbytes = session.journal.bytes.clone();
    assert!(!jbytes.windows(20).any(|w2| w2 == address), "address leaked into journal");
    // risc0 serde word-expands every field (each byte of a [u8;32] -> a 4-byte LE word, u64 ->
    // 2 words), so the journal is 456 bytes -- unchanged by the multi-wallet guest, since the
    // committed set is identical regardless of how many wallets were summed.
    assert_eq!(jbytes.len(), 456, "journal layout changed (risc0-serde word-expanded size)");
    println!("    OK: in-guest ownership verified; journal 456B, addr+balance hidden");

    // [2] NEGATIVE: tampered signature.
    println!("[2] negative: tampered signature ...");
    let mut bad = sig.clone();
    bad[5] ^= 0xff;
    assert!(
        exec.execute(make_env(&header, &[acct()], &[bad], threshold, chain_id, false, &challenge_nonce, &agent_id), POR_GUEST_ELF).is_err(),
        "tampered signature was NOT rejected"
    );
    println!("    OK: rejected");

    // [3] NEGATIVE: signature from a different key (recovers a different address).
    println!("[3] negative: signature from a different key ...");
    let sk_other = SigningKey::from_slice(&[0x07u8; 32]).unwrap();
    let sig_wrong = sign_eip191(&block_hash, &sk_other);
    assert!(
        exec.execute(make_env(&header, &[acct()], &[sig_wrong], threshold, chain_id, false, &challenge_nonce, &agent_id), POR_GUEST_ELF).is_err(),
        "wrong-signer signature was NOT rejected"
    );
    println!("    OK: rejected (signer address != proven address)");

    // [4] NEGATIVE: balance below threshold.
    println!("[4] negative: balance < threshold ...");
    assert!(
        exec.execute(make_env(&header, &[acct()], &[sig.clone()], balance + 1, chain_id, false, &challenge_nonce, &agent_id), POR_GUEST_ELF).is_err(),
        "below-threshold was NOT rejected"
    );
    println!("    OK: rejected");

    // ---- multi-wallet fixtures (tests 5-6): two owned accounts in ONE state trie ----
    // Pick a second key whose keccak(address) path diverges from the first at nibble 0.
    let n1_first = key_nibbles(keccak256(address).as_slice())[0];
    let (sk2, address2) = (2u8..=254)
        .find_map(|seed| {
            let sk2 = SigningKey::from_slice(&[seed; 32]).ok()?;
            let a2 = addr_of(&sk2);
            (a2 != address && key_nibbles(keccak256(a2).as_slice())[0] != n1_first).then_some((sk2, a2))
        })
        .expect("a second key with a distinct first path nibble");
    let (bal1, bal2) = (3 * ETH, 4 * ETH); // combined 7 ETH; each < 5 ETH
    let (root2, p1, p2) = two_leaf_trie(
        &address,
        &trie_account_rlp(nonce, bal1),
        &address2,
        &trie_account_rlp(9, bal2),
    );
    let header2 = header_rlp(&root2, block_number);
    let bh2: [u8; 32] = keccak256(&header2).into();
    // Guest requires wallets distinct + ascending by address -> sort (acct, sig) by address.
    let mut pair = vec![
        (eoa(address, nonce, bal1, p1), sign_eip191(&bh2, &sk)),
        (eoa(address2, 9, bal2, p2), sign_eip191(&bh2, &sk2)),
    ];
    pair.sort_by(|a, b| a.0.address.cmp(&b.0.address));
    let accts2: Vec<Acct> = pair.iter().map(|(a, _)| eoa(a.address, a.nonce, a.balance, a.account_proof.clone())).collect();
    let sigs2: Vec<Vec<u8>> = pair.iter().map(|(_, s)| s.clone()).collect();
    println!(
        "two wallets 0x{} ({} ETH) + 0x{} ({} ETH), combined {} ETH",
        hex::encode(address), bal1 as f64 / 1e18, hex::encode(address2), bal2 as f64 / 1e18, (bal1 + bal2) as f64 / 1e18
    );

    // [5] POSITIVE: combined balance (7 ETH) >= threshold (5 ETH), while NEITHER wallet alone
    //     meets it -- proves the guest sums, not checks per-wallet.
    println!("[5] positive multi-wallet: combined 7 ETH >= threshold 5 ETH (each wallet < 5) ...");
    let thr_multi = 5 * ETH;
    let session5 = exec
        .execute(make_env(&header2, &accts2, &sigs2, thr_multi, chain_id, false, &challenge_nonce, &agent_id), POR_GUEST_ELF)
        .expect("multi-wallet positive execution failed");
    let (j5bh, j5th, _c, _d, _n, _a, _num, _t, _i): (
        [u8; 32], u128, u32, bool, [u8; 32], [u8; 32], u64, u64, [u64; 4],
    ) = session5.journal.decode().expect("journal decode");
    assert_eq!(j5bh, bh2, "multi journal block_hash mismatch");
    assert_eq!(j5th, thr_multi, "multi journal threshold mismatch");
    let j5 = session5.journal.bytes.clone();
    assert!(!j5.windows(20).any(|w| w == address || w == address2), "an address leaked into the journal");
    assert!(!j5.windows(16).any(|w| w == bal1.to_le_bytes() || w == bal2.to_le_bytes()), "a balance leaked into the journal");
    assert_eq!(j5.len(), 456, "multi-wallet journal size differs from single-wallet (must be identical)");
    println!("    OK: aggregate verified; journal identical to single-wallet (456B), addrs+balances hidden");

    // [6] NEGATIVE: combined balance (7 ETH) < threshold (8 ETH).
    println!("[6] negative multi-wallet: combined 7 ETH < threshold 8 ETH ...");
    assert!(
        exec.execute(make_env(&header2, &accts2, &sigs2, 8 * ETH, chain_id, false, &challenge_nonce, &agent_id), POR_GUEST_ELF).is_err(),
        "below-combined-threshold was NOT rejected"
    );
    println!("    OK: rejected");

    // [7] NEGATIVE: the same wallet listed twice (double-count attack). Distinct/ascending
    //     enforcement must reject it, even though each entry is individually valid.
    println!("[7] negative: same wallet listed twice (double-count) ...");
    assert!(
        exec.execute(make_env(&header, &[acct(), acct()], &[sig.clone(), sig.clone()], threshold, chain_id, false, &challenge_nonce, &agent_id), POR_GUEST_ELF).is_err(),
        "duplicate wallet was NOT rejected"
    );
    println!("    OK: rejected (wallets must be distinct + ascending)");

    // [8] OPTIONAL: real succinct receipt with ownership ON (multi-wallet).
    if std::env::var("POR_SELFTEST_PROVE").is_ok() {
        println!("[8] proving real succinct receipt (debug=false, 2 wallets) ...");
        let t = Instant::now();
        let receipt = default_prover()
            .prove_with_opts(make_env(&header2, &accts2, &sigs2, thr_multi, chain_id, false, &challenge_nonce, &agent_id), POR_GUEST_ELF, &ProverOpts::succinct())
            .unwrap()
            .receipt;
        receipt.verify(POR_GUEST_ID).unwrap();
        println!("    OK: receipt verifies; proving {:?}", t.elapsed());
    }

    println!("\nALL OWNERSHIP SELF-TESTS PASSED");
}
