// Offset helper for HL Agent Marketplace (ValidationGatewayV2) registration.
//
// After the guest commits the two marketplace binding fields (numeric ERC-721 agentId +
// keccak256(agent_secret)), the gateway needs the exact BYTE OFFSETS of those fields
// within the risc0 journal (= the `publicSignals`/`pubsBytes` it hashes). risc0 serde
// word-expands some types (a [u8;32] -> 128 non-contiguous bytes) and packs integers as
// contiguous little-endian bytes (u64 -> 8), so the offsets can't be eyeballed -- they
// must be read off a real journal.
//
// This runs the guest via the FAST executor (no proving; debug=true so no signature is
// needed -- the MPT is still verified) with a known agentId + secret, locates both fields
// in the emitted journal, and prints:
//   - the setProofTypeConfig arguments (offsets + length + endianness + ctxHash), and
//   - the exact registerAgentCommitment bytes32 (it reproduces the gateway's _extractField
//     + Solidity bytes32() cast, so the printed value is what to register verbatim).
//
// REQUIRES the guest change (two new env::read + two new env::commit). Run:
//   cargo run --release --bin marketplace_offsets
//   POR_AGENT_TOKEN_ID=2094 POR_AGENT_SECRET=<64-hex> cargo run --release --bin marketplace_offsets
use methods::{POR_GUEST_ELF, POR_GUEST_ID};
use risc0_zkvm::{default_executor, ExecutorEnv};

use alloy_primitives::{keccak256, Address, B256, U256};
use alloy_rlp::{Encodable, Header as RlpHeader};
use alloy_trie::{TrieAccount, EMPTY_ROOT_HASH};

// Deterministic single-leaf state trie (same construction as ownership_selftest): the whole
// keccak(address) path lives in one leaf node; proof = [node], root = keccak(node).
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

// Minimal header RLP: items 0..=8, guest reads item 3 (state_root) and item 8 (number).
fn header_rlp(state_root: &B256, number: u64) -> Vec<u8> {
    let mut payload = Vec::new();
    B256::ZERO.encode(&mut payload); // 0 parent_hash
    B256::ZERO.encode(&mut payload); // 1 ommers_hash
    Address::ZERO.encode(&mut payload); // 2 beneficiary
    state_root.encode(&mut payload); // 3 state_root
    B256::ZERO.encode(&mut payload); // 4 transactions_root
    B256::ZERO.encode(&mut payload); // 5 receipts_root
    [0u8; 256].as_slice().encode(&mut payload); // 6 logs_bloom
    0u64.encode(&mut payload); // 7 difficulty
    number.encode(&mut payload); // 8 number
    let mut out = Vec::new();
    RlpHeader { list: true, payload_length: payload.len() }.encode(&mut out);
    out.extend_from_slice(&payload);
    out
}

// Rust mirror of ValidationGatewayV2._extractField for a <=8-byte integer field.
fn extract_u64(pubs: &[u8], offset: usize, length: usize, little_endian: bool) -> u64 {
    let mut r = 0u64;
    if little_endian {
        for i in 0..length {
            r |= (pubs[offset + i] as u64) << (8 * i);
        }
    } else {
        for i in 0..length {
            r = (r << 8) | pubs[offset + i] as u64;
        }
    }
    r
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn main() {
    // Distinctive sentinel token id makes the 8-byte LE pattern reliably locatable; override
    // with the real ERC-721 token id to double-check, though offsets are value-independent.
    let token_id: u64 = std::env::var("POR_AGENT_TOKEN_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0x1122_3344_5566_7788);
    let secret: [u8; 32] = std::env::var("POR_AGENT_SECRET")
        .ok()
        .map(|h| {
            let b = hex::decode(h.trim_start_matches("0x")).expect("POR_AGENT_SECRET must be hex");
            b.try_into().expect("POR_AGENT_SECRET must be 32 bytes")
        })
        .unwrap_or([0x42u8; 32]);

    // Synthetic valid state; debug=true skips ownership so no key/signature is needed.
    let address = [0x11u8; 20];
    let nonce = 1u64;
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
    let header = header_rlp(&state_root, 20_345_678);

    let challenge_nonce = [0xABu8; 32];
    let agent_id: [u8; 32] = keccak256(b"offset-helper").into();
    let identity: [u8; 32] = keccak256(&secret).into(); // what the guest commits as [u64;4]

    let env = ExecutorEnv::builder()
        .write(&header)
        .unwrap()
        .write(&account_proof)
        .unwrap()
        .write(&address)
        .unwrap()
        .write(&nonce)
        .unwrap()
        .write(&balance)
        .unwrap()
        .write(&storage_hash)
        .unwrap()
        .write(&code_hash)
        .unwrap()
        .write(&Vec::<u8>::new())
        .unwrap() // sig (empty; debug=true)
        .write(&1_000_000_000_000_000_000u128)
        .unwrap() // threshold (1 ETH <= balance)
        .write(&1u32)
        .unwrap() // chain_id
        .write(&true)
        .unwrap() // debug
        .write(&challenge_nonce)
        .unwrap()
        .write(&agent_id)
        .unwrap()
        .write(&token_id)
        .unwrap() // NEW: marketplace ERC-721 token id (u64)
        .write(&secret)
        .unwrap() // NEW: private agent secret ([u8;32])
        .build()
        .unwrap();

    let session = default_executor()
        .execute(env, POR_GUEST_ELF)
        .expect("guest execution failed -- did the guest change land?");
    let j = session.journal.bytes;
    println!("journal length: {} bytes", j.len());

    // Locate the two marketplace fields by their byte patterns.
    let off_tid =
        find(&j, &token_id.to_le_bytes()).expect("agent token id (u64 LE) not found in journal");
    let off_id = find(&j, &identity).expect("identity (keccak256(secret)) not found in journal");

    // Verify the read-back matches what the gateway will compute.
    assert_eq!(extract_u64(&j, off_tid, 8, true), token_id, "token id LE read-back mismatch");
    assert!(off_id + 32 <= j.len(), "identity field out of bounds");
    assert!(off_id > 0, "identityBindingOffset must be > 0 (0 == 'not configured' sentinel)");

    // registeredCommitment == bytes32(_extractField(pubs, off_id, 32, littleEndian=true))
    //                      == the 32 journal bytes reversed (LE integer -> BE bytes32).
    let mut commitment = j[off_id..off_id + 32].to_vec();
    commitment.reverse();

    // vk = risc0 image_id serialized as LE u32 words -- byte-identical to what main.rs
    // submits to Kurier as `vk`. zkVerify's risc0 vk_hash is the identity function, so this
    // 32-byte value IS the gateway vkHash. It only reproduces across machines if the guest
    // was built with RISC0_USE_DOCKER=1 (pinned builder container); a local build prints a
    // machine-specific value -- do NOT register that one.
    let vk = hex::encode(POR_GUEST_ID.iter().flat_map(|v| v.to_le_bytes()).collect::<Vec<_>>());

    println!("\n=== setVkHash(\"proof-of-reserves\", vkHash, true) ===");
    println!("  vkHash                0x{vk}");
    println!("  (risc0 image_id, LE words; reproducible only under RISC0_USE_DOCKER=1)");

    println!("\n=== setProofTypeConfig(...) ===");
    println!("  proofType             \"proof-of-reserves\"        (you become its registrar)");
    println!("  ctxHash               0x{}  (keccak256(\"risc0\"))", hex::encode(keccak256(b"risc0")));
    println!("  agentIdOffset         {off_tid}");
    println!("  agentIdLength         8");
    println!("  agentIdLittleEndian   true");
    println!("  active                true");
    println!("  identityBindingOffset {off_id}");
    println!("\n=== registerAgentCommitment(agentId, \"proof-of-reserves\", commitment, asRegistrar=true) ===");
    println!("  commitment            0x{}", hex::encode(&commitment));
    println!("  (derived from POR_AGENT_SECRET above; register once before recordValidation)");
    println!(
        "\nNOTE: agentIdLittleEndian=true is MEASURED from the journal and contradicts the\n\
         contract's \"BE for RISC Zero\" comment -- trust the measurement. ctxHash is the\n\
         contract's stated convention; it still must reproduce zkVerify's risc0 leaf\n\
         (the \"Leaf mismatch\" check will catch it if vkHash/versionHash are off)."
    );
}
