// Witness builder for the proof-of-reserves Noir circuit (noir/src/main.nr).
//
// Given the JSON from `eth_getProof(address, [], block)` plus the raw block-header
// RLP (`debug_getRawHeader(block)`), this produces the FLAT decimal-string witness
// vector that `noir::witness::from_vec_str_to_witness_map` consumes: one decimal
// string per scalar field in the circuit's ABI parameter order, with every struct,
// array and BoundedVec flattened in declaration / element order.
//
// ABI order (public then private), see noir/target/noir.json `abi.parameters`:
//   threshold: u128                       (public, 1 field)
//   block_hash: [u8;32]                   (public, 32 fields)
//   chain_id: u32                         (public, 1 field)
//   debug: bool                           (public, 1 field; 0 or 1)
//   address: [u8;20]                      (20 fields)
//   account: { nonce:u64, balance:Field, storage_root:[u8;32], code_hash:[u8;32] }
//   state_proof: ProofInput {
//       key:[u8;66], value:[u8;110],
//       proof: { nodes:[[u8;532];10], leaf:[u8;148], depth:u64 } }
//   header: { number:u64, hash:[u8;32], state_root:[u8;32],
//             transactions_root:[u8;32], receipts_root:[u8;32] }
//   header_rlp: BoundedVec<u8,708>        (storage:[u8;708] then len:u32)
//   pubkey_x:[u8;32], pubkey_y:[u8;32], signature:[u8;64]
//
// The serialization matches the eth-proofs TS reference (oracles/.../encode.ts and
// script/noir_fixtures/proof.ts): key/value LEFT-padded, trie nodes/leaf and the
// header RLP RIGHT-padded. The account `value` (the trie leaf's RLP value) is taken
// from the last proof node, exactly as the reference `getValue` does, rather than
// re-encoded, so it matches the trie path byte-for-byte.

use anyhow::{Result, anyhow, bail};
use serde_json::Value;
use tiny_keccak::{Hasher, Keccak};

// Circuit dimension constants (from the ABI / circuit globals).
const KEY_LEN: usize = 66; // MAX_PREFIXED_KEY_NIBBLE_LEN
const VALUE_LEN: usize = 110; // MAX_ACCOUNT_STATE_LEN
const MAX_TRIE_NODE_LEN: usize = 532;
const MAX_NODES: usize = 10; // MAX_ACCOUNT_DEPTH_NO_LEAF_M
const MAX_LEAF_LEN: usize = 148; // MAX_ACCOUNT_LEAF_LEN
const MAX_HEADER_RLP_LEN: usize = 708;

// ---------------------------------------------------------------------------
// keccak256
// ---------------------------------------------------------------------------
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    let mut out = [0u8; 32];
    k.update(data);
    k.finalize(&mut out);
    out
}

// ---------------------------------------------------------------------------
// Minimal RLP decoder for a TOP-LEVEL LIST of byte-strings.
//
// We only need to crack the header (a flat list of strings) and the account leaf
// (`fromRlp(leaf)[1]`). Both are RLP lists whose items are byte-strings (the header
// has no nested lists at the indices we read; the account leaf is [path, value]).
// We do NOT recurse into nested lists - if an item is itself a list we keep its raw
// encoded bytes, which is fine because we never read into those positions.
// ---------------------------------------------------------------------------

/// One decoded top-level item: its payload bytes (for a string) or, for a nested
/// list, the list's *content* bytes. We tag which it is so callers can guard.
struct RlpItem {
    is_list: bool,
    bytes: Vec<u8>,
}

/// Decode a top-level RLP list into its items. Asserts the outer item is a list and
/// that it consumes the whole input (canonical, no trailing bytes).
fn rlp_decode_list(input: &[u8]) -> Result<Vec<RlpItem>> {
    if input.is_empty() {
        bail!("rlp: empty input");
    }
    let p = input[0];
    let (payload_off, payload_len) = if (0xc0..=0xf7).contains(&p) {
        (1usize, (p - 0xc0) as usize)
    } else if p >= 0xf8 {
        let len_of_len = (p - 0xf7) as usize;
        if 1 + len_of_len > input.len() {
            bail!("rlp: list length header out of range");
        }
        let l = be_to_usize(&input[1..1 + len_of_len])?;
        (1 + len_of_len, l)
    } else {
        bail!("rlp: top-level item is not a list (prefix 0x{p:02x})");
    };
    let end = payload_off + payload_len;
    if end != input.len() {
        bail!("rlp: trailing bytes (consumed {end} of {})", input.len());
    }
    let body = &input[payload_off..end];

    let mut items = Vec::new();
    let mut i = 0usize;
    while i < body.len() {
        let item = rlp_read_item(body, &mut i)?;
        items.push(item);
    }
    Ok(items)
}

/// Read one RLP item (string or list) starting at *pos, advancing *pos past it.
fn rlp_read_item(body: &[u8], pos: &mut usize) -> Result<RlpItem> {
    let p = body[*pos];
    if p <= 0x7f {
        // single byte, is its own encoding
        let b = vec![p];
        *pos += 1;
        Ok(RlpItem { is_list: false, bytes: b })
    } else if p <= 0xb7 {
        // short string, len = p - 0x80
        let l = (p - 0x80) as usize;
        let s = *pos + 1;
        let e = s + l;
        if e > body.len() {
            bail!("rlp: short string out of range");
        }
        let b = body[s..e].to_vec();
        *pos = e;
        Ok(RlpItem { is_list: false, bytes: b })
    } else if p <= 0xbf {
        // long string
        let lol = (p - 0xb7) as usize;
        let ls = *pos + 1;
        let le = ls + lol;
        if le > body.len() {
            bail!("rlp: long string length out of range");
        }
        let l = be_to_usize(&body[ls..le])?;
        let s = le;
        let e = s + l;
        if e > body.len() {
            bail!("rlp: long string out of range");
        }
        let b = body[s..e].to_vec();
        *pos = e;
        Ok(RlpItem { is_list: false, bytes: b })
    } else if p <= 0xf7 {
        // short list
        let l = (p - 0xc0) as usize;
        let s = *pos + 1;
        let e = s + l;
        if e > body.len() {
            bail!("rlp: short list out of range");
        }
        let b = body[s..e].to_vec();
        *pos = e;
        Ok(RlpItem { is_list: true, bytes: b })
    } else {
        // long list
        let lol = (p - 0xf7) as usize;
        let ls = *pos + 1;
        let le = ls + lol;
        if le > body.len() {
            bail!("rlp: long list length out of range");
        }
        let l = be_to_usize(&body[ls..le])?;
        let s = le;
        let e = s + l;
        if e > body.len() {
            bail!("rlp: long list out of range");
        }
        let b = body[s..e].to_vec();
        *pos = e;
        Ok(RlpItem { is_list: true, bytes: b })
    }
}

fn be_to_usize(b: &[u8]) -> Result<usize> {
    if b.len() > 8 {
        bail!("rlp: integer too large");
    }
    let mut v = 0usize;
    for &x in b {
        v = (v << 8) | x as usize;
    }
    Ok(v)
}

fn be_to_u64(b: &[u8]) -> Result<u64> {
    if b.len() > 8 {
        bail!("rlp: u64 overflow");
    }
    let mut v = 0u64;
    for &x in b {
        v = (v << 8) | x as u64;
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// Hex parsing helpers
// ---------------------------------------------------------------------------
fn hex_decode(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s).map_err(|e| anyhow!("hex decode: {e}"))
}

/// Parse a 0x-prefixed quantity (e.g. "0x1c9c380") into a u64.
fn parse_hex_u64(s: &str) -> Result<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).map_err(|e| anyhow!("u64 hex: {e}"))
}

/// Parse a 0x-prefixed quantity into a decimal big-integer string (for `Field`).
/// Avoids any bigint dependency: decode the bytes and do base-256 -> base-10.
fn hex_quantity_to_decimal(s: &str) -> Result<String> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    // normalise to an even-length hex string
    let norm = if s.len() % 2 == 1 { format!("0{s}") } else { s.to_string() };
    let bytes = hex::decode(&norm).map_err(|e| anyhow!("hex quantity: {e}"))?;
    Ok(bytes_be_to_decimal(&bytes))
}

/// Big-endian bytes -> decimal string (schoolbook, base-256 digits to base-10).
fn bytes_be_to_decimal(bytes: &[u8]) -> String {
    let mut digits: Vec<u8> = vec![0]; // little-endian base-10 digits
    for &byte in bytes {
        let mut carry = byte as u32;
        for d in digits.iter_mut() {
            let cur = (*d as u32) * 256 + carry;
            *d = (cur % 10) as u8;
            carry = cur / 10;
        }
        while carry > 0 {
            digits.push((carry % 10) as u8);
            carry /= 10;
        }
    }
    let s: String = digits.iter().rev().map(|d| (b'0' + d) as char).collect();
    let trimmed = s.trim_start_matches('0');
    if trimmed.is_empty() { "0".to_string() } else { trimmed.to_string() }
}

// ---------------------------------------------------------------------------
// Padding helpers (return fixed-length byte vectors).
// ---------------------------------------------------------------------------
fn pad_left(bytes: &[u8], len: usize) -> Result<Vec<u8>> {
    if bytes.len() > len {
        bail!("pad_left: input {} exceeds target {len}", bytes.len());
    }
    let mut out = vec![0u8; len - bytes.len()];
    out.extend_from_slice(bytes);
    Ok(out)
}

fn pad_right(bytes: &[u8], len: usize) -> Result<Vec<u8>> {
    if bytes.len() > len {
        bail!("pad_right: input {} exceeds target {len}", bytes.len());
    }
    let mut out = bytes.to_vec();
    out.resize(len, 0);
    Ok(out)
}

// ---------------------------------------------------------------------------
// The decoded header pieces the circuit needs.
// ---------------------------------------------------------------------------
pub struct DecodedHeader {
    pub number: u64,
    pub hash: [u8; 32],
    pub state_root: [u8; 32],
    pub transactions_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub field_count: usize,
}

/// Decode the raw header RLP, extracting the fields the circuit reads and the keccak
/// hash. `header.hash` == `block_hash` (public) == keccak256(header_rlp).
pub fn decode_header(header_rlp: &[u8]) -> Result<DecodedHeader> {
    if header_rlp.len() > MAX_HEADER_RLP_LEN {
        bail!(
            "header RLP {} bytes exceeds circuit max {MAX_HEADER_RLP_LEN}",
            header_rlp.len()
        );
    }
    let items = rlp_decode_list(header_rlp)?;
    // Field indices per verifiers/header.nr: 3=state, 4=txns, 5=receipts, 8=number.
    let get32 = |idx: usize, name: &str| -> Result<[u8; 32]> {
        let it = items
            .get(idx)
            .ok_or_else(|| anyhow!("header missing field {idx} ({name})"))?;
        if it.is_list {
            bail!("header field {idx} ({name}) is unexpectedly a list");
        }
        if it.bytes.len() != 32 {
            bail!("header field {idx} ({name}) is {} bytes, want 32", it.bytes.len());
        }
        let mut a = [0u8; 32];
        a.copy_from_slice(&it.bytes);
        Ok(a)
    };
    let state_root = get32(3, "state_root")?;
    let transactions_root = get32(4, "transactions_root")?;
    let receipts_root = get32(5, "receipts_root")?;
    let number = be_to_u64(&items.get(8).ok_or_else(|| anyhow!("header missing number"))?.bytes)?;
    let hash = keccak256(header_rlp);
    Ok(DecodedHeader {
        number,
        hash,
        state_root,
        transactions_root,
        receipts_root,
        field_count: items.len(),
    })
}

// ---------------------------------------------------------------------------
// The public witness-building entry point.
// ---------------------------------------------------------------------------

/// Optional secp256k1 ownership material. When `debug` is true the circuit ignores
/// these (pass `None` and all-zeros are used).
pub struct Ownership {
    pub pubkey_x: [u8; 32],
    pub pubkey_y: [u8; 32],
    pub signature: [u8; 64],
}

/// Build the flat witness vector (decimal strings, ABI order).
///
/// * `eth_proof` - the `result` object of `eth_getProof(address, [], block)`
///   (must contain `address`, `nonce`, `balance`, `storageHash`, `codeHash`,
///   `accountProof`).
/// * `header_rlp` - raw bytes from `debug_getRawHeader(block)`.
/// * `threshold` - reserve threshold in wei (u128, public).
/// * `chain_id` - e.g. 1 (public).
/// * `debug` - public ownership bypass; true for tests without a wallet signature.
/// * `ownership` - secp256k1 pubkey + signature; ignored (zeros) when `debug`.
pub fn build_witness(
    eth_proof: &Value,
    header_rlp: &[u8],
    threshold: u128,
    chain_id: u32,
    debug: bool,
    ownership: Option<&Ownership>,
) -> Result<Vec<String>> {
    // ---- header ----
    let header = decode_header(header_rlp)?;

    // ---- address & account ----
    let addr_hex = eth_proof["address"]
        .as_str()
        .ok_or_else(|| anyhow!("eth_getProof result missing `address`"))?;
    let address = hex_decode(addr_hex)?;
    if address.len() != 20 {
        bail!("address is {} bytes, want 20", address.len());
    }

    let nonce = parse_hex_u64(
        eth_proof["nonce"].as_str().ok_or_else(|| anyhow!("missing `nonce`"))?,
    )?;
    let balance_dec = hex_quantity_to_decimal(
        eth_proof["balance"].as_str().ok_or_else(|| anyhow!("missing `balance`"))?,
    )?;
    let storage_root = hex_decode(
        eth_proof["storageHash"].as_str().ok_or_else(|| anyhow!("missing `storageHash`"))?,
    )?;
    let code_hash = hex_decode(
        eth_proof["codeHash"].as_str().ok_or_else(|| anyhow!("missing `codeHash`"))?,
    )?;
    if storage_root.len() != 32 || code_hash.len() != 32 {
        bail!("storageHash/codeHash not 32 bytes");
    }

    // ---- state proof ----
    let account_proof: Vec<Vec<u8>> = eth_proof["accountProof"]
        .as_array()
        .ok_or_else(|| anyhow!("missing `accountProof`"))?
        .iter()
        .map(|v| {
            v.as_str()
                .ok_or_else(|| anyhow!("accountProof entry not a string"))
                .and_then(hex_decode)
        })
        .collect::<Result<_>>()?;
    let depth = account_proof.len();
    if depth == 0 {
        bail!("empty accountProof");
    }
    if depth > MAX_NODES {
        bail!("proof depth {depth} exceeds circuit max {MAX_NODES}");
    }

    // key = keccak256(address) LEFT-padded to 66.
    let key_hash = keccak256(&address);
    let key = pad_left(&key_hash, KEY_LEN)?;

    // value = the trie leaf's RLP value field (fromRlp(leaf)[1]), LEFT-padded to 110.
    // This is the canonical account RLP [nonce, balance, storageRoot, codeHash]; we
    // take it from the proof leaf so it matches the trie path byte-for-byte.
    let leaf_node = &account_proof[depth - 1];
    let leaf_items = rlp_decode_list(leaf_node)
        .map_err(|e| anyhow!("decoding account leaf node: {e}"))?;
    if leaf_items.len() != 2 {
        bail!("account leaf node has {} items, want 2 [path, value]", leaf_items.len());
    }
    let account_rlp_value = &leaf_items[1].bytes; // the account RLP
    let value = pad_left(account_rlp_value, VALUE_LEN)?;

    // nodes = accountProof[0..depth-1], each RIGHT-padded to 532; array padded to 10.
    let mut nodes: Vec<Vec<u8>> = Vec::with_capacity(MAX_NODES);
    for node in &account_proof[..depth - 1] {
        nodes.push(pad_right(node, MAX_TRIE_NODE_LEN)?);
    }
    while nodes.len() < MAX_NODES {
        nodes.push(vec![0u8; MAX_TRIE_NODE_LEN]);
    }

    // leaf = accountProof[depth-1] RIGHT-padded to 148.
    let leaf = pad_right(leaf_node, MAX_LEAF_LEN)?;

    // ---- ownership ----
    let zeros32 = [0u8; 32];
    let zeros64 = [0u8; 64];
    let (pkx, pky, sig): (&[u8; 32], &[u8; 32], &[u8; 64]) = match ownership {
        Some(o) if !debug => (&o.pubkey_x, &o.pubkey_y, &o.signature),
        _ => (&zeros32, &zeros32, &zeros64),
    };

    // ---- flatten in ABI order ----
    let mut w: Vec<String> = Vec::new();
    let push_bytes = |w: &mut Vec<String>, b: &[u8]| {
        for &x in b {
            w.push((x as u32).to_string());
        }
    };

    // public: threshold, block_hash, chain_id, debug
    w.push(threshold.to_string());
    push_bytes(&mut w, &header.hash); // block_hash == keccak256(header_rlp)
    w.push((chain_id as u64).to_string());
    w.push(if debug { "1" } else { "0" }.to_string());

    // private: address
    push_bytes(&mut w, &address);

    // account: nonce, balance (Field decimal), storage_root, code_hash
    w.push(nonce.to_string());
    w.push(balance_dec);
    push_bytes(&mut w, &storage_root);
    push_bytes(&mut w, &code_hash);

    // state_proof: key, value, proof{nodes, leaf, depth}
    push_bytes(&mut w, &key);
    push_bytes(&mut w, &value);
    for node in &nodes {
        push_bytes(&mut w, node);
    }
    push_bytes(&mut w, &leaf);
    w.push((depth as u64).to_string());

    // header: number, hash, state_root, transactions_root, receipts_root
    w.push(header.number.to_string());
    push_bytes(&mut w, &header.hash);
    push_bytes(&mut w, &header.state_root);
    push_bytes(&mut w, &header.transactions_root);
    push_bytes(&mut w, &header.receipts_root);

    // header_rlp: BoundedVec { storage[708], len }
    let storage = pad_right(header_rlp, MAX_HEADER_RLP_LEN)?;
    push_bytes(&mut w, &storage);
    w.push((header_rlp.len() as u64).to_string());

    // pubkey_x, pubkey_y, signature
    push_bytes(&mut w, pkx);
    push_bytes(&mut w, pky);
    push_bytes(&mut w, sig);

    Ok(w)
}
