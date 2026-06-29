// Proof of reserves - prove a balance meets a threshold without revealing it.
//
// The prover commits, during the TLS session, to a SHA256 hash of the exact
// on-wire bytes of the balance field (a JSON number such as "1120688.94")
// concatenated with a random blinder. This circuit proves two things about that
// committed value, in zero knowledge:
//
//   1. SHA256(balance_bytes ++ blinder) == committed_hash   (binds to the wire)
//   2. floor(balance) >= threshold                          (the predicate)
//
// Public inputs : threshold (integer USD), committed_hash (32 bytes)
// Private inputs: the balance ASCII bytes, their true length, and the blinder.
//
// Because the committed hash binds the EXACT field bytes (including length), a
// cheating prover cannot substitute a different balance or truncate it without
// breaking constraint (1). So the verifier only needs the public threshold and
// the hash (which it cross-checks against the notary-signed commitment).

global MAX_BALANCE_LEN: u32 = 32; // max ASCII length of the balance field
global BLINDER_LEN: u32 = 16; // TLSNotary hash-commitment blinder length
global HASH_CAP: u32 = 48; // MAX_BALANCE_LEN + BLINDER_LEN

fn main(
    threshold: pub u64,
    committed_hash: pub [u8; 32],
    balance: [u8; MAX_BALANCE_LEN],
    balance_len: u32,
    blinder: [u8; BLINDER_LEN],
) {
    assert(balance_len <= MAX_BALANCE_LEN, "balance longer than MAX_BALANCE_LEN");

    // (1) Bind to the bytes that actually went over the wire.
    let correct_hash = check_hash(balance, balance_len, blinder, committed_hash);
    assert(correct_hash, "balance/blinder do not match the committed hash");

    // (2) Prove the threshold predicate on the integer part.
    let int_value = parse_integer_part(balance, balance_len);
    println(f"integer balance = {int_value}, threshold = {threshold}");
    assert(int_value >= threshold, "balance is below the threshold");
}

// SHA256(balance[0..balance_len] ++ blinder) == committed_hash
fn check_hash(
    balance: [u8; MAX_BALANCE_LEN],
    balance_len: u32,
    blinder: [u8; BLINDER_LEN],
    committed_hash: [u8; 32],
) -> bool {
    let mut input: [u8; HASH_CAP] = [0; HASH_CAP];
    for i in 0..MAX_BALANCE_LEN {
        if i < balance_len {
            input[i] = balance[i];
        }
    }
    // Append the blinder immediately after the real balance bytes.
    for i in 0..BLINDER_LEN {
        input[balance_len + i] = blinder[i];
    }
    let computed = sha256::sha256_var(input, balance_len + BLINDER_LEN);
    computed == committed_hash
}

// Parse the integer part of a decimal ASCII number: every digit before the '.'.
// A purely-integer string (no '.') parses in full. Bytes after the point are
// ignored, so this computes floor(balance).
fn parse_integer_part(balance: [u8; MAX_BALANCE_LEN], balance_len: u32) -> u64 {
    let mut value: u64 = 0;
    let mut past_point = false;
    for i in 0..MAX_BALANCE_LEN {
        if i < balance_len {
            let c = balance[i];
            if c == 46 {
                // '.' (start of the fractional part)
                past_point = true;
            } else if !past_point {
                let is_digit = (c >= 48) & (c <= 57);
                assert(is_digit, "non-digit byte before the decimal point");
                value = value * 10 + (c - 48) as u64;
            }
        }
    }
    value
}

#[test]
fn test_above_threshold() {
    // balance = "1234.56", blinder = [0,1,..,15]; integer part 1234 >= 1000.
    let balance = pad_balance("1234.56".as_bytes(), 7);
    let blinder = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let committed_hash = [
        223, 101, 196, 128, 142, 141, 43, 88, 77, 199, 141, 239, 180, 121, 190, 253, 193, 76, 28,
        106, 171, 133, 184, 140, 235, 42, 58, 153, 130, 144, 195, 146,
    ];
    main(1000, committed_hash, balance, 7, blinder);
}

#[test(should_fail_with = "balance is below the threshold")]
fn test_below_threshold() {
    // Same committed balance (1234), but threshold 2000 > 1234 -> must fail.
    let balance = pad_balance("1234.56".as_bytes(), 7);
    let blinder = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let committed_hash = [
        223, 101, 196, 128, 142, 141, 43, 88, 77, 199, 141, 239, 180, 121, 190, 253, 193, 76, 28,
        106, 171, 133, 184, 140, 235, 42, 58, 153, 130, 144, 195, 146,
    ];
    main(2000, committed_hash, balance, 7, blinder);
}

#[test(should_fail_with = "balance/blinder do not match the committed hash")]
fn test_wrong_hash() {
    // A balance that does not match the committed hash must fail constraint (1).
    let balance = pad_balance("9999.99".as_bytes(), 7);
    let blinder = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
    let committed_hash = [
        223, 101, 196, 128, 142, 141, 43, 88, 77, 199, 141, 239, 180, 121, 190, 253, 193, 76, 28,
        106, 171, 133, 184, 140, 235, 42, 58, 153, 130, 144, 195, 146,
    ];
    main(1000, committed_hash, balance, 7, blinder);
}

// Helper: copy `len` bytes of `src` into a zero-padded [u8; MAX_BALANCE_LEN].
fn pad_balance<let N: u32>(src: [u8; N], len: u32) -> [u8; MAX_BALANCE_LEN] {
    let mut out: [u8; MAX_BALANCE_LEN] = [0; MAX_BALANCE_LEN];
    for i in 0..N {
        if i < len {
            out[i] = src[i];
        }
    }
    out
}
