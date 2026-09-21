use blake3::hazmat::HasherExt;

const IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

const CHUNK_START: u8 = 1 << 0;
const CHUNK_END: u8 = 1 << 1;
const PARENT: u8 = 1 << 2;
const ROOT: u8 = 1 << 3;
const DERIVE_KEY_CONTEXT: u8 = 1 << 5;

#[inline(always)]
fn g(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(mx);
    state[d] = (state[d] ^ state[a]).rotate_right(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(12);
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(my);
    state[d] = (state[d] ^ state[a]).rotate_right(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_right(7);
}

#[inline(always)]
fn round(state: &mut [u32; 16], m: &[u32; 16]) {
    g(state, 0, 4, 8, 12, m[0], m[1]);
    g(state, 1, 5, 9, 13, m[2], m[3]);
    g(state, 2, 6, 10, 14, m[4], m[5]);
    g(state, 3, 7, 11, 15, m[6], m[7]);
    g(state, 0, 5, 10, 15, m[8], m[9]);
    g(state, 1, 6, 11, 12, m[10], m[11]);
    g(state, 2, 7, 8, 13, m[12], m[13]);
    g(state, 3, 4, 9, 14, m[14], m[15]);
}

fn compress_block(
    cv: &[u32; 8],
    block: &[u8],
    block_len: u8,
    counter: u64,
    flags: u8,
) -> [u32; 16] {
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        IV[0],
        IV[1],
        IV[2],
        IV[3],
        counter as u32,
        (counter >> 32) as u32,
        block_len as u32,
        flags as u32,
    ];
    let mut m = [0u32; 16];
    for (i, chunk) in block.chunks(4).enumerate() {
        let mut b = [0u8; 4];
        b[..chunk.len()].copy_from_slice(chunk);
        m[i] = u32::from_le_bytes(b);
    }
    let mut m_curr = m;
    for _ in 0..7 {
        round(&mut state, &m_curr);
        let mut m_next = [0u32; 16];
        for i in 0..16 {
            m_next[i] = m_curr[MSG_PERMUTATION[i]];
        }
        m_curr = m_next;
    }
    for i in 0..8 {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }
    state
}

fn hash_context_chunk(chunk_bytes: &[u8], chunk_counter: u64, is_root: bool) -> [u32; 8] {
    let mut cv = IV;
    let total_len = chunk_bytes.len();
    if total_len == 0 {
        let root_flag = if is_root { ROOT } else { 0 };
        let out = compress_block(
            &cv,
            &[],
            0,
            chunk_counter,
            CHUNK_START | CHUNK_END | root_flag | DERIVE_KEY_CONTEXT,
        );
        let mut res = [0u32; 8];
        res.copy_from_slice(&out[..8]);
        return res;
    }

    let num_blocks = (total_len + 63) / 64;
    for i in 0..num_blocks {
        let start = i * 64;
        let end = (start + 64).min(total_len);
        let block = &chunk_bytes[start..end];
        let mut flags = DERIVE_KEY_CONTEXT;
        if i == 0 {
            flags |= CHUNK_START;
        }
        if i == num_blocks - 1 {
            flags |= CHUNK_END;
            if is_root {
                flags |= ROOT;
            }
        }
        let out = compress_block(&cv, block, block.len() as u8, chunk_counter, flags);
        cv.copy_from_slice(&out[..8]);
    }
    cv
}

fn hash_derive_key_context_safe(context: &[u8]) -> [u8; 32] {
    if context.len() <= 1024 {
        let cv = hash_context_chunk(context, 0, true);
        let mut out = [0u8; 32];
        for (i, word) in cv.iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    } else {
        let mut chunk_cvs: Vec<[u32; 8]> = Vec::new();
        for (counter, chunk_bytes) in context.chunks(1024).enumerate() {
            chunk_cvs.push(hash_context_chunk(chunk_bytes, counter as u64, false));
        }

        while chunk_cvs.len() > 1 {
            let mut next_level: Vec<[u32; 8]> = Vec::new();
            for pair in chunk_cvs.chunks(2) {
                if pair.len() == 2 {
                    let mut parent_block = [0u8; 64];
                    for (i, w) in pair[0].iter().enumerate() {
                        parent_block[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
                    }
                    for (i, w) in pair[1].iter().enumerate() {
                        parent_block[32 + i * 4..32 + (i + 1) * 4]
                            .copy_from_slice(&w.to_le_bytes());
                    }
                    let is_root = chunk_cvs.len() == 2;
                    let root_flag = if is_root { ROOT } else { 0 };
                    let out = compress_block(
                        &IV,
                        &parent_block,
                        64,
                        0,
                        PARENT | root_flag | DERIVE_KEY_CONTEXT,
                    );
                    let mut cv = [0u32; 8];
                    cv.copy_from_slice(&out[..8]);
                    next_level.push(cv);
                } else {
                    next_level.push(pair[0]);
                }
            }
            chunk_cvs = next_level;
        }

        let mut out = [0u8; 32];
        for (i, word) in chunk_cvs[0].iter().enumerate() {
            out[i * 4..(i + 1) * 4].copy_from_slice(&word.to_le_bytes());
        }
        out
    }
}

pub fn derive_key(context: &[u8], key_material: &[u8]) -> [u8; 32] {
    let context_key = hash_derive_key_context_safe(context);

    let mut hasher = blake3::Hasher::new_from_context_key(&context_key);
    hasher.update(key_material);
    *hasher.finalize().as_bytes()
}

pub fn sum256(data: &[u8]) -> [u8; 32] {
    *blake3::hash(data).as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_length() {
        let key = b"example-key-material-for-test";
        let subkey = derive_key(b"VLESS", key);
        assert_eq!(subkey.len(), 32);
        assert_ne!(subkey, [0u8; 32]);
    }

    #[test]
    fn test_derive_key_ascii_context() {
        let key = b"01234567890123456789012345678901";
        let subkey = derive_key(b"VLESS", key);

        let subkey2 = derive_key(b"VLESS", key);
        assert_eq!(subkey, subkey2);
        assert_ne!(subkey, [0u8; 32]);
    }

    #[test]
    fn test_derive_key_binary_context_null_bytes() {
        let ctx = [0x00u8, 0x01, 0x02, 0x00, 0xFF, 0x80, 0x7F];
        let key = b"key-material-for-binary-context!";
        let out = derive_key(&ctx, key);
        assert_eq!(out.len(), 32);
        assert_ne!(out, [0u8; 32]);

        assert_eq!(out, derive_key(&ctx, key));
    }

    #[test]
    fn test_derive_key_binary_context_high_bytes() {
        let ctx = [0x80u8, 0x81, 0x82, 0xFF, 0xFE, 0xFD];
        let key = b"another-key-material-32-bytes!!!";
        let out = derive_key(&ctx, key);
        assert_eq!(out.len(), 32);
        assert_ne!(out, [0u8; 32]);
    }

    #[test]
    fn test_derive_key_random_iv_ticket() {
        let iv: [u8; 16] = [
            0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x80, 0xFF, 0x42, 0x13, 0x37, 0x00, 0xC0, 0xFF,
            0xEE, 0x00,
        ];
        let key = b"vless-test-key-material-32bytes!";
        let out = derive_key(&iv, key);
        assert_eq!(out.len(), 32);
        assert_ne!(out, [0u8; 32]);

        let out2 = derive_key(&iv[1..], key);
        assert_ne!(out, out2);
    }

    #[test]
    fn test_derive_key_different_context_different_output() {
        let key = b"same-key-material-32-bytes-long!";
        let out1 = derive_key(b"VLESS", key);
        let out2 = derive_key(b"XRAY", key);
        let out3 = derive_key(&[0x00u8; 1], key);

        assert_ne!(out1, out2);
        assert_ne!(out1, out3);
        assert_ne!(out2, out3);
    }

    #[test]
    fn test_sum256() {
        let h = sum256(b"hello world");
        assert_eq!(h.len(), 32);

        assert_eq!(h, sum256(b"hello world"));
        assert_ne!(h, sum256(b"hello world!"));
    }

    #[test]
    fn test_derive_key_xray_golden_vector() {
        let iv = [0u8, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let key = b"01234567890123456789012345678901";
        let out = derive_key(&iv, key);
        let expected_hex = "ccbb6d58251b5a08a4659b56b6ff30e7a1e933e7884ed68d23805b0eceeab087";
        assert_eq!(hex::encode(out), expected_hex);
    }

    #[test]
    fn test_derive_key_large_context_multichunk() {
        let large_ctx = vec![0x42u8; 1216];
        let key = b"01234567890123456789012345678901";
        let out1 = derive_key(&large_ctx, key);
        let out2 = derive_key(&large_ctx, key);
        assert_eq!(out1, out2);
        assert_ne!(out1, [0u8; 32]);
    }
}
