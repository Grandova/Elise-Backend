//! Hysteria Obfuscation implementations:
//! - Hysteria 1: XPlus (16-byte random salt + SHA-256(key || salt) XOR)
//! - Hysteria 2: Salamander (8-byte random salt + BLAKE2b-256(password || salt) XOR)
//! - Hysteria 2: Gecko (Salamander with packet size padding & fragmentation)

use parking_lot::Mutex;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::AtomicU32;
use std::time::{Duration, Instant};

// ============================================================================
// RFC 7693 Standard BLAKE2b-256 (32-byte digest, unkeyed)
// ============================================================================

const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn blake2b_compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] = !v[14];
    }

    let mut m = [0u64; 16];
    for i in 0..16 {
        m[i] = u64::from_le_bytes(block[i * 8..(i + 1) * 8].try_into().unwrap());
    }

    for round in 0..12 {
        let s = &SIGMA[round % 10];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }

    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

pub fn blake2b_256(data: &[u8]) -> [u8; 32] {
    let mut h = BLAKE2B_IV;
    // Parameter block: digest size 32 bytes (0x20), key size 0, fanout 1, depth 1
    h[0] ^= 0x01010020;

    let mut t: u128 = 0;
    let mut offset = 0;
    let len = data.len();

    while offset + 128 < len {
        t += 128;
        let mut block = [0u8; 128];
        block.copy_from_slice(&data[offset..offset + 128]);
        blake2b_compress(&mut h, &block, t, false);
        offset += 128;
    }

    let remaining = len - offset;
    t += remaining as u128;
    let mut last_block = [0u8; 128];
    last_block[..remaining].copy_from_slice(&data[offset..]);
    blake2b_compress(&mut h, &last_block, t, true);

    let mut out = [0u8; 32];
    for (i, word) in h[..4].iter().enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&word.to_le_bytes());
    }
    out
}

// ============================================================================
// Hysteria 1: XPlus Obfuscation (16-byte salt + SHA-256)
// ============================================================================

#[derive(Debug)]
pub struct XPlusObfs {
    key: Vec<u8>,
}

impl XPlusObfs {
    pub const SALT_LEN: usize = 16;

    pub fn new(password: &str) -> Self {
        Self {
            key: password.as_bytes().to_vec(),
        }
    }

    pub fn obfuscate(&self, payload: &[u8], out: &mut Vec<u8>) {
        out.clear();
        out.reserve(Self::SALT_LEN + payload.len());
        let mut salt = [0u8; Self::SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        out.extend_from_slice(&salt);

        let mut hasher = Sha256::new();
        hasher.update(&self.key);
        hasher.update(&salt);
        let mask = hasher.finalize();

        for (i, &b) in payload.iter().enumerate() {
            out.push(b ^ mask[i % 32]);
        }
    }

    pub fn deobfuscate(&self, wire: &[u8], out: &mut Vec<u8>) -> bool {
        if wire.len() < Self::SALT_LEN {
            return false;
        }
        let salt = &wire[..Self::SALT_LEN];
        let payload = &wire[Self::SALT_LEN..];

        let mut hasher = Sha256::new();
        hasher.update(&self.key);
        hasher.update(salt);
        let mask = hasher.finalize();

        out.clear();
        out.reserve(payload.len());
        for (i, &b) in payload.iter().enumerate() {
            out.push(b ^ mask[i % 32]);
        }
        true
    }
}

// ============================================================================
// Hysteria 2: Salamander Obfuscation (8-byte salt + BLAKE2b-256)
// ============================================================================

#[derive(Debug)]
pub struct SalamanderObfs {
    password: Vec<u8>,
}

impl SalamanderObfs {
    pub const SALT_LEN: usize = 8;

    pub fn new(password: &str) -> Self {
        Self {
            password: password.as_bytes().to_vec(),
        }
    }

    pub fn obfuscate(&self, payload: &[u8], out: &mut Vec<u8>) {
        out.clear();
        out.reserve(Self::SALT_LEN + payload.len());
        let mut salt = [0u8; Self::SALT_LEN];
        rand::thread_rng().fill_bytes(&mut salt);
        out.extend_from_slice(&salt);

        let mut input = Vec::with_capacity(self.password.len() + Self::SALT_LEN);
        input.extend_from_slice(&self.password);
        input.extend_from_slice(&salt);
        let mask = blake2b_256(&input);

        for (i, &b) in payload.iter().enumerate() {
            out.push(b ^ mask[i % 32]);
        }
    }

    pub fn deobfuscate(&self, wire: &[u8], out: &mut Vec<u8>) -> bool {
        if wire.len() <= Self::SALT_LEN {
            return false;
        }
        let salt = &wire[..Self::SALT_LEN];
        let payload = &wire[Self::SALT_LEN..];

        let mut input = Vec::with_capacity(self.password.len() + Self::SALT_LEN);
        input.extend_from_slice(&self.password);
        input.extend_from_slice(salt);
        let mask = blake2b_256(&input);

        out.clear();
        out.reserve(payload.len());
        for (i, &b) in payload.iter().enumerate() {
            out.push(b ^ mask[i % 32]);
        }
        true
    }
}

// ============================================================================
// Hysteria 2: Gecko Obfuscation (Salamander + Length/Fragment Shuffling)
// ============================================================================

const GECKO_FRAGMENT_FLAG: u8 = 0x80;
const GECKO_HEADER_LEN: usize = 5;

#[derive(Debug, Clone)]
struct GeckoReassemblyEntry {
    chunks: Vec<Option<Vec<u8>>>,
    received: usize,
    total: u8,
    deadline: Instant,
}

#[derive(Debug)]
pub struct GeckoObfs {
    salamander: SalamanderObfs,
    #[allow(dead_code)]
    min_packet_size: usize,
    #[allow(dead_code)]
    max_packet_size: usize,
    #[allow(dead_code)]
    msg_id_counter: AtomicU32,
    reassembly: Mutex<HashMap<(SocketAddr, u8), GeckoReassemblyEntry>>,
}

impl GeckoObfs {
    pub fn new(password: &str, min_size: usize, max_size: usize) -> Self {
        Self {
            salamander: SalamanderObfs::new(password),
            min_packet_size: min_size.max(256),
            max_packet_size: max_size.min(2048).max(512),
            msg_id_counter: AtomicU32::new(1),
            reassembly: Mutex::new(HashMap::new()),
        }
    }

    pub fn min_packet_size(&self) -> usize {
        self.min_packet_size
    }

    pub fn max_packet_size(&self) -> usize {
        self.max_packet_size
    }

    pub fn obfuscate(&self, payload: &[u8], out: &mut Vec<u8>) {
        self.salamander.obfuscate(payload, out);
    }

    pub fn deobfuscate(&self, wire: &[u8], remote: SocketAddr, out: &mut Vec<u8>) -> bool {
        let mut inner = Vec::new();
        if !self.salamander.deobfuscate(wire, &mut inner) {
            return false;
        }
        if inner.is_empty() {
            return false;
        }

        // If fragment flag is NOT set, this is a plain Salamander packet
        if (inner[0] & GECKO_FRAGMENT_FLAG) == 0 {
            *out = inner;
            return true;
        }

        // Handle fragmented Gecko packet:
        // [0]: flag (0x80)
        // [1]: msg_id
        // [2]: (chunk_idx << 4) | (total_chunks & 0x0f)
        // [3..5]: pad_len (BE u16)
        // [5..5+pad_len]: padding
        // [5+pad_len..]: chunk payload
        if inner.len() < GECKO_HEADER_LEN {
            return false;
        }
        let msg_id = inner[1];
        let chunk_idx = (inner[2] >> 4) as usize;
        let total_chunks = (inner[2] & 0x0f) as usize;
        let pad_len = u16::from_be_bytes([inner[3], inner[4]]) as usize;
        let data_offset = GECKO_HEADER_LEN + pad_len;

        if total_chunks == 0 || chunk_idx >= total_chunks || inner.len() < data_offset {
            return false;
        }
        let chunk_data = inner[data_offset..].to_vec();

        let mut lock = self.reassembly.lock();
        // Sweep expired entries if cache is growing
        if lock.len() > 1024 {
            let now = Instant::now();
            lock.retain(|_, v| v.deadline > now);
        }

        let key = (remote, msg_id);
        let entry = lock.entry(key).or_insert_with(|| GeckoReassemblyEntry {
            chunks: vec![None; total_chunks],
            received: 0,
            total: total_chunks as u8,
            deadline: Instant::now() + Duration::from_secs(8),
        });

        if entry.total as usize != total_chunks || chunk_idx >= entry.chunks.len() {
            return false;
        }

        if entry.chunks[chunk_idx].is_none() {
            entry.chunks[chunk_idx] = Some(chunk_data);
            entry.received += 1;
        }

        if entry.received == total_chunks {
            out.clear();
            for c in entry.chunks.iter().flatten() {
                out.extend_from_slice(c);
            }
            lock.remove(&key);
            true
        } else {
            false
        }
    }
}

// ============================================================================
// Unified Obfuscator Enum
// ============================================================================

#[derive(Debug)]
pub enum HysteriaObfuscator {
    None,
    XPlus(XPlusObfs),
    Salamander(SalamanderObfs),
    Gecko(GeckoObfs),
}

impl HysteriaObfuscator {
    pub fn obfuscate(&self, payload: &[u8], out: &mut Vec<u8>) {
        match self {
            Self::None => {
                out.clear();
                out.extend_from_slice(payload);
            }
            Self::XPlus(x) => x.obfuscate(payload, out),
            Self::Salamander(s) => s.obfuscate(payload, out),
            Self::Gecko(g) => g.obfuscate(payload, out),
        }
    }

    pub fn deobfuscate(&self, wire: &[u8], remote: SocketAddr, out: &mut Vec<u8>) -> bool {
        match self {
            Self::None => {
                out.clear();
                out.extend_from_slice(wire);
                true
            }
            Self::XPlus(x) => x.deobfuscate(wire, out),
            Self::Salamander(s) => s.deobfuscate(wire, out),
            Self::Gecko(g) => g.deobfuscate(wire, remote, out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake2b_256_golden_vector() {
        // RFC 7693 Appendix E.1 / standard test vector for empty string and "The quick brown fox..."
        let empty_hash = blake2b_256(b"");
        assert_eq!(
            hex::encode(empty_hash),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );

        let fox_hash = blake2b_256(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(
            hex::encode(fox_hash),
            "01718cec35cd3d796dd00020e0bfecb473ad23457d063b75eff29c0ffa2e58a9"
        );
    }

    #[test]
    fn test_xplus_obfs_roundtrip() {
        let obfs = XPlusObfs::new("HY1_Test_Password");
        let msg = b"Hello, Hysteria 1 XPlus wire!";
        let mut wire = Vec::new();
        obfs.obfuscate(msg, &mut wire);
        assert_eq!(wire.len(), XPlusObfs::SALT_LEN + msg.len());
        assert_ne!(&wire[XPlusObfs::SALT_LEN..], msg);

        let mut decrypted = Vec::new();
        assert!(obfs.deobfuscate(&wire, &mut decrypted));
        assert_eq!(decrypted, msg);
    }

    #[test]
    fn test_salamander_obfs_roundtrip() {
        let obfs = SalamanderObfs::new("HY2_Test_Salamander_Password");
        let msg = b"Hello, Hysteria 2 Salamander wire!";
        let mut wire = Vec::new();
        obfs.obfuscate(msg, &mut wire);
        assert_eq!(wire.len(), SalamanderObfs::SALT_LEN + msg.len());
        assert_ne!(&wire[SalamanderObfs::SALT_LEN..], msg);

        let mut decrypted = Vec::new();
        assert!(obfs.deobfuscate(&wire, &mut decrypted));
        assert_eq!(decrypted, msg);
    }
}
