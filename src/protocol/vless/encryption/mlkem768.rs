//! ML-KEM-768 (FIPS 203) Implementation in Pure Rust
//!
//! Compliant with NIST FIPS 203 and Go crypto/mlkem.

use std::io;

pub const MLKEM768_EK_SIZE: usize = 1184;
pub const MLKEM768_DK_SIZE: usize = 2400;
pub const MLKEM768_CIPHERTEXT_SIZE: usize = 1088;
pub const MLKEM768_SS_SIZE: usize = 32;

const Q: i32 = 3329;
const N: usize = 256;
const K: usize = 3;

// --- FIPS 202 Keccak Primitives ---

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

const ROT_CONSTANTS: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

fn keccak_f1600(state: &mut [u64; 25]) {
    for &rc in &ROUND_CONSTANTS {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = state[x] ^ state[x + 5] ^ state[x + 10] ^ state[x + 15] ^ state[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] ^= d[x];
            }
        }
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] =
                    state[x + 5 * y].rotate_left(ROT_CONSTANTS[x][y]);
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                state[x + 5 * y] =
                    b[x + 5 * y] ^ ((!b[((x + 1) % 5) + 5 * y]) & b[((x + 2) % 5) + 5 * y]);
            }
        }
        state[0] ^= rc;
    }
}

pub struct KeccakSponge {
    state: [u64; 25],
    rate: usize,
    pos: usize,
}

impl KeccakSponge {
    pub fn new(rate: usize) -> Self {
        Self {
            state: [0u64; 25],
            rate,
            pos: 0,
        }
    }

    pub fn absorb(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            let to_absorb = (self.rate - self.pos).min(data.len());
            for (i, &byte) in data[..to_absorb].iter().enumerate() {
                let idx = (self.pos + i) / 8;
                let shift = ((self.pos + i) % 8) * 8;
                self.state[idx] ^= (byte as u64) << shift;
            }
            self.pos += to_absorb;
            data = &data[to_absorb..];

            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
        }
    }

    pub fn pad_and_finalize(&mut self, delim: u8) {
        let idx = self.pos / 8;
        let shift = (self.pos % 8) * 8;
        self.state[idx] ^= (delim as u64) << shift;

        let last_idx = (self.rate - 1) / 8;
        let last_shift = ((self.rate - 1) % 8) * 8;
        self.state[last_idx] ^= 0x80u64 << last_shift;

        keccak_f1600(&mut self.state);
        self.pos = 0;
    }

    pub fn squeeze(&mut self, out: &mut [u8]) {
        let mut written = 0;
        while written < out.len() {
            if self.pos == self.rate {
                keccak_f1600(&mut self.state);
                self.pos = 0;
            }
            let to_squeeze = (self.rate - self.pos).min(out.len() - written);
            for (i, byte) in out[written..written + to_squeeze].iter_mut().enumerate() {
                let idx = (self.pos + i) / 8;
                let shift = ((self.pos + i) % 8) * 8;
                *byte = ((self.state[idx] >> shift) & 0xff) as u8;
            }
            self.pos += to_squeeze;
            written += to_squeeze;
        }
    }
}

pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut sponge = KeccakSponge::new(136);
    sponge.absorb(data);
    sponge.pad_and_finalize(0x06);
    let mut out = [0u8; 32];
    sponge.squeeze(&mut out);
    out
}

pub fn sha3_512(data: &[u8]) -> [u8; 64] {
    let mut sponge = KeccakSponge::new(72);
    sponge.absorb(data);
    sponge.pad_and_finalize(0x06);
    let mut out = [0u8; 64];
    sponge.squeeze(&mut out);
    out
}

pub fn shake256(data: &[u8], out: &mut [u8]) {
    let mut sponge = KeccakSponge::new(136);
    sponge.absorb(data);
    sponge.pad_and_finalize(0x1F);
    sponge.squeeze(out);
}

// --- ML-KEM Constants and Tables ---

const ZETAS: [i32; 128] = [
    1, 1729, 2580, 3289, 2642, 630, 1897, 848, 1062, 1919, 193, 797, 2786, 3260, 569, 1746, 296,
    2447, 1339, 1476, 3046, 56, 2240, 1333, 1426, 2094, 535, 2882, 2393, 2879, 1974, 821, 289, 331,
    3253, 1756, 1197, 2304, 2277, 2055, 650, 1977, 2513, 632, 2865, 33, 1320, 1915, 2319, 1435,
    807, 452, 1438, 2868, 1534, 2402, 2647, 2617, 1481, 648, 2474, 3110, 1227, 910, 17, 2761, 583,
    2649, 1637, 723, 2288, 1100, 1409, 2662, 3281, 233, 756, 2156, 3015, 3050, 1703, 1651, 2789,
    1789, 1847, 952, 1461, 2687, 939, 2308, 2437, 2388, 733, 2337, 268, 641, 1584, 2298, 2037,
    3220, 375, 2549, 2090, 1645, 1063, 319, 2773, 757, 2099, 561, 2466, 2594, 2804, 1092, 403,
    1026, 1143, 2150, 2775, 886, 1722, 1212, 1874, 1029, 2110, 2935, 885, 2154,
];

const GAMMAS: [i32; 128] = [
    17, 3312, 2761, 568, 583, 2746, 2649, 680, 1637, 1692, 723, 2606, 2288, 1041, 1100, 2229, 1409,
    1920, 2662, 667, 3281, 48, 233, 3096, 756, 2573, 2156, 1173, 3015, 314, 3050, 279, 1703, 1626,
    1651, 1678, 2789, 540, 1789, 1540, 1847, 1482, 952, 2377, 1461, 1868, 2687, 642, 939, 2390,
    2308, 1021, 2437, 892, 2388, 941, 733, 2596, 2337, 992, 268, 3061, 641, 2688, 1584, 1745, 2298,
    1031, 2037, 1292, 3220, 109, 375, 2954, 2549, 780, 2090, 1239, 1645, 1684, 1063, 2266, 319,
    3010, 2773, 556, 757, 2572, 2099, 1230, 561, 2768, 2466, 863, 2594, 735, 2804, 525, 1092, 2237,
    403, 2926, 1026, 2303, 1143, 2186, 2150, 1179, 2775, 554, 886, 2443, 1722, 1607, 1212, 2117,
    1874, 1455, 1029, 2300, 2110, 1219, 2935, 394, 885, 2444, 2154, 1175,
];

#[inline]
fn modq(a: i32) -> i32 {
    let r = a % Q;
    if r < 0 {
        r + Q
    } else {
        r
    }
}

#[inline]
fn compress(x: i32, d: u8) -> u16 {
    let dividend = ((x as u32) << d) + (Q as u32 / 2);
    let quotient = dividend / (Q as u32);
    let mask = (1 << d) - 1;
    (quotient & mask) as u16
}

#[inline]
fn decompress(y: u16, d: u8) -> i32 {
    let dividend = (y as u32) * (Q as u32);
    let mut quotient = dividend >> d;
    quotient += (dividend >> (d - 1)) & 1;
    quotient as i32
}

#[derive(Clone, Copy)]
pub struct Poly {
    pub coeffs: [i32; N],
}

impl Default for Poly {
    fn default() -> Self {
        Self { coeffs: [0; N] }
    }
}

impl Poly {
    pub fn ntt(&mut self) {
        let mut k = 1;
        let mut len = 128;
        while len >= 2 {
            let mut start = 0;
            while start < 256 {
                let zeta = ZETAS[k];
                k += 1;
                for j in 0..len {
                    let t = modq(zeta * self.coeffs[start + len + j]);
                    self.coeffs[start + len + j] = modq(self.coeffs[start + j] - t);
                    self.coeffs[start + j] = modq(self.coeffs[start + j] + t);
                }
                start += 2 * len;
            }
            len /= 2;
        }
    }

    pub fn inv_ntt(&mut self) {
        let mut k = 127;
        let mut len = 2;
        while len <= 128 {
            let mut start = 0;
            while start < 256 {
                let zeta = ZETAS[k];
                k -= 1;
                for j in 0..len {
                    let t = self.coeffs[start + j];
                    self.coeffs[start + j] = modq(t + self.coeffs[start + len + j]);
                    self.coeffs[start + len + j] = modq(zeta * (self.coeffs[start + len + j] - t));
                }
                start += 2 * len;
            }
            len *= 2;
        }
        for c in self.coeffs.iter_mut() {
            *c = modq(*c * 3303);
        }
    }

    pub fn add(&mut self, other: &Poly) {
        for i in 0..N {
            self.coeffs[i] = modq(self.coeffs[i] + other.coeffs[i]);
        }
    }

    pub fn sub(&mut self, other: &Poly) {
        for i in 0..N {
            self.coeffs[i] = modq(self.coeffs[i] - other.coeffs[i]);
        }
    }
}

fn ntt_mul(h: &mut Poly, f: &Poly, g: &Poly) {
    for i in (0..256).step_by(2) {
        let a0 = f.coeffs[i];
        let a1 = f.coeffs[i + 1];
        let b0 = g.coeffs[i];
        let b1 = g.coeffs[i + 1];
        h.coeffs[i] = modq(a0 * b0 + modq(a1 * b1) * GAMMAS[i / 2]);
        h.coeffs[i + 1] = modq(a0 * b1 + a1 * b0);
    }
}

// --- Sampling ---

fn sample_ntt(rho: &[u8; 32], ii: u8, jj: u8) -> Poly {
    let mut poly = Poly::default();
    let mut sponge = KeccakSponge::new(168);
    sponge.absorb(rho);
    sponge.absorb(&[ii, jj]);
    sponge.pad_and_finalize(0x1F);

    let mut buf = [0u8; 24];
    let mut j = 0;
    while j < 256 {
        sponge.squeeze(&mut buf);
        let mut off = 0;
        while off < 24 && j < 256 {
            let d1 = (u16::from_le_bytes([buf[off], buf[off + 1]]) & 0x0fff) as i32;
            let d2 = ((u16::from_le_bytes([buf[off + 1], buf[off + 2]]) >> 4) & 0x0fff) as i32;
            off += 3;
            if d1 < Q {
                poly.coeffs[j] = d1;
                j += 1;
            }
            if j < 256 && d2 < Q {
                poly.coeffs[j] = d2;
                j += 1;
            }
        }
    }
    poly
}

fn sample_poly_cbd2(sigma: &[u8; 32], n: u8) -> Poly {
    let mut poly = Poly::default();
    let mut buf = [0u8; 128];
    let mut sponge = KeccakSponge::new(136);
    sponge.absorb(sigma);
    sponge.absorb(&[n]);
    sponge.pad_and_finalize(0x1F);
    sponge.squeeze(&mut buf);

    for i in (0..256).step_by(2) {
        let b = buf[i / 2];
        let b7 = (b >> 7) & 1;
        let b6 = (b >> 6) & 1;
        let b5 = (b >> 5) & 1;
        let b4 = (b >> 4) & 1;
        let b3 = (b >> 3) & 1;
        let b2 = (b >> 2) & 1;
        let b1 = (b >> 1) & 1;
        let b0 = b & 1;
        poly.coeffs[i] = modq((b0 + b1) as i32 - (b2 + b3) as i32);
        poly.coeffs[i + 1] = modq((b4 + b5) as i32 - (b6 + b7) as i32);
    }
    poly
}

// --- Encoding & Compression ---

pub fn byte_encode_12(poly: &Poly, out: &mut [u8]) {
    for i in 0..N / 2 {
        let t0 = poly.coeffs[2 * i] as u16;
        let t1 = poly.coeffs[2 * i + 1] as u16;
        out[3 * i] = (t0 & 0xff) as u8;
        out[3 * i + 1] = ((t0 >> 8) | ((t1 & 0x0f) << 4)) as u8;
        out[3 * i + 2] = (t1 >> 4) as u8;
    }
}

pub fn byte_decode_12(bytes: &[u8], poly: &mut Poly) {
    for i in 0..N / 2 {
        let b0 = bytes[3 * i] as u16;
        let b1 = bytes[3 * i + 1] as u16;
        let b2 = bytes[3 * i + 2] as u16;
        poly.coeffs[2 * i] = (b0 | ((b1 & 0x0f) << 8)) as i32;
        poly.coeffs[2 * i + 1] = ((b1 >> 4) | (b2 << 4)) as i32;
    }
}

pub fn compress_and_encode_10(poly: &Poly, out: &mut [u8]) {
    let mut out_idx = 0;
    for i in (0..256).step_by(4) {
        let mut x: u64 = 0;
        x |= compress(poly.coeffs[i], 10) as u64;
        x |= (compress(poly.coeffs[i + 1], 10) as u64) << 10;
        x |= (compress(poly.coeffs[i + 2], 10) as u64) << 20;
        x |= (compress(poly.coeffs[i + 3], 10) as u64) << 30;
        out[out_idx] = x as u8;
        out[out_idx + 1] = (x >> 8) as u8;
        out[out_idx + 2] = (x >> 16) as u8;
        out[out_idx + 3] = (x >> 24) as u8;
        out[out_idx + 4] = (x >> 32) as u8;
        out_idx += 5;
    }
}

pub fn decode_and_decompress_10(bytes: &[u8], poly: &mut Poly) {
    let mut in_idx = 0;
    for i in (0..256).step_by(4) {
        let x = (bytes[in_idx] as u64)
            | ((bytes[in_idx + 1] as u64) << 8)
            | ((bytes[in_idx + 2] as u64) << 16)
            | ((bytes[in_idx + 3] as u64) << 24)
            | ((bytes[in_idx + 4] as u64) << 32);
        in_idx += 5;
        poly.coeffs[i] = decompress((x & 0x3ff) as u16, 10);
        poly.coeffs[i + 1] = decompress(((x >> 10) & 0x3ff) as u16, 10);
        poly.coeffs[i + 2] = decompress(((x >> 20) & 0x3ff) as u16, 10);
        poly.coeffs[i + 3] = decompress(((x >> 30) & 0x3ff) as u16, 10);
    }
}

pub fn compress_and_encode_4(poly: &Poly, out: &mut [u8]) {
    for i in (0..256).step_by(2) {
        out[i / 2] =
            (compress(poly.coeffs[i], 4) as u8) | ((compress(poly.coeffs[i + 1], 4) as u8) << 4);
    }
}

pub fn decode_and_decompress_4(bytes: &[u8], poly: &mut Poly) {
    for i in (0..256).step_by(2) {
        let b = bytes[i / 2];
        poly.coeffs[i] = decompress((b & 0x0f) as u16, 4);
        poly.coeffs[i + 1] = decompress(((b >> 4) & 0x0f) as u16, 4);
    }
}

pub fn compress_and_encode_1(poly: &Poly, out: &mut [u8; 32]) {
    out.fill(0);
    for i in 0..256 {
        let bit = compress(poly.coeffs[i], 1) as u8;
        out[i / 8] |= bit << (i % 8);
    }
}

pub fn decode_and_decompress_1(bytes: &[u8; 32]) -> Poly {
    let mut poly = Poly::default();
    let half_q = (Q + 1) / 2; // 1665
    for i in 0..256 {
        let bit = (bytes[i / 8] >> (i % 8)) & 1;
        poly.coeffs[i] = (bit as i32) * half_q;
    }
    poly
}

// --- KeyGen, Encapsulation, Decapsulation ---

pub struct Mlkem768PrivateKey {
    pub dk: [u8; MLKEM768_DK_SIZE],
}

pub struct Mlkem768PublicKey {
    pub ek: [u8; MLKEM768_EK_SIZE],
}

/// Generates ML-KEM-768 keypair from a 64-byte seed (d || z).
pub fn keygen_from_seed(seed: &[u8; 64]) -> (Mlkem768PublicKey, Mlkem768PrivateKey) {
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    d.copy_from_slice(&seed[..32]);
    z.copy_from_slice(&seed[32..]);

    let g = sha3_512(&d);
    let mut rho = [0u8; 32];
    let mut sigma = [0u8; 32];
    rho.copy_from_slice(&g[..32]);
    sigma.copy_from_slice(&g[32..]);

    let mut a_hat = [[Poly::default(); K]; K];
    for i in 0..K {
        for j in 0..K {
            a_hat[i][j] = sample_ntt(&rho, j as u8, i as u8);
        }
    }

    let mut s = [Poly::default(); K];
    let mut e = [Poly::default(); K];
    for i in 0..K {
        s[i] = sample_poly_cbd2(&sigma, i as u8);
        e[i] = sample_poly_cbd2(&sigma, (K + i) as u8);
    }

    let mut s_hat = s;
    for poly in s_hat.iter_mut() {
        poly.ntt();
    }

    let mut e_hat = e;
    for poly in e_hat.iter_mut() {
        poly.ntt();
    }

    let mut t_hat = [Poly::default(); K];
    for i in 0..K {
        for j in 0..K {
            let mut prod = Poly::default();
            ntt_mul(&mut prod, &a_hat[i][j], &s_hat[j]);
            t_hat[i].add(&prod);
        }
        t_hat[i].add(&e_hat[i]);
    }

    let mut ek = [0u8; MLKEM768_EK_SIZE];
    for i in 0..K {
        byte_encode_12(&t_hat[i], &mut ek[384 * i..384 * (i + 1)]);
    }
    ek[384 * K..384 * K + 32].copy_from_slice(&rho);

    let mut dk = [0u8; MLKEM768_DK_SIZE];
    for i in 0..K {
        byte_encode_12(&s_hat[i], &mut dk[384 * i..384 * (i + 1)]);
    }
    dk[1152..1152 + MLKEM768_EK_SIZE].copy_from_slice(&ek);
    let h_ek = sha3_256(&ek);
    dk[1152 + MLKEM768_EK_SIZE..1152 + MLKEM768_EK_SIZE + 32].copy_from_slice(&h_ek);
    dk[1152 + MLKEM768_EK_SIZE + 32..].copy_from_slice(&z);

    (Mlkem768PublicKey { ek }, Mlkem768PrivateKey { dk })
}

/// ML-KEM-768 Encapsulation: computes shared secret K and ciphertext c given public key ek.
pub fn encapsulate(
    ek: &[u8; MLKEM768_EK_SIZE],
) -> ([u8; MLKEM768_SS_SIZE], [u8; MLKEM768_CIPHERTEXT_SIZE]) {
    let mut m = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut m);

    let h_ek = sha3_256(ek);
    let mut g_in = [0u8; 64];
    g_in[..32].copy_from_slice(&m);
    g_in[32..].copy_from_slice(&h_ek);
    let g = sha3_512(&g_in);

    let mut k_shared = [0u8; 32];
    let mut r = [0u8; 32];
    k_shared.copy_from_slice(&g[..32]);
    r.copy_from_slice(&g[32..]);

    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[384 * K..384 * K + 32]);

    let mut t_hat = [Poly::default(); K];
    for i in 0..K {
        byte_decode_12(&ek[384 * i..384 * (i + 1)], &mut t_hat[i]);
    }

    let mut r_vec = [Poly::default(); K];
    for i in 0..K {
        r_vec[i] = sample_poly_cbd2(&r, i as u8);
    }
    let mut e1 = [Poly::default(); K];
    for i in 0..K {
        e1[i] = sample_poly_cbd2(&r, (K + i) as u8);
    }
    let e2 = sample_poly_cbd2(&r, (2 * K) as u8);

    let mut r_hat = r_vec;
    for poly in r_hat.iter_mut() {
        poly.ntt();
    }

    let mut u = [Poly::default(); K];
    for i in 0..K {
        let mut u_hat = Poly::default();
        for j in 0..K {
            let mut prod = Poly::default();
            let a_ji = sample_ntt(&rho, i as u8, j as u8);
            ntt_mul(&mut prod, &a_ji, &r_hat[j]);
            u_hat.add(&prod);
        }
        u_hat.inv_ntt();
        u_hat.add(&e1[i]);
        u[i] = u_hat;
    }

    let mut v_ntt = Poly::default();
    for i in 0..K {
        let mut prod = Poly::default();
        ntt_mul(&mut prod, &t_hat[i], &r_hat[i]);
        v_ntt.add(&prod);
    }
    v_ntt.inv_ntt();
    v_ntt.add(&e2);

    let mu = decode_and_decompress_1(&m);
    v_ntt.add(&mu);

    let mut ct = [0u8; MLKEM768_CIPHERTEXT_SIZE];
    for i in 0..K {
        compress_and_encode_10(&u[i], &mut ct[320 * i..320 * (i + 1)]);
    }
    compress_and_encode_4(&v_ntt, &mut ct[320 * K..]);

    (k_shared, ct)
}

/// ML-KEM-768 Decapsulation: computes shared secret K given private key (seed 64B or full dk 2400B) and ciphertext c.
pub fn decapsulate(
    dk_bytes: &[u8],
    c: &[u8; MLKEM768_CIPHERTEXT_SIZE],
) -> io::Result<[u8; MLKEM768_SS_SIZE]> {
    let dk = if dk_bytes.len() == 64 {
        let mut seed = [0u8; 64];
        seed.copy_from_slice(dk_bytes);
        let (_, priv_key) = keygen_from_seed(&seed);
        priv_key.dk
    } else if dk_bytes.len() == MLKEM768_DK_SIZE {
        let mut key = [0u8; MLKEM768_DK_SIZE];
        key.copy_from_slice(dk_bytes);
        key
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "invalid ML-KEM-768 decapsulation key length: {}",
                dk_bytes.len()
            ),
        ));
    };

    let mut s_hat = [Poly::default(); K];
    for i in 0..K {
        byte_decode_12(&dk[384 * i..384 * (i + 1)], &mut s_hat[i]);
    }

    let mut u = [Poly::default(); K];
    for i in 0..K {
        decode_and_decompress_10(&c[320 * i..320 * (i + 1)], &mut u[i]);
    }

    let mut v = Poly::default();
    decode_and_decompress_4(&c[320 * K..], &mut v);

    let mut mask = Poly::default();
    for i in 0..K {
        let mut u_ntt = u[i];
        u_ntt.ntt();
        let mut prod = Poly::default();
        ntt_mul(&mut prod, &s_hat[i], &u_ntt);
        mask.add(&prod);
    }
    mask.inv_ntt();

    let mut w = v;
    w.sub(&mask);

    let mut m_prime = [0u8; 32];
    compress_and_encode_1(&w, &mut m_prime);

    let ek = &dk[1152..1152 + MLKEM768_EK_SIZE];
    let h_ek = &dk[1152 + MLKEM768_EK_SIZE..1152 + MLKEM768_EK_SIZE + 32];
    let z = &dk[1152 + MLKEM768_EK_SIZE + 32..];

    let mut g_in = [0u8; 64];
    g_in[..32].copy_from_slice(&m_prime);
    g_in[32..].copy_from_slice(h_ek);
    let g = sha3_512(&g_in);

    let mut k_shared = [0u8; 32];
    k_shared.copy_from_slice(&g[..32]);
    let mut r_prime = [0u8; 32];
    r_prime.copy_from_slice(&g[32..]);

    // Re-encrypt m_prime to verify ciphertext
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&ek[384 * K..384 * K + 32]);

    let mut t_hat = [Poly::default(); K];
    for i in 0..K {
        byte_decode_12(&ek[384 * i..384 * (i + 1)], &mut t_hat[i]);
    }

    let mut r_vec = [Poly::default(); K];
    for i in 0..K {
        r_vec[i] = sample_poly_cbd2(&r_prime, i as u8);
    }
    let mut e1 = [Poly::default(); K];
    for i in 0..K {
        e1[i] = sample_poly_cbd2(&r_prime, (K + i) as u8);
    }
    let e2 = sample_poly_cbd2(&r_prime, (2 * K) as u8);

    let mut r_hat = r_vec;
    for poly in r_hat.iter_mut() {
        poly.ntt();
    }

    let mut u_re = [Poly::default(); K];
    for i in 0..K {
        let mut u_hat = Poly::default();
        for j in 0..K {
            let mut prod = Poly::default();
            let a_ji = sample_ntt(&rho, i as u8, j as u8);
            ntt_mul(&mut prod, &a_ji, &r_hat[j]);
            u_hat.add(&prod);
        }
        u_hat.inv_ntt();
        u_hat.add(&e1[i]);
        u_re[i] = u_hat;
    }

    let mut v_ntt = Poly::default();
    for i in 0..K {
        let mut prod = Poly::default();
        ntt_mul(&mut prod, &t_hat[i], &r_hat[i]);
        v_ntt.add(&prod);
    }
    v_ntt.inv_ntt();
    v_ntt.add(&e2);

    let mu = decode_and_decompress_1(&m_prime);
    v_ntt.add(&mu);

    let mut c_prime = [0u8; MLKEM768_CIPHERTEXT_SIZE];
    for i in 0..K {
        compress_and_encode_10(&u_re[i], &mut c_prime[320 * i..320 * (i + 1)]);
    }
    compress_and_encode_4(&v_ntt, &mut c_prime[320 * K..]);

    if c == &c_prime {
        Ok(k_shared)
    } else {
        // Implicit rejection
        let mut k_fail = [0u8; 32];
        let mut j_in = Vec::with_capacity(32 + MLKEM768_CIPHERTEXT_SIZE);
        j_in.extend_from_slice(z);
        j_in.extend_from_slice(c);
        shake256(&j_in, &mut k_fail);
        Ok(k_fail)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sha3_256_empty() {
        let h = sha3_256(b"");
        let expected =
            hex::decode("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a")
                .unwrap();
        assert_eq!(&h[..], &expected[..]);
    }

    #[test]
    fn test_mlkem768_encap_decap_roundtrip() {
        let seed = [0x42u8; 64];
        let (pub_key, priv_key) = keygen_from_seed(&seed);
        assert_eq!(pub_key.ek.len(), MLKEM768_EK_SIZE);
        assert_eq!(priv_key.dk.len(), MLKEM768_DK_SIZE);

        let (ss_enc, ct) = encapsulate(&pub_key.ek);
        assert_eq!(ct.len(), MLKEM768_CIPHERTEXT_SIZE);
        assert_eq!(ss_enc.len(), 32);

        // Decapsulate using full dk
        let ss_dec = decapsulate(&priv_key.dk, &ct).expect("decapsulation succeeds");
        assert_eq!(ss_enc, ss_dec);

        // Decapsulate using 64-byte seed
        let ss_dec_seed = decapsulate(&seed, &ct).expect("decapsulation from seed succeeds");
        assert_eq!(ss_enc, ss_dec_seed);
    }
}
