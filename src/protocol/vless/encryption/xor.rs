use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockEncrypt, KeyInit};
use aes::Aes256;
use std::io;

pub fn decode_header(h: &[u8]) -> io::Result<usize> {
    if h.len() < 5 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "header too short",
        ));
    }
    let mut l = ((h[3] as usize) << 8) | (h[4] as usize);
    if h[0] != 23 || h[1] != 3 || h[2] != 3 {
        l = 0;
    }
    if !(17..=16640).contains(&l) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid header: {:?}", &h[..5]),
        ));
    }
    Ok(l)
}

pub fn encode_header(h: &mut [u8], l: usize) {
    h[0] = 23;
    h[1] = 3;
    h[2] = 3;
    h[3] = (l >> 8) as u8;
    h[4] = l as u8;
}

/// AES-256 CTR stream cipher matching Go `cipher.NewCTR(aes.NewCipher(k), iv)`
/// with key derived via `blake3.DeriveKey(k, "VLESS", key)`.
pub struct Aes256Ctr {
    cipher: Aes256,
    ctr: [u8; 16],
    keystream: [u8; 16],
    keystream_pos: usize,
}

impl Aes256Ctr {
    pub fn new(key: &[u8], iv: &[u8]) -> Self {
        let subkey = super::kdf::derive_key(b"VLESS", key);
        let cipher = Aes256::new_from_slice(&subkey).expect("32-byte key is valid for AES-256");
        let mut ctr = [0u8; 16];
        let copy_len = iv.len().min(16);
        ctr[..copy_len].copy_from_slice(&iv[..copy_len]);

        Self {
            cipher,
            ctr,
            keystream: [0u8; 16],
            keystream_pos: 16,
        }
    }

    pub fn xor_keystream(&mut self, buf: &mut [u8]) {
        for byte in buf.iter_mut() {
            if self.keystream_pos >= 16 {
                let mut block = GenericArray::clone_from_slice(&self.ctr);
                self.cipher.encrypt_block(&mut block);
                self.keystream.copy_from_slice(block.as_slice());
                self.keystream_pos = 0;

                // Increment 128-bit big-endian counter
                for i in (0..16).rev() {
                    self.ctr[i] = self.ctr[i].wrapping_add(1);
                    if self.ctr[i] != 0 {
                        break;
                    }
                }
            }
            *byte ^= self.keystream[self.keystream_pos];
            self.keystream_pos += 1;
        }
    }
}

/// Filter that XORs 5-byte TLS headers with CTR while skipping the inner AEAD ciphertext.
/// Matches upstream Xray-core `XorConn`.
pub struct XorFilter {
    pub ctr: Aes256Ctr,
    pub peer_ctr: Aes256Ctr,
    pub out_skip: usize,
    pub out_header: Vec<u8>,
    pub in_skip: usize,
    pub in_header: Vec<u8>,
}

impl XorFilter {
    pub fn new(ctr: Aes256Ctr, peer_ctr: Aes256Ctr, out_skip: usize, in_skip: usize) -> Self {
        Self {
            ctr,
            peer_ctr,
            out_skip,
            out_header: Vec::with_capacity(5),
            in_skip,
            in_header: Vec::with_capacity(5),
        }
    }

    /// Processes outgoing buffer in place before writing to underlying connection.
    pub fn filter_out(&mut self, buf: &mut [u8]) {
        let mut offset = 0;
        let total = buf.len();

        while offset < total {
            let p_len = total - offset;
            if p_len <= self.out_skip {
                self.out_skip -= p_len;
                break;
            }

            offset += self.out_skip;
            self.out_skip = 0;

            let need = 5 - self.out_header.len();
            let cur_len = total - offset;
            if cur_len < need {
                self.out_header.extend_from_slice(&buf[offset..]);
                self.ctr.xor_keystream(&mut buf[offset..]);
                break;
            }

            let mut header = self.out_header.clone();
            header.extend_from_slice(&buf[offset..offset + need]);
            self.ctr.xor_keystream(&mut buf[offset..offset + need]);

            // Decode length
            if let Ok(l) = decode_header(&header) {
                self.out_skip = l;
            } else {
                self.out_skip = 0;
            }

            self.out_header.clear();
            offset += need;
        }
    }

    /// Processes incoming buffer in place after reading from underlying connection.
    pub fn filter_in(&mut self, buf: &mut [u8]) {
        let mut offset = 0;
        let total = buf.len();

        while offset < total {
            let p_len = total - offset;
            if p_len <= self.in_skip {
                self.in_skip -= p_len;
                break;
            }

            offset += self.in_skip;
            self.in_skip = 0;

            let need = 5 - self.in_header.len();
            let cur_len = total - offset;
            if cur_len < need {
                self.peer_ctr.xor_keystream(&mut buf[offset..]);
                self.in_header.extend_from_slice(&buf[offset..]);
                break;
            }

            self.peer_ctr.xor_keystream(&mut buf[offset..offset + need]);
            let mut header = self.in_header.clone();
            header.extend_from_slice(&buf[offset..offset + need]);

            // Decode length
            if let Ok(l) = decode_header(&header) {
                self.in_skip = l;
            } else {
                self.in_skip = 0;
            }

            self.in_header.clear();
            offset += need;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_header_encode_decode() {
        let mut h = [0u8; 5];
        encode_header(&mut h, 8213);
        assert_eq!(h[0], 23);
        assert_eq!(h[1], 3);
        assert_eq!(h[2], 3);
        assert_eq!(decode_header(&h).unwrap(), 8213);
    }

    #[test]
    fn test_aes_ctr_keystream_deterministic() {
        let key = b"my-secret-key-32-bytes-long----!";
        let iv = [0x42u8; 16];

        let mut ctr1 = Aes256Ctr::new(key, &iv);
        let mut ctr2 = Aes256Ctr::new(key, &iv);

        let mut data1 = b"Testing CTR encryption deterministic properties".to_vec();
        let mut data2 = data1.clone();

        ctr1.xor_keystream(&mut data1);
        assert_ne!(data1, data2);

        ctr2.xor_keystream(&mut data2);
        assert_eq!(data1, data2);
    }
}
