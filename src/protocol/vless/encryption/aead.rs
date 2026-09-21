use super::kdf::derive_key;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use chacha20poly1305::ChaCha20Poly1305;
use std::io;

pub const MAX_NONCE: [u8; 12] = [0xff; 12];

pub enum AeadBackend {
    AesGcm(Aes256Gcm),
    ChaCha(ChaCha20Poly1305),
}

pub struct VlessAead {
    pub backend: AeadBackend,
    pub nonce: [u8; 12],
    pub use_aes: bool,
}

pub fn increase_nonce(nonce: &mut [u8; 12]) {
    for i in 0..12 {
        nonce[11 - i] = nonce[11 - i].wrapping_add(1);
        if nonce[11 - i] != 0 {
            break;
        }
    }
}

impl VlessAead {
    pub fn new(ctx: &[u8], key: &[u8], use_aes: bool) -> Self {
        let derived_k = derive_key(ctx, key);

        let backend = if use_aes {
            AeadBackend::AesGcm(
                Aes256Gcm::new_from_slice(&derived_k)
                    .expect("32-byte key is valid for AES-256-GCM"),
            )
        } else {
            AeadBackend::ChaCha(
                ChaCha20Poly1305::new_from_slice(&derived_k)
                    .expect("32-byte key is valid for ChaCha20-Poly1305"),
            )
        };

        Self {
            backend,
            nonce: [0u8; 12],
            use_aes,
        }
    }

    pub fn seal(
        &mut self,
        explicit_nonce: Option<&[u8; 12]>,
        plaintext: &[u8],
        aad: &[u8],
    ) -> io::Result<Vec<u8>> {
        let nonce_bytes = match explicit_nonce {
            Some(n) => *n,
            None => {
                increase_nonce(&mut self.nonce);
                self.nonce
            }
        };

        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        match &self.backend {
            AeadBackend::AesGcm(c) => c.encrypt(nonce, payload).map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("AES-GCM seal error: {e:?}"))
            }),
            AeadBackend::ChaCha(c) => c.encrypt(nonce, payload).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("ChaCha20-Poly1305 seal error: {e:?}"),
                )
            }),
        }
    }

    pub fn open(
        &mut self,
        explicit_nonce: Option<&[u8; 12]>,
        ciphertext: &[u8],
        aad: &[u8],
    ) -> io::Result<Vec<u8>> {
        let nonce_bytes = match explicit_nonce {
            Some(n) => *n,
            None => {
                increase_nonce(&mut self.nonce);
                self.nonce
            }
        };

        let nonce = aes_gcm::Nonce::from_slice(&nonce_bytes);
        let payload = Payload {
            msg: ciphertext,
            aad,
        };

        match &self.backend {
            AeadBackend::AesGcm(c) => c.decrypt(nonce, payload).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("AES-GCM open error: {e:?}"),
                )
            }),
            AeadBackend::ChaCha(c) => c.decrypt(nonce, payload).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("ChaCha20-Poly1305 open error: {e:?}"),
                )
            }),
        }
    }

    pub fn is_max_nonce(&self) -> bool {
        self.nonce == MAX_NONCE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aead_roundtrip_aes() {
        let mut enc = VlessAead::new(b"test-ctx", b"secret-key-32-bytes-long-------", true);
        let mut dec = VlessAead::new(b"test-ctx", b"secret-key-32-bytes-long-------", true);

        let msg = b"hello vless encryption over aes-gcm";
        let aad = b"tls-record-header-5b";

        let ct = enc.seal(None, msg, aad).unwrap();
        assert_eq!(ct.len(), msg.len() + 16);

        let pt = dec.open(None, &ct, aad).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn test_aead_roundtrip_chacha() {
        let mut enc = VlessAead::new(b"test-ctx", b"secret-key-32-bytes-long-------", false);
        let mut dec = VlessAead::new(b"test-ctx", b"secret-key-32-bytes-long-------", false);

        let msg = b"hello vless encryption over chacha20poly1305";
        let aad = b"tls-record-header-5b";

        let ct = enc.seal(None, msg, aad).unwrap();
        let pt = dec.open(None, &ct, aad).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn test_nonce_increment() {
        let mut nonce = [0u8; 12];
        increase_nonce(&mut nonce);
        assert_eq!(nonce[11], 1);
        nonce[11] = 0xff;
        increase_nonce(&mut nonce);
        assert_eq!(nonce[11], 0);
        assert_eq!(nonce[10], 1);
    }
}
