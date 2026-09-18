use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, AesGcm};
use bytes::{Bytes, BytesMut};
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest, Md5};
use std::io::{self, Error, ErrorKind};
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};
use tokio_util::io::{SinkWriter, StreamReader};

pub const MAX_PAYLOAD_LEN: usize = 0x3FFF; // 16383 bytes

type Aes192Gcm = AesGcm<aes::Aes192, aes_gcm::aead::consts::U12>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherKind {
    ChaCha20Poly1305,
    Aes256Gcm,
    Aes128Gcm,
    Aes192Gcm,
}

impl CipherKind {
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(name: &str) -> Option<Self> {
        match name.to_ascii_lowercase().as_str() {
            "chacha20-ietf-poly1305" | "chacha20-poly1305" => Some(Self::ChaCha20Poly1305),
            "aes-256-gcm" => Some(Self::Aes256Gcm),
            "aes-128-gcm" | "gcm" | "aes-gcm" => Some(Self::Aes128Gcm),
            "aes-192-gcm" => Some(Self::Aes192Gcm),
            _ => None,
        }
    }

    pub fn key_len(&self) -> usize {
        match self {
            Self::ChaCha20Poly1305 => 32,
            Self::Aes256Gcm => 32,
            Self::Aes128Gcm => 16,
            Self::Aes192Gcm => 24,
        }
    }

    pub fn salt_len(&self) -> usize {
        self.key_len()
    }

    pub fn tag_len(&self) -> usize {
        16
    }
}

pub fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while key.len() < key_len {
        let mut hasher = Md5::new();
        hasher.update(&prev);
        hasher.update(password);
        let digest = hasher.finalize();
        prev = digest.to_vec();
        key.extend_from_slice(&digest);
    }
    key.truncate(key_len);
    key
}

pub fn hkdf_sha1(master_key: &[u8], salt: &[u8], subkey_out: &mut [u8]) {
    let salt = ring::hkdf::Salt::new(ring::hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt);
    let prk = salt.extract(master_key);
    struct SubkeyLen(usize);
    impl ring::hkdf::KeyType for SubkeyLen {
        fn len(&self) -> usize {
            self.0
        }
    }
    let okm = prk
        .expand(&[b"ss-subkey"], SubkeyLen(subkey_out.len()))
        .expect("hkdf expand");
    okm.fill(subkey_out).expect("hkdf fill");
}

pub fn increment_nonce(nonce: &mut [u8; 12]) {
    for byte in nonce.iter_mut() {
        *byte = byte.wrapping_add(1);
        if *byte != 0 {
            break;
        }
    }
}

#[allow(clippy::large_enum_variant)]
pub enum AeadCipher {
    ChaCha20(ChaCha20Poly1305),
    Aes256(Aes256Gcm),
    Aes128(Aes128Gcm),
    Aes192(Aes192Gcm),
}

impl AeadCipher {
    pub fn new(kind: CipherKind, subkey: &[u8]) -> Self {
        match kind {
            CipherKind::ChaCha20Poly1305 => {
                Self::ChaCha20(ChaCha20Poly1305::new_from_slice(subkey).expect("valid chacha key"))
            }
            CipherKind::Aes256Gcm => {
                Self::Aes256(Aes256Gcm::new_from_slice(subkey).expect("valid aes256 key"))
            }
            CipherKind::Aes128Gcm => {
                Self::Aes128(Aes128Gcm::new_from_slice(subkey).expect("valid aes128 key"))
            }
            CipherKind::Aes192Gcm => {
                Self::Aes192(Aes192Gcm::new_from_slice(subkey).expect("valid aes192 key"))
            }
        }
    }

    pub fn decrypt_in_place(&self, nonce: &[u8; 12], buffer: &mut [u8]) -> io::Result<()> {
        if nonce == &[255; 12] {
            return Err(Error::new(ErrorKind::InvalidData, "AEAD nonce exhausted"));
        }
        let tag_len = 16;
        if buffer.len() < tag_len {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "buffer too small for tag",
            ));
        }
        let (data, tag_bytes) = buffer.split_at_mut(buffer.len() - tag_len);

        match self {
            Self::ChaCha20(c) => {
                let nonce = chacha20poly1305::Nonce::from_slice(nonce);
                let tag = chacha20poly1305::Tag::from_slice(tag_bytes);
                c.decrypt_in_place_detached(nonce, b"", data, tag)
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "AEAD decrypt failed"))
            }
            Self::Aes256(c) => {
                let nonce = aes_gcm::Nonce::from_slice(nonce);
                let tag = aes_gcm::Tag::from_slice(tag_bytes);
                c.decrypt_in_place_detached(nonce, b"", data, tag)
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "AEAD decrypt failed"))
            }
            Self::Aes128(c) => {
                let nonce = aes_gcm::Nonce::from_slice(nonce);
                let tag = aes_gcm::Tag::from_slice(tag_bytes);
                c.decrypt_in_place_detached(nonce, b"", data, tag)
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "AEAD decrypt failed"))
            }
            Self::Aes192(c) => {
                let nonce = aes_gcm::Nonce::from_slice(nonce);
                let tag = aes_gcm::Tag::from_slice(tag_bytes);
                c.decrypt_in_place_detached(nonce, b"", data, tag)
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "AEAD decrypt failed"))
            }
        }
    }

    pub fn encrypt_in_place(&self, nonce: &[u8; 12], buffer: &mut Vec<u8>) -> io::Result<()> {
        match self {
            Self::ChaCha20(c) => {
                let nonce = chacha20poly1305::Nonce::from_slice(nonce);
                let tag = c
                    .encrypt_in_place_detached(nonce, b"", buffer)
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "AEAD encrypt failed"))?;
                buffer.extend_from_slice(tag.as_slice());
                Ok(())
            }
            Self::Aes256(c) => {
                let nonce = aes_gcm::Nonce::from_slice(nonce);
                let tag = c
                    .encrypt_in_place_detached(nonce, b"", buffer)
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "AEAD encrypt failed"))?;
                buffer.extend_from_slice(tag.as_slice());
                Ok(())
            }
            Self::Aes128(c) => {
                let nonce = aes_gcm::Nonce::from_slice(nonce);
                let tag = c
                    .encrypt_in_place_detached(nonce, b"", buffer)
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "AEAD encrypt failed"))?;
                buffer.extend_from_slice(tag.as_slice());
                Ok(())
            }
            Self::Aes192(c) => {
                let nonce = aes_gcm::Nonce::from_slice(nonce);
                let tag = c
                    .encrypt_in_place_detached(nonce, b"", buffer)
                    .map_err(|_| Error::new(ErrorKind::InvalidData, "AEAD encrypt failed"))?;
                buffer.extend_from_slice(tag.as_slice());
                Ok(())
            }
        }
    }
}

pub struct ShadowsocksDecrypter {
    pub cipher_read: AeadCipher,
    pub read_nonce: [u8; 12],
    payload_len: Option<usize>,
}

impl Decoder for ShadowsocksDecrypter {
    type Item = Bytes;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Bytes>> {
        let len = match self.payload_len {
            Some(len) => len,
            None => {
                if src.len() < 18 {
                    return Ok(None);
                }
                let mut header = src.split_to(18)[..].try_into().unwrap();
                let len = self.decrypt_length(&mut header)?;
                self.payload_len = Some(len);
                len
            }
        };
        if src.len() < len + 16 {
            return Ok(None);
        }
        let mut payload = src.split_to(len + 16);
        self.decrypt_payload(&mut payload)?;
        self.payload_len = None;
        payload.truncate(len);
        Ok(Some(payload.freeze()))
    }

    fn decode_eof(&mut self, src: &mut BytesMut) -> io::Result<Option<Bytes>> {
        let decoded = self.decode(src)?;
        if decoded.is_none() && (!src.is_empty() || self.payload_len.is_some()) {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Truncated Shadowsocks frame",
            ));
        }
        Ok(decoded)
    }
}

impl ShadowsocksDecrypter {
    pub fn decrypt_length(&mut self, encrypted_len_block: &mut [u8; 18]) -> io::Result<usize> {
        self.cipher_read
            .decrypt_in_place(&self.read_nonce, encrypted_len_block)?;
        let len = u16::from_be_bytes([encrypted_len_block[0], encrypted_len_block[1]]) as usize;
        if len > MAX_PAYLOAD_LEN {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Payload length exceeds maximum",
            ));
        }
        increment_nonce(&mut self.read_nonce);
        Ok(len)
    }

    pub fn decrypt_payload(&mut self, payload_block: &mut [u8]) -> io::Result<()> {
        self.cipher_read
            .decrypt_in_place(&self.read_nonce, payload_block)?;
        increment_nonce(&mut self.read_nonce);
        Ok(())
    }
}

pub struct ShadowsocksEncrypter {
    pub cipher_write: AeadCipher,
    pub write_nonce: [u8; 12],
    pub server_salt: Vec<u8>,
    pub salt_sent: bool,
}

impl ShadowsocksEncrypter {
    pub fn encrypt_chunk(&mut self, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Payload length exceeds maximum",
            ));
        }
        // Reserve both AEAD operations before publishing salt or ciphertext.
        if self.write_nonce[1..] == [255; 11] && self.write_nonce[0] >= 254 {
            return Err(Error::new(ErrorKind::InvalidData, "AEAD nonce exhausted"));
        }
        if !self.salt_sent {
            out.extend_from_slice(&self.server_salt);
            self.salt_sent = true;
        }

        let len_bytes = (payload.len() as u16).to_be_bytes();
        let mut len_buf = len_bytes.to_vec();
        self.cipher_write
            .encrypt_in_place(&self.write_nonce, &mut len_buf)?;
        increment_nonce(&mut self.write_nonce);
        out.extend_from_slice(&len_buf);

        let mut payload_buf = payload.to_vec();
        self.cipher_write
            .encrypt_in_place(&self.write_nonce, &mut payload_buf)?;
        increment_nonce(&mut self.write_nonce);
        out.extend_from_slice(&payload_buf);

        Ok(())
    }
}

pub struct ShadowsocksServerSession {
    pub decrypter: ShadowsocksDecrypter,
    pub encrypter: ShadowsocksEncrypter,
}

impl Encoder<&[u8]> for ShadowsocksEncrypter {
    type Error = io::Error;

    fn encode(&mut self, item: &[u8], dst: &mut BytesMut) -> io::Result<()> {
        let mut chunk = Vec::with_capacity(MAX_PAYLOAD_LEN + 66);
        for payload in item.chunks(MAX_PAYLOAD_LEN) {
            chunk.clear();
            self.encrypt_chunk(payload, &mut chunk)?;
            dst.extend_from_slice(&chunk);
        }
        Ok(())
    }
}

impl ShadowsocksServerSession {
    pub fn new(kind: CipherKind, master_key: &[u8], client_salt: &[u8]) -> Self {
        let key_len = kind.key_len();
        let mut client_subkey = vec![0u8; key_len];
        hkdf_sha1(master_key, client_salt, &mut client_subkey);

        // Generate server salt
        let mut server_salt = vec![0u8; kind.salt_len()];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut server_salt);

        let mut server_subkey = vec![0u8; key_len];
        hkdf_sha1(master_key, &server_salt, &mut server_subkey);

        let cipher_read = AeadCipher::new(kind, &client_subkey);
        let cipher_write = AeadCipher::new(kind, &server_subkey);

        Self {
            decrypter: ShadowsocksDecrypter {
                cipher_read,
                read_nonce: [0u8; 12],
                payload_len: None,
            },
            encrypter: ShadowsocksEncrypter {
                cipher_write,
                write_nonce: [0u8; 12],
                server_salt,
                salt_sent: false,
            },
        }
    }

    pub fn decrypt_length(&mut self, encrypted_len_block: &mut [u8; 18]) -> io::Result<usize> {
        self.decrypter.decrypt_length(encrypted_len_block)
    }

    pub fn decrypt_payload(&mut self, payload_block: &mut [u8]) -> io::Result<()> {
        self.decrypter.decrypt_payload(payload_block)
    }

    pub fn encrypt_chunk(&mut self, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        self.encrypter.encrypt_chunk(payload, out)
    }

    pub fn into_split(self) -> (ShadowsocksDecrypter, ShadowsocksEncrypter) {
        (self.decrypter, self.encrypter)
    }

    pub fn into_stream<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static>(
        mut self,
        stream: S,
        first_payload_len: Option<usize>,
    ) -> crate::conn::BoxedStream {
        self.decrypter.payload_len = first_payload_len;
        let (read, write) = tokio::io::split(stream);
        Box::new(tokio::io::join(
            StreamReader::new(FramedRead::new(read, self.decrypter)),
            SinkWriter::new(FramedWrite::new(write, self.encrypter)),
        ))
    }
}

pub struct ShadowsocksClientSession {
    pub cipher_write: AeadCipher,
    pub write_nonce: [u8; 12],
}

impl ShadowsocksClientSession {
    pub fn new(kind: CipherKind, master_key: &[u8], client_salt: &[u8]) -> Self {
        let key_len = kind.key_len();
        let mut client_subkey = vec![0u8; key_len];
        hkdf_sha1(master_key, client_salt, &mut client_subkey);

        let cipher_write = AeadCipher::new(kind, &client_subkey);
        Self {
            cipher_write,
            write_nonce: [0u8; 12],
        }
    }

    pub fn encrypt_chunk(&mut self, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(Error::new(
                ErrorKind::InvalidInput,
                "Payload length exceeds maximum",
            ));
        }
        if self.write_nonce[1..] == [255; 11] && self.write_nonce[0] >= 254 {
            return Err(Error::new(ErrorKind::InvalidData, "AEAD nonce exhausted"));
        }
        let len_bytes = (payload.len() as u16).to_be_bytes();
        let mut len_buf = len_bytes.to_vec();
        self.cipher_write
            .encrypt_in_place(&self.write_nonce, &mut len_buf)?;
        increment_nonce(&mut self.write_nonce);
        out.extend_from_slice(&len_buf);

        let mut payload_buf = payload.to_vec();
        self.cipher_write
            .encrypt_in_place(&self.write_nonce, &mut payload_buf)?;
        increment_nonce(&mut self.write_nonce);
        out.extend_from_slice(&payload_buf);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evp_bytes_to_key() {
        let key32 = evp_bytes_to_key(b"test-password", 32);
        assert_eq!(key32.len(), 32);
        let key16 = evp_bytes_to_key(b"test-password", 16);
        assert_eq!(key16.len(), 16);
    }

    #[test]
    fn test_shadowsocks_aead_roundtrip() {
        for kind in [
            CipherKind::ChaCha20Poly1305,
            CipherKind::Aes256Gcm,
            CipherKind::Aes128Gcm,
        ] {
            let master_key = evp_bytes_to_key(b"secret123", kind.key_len());
            let client_salt = vec![7u8; kind.salt_len()];

            // 1. Client creates session & encodes a chunk
            let mut client = ShadowsocksClientSession::new(kind, &master_key, &client_salt);
            let original_data = b"Hello, Elise native Rust kernel!";
            let mut client_wire = Vec::new();
            client
                .encrypt_chunk(original_data, &mut client_wire)
                .unwrap();

            // 2. Server decodes
            let mut server = ShadowsocksServerSession::new(kind, &master_key, &client_salt);
            let mut enc_len = [0u8; 18];
            enc_len.copy_from_slice(&client_wire[..18]);
            let dec_len = server.decrypt_length(&mut enc_len).unwrap();
            assert_eq!(dec_len, original_data.len());

            let mut enc_payload = client_wire[18..].to_vec();
            server.decrypt_payload(&mut enc_payload).unwrap();
            assert_eq!(&enc_payload[..dec_len], original_data);
        }
    }
}
