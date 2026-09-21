use crate::conn::BoxedStream;
use crate::panel::types::User;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use base64::Engine;
use bytes::{BufMut, BytesMut};
use rand::RngCore;
use sha2::Digest;
use shadowsocks::context::Context;
use shadowsocks::crypto::{v2::tcp::TcpCipher, v2::udp::UdpCipher, CipherKind};
use shadowsocks::relay::socks5::Address;
use std::collections::{HashMap, HashSet};
use std::io::{self, Cursor};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};
use tracing::{info, warn};
use uuid::Uuid;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    None,
    Legacy(crate::protocol::ss_crypto::CipherKind),
    Aead2022(CipherKind),
}

impl std::str::FromStr for Method {
    type Err = io::Error;
    fn from_str(name: &str) -> io::Result<Self> {
        let name_lower = name.to_ascii_lowercase();
        if matches!(name_lower.as_str(), "none" | "plain") {
            return Ok(Self::None);
        }
        if let Some(method) = crate::protocol::ss_crypto::CipherKind::from_str(name) {
            return Ok(Self::Legacy(method));
        }
        match name {
            "2022-blake3-aes-128-gcm"
            | "2022-blake3-aes-256-gcm"
            | "2022-blake3-chacha20-poly1305" => Ok(Self::Aead2022(
                name.parse().map_err(|_| invalid("Unknown SS2022 method"))?,
            )),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unsupported Shadowsocks method",
            )),
        }
    }
}

impl Method {
    pub fn is_aead_2022(self) -> bool {
        matches!(self, Self::Aead2022(_))
    }
    pub fn key_len(self) -> usize {
        match self {
            Self::None => 0,
            Self::Legacy(m) => m.key_len(),
            Self::Aead2022(m) => m.key_len(),
        }
    }
    pub fn replay_method(self) -> CipherKind {
        match self {
            Self::None | Self::Legacy(_) => CipherKind::AES_128_GCM,
            Self::Aead2022(m) => m,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ss2022Key {
    raw: Vec<u8>,
    identity_hash: [u8; 16],
}

impl Ss2022Key {
    pub fn parse(b64_key: &str, method: Method) -> io::Result<Self> {
        let raw = decode_key(b64_key, method)?;
        let hash = blake3::hash(&raw);
        let mut identity_hash = [0u8; 16];
        identity_hash.copy_from_slice(&hash.as_bytes()[..16]);
        Ok(Self { raw, identity_hash })
    }

    pub fn from_raw(raw: Vec<u8>, method: Method) -> io::Result<Self> {
        if raw.len() != method.key_len() {
            return Err(invalid("Raw key length mismatch for cipher"));
        }
        let hash = blake3::hash(&raw);
        let mut identity_hash = [0u8; 16];
        identity_hash.copy_from_slice(&hash.as_bytes()[..16]);
        Ok(Self { raw, identity_hash })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }

    pub fn identity_hash(&self) -> &[u8; 16] {
        &self.identity_hash
    }
}

pub struct Credential {
    pub user: User,
    pub key: Vec<u8>,
    pub identity_hash: [u8; 16],
    pub context: Arc<Context>,
}

impl Credential {
    pub fn all_for_user(user: User, method: Method, context: Arc<Context>) -> Vec<Self> {
        match Self::new(user, method, context) {
            Ok(cred) => vec![cred],
            Err(_) => Vec::new(),
        }
    }

    pub fn new(user: User, method: Method, context: Arc<Context>) -> io::Result<Self> {
        if method == Method::None {
            return Ok(Self {
                user,
                key: Vec::new(),
                identity_hash: [0u8; 16],
                context,
            });
        }
        let raw_pwd = user
            .password
            .as_deref()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or(user.uuid.as_str());

        let key = if method.is_aead_2022() {
            decode_key(raw_pwd, method)?
        } else {
            crate::protocol::ss_crypto::evp_bytes_to_key(raw_pwd.as_bytes(), method.key_len())
        };

        let hash = blake3::hash(&key);
        let mut identity_hash = [0u8; 16];
        identity_hash.copy_from_slice(&hash.as_bytes()[..16]);

        Ok(Self {
            user,
            key,
            identity_hash,
            context,
        })
    }
}

#[derive(Clone, Default)]
pub struct UserIndex {
    pub credentials: Vec<Arc<Credential>>,
    pub identity_map: HashMap<[u8; 16], Arc<Credential>>,
    pub valid_keys: HashSet<(u32, [u8; 32])>,
}

impl UserIndex {
    pub fn new(credentials: Vec<Arc<Credential>>) -> Self {
        let mut identity_map = HashMap::with_capacity(credentials.len());
        let mut valid_keys = HashSet::with_capacity(credentials.len());
        for cred in &credentials {
            let hash = blake3::hash(&cred.key);
            let mut id = [0u8; 16];
            id.copy_from_slice(&hash.as_bytes()[..16]);
            identity_map.insert(id, cred.clone());
            valid_keys.insert((cred.user.id, *hash.as_bytes()));
        }
        Self {
            credentials,
            identity_map,
            valid_keys,
        }
    }

    #[allow(dead_code)]
    pub fn from_slice(slice: &[Arc<Credential>]) -> Self {
        Self::new(slice.to_vec())
    }
}

impl From<Vec<Arc<Credential>>> for UserIndex {
    fn from(credentials: Vec<Arc<Credential>>) -> Self {
        Self::new(credentials)
    }
}

impl From<&[Arc<Credential>]> for UserIndex {
    fn from(slice: &[Arc<Credential>]) -> Self {
        Self::new(slice.to_vec())
    }
}

pub fn decode_key(value: &str, method: Method) -> io::Result<Vec<u8>> {
    let key_len = method.key_len();
    if key_len == 0 {
        return Ok(Vec::new());
    }
    let mut value = value.trim();
    if value.is_empty() {
        return Err(invalid("SS2022 key cannot be empty"));
    }

    if let Some(pos) = value.rfind(':') {
        value = value[pos + 1..].trim();
        if value.is_empty() {
            return Err(invalid("SS2022 user key cannot be empty"));
        }
    }

    if Uuid::parse_str(value).is_ok() {
        if value.as_bytes().len() >= key_len {
            return Ok(value.as_bytes()[..key_len].to_vec());
        } else {
            return Err(invalid("UUID shorter than SS2022 key length"));
        }
    }

    const STANDARD_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
        &base64::alphabet::STANDARD,
        base64::engine::GeneralPurposeConfig::new()
            .with_encode_padding(true)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );
    let std_res = STANDARD_ENGINE.decode(value);
    if let Ok(ref key) = std_res {
        if key.len() == key_len {
            return Ok(key.clone());
        }
    }

    const URL_SAFE_ENGINE: base64::engine::GeneralPurpose = base64::engine::GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        base64::engine::GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(base64::engine::DecodePaddingMode::Indifferent),
    );
    let url_res = URL_SAFE_ENGINE.decode(value);
    if let Ok(ref key) = url_res {
        if key.len() == key_len {
            return Ok(key.clone());
        }
    }

    if std_res.is_ok() || url_res.is_ok() {
        return Err(invalid(
            "SS2022 Base64 key length does not match cipher requirement",
        ));
    }

    if value.as_bytes().len() >= key_len {
        return Ok(value.as_bytes()[..key_len].to_vec());
    }

    Err(invalid(
        "SS2022 key must be Base64-encoded PSK with matching length, valid UUID, or raw string of at least key_len characters",
    ))
}

pub const SS2022_SESSION_SUBKEY_CONTEXT: &str = "shadowsocks 2022 session subkey";
pub const SS2022_IDENTITY_SUBKEY_CONTEXT: &str = "shadowsocks 2022 identity subkey";
pub const SERVER_STREAM_TIMESTAMP_MAX_DIFF: u64 = 30;
pub const SERVER_PACKET_TIMESTAMP_MAX_DIFF: u64 = 30;
pub const MAX_TIMESTAMP_SKEW_SECS: u64 = 30;
pub const SS2022_MAX_CHUNK_LEN: usize = 0xFFFF;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| invalid("System clock is before UNIX epoch"))
}

pub fn derive_session_subkey(psk: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    let mut hasher = blake3::Hasher::new_derive_key(SS2022_SESSION_SUBKEY_CONTEXT);
    hasher.update(psk);
    hasher.update(salt);
    let mut out = vec![0u8; key_len];
    hasher.finalize_xof().fill(&mut out);
    out
}

pub fn derive_identity_subkey(server_key: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key_material = Vec::with_capacity(server_key.len() + salt.len());
    key_material.extend_from_slice(server_key);
    key_material.extend_from_slice(salt);
    blake3::derive_key(SS2022_IDENTITY_SUBKEY_CONTEXT, &key_material)
}

pub fn aes_block_encrypt(_method: CipherKind, key: &[u8], block: &mut [u8; 16]) {
    match key.len() {
        16 => {
            let cipher = aes::Aes128::new_from_slice(key).expect("16-byte AES-128 key");
            cipher.encrypt_block(block.into());
        }
        32 => {
            let cipher = aes::Aes256::new_from_slice(key).expect("32-byte AES-256 key");
            cipher.encrypt_block(block.into());
        }
        len => panic!("AES block encrypt requires 16 or 32 byte key, got {len}"),
    }
}

pub fn aes_block_decrypt(_method: CipherKind, key: &[u8], block: &mut [u8; 16]) {
    match key.len() {
        16 => {
            let cipher = aes::Aes128::new_from_slice(key).expect("16-byte AES-128 key");
            cipher.decrypt_block(block.into());
        }
        32 => {
            let cipher = aes::Aes256::new_from_slice(key).expect("32-byte AES-256 key");
            cipher.decrypt_block(block.into());
        }
        len => panic!("AES block decrypt requires 16 or 32 byte key, got {len}"),
    }
}

pub fn aes_block(method: CipherKind, key: &[u8], block: &mut [u8], encrypt: bool) {
    let b: &mut [u8; 16] = block.try_into().expect("16-byte block");
    if encrypt {
        aes_block_encrypt(method, key, b);
    } else {
        aes_block_decrypt(method, key, b);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ss2022Nonce {
    bytes: [u8; 12],
}

impl Default for Ss2022Nonce {
    fn default() -> Self {
        Self::new()
    }
}

impl Ss2022Nonce {
    pub fn new() -> Self {
        Self { bytes: [0u8; 12] }
    }

    pub fn as_slice(&self) -> &[u8; 12] {
        &self.bytes
    }

    pub fn increment(&mut self) {
        let mut c = self.bytes[0] as u16 + 1;
        self.bytes[0] = c as u8;
        c >>= 8;
        let mut n = 1;
        while n < 12 {
            c += self.bytes[n] as u16;
            self.bytes[n] = c as u8;
            c >>= 8;
            n += 1;
        }
    }
}

enum ReaderState {
    YieldingData {
        buf: Vec<u8>,
        pos: usize,
    },
    ReadingLength {
        buf: [u8; 18],
        pos: usize,
    },
    ReadingData {
        length: usize,
        buf: Vec<u8>,
        pos: usize,
    },
}

pub struct Ss2022TcpReader {
    cipher: TcpCipher,
    state: ReaderState,
}

impl Ss2022TcpReader {
    pub fn new(cipher: TcpCipher, initial_payload: Vec<u8>) -> Self {
        let state = if initial_payload.is_empty() {
            ReaderState::ReadingLength {
                buf: [0u8; 18],
                pos: 0,
            }
        } else {
            ReaderState::YieldingData {
                buf: initial_payload,
                pos: 0,
            }
        };
        Self { cipher, state }
    }

    pub fn poll_read_decrypted<S>(
        &mut self,
        cx: &mut TaskContext<'_>,
        stream: &mut S,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>>
    where
        S: AsyncRead + Unpin + ?Sized,
    {
        loop {
            match &mut self.state {
                ReaderState::YieldingData { buf: data, pos } => {
                    let remaining = data.len() - *pos;
                    let to_read = remaining.min(buf.remaining());
                    buf.put_slice(&data[*pos..*pos + to_read]);
                    *pos += to_read;
                    if *pos >= data.len() {
                        self.state = ReaderState::ReadingLength {
                            buf: [0u8; 18],
                            pos: 0,
                        };
                    }
                    return Poll::Ready(Ok(()));
                }
                ReaderState::ReadingLength { buf: len_buf, pos } => {
                    while *pos < 18 {
                        let mut read_buf = ReadBuf::new(&mut len_buf[*pos..18]);
                        match Pin::new(&mut *stream).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    if *pos == 0 {
                                        return Poll::Ready(Ok(()));
                                    } else {
                                        return Poll::Ready(Err(io::Error::new(
                                            io::ErrorKind::UnexpectedEof,
                                            "Unexpected EOF while reading length chunk",
                                        )));
                                    }
                                }
                                *pos += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    if !self.cipher.decrypt_packet(len_buf) {
                        warn!(
                            transport = "tcp",
                            direction = "request",
                            stage = "chunk-length",
                            nonce_len = 12,
                            ciphertext_len = 18,
                            expected_plaintext_len = 2,
                            "SS2022 decrypt failed: chunk length tag verification failed"
                        );
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Failed to decrypt SS2022 chunk length tag",
                        )));
                    }
                    let chunk_len = u16::from_be_bytes([len_buf[0], len_buf[1]]) as usize;
                    if chunk_len == 0 {
                        self.state = ReaderState::ReadingLength {
                            buf: [0u8; 18],
                            pos: 0,
                        };
                        continue;
                    }
                    self.state = ReaderState::ReadingData {
                        length: chunk_len,
                        buf: vec![0u8; chunk_len + 16],
                        pos: 0,
                    };
                }
                ReaderState::ReadingData {
                    length,
                    buf: data_buf,
                    pos,
                } => {
                    let total = *length + 16;
                    while *pos < total {
                        let mut read_buf = ReadBuf::new(&mut data_buf[*pos..total]);
                        match Pin::new(&mut *stream).poll_read(cx, &mut read_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = read_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "Unexpected EOF while reading data chunk",
                                    )));
                                }
                                *pos += n;
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                    if !self.cipher.decrypt_packet(data_buf) {
                        warn!(
                            transport = "tcp",
                            direction = "request",
                            stage = "chunk-data",
                            nonce_len = 12,
                            ciphertext_len = total,
                            expected_plaintext_len = *length,
                            "SS2022 decrypt failed: chunk data tag verification failed"
                        );
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Failed to decrypt SS2022 chunk data tag",
                        )));
                    }
                    data_buf.truncate(*length);
                    let finished_buf = std::mem::take(data_buf);
                    self.state = ReaderState::YieldingData {
                        buf: finished_buf,
                        pos: 0,
                    };
                }
            }
        }
    }
}

enum WriterState {
    FirstChunk,
    Normal,
}

pub struct Ss2022TcpWriter {
    cipher: TcpCipher,
    response_salt: Vec<u8>,
    request_salt: Vec<u8>,
    pending_buf: Vec<u8>,
    pending_pos: usize,
    state: WriterState,
}

impl Ss2022TcpWriter {
    pub fn new(cipher: TcpCipher, response_salt: Vec<u8>, request_salt: Vec<u8>) -> Self {
        Self {
            cipher,
            response_salt,
            request_salt,
            pending_buf: Vec::new(),
            pending_pos: 0,
            state: WriterState::FirstChunk,
        }
    }

    pub fn poll_write_encrypted<S>(
        &mut self,
        cx: &mut TaskContext<'_>,
        stream: &mut S,
        buf: &[u8],
    ) -> Poll<io::Result<usize>>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        while self.pending_pos < self.pending_buf.len() {
            match Pin::new(&mut *stream).poll_write(cx, &self.pending_buf[self.pending_pos..]) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "Failed to write to stream",
                        )));
                    }
                    self.pending_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        self.pending_buf.clear();
        self.pending_pos = 0;

        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let chunk_len = buf.len().min(SS2022_MAX_CHUNK_LEN);
        let payload = &buf[..chunk_len];

        match self.state {
            WriterState::FirstChunk => {
                let salt_len = self.request_salt.len();
                let fixed_header_plain_len = 1 + 8 + salt_len + 2;
                let mut fixed_header = Vec::with_capacity(fixed_header_plain_len + 16);
                fixed_header.push(1u8);
                fixed_header.extend_from_slice(&now()?.to_be_bytes());
                fixed_header.extend_from_slice(&self.request_salt);
                fixed_header.extend_from_slice(&(chunk_len as u16).to_be_bytes());
                fixed_header.resize(fixed_header_plain_len + 16, 0);
                self.cipher.encrypt_packet(&mut fixed_header);

                let mut data_chunk = Vec::with_capacity(chunk_len + 16);
                data_chunk.extend_from_slice(payload);
                data_chunk.resize(chunk_len + 16, 0);
                self.cipher.encrypt_packet(&mut data_chunk);

                self.pending_buf.extend_from_slice(&self.response_salt);
                self.pending_buf.extend_from_slice(&fixed_header);
                self.pending_buf.extend_from_slice(&data_chunk);
                self.state = WriterState::Normal;
            }
            WriterState::Normal => {
                let mut len_chunk = vec![0u8; 18];
                len_chunk[..2].copy_from_slice(&(chunk_len as u16).to_be_bytes());
                self.cipher.encrypt_packet(&mut len_chunk);

                let mut data_chunk = Vec::with_capacity(chunk_len + 16);
                data_chunk.extend_from_slice(payload);
                data_chunk.resize(chunk_len + 16, 0);
                self.cipher.encrypt_packet(&mut data_chunk);

                self.pending_buf.extend_from_slice(&len_chunk);
                self.pending_buf.extend_from_slice(&data_chunk);
            }
        }

        while self.pending_pos < self.pending_buf.len() {
            match Pin::new(&mut *stream).poll_write(cx, &self.pending_buf[self.pending_pos..]) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "Failed to write to stream",
                        )));
                    }
                    self.pending_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    return Poll::Ready(Ok(chunk_len));
                }
            }
        }

        self.pending_buf.clear();
        self.pending_pos = 0;
        Poll::Ready(Ok(chunk_len))
    }

    pub fn poll_flush<S>(
        &mut self,
        cx: &mut TaskContext<'_>,
        stream: &mut S,
    ) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        while self.pending_pos < self.pending_buf.len() {
            match Pin::new(&mut *stream).poll_write(cx, &self.pending_buf[self.pending_pos..]) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "Failed to write to stream",
                        )));
                    }
                    self.pending_pos += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        self.pending_buf.clear();
        self.pending_pos = 0;
        Pin::new(&mut *stream).poll_flush(cx)
    }

    pub fn poll_shutdown<S>(
        &mut self,
        cx: &mut TaskContext<'_>,
        stream: &mut S,
    ) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        match self.poll_flush(cx, stream) {
            Poll::Ready(Ok(())) => Pin::new(&mut *stream).poll_shutdown(cx),
            other => other,
        }
    }
}

pub struct Ss2022Stream<S> {
    inner: S,
    reader: Ss2022TcpReader,
    writer: Ss2022TcpWriter,
}

impl<S: AsyncRead + Unpin> AsyncRead for Ss2022Stream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.reader.poll_read_decrypted(cx, &mut this.inner, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Ss2022Stream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;
        this.writer.poll_write_encrypted(cx, &mut this.inner, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.writer.poll_flush(cx, &mut this.inner)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        let this = &mut *self;
        this.writer.poll_shutdown(cx, &mut this.inner)
    }
}

pub async fn handshake(
    mut stream: BoxedStream,
    method: Method,
    server_key: Option<&[u8]>,
    users: &UserIndex,
) -> io::Result<(Arc<Credential>, BoxedStream, Address)> {
    let Method::Aead2022(method) = method else {
        return Err(invalid("Expected SS2022 method"));
    };
    let salt_len = method.salt_len();
    let mut salt = vec![0u8; salt_len];
    stream.read_exact(&mut salt).await?;

    if users.credentials.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SS2022 no user configured",
        ));
    }

    let mut first_27 = [0u8; 27];
    stream.read_exact(&mut first_27).await?;

    let mut received_initial_bytes = Vec::with_capacity(salt_len + 27 + 16);
    received_initial_bytes.extend_from_slice(&salt);
    received_initial_bytes.extend_from_slice(&first_27);

    let mut resolved_handshake: Option<(Arc<Credential>, TcpCipher, [u8; 27])> = None;
    let direct_attempted = true;
    let mut direct_auth_success = false;
    let mut eih_attempted = false;
    let server_key_present = server_key.is_some();
    let mut eih_identity_success = false;
    let mut eih_user_trial_count = 0usize;
    let mut eih_header_auth_success = false;

    for (idx, cred) in users.credentials.iter().enumerate() {
        let mut cipher = TcpCipher::new(method, &cred.key, &salt);
        let mut candidate_fixed = first_27;
        if cipher.decrypt_packet(&mut candidate_fixed) && candidate_fixed[0] == 0 {
            direct_auth_success = true;
            let session_subkey = derive_session_subkey(&cred.key, &salt, method.key_len());
            let subkey_fingerprint = hex::encode(&sha2::Sha256::digest(&session_subkey)[..8]);
            info!(
                transport = "tcp",
                direction = "request",
                method = ?method,
                salt_len = salt_len,
                eih_count = 0,
                eih_bytes_consumed = 0,
                aead_header_offset = salt_len,
                aead_ciphertext_len = 27,
                selected_user_index = idx,
                mode = if users.credentials.len() == 1 { "single_user" } else { "multi_user" },
                master_key_source = "user",
                session_subkey_fingerprint = %subkey_fingerprint,
                received_initial_bytes = %hex::encode(&received_initial_bytes[..received_initial_bytes.len().min(64)]),
                "SS2022 handshake successful (wire offset {}, no EIH)",
                salt_len
            );
            resolved_handshake = Some((cred.clone(), cipher, candidate_fixed));
            break;
        }
    }

    if resolved_handshake.is_none() {
        if let Some(skey) = server_key {
            let mut cipher = TcpCipher::new(method, skey, &salt);
            let mut candidate_fixed = first_27;
            if cipher.decrypt_packet(&mut candidate_fixed) && candidate_fixed[0] == 0 {
                direct_auth_success = true;
                let default_cred = users.credentials.first().cloned().unwrap_or_else(|| {
                    Arc::new(Credential {
                        user: User {
                            id: 0,
                            ..Default::default()
                        },
                        key: skey.to_vec(),
                        identity_hash: [0u8; 16],
                        context: Arc::new(Context::new(shadowsocks::config::ServerType::Server)),
                    })
                });
                let session_subkey = derive_session_subkey(skey, &salt, method.key_len());
                let subkey_fingerprint = hex::encode(&sha2::Sha256::digest(&session_subkey)[..8]);
                info!(
                    transport = "tcp",
                    direction = "request",
                    method = ?method,
                    salt_len = salt_len,
                    eih_count = 0,
                    eih_bytes_consumed = 0,
                    aead_header_offset = salt_len,
                    aead_ciphertext_len = 27,
                    selected_user_index = 0,
                    mode = if users.credentials.len() == 1 { "single_user" } else { "multi_user" },
                    master_key_source = "server",
                    session_subkey_fingerprint = %subkey_fingerprint,
                    received_initial_bytes = %hex::encode(&received_initial_bytes[..received_initial_bytes.len().min(64)]),
                    "SS2022 handshake successful (wire offset {}, no EIH, matched server_key)",
                    salt_len
                );
                resolved_handshake = Some((default_cred, cipher, candidate_fixed));
            }
        }
    }

    if resolved_handshake.is_none() {
        eih_attempted = true;
        let mut next_16 = [0u8; 16];
        stream.read_exact(&mut next_16).await?;
        received_initial_bytes.extend_from_slice(&next_16);

        let mut eih_block = [0u8; 16];
        eih_block.copy_from_slice(&first_27[0..16]);
        let mut candidate_fixed = [0u8; 27];
        candidate_fixed[..11].copy_from_slice(&first_27[16..27]);
        candidate_fixed[11..].copy_from_slice(&next_16);

        if let Some(skey) = server_key {
            let id_subkey = derive_identity_subkey(skey, &salt);
            let mut identity = eih_block;
            aes_block_decrypt(
                method,
                &id_subkey[..skey.len().min(id_subkey.len())],
                &mut identity,
            );
            if let Some(cred) = users.identity_map.get(&identity).cloned() {
                eih_identity_success = true;
                let mut cipher = TcpCipher::new(method, &cred.key, &salt);
                let mut test_header = candidate_fixed;
                if cipher.decrypt_packet(&mut test_header) && test_header[0] == 0 {
                    eih_header_auth_success = true;
                    let user_idx = users
                        .credentials
                        .iter()
                        .position(|c| c.user.id == cred.user.id)
                        .unwrap_or(0);
                    let session_subkey = derive_session_subkey(&cred.key, &salt, method.key_len());
                    let subkey_fingerprint =
                        hex::encode(&sha2::Sha256::digest(&session_subkey)[..8]);
                    info!(
                        transport = "tcp",
                        direction = "request",
                        method = ?method,
                        salt_len = salt_len,
                        eih_count = 1,
                        eih_bytes_consumed = 16,
                        aead_header_offset = salt_len + 16,
                        aead_ciphertext_len = 27,
                        selected_user_index = user_idx,
                        mode = if users.credentials.len() == 1 { "single_user" } else { "multi_user" },
                        master_key_source = "server",
                        session_subkey_fingerprint = %subkey_fingerprint,
                        received_initial_bytes = %hex::encode(&received_initial_bytes[..received_initial_bytes.len().min(64)]),
                        "SS2022 handshake successful (wire offset {}, 16-byte EIH resolved via server_key)",
                        salt_len + 16
                    );
                    resolved_handshake = Some((cred, cipher, test_header));
                }
            }
        }

        if resolved_handshake.is_none() {
            for (idx, cred) in users.credentials.iter().enumerate() {
                eih_user_trial_count += 1;
                let mut cipher = TcpCipher::new(method, &cred.key, &salt);
                let mut test_header = candidate_fixed;
                if cipher.decrypt_packet(&mut test_header) && test_header[0] == 0 {
                    eih_header_auth_success = true;
                    let session_subkey = derive_session_subkey(&cred.key, &salt, method.key_len());
                    let subkey_fingerprint =
                        hex::encode(&sha2::Sha256::digest(&session_subkey)[..8]);
                    info!(
                        transport = "tcp",
                        direction = "request",
                        method = ?method,
                        salt_len = salt_len,
                        eih_count = 1,
                        eih_bytes_consumed = 16,
                        aead_header_offset = salt_len + 16,
                        aead_ciphertext_len = 27,
                        selected_user_index = idx,
                        mode = if users.credentials.len() == 1 { "single_user" } else { "multi_user" },
                        master_key_source = "user",
                        session_subkey_fingerprint = %subkey_fingerprint,
                        received_initial_bytes = %hex::encode(&received_initial_bytes[..received_initial_bytes.len().min(64)]),
                        "SS2022 handshake successful (wire offset {}, 16-byte EIH trial matched user credential)",
                        salt_len + 16
                    );
                    resolved_handshake = Some((cred.clone(), cipher, test_header));
                    break;
                }
            }

            if resolved_handshake.is_none() {
                if let Some(skey) = server_key {
                    let mut cipher = TcpCipher::new(method, skey, &salt);
                    let mut test_header = candidate_fixed;
                    if cipher.decrypt_packet(&mut test_header) && test_header[0] == 0 {
                        eih_header_auth_success = true;
                        let default_cred =
                            users.credentials.first().cloned().unwrap_or_else(|| {
                                Arc::new(Credential {
                                    user: User {
                                        id: 0,
                                        ..Default::default()
                                    },
                                    key: skey.to_vec(),
                                    identity_hash: [0u8; 16],
                                    context: Arc::new(Context::new(
                                        shadowsocks::config::ServerType::Server,
                                    )),
                                })
                            });
                        let session_subkey = derive_session_subkey(skey, &salt, method.key_len());
                        let subkey_fingerprint =
                            hex::encode(&sha2::Sha256::digest(&session_subkey)[..8]);
                        info!(
                            transport = "tcp",
                            direction = "request",
                            method = ?method,
                            salt_len = salt_len,
                            eih_count = 1,
                            eih_bytes_consumed = 16,
                            aead_header_offset = salt_len + 16,
                            aead_ciphertext_len = 27,
                            selected_user_index = 0,
                            mode = if users.credentials.len() == 1 { "single_user" } else { "multi_user" },
                            master_key_source = "server",
                            session_subkey_fingerprint = %subkey_fingerprint,
                            received_initial_bytes = %hex::encode(&received_initial_bytes[..received_initial_bytes.len().min(64)]),
                            "SS2022 handshake successful (wire offset {}, 16-byte EIH trial matched server_key)",
                            salt_len + 16
                        );
                        resolved_handshake = Some((default_cred, cipher, test_header));
                    }
                }
            }
        }
    }

    let (credential, mut req_cipher, fixed_header) = match resolved_handshake {
        Some(res) => res,
        None => {
            let default_cred = users.credentials.first();
            let (session_subkey, master_key_source) = match (default_cred, server_key) {
                (Some(c), _) => (
                    derive_session_subkey(&c.key, &salt, method.key_len()),
                    "user",
                ),
                (None, Some(sk)) => (derive_session_subkey(sk, &salt, method.key_len()), "server"),
                (None, None) => (vec![0u8; method.key_len()], "none"),
            };
            let subkey_fingerprint = hex::encode(&sha2::Sha256::digest(&session_subkey)[..8]);
            let aead_header_offset = if eih_attempted {
                salt_len + 16
            } else {
                salt_len
            };
            let eih_bytes_consumed = if eih_attempted { 16 } else { 0 };
            let eih_count = if eih_attempted { 1 } else { 0 };
            warn!(
                method = ?method,
                transport = "tcp",
                direction = "request",
                stage = "request-header",
                salt_len = salt_len,
                eih_count = eih_count,
                eih_bytes_consumed = eih_bytes_consumed,
                aead_header_offset = aead_header_offset,
                aead_ciphertext_len = 27,
                selected_user_index = 0,
                mode = if users.credentials.len() == 1 { "single_user" } else { "multi_user" },
                master_key_source = master_key_source,
                session_subkey_fingerprint = %subkey_fingerprint,
                direct_attempted = direct_attempted,
                direct_auth_success = direct_auth_success,
                eih_attempted = eih_attempted,
                server_key_present = server_key_present,
                eih_identity_success = eih_identity_success,
                eih_user_trial_count = eih_user_trial_count,
                eih_header_auth_success = eih_header_auth_success,
                received_initial_bytes = %hex::encode(&received_initial_bytes[..received_initial_bytes.len().min(64)]),
                "SS2022 decrypt failed: request header tag verification failed"
            );
            return Err(invalid("Invalid SS2022 header tag"));
        }
    };
    if fixed_header[0] != 0 {
        warn!(
            method = ?method,
            transport = "tcp",
            direction = "request",
            stage = "request-header",
            received_type = fixed_header[0],
            "SS2022 request failed: invalid request type, expected 0"
        );
        return Err(invalid("Invalid SS2022 request type"));
    }
    let timestamp = u64::from_be_bytes(fixed_header[1..9].try_into().unwrap());
    let current_time = now()?;
    if current_time.abs_diff(timestamp) > SERVER_STREAM_TIMESTAMP_MAX_DIFF {
        warn!(
            method = ?method,
            transport = "tcp",
            direction = "request",
            stage = "request-header",
            client_timestamp = timestamp,
            server_timestamp = current_time,
            skew = current_time.abs_diff(timestamp),
            "SS2022 request failed: timestamp skew exceeds limit"
        );
        return Err(invalid("Invalid SS2022 request timestamp"));
    }

    let var_len = u16::from_be_bytes([fixed_header[9], fixed_header[10]]) as usize;
    let mut body = vec![0u8; var_len + 16];
    stream.read_exact(&mut body).await?;
    if !req_cipher.decrypt_packet(&mut body) {
        warn!(
            method = ?method,
            transport = "tcp",
            direction = "request",
            stage = "request-variable-header",
            key_len = credential.key.len(),
            salt_len = salt.len(),
            nonce_len = 12,
            nonce_counter = 1,
            ciphertext_len = var_len + 16,
            expected_plaintext_len = var_len,
            "SS2022 decrypt failed: variable header tag verification failed"
        );
        return Err(invalid("Invalid SS2022 variable header tag"));
    }
    body.truncate(var_len);

    let mut cursor = Cursor::new(&body);
    let address = Address::read_cursor(&mut cursor).map_err(io::Error::other)?;
    let offset = cursor.position() as usize;
    if var_len < offset + 2 {
        return Err(invalid("Truncated SS2022 padding length"));
    }

    let padding = u16::from_be_bytes([body[offset], body[offset + 1]]) as usize;
    let payload_start = offset + 2 + padding;
    if var_len < payload_start {
        return Err(invalid("Invalid SS2022 initial padding/payload"));
    }
    let initial_payload = body[payload_start..].to_vec();
    if padding == 0 && initial_payload.is_empty() {
        return Err(invalid(
            "Insecure client: padding is 0 and no initial payload",
        ));
    }

    credential.context.check_nonce_replay(method, &salt)?;

    let reader = Ss2022TcpReader::new(req_cipher, initial_payload);

    let mut response_salt = vec![0u8; method.salt_len()];
    rand::rngs::OsRng.fill_bytes(&mut response_salt);
    let resp_cipher = TcpCipher::new(method, &credential.key, &response_salt);
    let writer = Ss2022TcpWriter::new(resp_cipher, response_salt, salt);

    let ss_stream = Ss2022Stream {
        inner: stream,
        reader,
        writer,
    };

    Ok((credential, Box::new(ss_stream), address))
}

pub struct Datagram {
    pub credential: Arc<Credential>,
    pub address: Address,
    pub payload: Vec<u8>,
    pub session_id: u64,
    pub packet_id: u64,
}

#[allow(dead_code)]
pub fn decrypt_udp(
    method: Method,
    server_key: Option<&[u8]>,
    users: &UserIndex,
    packet: &[u8],
) -> io::Result<Datagram> {
    decrypt_udp_with_cache(method, server_key, users, packet, None)
}

pub fn decrypt_udp_with_cache(
    method: Method,
    server_key: Option<&[u8]>,
    users: &UserIndex,
    packet: &[u8],
    cached_user_id: Option<u32>,
) -> io::Result<Datagram> {
    if method == Method::None {
        if packet.len() < 3 {
            return Err(invalid("Truncated Shadowsocks UDP packet"));
        }
        let mut cursor = Cursor::new(packet);
        let address = Address::read_cursor(&mut cursor).map_err(io::Error::other)?;
        let offset = cursor.position() as usize;
        let credential = users
            .credentials
            .first()
            .cloned()
            .ok_or_else(|| invalid("No users configured for Shadowsocks UDP"))?;
        return Ok(Datagram {
            credential,
            address,
            payload: packet[offset..].to_vec(),
            session_id: 0,
            packet_id: 0,
        });
    }
    if let Method::Legacy(kind) = method {
        if packet.len() < kind.salt_len() + 16 {
            return Err(invalid("Truncated Shadowsocks UDP packet"));
        }
        let (salt, encrypted) = packet.split_at(kind.salt_len());

        if let Some(uid) = cached_user_id {
            for credential in users.credentials.iter().filter(|c| c.user.id == uid) {
                let mut key = vec![0; kind.key_len()];
                crate::protocol::ss_crypto::hkdf_sha1(&credential.key, salt, &mut key);
                let cipher = crate::protocol::ss_crypto::AeadCipher::new(kind, &key);
                let mut data = encrypted.to_vec();
                if cipher.decrypt_in_place(&[0; 12], &mut data).is_ok() {
                    data.truncate(data.len() - 16);
                    let mut cursor = Cursor::new(data.as_slice());
                    let address = Address::read_cursor(&mut cursor).map_err(io::Error::other)?;
                    let offset = cursor.position() as usize;
                    credential
                        .context
                        .check_nonce_replay(method.replay_method(), salt)?;
                    return Ok(Datagram {
                        credential: credential.clone(),
                        address,
                        payload: data[offset..].to_vec(),
                        session_id: 0,
                        packet_id: 0,
                    });
                }
            }
        }

        for credential in &users.credentials {
            if Some(credential.user.id) == cached_user_id {
                continue;
            }
            let mut key = vec![0; kind.key_len()];
            crate::protocol::ss_crypto::hkdf_sha1(&credential.key, salt, &mut key);
            let cipher = crate::protocol::ss_crypto::AeadCipher::new(kind, &key);
            let mut data = encrypted.to_vec();
            if cipher.decrypt_in_place(&[0; 12], &mut data).is_ok() {
                data.truncate(data.len() - 16);
                let mut cursor = Cursor::new(data.as_slice());
                let address = Address::read_cursor(&mut cursor).map_err(io::Error::other)?;
                let offset = cursor.position() as usize;
                credential
                    .context
                    .check_nonce_replay(method.replay_method(), salt)?;
                return Ok(Datagram {
                    credential: credential.clone(),
                    address,
                    payload: data[offset..].to_vec(),
                    session_id: 0,
                    packet_id: 0,
                });
            }
        }
        return Err(invalid("Shadowsocks UDP authentication failed"));
    }
    let Method::Aead2022(method) = method else {
        unreachable!()
    };
    let chacha = method == CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305;

    if chacha {
        if packet.len() < 24 + 16 + 11 + 16 {
            return Err(invalid("Truncated SS2022 ChaCha20 UDP packet"));
        }
        let credential = if let Some(uid) = cached_user_id {
            users
                .credentials
                .iter()
                .find(|c| c.user.id == uid)
                .or_else(|| users.credentials.first())
        } else {
            users.credentials.first()
        }
        .ok_or_else(|| invalid("No user configured for SS2022 UDP"))?;

        let mut data = packet[24..].to_vec();
        if !UdpCipher::new(method, &credential.key, 0).decrypt_packet(&packet[..24], &mut data) {
            warn!(
                method = "2022-blake3-chacha20-poly1305",
                transport = "udp",
                direction = "request",
                stage = "udp-payload",
                key_len = credential.key.len(),
                nonce_len = 24,
                ciphertext_len = data.len(),
                "SS2022 decrypt failed: ChaCha20 UDP tag verification failed"
            );
            return Err(invalid("SS2022 ChaCha20 UDP tag verification failed"));
        }
        data.truncate(data.len() - 16);
        let sid = u64::from_be_bytes(data[..8].try_into().unwrap());
        let pid = u64::from_be_bytes(data[8..16].try_into().unwrap());
        let offset = 16;
        if data[offset] != 0 {
            return Err(invalid("Invalid SS2022 UDP request type"));
        }
        let timestamp = u64::from_be_bytes(data[offset + 1..offset + 9].try_into().unwrap());
        if now()?.abs_diff(timestamp) > MAX_TIMESTAMP_SKEW_SECS {
            return Err(invalid("Invalid SS2022 UDP timestamp"));
        }
        let padding = u16::from_be_bytes([data[offset + 9], data[offset + 10]]) as usize;
        let start = offset + 11 + padding;
        if start > data.len() {
            return Err(invalid("Invalid SS2022 UDP padding"));
        }
        let mut cursor = Cursor::new(&data[start..]);
        let address = Address::read_cursor(&mut cursor).map_err(io::Error::other)?;
        let payload = data[start + cursor.position() as usize..].to_vec();
        return Ok(Datagram {
            credential: credential.clone(),
            address,
            payload,
            session_id: sid,
            packet_id: pid,
        });
    }

    if let Some(header_key) = server_key {
        if packet.len() < 32 + 11 + 16 {
            return Err(invalid("Truncated SS2022 multi-user UDP packet"));
        }
        let mut data = packet.to_vec();
        aes_block(method, header_key, &mut data[..16], false);
        aes_block(method, header_key, &mut data[16..32], false);
        for i in 0..16 {
            data[16 + i] ^= data[i];
        }
        let mut user_id = [0u8; 16];
        user_id.copy_from_slice(&data[16..32]);

        let credential = users.identity_map.get(&user_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SS2022 UDP EIH user authentication failed",
            )
        })?;

        let sid = u64::from_be_bytes(data[..8].try_into().unwrap());
        let pid = u64::from_be_bytes(data[8..16].try_into().unwrap());
        let nonce = data[4..16].to_vec();
        if !UdpCipher::new(method, &credential.key, sid).decrypt_packet(&nonce, &mut data[32..]) {
            return Err(invalid("SS2022 UDP body tag verification failed"));
        }
        data.truncate(data.len() - 16);
        let offset = 32;
        if data[offset] != 0 {
            return Err(invalid("Invalid SS2022 UDP request type"));
        }
        let timestamp = u64::from_be_bytes(data[offset + 1..offset + 9].try_into().unwrap());
        if now()?.abs_diff(timestamp) > MAX_TIMESTAMP_SKEW_SECS {
            return Err(invalid("Invalid SS2022 UDP timestamp"));
        }
        let padding = u16::from_be_bytes([data[offset + 9], data[offset + 10]]) as usize;
        let start = offset + 11 + padding;
        if start > data.len() {
            return Err(invalid("Invalid SS2022 UDP padding"));
        }
        let mut cursor = Cursor::new(&data[start..]);
        let address = Address::read_cursor(&mut cursor).map_err(io::Error::other)?;
        let payload = data[start + cursor.position() as usize..].to_vec();
        return Ok(Datagram {
            credential: credential.clone(),
            address,
            payload,
            session_id: sid,
            packet_id: pid,
        });
    }

    if packet.len() < 16 + 11 + 16 {
        return Err(invalid("Truncated SS2022 single-user UDP packet"));
    }
    let credential = if let Some(uid) = cached_user_id {
        users
            .credentials
            .iter()
            .find(|c| c.user.id == uid)
            .or_else(|| users.credentials.first())
    } else {
        users.credentials.first()
    }
    .ok_or_else(|| invalid("No user configured for SS2022 UDP"))?;

    let mut data = packet.to_vec();
    aes_block(method, &credential.key, &mut data[..16], false);
    let sid = u64::from_be_bytes(data[..8].try_into().unwrap());
    let pid = u64::from_be_bytes(data[8..16].try_into().unwrap());
    let nonce = data[4..16].to_vec();
    if !UdpCipher::new(method, &credential.key, sid).decrypt_packet(&nonce, &mut data[16..]) {
        return Err(invalid("SS2022 UDP body tag verification failed"));
    }
    data.truncate(data.len() - 16);
    let offset = 16;
    if data[offset] != 0 {
        return Err(invalid("Invalid SS2022 UDP request type"));
    }
    let timestamp = u64::from_be_bytes(data[offset + 1..offset + 9].try_into().unwrap());
    if now()?.abs_diff(timestamp) > MAX_TIMESTAMP_SKEW_SECS {
        return Err(invalid("Invalid SS2022 UDP timestamp"));
    }
    let padding = u16::from_be_bytes([data[offset + 9], data[offset + 10]]) as usize;
    let start = offset + 11 + padding;
    if start > data.len() {
        return Err(invalid("Invalid SS2022 UDP padding"));
    }
    let mut cursor = Cursor::new(&data[start..]);
    let address = Address::read_cursor(&mut cursor).map_err(io::Error::other)?;
    let payload = data[start + cursor.position() as usize..].to_vec();
    Ok(Datagram {
        credential: credential.clone(),
        address,
        payload,
        session_id: sid,
        packet_id: pid,
    })
}

pub fn encrypt_udp(
    method: Method,
    credential: &Credential,
    address: &Address,
    client_session: u64,
    server_session: u64,
    packet_id: u64,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut data = BytesMut::new();
    if method == Method::None {
        address.write_to_buf(&mut data);
        data.extend_from_slice(payload);
        if data.len() > 65507 {
            return Err(invalid("Encrypted Shadowsocks datagram exceeds UDP limit"));
        }
        return Ok(data.to_vec());
    }
    if let Method::Legacy(kind) = method {
        let mut salt = vec![0; kind.salt_len()];
        use rand::RngCore;
        rand::rngs::OsRng.fill_bytes(&mut salt);
        let mut key = vec![0; kind.key_len()];
        crate::protocol::ss_crypto::hkdf_sha1(&credential.key, &salt, &mut key);
        address.write_to_buf(&mut data);
        data.extend_from_slice(payload);
        let mut body = data.to_vec();
        crate::protocol::ss_crypto::AeadCipher::new(kind, &key)
            .encrypt_in_place(&[0; 12], &mut body)?;
        data.clear();
        data.extend_from_slice(&salt);
        data.extend_from_slice(&body);
    } else {
        let Method::Aead2022(method) = method else {
            unreachable!()
        };
        let chacha = method == CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305;
        if chacha {
            let nonce: [u8; 24] = rand::random();
            data.extend_from_slice(&nonce);
        }
        data.put_u64(server_session);
        data.put_u64(packet_id);
        data.put_u8(1);
        data.put_u64(now()?);
        data.put_u64(client_session);
        let padding: u16 = if payload.is_empty() { 1 } else { 0 };
        data.put_u16(padding);
        if padding > 0 {
            data.put_u8(rand::random());
        }
        address.write_to_buf(&mut data);
        data.extend_from_slice(payload);
        data.resize(data.len() + 16, 0);
        let cipher = UdpCipher::new(method, &credential.key, server_session);
        if chacha {
            let (nonce, message) = data.split_at_mut(24);
            cipher.encrypt_packet(nonce, message);
        } else {
            let (header, message) = data.split_at_mut(16);
            cipher.encrypt_packet(&header[4..16], message);
            aes_block(method, &credential.key, header, true);
        }
    }
    if data.len() > 65507 {
        return Err(invalid("Encrypted Shadowsocks datagram exceeds UDP limit"));
    }
    Ok(data.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn first_header_boundaries_authentication_and_replay() {
        for name in [
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ] {
            let method: Method = name.parse().unwrap();
            let Method::Aead2022(cipher_kind) = method else {
                unreachable!()
            };
            let password =
                base64::engine::general_purpose::STANDARD.encode(vec![7; method.key_len()]);
            let context = Arc::new(Context::new(shadowsocks::config::ServerType::Server));
            let credential = Arc::new(
                Credential::new(
                    User {
                        password: Some(password),
                        ..Default::default()
                    },
                    method,
                    context,
                )
                .unwrap(),
            );
            let salt = vec![3; method.key_len()];
            let mut cipher = TcpCipher::new(cipher_kind, &credential.key, &salt);
            let mut fixed = vec![0];
            fixed.extend_from_slice(&now().unwrap().to_be_bytes());
            fixed.extend_from_slice(&10u16.to_be_bytes());
            fixed.resize(27, 0);
            cipher.encrypt_packet(&mut fixed);
            let mut variable = vec![1, 127, 0, 0, 1, 0, 80, 0, 1, 0];
            variable.resize(26, 0);
            cipher.encrypt_packet(&mut variable);
            let wire = [salt, fixed, variable].concat();
            let user_index = UserIndex::new(vec![credential.clone()]);
            for length in 0..wire.len() {
                let (mut tx, rx) = tokio::io::duplex(wire.len() + 1);
                tx.write_all(&wire[..length]).await.unwrap();
                tx.shutdown().await.unwrap();
                assert!(
                    handshake(Box::new(rx), method, None, &user_index,)
                        .await
                        .is_err(),
                    "accepted truncated {name} length {length}"
                );
            }
            let mut bad = wire.clone();
            *bad.last_mut().unwrap() ^= 1;
            let (mut tx, rx) = tokio::io::duplex(wire.len() + 1);
            tx.write_all(&bad).await.unwrap();
            tx.shutdown().await.unwrap();
            assert!(handshake(Box::new(rx), method, None, &user_index,)
                .await
                .is_err());
            for replay in [false, true] {
                let (mut tx, rx) = tokio::io::duplex(wire.len() + 1);
                tx.write_all(&wire).await.unwrap();
                tx.shutdown().await.unwrap();
                let result = handshake(Box::new(rx), method, None, &user_index).await;
                assert_eq!(result.is_err(), replay);
            }
        }
    }

    #[test]
    fn key_and_packet_lengths_are_checked() {
        let empty_index = UserIndex::default();
        for name in [
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ] {
            let method: Method = name.parse().unwrap();
            for value in ["", "wrong-password", "YWJjZA=="] {
                assert!(decode_key(value, method).is_err());
            }
            for length in 0..43 {
                assert!(decrypt_udp(method, None, &empty_index, &vec![0; length]).is_err());
            }
        }
    }

    #[test]
    fn test_ss2022_massive_users_o1_lookup() {
        let method: Method = "2022-blake3-aes-128-gcm".parse().unwrap();
        let server_key = vec![0x42u8; 16];
        let context = Arc::new(Context::new(shadowsocks::config::ServerType::Server));

        let mut users = Vec::with_capacity(5000);
        for id in 1u32..=5000 {
            let mut key = vec![0u8; 16];
            key[..4].copy_from_slice(&id.to_be_bytes());
            key[4..8].copy_from_slice(&0xdeadbeefu32.to_be_bytes());
            let password = base64::engine::general_purpose::STANDARD.encode(&key);
            let cred = Arc::new(
                Credential::new(
                    User {
                        id,
                        password: Some(password),
                        ..Default::default()
                    },
                    method,
                    context.clone(),
                )
                .unwrap(),
            );
            users.push(cred);
        }

        let user_index = UserIndex::new(users.clone());
        assert_eq!(user_index.identity_map.len(), 5000);
        assert_eq!(user_index.valid_keys.len(), 5000);

        let target_user = &users[4241];
        let addr = Address::SocketAddress("1.1.1.1:53".parse().unwrap());
        let payload = b"hello-massive-o1";

        let Method::Aead2022(cipher_kind) = method else {
            unreachable!()
        };
        let mut header = [0u8; 16];
        header[..8].copy_from_slice(&100u64.to_be_bytes());
        header[8..16].copy_from_slice(&1u64.to_be_bytes());

        let mut eih = [0u8; 16];
        let id_hash = blake3::hash(&target_user.key);
        eih.copy_from_slice(&id_hash.as_bytes()[..16]);
        for i in 0..16 {
            eih[i] ^= header[i];
        }

        let mut body = Vec::new();
        body.push(0u8);
        body.extend_from_slice(&now().unwrap().to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        addr.write_to_buf(&mut body);
        body.extend_from_slice(payload);
        body.resize(body.len() + 16, 0);

        let cipher = UdpCipher::new(cipher_kind, &target_user.key, 100);
        cipher.encrypt_packet(&header[4..16], &mut body);

        aes_block(cipher_kind, &server_key, &mut header, true);
        aes_block(cipher_kind, &server_key, &mut eih, true);

        let mut wire = Vec::new();
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&eih);
        wire.extend_from_slice(&body);

        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let dg = decrypt_udp(method, Some(&server_key), &user_index, &wire).unwrap();
            assert_eq!(dg.credential.user.id, 4242);
            assert_eq!(dg.payload, payload);
        }
        let elapsed = start.elapsed();

        assert!(
            elapsed.as_millis() < 50,
            "Expected O(1) decryption, took {:?}",
            elapsed
        );
    }

    #[test]
    fn test_ss2022_key_base64_strict_and_rejection() {
        for name in [
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ] {
            let method: Method = name.parse().unwrap();
            let raw_key = vec![0x37u8; method.key_len()];

            let std_padded = base64::engine::general_purpose::STANDARD.encode(&raw_key);
            assert_eq!(decode_key(&std_padded, method).unwrap(), raw_key);

            let std_unpadded = std_padded.trim_end_matches('=').to_string();
            assert_eq!(decode_key(&std_unpadded, method).unwrap(), raw_key);

            let url_padded = base64::engine::general_purpose::URL_SAFE.encode(&raw_key);
            assert_eq!(decode_key(&url_padded, method).unwrap(), raw_key);
            let url_unpadded = url_padded.trim_end_matches('=').to_string();
            assert_eq!(decode_key(&url_unpadded, method).unwrap(), raw_key);

            let ss_key = Ss2022Key::parse(&std_padded, method).unwrap();
            assert_eq!(ss_key.as_bytes(), &raw_key);
            let hash = blake3::hash(&raw_key);
            let expected_hash = &hash.as_bytes()[..16];
            assert_eq!(ss_key.identity_hash(), expected_hash);

            let context = Arc::new(Context::new(shadowsocks::config::ServerType::Server));
            let uuid = "c26f63be-5c1a-4d2b-923c-74a49c638e4a";
            let expected_psk = &uuid.as_bytes()[..method.key_len()];
            assert_eq!(decode_key(uuid, method).unwrap(), expected_psk);
            let cred = Credential::new(
                User {
                    uuid: uuid.to_string(),
                    ..Default::default()
                },
                method,
                context.clone(),
            )
            .unwrap();
            assert_eq!(&cred.key, expected_psk);

            let colon_key = format!("dummy_server_key:{}", uuid);
            assert_eq!(decode_key(&colon_key, method).unwrap(), expected_psk);

            let wrong_len_raw = vec![0x37u8; method.key_len() + 1];
            let wrong_len_b64 = base64::engine::general_purpose::STANDARD.encode(&wrong_len_raw);
            assert!(decode_key(&wrong_len_b64, method).is_err());

            let wrong_short_raw = vec![0x37u8; method.key_len() - 1];
            let wrong_short_b64 =
                base64::engine::general_purpose::STANDARD.encode(&wrong_short_raw);
            assert!(decode_key(&wrong_short_b64, method).is_err());
        }
    }

    #[test]
    fn test_ss2022_cryptographic_primitives_deterministic() {
        let psk16 = [0x42u8; 16];
        let psk32 = [0x24u8; 32];
        let salt16 = [0x11u8; 16];
        let salt32 = [0x99u8; 32];

        let subkey16 = derive_session_subkey(&psk16, &salt16, 16);
        assert_eq!(subkey16.len(), 16);
        let mut hasher16 = blake3::Hasher::new_derive_key(SS2022_SESSION_SUBKEY_CONTEXT);
        hasher16.update(&psk16);
        hasher16.update(&salt16);
        let mut expected_subkey16 = [0u8; 16];
        hasher16.finalize_xof().fill(&mut expected_subkey16);
        assert_eq!(subkey16.as_slice(), &expected_subkey16);

        let subkey32 = derive_session_subkey(&psk32, &salt32, 32);
        assert_eq!(subkey32.len(), 32);
        let mut hasher32 = blake3::Hasher::new_derive_key(SS2022_SESSION_SUBKEY_CONTEXT);
        hasher32.update(&psk32);
        hasher32.update(&salt32);
        let mut expected_subkey32 = [0u8; 32];
        hasher32.finalize_xof().fill(&mut expected_subkey32);
        assert_eq!(subkey32.as_slice(), &expected_subkey32);

        let id_subkey = derive_identity_subkey(&psk16, &salt16);
        let expected_id_subkey = blake3::derive_key(
            SS2022_IDENTITY_SUBKEY_CONTEXT,
            &[&psk16[..], &salt16[..]].concat(),
        );
        assert_eq!(id_subkey, expected_id_subkey);

        let mut block = [0x55u8; 16];
        let orig_block = block;
        aes_block_encrypt(CipherKind::AEAD2022_BLAKE3_AES_128_GCM, &psk16, &mut block);
        assert_ne!(block, orig_block);
        aes_block_decrypt(CipherKind::AEAD2022_BLAKE3_AES_128_GCM, &psk16, &mut block);
        assert_eq!(block, orig_block);

        aes_block_encrypt(CipherKind::AEAD2022_BLAKE3_AES_256_GCM, &psk32, &mut block);
        assert_ne!(block, orig_block);
        aes_block_decrypt(CipherKind::AEAD2022_BLAKE3_AES_256_GCM, &psk32, &mut block);
        assert_eq!(block, orig_block);

        let mut nonce = Ss2022Nonce::new();
        assert_eq!(nonce.as_slice(), &[0u8; 12]);
        nonce.increment();
        assert_eq!(nonce.as_slice()[0], 1);
        for _ in 0..254 {
            nonce.increment();
        }
        assert_eq!(nonce.as_slice()[0], 255);
        assert_eq!(nonce.as_slice()[1], 0);
        nonce.increment();
        assert_eq!(nonce.as_slice()[0], 0);
        assert_eq!(nonce.as_slice()[1], 1);
    }

    #[tokio::test]
    async fn test_ss2022_all_ciphers_tcp_handshake_and_bidirectional_data() {
        use shadowsocks::config::ServerConfig;
        use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream;

        for name in [
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ] {
            let method: Method = name.parse().unwrap();
            let Method::Aead2022(cipher_kind) = method else {
                unreachable!()
            };
            let is_chacha = cipher_kind == CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305;
            let raw_user_key = vec![0x5au8; method.key_len()];
            let user_password = base64::engine::general_purpose::STANDARD.encode(&raw_user_key);
            let server_context = Arc::new(Context::new(shadowsocks::config::ServerType::Server));
            let client_context = Arc::new(Context::new(shadowsocks::config::ServerType::Local));

            let cred = Arc::new(
                Credential::new(
                    User {
                        id: 1,
                        password: Some(user_password.clone()),
                        ..Default::default()
                    },
                    method,
                    server_context.clone(),
                )
                .unwrap(),
            );
            let user_index = UserIndex::new(vec![cred.clone()]);
            let target_addr = Address::SocketAddress("1.1.1.1:80".parse().unwrap());

            let raw_server_key = vec![0x21u8; method.key_len()];

            {
                let (client_io, server_io) = tokio::io::duplex(65536);
                let svr_cfg = ServerConfig::new(
                    "127.0.0.1:8388".parse::<std::net::SocketAddr>().unwrap(),
                    &user_password,
                    cipher_kind,
                )
                .unwrap();
                let mut client_stream = ProxyClientStream::from_stream(
                    client_context.clone(),
                    client_io,
                    &svr_cfg,
                    target_addr.clone(),
                );

                let target_clone = target_addr.clone();
                let client_task = tokio::spawn(async move {
                    client_stream.write_all(b"ping-from-client").await.unwrap();
                    client_stream.flush().await.unwrap();
                    let mut resp = vec![0u8; 16];
                    client_stream.read_exact(&mut resp).await.unwrap();
                    assert_eq!(&resp, b"pong-from-server");
                });

                let (authed_cred, mut server_stream, parsed_addr) =
                    handshake(Box::new(server_io), method, None, &user_index)
                        .await
                        .unwrap();
                assert_eq!(authed_cred.user.id, 1);
                assert_eq!(parsed_addr, target_clone);

                let mut req = vec![0u8; 16];
                server_stream.read_exact(&mut req).await.unwrap();
                assert_eq!(&req, b"ping-from-client");

                server_stream.write_all(b"pong-from-server").await.unwrap();
                server_stream.flush().await.unwrap();

                client_task.await.unwrap();
            }

            if !is_chacha {
                let server_key_b64 =
                    base64::engine::general_purpose::STANDARD.encode(&raw_server_key);
                let eih_client_password = format!("{}:{}", server_key_b64, user_password);

                let (client_io, server_io) = tokio::io::duplex(65536);
                let svr_cfg = ServerConfig::new(
                    "127.0.0.1:8388".parse::<std::net::SocketAddr>().unwrap(),
                    &eih_client_password,
                    cipher_kind,
                )
                .unwrap();
                let mut client_stream = ProxyClientStream::from_stream(
                    client_context.clone(),
                    client_io,
                    &svr_cfg,
                    target_addr.clone(),
                );

                let target_clone = target_addr.clone();
                let client_task = tokio::spawn(async move {
                    client_stream.write_all(b"eih-ping-client!").await.unwrap();
                    client_stream.flush().await.unwrap();
                    let mut resp = vec![0u8; 16];
                    client_stream.read_exact(&mut resp).await.unwrap();
                    assert_eq!(&resp, b"eih-pong-server!");
                });

                let (authed_cred, mut server_stream, parsed_addr) = handshake(
                    Box::new(server_io),
                    method,
                    Some(&raw_server_key),
                    &user_index,
                )
                .await
                .unwrap();
                assert_eq!(authed_cred.user.id, 1);
                assert_eq!(parsed_addr, target_clone);

                let mut req = vec![0u8; 16];
                server_stream.read_exact(&mut req).await.unwrap();
                assert_eq!(&req, b"eih-ping-client!");

                server_stream.write_all(b"eih-pong-server!").await.unwrap();
                server_stream.flush().await.unwrap();

                client_task.await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn test_ss2022_xboard_panel_contract_handshake_and_bidirectional_data() {
        use shadowsocks::config::ServerConfig;
        use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream;

        let panel_user_uuid = "c748c8c7-4e92-4a5f-9f79-6b83f06b9b12";
        let server_context = Arc::new(Context::new(shadowsocks::config::ServerType::Server));
        let client_context = Arc::new(Context::new(shadowsocks::config::ServerType::Local));
        let target_addr = Address::SocketAddress("1.1.1.1:80".parse().unwrap());

        for name in [
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ] {
            let method: Method = name.parse().unwrap();
            let Method::Aead2022(cipher_kind) = method else {
                unreachable!()
            };
            let is_chacha = cipher_kind == CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305;
            let key_len = method.key_len();

            let server_cred = Arc::new(
                Credential::new(
                    User {
                        id: 33,
                        uuid: panel_user_uuid.to_string(),
                        password: None,
                        ..Default::default()
                    },
                    method,
                    server_context.clone(),
                )
                .expect("Failed to create credential from Xboard user UUID"),
            );
            let user_index = UserIndex::new(vec![server_cred.clone()]);

            let raw_server_key = vec![0x33u8; key_len];
            let server_key_b64 = base64::engine::general_purpose::STANDARD.encode(&raw_server_key);
            let server_key = if is_chacha {
                None
            } else {
                Some(decode_key(&server_key_b64, method).unwrap())
            };

            let client_user_key_b64 = base64::engine::general_purpose::STANDARD
                .encode(&panel_user_uuid.as_bytes()[..key_len]);
            let client_password = if is_chacha {
                client_user_key_b64
            } else {
                format!("{}:{}", server_key_b64, client_user_key_b64)
            };

            let (client_io, server_io) = tokio::io::duplex(65536);
            let svr_cfg = ServerConfig::new(
                "127.0.0.1:8388".parse::<std::net::SocketAddr>().unwrap(),
                &client_password,
                cipher_kind,
            )
            .unwrap();
            let mut client_stream = ProxyClientStream::from_stream(
                client_context.clone(),
                client_io,
                &svr_cfg,
                target_addr.clone(),
            );

            let target_clone = target_addr.clone();
            let client_task = tokio::spawn(async move {
                client_stream.write_all(b"xboard-node33-ok").await.unwrap();
                client_stream.flush().await.unwrap();
                let mut resp = vec![0u8; 16];
                client_stream.read_exact(&mut resp).await.unwrap();
                assert_eq!(&resp, b"elise-node33-ack");
            });

            let (authed_cred, mut server_stream, parsed_addr) = handshake(
                Box::new(server_io),
                method,
                server_key.as_deref(),
                &user_index,
            )
            .await
            .expect("SS2022 handshake failed with Xboard client subscription!");

            assert_eq!(authed_cred.user.id, 33);
            assert_eq!(parsed_addr, target_clone);

            let mut req = vec![0u8; 16];
            server_stream.read_exact(&mut req).await.unwrap();
            assert_eq!(&req, b"xboard-node33-ok");

            server_stream.write_all(b"elise-node33-ack").await.unwrap();
            server_stream.flush().await.unwrap();

            client_task.await.unwrap();
        }

        {
            let method: Method = "2022-blake3-chacha20-poly1305".parse().unwrap();
            let Method::Aead2022(cipher_kind) = method else {
                unreachable!()
            };
            let user_key = panel_user_uuid.as_bytes()[..32].to_vec();
            let raw_server_key = vec![0x33u8; 32];

            let server_cred = Arc::new(
                Credential::new(
                    User {
                        id: 33,
                        uuid: panel_user_uuid.to_string(),
                        password: None,
                        ..Default::default()
                    },
                    method,
                    server_context.clone(),
                )
                .unwrap(),
            );
            let user_index = UserIndex::new(vec![server_cred.clone()]);

            for with_server_key in [true, false] {
                let (mut client_io, server_io) = tokio::io::duplex(65536);
                let salt = if with_server_key {
                    [0x42u8; 32]
                } else {
                    [0x43u8; 32]
                };
                let mut client_cipher = TcpCipher::new(cipher_kind, &user_key, &salt);

                let id_subkey = derive_identity_subkey(&raw_server_key, &salt);
                let mut eih = server_cred.identity_hash;
                aes_block_encrypt(cipher_kind, &id_subkey, &mut eih);

                let mut var_body = Vec::new();
                target_addr.write_to_buf(&mut var_body);
                var_body.extend_from_slice(&0u16.to_be_bytes());
                var_body.extend_from_slice(b"chacha-eih-req");
                let var_len = var_body.len();

                let mut var_packet = var_body;
                var_packet.resize(var_len + 16, 0);

                let mut fixed_header = [0u8; 27];
                fixed_header[0] = 0;
                fixed_header[1..9].copy_from_slice(&now().unwrap().to_be_bytes());
                fixed_header[9..11].copy_from_slice(&(var_len as u16).to_be_bytes());
                client_cipher.encrypt_packet(&mut fixed_header);
                client_cipher.encrypt_packet(&mut var_packet);

                tokio::spawn(async move {
                    client_io.write_all(&salt).await.unwrap();
                    client_io.write_all(&eih).await.unwrap();
                    client_io.write_all(&fixed_header).await.unwrap();
                    client_io.write_all(&var_packet).await.unwrap();
                    client_io.flush().await.unwrap();

                    let mut resp_buf = vec![0u8; 27 + (2 + 16) + (14 + 16)];
                    client_io.read_exact(&mut resp_buf).await.unwrap();
                });

                let (authed_cred, mut server_stream, parsed_addr) = handshake(
                    Box::new(server_io),
                    method,
                    if with_server_key {
                        Some(raw_server_key.as_slice())
                    } else {
                        None
                    },
                    &user_index,
                )
                .await
                .expect("Handshake failed in ChaCha20 dual-offset test");

                assert_eq!(authed_cred.user.id, 33);
                assert_eq!(parsed_addr, target_addr);

                let mut req = vec![0u8; 14];
                server_stream.read_exact(&mut req).await.unwrap();
                assert_eq!(&req, b"chacha-eih-req");

                server_stream.write_all(b"chacha-eih-ack").await.unwrap();
                server_stream.flush().await.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn test_ss2022_chacha20_single_user_tcp_http_1mb_and_half_close() {
        use shadowsocks::config::ServerConfig;
        use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream;

        let method: Method = "2022-blake3-chacha20-poly1305".parse().unwrap();
        let Method::Aead2022(cipher_kind) = method else {
            unreachable!()
        };

        let mut raw_psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw_psk);
        let psk_b64 = base64::engine::general_purpose::STANDARD.encode(raw_psk);

        let server_context = Arc::new(Context::new(shadowsocks::config::ServerType::Server));
        let client_context = Arc::new(Context::new(shadowsocks::config::ServerType::Local));
        let target_addr = Address::SocketAddress("127.0.0.1:8080".parse().unwrap());

        let cred = Arc::new(
            Credential::new(
                User {
                    id: 1,
                    password: Some(psk_b64.clone()),
                    ..Default::default()
                },
                method,
                server_context.clone(),
            )
            .unwrap(),
        );
        let user_index = UserIndex::new(vec![cred.clone()]);

        let (client_io, server_io) = tokio::io::duplex(2 * 1024 * 1024);
        let svr_cfg = ServerConfig::new(
            "127.0.0.1:8388".parse::<std::net::SocketAddr>().unwrap(),
            &psk_b64,
            cipher_kind,
        )
        .unwrap();

        let mut client_stream = ProxyClientStream::from_stream(
            client_context.clone(),
            client_io,
            &svr_cfg,
            target_addr.clone(),
        );

        let client_payload = vec![0x42u8; 1024 * 1024];
        let client_payload_clone = client_payload.clone();

        let client_task = tokio::spawn(async move {
            client_stream
                .write_all(b"GET /large HTTP/1.1\r\nHost: example.com\r\n\r\n")
                .await
                .unwrap();
            client_stream
                .write_all(&client_payload_clone)
                .await
                .unwrap();
            client_stream.flush().await.unwrap();

            client_stream.shutdown().await.unwrap();

            let mut response = Vec::new();
            client_stream.read_to_end(&mut response).await.unwrap();
            response
        });

        let (authed_cred, mut server_stream, parsed_addr) =
            handshake(Box::new(server_io), method, None, &user_index)
                .await
                .expect("SS2022 ChaCha20 single-user handshake failed!");

        assert_eq!(authed_cred.user.id, 1);
        assert_eq!(parsed_addr, target_addr);

        let mut request_data = Vec::new();
        server_stream.read_to_end(&mut request_data).await.unwrap();

        let expected_header = b"GET /large HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert_eq!(&request_data[..expected_header.len()], expected_header);
        assert_eq!(&request_data[expected_header.len()..], &client_payload[..]);

        let server_payload = vec![0x77u8; 1024 * 1024];
        server_stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n")
            .await
            .unwrap();
        server_stream.write_all(&server_payload).await.unwrap();
        server_stream.flush().await.unwrap();
        server_stream.shutdown().await.unwrap();

        let client_received = client_task.await.unwrap();
        let expected_resp_header = b"HTTP/1.1 200 OK\r\nContent-Length: 1048576\r\n\r\n";
        assert_eq!(
            &client_received[..expected_resp_header.len()],
            expected_resp_header
        );
        assert_eq!(
            &client_received[expected_resp_header.len()..],
            &server_payload[..]
        );
    }

    #[test]
    fn test_ss2022_all_ciphers_udp_roundtrip() {
        for name in [
            "2022-blake3-aes-128-gcm",
            "2022-blake3-aes-256-gcm",
            "2022-blake3-chacha20-poly1305",
        ] {
            let method: Method = name.parse().unwrap();
            let Method::Aead2022(cipher_kind) = method else {
                unreachable!()
            };
            let is_chacha = cipher_kind == CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305;
            let raw_user_key = vec![0x77u8; method.key_len()];
            let user_password = base64::engine::general_purpose::STANDARD.encode(&raw_user_key);
            let context = Arc::new(Context::new(shadowsocks::config::ServerType::Server));

            let cred = Arc::new(
                Credential::new(
                    User {
                        id: 42,
                        password: Some(user_password),
                        ..Default::default()
                    },
                    method,
                    context,
                )
                .unwrap(),
            );
            let user_index = UserIndex::new(vec![cred.clone()]);
            let target_addr = Address::SocketAddress("8.8.8.8:53".parse().unwrap());
            let client_payload = b"test-udp-payload-12345";
            let raw_server_key = vec![0x88u8; method.key_len()];

            let client_session: u64 = 0x1122334455667788;
            let client_packet_id: u64 = 0x01;
            let mut wire = Vec::new();

            if is_chacha {
                let nonce = [0x55u8; 24];
                wire.extend_from_slice(&nonce);
                let mut body = Vec::new();
                body.extend_from_slice(&client_session.to_be_bytes());
                body.extend_from_slice(&client_packet_id.to_be_bytes());
                body.push(0u8);
                body.extend_from_slice(&now().unwrap().to_be_bytes());
                body.extend_from_slice(&0u16.to_be_bytes());
                target_addr.write_to_buf(&mut body);
                body.extend_from_slice(client_payload);
                body.resize(body.len() + 16, 0);

                let cipher = UdpCipher::new(cipher_kind, &cred.key, 0);
                cipher.encrypt_packet(&nonce, &mut body);
                wire.extend_from_slice(&body);
            } else {
                let mut header = [0u8; 16];
                header[..8].copy_from_slice(&client_session.to_be_bytes());
                header[8..16].copy_from_slice(&client_packet_id.to_be_bytes());

                let mut body = Vec::new();
                body.push(0u8);
                body.extend_from_slice(&now().unwrap().to_be_bytes());
                body.extend_from_slice(&0u16.to_be_bytes());
                target_addr.write_to_buf(&mut body);
                body.extend_from_slice(client_payload);
                body.resize(body.len() + 16, 0);

                let cipher = UdpCipher::new(cipher_kind, &cred.key, client_session);
                cipher.encrypt_packet(&header[4..16], &mut body);
                aes_block(cipher_kind, &cred.key, &mut header, true);

                wire.extend_from_slice(&header);
                wire.extend_from_slice(&body);
            }

            let dg = decrypt_udp(method, None, &user_index, &wire).unwrap();
            assert_eq!(dg.credential.user.id, 42);
            assert_eq!(dg.address, target_addr);
            assert_eq!(dg.payload, client_payload);
            assert_eq!(dg.session_id, client_session);
            assert_eq!(dg.packet_id, client_packet_id);

            if !is_chacha {
                assert!(
                    decrypt_udp(method, Some(raw_server_key.as_slice()), &user_index, &wire)
                        .is_err()
                );

                let mut eih_wire = Vec::new();
                let mut header = [0u8; 16];
                header[..8].copy_from_slice(&client_session.to_be_bytes());
                header[8..16].copy_from_slice(&client_packet_id.to_be_bytes());

                let mut eih = [0u8; 16];
                let id_hash = blake3::hash(&cred.key);
                eih.copy_from_slice(&id_hash.as_bytes()[..16]);
                for i in 0..16 {
                    eih[i] ^= header[i];
                }

                let mut body = Vec::new();
                body.push(0u8);
                body.extend_from_slice(&now().unwrap().to_be_bytes());
                body.extend_from_slice(&0u16.to_be_bytes());
                target_addr.write_to_buf(&mut body);
                body.extend_from_slice(client_payload);
                body.resize(body.len() + 16, 0);

                let cipher = UdpCipher::new(cipher_kind, &cred.key, client_session);
                cipher.encrypt_packet(&header[4..16], &mut body);
                aes_block(cipher_kind, &raw_server_key, &mut header, true);
                aes_block(cipher_kind, &raw_server_key, &mut eih, true);

                eih_wire.extend_from_slice(&header);
                eih_wire.extend_from_slice(&eih);
                eih_wire.extend_from_slice(&body);

                let eih_dg = decrypt_udp(
                    method,
                    Some(raw_server_key.as_slice()),
                    &user_index,
                    &eih_wire,
                )
                .unwrap();
                assert_eq!(eih_dg.credential.user.id, 42);
                assert_eq!(eih_dg.address, target_addr);
                assert_eq!(eih_dg.payload, client_payload);
                assert_eq!(eih_dg.session_id, client_session);
                assert_eq!(eih_dg.packet_id, client_packet_id);
            }

            let server_session: u64 = 0x9988776655443322;
            let server_packet_id: u64 = 0x01;
            let server_payload = b"test-udp-response-hello";
            let resp_wire = encrypt_udp(
                method,
                &cred,
                &target_addr,
                client_session,
                server_session,
                server_packet_id,
                server_payload,
            )
            .unwrap();

            if is_chacha {
                let mut resp_data = resp_wire[24..].to_vec();
                let cipher = UdpCipher::new(cipher_kind, &cred.key, 0);
                assert!(cipher.decrypt_packet(&resp_wire[..24], &mut resp_data));
                assert_eq!(
                    u64::from_be_bytes(resp_data[..8].try_into().unwrap()),
                    server_session
                );
                assert_eq!(
                    u64::from_be_bytes(resp_data[8..16].try_into().unwrap()),
                    server_packet_id
                );
                assert_eq!(resp_data[16], 1);
                assert_eq!(
                    u64::from_be_bytes(resp_data[25..33].try_into().unwrap()),
                    client_session
                );
            } else {
                let mut header = [0u8; 16];
                header.copy_from_slice(&resp_wire[..16]);
                aes_block(cipher_kind, &cred.key, &mut header, false);
                assert_eq!(
                    u64::from_be_bytes(header[..8].try_into().unwrap()),
                    server_session
                );
                assert_eq!(
                    u64::from_be_bytes(header[8..16].try_into().unwrap()),
                    server_packet_id
                );

                let mut message = resp_wire[16..].to_vec();
                let cipher = UdpCipher::new(cipher_kind, &cred.key, server_session);
                assert!(cipher.decrypt_packet(&header[4..16], &mut message));
                assert_eq!(message[0], 1);
                assert_eq!(
                    u64::from_be_bytes(message[9..17].try_into().unwrap()),
                    client_session
                );
            }
        }
    }

    #[tokio::test]
    async fn test_ss2022_chacha20_shadowsocks_rust_udp_bidirectional_roundtrip() {
        use shadowsocks::relay::udprelay::crypto_io::{
            decrypt_server_payload, encrypt_client_payload,
        };
        use shadowsocks::relay::udprelay::options::UdpSocketControlData;

        let method: Method = "2022-blake3-chacha20-poly1305".parse().unwrap();
        let Method::Aead2022(cipher_kind) = method else {
            unreachable!()
        };

        let mut raw_psk = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut raw_psk);
        let psk_b64 = base64::engine::general_purpose::STANDARD.encode(raw_psk);

        let server_context = Arc::new(Context::new(shadowsocks::config::ServerType::Server));
        let client_context = Arc::new(Context::new(shadowsocks::config::ServerType::Local));

        let cred = Arc::new(
            Credential::new(
                User {
                    id: 1,
                    password: Some(psk_b64),
                    ..Default::default()
                },
                method,
                server_context.clone(),
            )
            .unwrap(),
        );
        let user_index = UserIndex::new(vec![cred.clone()]);
        let target_addr = Address::SocketAddress("1.1.1.1:53".parse().unwrap());
        let client_payload = b"DNS query payload for test";

        let client_session: u64 = 0x1122334455667788;
        let client_packet_id: u64 = 0x01;
        let mut control = UdpSocketControlData::default();
        control.client_session_id = client_session;
        control.packet_id = client_packet_id;

        let mut client_wire = bytes::BytesMut::new();
        encrypt_client_payload(
            &client_context,
            cipher_kind,
            &raw_psk,
            &target_addr,
            &control,
            &[],
            client_payload,
            &mut client_wire,
        );

        let decrypted = decrypt_udp(method, None, &user_index, &client_wire)
            .expect("Elise failed to decrypt shadowsocks-rust ChaCha20 UDP packet");
        assert_eq!(decrypted.credential.user.id, 1);
        assert_eq!(decrypted.address, target_addr);
        assert_eq!(decrypted.payload, client_payload);
        assert_eq!(decrypted.session_id, client_session);
        assert_eq!(decrypted.packet_id, client_packet_id);

        let server_session: u64 = 0x9988776655443322;
        let server_packet_id: u64 = 0x02;
        let server_payload = b"DNS response payload from 1.1.1.1";
        let server_wire = encrypt_udp(
            method,
            &cred,
            &target_addr,
            client_session,
            server_session,
            server_packet_id,
            server_payload,
        )
        .expect("Elise failed to encrypt ChaCha20 UDP response");

        let mut client_recv_buf = server_wire;
        let (recv_len, resp_addr, resp_control) =
            decrypt_server_payload(&client_context, cipher_kind, &raw_psk, &mut client_recv_buf)
                .expect("shadowsocks-rust failed to decrypt Elise ChaCha20 UDP response");

        assert_eq!(recv_len, server_payload.len());
        assert_eq!(&client_recv_buf[..recv_len], server_payload);
        assert_eq!(resp_addr, target_addr);
        let resp_control = resp_control.expect("Missing resp_control");
        assert_eq!(resp_control.client_session_id, client_session);
        assert_eq!(resp_control.server_session_id, server_session);
        assert_eq!(resp_control.packet_id, server_packet_id);
    }

    #[tokio::test]
    async fn test_ss2022_chacha20_tcp_single_user_and_eih_handshake() {
        let method: Method = "2022-blake3-chacha20-poly1305".parse().unwrap();
        let Method::Aead2022(cipher_kind) = method else {
            unreachable!()
        };

        let server_context = Arc::new(Context::new(shadowsocks::config::ServerType::Server));
        let user_psk = b"01234567890123456789012345678901";
        let user_psk_b64 = base64::engine::general_purpose::STANDARD.encode(user_psk);

        let cred = Arc::new(
            Credential::new(
                User {
                    id: 42,
                    password: Some(user_psk_b64),
                    ..Default::default()
                },
                method,
                server_context.clone(),
            )
            .unwrap(),
        );
        let user_index = UserIndex::new(vec![cred.clone()]);
        let server_key = b"abcdefghijklmnopqrstuvwxyz123456";

        let target_addr = Address::DomainNameAddress("example.com".to_string(), 443);
        let test_payload = b"Hello, SS2022 ChaCha20!";

        {
            let (mut client_stream, server_stream) = tokio::io::duplex(4096);
            let salt = [0x5au8; 32];
            let mut client_cipher = TcpCipher::new(cipher_kind, user_psk, &salt);

            let mut var_body = Vec::new();
            target_addr.write_to_buf(&mut var_body);
            var_body.extend_from_slice(&0u16.to_be_bytes());
            var_body.extend_from_slice(test_payload);
            let var_len = var_body.len();

            let mut var_packet = var_body;
            var_packet.resize(var_len + 16, 0);

            let mut fixed_header = [0u8; 27];
            fixed_header[0] = 0;
            fixed_header[1..9].copy_from_slice(&now().unwrap().to_be_bytes());
            fixed_header[9..11].copy_from_slice(&(var_len as u16).to_be_bytes());
            client_cipher.encrypt_packet(&mut fixed_header);
            client_cipher.encrypt_packet(&mut var_packet);

            tokio::spawn(async move {
                tokio::io::AsyncWriteExt::write_all(&mut client_stream, &salt)
                    .await
                    .unwrap();
                tokio::io::AsyncWriteExt::write_all(&mut client_stream, &fixed_header)
                    .await
                    .unwrap();
                tokio::io::AsyncWriteExt::write_all(&mut client_stream, &var_packet)
                    .await
                    .unwrap();
            });

            let (authed_cred, _ss_stream, address) =
                handshake(Box::new(server_stream), method, None, &user_index)
                    .await
                    .expect("Handshake failed in single-user mode");

            assert_eq!(authed_cred.user.id, 42);
            assert_eq!(address, target_addr);
        }

        {
            let (mut client_stream, server_stream) = tokio::io::duplex(4096);
            let salt = [0x7bu8; 32];
            let mut client_cipher = TcpCipher::new(cipher_kind, user_psk, &salt);

            let id_subkey = derive_identity_subkey(server_key, &salt);
            let mut eih = cred.identity_hash;
            aes_block_encrypt(cipher_kind, &id_subkey, &mut eih);

            let mut var_body = Vec::new();
            target_addr.write_to_buf(&mut var_body);
            var_body.extend_from_slice(&0u16.to_be_bytes());
            var_body.extend_from_slice(test_payload);
            let var_len = var_body.len();

            let mut var_packet = var_body;
            var_packet.resize(var_len + 16, 0);

            let mut fixed_header = [0u8; 27];
            fixed_header[0] = 0;
            fixed_header[1..9].copy_from_slice(&now().unwrap().to_be_bytes());
            fixed_header[9..11].copy_from_slice(&(var_len as u16).to_be_bytes());
            client_cipher.encrypt_packet(&mut fixed_header);
            client_cipher.encrypt_packet(&mut var_packet);

            tokio::spawn(async move {
                tokio::io::AsyncWriteExt::write_all(&mut client_stream, &salt)
                    .await
                    .unwrap();
                tokio::io::AsyncWriteExt::write_all(&mut client_stream, &eih)
                    .await
                    .unwrap();
                tokio::io::AsyncWriteExt::write_all(&mut client_stream, &fixed_header)
                    .await
                    .unwrap();
                tokio::io::AsyncWriteExt::write_all(&mut client_stream, &var_packet)
                    .await
                    .unwrap();
            });

            let (authed_cred, _ss_stream, address) = handshake(
                Box::new(server_stream),
                method,
                Some(server_key),
                &user_index,
            )
            .await
            .expect("Handshake failed in EIH mode");

            assert_eq!(authed_cred.user.id, 42);
            assert_eq!(address, target_addr);
        }
    }
}
