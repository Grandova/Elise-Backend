use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, Nonce as GcmNonce, Tag as GcmTag};
use chacha20poly1305::ChaCha20Poly1305;
use md5::{Digest as Md5Digest, Md5};
use sha2::{Digest as Sha256Digest, Sha256};
use std::collections::HashMap;
use std::io::{self, Error, ErrorKind};
use std::sync::Mutex;
use uuid::Uuid;

pub const VMESS_VERSION: u8 = 1;
pub const SECURITY_AES_128_GCM: u8 = 3;
pub const SECURITY_CHACHA20_POLY1305: u8 = 4;
pub const SECURITY_NONE: u8 = 5;

pub const CMD_TCP: u8 = 1;
pub const CMD_UDP: u8 = 2;
pub const CMD_MUX: u8 = 3;

pub const OPTION_CHUNK_STREAM: u8 = 0x01;
pub const OPTION_CHUNK_MASKING: u8 = 0x04;
pub const OPTION_GLOBAL_PADDING: u8 = 0x08;
pub const OPTION_AUTH_LENGTH: u8 = 0x10;

const KDF_SALT_AUTH_ID_ENCRYPTION_KEY: &[u8] = b"AES Auth ID Encryption";
const KDF_SALT_AEAD_RESP_HEADER_LEN_KEY: &[u8] = b"AEAD Resp Header Len Key";
const KDF_SALT_AEAD_RESP_HEADER_LEN_IV: &[u8] = b"AEAD Resp Header Len IV";
const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";
const KDF_SALT_VMESS_AEAD_KDF: &[u8] = b"VMess AEAD KDF";
const KDF_SALT_HEADER_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
const KDF_SALT_HEADER_PAYLOAD_IV: &[u8] = b"VMess Header AEAD Nonce";
const KDF_SALT_HEADER_PAYLOAD_LEN_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const KDF_SALT_HEADER_PAYLOAD_LEN_IV: &[u8] = b"VMess Header AEAD Nonce_Length";

pub fn crc32_ieee(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            let mask = -((crc & 1) as i32) as u32;
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

pub fn fnv1a_32(data: &[u8]) -> u32 {
    let mut hash: u32 = 0x811c_9dc5;
    for &b in data {
        hash ^= b as u32;
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

pub trait VmessHash: Send {
    fn update(&mut self, data: &[u8]);
    fn finalize(self: Box<Self>) -> Vec<u8>;
    fn block_size(&self) -> usize;
    fn clone_box(&self) -> Box<dyn VmessHash>;
}

struct Sha256Hash(Sha256);

impl VmessHash for Sha256Hash {
    fn update(&mut self, data: &[u8]) {
        Sha256Digest::update(&mut self.0, data);
    }
    fn finalize(self: Box<Self>) -> Vec<u8> {
        self.0.finalize().to_vec()
    }
    fn block_size(&self) -> usize {
        64
    }
    fn clone_box(&self) -> Box<dyn VmessHash> {
        Box::new(Sha256Hash(self.0.clone()))
    }
}

type HashCreator = std::sync::Arc<dyn Fn() -> Box<dyn VmessHash> + Send + Sync>;

struct NestedHmac {
    parent_create: HashCreator,
    inner: Box<dyn VmessHash>,
    outer_key_pad: Vec<u8>,
    block_size: usize,
}

impl NestedHmac {
    fn new(parent_create: HashCreator, key: &[u8]) -> Self {
        let sample = parent_create();
        let b = sample.block_size();
        let mut actual_key = if key.len() > b {
            let mut h = parent_create();
            h.update(key);
            h.finalize()
        } else {
            key.to_vec()
        };
        if actual_key.len() < b {
            actual_key.resize(b, 0);
        }

        let mut ipad = vec![0x36u8; b];
        let mut opad = vec![0x5cu8; b];
        for i in 0..b {
            ipad[i] ^= actual_key[i];
            opad[i] ^= actual_key[i];
        }

        let mut inner = parent_create();
        inner.update(&ipad);

        Self {
            parent_create,
            inner,
            outer_key_pad: opad,
            block_size: b,
        }
    }
}

impl VmessHash for NestedHmac {
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }
    fn finalize(self: Box<Self>) -> Vec<u8> {
        let inner_res = self.inner.finalize();
        let mut outer = (self.parent_create)();
        outer.update(&self.outer_key_pad);
        outer.update(&inner_res);
        outer.finalize()
    }
    fn block_size(&self) -> usize {
        self.block_size
    }
    fn clone_box(&self) -> Box<dyn VmessHash> {
        Box::new(Self {
            parent_create: self.parent_create.clone(),
            inner: self.inner.clone_box(),
            outer_key_pad: self.outer_key_pad.clone(),
            block_size: self.block_size,
        })
    }
}

#[derive(Clone)]
enum CreatorNode {
    Root(Vec<u8>),
    Child {
        parent: Box<CreatorNode>,
        value: Vec<u8>,
    },
}

impl CreatorNode {
    fn create(&self) -> Box<dyn VmessHash> {
        match self {
            CreatorNode::Root(value) => {
                let v = value.clone();
                let parent_ctor: HashCreator =
                    std::sync::Arc::new(|| Box::new(Sha256Hash(Sha256::new())));
                Box::new(NestedHmac::new(parent_ctor, &v))
            }
            CreatorNode::Child { parent, value } => {
                let p = parent.clone();
                let parent_ctor: HashCreator = std::sync::Arc::new(move || p.create());
                Box::new(NestedHmac::new(parent_ctor, value))
            }
        }
    }
}

pub fn vmess_kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    let mut node = CreatorNode::Root(KDF_SALT_VMESS_AEAD_KDF.to_vec());
    for &p in path {
        node = CreatorNode::Child {
            parent: Box::new(node),
            value: p.to_vec(),
        };
    }
    let mut h = node.create();
    h.update(key);
    let res = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&res);
    out
}

pub fn derive_cmd_key(uuid_bytes: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, uuid_bytes);
    Md5Digest::update(&mut hasher, b"c48619fe-8f02-49e0-b9e9-edf763e17e21");
    let res = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&res);
    out
}

pub fn generate_chacha20_poly1305_key(key: &[u8]) -> [u8; 32] {
    let mut key32 = [0u8; 32];
    let mut h1 = Md5::new();
    Md5Digest::update(&mut h1, key);
    let d1 = h1.finalize();
    key32[..16].copy_from_slice(&d1);
    let mut h2 = Md5::new();
    Md5Digest::update(&mut h2, d1);
    key32[16..].copy_from_slice(&h2.finalize());
    key32
}

pub struct Shake128 {
    state: [u64; 25],
    byte_index: usize,
}

const KECCAK_ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const SHAKE128_RATE: usize = 168;

impl Shake128 {
    pub fn new(nonce: &[u8]) -> Self {
        let mut s = Self {
            state: [0u64; 25],
            byte_index: 0,
        };

        for &b in nonce {
            s.absorb_byte(b);
        }

        s.absorb_byte(0x1f);
        let last_byte = SHAKE128_RATE - 1;
        if s.byte_index == last_byte {
            s.absorb_byte(0x80);
        } else {
            while s.byte_index != last_byte {
                s.absorb_byte(0x00);
            }
            s.absorb_byte(0x80);
        }

        s.byte_index = 0;
        s
    }

    fn absorb_byte(&mut self, b: u8) {
        let lane = self.byte_index / 8;
        let shift = (self.byte_index % 8) * 8;
        self.state[lane] ^= (b as u64) << shift;
        self.byte_index += 1;
        if self.byte_index == SHAKE128_RATE {
            self.permute();
            self.byte_index = 0;
        }
    }

    #[allow(clippy::needless_range_loop)]
    fn permute(&mut self) {
        for &round_constant in &KECCAK_ROUND_CONSTANTS {
            let mut c = [0u64; 5];
            for x in 0..5 {
                c[x] = self.state[x]
                    ^ self.state[x + 5]
                    ^ self.state[x + 10]
                    ^ self.state[x + 15]
                    ^ self.state[x + 20];
            }
            for x in 0..5 {
                let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
                for y in 0..5 {
                    self.state[x + y * 5] ^= d;
                }
            }

            let mut current = self.state[1];
            let mut x = 1;
            let mut y = 0;
            for t in 0..24 {
                let r = ((t + 1) * (t + 2) / 2) % 64;
                let next_x = y;
                let next_y = (2 * x + 3 * y) % 5;
                let temp = self.state[next_x + next_y * 5];
                self.state[next_x + next_y * 5] = current.rotate_left(r as u32);
                current = temp;
                x = next_x;
                y = next_y;
            }

            for y_step in 0..5 {
                let base = y_step * 5;
                let mut row = [0u64; 5];
                row.copy_from_slice(&self.state[base..base + 5]);
                for x_step in 0..5 {
                    self.state[base + x_step] =
                        row[x_step] ^ ((!row[(x_step + 1) % 5]) & row[(x_step + 2) % 5]);
                }
            }

            self.state[0] ^= round_constant;
        }
    }

    pub fn read(&mut self, out: &mut [u8]) {
        for b in out.iter_mut() {
            if self.byte_index == SHAKE128_RATE {
                self.permute();
                self.byte_index = 0;
            }
            let lane = self.byte_index / 8;
            let shift = (self.byte_index % 8) * 8;
            *b = (self.state[lane] >> shift) as u8;
            self.byte_index += 1;
        }
    }

    pub fn next_u16(&mut self) -> u16 {
        let mut buf = [0u8; 2];
        self.read(&mut buf);
        u16::from_be_bytes(buf)
    }
}

pub struct AuthIdReplayFilter {
    records: Mutex<HashMap<[u8; 16], i64>>,
}

impl AuthIdReplayFilter {
    pub fn new() -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
        }
    }

    pub fn check_and_insert(&self, auth_id: &[u8; 16], now_sec: i64) -> bool {
        let mut map = self.records.lock().unwrap();

        map.retain(|_, &mut ts| (now_sec - ts).abs() <= 120);

        if map.contains_key(auth_id) {
            return false;
        }
        map.insert(*auth_id, now_sec);
        true
    }
}

impl Default for AuthIdReplayFilter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct VmessUserKeys {
    pub cmd_key: [u8; 16],
    pub auth_id_cipher: Aes128,
    pub replay_filter: AuthIdReplayFilter,
}

impl VmessUserKeys {
    pub fn new(uuid_str: &str) -> Option<Self> {
        let parsed = Uuid::parse_str(uuid_str).ok()?;
        let cmd_key = derive_cmd_key(parsed.as_bytes());
        let auth_id_key = &vmess_kdf(&cmd_key, &[KDF_SALT_AUTH_ID_ENCRYPTION_KEY])[..16];
        let auth_id_cipher = Aes128::new_from_slice(auth_id_key).ok()?;
        Some(Self {
            cmd_key,
            auth_id_cipher,
            replay_filter: AuthIdReplayFilter::new(),
        })
    }

    pub fn validate_auth_id(&self, auth_id: &[u8; 16], now_sec: i64) -> bool {
        let mut block = aes::Block::clone_from_slice(auth_id);
        self.auth_id_cipher.decrypt_block(&mut block);
        let decoded = block.as_slice();

        let timestamp = i64::from_be_bytes(decoded[0..8].try_into().unwrap());
        let expected_checksum = u32::from_be_bytes(decoded[12..16].try_into().unwrap());
        let actual_checksum = crc32_ieee(&decoded[0..12]);

        if expected_checksum != actual_checksum {
            return false;
        }

        if (timestamp - now_sec).abs() > 120 {
            return false;
        }

        self.replay_filter.check_and_insert(auth_id, now_sec)
    }
}

pub struct VmessRequestHeader {
    pub version: u8,
    pub request_body_key: [u8; 16],
    pub request_body_nonce: [u8; 16],
    pub response_header: u8,
    pub option: u8,
    pub security: u8,
    pub command: u8,
    pub target_port: u16,
    pub target_host: String,
    pub target_ip: Option<std::net::IpAddr>,
}

pub fn decrypt_vmess_header_length(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    connection_nonce: &[u8; 8],
    enc_len_block: &[u8; 18],
) -> io::Result<usize> {
    let len_key = &vmess_kdf(
        cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_LEN_KEY, auth_id, connection_nonce],
    )[..16];
    let len_iv = &vmess_kdf(
        cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_LEN_IV, auth_id, connection_nonce],
    )[..12];

    let cipher_len = Aes128Gcm::new_from_slice(len_key)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Cipher init failed"))?;
    let mut len_data = enc_len_block[..2].to_vec();
    let len_tag = GcmTag::from_slice(&enc_len_block[2..18]);
    cipher_len
        .decrypt_in_place_detached(
            GcmNonce::from_slice(len_iv),
            auth_id,
            &mut len_data,
            len_tag,
        )
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Header length decryption failed"))?;

    let header_len = u16::from_be_bytes([len_data[0], len_data[1]]) as usize;
    Ok(header_len)
}

pub fn decrypt_vmess_header(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    enc_len_block: &[u8; 18],
    connection_nonce: &[u8; 8],
    enc_header_payload: &[u8],
) -> io::Result<VmessRequestHeader> {
    let header_len =
        decrypt_vmess_header_length(cmd_key, auth_id, connection_nonce, enc_len_block)?;
    if enc_header_payload.len() < header_len + 16 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "Header payload too short",
        ));
    }

    let header_key = &vmess_kdf(
        cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_KEY, auth_id, connection_nonce],
    )[..16];
    let header_iv = &vmess_kdf(
        cmd_key,
        &[KDF_SALT_HEADER_PAYLOAD_IV, auth_id, connection_nonce],
    )[..12];

    let cipher_header = Aes128Gcm::new_from_slice(header_key)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Cipher init failed"))?;
    let mut header_data = enc_header_payload[..header_len].to_vec();
    let header_tag = GcmTag::from_slice(&enc_header_payload[header_len..header_len + 16]);
    cipher_header
        .decrypt_in_place_detached(
            GcmNonce::from_slice(header_iv),
            auth_id,
            &mut header_data,
            header_tag,
        )
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Header payload decryption failed"))?;

    if header_data.len() < 38 {
        return Err(Error::new(ErrorKind::InvalidData, "Header body too short"));
    }

    let version = header_data[0];
    if version != VMESS_VERSION {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "Unsupported VMess version",
        ));
    }

    let mut request_body_nonce = [0u8; 16];
    request_body_nonce.copy_from_slice(&header_data[1..17]);

    let mut request_body_key = [0u8; 16];
    request_body_key.copy_from_slice(&header_data[17..33]);

    let response_header = header_data[33];
    let option = header_data[34];
    let padding_len = (header_data[35] >> 4) as usize;
    let security = header_data[35] & 0x0F;
    let command = header_data[37];

    let mut cursor = 38;
    let (target_port, target_host, target_ip) = if command == CMD_MUX {
        (0, "v1.mux.cool".to_string(), None)
    } else {
        if header_data.len() < cursor + 3 {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Target address truncated",
            ));
        }
        let port = u16::from_be_bytes([header_data[cursor], header_data[cursor + 1]]);
        cursor += 2;

        let atyp = header_data[cursor];
        cursor += 1;

        let (host, ip) = match atyp {
            0x01 => {
                if header_data.len() < cursor + 4 {
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "IPv4 address truncated",
                    ));
                }
                let ip_addr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                    header_data[cursor],
                    header_data[cursor + 1],
                    header_data[cursor + 2],
                    header_data[cursor + 3],
                ));
                cursor += 4;
                (ip_addr.to_string(), Some(ip_addr))
            }
            0x02 => {
                if header_data.len() < cursor + 1 {
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "Domain length truncated",
                    ));
                }
                let domain_len = header_data[cursor] as usize;
                cursor += 1;
                if header_data.len() < cursor + domain_len {
                    return Err(Error::new(ErrorKind::UnexpectedEof, "Domain truncated"));
                }
                let domain =
                    String::from_utf8_lossy(&header_data[cursor..cursor + domain_len]).to_string();
                cursor += domain_len;
                (domain, None)
            }
            0x03 => {
                if header_data.len() < cursor + 16 {
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "IPv6 address truncated",
                    ));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&header_data[cursor..cursor + 16]);
                let ip_addr = std::net::IpAddr::V6(std::net::Ipv6Addr::from(octets));
                cursor += 16;
                (ip_addr.to_string(), Some(ip_addr))
            }
            _ => return Err(Error::new(ErrorKind::InvalidData, "Invalid ATYP in VMess")),
        };
        (port, host, ip)
    };

    if header_data.len() < cursor + padding_len + 4 {
        return Err(Error::new(
            ErrorKind::UnexpectedEof,
            "Padding or FNV1a truncated",
        ));
    }
    let data_to_check = &header_data[..cursor + padding_len];
    cursor += padding_len;

    let expected_fnv = u32::from_be_bytes(header_data[cursor..cursor + 4].try_into().unwrap());
    let actual_fnv = fnv1a_32(data_to_check);
    if expected_fnv != actual_fnv {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "VMess Header FNV-1a checksum mismatch",
        ));
    }

    Ok(VmessRequestHeader {
        version,
        request_body_key,
        request_body_nonce,
        response_header,
        option,
        security,
        command,
        target_port,
        target_host,
        target_ip,
    })
}

pub fn create_vmess_response_header(
    request_body_key: &[u8; 16],
    request_body_nonce: &[u8; 16],
    response_header_byte: u8,
    option: u8,
) -> io::Result<([u8; 38], [u8; 16], [u8; 16])> {
    let mut resp_key_hasher = Sha256::new();
    Sha256Digest::update(&mut resp_key_hasher, request_body_key);
    let resp_key_full = resp_key_hasher.finalize();
    let mut resp_key = [0u8; 16];
    resp_key.copy_from_slice(&resp_key_full[..16]);

    let mut resp_nonce_hasher = Sha256::new();
    Sha256Digest::update(&mut resp_nonce_hasher, request_body_nonce);
    let resp_nonce_full = resp_nonce_hasher.finalize();
    let mut resp_nonce = [0u8; 16];
    resp_nonce.copy_from_slice(&resp_nonce_full[..16]);

    let header_len_key = &vmess_kdf(&resp_key, &[KDF_SALT_AEAD_RESP_HEADER_LEN_KEY])[..16];
    let header_len_iv = &vmess_kdf(&resp_nonce, &[KDF_SALT_AEAD_RESP_HEADER_LEN_IV])[..12];
    let cipher_len = Aes128Gcm::new_from_slice(header_len_key)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Cipher init failed"))?;

    let mut len_data = 4u16.to_be_bytes().to_vec();
    let tag_len = cipher_len
        .encrypt_in_place_detached(GcmNonce::from_slice(header_len_iv), b"", &mut len_data)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Resp len encrypt failed"))?;

    let header_payload_key = &vmess_kdf(&resp_key, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_KEY])[..16];
    let header_payload_iv = &vmess_kdf(&resp_nonce, &[KDF_SALT_AEAD_RESP_HEADER_PAYLOAD_IV])[..12];
    let cipher_payload = Aes128Gcm::new_from_slice(header_payload_key)
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Cipher init failed"))?;

    let mut payload_data = vec![response_header_byte, option, 0x00, 0x00];
    let tag_payload = cipher_payload
        .encrypt_in_place_detached(
            GcmNonce::from_slice(header_payload_iv),
            b"",
            &mut payload_data,
        )
        .map_err(|_| Error::new(ErrorKind::InvalidData, "Resp payload encrypt failed"))?;

    let mut out = [0u8; 38];
    out[0..2].copy_from_slice(&len_data);
    out[2..18].copy_from_slice(tag_len.as_slice());
    out[18..22].copy_from_slice(&payload_data);
    out[22..38].copy_from_slice(tag_payload.as_slice());

    Ok((out, resp_key, resp_nonce))
}

#[allow(clippy::large_enum_variant)]
pub enum VmessCipher {
    AesGcm(Aes128Gcm),
    ChaCha20(ChaCha20Poly1305),
}

#[allow(clippy::large_enum_variant)]
pub enum ChunkLengthCodec {
    Authenticated {
        cipher: VmessCipher,
        nonce_base: [u8; 12],
        count: u16,
    },
    Masked {
        shake: Shake128,
        global_padding: bool,
    },
}

pub struct VmessChunkDecrypter {
    len_codec: ChunkLengthCodec,
    payload_cipher: VmessCipher,
    payload_nonce_base: [u8; 12],
    payload_count: u16,
    is_authenticated_length: bool,
    current_padding_len: usize,
}

impl VmessChunkDecrypter {
    pub fn new(
        request_key: &[u8; 16],
        request_nonce: &[u8; 16],
        security: u8,
        option: u8,
    ) -> io::Result<Self> {
        let is_authenticated_length = (option & OPTION_AUTH_LENGTH) != 0;
        let global_padding = (option & OPTION_GLOBAL_PADDING) != 0;

        let len_codec = if is_authenticated_length {
            let auth_len_kdf = vmess_kdf(request_key, &[b"auth_len"]);
            let mut nonce_base = [0u8; 12];
            nonce_base.copy_from_slice(&request_nonce[..12]);

            let cipher = if security == SECURITY_CHACHA20_POLY1305 {
                let chacha_len_key = generate_chacha20_poly1305_key(&auth_len_kdf[..16]);
                let c = ChaCha20Poly1305::new_from_slice(&chacha_len_key).map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "ChaCha len cipher init failed")
                })?;
                VmessCipher::ChaCha20(c)
            } else {
                let c = Aes128Gcm::new_from_slice(&auth_len_kdf[..16]).map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "AesGcm len cipher init failed")
                })?;
                VmessCipher::AesGcm(c)
            };
            ChunkLengthCodec::Authenticated {
                cipher,
                nonce_base,
                count: 0,
            }
        } else {
            ChunkLengthCodec::Masked {
                shake: Shake128::new(request_nonce),
                global_padding,
            }
        };

        let mut payload_nonce_base = [0u8; 12];
        payload_nonce_base.copy_from_slice(&request_nonce[..12]);

        let payload_cipher = if security == SECURITY_CHACHA20_POLY1305 {
            let key32 = generate_chacha20_poly1305_key(request_key);
            let c = ChaCha20Poly1305::new_from_slice(&key32)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "ChaCha init failed"))?;
            VmessCipher::ChaCha20(c)
        } else {
            let c = Aes128Gcm::new_from_slice(request_key)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "AesGcm init failed"))?;
            VmessCipher::AesGcm(c)
        };

        Ok(Self {
            len_codec,
            payload_cipher,
            payload_nonce_base,
            payload_count: 0,
            is_authenticated_length,
            current_padding_len: 0,
        })
    }

    pub fn is_authenticated_length(&self) -> bool {
        self.is_authenticated_length
    }

    pub fn decrypt_length(&mut self, raw_len_bytes: &[u8]) -> io::Result<usize> {
        match &mut self.len_codec {
            ChunkLengthCodec::Authenticated {
                cipher,
                nonce_base,
                count,
            } => {
                if raw_len_bytes.len() < 18 {
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "Len block requires 18 bytes",
                    ));
                }
                let mut nonce = *nonce_base;
                let count_be = count.to_be_bytes();
                nonce[0] = count_be[0];
                nonce[1] = count_be[1];
                *count = count.wrapping_add(1);

                let mut data = raw_len_bytes[..2].to_vec();
                let tag = &raw_len_bytes[2..18];

                match cipher {
                    VmessCipher::AesGcm(c) => {
                        let gcm_tag = GcmTag::from_slice(tag);
                        c.decrypt_in_place_detached(
                            GcmNonce::from_slice(&nonce),
                            b"",
                            &mut data,
                            gcm_tag,
                        )
                        .map_err(|_| {
                            Error::new(ErrorKind::InvalidData, "AesGcm chunk length decrypt failed")
                        })?;
                    }
                    VmessCipher::ChaCha20(c) => {
                        let chacha_tag = chacha20poly1305::Tag::from_slice(tag);
                        c.decrypt_in_place_detached(
                            chacha20poly1305::Nonce::from_slice(&nonce),
                            b"",
                            &mut data,
                            chacha_tag,
                        )
                        .map_err(|_| {
                            Error::new(ErrorKind::InvalidData, "ChaCha chunk length decrypt failed")
                        })?;
                    }
                }
                self.current_padding_len = 0;
                let total_len = u16::from_be_bytes([data[0], data[1]]) as usize;
                if total_len == 16 {
                    return Ok(0);
                }
                if total_len < 16 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Authenticated chunk length too short for tag",
                    ));
                }
                Ok(total_len)
            }
            ChunkLengthCodec::Masked {
                shake,
                global_padding,
            } => {
                if raw_len_bytes.len() < 2 {
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "Masked len requires 2 bytes",
                    ));
                }
                let padding_len = if *global_padding {
                    (shake.next_u16() % 64) as usize
                } else {
                    0
                };
                self.current_padding_len = padding_len;
                let mask = shake.next_u16();
                let enc_len = u16::from_be_bytes([raw_len_bytes[0], raw_len_bytes[1]]);
                let total_len = (enc_len ^ mask) as usize;
                if total_len == 16 + padding_len {
                    return Ok(0);
                }
                if total_len < 16 + padding_len {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Masked chunk len too short for AEAD tag and padding",
                    ));
                }
                Ok(total_len)
            }
        }
    }

    pub fn decrypt_chunk_payload(
        &mut self,
        payload_with_tag_and_padding: &mut [u8],
    ) -> io::Result<usize> {
        let padding_len = self.current_padding_len;
        if payload_with_tag_and_padding.len() < 16 + padding_len {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                "Payload chunk too short for tag and padding",
            ));
        }
        let effective_len = payload_with_tag_and_padding.len() - padding_len;
        let data_len = effective_len - 16;
        let mut nonce = self.payload_nonce_base;
        let count_be = self.payload_count.to_be_bytes();
        nonce[0] = count_be[0];
        nonce[1] = count_be[1];
        self.payload_count = self.payload_count.wrapping_add(1);

        let (effective_slice, _padding_slice) =
            payload_with_tag_and_padding.split_at_mut(effective_len);
        let (payload_slice, tag_slice) = effective_slice.split_at_mut(data_len);

        match &self.payload_cipher {
            VmessCipher::AesGcm(c) => {
                let tag = GcmTag::from_slice(tag_slice);
                c.decrypt_in_place_detached(GcmNonce::from_slice(&nonce), b"", payload_slice, tag)
                    .map_err(|_| {
                        Error::new(
                            ErrorKind::InvalidData,
                            "AesGcm payload chunk decrypt failed",
                        )
                    })?;
            }
            VmessCipher::ChaCha20(c) => {
                let tag = chacha20poly1305::Tag::from_slice(tag_slice);
                c.decrypt_in_place_detached(
                    chacha20poly1305::Nonce::from_slice(&nonce),
                    b"",
                    payload_slice,
                    tag,
                )
                .map_err(|_| {
                    Error::new(
                        ErrorKind::InvalidData,
                        "ChaCha payload chunk decrypt failed",
                    )
                })?;
            }
        }

        Ok(data_len)
    }
}

pub struct VmessChunkEncrypter {
    len_codec: ChunkLengthCodec,
    payload_cipher: VmessCipher,
    payload_nonce_base: [u8; 12],
    payload_count: u16,
    is_authenticated_length: bool,
}

impl VmessChunkEncrypter {
    pub fn new(
        resp_key: &[u8; 16],
        resp_nonce: &[u8; 16],
        security: u8,
        option: u8,
    ) -> io::Result<Self> {
        let is_authenticated_length = (option & OPTION_AUTH_LENGTH) != 0;
        let global_padding = (option & OPTION_GLOBAL_PADDING) != 0;

        let len_codec = if is_authenticated_length {
            let auth_len_kdf = vmess_kdf(resp_key, &[b"auth_len"]);
            let mut nonce_base = [0u8; 12];
            nonce_base.copy_from_slice(&resp_nonce[..12]);

            let cipher = if security == SECURITY_CHACHA20_POLY1305 {
                let chacha_len_key = generate_chacha20_poly1305_key(&auth_len_kdf[..16]);
                let c = ChaCha20Poly1305::new_from_slice(&chacha_len_key).map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "ChaCha len cipher init failed")
                })?;
                VmessCipher::ChaCha20(c)
            } else {
                let c = Aes128Gcm::new_from_slice(&auth_len_kdf[..16]).map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "AesGcm len cipher init failed")
                })?;
                VmessCipher::AesGcm(c)
            };
            ChunkLengthCodec::Authenticated {
                cipher,
                nonce_base,
                count: 0,
            }
        } else {
            ChunkLengthCodec::Masked {
                shake: Shake128::new(resp_nonce),
                global_padding,
            }
        };

        let mut payload_nonce_base = [0u8; 12];
        payload_nonce_base.copy_from_slice(&resp_nonce[..12]);

        let payload_cipher = if security == SECURITY_CHACHA20_POLY1305 {
            let key32 = generate_chacha20_poly1305_key(resp_key);
            let c = ChaCha20Poly1305::new_from_slice(&key32)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "ChaCha init failed"))?;
            VmessCipher::ChaCha20(c)
        } else {
            let c = Aes128Gcm::new_from_slice(resp_key)
                .map_err(|_| Error::new(ErrorKind::InvalidData, "AesGcm init failed"))?;
            VmessCipher::AesGcm(c)
        };

        Ok(Self {
            len_codec,
            payload_cipher,
            payload_nonce_base,
            payload_count: 0,
            is_authenticated_length,
        })
    }

    pub fn is_authenticated_length(&self) -> bool {
        self.is_authenticated_length
    }

    pub fn encrypt_chunk(&mut self, payload: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        if payload.len() > u16::MAX as usize - 16 {
            return Err(Error::new(ErrorKind::InvalidInput, "VMess chunk too large"));
        }
        let encrypted_size = (payload.len() + 16) as u16;

        let padding_len = match &mut self.len_codec {
            ChunkLengthCodec::Authenticated { .. } => 0usize,
            ChunkLengthCodec::Masked {
                shake,
                global_padding,
            } => {
                if *global_padding {
                    (shake.next_u16() % 64) as usize
                } else {
                    0usize
                }
            }
        };

        let chunk_total_len = encrypted_size
            .checked_add(padding_len as u16)
            .ok_or_else(|| Error::new(ErrorKind::InvalidInput, "VMess padded chunk too large"))?;

        match &mut self.len_codec {
            ChunkLengthCodec::Authenticated {
                cipher,
                nonce_base,
                count,
            } => {
                let mut len_nonce = *nonce_base;
                let count_be = count.to_be_bytes();
                len_nonce[0] = count_be[0];
                len_nonce[1] = count_be[1];
                *count = count.wrapping_add(1);

                let mut len_data = chunk_total_len.to_be_bytes().to_vec();
                let tag_len_bytes = match cipher {
                    VmessCipher::AesGcm(c) => {
                        let tag = c
                            .encrypt_in_place_detached(
                                GcmNonce::from_slice(&len_nonce),
                                b"",
                                &mut len_data,
                            )
                            .map_err(|_| {
                                Error::new(ErrorKind::InvalidData, "Encrypt chunk len failed")
                            })?;
                        tag.as_slice().to_vec()
                    }
                    VmessCipher::ChaCha20(c) => {
                        let tag = c
                            .encrypt_in_place_detached(
                                chacha20poly1305::Nonce::from_slice(&len_nonce),
                                b"",
                                &mut len_data,
                            )
                            .map_err(|_| {
                                Error::new(ErrorKind::InvalidData, "Encrypt chunk len failed")
                            })?;
                        tag.as_slice().to_vec()
                    }
                };
                out.extend_from_slice(&len_data);
                out.extend_from_slice(&tag_len_bytes);
            }
            ChunkLengthCodec::Masked { shake, .. } => {
                let mask = shake.next_u16();
                let masked_len = chunk_total_len ^ mask;
                out.extend_from_slice(&masked_len.to_be_bytes());
            }
        }

        let mut payload_nonce = self.payload_nonce_base;
        let pcount_be = self.payload_count.to_be_bytes();
        payload_nonce[0] = pcount_be[0];
        payload_nonce[1] = pcount_be[1];
        self.payload_count = self.payload_count.wrapping_add(1);

        let mut payload_data = payload.to_vec();
        match &self.payload_cipher {
            VmessCipher::AesGcm(c) => {
                let tag_p = c
                    .encrypt_in_place_detached(
                        GcmNonce::from_slice(&payload_nonce),
                        b"",
                        &mut payload_data,
                    )
                    .map_err(|_| {
                        Error::new(ErrorKind::InvalidData, "AesGcm encrypt chunk failed")
                    })?;
                out.extend_from_slice(&payload_data);
                out.extend_from_slice(tag_p.as_slice());
            }
            VmessCipher::ChaCha20(c) => {
                let tag_p = c
                    .encrypt_in_place_detached(
                        chacha20poly1305::Nonce::from_slice(&payload_nonce),
                        b"",
                        &mut payload_data,
                    )
                    .map_err(|_| {
                        Error::new(ErrorKind::InvalidData, "ChaCha encrypt chunk failed")
                    })?;
                out.extend_from_slice(&payload_data);
                out.extend_from_slice(tag_p.as_slice());
            }
        }

        if padding_len > 0 {
            out.resize(out.len() + padding_len, 0u8);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32_ieee() {
        assert_eq!(crc32_ieee(b"123456789"), 0xcbf43926);
    }

    #[test]
    fn test_fnv1a_32() {
        assert_eq!(fnv1a_32(b""), 0x811c_9dc5);
        assert_eq!(fnv1a_32(b"hello world"), 0xd58b_3fa7);
    }

    #[test]
    fn test_official_vmess_kdf_golden_vector_1() {
        let mut key = [0u8; 16];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let derived = vmess_kdf(&key, &[b"AES Auth ID Encryption"]);
        let hex_str = hex::encode(derived);
        assert_eq!(
            hex_str, "9fa4289c41650861a45b34aeab3879fe4785dce57ab3f68cfb0cc60fca69460a",
            "KDF Vector 1 must strictly match official V2Fly/sing-box implementation"
        );
    }

    #[test]
    fn test_official_vmess_kdf_golden_vector_2() {
        let mut key = [0u8; 16];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let auth_id = hex::decode("101112131415161718191a1b1c1d1e1f").unwrap();
        let conn_nonce = hex::decode("2021222324252627").unwrap();
        let derived = vmess_kdf(
            &key,
            &[b"VMess Header AEAD Key_Length", &auth_id, &conn_nonce],
        );
        let hex_str = hex::encode(derived);
        assert_eq!(
            hex_str, "f6854515f670c79b2ae6d932bbde9ea0993dd0b7f51934f04eca2ee0590e3fb3",
            "KDF Vector 2 must strictly match official V2Fly/sing-box multi-path KDF"
        );
    }

    #[test]
    fn test_shake128_golden_vector() {
        let mut nonce = [0u8; 16];
        for (i, b) in nonce.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut shake = Shake128::new(&nonce);
        let mut out = [0u8; 16];
        shake.read(&mut out);
        assert_eq!(
            hex::encode(out),
            "98481946de85c670a7a84432ab4091a8",
            "Shake128 output must match official Go sha3.NewShake128"
        );
    }

    #[test]
    fn test_vmess_user_keys_and_auth_id() {
        let uuid_str = "a1b2c3d4-e5f6-7a8b-9c0d-1e2f3a4b5c6d";
        let user_keys = VmessUserKeys::new(uuid_str).expect("Valid UUID");

        let now_sec = 1700000000i64;
        let mut plain_block = [0u8; 16];
        plain_block[0..8].copy_from_slice(&now_sec.to_be_bytes());
        plain_block[8..12].copy_from_slice(&[1, 2, 3, 4]);
        let c = crc32_ieee(&plain_block[0..12]);
        plain_block[12..16].copy_from_slice(&c.to_be_bytes());

        let auth_id_key = &vmess_kdf(&user_keys.cmd_key, &[KDF_SALT_AUTH_ID_ENCRYPTION_KEY])[..16];
        let enc_cipher = Aes128::new_from_slice(auth_id_key).unwrap();
        use aes::cipher::BlockEncrypt;
        let mut block = aes::Block::clone_from_slice(&plain_block);
        enc_cipher.encrypt_block(&mut block);

        let mut auth_id = [0u8; 16];
        auth_id.copy_from_slice(block.as_slice());

        assert!(user_keys.validate_auth_id(&auth_id, now_sec));

        assert!(!user_keys.validate_auth_id(&auth_id, now_sec));
    }

    #[test]
    fn test_vmess_chunk_masked_roundtrip() {
        let req_key = [7u8; 16];
        let req_nonce = [9u8; 16];

        let mut enc = VmessChunkEncrypter::new(
            &req_key,
            &req_nonce,
            SECURITY_AES_128_GCM,
            OPTION_CHUNK_MASKING,
        )
        .unwrap();
        let mut dec = VmessChunkDecrypter::new(
            &req_key,
            &req_nonce,
            SECURITY_AES_128_GCM,
            OPTION_CHUNK_MASKING,
        )
        .unwrap();

        let original_data = b"Hello, official VMess masked chunk in pure Rust!";
        let mut out = Vec::new();
        enc.encrypt_chunk(original_data, &mut out).unwrap();

        assert_eq!(out.len(), 2 + original_data.len() + 16);

        let payload_len = dec.decrypt_length(&out[0..2]).unwrap();
        assert_eq!(payload_len, original_data.len() + 16);

        let mut payload_buf = out[2..].to_vec();
        let plain_len = dec.decrypt_chunk_payload(&mut payload_buf).unwrap();
        assert_eq!(plain_len, original_data.len());
        assert_eq!(&payload_buf[..plain_len], original_data);
    }

    #[test]
    fn test_vmess_chunk_size_boundary() {
        let mut enc = VmessChunkEncrypter::new(
            &[7; 16],
            &[9; 16],
            SECURITY_AES_128_GCM,
            OPTION_CHUNK_MASKING,
        )
        .unwrap();
        let mut out = Vec::new();
        assert_eq!(
            enc.encrypt_chunk(&vec![0; 65520], &mut out)
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
        assert!(out.is_empty());
        enc.encrypt_chunk(&vec![0; 65519], &mut out).unwrap();
        assert_eq!(out.len(), 65537);
        let mut enc = VmessChunkEncrypter::new(
            &[7; 16],
            &[9; 16],
            SECURITY_AES_128_GCM,
            OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING,
        )
        .unwrap();
        assert_eq!(
            enc.encrypt_chunk(&vec![0; 65519], &mut Vec::new())
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidInput
        );
    }

    #[test]
    fn test_vmess_chunk_authenticated_roundtrip_chacha() {
        let req_key = [5u8; 16];
        let req_nonce = [3u8; 16];

        let mut enc = VmessChunkEncrypter::new(
            &req_key,
            &req_nonce,
            SECURITY_CHACHA20_POLY1305,
            OPTION_AUTH_LENGTH,
        )
        .unwrap();
        let mut dec = VmessChunkDecrypter::new(
            &req_key,
            &req_nonce,
            SECURITY_CHACHA20_POLY1305,
            OPTION_AUTH_LENGTH,
        )
        .unwrap();

        let original_data = b"ChaCha20 AuthenticatedLength stream!";
        let mut out = Vec::new();
        enc.encrypt_chunk(original_data, &mut out).unwrap();

        assert_eq!(out.len(), 18 + original_data.len() + 16);

        let payload_len = dec.decrypt_length(&out[0..18]).unwrap();
        assert_eq!(payload_len, original_data.len() + 16);

        let mut payload_buf = out[18..].to_vec();
        let plain_len = dec.decrypt_chunk_payload(&mut payload_buf).unwrap();
        assert_eq!(plain_len, original_data.len());
        assert_eq!(&payload_buf[..plain_len], original_data);
    }

    #[test]
    fn test_vmess_chunk_global_padding_roundtrip() {
        let req_key = [11u8; 16];
        let req_nonce = [13u8; 16];

        let opt = OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING;
        let mut enc =
            VmessChunkEncrypter::new(&req_key, &req_nonce, SECURITY_AES_128_GCM, opt).unwrap();
        let mut dec =
            VmessChunkDecrypter::new(&req_key, &req_nonce, SECURITY_AES_128_GCM, opt).unwrap();

        let chunk1_data = b"GET /download/64mb HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let mut out1 = Vec::new();
        enc.encrypt_chunk(chunk1_data, &mut out1).unwrap();

        let chunk1_wire_len = dec.decrypt_length(&out1[0..2]).unwrap();
        assert!(chunk1_wire_len >= chunk1_data.len() + 16);

        let mut payload_buf1 = out1[2..2 + chunk1_wire_len].to_vec();
        let plain_len1 = dec.decrypt_chunk_payload(&mut payload_buf1).unwrap();
        assert_eq!(plain_len1, chunk1_data.len());
        assert_eq!(&payload_buf1[..plain_len1], chunk1_data);

        let chunk2_data = b"Response payload chunk 2 with different padding";
        let mut out2 = Vec::new();
        enc.encrypt_chunk(chunk2_data, &mut out2).unwrap();

        let chunk2_wire_len = dec.decrypt_length(&out2[0..2]).unwrap();
        assert!(chunk2_wire_len >= chunk2_data.len() + 16);

        let mut payload_buf2 = out2[2..2 + chunk2_wire_len].to_vec();
        let plain_len2 = dec.decrypt_chunk_payload(&mut payload_buf2).unwrap();
        assert_eq!(plain_len2, chunk2_data.len());
        assert_eq!(&payload_buf2[..plain_len2], chunk2_data);

        let mut out_eof = Vec::new();
        enc.encrypt_chunk(&[], &mut out_eof).unwrap();
        let eof_len = dec.decrypt_length(&out_eof[0..2]).unwrap();
        assert_eq!(eof_len, 0, "EOF chunk must return 0 bytes");
    }
}
