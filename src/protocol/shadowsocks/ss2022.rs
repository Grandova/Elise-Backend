use crate::conn::{BoxedStream, PrefixedStream};
use crate::panel::types::User;
use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use base64::Engine;
use bytes::{BufMut, BytesMut};
use shadowsocks::context::Context;
use shadowsocks::crypto::{v2::tcp::TcpCipher, v2::udp::UdpCipher, CipherKind};
use shadowsocks::relay::socks5::Address;
use shadowsocks::relay::tcprelay::proxy_stream::ProxyServerStream;
use std::collections::{HashMap, HashSet};
use std::io::{self, Cursor};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::AsyncReadExt;

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
        // Upstream replay uses only the AEAD generation; AES-192 has no upstream enum.
        match self {
            Self::None | Self::Legacy(_) => CipherKind::AES_128_GCM,
            Self::Aead2022(m) => m,
        }
    }
}

pub struct Credential {
    pub user: User,
    pub key: Vec<u8>,
    pub context: Arc<Context>,
}

impl Credential {
    pub fn new(user: User, method: Method, context: Arc<Context>) -> io::Result<Self> {
        let password = user.password.as_deref().unwrap_or(&user.uuid);
        let key = if method == Method::None {
            Vec::new()
        } else if method.is_aead_2022() {
            decode_key(password, method)?
        } else {
            crate::protocol::ss_crypto::evp_bytes_to_key(password.as_bytes(), method.key_len())
        };
        Ok(Self { user, key, context })
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
    let key = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| invalid("SS2022 key must be padded Base64"))?;
    if key.len() != method.key_len() {
        return Err(invalid("SS2022 key length does not match cipher"));
    }
    Ok(key)
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn now() -> io::Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|t| t.as_secs())
        .map_err(|_| invalid("System clock is before UNIX epoch"))
}

// SIP023 uses a single AES block, not AEAD, for the identity/header block.
fn aes_block(method: CipherKind, key: &[u8], block: &mut [u8], encrypt: bool) {
    match method {
        CipherKind::AEAD2022_BLAKE3_AES_128_GCM => {
            let cipher = aes::Aes128::new_from_slice(key).expect("validated AES key");
            if encrypt {
                cipher.encrypt_block(block.into());
            } else {
                cipher.decrypt_block(block.into());
            }
        }
        CipherKind::AEAD2022_BLAKE3_AES_256_GCM => {
            let cipher = aes::Aes256::new_from_slice(key).expect("validated AES key");
            if encrypt {
                cipher.encrypt_block(block.into());
            } else {
                cipher.decrypt_block(block.into());
            }
        }
        _ => unreachable!("AES identity only"),
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
    let mut salt = vec![0; method.salt_len()];
    stream.read_exact(&mut salt).await?;
    let mut identity = [0; 16];
    let candidates: Vec<Arc<Credential>> = if let Some(key) = server_key {
        stream.read_exact(&mut identity).await?;
        let subkey = blake3::derive_key("shadowsocks 2022 identity subkey", &[key, &salt].concat());
        aes_block(method, &subkey[..method.key_len()], &mut identity, false);
        // O(1) user identification via precomputed EIH table - zero N-user loop
        match users.identity_map.get(&identity) {
            Some(cred) => vec![cred.clone()],
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SS2022 user not found",
                ))
            }
        }
    } else {
        users.credentials.clone()
    };
    let mut header = [0; 27];
    stream.read_exact(&mut header).await?;
    for credential in candidates {
        let mut cipher = TcpCipher::new(method, &credential.key, &salt);
        let mut plain = header;
        if !cipher.decrypt_packet(&mut plain) {
            continue;
        }
        if plain[0] != 0
            || now()?.abs_diff(u64::from_be_bytes(plain[1..9].try_into().unwrap())) > 30
        {
            return Err(invalid("Invalid SS2022 request type or timestamp"));
        }
        let length = u16::from_be_bytes([plain[9], plain[10]]) as usize;
        let mut body = vec![0; length + 16];
        stream.read_exact(&mut body).await?;
        let mut decoded = body.clone();
        if !cipher.decrypt_packet(&mut decoded) {
            return Err(invalid("Invalid SS2022 header tag"));
        }
        let mut cursor = Cursor::new(&decoded[..length]);
        let address = Address::read_cursor(&mut cursor).map_err(io::Error::other)?;
        let offset = cursor.position() as usize;
        if length < offset + 2 {
            return Err(invalid("Truncated SS2022 padding length"));
        }
        let padding = u16::from_be_bytes([decoded[offset], decoded[offset + 1]]) as usize;
        if padding > 900 || offset + 2 + padding > length || (padding == 0 && offset + 2 == length)
        {
            return Err(invalid("Invalid SS2022 initial padding/payload"));
        }
        // Strip EIH after authenticating it; the library then handles the selected user's
        // single-key stream, including replay and binding the response to the request salt.
        let mut prefix = salt;
        prefix.extend_from_slice(&header);
        prefix.extend_from_slice(&body);
        let stream = PrefixedStream::new(stream, Some(prefix));
        let mut stream = ProxyServerStream::from_stream(
            credential.context.clone(),
            stream,
            method,
            &credential.key,
        );
        let parsed = stream.handshake().await?;
        if parsed != address {
            return Err(invalid("SS2022 header mismatch"));
        }
        return Ok((credential, Box::new(stream), address));
    }
    Err(io::Error::new(
        io::ErrorKind::PermissionDenied,
        "SS2022 authentication failed",
    ))
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

        // Fast path: try cached user credential first
        if let Some(uid) = cached_user_id {
            if let Some(credential) = users.credentials.iter().find(|c| c.user.id == uid) {
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

        // Full scan
        for credential in &users.credentials {
            if Some(credential.user.id) == cached_user_id {
                continue; // already tested
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
    let nonce_len = if chacha { 24 } else { 0 };
    let eih_len = if server_key.is_some() { 16 } else { 0 };
    if packet.len() < nonce_len + 16 + eih_len + 11 + 16 {
        return Err(invalid("Truncated SS2022 UDP packet"));
    }

    // SS2022 Multi-User AES EIH Fast Path: O(1) user identification without looping
    if !chacha && server_key.is_some() {
        let header_key = server_key.unwrap();
        let mut data = packet.to_vec();
        aes_block(method, header_key, &mut data[..16], false);
        aes_block(method, header_key, &mut data[16..32], false);
        for i in 0..16 {
            data[16 + i] ^= data[i];
        }
        let mut user_id = [0u8; 16];
        user_id.copy_from_slice(&data[16..32]);

        let credential = users
            .identity_map
            .get(&user_id)
            .ok_or_else(|| invalid("SS2022 UDP user not found"))?;

        let sid = u64::from_be_bytes(data[..8].try_into().unwrap());
        let nonce = data[4..16].to_vec();
        if !UdpCipher::new(method, &credential.key, sid).decrypt_packet(&nonce, &mut data[32..]) {
            return Err(invalid("SS2022 UDP decryption failed"));
        }

        data.truncate(data.len() - 16);
        let offset = 32;
        if data[offset] != 0
            || now()?.abs_diff(u64::from_be_bytes(
                data[offset + 1..offset + 9].try_into().unwrap(),
            )) > 30
        {
            return Err(invalid("Invalid SS2022 UDP type or timestamp"));
        }
        let padding = u16::from_be_bytes([data[offset + 9], data[offset + 10]]) as usize;
        let start = offset + 11 + padding;
        if start > data.len() {
            return Err(invalid("Truncated SS2022 UDP padding"));
        }
        let mut cursor = Cursor::new(&data[start..]);
        let address = Address::read_cursor(&mut cursor).map_err(io::Error::other)?;
        return Ok(Datagram {
            credential: credential.clone(),
            address,
            payload: data[start + cursor.position() as usize..].to_vec(),
            session_id: u64::from_be_bytes(data[..8].try_into().unwrap()),
            packet_id: u64::from_be_bytes(data[8..16].try_into().unwrap()),
        });
    }

    // Fallback for single-user or ChaCha20 without EIH
    for credential in &users.credentials {
        let mut data = packet[nonce_len..].to_vec();
        if chacha {
            if !UdpCipher::new(method, &credential.key, 0).decrypt_packet(&packet[..24], &mut data)
            {
                continue;
            }
        } else {
            let header_key = server_key.unwrap_or(&credential.key);
            aes_block(method, header_key, &mut data[..16], false);
            if eih_len > 0 {
                aes_block(method, header_key, &mut data[16..32], false);
                for i in 0..16 {
                    data[16 + i] ^= data[i];
                }
                if data[16..32] != blake3::hash(&credential.key).as_bytes()[..16] {
                    continue;
                }
            }
            let sid = u64::from_be_bytes(data[..8].try_into().unwrap());
            let nonce = data[4..16].to_vec();
            if !UdpCipher::new(method, &credential.key, sid)
                .decrypt_packet(&nonce, &mut data[16 + eih_len..])
            {
                continue;
            }
        }
        data.truncate(data.len() - 16);
        let offset = 16 + eih_len;
        if data[offset] != 0
            || now()?.abs_diff(u64::from_be_bytes(
                data[offset + 1..offset + 9].try_into().unwrap(),
            )) > 30
        {
            return Err(invalid("Invalid SS2022 UDP type or timestamp"));
        }
        let padding = u16::from_be_bytes([data[offset + 9], data[offset + 10]]) as usize;
        let start = offset + 11 + padding;
        if start > data.len() {
            return Err(invalid("Truncated SS2022 UDP padding"));
        }
        let mut cursor = Cursor::new(&data[start..]);
        let address = Address::read_cursor(&mut cursor).map_err(io::Error::other)?;
        return Ok(Datagram {
            credential: credential.clone(),
            address,
            payload: data[start + cursor.position() as usize..].to_vec(),
            session_id: u64::from_be_bytes(data[..8].try_into().unwrap()),
            packet_id: u64::from_be_bytes(data[8..16].try_into().unwrap()),
        });
    }
    Err(invalid("SS2022 UDP authentication failed"))
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

        // Create 5,000 distinct users
        let mut users = Vec::with_capacity(5000);
        for id in 1..=5000 {
            let mut key = vec![0u8; 16];
            key[..4].copy_from_slice(&(id as u32).to_be_bytes());
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

        // Pick user #4242 and craft an encrypted SS2022 UDP packet
        let target_user = &users[4241];
        let addr = Address::SocketAddress("1.1.1.1:53".parse().unwrap());
        let payload = b"hello-massive-o1";

        // In multi-user mode with server_key, the client prepends the EIH block.
        // Let's construct a standard EIH UDP packet:
        // Header block (16B) = SID (8B) + PacketID (8B) encrypted with server_key
        // EIH block (16B) = (blake3(key)[..16] ^ HeaderBlock) encrypted with server_key
        // Payload = AES-GCM encrypted with user_key and SID nonce
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

        // Body: type (1B) + timestamp (8B) + padding_len (2B) + addr + payload
        let mut body = Vec::new();
        body.push(0u8);
        body.extend_from_slice(&now().unwrap().to_be_bytes());
        body.extend_from_slice(&0u16.to_be_bytes());
        addr.write_to_buf(&mut body);
        body.extend_from_slice(payload);
        body.resize(body.len() + 16, 0);

        // Nonce is plaintext header[4..16]
        let cipher = UdpCipher::new(cipher_kind, &target_user.key, 100);
        cipher.encrypt_packet(&header[4..16], &mut body);

        aes_block(cipher_kind, &server_key, &mut header, true);
        aes_block(cipher_kind, &server_key, &mut eih, true);

        let mut wire = Vec::new();
        wire.extend_from_slice(&header);
        wire.extend_from_slice(&eih);
        wire.extend_from_slice(&body);

        // Measure O(1) decryption speed across 1,000 iterations
        let start = std::time::Instant::now();
        for _ in 0..1000 {
            let dg = decrypt_udp(method, Some(&server_key), &user_index, &wire).unwrap();
            assert_eq!(dg.credential.user.id, 4242);
            assert_eq!(dg.payload, payload);
        }
        let elapsed = start.elapsed();
        // 1,000 decryptions against 5,000 users must complete in less than 50ms (strictly O(1))
        assert!(
            elapsed.as_millis() < 50,
            "Expected O(1) decryption, took {:?}",
            elapsed
        );
    }
}
