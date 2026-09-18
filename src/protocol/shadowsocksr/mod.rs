use crate::conn::{bind_tcp_listener, read_proxy_protocol, MonitoredStream};
use crate::observability::AuditRecord;
use crate::panel::types::{NodeInfo, User};
use crate::protocol::{Inbound, InboundContext};
use crate::proxy::router::MatchContext;
use async_trait::async_trait;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tracing::{info, warn};

pub struct ShadowsocksrInbound {
    users: Arc<RwLock<HashMap<String, User>>>,
    replay: Arc<Mutex<HashMap<(u32, u32, u32), Instant>>>,
}

impl Default for ShadowsocksrInbound {
    fn default() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            replay: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl ShadowsocksrInbound {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Inbound for ShadowsocksrInbound {
    fn protocol_type(&self) -> &'static str {
        "shadowsocksr"
    }

    fn update_users(&self, users: Vec<User>) {
        let mut map = HashMap::new();
        for u in users {
            map.insert(u.id.to_string(), u);
        }
        *self.users.write() = map;
    }

    async fn start(
        &self,
        ctx: InboundContext,
        node_info: NodeInfo,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> std::io::Result<()> {
        let settings = Arc::new(SsrSettings::new(&node_info)?);
        let bind_addr = format!("{}:{}", ctx.listen_addr, ctx.port);
        let listener = bind_tcp_listener(&bind_addr, ctx.global_config.mptcp).await?;
        info!("ShadowsocksR inbound listening on {}", bind_addr);

        let users = self.users.clone();

        let mut connections = tokio::task::JoinSet::new();
        ctx.mark_ready();
        loop {
            tokio::select! {
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(e)) = result { tracing::warn!(error = %e, "Connection task failed"); }
                }
                _ = shutdown_rx.recv() => {
                    info!("ShadowsocksR inbound on port {} stopping", ctx.port);
                    break;
                }
                accept_res = listener.accept() => {
                    let (stream, remote_addr) = match accept_res {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!("ShadowsocksR accept error: {:?}", e);
                            continue;
                        }
                    };
                    let _ = stream.set_nodelay(true);

                    let ctx = ctx.clone();
                    let users = users.clone();
                    let settings = settings.clone();
                    let replay = self.replay.clone();
                    connections.spawn(async move {
                        let _ = handle_connection(stream, remote_addr, ctx, users, settings, replay).await;
                    });
                }
            }
        }
        drop(listener);
        crate::protocol::common::inbound::drain_connections(&mut connections).await;
        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    mut remote_addr: SocketAddr,
    ctx: InboundContext,
    users: Arc<RwLock<HashMap<String, User>>>,
    settings: Arc<SsrSettings>,
    replay: Arc<Mutex<HashMap<(u32, u32, u32), Instant>>>,
) -> std::io::Result<()> {
    let local_ip = stream.local_addr().ok().map(|s| s.ip());

    // Proxy Protocol check (supports Auto, Strict, Off)
    let (src_opt, stream) = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        read_proxy_protocol(stream, ctx.global_config.get_proxy_protocol_mode()),
    )
    .await
    .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "SSR proxy header timeout"))??;
    if let Some(src) = src_opt {
        remote_addr = src;
    }

    let client_ip = remote_addr.ip();
    if ctx.defense.is_banned(client_ip) {
        return Ok(());
    }

    let snapshot: Vec<User> = users.read().values().cloned().collect();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(std::io::Error::other)?
        .as_secs();
    let auth = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        settings.authenticate(Box::new(stream), &snapshot, &replay, now),
    )
    .await;
    let (user, mut stream) = match auth {
        Ok(Ok(result)) => result,
        _ => {
            ctx.defense.record_failure(remote_addr.ip());
            return Ok(());
        }
    };
    ctx.defense.record_success(remote_addr.ip());

    // Device limit check
    if !ctx
        .device_limiter
        .check_and_record_async(user.id, remote_addr.ip())
        .await
    {
        return Ok(());
    }

    // Connection limit check
    let _conn_guard = match ctx.conn_limiter.try_acquire(user.id) {
        Some(g) => g,
        None => return Ok(()),
    };

    // Read SSR Address Header: [ATYP 1 byte] [ADDR] [PORT 2 bytes]
    let mut atyp_buf = [0u8; 1];
    stream.read_exact(&mut atyp_buf).await?;

    let (target_host, target_ip) = match atyp_buf[0] {
        0x01 => {
            let mut ipv4 = [0u8; 4];
            stream.read_exact(&mut ipv4).await?;
            let ip = IpAddr::V4(Ipv4Addr::from(ipv4));
            (ip.to_string(), Some(ip))
        }
        0x03 => {
            let mut len_buf = [0u8; 1];
            stream.read_exact(&mut len_buf).await?;
            let mut domain_buf = vec![0u8; len_buf[0] as usize];
            stream.read_exact(&mut domain_buf).await?;
            let domain = String::from_utf8_lossy(&domain_buf).to_string();
            (domain, None)
        }
        0x04 => {
            let mut ipv6 = [0u8; 16];
            stream.read_exact(&mut ipv6).await?;
            let ip = IpAddr::V6(Ipv6Addr::from(ipv6));
            (ip.to_string(), Some(ip))
        }
        _ => return Ok(()),
    };

    let mut port_buf = [0u8; 2];
    stream.read_exact(&mut port_buf).await?;
    let target_port = u16::from_be_bytes(port_buf);

    let (sniffed, stream) =
        crate::conn::sniff_async_stream(stream, target_ip, ctx.global_config.domain_sniff).await;
    let match_host = sniffed.as_deref().unwrap_or(&target_host);
    let dial_host = if ctx.global_config.sniff_redirect {
        match_host
    } else {
        &target_host
    };

    if ctx.audit.should_block(match_host, target_ip, target_port) {
        return Ok(());
    }

    let mctx = MatchContext {
        node_id: ctx.node_id,
        network: "tcp",
        target_host: match_host,
        target_ip,
        target_port,
        inbound_local_ip: local_ip,
    };
    let outbound = ctx.router.match_outbound(&mctx);

    let mut out_stream = match ctx
        .router
        .dialer()
        .dial(&outbound, dial_host, target_port, local_ip)
        .await
    {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    let mut client_conn = MonitoredStream::new(stream, user.id, remote_addr);
    let _traffic = client_conn.traffic_guard(ctx.on_traffic.clone());
    let start_time = Instant::now();

    let _ = crate::conn::copy_bidirectional_throttled(
        &mut client_conn,
        &mut out_stream,
        user.id,
        Some(&ctx.rate_limiter),
        ctx.global_config.tcp_timeout,
    )
    .await;

    let duration = start_time.elapsed();
    let (up, down) = client_conn.stats();

    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user.id,
        "shadowsocksr",
        "tcp",
        &client_ip.to_string(),
        &target_host,
        target_port,
        up,
        down,
        duration.as_millis() as i64,
        &outbound.tag,
        "connected",
    ));

    Ok(())
}

// Wire reference: shadowsocksrr/shadowsocksr, obfsplugin/auth.py (auth_aes128_sha1).
#[derive(Clone, Copy)]
enum SsrAuth {
    Md5,
    Sha1,
}

impl SsrAuth {
    fn hash(self, data: &[u8]) -> Vec<u8> {
        use sha1::Digest;
        match self {
            Self::Md5 => md5::Md5::digest(data).to_vec(),
            Self::Sha1 => sha1::Sha1::digest(data).to_vec(),
        }
    }

    fn mac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::Mac;
        match self {
            Self::Md5 => {
                let mut mac = hmac::Hmac::<md5::Md5>::new_from_slice(key).unwrap();
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha1 => {
                let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(key).unwrap();
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    fn verify(self, key: &[u8], data: &[u8], tag: &[u8]) -> std::io::Result<()> {
        use hmac::Mac;
        let result = match self {
            Self::Md5 => {
                let mut mac = hmac::Hmac::<md5::Md5>::new_from_slice(key).unwrap();
                mac.update(data);
                mac.verify_truncated_left(tag)
            }
            Self::Sha1 => {
                let mut mac = hmac::Hmac::<sha1::Sha1>::new_from_slice(key).unwrap();
                mac.update(data);
                mac.verify_truncated_left(tag)
            }
        };
        result.map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "SSR authentication failed",
            )
        })
    }
}

struct SsrSettings {
    auth: SsrAuth,
    salt: String,
    key_len: usize,
    password: Option<String>,
}

impl SsrSettings {
    fn new(node: &NodeInfo) -> std::io::Result<Self> {
        let protocol = node
            .network_settings
            .as_ref()
            .and_then(|v| v.get("protocol"))
            .and_then(serde_json::Value::as_str);
        let auth = match protocol {
            Some("auth_aes128_md5") => SsrAuth::Md5,
            Some("auth_aes128_sha1") => SsrAuth::Sha1,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Missing or unsupported SSR authentication protocol",
                ))
            }
        };
        let key_len = match node.cipher.as_deref() {
            Some("aes-128-cfb") => 16,
            Some("aes-192-cfb") => 24,
            Some("aes-256-cfb") => 32,
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Unsupported SSR stream cipher",
                ))
            }
        };
        if !matches!(node.obfs.as_deref(), None | Some("plain")) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Unsupported SSR obfuscation",
            ));
        }
        Ok(Self {
            auth,
            salt: protocol.unwrap().to_owned(),
            key_len,
            password: node.server_key.clone(),
        })
    }

    async fn authenticate(
        &self,
        mut stream: crate::conn::BoxedStream,
        users: &[User],
        replay: &Mutex<HashMap<(u32, u32, u32), Instant>>,
        now: u64,
    ) -> std::io::Result<(User, crate::conn::BoxedStream)> {
        use aes::cipher::{BlockDecrypt, KeyInit};
        use base64::Engine;
        use futures_util::SinkExt;
        use tokio_util::codec::{FramedRead, FramedWrite};
        use tokio_util::io::{SinkWriter, StreamReader};

        let mut iv = [0; 16];
        stream.read_exact(&mut iv).await?;
        let mut encrypted = [0; 31];
        stream.read_exact(&mut encrypted).await?;
        let mut matched = None;
        let passwords: Vec<&str> = if let Some(password) = &self.password {
            vec![password]
        } else {
            users
                .iter()
                .map(|u| u.password.as_deref().unwrap_or(&u.uuid))
                .collect()
        };
        for password in passwords {
            let key =
                crate::protocol::ss_crypto::evp_bytes_to_key(password.as_bytes(), self.key_len);
            let mut cipher = SsrCfb::new(&key, iv);
            let mut header = encrypted;
            cipher.apply(&mut header, true);
            let mac_key = [iv.as_slice(), &key].concat();
            if self
                .auth
                .verify(&mac_key, &header[..1], &header[1..7])
                .is_ok()
                && self
                    .auth
                    .verify(&mac_key, &header[7..27], &header[27..31])
                    .is_ok()
            {
                matched = Some((cipher, key, header));
                break;
            }
        }
        let (mut cipher, key, header) = matched.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "SSR stream authentication failed",
            )
        })?;
        let uid = u32::from_le_bytes(header[7..11].try_into().unwrap());
        let user = users
            .iter()
            .find(|u| u.id == uid)
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Unknown SSR user")
            })?
            .clone();
        let user_key = self
            .auth
            .hash(user.password.as_deref().unwrap_or(&user.uuid).as_bytes());
        let password = base64::engine::general_purpose::STANDARD.encode(&user_key) + &self.salt;
        let auth_key = crate::protocol::ss_crypto::evp_bytes_to_key(password.as_bytes(), 16);
        let mut block = aes::cipher::Block::<aes::Aes128>::clone_from_slice(&header[11..27]);
        aes::Aes128::new_from_slice(&auth_key)
            .unwrap()
            .decrypt_block(&mut block);
        let length = u16::from_le_bytes(block[12..14].try_into().unwrap()) as usize;
        let padding = u16::from_le_bytes(block[14..16].try_into().unwrap()) as usize;
        if !(35..8192).contains(&length) || padding > length - 35 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid SSR authentication length",
            ));
        }
        let mut packet = header.to_vec();
        packet.resize(length, 0);
        stream.read_exact(&mut packet[31..]).await?;
        cipher.apply(&mut packet[31..], true);
        self.auth
            .verify(&user_key, &packet[..length - 4], &packet[length - 4..])?;
        let timestamp = u32::from_le_bytes(block[..4].try_into().unwrap());
        if now.abs_diff(timestamp as u64) > 86400 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Expired SSR authentication",
            ));
        }
        let identity = (
            uid,
            u32::from_le_bytes(block[4..8].try_into().unwrap()),
            u32::from_le_bytes(block[8..12].try_into().unwrap()),
        );
        {
            let mut cache = replay.lock();
            cache.retain(|_, seen| seen.elapsed().as_secs() <= 172800);
            if cache.contains_key(&identity) || cache.len() >= 65536 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "SSR replay or replay capacity exceeded",
                ));
            }
            cache.insert(identity, Instant::now());
        }
        let initial = bytes::Bytes::copy_from_slice(&packet[31 + padding..length - 4]);
        let decoder = SsrDecoder {
            cipher,
            auth: self.auth,
            key: user_key.clone(),
            counter: 1,
            plain: bytes::BytesMut::new(),
            initial: Some(initial),
        };
        let server_iv: [u8; 16] = rand::random();
        let encoder = SsrEncoder {
            cipher: SsrCfb::new(&key, server_iv),
            auth: self.auth,
            key: user_key,
            counter: 1,
            iv: Some(server_iv),
        };
        let (read, write) = tokio::io::split(stream);
        let mut writer = FramedWrite::new(write, encoder);
        writer.send(&[][..]).await?;
        Ok((
            user,
            Box::new(tokio::io::join(
                StreamReader::new(FramedRead::new(read, decoder)),
                SinkWriter::new(writer),
            )),
        ))
    }
}

enum SsrAes {
    Aes128(aes::Aes128),
    Aes192(aes::Aes192),
    Aes256(aes::Aes256),
}

struct SsrCfb {
    aes: SsrAes,
    feedback: [u8; 16],
    mask: [u8; 16],
    position: usize,
}

impl SsrCfb {
    fn new(key: &[u8], iv: [u8; 16]) -> Self {
        use aes::cipher::KeyInit;
        let aes = match key.len() {
            16 => SsrAes::Aes128(aes::Aes128::new_from_slice(key).unwrap()),
            24 => SsrAes::Aes192(aes::Aes192::new_from_slice(key).unwrap()),
            32 => SsrAes::Aes256(aes::Aes256::new_from_slice(key).unwrap()),
            _ => unreachable!("validated SSR key length"),
        };
        Self {
            aes,
            feedback: iv,
            mask: [0; 16],
            position: 0,
        }
    }

    fn apply(&mut self, data: &mut [u8], decrypt: bool) {
        use aes::cipher::BlockEncrypt;
        for byte in data {
            if self.position == 0 {
                let mut block = self.feedback.into();
                match &self.aes {
                    SsrAes::Aes128(aes) => aes.encrypt_block(&mut block),
                    SsrAes::Aes192(aes) => aes.encrypt_block(&mut block),
                    SsrAes::Aes256(aes) => aes.encrypt_block(&mut block),
                }
                self.mask.copy_from_slice(&block);
            }
            let input = *byte;
            *byte ^= self.mask[self.position];
            self.feedback[self.position] = if decrypt { input } else { *byte };
            self.position = (self.position + 1) % 16;
        }
    }
}

struct SsrDecoder {
    cipher: SsrCfb,
    auth: SsrAuth,
    key: Vec<u8>,
    counter: u32,
    plain: bytes::BytesMut,
    initial: Option<bytes::Bytes>,
}

impl tokio_util::codec::Decoder for SsrDecoder {
    type Item = bytes::Bytes;
    type Error = std::io::Error;

    fn decode(&mut self, src: &mut bytes::BytesMut) -> std::io::Result<Option<bytes::Bytes>> {
        if let Some(initial) = self.initial.take() {
            if !initial.is_empty() {
                return Ok(Some(initial));
            }
        }
        self.cipher.apply(src, true);
        self.plain.extend_from_slice(&src.split());
        loop {
            if self.plain.len() < 4 {
                return Ok(None);
            }
            let key = [self.key.as_slice(), &self.counter.to_le_bytes()].concat();
            self.auth
                .verify(&key, &self.plain[..2], &self.plain[2..4])?;
            let size = u16::from_le_bytes(self.plain[..2].try_into().unwrap()) as usize;
            if !(9..8192).contains(&size) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid SSR frame size",
                ));
            }
            if self.plain.len() < size {
                return Ok(None);
            }
            self.auth
                .verify(&key, &self.plain[..size - 4], &self.plain[size - 4..size])?;
            let padding = match self.plain[4] {
                255 => u16::from_le_bytes(self.plain[5..7].try_into().unwrap()) as usize,
                n => n as usize,
            };
            if padding == 0 || padding > size - 8 || (self.plain[4] == 255 && padding < 3) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid SSR padding",
                ));
            }
            self.counter = self
                .counter
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("SSR frame counter exhausted"))?;
            let packet = self.plain.split_to(size).freeze();
            if padding + 8 < size {
                return Ok(Some(packet.slice(4 + padding..size - 4)));
            }
        }
    }

    fn decode_eof(&mut self, src: &mut bytes::BytesMut) -> std::io::Result<Option<bytes::Bytes>> {
        let result = self.decode(src)?;
        if result.is_none() && !self.plain.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "Truncated SSR frame",
            ));
        }
        Ok(result)
    }
}

struct SsrEncoder {
    cipher: SsrCfb,
    auth: SsrAuth,
    key: Vec<u8>,
    counter: u32,
    iv: Option<[u8; 16]>,
}

impl tokio_util::codec::Encoder<&[u8]> for SsrEncoder {
    type Error = std::io::Error;

    fn encode(&mut self, data: &[u8], dst: &mut bytes::BytesMut) -> std::io::Result<()> {
        if let Some(iv) = self.iv.take() {
            dst.extend_from_slice(&iv);
        }
        let chunks: Vec<&[u8]> = if data.is_empty() {
            vec![&[]]
        } else {
            data.chunks(8100).collect()
        };
        for chunk in chunks {
            let key = [self.key.as_slice(), &self.counter.to_le_bytes()].concat();
            let mut frame = ((chunk.len() + 9) as u16).to_le_bytes().to_vec();
            frame.extend_from_slice(&self.auth.mac(&key, &frame)[..2]);
            frame.push(1);
            frame.extend_from_slice(chunk);
            frame.extend_from_slice(&self.auth.mac(&key, &frame)[..4]);
            self.counter = self
                .counter
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("SSR frame counter exhausted"))?;
            self.cipher.apply(&mut frame, false);
            dst.extend_from_slice(&frame);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    // Generated by unmodified upstream pack_auth_data/pack_data with deterministic randomness.
    const VECTORS: [(&str, &str); 2] = [
        ("auth_aes128_md5", "000102030405060708090a0b0c0d0e0f9aa78ab093a3a86056d9d2447896bbc4ce65fafe02727f734177002f7daf1094a8c4b000e7820b7074ca3d192486e0fea0ad4c09825de98acd6d6412688efc31acd4efbe8c0ed4a21b9498c7349233d53563328e456744c18d"),
        ("auth_aes128_sha1", "000102030405060708090a0b0c0d0e0f9a20685a9100976056d9d250e246f9524029b01af84e9199d9f206f2b1c583aa1bab1dd2562a01633ff4be7d34103cfc0d159be810fd267e3e341bdd8fb4a0050ff48231a89ffeb53dfa44fde28f224947b19f550d5dc5e947"),
    ];

    fn settings(protocol: &str) -> SsrSettings {
        SsrSettings::new(&NodeInfo {
            cipher: Some("aes-128-cfb".into()),
            server_key: Some("server-secret".into()),
            network_settings: Some(serde_json::json!({"protocol": protocol})),
            ..Default::default()
        })
        .unwrap()
    }

    async fn authenticate(
        packet: &[u8],
        protocol: &str,
        id: u32,
        password: &str,
        replay: &Mutex<HashMap<(u32, u32, u32), Instant>>,
    ) -> std::io::Result<(User, crate::conn::BoxedStream)> {
        let (mut client, server) = tokio::io::duplex(4096);
        client.write_all(packet).await?;
        client.shutdown().await?;
        let result = settings(protocol)
            .authenticate(
                Box::new(server),
                &[User {
                    id,
                    password: Some(password.into()),
                    ..Default::default()
                }],
                replay,
                1700000000,
            )
            .await;
        // Keep the duplex peer alive until the server has sent the authenticated acknowledgement.
        drop(client);
        result
    }

    #[tokio::test]
    async fn upstream_authentication_vectors_and_replay() {
        for (protocol, hex) in VECTORS {
            let packet = hex::decode(hex).unwrap();
            let replay = Mutex::new(HashMap::new());
            let (user, mut stream) = authenticate(&packet, protocol, 42, "user-secret", &replay)
                .await
                .unwrap();
            assert_eq!(user.id, 42);
            let mut plain = Vec::new();
            stream.read_to_end(&mut plain).await.unwrap();
            assert_eq!(
                plain,
                b"\x01\x7f\0\0\x01\0\x50upstream-auth-fixtureindependent-frame"
            );
            assert!(authenticate(&packet, protocol, 42, "user-secret", &replay)
                .await
                .is_err());
        }
    }

    #[tokio::test]
    async fn reject_wrong_password_unknown_user_truncation_and_bad_mac() {
        for (protocol, hex) in VECTORS {
            let mut packet = hex::decode(hex).unwrap();
            assert!(
                authenticate(&packet, protocol, 42, "wrong", &Mutex::new(HashMap::new()))
                    .await
                    .is_err()
            );
            assert!(authenticate(
                &packet,
                protocol,
                43,
                "user-secret",
                &Mutex::new(HashMap::new())
            )
            .await
            .is_err());
            for end in 0..79 {
                assert!(
                    authenticate(
                        &packet[..end],
                        protocol,
                        42,
                        "user-secret",
                        &Mutex::new(HashMap::new())
                    )
                    .await
                    .is_err(),
                    "truncation {end}"
                );
            }
            packet[78] ^= 1;
            assert!(authenticate(
                &packet,
                protocol,
                42,
                "user-secret",
                &Mutex::new(HashMap::new())
            )
            .await
            .is_err());
        }
    }

    #[tokio::test]
    async fn reject_truncated_or_corrupted_data_frames() {
        for (protocol, hex) in VECTORS {
            let packet = hex::decode(hex).unwrap();
            for end in 80..packet.len() {
                let (_, mut stream) = authenticate(
                    &packet[..end],
                    protocol,
                    42,
                    "user-secret",
                    &Mutex::new(HashMap::new()),
                )
                .await
                .unwrap();
                assert!(stream.read_to_end(&mut Vec::new()).await.is_err());
            }
            let mut corrupt = packet;
            *corrupt.last_mut().unwrap() ^= 1;
            let (_, mut stream) = authenticate(
                &corrupt,
                protocol,
                42,
                "user-secret",
                &Mutex::new(HashMap::new()),
            )
            .await
            .unwrap();
            assert!(stream.read_to_end(&mut Vec::new()).await.is_err());
        }
    }

    #[test]
    fn missing_or_unsupported_modes_fail_closed() {
        assert!(SsrSettings::new(&NodeInfo::default()).is_err());
        for protocol in ["origin", "auth_chain_a", "shadowsocks", ""] {
            assert!(SsrSettings::new(&NodeInfo {
                cipher: Some("aes-128-cfb".into()),
                network_settings: Some(serde_json::json!({"protocol":protocol})),
                ..Default::default()
            })
            .is_err());
        }
    }

    #[tokio::test]
    async fn panel_responses_preserve_ssr_settings() {
        for panel_type in ["sspanel", "v2board"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(socket.read_u8().await.unwrap());
                }
                let body = serde_json::json!({"data": {
                    "type":"shadowsocksr", "protocol":"auth_aes128_sha1", "method":"aes-256-cfb",
                    "password":"server-secret", "obfs":"plain", "server_port":8388
                }})
                .to_string();
                socket
                    .write_all(
                        format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        )
                        .as_bytes(),
                    )
                    .await
                    .unwrap();
            });
            let client = crate::panel::create_panel_client(
                panel_type,
                &format!("http://{address}"),
                "fixture",
            );
            let node = client.get_node_info(1).await.unwrap();
            assert_eq!(node.node_type, "shadowsocksr");
            let settings = SsrSettings::new(&node).unwrap();
            assert_eq!(settings.key_len, 32);
            assert_eq!(settings.salt, "auth_aes128_sha1");
            assert_eq!(settings.password.as_deref(), Some("server-secret"));
            server.await.unwrap();
        }
    }
}
