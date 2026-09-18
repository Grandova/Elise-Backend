use crate::conn::{bind_tcp_listener, read_proxy_protocol};
use crate::observability::AuditRecord;
use crate::panel::types::{NodeInfo, User};
use super::crypto::{CipherKind, ShadowsocksServerSession};
use super::ss2022::{self, Credential, Method, UserIndex};
use super::transport::Transport;
use super::udp::run_udp;
use crate::protocol::{Inbound, InboundContext};
use crate::proxy::router::MatchContext;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

pub struct ShadowsocksInbound {
    users: Arc<RwLock<HashMap<String, User>>>, // password -> User
    method: RwLock<Method>,
    credentials: Arc<RwLock<Arc<UserIndex>>>,
    crypto_context: Arc<shadowsocks::context::Context>,
}

impl Default for ShadowsocksInbound {
    fn default() -> Self {
        let mut crypto_context =
            shadowsocks::context::Context::new(shadowsocks::config::ServerType::Server);
        crypto_context.set_replay_attack_policy(shadowsocks::config::ReplayAttackPolicy::Reject);
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
            method: RwLock::new(Method::Legacy(CipherKind::ChaCha20Poly1305)),
            credentials: Arc::new(RwLock::new(Arc::new(UserIndex::default()))),
            crypto_context: Arc::new(crypto_context),
        }
    }
}

impl ShadowsocksInbound {
    pub fn new() -> Self {
        Self::default()
    }

    fn cipher(node_info: &NodeInfo) -> std::io::Result<Method> {
        Transport::validate(node_info)?;
        node_info
            .cipher
            .as_deref()
            .filter(|name| {
                matches!(
                    *name,
                    "aes-128-gcm"
                        | "gcm"
                        | "aes-gcm"
                        | "aes-192-gcm"
                        | "aes-256-gcm"
                        | "chacha20-ietf-poly1305"
                        | "2022-blake3-aes-128-gcm"
                        | "2022-blake3-aes-256-gcm"
                        | "2022-blake3-chacha20-poly1305"
                        | "none"
                        | "plain"
                )
            })
            .and_then(|name| name.parse().ok())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Missing or unsupported Shadowsocks cipher",
                )
            })
    }
}

#[async_trait]
impl Inbound for ShadowsocksInbound {
    fn protocol_type(&self) -> &'static str {
        "shadowsocks"
    }

    fn update_users(&self, users: Vec<User>) {
        let mut map = HashMap::new();
        let method = *self.method.read();
        let mut credentials = Vec::new();
        for u in users {
            let pwd = u.password.clone().unwrap_or_else(|| u.uuid.clone());
            match Credential::new(u.clone(), method, self.crypto_context.clone()) {
                Ok(credential) => {
                    credentials.push(Arc::new(credential));
                    map.insert(pwd, u);
                }
                Err(_) => warn!(user_id = u.id, "Rejected invalid Shadowsocks user key"),
            }
        }
        // Ambiguous credentials cannot be attributed to a single panel account.
        let mut counts = HashMap::new();
        for c in &credentials {
            *counts.entry(c.key.clone()).or_insert(0) += 1;
        }
        credentials.retain(|c| counts[&c.key] == 1);
        let user_index = Arc::new(UserIndex::new(credentials));
        *self.users.write() = map;
        *self.credentials.write() = user_index;
    }

    async fn start(
        &self,
        ctx: InboundContext,
        node_info: NodeInfo,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> std::io::Result<()> {
        let method = Self::cipher(&node_info)?;
        let transport = Arc::new(Transport::new(&node_info, &ctx.tls_manager).await?);
        *self.method.write() = method;
        let server_key = if method.is_aead_2022() {
            node_info
                .server_key
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(|key| ss2022::decode_key(key, method))
                .transpose()?
        } else {
            None
        };
        if server_key.is_some()
            && method
                == Method::Aead2022(
                    shadowsocks::crypto::CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305,
                )
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "SS2022 ChaCha20 does not support AES identity headers",
            ));
        }
        let server_key = Arc::new(server_key);
        let existing = self.users.read().values().cloned().collect();
        self.update_users(existing);

        let bind_addr = format!("{}:{}", ctx.listen_addr, ctx.port);
        let listener = if transport.is_quic() {
            None
        } else {
            Some(bind_tcp_listener(&bind_addr, ctx.global_config.mptcp).await?)
        };
        let socket = if transport.is_kcptun() {
            None
        } else {
            let s = std::net::UdpSocket::bind(&bind_addr)?;
            s.set_nonblocking(true)?;
            Some(s)
        };
        #[cfg(feature = "quic-protocols")]
        let quic = if transport.is_quic() {
            Some(super::quic::endpoint(
                socket.as_ref().unwrap().try_clone()?,
                transport
                    .quic_tls()
                    .ok_or_else(|| std::io::Error::other("QUIC requires TLS"))?,
            )?)
        } else {
            None
        };
        let udp = socket.map(|s| Arc::new(tokio::net::UdpSocket::from_std(s).unwrap()));
        info!(
            "Shadowsocks AEAD inbound listening on {} (cipher: {:?})",
            bind_addr, method
        );

        let users = self.credentials.clone();
        let cancel = CancellationToken::new();
        let mut tasks = JoinSet::new();
        let decrypt_semaphore = Arc::new(tokio::sync::Semaphore::new(
            ctx.global_config.ss_decrypt_concurrency.max(1),
        ));
        let ss_defense = if ctx.global_config.ss_invalid_access_enable {
            Arc::new(crate::security::AttackDefenseManager::new(
                ctx.global_config.ss_invalid_access_count,
                ctx.global_config.ss_invalid_access_duration,
                ctx.global_config.ss_invalid_access_forbidden_time,
            ))
        } else {
            ctx.defense.clone()
        };

        if transport.is_kcptun() {
            let mut kcptun_bin = None;
            for path in [
                "/root/elise-ss-test/bin/kcptun-server",
                "/usr/local/bin/kcptun-server",
                "/usr/bin/kcptun-server",
                "kcptun-server",
            ] {
                if std::path::Path::new(path).exists() {
                    kcptun_bin = Some(path.to_string());
                    break;
                }
            }
            if let Some(bin) = kcptun_bin {
                let key = transport.opts.get("key").cloned().unwrap_or_else(|| "testkey".into());
                let crypt = transport.opts.get("crypt").cloned().unwrap_or_else(|| "aes-128".into());
                let mode = transport.opts.get("mode").cloned().unwrap_or_else(|| "fast".into());
                let datashard = transport.opts.get("datashard").cloned().unwrap_or_else(|| "10".into());
                let parityshard = transport.opts.get("parityshard").cloned().unwrap_or_else(|| "3".into());
                let l_arg = format!("{}:{}", ctx.listen_addr, ctx.port);
                let t_arg = format!("127.0.0.1:{}", ctx.port);
                
                info!("Starting managed KCPTun server {} -> {}", l_arg, t_arg);
                if let Ok(mut child) = tokio::process::Command::new(bin)
                    .args(["-l", &l_arg, "-t", &t_arg, "-key", &key, "-crypt", &crypt, "-mode", &mode, "-datashard", &datashard, "-parityshard", &parityshard])
                    .spawn()
                {
                    let cancel_child = cancel.clone();
                    tasks.spawn(async move {
                        tokio::select! {
                            _ = cancel_child.cancelled() => {
                                let _ = child.kill().await;
                            }
                            _ = child.wait() => {}
                        }
                        Ok(())
                    });
                }
            }
        }

        #[cfg(feature = "quic-protocols")]
        let quic = {
            let decrypt_sem = decrypt_semaphore.clone();
            let defense_clone = ss_defense.clone();
            quic.map(|(endpoint, sender)| {
                let ctx = ctx.clone();
                let users = users.clone();
                let server_key = server_key.clone();
                let local_ip = udp.as_ref().and_then(|u| u.local_addr().ok().map(|addr| addr.ip()));
                tasks.spawn(super::quic::serve(
                    endpoint,
                    cancel.clone(),
                    move |stream, remote, cancel| {
                        handle_stream(
                            stream,
                            remote,
                            local_ip,
                            ctx.clone(),
                            users.clone(),
                            method,
                            server_key.clone(),
                            cancel,
                            decrypt_sem.clone(),
                            defense_clone.clone(),
                        )
                    },
                ));
                sender
            })
        };
        #[cfg(not(feature = "quic-protocols"))]
        let quic = None;
        if let Some(udp) = udp {
            tasks.spawn(run_udp(
                udp,
                ctx.clone(),
                users.clone(),
                method,
                server_key.clone(),
                cancel.clone(),
                quic,
            ));
        }

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Shadowsocks inbound on port {} stopping", ctx.port);
                    break;
                }
                result = tasks.join_next(), if !tasks.is_empty() => {
                    match result {
                        Some(Ok(Err(e))) => tracing::debug!(error = %e, "Shadowsocks session ended"),
                        Some(Err(e)) => warn!(error = %e, "Shadowsocks task failed"),
                        _ => {}
                    }
                }
                accept_res = async { listener.as_ref().unwrap().accept().await }, if listener.is_some() => {
                    let (stream, remote_addr) = match accept_res {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!("Shadowsocks accept error: {:?}", e);
                            continue;
                        }
                    };
                    let _ = stream.set_nodelay(true);

                    let ctx = ctx.clone();
                    let users = users.clone();
                    let server_key = server_key.clone();
                    let transport = transport.clone();
                    let cancel = cancel.clone();
                    let decrypt_sem = decrypt_semaphore.clone();
                    let defense_clone = ss_defense.clone();
                    tasks.spawn(async move {
                        handle_connection(stream, remote_addr, ctx, users, method, server_key, transport, cancel, decrypt_sem, defense_clone).await
                    });
                }
            }
        }
        cancel.cancel();
        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result {
                warn!(error = %e, "Shadowsocks shutdown task failed");
            }
        }
        Ok(())
    }
}

async fn read_target<S: tokio::io::AsyncRead + Unpin>(
    stream: &mut S,
) -> std::io::Result<(String, Option<IpAddr>, u16)> {
    let (host, ip) = match stream.read_u8().await? {
        1 => {
            let mut bytes = [0; 4];
            stream.read_exact(&mut bytes).await?;
            let ip = IpAddr::V4(Ipv4Addr::from(bytes));
            (ip.to_string(), Some(ip))
        }
        3 => {
            let len = stream.read_u8().await? as usize;
            if len == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Empty Shadowsocks domain",
                ));
            }
            let mut bytes = vec![0; len];
            stream.read_exact(&mut bytes).await?;
            let host = String::from_utf8(bytes).map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Invalid Shadowsocks domain",
                )
            })?;
            (host, None)
        }
        4 => {
            let mut bytes = [0; 16];
            stream.read_exact(&mut bytes).await?;
            let ip = IpAddr::V6(Ipv6Addr::from(bytes));
            (ip.to_string(), Some(ip))
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid Shadowsocks address type",
            ))
        }
    };
    let port = stream.read_u16().await?;
    Ok((host, ip, port))
}

#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    stream: TcpStream,
    mut remote_addr: SocketAddr,
    ctx: InboundContext,
    users: Arc<RwLock<Arc<UserIndex>>>,
    method: Method,
    server_key: Arc<Option<Vec<u8>>>,
    transport: Arc<Transport>,
    cancel: CancellationToken,
    decrypt_semaphore: Arc<tokio::sync::Semaphore>,
    ss_defense: Arc<crate::security::AttackDefenseManager>,
) -> std::io::Result<()> {
    let local_ip = stream.local_addr().ok().map(|s| s.ip());
    let defense_check = ss_defense.clone();
    let accept = async {
        let (src_opt, stream) =
            read_proxy_protocol(stream, ctx.global_config.get_proxy_protocol_mode()).await?;
        if let Some(src) = src_opt {
            remote_addr = src;
        }
        if defense_check.is_banned(remote_addr.ip()) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Client banned",
            ));
        }
        transport.accept(Box::new(stream), &ctx, local_ip).await
    };
    let stream = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = tokio::time::timeout(std::time::Duration::from_secs(15), accept) => result.map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "SS transport handshake timeout"))??,
    };
    let stream = match stream {
        super::transport::Accepted::Stream(stream) => stream,
        super::transport::Accepted::Restls(session) => {
            let (plain, framed) = tokio::io::duplex(64 * 1024);
            let relay = async { session.relay(framed).await.map_err(std::io::Error::other) };
            let handler = handle_stream(
                Box::new(plain),
                remote_addr,
                local_ip,
                ctx,
                users,
                method,
                server_key,
                cancel.clone(),
                decrypt_semaphore,
                ss_defense,
            );
            return tokio::select! {
                _ = cancel.cancelled() => Ok(()),
                result = async { tokio::try_join!(relay, handler).map(|_| ()) } => result,
            };
        }
        super::transport::Accepted::Fallback(mut client, mut decoy) => {
            return tokio::select! {
                _ = cancel.cancelled() => Ok(()),
                result = tokio::io::copy_bidirectional(&mut client, &mut decoy) => result.map(|_| ()),
            };
        }
    };
    if transport.is_http2() {
        let d_sem = decrypt_semaphore.clone();
        let s_def = ss_defense.clone();
        return super::h2::serve(
            stream,
            &transport.path,
            transport.grpc,
            cancel.clone(),
            move |stream| {
                handle_stream(
                    stream,
                    remote_addr,
                    local_ip,
                    ctx.clone(),
                    users.clone(),
                    method,
                    server_key.clone(),
                    cancel.clone(),
                    d_sem.clone(),
                    s_def.clone(),
                )
            },
        )
        .await;
    }
    if let Some(mux) = transport.mux {
        let d_sem = decrypt_semaphore.clone();
        let s_def = ss_defense.clone();
        return super::mux::serve(stream, mux, cancel.clone(), move |stream| {
            handle_stream(
                stream,
                remote_addr,
                local_ip,
                ctx.clone(),
                users.clone(),
                method,
                server_key.clone(),
                cancel.clone(),
                d_sem.clone(),
                s_def.clone(),
            )
        })
        .await;
    }
    handle_stream(
        stream,
        remote_addr,
        local_ip,
        ctx,
        users,
        method,
        server_key,
        cancel,
        decrypt_semaphore,
        ss_defense,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_stream(
    mut stream: crate::conn::BoxedStream,
    remote_addr: SocketAddr,
    local_ip: Option<IpAddr>,
    ctx: InboundContext,
    users: Arc<RwLock<Arc<UserIndex>>>,
    method: Method,
    server_key: Arc<Option<Vec<u8>>>,
    cancel: CancellationToken,
    decrypt_semaphore: Arc<tokio::sync::Semaphore>,
    ss_defense: Arc<crate::security::AttackDefenseManager>,
) -> std::io::Result<()> {
    if ss_defense.is_banned(remote_addr.ip()) {
        return Ok(());
    }

    let handshake = async {
        let user_index = users.read().clone();
        if method == Method::None {
            let user = user_index
                .credentials
                .first()
                .map(|c| c.user.clone())
                .unwrap_or_default();
            let (host, ip, port) = read_target(&mut stream).await?;
            return Ok((user, stream, host, ip, port));
        }
        if method.is_aead_2022() {
            let (credential, stream, address) =
                ss2022::handshake(Box::new(stream), method, server_key.as_deref(), &user_index)
                    .await?;
            let host = address.host();
            let ip = host.parse().ok();
            return Ok((credential.user.clone(), stream, host, ip, address.port()));
        }
        let Method::Legacy(cipher_kind) = method else {
            unreachable!()
        };
        let mut client_salt = vec![0; cipher_kind.salt_len()];
        stream.read_exact(&mut client_salt).await?;
        let mut enc_len_block = [0; 18];
        stream.read_exact(&mut enc_len_block).await?;

        let cached_user_id = ctx.ip_user_cache.get(&remote_addr.ip());
        let mut matched = None;

        // 1. Fast path for cached user (O(1) direct lookup, bypasses semaphore)
        if let Some(uid) = cached_user_id {
            if let Some(credential) = user_index.credentials.iter().find(|c| c.user.id == uid) {
                let mut session =
                    ShadowsocksServerSession::new(cipher_kind, &credential.key, &client_salt);
                let mut header = enc_len_block;
                if let Ok(len) = session.decrypt_length(&mut header) {
                    if credential
                        .context
                        .check_nonce_replay(method.replay_method(), &client_salt)
                        .is_ok()
                    {
                        matched = Some((credential.user.clone(), session, len));
                    }
                }
            }
        }

        // 2. Slow path: acquire concurrency semaphore and test remaining credentials
        if matched.is_none() {
            let _permit = decrypt_semaphore.acquire().await.map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::Interrupted, e)
            })?;
            for credential in &user_index.credentials {
                if Some(credential.user.id) == cached_user_id {
                    continue;
                }
                let mut session =
                    ShadowsocksServerSession::new(cipher_kind, &credential.key, &client_salt);
                let mut header = enc_len_block;
                if let Ok(len) = session.decrypt_length(&mut header) {
                    credential
                        .context
                        .check_nonce_replay(method.replay_method(), &client_salt)?;
                    matched = Some((credential.user.clone(), session, len));
                    break;
                }
            }
        }

        let (user, session, len) = matched.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Shadowsocks authentication failed",
            )
        })?;
        let mut stream = session.into_stream(stream, Some(len));
        let (host, ip, port) = read_target(&mut stream).await?;
        Ok::<_, std::io::Error>((user, stream, host, ip, port))
    };
    let result = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = tokio::time::timeout(std::time::Duration::from_secs(15), handshake) => result,
    };
    let (user, stream, target_host, target_ip, target_port) = match result {
        Ok(Ok(value)) => value,
        Ok(Err(err)) => {
            ss_defense.record_failure(remote_addr.ip());
            return Err(err);
        }
        Err(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Shadowsocks handshake timeout",
            ))
        }
    };
    ss_defense.record_success(remote_addr.ip());
    ctx.ip_user_cache.insert(remote_addr.ip(), user.id);
    if !ctx
        .device_limiter
        .check_and_record_async(user.id, remote_addr.ip())
        .await
    {
        return Ok(());
    }
    let _conn_guard = match ctx.conn_limiter.try_acquire(user.id) {
        Some(guard) => guard,
        None => return Ok(()),
    };
    let (sniffed, stream) = match crate::conn::sniff_and_detect_stream(
        stream,
        target_ip,
        ctx.global_config.domain_sniff,
        ctx.global_config.detect_packet,
        Some(&ctx.audit),
    )
    .await
    {
        Ok(res) => res,
        Err(_) => return Ok(()),
    };
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
    let dialer = ctx.router.dialer();
    let dial = dialer.dial(&outbound, dial_host, target_port, local_ip);
    let mut out_stream = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = tokio::time::timeout(std::time::Duration::from_secs(10), dial) => result.map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "Shadowsocks outbound timeout"))??,
    };
    let start_time = Instant::now();
    let mut stream = crate::conn::MonitoredStream::new(stream, user.id, remote_addr);
    let result = tokio::select! {
        _ = cancel.cancelled() => Ok((0, 0)),
        result = crate::conn::copy_bidirectional_throttled(
        &mut stream,
        &mut out_stream,
        user.id,
        Some(&ctx.rate_limiter),
        ) => result,
    };
    let (up_bytes, down_bytes) = stream.stats();
    (ctx.on_traffic)(user.id, up_bytes, down_bytes);
    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user.id,
        "shadowsocks",
        "tcp",
        &remote_addr.ip().to_string(),
        &target_host,
        target_port,
        up_bytes,
        down_bytes,
        start_time.elapsed().as_millis() as i64,
        &outbound.tag,
        if result.is_ok() { "connected" } else { "error" },
    ));
    result.map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn target_all_truncations_and_invalid_addresses() {
        for address in [
            vec![1, 127, 0, 0, 1, 0, 80],
            vec![3, 3, b'a', b'b', b'c', 0, 80],
            vec![4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 80],
        ] {
            for n in 0..address.len() {
                assert_eq!(
                    read_target(&mut &address[..n]).await.unwrap_err().kind(),
                    std::io::ErrorKind::UnexpectedEof
                );
            }
            assert_eq!(read_target(&mut &address[..]).await.unwrap().2, 80);
        }
        for bytes in [vec![0], vec![3, 0], vec![3, 1, 255, 0, 80]] {
            assert_eq!(
                read_target(&mut &bytes[..]).await.unwrap_err().kind(),
                std::io::ErrorKind::InvalidData
            );
        }
    }

    #[test]
    fn cipher_uses_panel_field_and_never_falls_back() {
        for name in [
            "aes-128-gcm",
            "gcm",
            "aes-192-gcm",
            "aes-256-gcm",
            "chacha20-ietf-poly1305",
            "none",
        ] {
            let node = NodeInfo {
                cipher: Some(name.into()),
                network: Some("tcp".into()),
                ..Default::default()
            };
            assert_eq!(
                ShadowsocksInbound::cipher(&node).unwrap(),
                name.parse::<Method>().unwrap()
            );
        }
        for name in [None, Some(""), Some("unknown")] {
            let node = NodeInfo {
                cipher: name.map(String::from),
                network: Some("aes-128-gcm".into()),
                ..Default::default()
            };
            assert_eq!(
                ShadowsocksInbound::cipher(&node).unwrap_err().kind(),
                std::io::ErrorKind::Unsupported
            );
        }
    }

    #[test]
    fn plugin_is_never_silently_ignored() {
        let node = NodeInfo {
            cipher: Some("aes-128-gcm".into()),
            plugin: Some("restls".into()),
            ..Default::default()
        };
        assert!(ShadowsocksInbound::cipher(&node).is_err());
        let node = NodeInfo {
            plugin_opts: Some(serde_json::json!({"host":"localhost", "password":"fixture"})),
            ..node
        };
        assert!(ShadowsocksInbound::cipher(&node).is_ok());

        for plugin in [None, Some(""), Some("None")] {
            let node = NodeInfo {
                cipher: Some("aes-128-gcm".into()),
                plugin: plugin.map(String::from),
                ..Default::default()
            };
            assert!(ShadowsocksInbound::cipher(&node).is_ok());
        }
        for plugin in ["shadow-tls", "unknown"] {
            let node = NodeInfo {
                cipher: Some("aes-128-gcm".into()),
                plugin: Some(plugin.into()),
                ..Default::default()
            };
            assert_eq!(
                ShadowsocksInbound::cipher(&node).unwrap_err().kind(),
                std::io::ErrorKind::Unsupported
            );
        }
        let node = NodeInfo {
            cipher: Some("aes-128-gcm".into()),
            plugin: Some("kcptun".into()),
            plugin_opts: Some(serde_json::json!({"key":"fixture", "crypt":"aes-128"})),
            ..Default::default()
        };
        assert!(ShadowsocksInbound::cipher(&node).is_ok());
    }
}
