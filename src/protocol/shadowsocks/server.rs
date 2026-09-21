use super::crypto::{CipherKind, ShadowsocksServerSession};
use super::ss2022::{self, Credential, Method, UserIndex};
use super::transport::Transport;
use super::udp::run_udp;
use crate::conn::{bind_tcp_listener, read_proxy_protocol, BoxedStream};
use crate::observability::AuditRecord;
use crate::panel::types::{NodeInfo, User};
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
    users: Arc<RwLock<HashMap<String, User>>>,
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

        let mut counts = HashMap::new();
        for c in &credentials {
            *counts.entry(c.key.clone()).or_insert(0) += 1;
        }
        credentials.retain(|c| counts[&c.key] == 1);
        if method
            == Method::Aead2022(shadowsocks::crypto::CipherKind::AEAD2022_BLAKE3_CHACHA20_POLY1305)
            && credentials.len() > 1
        {
            warn!(
                user_count = credentials.len(),
                first_user_id = credentials[0].user.id,
                "SS2022 ChaCha20-Poly1305 only supports single-user per SIP022/SIP023 specification (no EIH). Only the first user will be active; subsequent users cannot authenticate without EIH."
            );
        }
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
        let server_key = Arc::new(server_key);
        let existing = self.users.read().values().cloned().collect();
        self.update_users(existing);

        let bind_addr = format!("{}:{}", ctx.listen_addr, ctx.port);
        let listener = if transport.is_quic() {
            None
        } else {
            let tcp_bind = if transport.is_kcptun() {
                "127.0.0.1:0"
            } else {
                &bind_addr
            };
            Some(bind_tcp_listener(tcp_bind, ctx.global_config.mptcp).await?)
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

        let mut kcptun_child = if transport.is_kcptun() {
            let target = listener.as_ref().unwrap().local_addr()?.to_string();
            let args = transport.kcptun_args(&bind_addr, &target)?;
            let bin = transport
                .opts
                .get("bin")
                .or_else(|| transport.opts.get("server_path"))
                .map(String::as_str)
                .or_else(|| {
                    [
                        "kcptun-server",
                        "/usr/local/bin/kcptun-server",
                        "/usr/bin/kcptun-server",
                        "/etc/elise/kcptun-server",
                        "server_linux_amd64",
                        "server_linux_arm64",
                        "/usr/local/bin/server_linux_amd64",
                        "/usr/local/bin/server_linux_arm64",
                        "kcptun",
                    ]
                    .into_iter()
                    .find(|p| std::path::Path::new(p).is_file())
                })
                .unwrap_or("kcptun-server");
            info!(listen = %bind_addr, target = %target, bin = %bin, "Starting managed KCPTun server");
            let mut cmd = tokio::process::Command::new(bin);
            cmd.args(args)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .kill_on_drop(true);
            let mut child = cmd.spawn().map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!("Failed to start kcptun-server ({bin}): {e}. Run 'elise plugin kcptun' or install kcptun-server to /usr/local/bin/kcptun-server"),
                )
            })?;
            if let Some(stdout) = child.stdout.take() {
                tasks.spawn(async move {
                    use tokio::io::AsyncBufReadExt;
                    let mut reader = tokio::io::BufReader::new(stdout).lines();
                    while let Ok(Some(line)) = reader.next_line().await {
                        info!(target: "kcptun", "{line}");
                    }
                    Ok(())
                });
            }
            if let Some(stderr) = child.stderr.take() {
                tasks.spawn(async move {
                    use tokio::io::AsyncBufReadExt;
                    let mut reader = tokio::io::BufReader::new(stderr).lines();
                    while let Ok(Some(line)) = reader.next_line().await {
                        warn!(target: "kcptun", "{line}");
                    }
                    Ok(())
                });
            }
            Some(child)
        } else {
            None
        };

        #[cfg(feature = "quic-protocols")]
        let quic = {
            let decrypt_sem = decrypt_semaphore.clone();
            let defense_clone = ss_defense.clone();
            quic.map(|(endpoint, sender)| {
                let ctx = ctx.clone();
                let users = users.clone();
                let server_key = server_key.clone();
                let local_ip = udp
                    .as_ref()
                    .and_then(|u| u.local_addr().ok().map(|addr| addr.ip()));
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

        ctx.mark_ready();
        let result = loop {
            tokio::select! {
                status = async { kcptun_child.as_mut().unwrap().wait().await }, if kcptun_child.is_some() => {
                    let message = match status {
                        Ok(status) => format!("kcptun-server exited unexpectedly: {status}"),
                        Err(e) => format!("Failed to wait for kcptun-server: {e}"),
                    };
                    warn!("{message}");
                    break Err(std::io::Error::other(message));
                }
                _ = shutdown_rx.recv() => {
                    info!("Shadowsocks inbound on port {} stopping", ctx.port);
                    break Ok(());
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
                            warn!(stage = "tcp", error = %e, "Shadowsocks accept error");
                            continue;
                        }
                    };
                    tracing::debug!(
                        milestone = "tcp_accept_ok",
                        stage = "tcp",
                        client_addr = %remote_addr,
                        "Shadowsocks TCP connection accepted"
                    );
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
        };
        drop(listener);
        if let Some(child) = &mut kcptun_child {
            if child.try_wait()?.is_none() {
                child.kill().await?;
            }
        }
        cancel.cancel();
        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result {
                warn!(error = %e, "Shadowsocks shutdown task failed");
            }
        }
        result
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
    let stream = match tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = tokio::time::timeout(std::time::Duration::from_secs(15), accept) => result,
    } {
        Ok(Ok(stream)) => stream,
        Ok(Err(err)) => {
            tracing::warn!(
                stage = "tcp",
                client_addr = %remote_addr,
                error = %err,
                "Shadowsocks transport accept failed"
            );
            return Err(err);
        }
        Err(_) => {
            tracing::warn!(
                stage = "tcp",
                client_addr = %remote_addr,
                "Shadowsocks transport handshake timeout"
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "SS transport handshake timeout",
            ));
        }
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
    let (stream, auto_mux) = if transport.is_websocket() {
        if matches!(transport.mux, Some(super::mux::Mux::Smux)) {
            (stream, Some(super::mux::Mux::Smux))
        } else {
            let mut probe = [0u8; 14];
            let mut s = stream;
            match s.read_exact(&mut probe).await {
                Ok(_) => {
                    let is_vmess = {
                        let len = u16::from_be_bytes([probe[0], probe[1]]) as usize;
                        let status = probe[4];
                        let options = probe[5];
                        let net_type = probe[6];
                        let addr_type = probe[9];
                        (4..=512).contains(&len)
                            && status == 1
                            && (options & !3 == 0)
                            && net_type == 1
                            && matches!(addr_type, 1..=3)
                    };
                    let is_smux = probe[0] == 1 && probe[1] <= 3;
                    let prefixed =
                        Box::new(crate::conn::PrefixedStream::new(s, Some(probe.to_vec())))
                            as BoxedStream;
                    if is_vmess {
                        tracing::info!(
                            stage = "transport_mux_auto_detected",
                            detected_mux = "vmess",
                            probe_hex = %hex::encode(&probe),
                            client_addr = %remote_addr,
                            "Auto-detected VMess Mux on WebSocket stream, routing to mux::serve"
                        );
                        (prefixed, Some(super::mux::Mux::Vmess))
                    } else if is_smux && transport.is_gost() {
                        tracing::info!(
                            stage = "transport_mux_auto_detected",
                            detected_mux = "smux",
                            probe_hex = %hex::encode(&probe),
                            client_addr = %remote_addr,
                            "Auto-detected Smux on GOST WebSocket stream, routing to mux::serve"
                        );
                        (prefixed, Some(super::mux::Mux::Smux))
                    } else {
                        (prefixed, None)
                    }
                }
                Err(_) => (s, None),
            }
        }
    } else {
        (stream, transport.mux)
    };

    if let Some(mux) = auto_mux {
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

        let mut first_chunk = Vec::with_capacity(client_salt.len() + 18);
        first_chunk.extend_from_slice(&client_salt);
        first_chunk.extend_from_slice(&enc_len_block);
        let first_read_len = first_chunk.len();
        let first_64_sha256 = {
            use sha2::{Digest, Sha256};
            hex::encode(Sha256::digest(&first_chunk))
        };
        let first_16_hex = hex::encode(&first_chunk[..16.min(first_chunk.len())]);

        tracing::debug!(
            stage = "shadowsocks_handshake",
            first_read_len,
            transport_payload_len = first_read_len,
            transport_payload_first_64_sha256 = %first_64_sha256,
            first_16_bytes_hex = %first_16_hex,
            cipher = ?cipher_kind,
            key_len = cipher_kind.key_len(),
            salt_len = cipher_kind.salt_len(),
            client_addr = %remote_addr,
            "Shadowsocks initial stream read completed, evaluating credentials"
        );

        let cached_user_id = ctx.ip_user_cache.get(&remote_addr.ip());
        let mut matched = None;

        if let Some(uid) = cached_user_id {
            if let Some(credential) = user_index.credentials.iter().find(|c| c.user.id == uid) {
                let key_fingerprint = hex::encode(&blake3::hash(&credential.key).as_bytes()[..8]);
                let mut session =
                    ShadowsocksServerSession::new(cipher_kind, &credential.key, &client_salt);
                let mut header = enc_len_block;
                if let Ok(len) = session.decrypt_length(&mut header) {
                    if credential
                        .context
                        .check_nonce_replay(method.replay_method(), &client_salt)
                        .is_ok()
                    {
                        tracing::debug!(
                            milestone = "shadowsocks_auth_ok",
                            user_id = credential.user.id,
                            cipher = ?cipher_kind,
                            key_len = credential.key.len(),
                            derived_key_fingerprint = %key_fingerprint,
                            fast_path = true,
                            "Shadowsocks authenticated via cached user"
                        );
                        matched = Some((credential.user.clone(), session, len));
                    }
                }
            }
        }

        if matched.is_none() {
            let _permit = decrypt_semaphore
                .acquire()
                .await
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Interrupted, e))?;
            for credential in &user_index.credentials {
                if Some(credential.user.id) == cached_user_id {
                    continue;
                }
                let key_fingerprint = hex::encode(&blake3::hash(&credential.key).as_bytes()[..8]);
                let mut session =
                    ShadowsocksServerSession::new(cipher_kind, &credential.key, &client_salt);
                let mut header = enc_len_block;
                if let Ok(len) = session.decrypt_length(&mut header) {
                    credential
                        .context
                        .check_nonce_replay(method.replay_method(), &client_salt)?;
                    tracing::debug!(
                        milestone = "shadowsocks_auth_ok",
                        user_id = credential.user.id,
                        cipher = ?cipher_kind,
                        key_len = credential.key.len(),
                        derived_key_fingerprint = %key_fingerprint,
                        fast_path = false,
                        "Shadowsocks authenticated via credential search"
                    );
                    matched = Some((credential.user.clone(), session, len));
                    break;
                }
            }
        }

        let (user, session, len) = matched.ok_or_else(|| {
            let candidate_fingerprints = user_index
                .credentials
                .iter()
                .map(|c| {
                    format!(
                        "{}:{}",
                        c.user.id,
                        hex::encode(&blake3::hash(&c.key).as_bytes()[..8])
                    )
                })
                .collect::<Vec<_>>();
            tracing::warn!(
                stage = "shadowsocks_auth_failed",
                cipher = ?cipher_kind,
                key_len = cipher_kind.key_len(),
                client_addr = %remote_addr,
                first_read_len,
                transport_payload_len = first_read_len,
                transport_payload_first_64_sha256 = %first_64_sha256,
                first_16_bytes_hex = %first_16_hex,
                candidate_count = user_index.credentials.len(),
                candidate_fingerprints = ?candidate_fingerprints,
                "Shadowsocks authentication failed: no user credentials could decrypt initial frame"
            );
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
    let mut out_stream = match tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = tokio::time::timeout(std::time::Duration::from_secs(10), dial) => result,
    } {
        Ok(Ok(stream)) => {
            tracing::debug!(
                milestone = "backend_connect_ok",
                stage = "backend_connect",
                user_id = user.id,
                target_host = %target_host,
                target_port = target_port,
                "Shadowsocks backend connection established"
            );
            stream
        }
        Ok(Err(e)) => {
            tracing::warn!(
                stage = "backend_connect",
                user_id = user.id,
                target_host = %target_host,
                target_port = target_port,
                error = %e,
                "Shadowsocks backend connection failed"
            );
            return Err(e);
        }
        Err(_) => {
            tracing::warn!(
                stage = "backend_connect",
                user_id = user.id,
                target_host = %target_host,
                target_port = target_port,
                "Shadowsocks outbound dial timeout"
            );
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Shadowsocks outbound timeout",
            ));
        }
    };
    let start_time = Instant::now();
    let mut stream = crate::conn::MonitoredStream::new(stream, user.id, remote_addr);
    let _traffic = stream.traffic_guard(ctx.on_traffic.clone());
    let result = tokio::select! {
        _ = cancel.cancelled() => Ok((0, 0)),
        result = crate::conn::copy_bidirectional_throttled(
        &mut stream,
        &mut out_stream,
        user.id,
        Some(&ctx.rate_limiter),
        ctx.global_config.tcp_timeout,
        ) => result,
    };
    let (up_bytes, down_bytes) = stream.stats();
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
    async fn kcptun_options_reach_server_or_fail_explicitly() {
        let mut opts = serde_json::Map::new();
        for name in [
            "mtu",
            "sndwnd",
            "rcvwnd",
            "dscp",
            "nodelay",
            "interval",
            "resend",
            "nc",
            "sockbuf",
            "smuxbuf",
            "framesize",
            "streambuf",
            "smuxver",
            "keepalive",
            "ratelimit",
        ] {
            opts.insert(name.into(), serde_json::json!(2));
        }
        opts.insert("nocomp".into(), serde_json::json!(true));
        opts.insert("acknodelay".into(), serde_json::json!(false));
        opts.insert("key".into(), serde_json::json!("a key with spaces"));
        opts.insert("server".into(), serde_json::json!(true));
        let node = NodeInfo {
            plugin: Some("kcptun".into()),
            plugin_opts: Some(opts.into()),
            ..Default::default()
        };
        let transport = Transport::new(
            &node,
            &crate::security::TLSManager::new(false, "localhost".into()),
        )
        .await
        .unwrap();
        let args = transport
            .kcptun_args("127.0.0.1:3000", "127.0.0.1:4000")
            .unwrap();
        for name in [
            "mtu",
            "sndwnd",
            "rcvwnd",
            "dscp",
            "nodelay",
            "interval",
            "resend",
            "nc",
            "sockbuf",
            "smuxbuf",
            "framesize",
            "streambuf",
            "smuxver",
            "keepalive",
            "ratelimit",
        ] {
            assert!(args
                .windows(2)
                .any(|v| v == [format!("--{name}"), "2".into()]));
        }
        assert!(args.contains(&"--nocomp=true".into()));
        assert!(args.contains(&"--acknodelay=false".into()));
        assert!(args.contains(&"a key with spaces".into()));
        for name in ["conn", "autoexpire", "scavengettl"] {
            let node = NodeInfo {
                plugin: Some("kcptun".into()),
                plugin_opts: Some(serde_json::json!({name:1})),
                ..Default::default()
            };
            assert_eq!(
                Transport::validate(&node).unwrap_err().kind(),
                std::io::ErrorKind::Unsupported
            );
        }
    }

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

    #[tokio::test]
    async fn test_simple_obfs_aliases_and_options_mapping() {
        use super::super::transport::Mode;

        let aliases = [
            "obfs",
            "simple-obfs",
            "simple_obfs",
            "simple obfs",
            "Simple Obfs",
            "Simple-Obfs",
            "Simple_Obfs",
            "simpleobfs",
            "obfs-local",
            "obfs-server",
            "obfs_local",
            "obfs_server",
            "obfslocal",
            "obfsserver",
        ];

        for alias in aliases {
            let node = NodeInfo {
                plugin: Some(alias.into()),
                plugin_opts: Some("obfs=http;obfs-host=www.bing.com".into()),
                ..Default::default()
            };
            assert!(
                Transport::validate(&node).is_ok(),
                "Transport::validate should succeed for alias: {alias}"
            );
            let (mode, tls, opts) =
                Transport::options(&node).expect("options parsing should succeed");
            assert_eq!(
                mode,
                Mode::ObfsHttp,
                "mode should be ObfsHttp for alias: {alias}"
            );
            assert!(!tls, "simple-obfs plain http should not use tls acceptor");

            assert_eq!(opts.get("obfs").map(String::as_str), Some("http"));
            assert_eq!(opts.get("mode").map(String::as_str), Some("http"));
            assert_eq!(
                opts.get("obfs-host").map(String::as_str),
                Some("www.bing.com")
            );
            assert_eq!(opts.get("host").map(String::as_str), Some("www.bing.com"));
        }

        let node_reversed = NodeInfo {
            plugin: Some("obfs".into()),
            plugin_opts: Some("mode=http;host=www.bing.com".into()),
            ..Default::default()
        };
        let (mode, _, opts) = Transport::options(&node_reversed).unwrap();
        assert_eq!(mode, Mode::ObfsHttp);
        assert_eq!(opts.get("obfs").map(String::as_str), Some("http"));
        assert_eq!(opts.get("mode").map(String::as_str), Some("http"));
        assert_eq!(
            opts.get("obfs-host").map(String::as_str),
            Some("www.bing.com")
        );
        assert_eq!(opts.get("host").map(String::as_str), Some("www.bing.com"));

        let node_tls = NodeInfo {
            plugin: Some("obfs".into()),
            plugin_opts: Some("obfs=tls;obfs-host=www.bing.com".into()),
            ..Default::default()
        };
        let (mode, _, opts) = Transport::options(&node_tls).unwrap();
        assert_eq!(mode, Mode::ObfsTls);
        assert_eq!(opts.get("obfs").map(String::as_str), Some("tls"));
        assert_eq!(opts.get("mode").map(String::as_str), Some("tls"));

        let node_default = NodeInfo {
            plugin: Some("obfs".into()),
            plugin_opts: Some("obfs-host=www.bing.com".into()),
            ..Default::default()
        };
        let (mode, _, opts) = Transport::options(&node_default).unwrap();
        assert_eq!(mode, Mode::ObfsHttp);
        assert_eq!(opts.get("obfs").map(String::as_str), Some("http"));
        assert_eq!(opts.get("mode").map(String::as_str), Some("http"));

        let node_json = NodeInfo {
            plugin: Some("obfs".into()),
            plugin_opts: Some(serde_json::json!({
                "obfs": "http",
                "obfs-host": "www.bing.com"
            })),
            ..Default::default()
        };
        let (mode, _, opts) = Transport::options(&node_json).unwrap();
        assert_eq!(mode, Mode::ObfsHttp);
        assert_eq!(opts.get("host").map(String::as_str), Some("www.bing.com"));

        let node_bad_mode = NodeInfo {
            plugin: Some("obfs".into()),
            plugin_opts: Some("obfs=grpc;obfs-host=www.bing.com".into()),
            ..Default::default()
        };
        assert_eq!(
            Transport::validate(&node_bad_mode).unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );

        let node_bad_opt = NodeInfo {
            plugin: Some("obfs".into()),
            plugin_opts: Some("obfs=http;unsupported_opt=1".into()),
            ..Default::default()
        };
        assert_eq!(
            Transport::validate(&node_bad_opt).unwrap_err().kind(),
            std::io::ErrorKind::Unsupported
        );

        let node_unknown_plugin = NodeInfo {
            plugin: Some("unknown_plugin".into()),
            plugin_opts: Some("obfs=http;obfs-host=www.bing.com".into()),
            ..Default::default()
        };
        assert_eq!(
            Transport::validate(&node_unknown_plugin)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::Unsupported
        );
    }

    #[tokio::test]
    async fn test_node_33_simulation_realistic_xboard_config() {
        let node33 = NodeInfo {
            id: 33,
            node_type: "shadowsocks".into(),
            cipher: Some("aes-128-gcm".into()),
            server_port: 10033,
            plugin: Some("obfs".into()),
            plugin_opts: Some("obfs=http;obfs-host=www.bing.com".into()),
            ..Default::default()
        };

        assert!(Transport::validate(&node33).is_ok());

        let method =
            ShadowsocksInbound::cipher(&node33).expect("cipher should resolve successfully");
        assert_eq!(
            method,
            "aes-128-gcm"
                .parse::<super::super::ss2022::Method>()
                .unwrap()
        );

        let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
        let transport = Transport::new(&node33, &tls_manager)
            .await
            .expect("Transport::new must succeed");
        assert!(transport.is_obfs(), "transport must be identified as obfs");
        assert!(
            transport.is_obfs_http(),
            "transport must be identified as obfs http"
        );
        assert_eq!(
            transport.host(),
            Some("www.bing.com"),
            "host must resolve to www.bing.com"
        );
        assert_eq!(transport.opts.get("obfs").map(String::as_str), Some("http"));
        assert_eq!(transport.opts.get("mode").map(String::as_str), Some("http"));
        assert_eq!(
            transport.opts.get("obfs-host").map(String::as_str),
            Some("www.bing.com")
        );
        assert_eq!(
            transport.opts.get("host").map(String::as_str),
            Some("www.bing.com")
        );

        let mut node33_ss2022 = node33.clone();
        node33_ss2022.cipher = Some("2022-blake3-aes-128-gcm".into());
        assert!(Transport::validate(&node33_ss2022).is_ok());
        let method2022 =
            ShadowsocksInbound::cipher(&node33_ss2022).expect("SS2022 cipher should resolve");
        assert_eq!(
            method2022,
            "2022-blake3-aes-128-gcm"
                .parse::<super::super::ss2022::Method>()
                .unwrap()
        );

        let (client_stream, server_stream) = tokio::io::duplex(4096);
        let client_task = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut client = client_stream;

            let request = b"GET / HTTP/1.1\r\nHost: www.bing.com\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n";
            client.write_all(request).await.unwrap();
            client
                .write_all(b"shadowsocks-payload-bytes")
                .await
                .unwrap();
            client.flush().await.unwrap();

            let mut resp = [0u8; 1024];
            let n = client.read(&mut resp).await.unwrap();
            let resp_str = std::str::from_utf8(&resp[..n]).unwrap();
            assert!(resp_str.starts_with("HTTP/1.1 101 Switching Protocols"));
            assert!(resp_str.ends_with("server-echo-bytes"));
        });

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut unmasked = crate::protocol::shadowsocks::simple_obfs::accept_http(
            Box::new(server_stream),
            transport.host(),
        )
        .await
        .expect("accept_http should successfully unmask HTTP simple-obfs");

        let mut payload = [0u8; 25];
        unmasked
            .read_exact(&mut payload)
            .await
            .expect("read payload");
        assert_eq!(&payload, b"shadowsocks-payload-bytes");

        unmasked
            .write_all(b"server-echo-bytes")
            .await
            .expect("write server echo");
        unmasked.flush().await.expect("flush server echo");

        client_task.await.unwrap();
    }

    fn generate_test_cert_and_key(
        domain: &str,
    ) -> (String, String, rustls::pki_types::CertificateDer<'static>) {
        let mut params =
            rcgen::CertificateParams::new(vec![domain.to_string(), "localhost".to_string()])
                .unwrap();
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2034, 1, 1);
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();
        let cert_der = rustls::pki_types::CertificateDer::from(cert.der().to_vec());
        (cert_pem, key_pem, cert_der)
    }

    fn test_context() -> InboundContext {
        let geo = Arc::new(crate::geo::GeoEngine::default());
        let dialer = Arc::new(crate::proxy::router::OutboundDialer::new(
            Arc::new(crate::dns::DNSResolver::default()),
            None,
            None,
            false,
        ));
        InboundContext {
            ready: None,
            node_id: 1,
            listen_addr: "127.0.0.1".into(),
            port: 0,
            router: Arc::new(crate::proxy::router::Router::new(
                Default::default(),
                dialer,
                geo.clone(),
            )),
            rate_limiter: Arc::new(crate::limiter::RateLimiter::new()),
            conn_limiter: Arc::new(crate::limiter::ConnectionLimiter::new()),
            device_limiter: Arc::new(crate::limiter::DeviceLimiter::new(60, 32, 128, None)),
            audit: Arc::new(crate::security::AuditController::new("", "", geo)),
            defense: Arc::new(crate::security::AttackDefenseManager::default()),
            tls_manager: Arc::new(crate::security::TLSManager::new(false, "localhost".into())),
            audit_logger: Arc::new(crate::observability::AuditLogger::new(None::<&str>)),
            clickhouse_logger: Arc::new(crate::observability::ClickHouseLogger::new(
                false,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                None,
            )),
            on_traffic: Arc::new(|_, _, _| ()),
            global_config: Arc::new(crate::config::GlobalConfig::default()),
            ip_user_cache: Arc::new(crate::limiter::IpUserCache::new(24, false, "")),
        }
    }

    #[tokio::test]
    async fn test_v2ray_plugin_websocket_notls_regression() {
        let node = NodeInfo {
            id: 34,
            node_type: "shadowsocks".into(),
            cipher: Some("aes-128-gcm".into()),
            server_port: 10034,
            plugin: Some("v2ray-plugin".into()),
            plugin_opts: Some("mode=websocket;host=www.bing.com;path=/".into()),
            ..Default::default()
        };

        assert!(Transport::validate(&node).is_ok());
        let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
        let transport = Transport::new(&node, &tls_manager)
            .await
            .expect("Transport::new must succeed");

        assert!(transport.is_websocket());
        assert!(!transport.is_tls());
        assert_eq!(transport.host(), Some("www.bing.com"));
        assert_eq!(transport.path, "/");

        let (client, server) = tokio::io::duplex(64 * 1024);
        let ctx = test_context();

        let transport_clone = Arc::new(transport);
        let server_transport = transport_clone.clone();
        let server_task = tokio::spawn(async move {
            let accepted = server_transport
                .accept(Box::new(server), &ctx, None)
                .await
                .expect("server transport accept");
            let mut stream = match accepted {
                super::super::transport::Accepted::Stream(s) => s,
                _ => panic!("Expected Accepted::Stream"),
            };

            let mut buf = [0u8; 18];
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            stream
                .read_exact(&mut buf)
                .await
                .expect("server read exact");
            assert_eq!(&buf, b"shadowsocks-client");

            stream
                .write_all(b"shadowsocks-server")
                .await
                .expect("server write");
            stream.flush().await.expect("server flush");
        });

        let req = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri("ws://www.bing.com/")
            .header("Host", "www.bing.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(())
            .unwrap();

        let (mut client_ws, _response) = tokio_tungstenite::client_async(req, client)
            .await
            .expect("client ws upgrade handshake");

        use futures_util::{SinkExt, StreamExt};
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                bytes::Bytes::from_static(b"shadowsocks-client"),
            ))
            .await
            .expect("client send");

        let reply = client_ws.next().await.unwrap().unwrap();
        assert_eq!(
            reply,
            tokio_tungstenite::tungstenite::Message::Binary(bytes::Bytes::from_static(
                b"shadowsocks-server"
            ))
        );

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_v2ray_plugin_websocket_tls_handshake() {
        let (cert_pem, key_pem, cert_der) = generate_test_cert_and_key("node.example.com");

        let node = NodeInfo {
            id: 35,
            node_type: "shadowsocks".into(),
            cipher: Some("aes-128-gcm".into()),
            server_port: 10035,
            plugin: Some("v2ray-plugin".into()),
            plugin_opts: Some("mode=websocket;host=node.example.com;path=/ws;tls=true".into()),
            cert_config: Some(serde_json::json!({
                "cert": cert_pem,
                "key": key_pem,
            })),
            ..Default::default()
        };

        assert!(Transport::validate(&node).is_ok());
        let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
        let transport = Transport::new(&node, &tls_manager)
            .await
            .expect("Transport::new must resolve cert from cert_config");

        assert!(transport.is_websocket());
        assert!(transport.is_tls());
        assert_eq!(transport.host(), Some("node.example.com"));
        assert_eq!(transport.path, "/ws");

        let (client, server) = tokio::io::duplex(64 * 1024);
        let ctx = test_context();

        let transport = Arc::new(transport);
        let server_transport = transport.clone();
        let server_task = tokio::spawn(async move {
            let accepted = server_transport
                .accept(Box::new(server), &ctx, None)
                .await
                .expect("server transport accept with TLS");
            let mut stream = match accepted {
                super::super::transport::Accepted::Stream(s) => s,
                _ => panic!("Expected Accepted::Stream"),
            };

            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 12];
            stream.read_exact(&mut buf).await.expect("read from client");
            assert_eq!(&buf, b"client-hello");
            stream
                .write_all(b"server-world")
                .await
                .expect("write reply");
            stream.flush().await.expect("flush");
        });

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der).expect("add test root cert");
        let mut client_tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls_config));
        let server_name = rustls::pki_types::ServerName::try_from("node.example.com")
            .unwrap()
            .to_owned();
        let tls_client = connector
            .connect(server_name, client)
            .await
            .expect("client tls handshake");

        assert_eq!(
            tls_client.get_ref().1.alpn_protocol(),
            Some(b"http/1.1".as_ref())
        );

        let req = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri("wss://node.example.com/ws")
            .header("Host", "node.example.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(())
            .unwrap();

        let (mut client_ws, _resp) = tokio_tungstenite::client_async(req, tls_client)
            .await
            .expect("client ws upgrade over tls");

        use futures_util::{SinkExt, StreamExt};
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                bytes::Bytes::from_static(b"client-hello"),
            ))
            .await
            .expect("send message");

        let reply = client_ws.next().await.unwrap().unwrap();
        assert_eq!(
            reply,
            tokio_tungstenite::tungstenite::Message::Binary(bytes::Bytes::from_static(
                b"server-world"
            ))
        );

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_v2ray_plugin_websocket_tls_50mb_transfer_and_sha256() {
        use sha2::{Digest, Sha256};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (cert_pem, key_pem, cert_der) = generate_test_cert_and_key("stream.example.com");

        let node = NodeInfo {
            id: 36,
            node_type: "shadowsocks".into(),
            cipher: Some("aes-128-gcm".into()),
            server_port: 10036,
            plugin: Some("v2ray-plugin".into()),
            plugin_opts: Some(
                "mode=websocket;host=stream.example.com;path=/stream;tls=true".into(),
            ),
            cert_config: Some(serde_json::json!({
                "cert": cert_pem,
                "key": key_pem,
            })),
            ..Default::default()
        };

        let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
        let transport = Arc::new(
            Transport::new(&node, &tls_manager)
                .await
                .expect("Transport::new"),
        );

        let (client, server) = tokio::io::duplex(256 * 1024);
        let ctx = test_context();

        const TOTAL_BYTES: usize = 50 * 1024 * 1024;
        const CHUNK_SIZE: usize = 64 * 1024;

        let mut sample_chunk = vec![0u8; CHUNK_SIZE];
        for (i, b) in sample_chunk.iter_mut().enumerate() {
            *b = (i % 251) as u8;
        }

        let server_transport = transport.clone();
        let server_task = tokio::spawn(async move {
            let accepted = server_transport
                .accept(Box::new(server), &ctx, None)
                .await
                .expect("server transport accept");
            let mut stream = match accepted {
                super::super::transport::Accepted::Stream(s) => s,
                _ => panic!("Expected Stream"),
            };

            let mut hasher = Sha256::new();
            let mut read_buf = vec![0u8; CHUNK_SIZE];
            let mut total_read = 0;
            while total_read < TOTAL_BYTES {
                let to_read = (TOTAL_BYTES - total_read).min(CHUNK_SIZE);
                let n = stream
                    .read(&mut read_buf[..to_read])
                    .await
                    .expect("server read chunk");
                if n == 0 {
                    break;
                }
                hasher.update(&read_buf[..n]);
                total_read += n;
            }
            assert_eq!(total_read, TOTAL_BYTES, "server must read all 50MB");
            let server_hash = hasher.finalize();

            stream
                .write_all(&server_hash)
                .await
                .expect("server write hash");
            stream.flush().await.expect("server flush hash");
            server_hash
        });

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der).expect("add test root cert");
        let mut client_tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls_config));
        let server_name = rustls::pki_types::ServerName::try_from("stream.example.com")
            .unwrap()
            .to_owned();
        let tls_client = connector
            .connect(server_name, client)
            .await
            .expect("client tls handshake");

        let req = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri("wss://stream.example.com/stream")
            .header("Host", "stream.example.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(())
            .unwrap();

        let (mut client_ws, _resp) = tokio_tungstenite::client_async(req, tls_client)
            .await
            .expect("client ws handshake");

        use futures_util::{SinkExt, StreamExt};
        let mut client_hasher = Sha256::new();
        let mut total_sent = 0;
        while total_sent < TOTAL_BYTES {
            let to_send = (TOTAL_BYTES - total_sent).min(CHUNK_SIZE);
            client_ws
                .send(tokio_tungstenite::tungstenite::Message::Binary(
                    bytes::Bytes::copy_from_slice(&sample_chunk[..to_send]),
                ))
                .await
                .expect("client send");
            client_hasher.update(&sample_chunk[..to_send]);
            total_sent += to_send;
        }
        client_ws.flush().await.expect("client flush");
        let client_hash = client_hasher.finalize();

        let msg = client_ws.next().await.unwrap().expect("read hash msg");
        let received_bytes = msg.into_data();

        let server_hash = server_task.await.unwrap();
        assert_eq!(
            &server_hash[..],
            &client_hash[..],
            "Server computed hash matches client hash"
        );
        assert_eq!(
            &received_bytes[..],
            &client_hash[..],
            "Echoed hash matches client hash"
        );
    }

    #[tokio::test]
    async fn test_v2ray_plugin_websocket_tls_half_close() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (cert_pem, key_pem, cert_der) = generate_test_cert_and_key("halfclose.example.com");

        let node = NodeInfo {
            id: 37,
            node_type: "shadowsocks".into(),
            cipher: Some("aes-128-gcm".into()),
            server_port: 10037,
            plugin: Some("v2ray-plugin".into()),
            plugin_opts: Some(
                "mode=websocket;host=halfclose.example.com;path=/half;tls=true".into(),
            ),
            cert_config: Some(serde_json::json!({
                "cert": cert_pem,
                "key": key_pem,
            })),
            ..Default::default()
        };

        let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
        let transport = Arc::new(
            Transport::new(&node, &tls_manager)
                .await
                .expect("Transport::new"),
        );

        let (client, server) = tokio::io::duplex(64 * 1024);
        let ctx = test_context();

        let server_transport = transport.clone();
        let server_task = tokio::spawn(async move {
            let accepted = server_transport
                .accept(Box::new(server), &ctx, None)
                .await
                .expect("server transport accept");
            let mut stream = match accepted {
                super::super::transport::Accepted::Stream(s) => s,
                _ => panic!("Expected Stream"),
            };

            let mut buf = [0u8; 10];
            stream.read_exact(&mut buf).await.expect("read 10 bytes");
            assert_eq!(&buf, b"ping-first");

            stream
                .write_all(b"server-goodbye")
                .await
                .expect("server write goodbye");
            stream.flush().await.expect("server flush");

            stream.shutdown().await.expect("server shutdown");
        });

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der).expect("add test root cert");
        let mut client_tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls_config));
        let server_name = rustls::pki_types::ServerName::try_from("halfclose.example.com")
            .unwrap()
            .to_owned();
        let tls_client = connector
            .connect(server_name, client)
            .await
            .expect("client tls handshake");

        let req = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri("wss://halfclose.example.com/half")
            .header("Host", "halfclose.example.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(())
            .unwrap();

        let (mut client_ws, _resp) = tokio_tungstenite::client_async(req, tls_client)
            .await
            .expect("client ws handshake");

        use futures_util::{SinkExt, StreamExt};
        client_ws
            .send(tokio_tungstenite::tungstenite::Message::Binary(
                bytes::Bytes::from_static(b"ping-first"),
            ))
            .await
            .expect("client send ping-first");

        let reply = client_ws.next().await.unwrap().expect("read server reply");
        assert_eq!(
            reply,
            tokio_tungstenite::tungstenite::Message::Binary(bytes::Bytes::from_static(
                b"server-goodbye"
            ))
        );

        let close_msg = client_ws.next().await;
        assert!(matches!(
            close_msg,
            None | Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_)))
        ));

        let _ = client_ws.close(None).await;

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_v2ray_plugin_websocket_tls_reconnect() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (cert_pem, key_pem, cert_der) = generate_test_cert_and_key("reconnect.example.com");

        let node = NodeInfo {
            id: 38,
            node_type: "shadowsocks".into(),
            cipher: Some("aes-128-gcm".into()),
            server_port: 10038,
            plugin: Some("v2ray-plugin".into()),
            plugin_opts: Some(
                "mode=websocket;host=reconnect.example.com;path=/reconnect;tls=true".into(),
            ),
            cert_config: Some(serde_json::json!({
                "cert": cert_pem,
                "key": key_pem,
            })),
            ..Default::default()
        };

        let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
        let transport = Arc::new(
            Transport::new(&node, &tls_manager)
                .await
                .expect("Transport::new"),
        );
        let ctx = test_context();

        for session_id in 1..=3 {
            let (client, server) = tokio::io::duplex(64 * 1024);
            let server_transport = transport.clone();
            let ctx_clone = ctx.clone();

            let server_task = tokio::spawn(async move {
                let accepted = server_transport
                    .accept(Box::new(server), &ctx_clone, None)
                    .await
                    .expect("server transport accept");
                let mut stream = match accepted {
                    super::super::transport::Accepted::Stream(s) => s,
                    _ => panic!("Expected Stream"),
                };

                let mut buf = [0u8; 8];
                stream.read_exact(&mut buf).await.expect("server read");
                let expected = format!("client-{session_id}");
                assert_eq!(&buf, expected.as_bytes());

                let reply = format!("server-{session_id}");
                stream
                    .write_all(reply.as_bytes())
                    .await
                    .expect("server write");
                stream.flush().await.expect("server flush");
            });

            let mut root_store = rustls::RootCertStore::empty();
            root_store.add(cert_der.clone()).expect("add root cert");
            let mut client_tls_config = rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            client_tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

            let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls_config));
            let server_name = rustls::pki_types::ServerName::try_from("reconnect.example.com")
                .unwrap()
                .to_owned();
            let tls_client = connector
                .connect(server_name, client)
                .await
                .expect("tls handshake");

            let req = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
                .uri("wss://reconnect.example.com/reconnect")
                .header("Host", "reconnect.example.com")
                .header("Connection", "Upgrade")
                .header("Upgrade", "websocket")
                .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
                .header("Sec-WebSocket-Version", "13")
                .body(())
                .unwrap();

            let (mut client_ws, _resp) = tokio_tungstenite::client_async(req, tls_client)
                .await
                .expect("client ws handshake");

            use futures_util::{SinkExt, StreamExt};
            let client_msg = format!("client-{session_id}");
            client_ws
                .send(tokio_tungstenite::tungstenite::Message::Binary(
                    bytes::Bytes::copy_from_slice(client_msg.as_bytes()),
                ))
                .await
                .expect("client send");

            let reply = client_ws.next().await.unwrap().unwrap();
            let expected_reply = format!("server-{session_id}");
            assert_eq!(
                reply,
                tokio_tungstenite::tungstenite::Message::Binary(bytes::Bytes::copy_from_slice(
                    expected_reply.as_bytes()
                ))
            );

            server_task.await.unwrap();
        }
    }

    struct ClientWsStream<S> {
        socket: tokio_tungstenite::WebSocketStream<S>,
        buffered: bytes::Bytes,
    }

    impl<S> ClientWsStream<S> {
        fn new(socket: tokio_tungstenite::WebSocketStream<S>) -> Self {
            Self {
                socket,
                buffered: bytes::Bytes::new(),
            }
        }
    }

    impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> tokio::io::AsyncRead
        for ClientWsStream<S>
    {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            use bytes::Buf;
            use futures_util::Stream;
            if buf.remaining() == 0 {
                return std::task::Poll::Ready(Ok(()));
            }
            loop {
                if !self.buffered.is_empty() {
                    let n = buf.remaining().min(self.buffered.len());
                    buf.put_slice(&self.buffered[..n]);
                    self.buffered.advance(n);
                    return std::task::Poll::Ready(Ok(()));
                }
                match futures_util::ready!(std::pin::Pin::new(&mut self.socket).poll_next(cx)) {
                    Some(Ok(tokio_tungstenite::tungstenite::Message::Binary(data))) => {
                        self.buffered = data;
                    }
                    None | Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) => {
                        return std::task::Poll::Ready(Ok(()));
                    }
                    Some(Ok(
                        tokio_tungstenite::tungstenite::Message::Ping(_)
                        | tokio_tungstenite::tungstenite::Message::Pong(_),
                    )) => {
                        continue;
                    }
                    Some(Ok(_)) => {
                        return std::task::Poll::Ready(Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Expected binary WebSocket frame",
                        )));
                    }
                    Some(Err(e)) => return std::task::Poll::Ready(Err(std::io::Error::other(e))),
                }
            }
        }
    }

    impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite
        for ClientWsStream<S>
    {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            data: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            use futures_util::Sink;
            if data.is_empty() {
                return std::task::Poll::Ready(Ok(0));
            }
            futures_util::ready!(std::pin::Pin::new(&mut self.socket).poll_ready(cx))
                .map_err(std::io::Error::other)?;
            let n = data.len().min(16384);
            std::pin::Pin::new(&mut self.socket)
                .start_send(tokio_tungstenite::tungstenite::Message::Binary(
                    bytes::Bytes::copy_from_slice(&data[..n]),
                ))
                .map_err(std::io::Error::other)?;
            std::task::Poll::Ready(Ok(n))
        }

        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            use futures_util::Sink;
            std::pin::Pin::new(&mut self.socket)
                .poll_flush(cx)
                .map_err(std::io::Error::other)
        }

        fn poll_shutdown(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            use futures_util::Sink;
            std::pin::Pin::new(&mut self.socket)
                .poll_close(cx)
                .map_err(std::io::Error::other)
        }
    }

    #[tokio::test]
    async fn test_shadowsocks_plain_baseline() {
        use shadowsocks::config::ServerConfig;
        use shadowsocks::crypto::CipherKind as UpstreamCipher;
        use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let password = "gost-test-secret-1234";
        let user = User {
            id: 1,
            password: Some(password.into()),
            ..Default::default()
        };
        let method: Method = "chacha20-ietf-poly1305".parse().unwrap();
        let server_context = Arc::new(shadowsocks::context::Context::new(
            shadowsocks::config::ServerType::Server,
        ));
        let cred = Arc::new(Credential::new(user, method, server_context.clone()).unwrap());

        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);

        let target_addr =
            shadowsocks::relay::socks5::Address::SocketAddress("127.0.0.1:8080".parse().unwrap());
        let client_context = Arc::new(shadowsocks::context::Context::new(
            shadowsocks::config::ServerType::Local,
        ));
        let svr_cfg = ServerConfig::new(
            "127.0.0.1:8388".parse::<std::net::SocketAddr>().unwrap(),
            password,
            UpstreamCipher::CHACHA20_POLY1305,
        )
        .unwrap();

        let client_task = tokio::spawn(async move {
            let mut client_stream =
                ProxyClientStream::from_stream(client_context, client_io, &svr_cfg, target_addr);
            client_stream
                .write_all(b"ping-baseline-plain")
                .await
                .unwrap();
            client_stream.flush().await.unwrap();

            let mut reply = [0u8; 19];
            client_stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"pong-baseline-plain");
        });

        let Method::Legacy(cipher_kind) = method else {
            unreachable!()
        };
        let mut client_salt = vec![0; cipher_kind.salt_len()];
        server_io.read_exact(&mut client_salt).await.unwrap();
        let mut enc_len_block = [0; 18];
        server_io.read_exact(&mut enc_len_block).await.unwrap();

        let mut session = ShadowsocksServerSession::new(cipher_kind, &cred.key, &client_salt);
        let mut header = enc_len_block;
        let len = session
            .decrypt_length(&mut header)
            .expect("plain baseline decrypt_length must succeed");
        let mut stream = session.into_stream(Box::new(server_io), Some(len));

        let (host, _ip, port) = read_target(&mut stream).await.unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(port, 8080);

        let mut payload = [0u8; 19];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping-baseline-plain");

        stream.write_all(b"pong-baseline-plain").await.unwrap();
        stream.flush().await.unwrap();

        client_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_gost_plugin_websocket_baseline_no_early_data() {
        use shadowsocks::config::ServerConfig;
        use shadowsocks::crypto::CipherKind as UpstreamCipher;
        use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let password = "gost-test-secret-1234";
        let user = User {
            id: 1,
            password: Some(password.into()),
            ..Default::default()
        };
        let method: Method = "chacha20-ietf-poly1305".parse().unwrap();
        let server_context = Arc::new(shadowsocks::context::Context::new(
            shadowsocks::config::ServerType::Server,
        ));
        let cred = Arc::new(Credential::new(user, method, server_context.clone()).unwrap());

        let node = NodeInfo {
            id: 40,
            node_type: "shadowsocks".into(),
            cipher: Some("chacha20-ietf-poly1305".into()),
            server_port: 10040,
            plugin: Some("gost-plugin".into()),
            plugin_opts: Some("mode=ws;host=example.com;path=/ws".into()),
            ..Default::default()
        };

        let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
        let transport = Arc::new(Transport::new(&node, &tls_manager).await.unwrap());
        let ctx = test_context();

        let (client_duplex, server_duplex) = tokio::io::duplex(64 * 1024);

        let server_transport = transport.clone();
        let server_task = tokio::spawn(async move {
            let accepted = server_transport
                .accept(Box::new(server_duplex), &ctx, None)
                .await
                .expect("server transport accept");
            let mut server_stream = match accepted {
                super::super::transport::Accepted::Stream(s) => s,
                _ => panic!("Expected Accepted::Stream"),
            };

            let Method::Legacy(cipher_kind) = method else {
                unreachable!()
            };
            let mut client_salt = vec![0; cipher_kind.salt_len()];
            server_stream.read_exact(&mut client_salt).await.unwrap();
            let mut enc_len_block = [0; 18];
            server_stream.read_exact(&mut enc_len_block).await.unwrap();

            let mut session = ShadowsocksServerSession::new(cipher_kind, &cred.key, &client_salt);
            let mut header = enc_len_block;
            let len = session
                .decrypt_length(&mut header)
                .expect("gost ws decrypt_length must succeed");
            let mut stream = session.into_stream(server_stream, Some(len));

            let (host, _ip, port) = read_target(&mut stream).await.unwrap();
            assert_eq!(host, "127.0.0.1");
            assert_eq!(port, 8080);

            let mut payload = [0u8; 15];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping-gost-no-ed");

            stream.write_all(b"pong-gost-no-ed").await.unwrap();
            stream.flush().await.unwrap();
        });

        let req = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri("ws://example.com/ws")
            .header("Host", "example.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(())
            .unwrap();

        let (client_ws, _resp) = tokio_tungstenite::client_async(req, client_duplex)
            .await
            .expect("client ws upgrade");

        let client_ws_stream = ClientWsStream::new(client_ws);

        let target_addr =
            shadowsocks::relay::socks5::Address::SocketAddress("127.0.0.1:8080".parse().unwrap());
        let client_context = Arc::new(shadowsocks::context::Context::new(
            shadowsocks::config::ServerType::Local,
        ));
        let svr_cfg = ServerConfig::new(
            "127.0.0.1:8388".parse::<std::net::SocketAddr>().unwrap(),
            password,
            UpstreamCipher::CHACHA20_POLY1305,
        )
        .unwrap();

        let mut client_stream =
            ProxyClientStream::from_stream(client_context, client_ws_stream, &svr_cfg, target_addr);

        client_stream.write_all(b"ping-gost-no-ed").await.unwrap();
        client_stream.flush().await.unwrap();

        let mut reply = [0u8; 15];
        client_stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong-gost-no-ed");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_gost_plugin_websocket_with_early_data() {
        use base64::Engine;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let password = "gost-test-secret-1234";
        let user = User {
            id: 1,
            password: Some(password.into()),
            ..Default::default()
        };
        let method: Method = "chacha20-ietf-poly1305".parse().unwrap();
        let server_context = Arc::new(shadowsocks::context::Context::new(
            shadowsocks::config::ServerType::Server,
        ));
        let cred = Arc::new(Credential::new(user, method, server_context.clone()).unwrap());

        let node = NodeInfo {
            id: 41,
            node_type: "shadowsocks".into(),
            cipher: Some("chacha20-ietf-poly1305".into()),
            server_port: 10041,
            plugin: Some("gost-plugin".into()),
            plugin_opts: Some("mode=ws;host=example.com;path=/ws".into()),
            ..Default::default()
        };

        let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
        let transport = Arc::new(Transport::new(&node, &tls_manager).await.unwrap());
        let ctx = test_context();

        let (client_duplex, server_duplex) = tokio::io::duplex(64 * 1024);

        let Method::Legacy(cipher_kind) = method else {
            unreachable!()
        };

        let client_salt = vec![0x33u8; cipher_kind.salt_len()];
        let mut client_subkey = vec![0u8; cipher_kind.key_len()];
        super::super::crypto::hkdf_sha1(&cred.key, &client_salt, &mut client_subkey);
        let mut encrypter = super::super::crypto::ShadowsocksEncrypter {
            cipher_write: super::super::crypto::AeadCipher::new(cipher_kind, &client_subkey),
            write_nonce: [0u8; 12],
            server_salt: client_salt.clone(),
            salt_sent: false,
        };

        let mut initial_plain = Vec::new();
        initial_plain.push(1u8);
        initial_plain.extend_from_slice(&[127, 0, 0, 1]);
        initial_plain.extend_from_slice(&8080u16.to_be_bytes());
        initial_plain.extend_from_slice(b"ping-gost-early-data");

        let mut initial_cipher = Vec::new();
        encrypter
            .encrypt_chunk(&initial_plain, &mut initial_cipher)
            .unwrap();

        let early_data_b64 = base64::engine::general_purpose::STANDARD.encode(&initial_cipher);

        let server_transport = transport.clone();
        let server_cred = cred.clone();
        let server_task = tokio::spawn(async move {
            let accepted = server_transport
                .accept(Box::new(server_duplex), &ctx, None)
                .await
                .expect("server transport accept with early data");
            let mut server_stream = match accepted {
                super::super::transport::Accepted::Stream(s) => s,
                _ => panic!("Expected Accepted::Stream"),
            };

            let mut salt_buf = vec![0; cipher_kind.salt_len()];
            server_stream.read_exact(&mut salt_buf).await.unwrap();
            assert_eq!(salt_buf, client_salt);

            let mut enc_len = [0u8; 18];
            server_stream.read_exact(&mut enc_len).await.unwrap();

            let mut session =
                ShadowsocksServerSession::new(cipher_kind, &server_cred.key, &salt_buf);
            let len = session.decrypt_length(&mut enc_len).unwrap();
            let mut stream = session.into_stream(server_stream, Some(len));

            let (host, _ip, port) = read_target(&mut stream).await.unwrap();
            assert_eq!(host, "127.0.0.1");
            assert_eq!(port, 8080);

            let mut payload = [0u8; 20];
            stream.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping-gost-early-data");

            stream.write_all(b"pong-gost-early-data").await.unwrap();
            stream.flush().await.unwrap();
        });

        let req = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri("ws://example.com/ws")
            .header("Host", "example.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Protocol", early_data_b64)
            .body(())
            .unwrap();

        let (client_ws, _resp) = tokio_tungstenite::client_async(req, client_duplex)
            .await
            .expect("client ws upgrade with early data");

        let mut client_ws_stream = ClientWsStream::new(client_ws);

        let mut server_salt = vec![0; cipher_kind.salt_len()];
        client_ws_stream.read_exact(&mut server_salt).await.unwrap();

        let mut server_subkey = vec![0u8; cipher_kind.key_len()];
        super::super::crypto::hkdf_sha1(&cred.key, &server_salt, &mut server_subkey);
        let mut decrypter = super::super::crypto::ShadowsocksDecrypter::new(
            super::super::crypto::AeadCipher::new(cipher_kind, &server_subkey),
        );

        let mut resp_enc_len = [0u8; 18];
        client_ws_stream
            .read_exact(&mut resp_enc_len)
            .await
            .unwrap();
        let resp_len = decrypter.decrypt_length(&mut resp_enc_len).unwrap();

        let mut resp_payload = vec![0u8; resp_len + 16];
        client_ws_stream
            .read_exact(&mut resp_payload)
            .await
            .unwrap();
        decrypter.decrypt_payload(&mut resp_payload).unwrap();
        assert_eq!(&resp_payload[..resp_len], b"pong-gost-early-data");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_gost_plugin_websocket_chunking_partial_reads_and_50mb_transfer() {
        use sha2::{Digest, Sha256};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let node = NodeInfo {
            id: 42,
            node_type: "shadowsocks".into(),
            cipher: Some("chacha20-ietf-poly1305".into()),
            server_port: 10042,
            plugin: Some("gost-plugin".into()),
            plugin_opts: Some("mode=ws;host=example.com;path=/ws".into()),
            ..Default::default()
        };

        let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
        let transport = Arc::new(Transport::new(&node, &tls_manager).await.unwrap());
        let ctx = test_context();

        let (client_duplex, server_duplex) = tokio::io::duplex(256 * 1024);

        const TOTAL_BYTES: usize = 50 * 1024 * 1024;
        const CHUNK_SIZE: usize = 16 * 1024;

        let sample_chunk = {
            let mut c = vec![0u8; CHUNK_SIZE];
            for (i, b) in c.iter_mut().enumerate() {
                *b = ((i * 7 + 13) % 251) as u8;
            }
            c
        };

        let server_transport = transport.clone();
        let server_task = tokio::spawn(async move {
            let accepted = server_transport
                .accept(Box::new(server_duplex), &ctx, None)
                .await
                .expect("server transport accept");
            let mut stream = match accepted {
                super::super::transport::Accepted::Stream(s) => s,
                _ => panic!("Expected Stream"),
            };

            let mut server_hasher = Sha256::new();
            let mut total_read = 0;

            let mut irregular_buf = [0u8; 7];
            stream.read_exact(&mut irregular_buf).await.unwrap();
            server_hasher.update(irregular_buf);
            total_read += 7;

            let mut irregular_buf2 = [0u8; 13];
            stream.read_exact(&mut irregular_buf2).await.unwrap();
            server_hasher.update(irregular_buf2);
            total_read += 13;

            let mut large_buf = vec![0u8; 32 * 1024];
            while total_read < TOTAL_BYTES {
                let to_read = (TOTAL_BYTES - total_read).min(large_buf.len());
                let n = stream.read(&mut large_buf[..to_read]).await.unwrap();
                if n == 0 {
                    break;
                }
                server_hasher.update(&large_buf[..n]);
                total_read += n;
            }
            assert_eq!(total_read, TOTAL_BYTES);
            let server_digest = server_hasher.finalize();

            stream.write_all(&server_digest).await.unwrap();
            stream.flush().await.unwrap();
            server_digest
        });

        let req = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri("ws://example.com/ws")
            .header("Host", "example.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(())
            .unwrap();

        let (client_ws, _resp) = tokio_tungstenite::client_async(req, client_duplex)
            .await
            .expect("client ws handshake");

        let mut client_stream = ClientWsStream::new(client_ws);

        let mut client_hasher = Sha256::new();
        let mut total_sent = 0;
        while total_sent < TOTAL_BYTES {
            let to_send = (TOTAL_BYTES - total_sent).min(CHUNK_SIZE);
            client_stream
                .write_all(&sample_chunk[..to_send])
                .await
                .unwrap();
            client_hasher.update(&sample_chunk[..to_send]);
            total_sent += to_send;
        }
        client_stream.flush().await.unwrap();
        let client_digest = client_hasher.finalize();

        let mut received_digest = [0u8; 32];
        client_stream
            .read_exact(&mut received_digest)
            .await
            .unwrap();

        let server_digest = server_task.await.unwrap();
        assert_eq!(&server_digest[..], &client_digest[..]);
        assert_eq!(&received_digest[..], &client_digest[..]);
    }

    #[tokio::test]
    async fn test_gost_plugin_websocket_with_tls_and_panel_tls_switch() {
        use rcgen::generate_simple_self_signed;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let subject_alt_names = vec!["www.bing.com".to_string(), "example.com".to_string()];
        let cert = generate_simple_self_signed(subject_alt_names).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let cert_der = cert.cert.der().to_owned();

        let node = NodeInfo {
            id: 33,
            node_type: "shadowsocks".into(),
            server_port: 8000,
            host: Some("example.com".into()),
            tls: Some(1),
            cipher: Some("chacha20-ietf-poly1305".into()),
            plugin: Some("gost-plugin".into()),
            plugin_opts: Some("mode=ws;host=www.bing.com;path=/".into()),
            cert_config: Some(serde_json::json!({
                "cert": cert_pem,
                "key": key_pem,
            })),
            ..Default::default()
        };

        assert!(Transport::validate(&node).is_ok());
        let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
        let transport = Transport::new(&node, &tls_manager)
            .await
            .expect("Transport::new must enable TLS due to panel tls switch and cert_config");

        assert!(transport.is_websocket());
        assert!(transport.is_tls());
        assert_eq!(transport.host(), Some("www.bing.com"));
        assert_eq!(transport.path, "/");

        let (client, server) = tokio::io::duplex(64 * 1024);
        let ctx = test_context();

        let transport = Arc::new(transport);
        let server_transport = transport.clone();
        let server_task = tokio::spawn(async move {
            let accepted = server_transport
                .accept(Box::new(server), &ctx, None)
                .await
                .expect("server transport accept with TLS");
            let mut stream = match accepted {
                super::super::transport::Accepted::Stream(s) => s,
                _ => panic!("Expected Accepted::Stream"),
            };

            let mut buf = [0u8; 15];
            stream.read_exact(&mut buf).await.expect("read from client");
            assert_eq!(&buf, b"ping-gost-tls-1");
            stream
                .write_all(b"pong-gost-tls-1")
                .await
                .expect("write reply");
            stream.flush().await.expect("flush");
        });

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der).expect("add test root cert");
        let mut client_tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls_config));
        let server_name = rustls::pki_types::ServerName::try_from("example.com")
            .unwrap()
            .to_owned();
        let tls_client = connector
            .connect(server_name, client)
            .await
            .expect("client tls handshake");

        let req = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri("wss://www.bing.com/")
            .header("Host", "www.bing.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(())
            .unwrap();

        let (client_ws, _resp) = tokio_tungstenite::client_async(req, tls_client)
            .await
            .expect("client ws handshake over TLS");

        let mut client_stream = ClientWsStream::new(client_ws);
        client_stream.write_all(b"ping-gost-tls-1").await.unwrap();
        client_stream.flush().await.unwrap();

        let mut reply = [0u8; 15];
        client_stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong-gost-tls-1");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_gost_plugin_websocket_with_mux_false_and_standard_flags() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        for mux_flag in ["mux=false", "mux=0", "mux=off", "mux=no"] {
            let node = NodeInfo {
                id: 33,
                node_type: "shadowsocks".into(),
                server_port: 8000,
                host: Some("example.com".into()),
                cipher: Some("chacha20-ietf-poly1305".into()),
                plugin: Some("gost-plugin".into()),
                plugin_opts: Some(
                    format!(
                        "mode=ws;host=example.com;path=/ws;{mux_flag};nocomp=true;insecure=true"
                    )
                    .into(),
                ),
                ..Default::default()
            };

            assert!(Transport::validate(&node).is_ok());
            let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
            let transport = Transport::new(&node, &tls_manager)
                .await
                .expect("Transport::new must succeed with mux disabled");

            assert!(transport.is_websocket());
            assert!(!transport.is_tls());
            assert_eq!(transport.host(), Some("example.com"));
            assert_eq!(transport.path, "/ws");
            assert!(transport.mux.is_none());
        }

        for mux_flag in ["mux=1", "mux=true", "mux=on"] {
            let node = NodeInfo {
                id: 33,
                node_type: "shadowsocks".into(),
                server_port: 8000,
                host: Some("example.com".into()),
                cipher: Some("chacha20-ietf-poly1305".into()),
                plugin: Some("gost-plugin".into()),
                plugin_opts: Some(format!("mode=ws;host=example.com;path=/ws;{mux_flag}").into()),
                ..Default::default()
            };
            assert!(Transport::validate(&node).is_ok());
            let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
            let transport = Transport::new(&node, &tls_manager)
                .await
                .expect("Transport::new must succeed with mux enabled");
            assert!(transport.mux.is_some());
        }

        let node = NodeInfo {
            id: 33,
            node_type: "shadowsocks".into(),
            server_port: 8000,
            host: Some("example.com".into()),
            cipher: Some("chacha20-ietf-poly1305".into()),
            plugin: Some("gost-plugin".into()),
            plugin_opts: Some("mode=ws;host=example.com;path=/ws;mux=false".into()),
            ..Default::default()
        };

        let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
        let transport = Arc::new(
            Transport::new(&node, &tls_manager)
                .await
                .expect("Transport::new must succeed"),
        );

        let (client, server) = tokio::io::duplex(64 * 1024);
        let ctx = test_context();

        let server_transport = transport.clone();
        let server_task = tokio::spawn(async move {
            let accepted = server_transport
                .accept(Box::new(server), &ctx, None)
                .await
                .expect("server transport accept");
            let mut stream = match accepted {
                super::super::transport::Accepted::Stream(s) => s,
                _ => panic!("Expected Accepted::Stream"),
            };

            let mut buf = [0u8; 18];
            stream.read_exact(&mut buf).await.expect("read from client");
            assert_eq!(&buf, b"ping-gost-no-mux-1");
            stream
                .write_all(b"pong-gost-no-mux-1")
                .await
                .expect("write reply");
            stream.flush().await.expect("flush");
        });

        let req = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri("ws://example.com/ws")
            .header("Host", "example.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(())
            .unwrap();

        let (client_ws, _resp) = tokio_tungstenite::client_async(req, client)
            .await
            .expect("client ws handshake");

        let mut client_stream = ClientWsStream::new(client_ws);
        client_stream
            .write_all(b"ping-gost-no-mux-1")
            .await
            .unwrap();
        client_stream.flush().await.unwrap();

        let mut reply = [0u8; 18];
        client_stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong-gost-no-mux-1");

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_gost_plugin_websocket_with_clash_vmess_mux_frames_auto_detected() {
        use crate::protocol::shadowsocks::mux::{self, Mux};
        use shadowsocks::config::ServerConfig;
        use shadowsocks::crypto::CipherKind as UpstreamCipher;
        use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let node = NodeInfo {
            id: 33,
            node_type: "shadowsocks".into(),
            server_port: 8000,
            host: Some("example.com".into()),
            cipher: Some("chacha20-ietf-poly1305".into()),
            plugin: Some("gost-plugin".into()),
            plugin_opts: Some("mode=ws;host=example.com;path=/ws;mux=false".into()),
            ..Default::default()
        };

        let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
        let transport = Arc::new(
            Transport::new(&node, &tls_manager)
                .await
                .expect("Transport::new"),
        );

        let (client_duplex, server_duplex) = tokio::io::duplex(64 * 1024);
        let ctx = test_context();

        let password = "clash-gost-test-secret";
        let user = User {
            id: 1,
            password: Some(password.into()),
            ..Default::default()
        };
        let method: Method = "chacha20-ietf-poly1305".parse().unwrap();
        let server_context = Arc::new(shadowsocks::context::Context::new(
            shadowsocks::config::ServerType::Server,
        ));
        let cred = Arc::new(Credential::new(user, method, server_context).unwrap());
        let mut index = UserIndex::default();
        index.credentials.push(cred);
        let users = Arc::new(parking_lot::RwLock::new(Arc::new(index)));

        let remote_addr: SocketAddr = "45.59.185.107:51094".parse().unwrap();
        let cancel = CancellationToken::new();
        let d_sem = Arc::new(tokio::sync::Semaphore::new(16));
        let s_def = Arc::new(crate::security::AttackDefenseManager::new(5, 60, 300));

        let server_transport = transport.clone();
        let server_cancel = cancel.clone();
        let server_users = users.clone();
        let server_ctx = ctx.clone();

        let server_task = tokio::spawn(async move {
            let accepted = server_transport
                .accept(Box::new(server_duplex), &server_ctx, None)
                .await
                .expect("server transport accept");
            let stream = match accepted {
                super::super::transport::Accepted::Stream(s) => s,
                _ => panic!("Expected Stream"),
            };

            let (stream, auto_mux) = if server_transport.is_websocket() {
                if matches!(server_transport.mux, Some(Mux::Smux)) {
                    (stream, Some(Mux::Smux))
                } else {
                    let mut probe = [0u8; 14];
                    let mut s = stream;
                    match s.read_exact(&mut probe).await {
                        Ok(_) => {
                            let is_vmess = {
                                let len = u16::from_be_bytes([probe[0], probe[1]]) as usize;
                                let status = probe[4];
                                let options = probe[5];
                                let net_type = probe[6];
                                let addr_type = probe[9];
                                (4..=512).contains(&len)
                                    && status == 1
                                    && (options & !3 == 0)
                                    && net_type == 1
                                    && matches!(addr_type, 1..=3)
                            };
                            let is_smux = probe[0] == 1 && probe[1] <= 3;
                            let prefixed =
                                Box::new(crate::conn::PrefixedStream::new(s, Some(probe.to_vec())))
                                    as BoxedStream;
                            if is_vmess {
                                (prefixed, Some(Mux::Vmess))
                            } else if is_smux && server_transport.is_gost() {
                                (prefixed, Some(Mux::Smux))
                            } else {
                                (prefixed, None)
                            }
                        }
                        Err(_) => (s, None),
                    }
                }
            } else {
                (stream, server_transport.mux)
            };

            assert_eq!(
                auto_mux.map(|m| matches!(m, Mux::Vmess)),
                Some(true),
                "VMess Mux must be auto-detected"
            );

            let d_sem_clone = d_sem.clone();
            let s_def_clone = s_def.clone();
            let _ = mux::serve(
                stream,
                auto_mux.unwrap(),
                server_cancel.clone(),
                move |stream| {
                    handle_stream(
                        stream,
                        remote_addr,
                        None,
                        server_ctx.clone(),
                        server_users.clone(),
                        method,
                        Arc::new(None),
                        server_cancel.clone(),
                        d_sem_clone.clone(),
                        s_def_clone.clone(),
                    )
                },
            )
            .await;
        });

        let req = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri("ws://example.com/ws")
            .header("Host", "example.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(())
            .unwrap();

        let (client_ws, _resp) = tokio_tungstenite::client_async(req, client_duplex)
            .await
            .expect("client ws handshake");
        let mut client_stream = ClientWsStream::new(client_ws);

        let mux_new = [
            0x00, 0x0c, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01,
        ];
        client_stream.write_all(&mux_new).await.unwrap();
        client_stream.flush().await.unwrap();

        let (ss_client_io, mut ss_plain_writer) = tokio::io::duplex(64 * 1024);
        let client_context = Arc::new(shadowsocks::context::Context::new(
            shadowsocks::config::ServerType::Local,
        ));
        let svr_cfg = ServerConfig::new(
            "127.0.0.1:8000".parse::<std::net::SocketAddr>().unwrap(),
            password,
            UpstreamCipher::CHACHA20_POLY1305,
        )
        .unwrap();
        let target_addr =
            shadowsocks::relay::socks5::Address::SocketAddress("127.0.0.1:9090".parse().unwrap());

        let mut proxy_client =
            ProxyClientStream::from_stream(client_context, ss_client_io, &svr_cfg, target_addr);

        let bridge_task = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let n = ss_plain_writer.read(&mut buf).await.unwrap();
            let mut mux_data = vec![0x00, 0x04, 0x00, 0x00, 0x02, 0x01];
            mux_data.extend_from_slice(&(n as u16).to_be_bytes());
            mux_data.extend_from_slice(&buf[..n]);
            client_stream.write_all(&mux_data).await.unwrap();
            client_stream.flush().await.unwrap();
        });

        proxy_client.write_all(b"ping-clash-mux").await.unwrap();
        proxy_client.flush().await.unwrap();

        bridge_task.await.unwrap();
        cancel.cancel();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn test_gost_plugin_websocket_with_mode_websocket_and_aes_128_gcm() {
        use rcgen::generate_simple_self_signed;
        use shadowsocks::config::ServerConfig;
        use shadowsocks::crypto::CipherKind as UpstreamCipher;
        use shadowsocks::relay::tcprelay::proxy_stream::ProxyClientStream;
        use tokio::io::AsyncWriteExt;

        let subject_alt_names = vec!["example.com".to_string(), "localhost".to_string()];
        let cert = generate_simple_self_signed(subject_alt_names).unwrap();
        let cert_pem = cert.cert.pem();
        let key_pem = cert.key_pair.serialize_pem();
        let cert_der = cert.cert.der().to_owned();

        let node1 = NodeInfo {
            id: 33,
            node_type: "shadowsocks".into(),
            server_port: 8000,
            host: Some("example.com".into()),
            cipher: Some("aes-128-gcm".into()),
            plugin: Some("gost-plugin".into()),
            plugin_opts: Some("mode=websocket;host=example.com;path=/ws;tls=true;mux=false".into()),
            cert_config: Some(serde_json::json!({
                "cert": cert_pem,
                "key": key_pem,
            })),
            ..Default::default()
        };
        assert!(Transport::validate(&node1).is_ok());

        let node2 = NodeInfo {
            id: 33,
            node_type: "shadowsocks".into(),
            server_port: 8000,
            host: Some("example.com".into()),
            cipher: Some("aes-128-gcm".into()),
            plugin: Some("gost-plugin".into()),
            plugin_opts: Some(serde_json::json!({
                "mode": "websocket",
                "host": "example.com",
                "path": "/ws",
                "tls": "'true'",
                "mux": "'false'",
            })),
            cert_config: Some(serde_json::json!({
                "cert": cert_pem,
                "key": key_pem,
            })),
            ..Default::default()
        };
        assert!(Transport::validate(&node2).is_ok());

        let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
        let transport = Arc::new(
            Transport::new(&node1, &tls_manager)
                .await
                .expect("Transport::new"),
        );

        assert!(transport.is_websocket());
        assert!(transport.is_tls());
        assert_eq!(transport.host(), Some("example.com"));
        assert_eq!(transport.path, "/ws");
        assert!(transport.mux.is_none());

        let (client, server) = tokio::io::duplex(64 * 1024);
        let ctx = test_context();

        let password = "c72a3561-bd6c-40de-b819-e9289bc166f2";
        let user = User {
            id: 1,
            password: Some(password.into()),
            ..Default::default()
        };
        let method: Method = "aes-128-gcm".parse().unwrap();
        let server_context = Arc::new(shadowsocks::context::Context::new(
            shadowsocks::config::ServerType::Server,
        ));
        let cred = Arc::new(Credential::new(user, method, server_context).unwrap());
        let mut index = UserIndex::default();
        index.credentials.push(cred);
        let users = Arc::new(parking_lot::RwLock::new(Arc::new(index)));

        let remote_addr: SocketAddr = "198.51.100.1:63779".parse().unwrap();
        let cancel = CancellationToken::new();
        let d_sem = Arc::new(tokio::sync::Semaphore::new(16));
        let s_def = Arc::new(crate::security::AttackDefenseManager::new(5, 60, 300));

        let server_transport = transport.clone();
        let server_cancel = cancel.clone();
        let server_users = users.clone();
        let server_ctx = ctx.clone();

        let server_task = tokio::spawn(async move {
            let accepted = server_transport
                .accept(Box::new(server), &server_ctx, None)
                .await
                .expect("server accept");
            let stream = match accepted {
                super::super::transport::Accepted::Stream(s) => s,
                _ => panic!("Expected Stream"),
            };

            let _ = handle_stream(
                stream,
                remote_addr,
                None,
                server_ctx,
                server_users,
                method,
                Arc::new(None),
                server_cancel,
                d_sem,
                s_def,
            )
            .await;
        });

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add(cert_der).expect("add test root cert");
        let mut client_tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        client_tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls_config));
        let server_name = rustls::pki_types::ServerName::try_from("example.com")
            .unwrap()
            .to_owned();
        let tls_client = connector
            .connect(server_name, client)
            .await
            .expect("client tls handshake");

        let req = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri("wss://example.com/ws")
            .header("Host", "example.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(())
            .unwrap();

        let (client_ws, _resp) = tokio_tungstenite::client_async(req, tls_client)
            .await
            .expect("client ws handshake over TLS");
        let client_stream = ClientWsStream::new(client_ws);

        let client_context = Arc::new(shadowsocks::context::Context::new(
            shadowsocks::config::ServerType::Local,
        ));
        let svr_cfg = ServerConfig::new(
            "127.0.0.1:8000".parse::<std::net::SocketAddr>().unwrap(),
            password,
            UpstreamCipher::AES_128_GCM,
        )
        .unwrap();
        let target_addr =
            shadowsocks::relay::socks5::Address::SocketAddress("127.0.0.1:9090".parse().unwrap());

        let mut proxy_client = ProxyClientStream::from_stream(
            client_context,
            Box::new(client_stream),
            &svr_cfg,
            target_addr,
        );

        proxy_client.write_all(b"ping-aes-128-gcm").await.unwrap();
        proxy_client.flush().await.unwrap();

        cancel.cancel();
        let _ = server_task.await;
    }

    #[tokio::test]
    async fn test_restls_plugin_xboard_configuration_and_aliases() {
        let node = NodeInfo {
            id: 33,
            node_type: "shadowsocks".into(),
            server_port: 8000,
            host: Some("example.com".into()),
            cipher: Some("aes-128-gcm".into()),
            plugin: Some("ResTLS".into()),
            plugin_opts: Some(
                "host=www.microsoft.com;password=test-secret-123456;version-hint=tls13;restls-script=300?100<1,400~100"
                    .into(),
            ),
            ..Default::default()
        };

        assert!(Transport::validate(&node).is_ok());
        let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
        let transport = Transport::new(&node, &tls_manager)
            .await
            .expect("Transport::new must succeed for ResTLS with XBoard options");

        assert_eq!(transport.host(), Some("www.microsoft.com"));

        let node2 = NodeInfo {
            id: 34,
            node_type: "shadowsocks".into(),
            server_port: 8001,
            host: Some("example.com".into()),
            cipher: Some("aes-128-gcm".into()),
            plugin: Some("restls-plugin".into()),
            plugin_opts: Some(
                "host=www.microsoft.com:8443;password=test-secret-123456;version_hint=tls13;restls_script=300?100<1,400~100;min_record_len=20"
                    .into(),
            ),
            ..Default::default()
        };
        assert!(Transport::validate(&node2).is_ok());
        let transport2 = Transport::new(&node2, &tls_manager)
            .await
            .expect("Transport::new must succeed with restls-plugin aliases");
        assert_eq!(transport2.host(), Some("www.microsoft.com:8443"));
    }

    #[tokio::test]
    async fn test_kcptun_plugin_xboard_configuration_and_aliases() {
        let node = NodeInfo {
            id: 33,
            node_type: "shadowsocks".into(),
            server_port: 8000,
            cipher: Some("aes-128-gcm".into()),
            plugin: Some("KCPTun".into()),
            plugin_opts: Some("key=test-key-123456;crypt=aes-128-gcm;mode=fast".into()),
            ..Default::default()
        };
        assert!(Transport::validate(&node).is_ok());
        let tls_manager = crate::security::TLSManager::new(false, "localhost".into());
        let transport = Transport::new(&node, &tls_manager)
            .await
            .expect("Transport::new must succeed for KCPTun with XBoard options");
        assert!(transport.is_kcptun());

        let args = transport
            .kcptun_args("0.0.0.0:8000", "127.0.0.1:12345")
            .unwrap();

        assert!(args.windows(2).any(|w| w == ["--crypt", "aes-128"]));
        assert!(args.windows(2).any(|w| w == ["--key", "test-key-123456"]));
        assert!(args.windows(2).any(|w| w == ["--mode", "fast"]));
        assert!(args.windows(2).any(|w| w == ["--smuxver", "1"]));

        let node2 = NodeInfo {
            id: 34,
            node_type: "shadowsocks".into(),
            server_port: 8001,
            cipher: Some("aes-128-gcm".into()),
            plugin: Some("kcptun-plugin".into()),
            plugin_opts: Some(
                "password=MySecretPassword;crypt=aes-256-gcm;mode=fast2;mtu=1350".into(),
            ),
            ..Default::default()
        };
        assert!(Transport::validate(&node2).is_ok());
        let transport2 = Transport::new(&node2, &tls_manager)
            .await
            .expect("Transport::new must succeed for kcptun-plugin");
        assert!(transport2.is_kcptun());
        let args2 = transport2
            .kcptun_args("0.0.0.0:8001", "127.0.0.1:12346")
            .unwrap();

        assert!(args2.windows(2).any(|w| w == ["--crypt", "aes"]));

        assert!(args2.windows(2).any(|w| w == ["--key", "MySecretPassword"]));
        assert!(args2.windows(2).any(|w| w == ["--mode", "fast2"]));
        assert!(args2.windows(2).any(|w| w == ["--mtu", "1350"]));
    }
}
