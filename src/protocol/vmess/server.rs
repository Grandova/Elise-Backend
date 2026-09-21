use super::crypto::{
    create_vmess_response_header, decrypt_vmess_header, decrypt_vmess_header_length,
    VmessChunkDecrypter, VmessChunkEncrypter, VmessUserKeys, CMD_MUX, CMD_UDP,
};
use crate::conn::{bind_tcp_listener, read_proxy_protocol, BoxedStream, ProxyProtocolMode};
use crate::observability::AuditRecord;
use crate::panel::types::{NodeInfo, User};
use crate::protocol::{Inbound, InboundContext};
use crate::proxy::router::MatchContext;
use crate::security::TLSManager;
use crate::transport::{apply_transport_security, StreamSettings, TransportSecurityConfig};
use async_trait::async_trait;
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tracing::{info, warn};

pub struct VmessInbound {
    users: Arc<RwLock<Vec<(VmessUserKeys, User)>>>,
}

impl Default for VmessInbound {
    fn default() -> Self {
        Self {
            users: Arc::new(RwLock::new(Vec::new())),
        }
    }
}

impl VmessInbound {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Inbound for VmessInbound {
    fn protocol_type(&self) -> &'static str {
        "vmess"
    }

    fn update_users(&self, users: Vec<User>) {
        let mut list = Vec::with_capacity(users.len());
        for u in users {
            if let Some(keys) = VmessUserKeys::new(&u.uuid) {
                list.push((keys, u));
            }
        }
        *self.users.write() = list;
    }

    async fn start(
        &self,
        ctx: InboundContext,
        node_info: NodeInfo,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> std::io::Result<()> {
        let settings = StreamSettings::from_node_info(&node_info)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;

        let tls_manager = match &settings.security {
            TransportSecurityConfig::Tls(tls_cfg) => {
                let mgr = TLSManager::from_config(
                    tls_cfg,
                    ctx.global_config.auto_tls,
                    &ctx.global_config.fake_sni,
                )
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Failed to initialize TLS for VMess inbound: {e}"),
                    )
                })?;
                Some(Arc::new(mgr))
            }
            _ => Some(ctx.tls_manager.clone()),
        };

        let settings = Arc::new(settings);
        let bind_addr = format!("{}:{}", ctx.listen_addr, ctx.port);
        let listener = bind_tcp_listener(&bind_addr, ctx.global_config.mptcp).await?;
        info!(
            "VMess inbound listening on {} (transport: {:?})",
            bind_addr,
            settings.transport.transport_type()
        );

        let users = self.users.clone();
        let alter_id = node_info.alter_id.unwrap_or(0);
        let force_md5 = ctx.global_config.force_vmess_md5
            || (!ctx.global_config.force_vmess_aead && alter_id > 0);
        let decrypt_semaphore = Arc::new(tokio::sync::Semaphore::new(
            ctx.global_config.ss_decrypt_concurrency.max(1),
        ));
        let vmess_defense = if ctx.global_config.vmess_aead_invalid_access_enable {
            Arc::new(crate::security::AttackDefenseManager::new(
                ctx.global_config.vmess_aead_invalid_access_count,
                ctx.global_config.vmess_aead_invalid_access_duration,
                ctx.global_config.vmess_aead_invalid_access_forbidden_time,
            ))
        } else {
            ctx.defense.clone()
        };

        let mut connections = tokio::task::JoinSet::new();
        ctx.mark_ready();
        loop {
            tokio::select! {
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(e)) = result { tracing::warn!(error = %e, "Connection task failed"); }
                }
                _ = shutdown_rx.recv() => {
                    info!("VMess inbound on port {} stopping", ctx.port);
                    break;
                }
                accept_res = listener.accept() => {
                    let (stream, remote_addr) = match accept_res {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!("VMess accept error: {:?}", e);
                            continue;
                        }
                    };
                    let _ = stream.set_nodelay(true);

                    let ctx = ctx.clone();
                    let users = users.clone();
                    let settings = settings.clone();
                    let tls_manager = tls_manager.clone();
                    let sem = decrypt_semaphore.clone();
                    let def = vmess_defense.clone();
                    connections.spawn(async move {
                        let _ = handle_connection(stream, remote_addr, ctx, users, settings, tls_manager.as_deref(), force_md5, sem, def).await;
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
    users: Arc<RwLock<Vec<(VmessUserKeys, User)>>>,
    settings: Arc<StreamSettings>,
    tls_manager: Option<&TLSManager>,
    force_md5: bool,
    decrypt_semaphore: Arc<tokio::sync::Semaphore>,
    vmess_defense: Arc<crate::security::AttackDefenseManager>,
) -> std::io::Result<()> {
    info!("VMess: handle_connection accepted from {}", remote_addr);
    let _ = stream.set_nodelay(true);
    let local_ip = stream.local_addr().ok().map(|s| s.ip());

    let proxy_mode = if settings.accept_proxy_protocol {
        ProxyProtocolMode::Strict
    } else {
        ctx.global_config.get_proxy_protocol_mode()
    };
    let (src_opt, stream) = match read_proxy_protocol(stream, proxy_mode).await {
        Ok(res) => res,
        Err(e) => {
            warn!(
                "VMess: read_proxy_protocol failed from {}: {:?}",
                remote_addr, e
            );
            return Ok(());
        }
    };
    if let Some(src) = src_opt {
        remote_addr = src;
    }

    let client_ip = remote_addr.ip();
    if vmess_defense.is_banned(client_ip) {
        warn!(
            "VMess: client_ip {} is banned by defense manager",
            client_ip
        );
        return Ok(());
    }

    let alpn = match &settings.transport {
        crate::transport::TransportConfig::Grpc(_)
        | crate::transport::TransportConfig::LegacyHttp2(_) => {
            vec![b"h2".to_vec()]
        }
        crate::transport::TransportConfig::XHttp(_) => {
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        }
        _ => vec![b"http/1.1".to_vec()],
    };
    let sec_stream = match apply_transport_security(
        Box::new(stream),
        remote_addr,
        &settings.security,
        tls_manager,
        None,
        alpn,
    )
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return Ok(()),
        Err(e) => {
            warn!(
                "VMess transport security handshake failed from {}: {:?}",
                client_ip, e
            );
            return Ok(());
        }
    };

    let ctx_clone = ctx.clone();
    let users_clone = users.clone();
    let sem_clone = decrypt_semaphore.clone();
    let def_clone = vmess_defense.clone();

    let res = crate::transport::serve_transport(
        sec_stream,
        &settings.transport,
        tls_manager,
        move |stream| {
            let ctx = ctx_clone.clone();
            let users = users_clone.clone();
            let decrypt_semaphore = sem_clone.clone();
            let vmess_defense = def_clone.clone();
            async move {
                info!(
                    "VMess: stream accepted, starting handshake for {}",
                    client_ip
                );

                let handshake_res = tokio::time::timeout(
                    Duration::from_secs(15),
                    perform_vmess_handshake(
                        stream,
                        remote_addr,
                        local_ip,
                        &ctx,
                        &users,
                        force_md5,
                        decrypt_semaphore,
                        vmess_defense,
                    ),
                )
                .await;

                let handshake_data = match handshake_res {
                    Ok(Ok(Some(data))) => data,
                    Ok(Ok(None)) => {
                        warn!(
                            "VMess: perform_vmess_handshake returned None for {}",
                            client_ip
                        );
                        return;
                    }
                    Ok(Err(e)) => {
                        warn!(
                            "VMess: perform_vmess_handshake error from {}: {:?}",
                            client_ip, e
                        );
                        return;
                    }
                    Err(_) => {
                        warn!("VMess: perform_vmess_handshake timed out for {}", client_ip);
                        return;
                    }
                };

                info!(
                    "VMess: handshake completed, entering forward_vmess_stream for {}",
                    client_ip
                );

                let _ = forward_vmess_stream(handshake_data, ctx).await;
            }
        },
    )
    .await;

    if let Err(e) = res {
        warn!("VMess transport serve error from {}: {:?}", client_ip, e);
    }
    Ok(())
}

enum VmessOutbound {
    Tcp(BoxedStream),
    Udp(crate::proxy::router::outbound::UdpOutbound),
}

struct VmessHandshakeData {
    client_stream: BoxedStream,
    out_stream: VmessOutbound,
    user: User,
    client_ip: std::net::IpAddr,
    target_host: String,
    target_port: u16,
    is_udp: bool,
    outbound_tag: String,
    decrypter: VmessChunkDecrypter,
    encrypter: VmessChunkEncrypter,
    _conn_guard: Option<crate::limiter::ConnGuard>,
}

async fn perform_vmess_handshake(
    mut stream: BoxedStream,
    remote_addr: SocketAddr,
    local_ip: Option<std::net::IpAddr>,
    ctx: &InboundContext,
    users: &Arc<RwLock<Vec<(VmessUserKeys, User)>>>,
    force_md5: bool,
    decrypt_semaphore: Arc<tokio::sync::Semaphore>,
    vmess_defense: Arc<crate::security::AttackDefenseManager>,
) -> std::io::Result<Option<VmessHandshakeData>> {
    let client_ip = remote_addr.ip();
    if vmess_defense.is_banned(client_ip) {
        return Ok(None);
    }
    if force_md5 {
        vmess_defense.record_failure(client_ip);
        return Ok(None);
    }

    let mut auth_id = [0u8; 16];
    if let Err(e) = stream.read_exact(&mut auth_id).await {
        warn!(
            "VMess: failed to read 16-byte auth_id from {}: {:?}",
            client_ip, e
        );
        return Ok(None);
    }
    info!("VMess: read auth_id successfully from {}", client_ip);

    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let cached_user_id = ctx.ip_user_cache.get(&client_ip);
    let mut authed_entry = None;

    if let Some(uid) = cached_user_id {
        let guard = users.read();
        if let Some((keys, u)) = guard.iter().find(|(_, u)| u.id == uid) {
            if keys.validate_auth_id(&auth_id, now_sec) {
                authed_entry = Some((keys.cmd_key, u.clone()));
            }
        }
    }

    if authed_entry.is_none() {
        let _permit = decrypt_semaphore
            .acquire()
            .await
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Interrupted, e))?;
        let guard = users.read();
        authed_entry = guard
            .iter()
            .find(|(keys, u)| {
                Some(u.id) != cached_user_id && keys.validate_auth_id(&auth_id, now_sec)
            })
            .map(|(keys, u)| (keys.cmd_key, u.clone()));
    }

    let (cmd_key, user) = match authed_entry {
        Some((k, u)) => {
            info!("VMess: user auth succeeded: id={}, uuid={}", u.id, u.uuid);
            vmess_defense.record_success(client_ip);
            ctx.ip_user_cache.insert(client_ip, u.id);
            (k, u)
        }
        None => {
            warn!(
                "VMess: user auth failed for client_ip {} (users count: {})",
                client_ip,
                users.read().len()
            );
            vmess_defense.record_failure(client_ip);
            return Ok(None);
        }
    };

    if !ctx
        .device_limiter
        .check_and_record_async(user.id, client_ip)
        .await
    {
        warn!("VMess: device limit rejected for user {}", user.id);
        return Ok(None);
    }

    let conn_guard = match ctx.conn_limiter.try_acquire(user.id) {
        Some(g) => g,
        None => {
            warn!("VMess: connection limit rejected for user {}", user.id);
            return Ok(None);
        }
    };

    let mut len_and_nonce = [0u8; 26];
    if let Err(e) = stream.read_exact(&mut len_and_nonce).await {
        warn!(
            "VMess: failed to read len_and_nonce from {}: {:?}",
            client_ip, e
        );
        return Ok(None);
    }
    let mut enc_len_block = [0u8; 18];
    enc_len_block.copy_from_slice(&len_and_nonce[..18]);
    let mut conn_nonce = [0u8; 8];
    conn_nonce.copy_from_slice(&len_and_nonce[18..26]);

    let header_len =
        match decrypt_vmess_header_length(&cmd_key, &auth_id, &conn_nonce, &enc_len_block) {
            Ok(l) => l,
            Err(e) => {
                warn!(
                    "VMess: decrypt_vmess_header_length failed from {}: {:?}",
                    client_ip, e
                );
                return Ok(None);
            }
        };
    info!("VMess: decrypted header_len: {} bytes", header_len);

    let mut header_buf = vec![0u8; header_len + 16];
    if let Err(e) = stream.read_exact(&mut header_buf).await {
        warn!(
            "VMess: failed to read exact header_buf from {}: {:?}",
            client_ip, e
        );
        return Ok(None);
    }

    let req_header =
        match decrypt_vmess_header(&cmd_key, &auth_id, &enc_len_block, &conn_nonce, &header_buf) {
            Ok(h) => h,
            Err(e) => {
                warn!(
                    "VMess: decrypt_vmess_header failed from {}: {:?}",
                    client_ip, e
                );
                return Ok(None);
            }
        };

    info!(
        "VMess: request header parsed: target={}:{}, cmd={}",
        req_header.target_host, req_header.target_port, req_header.command
    );

    if req_header.command == CMD_MUX {
        warn!(
            "VMess Mux command requested from {}, but internal multiplexer is not active",
            client_ip
        );
        return Ok(None);
    }

    let (resp_header_38b, resp_key, resp_nonce) = match create_vmess_response_header(
        &req_header.request_body_key,
        &req_header.request_body_nonce,
        req_header.response_header,
        req_header.option,
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!(
                "VMess: create_vmess_response_header failed from {}: {:?}",
                client_ip, e
            );
            return Ok(None);
        }
    };

    stream.write_all(&resp_header_38b).await?;
    stream.flush().await?;
    info!("VMess: sent 38-byte response header to {}", client_ip);

    let target_host = req_header.target_host;
    let target_ip = req_header.target_ip;
    let target_port = req_header.target_port;
    let is_udp = req_header.command == CMD_UDP;

    if ctx.audit.should_block(&target_host, target_ip, target_port) {
        warn!(
            "VMess: audit blocked target {}:{}",
            target_host, target_port
        );
        return Ok(None);
    }

    let mctx = MatchContext {
        node_id: ctx.node_id,
        network: if is_udp { "udp" } else { "tcp" },
        target_host: &target_host,
        target_ip,
        target_port,
        inbound_local_ip: local_ip,
    };
    let outbound = ctx.router.match_outbound(&mctx);

    let out_stream = if is_udp {
        VmessOutbound::Udp(
            ctx.router
                .dialer()
                .dial_udp_outbound(&outbound, &target_host, target_port, local_ip)
                .await?,
        )
    } else {
        VmessOutbound::Tcp(Box::new(
            ctx.router
                .dialer()
                .dial(&outbound, &target_host, target_port, local_ip)
                .await?,
        ))
    };

    let decrypter = match VmessChunkDecrypter::new(
        &req_header.request_body_key,
        &req_header.request_body_nonce,
        req_header.security,
        req_header.option,
    ) {
        Ok(d) => d,
        Err(_) => return Ok(None),
    };

    let encrypter = match VmessChunkEncrypter::new(
        &resp_key,
        &resp_nonce,
        req_header.security,
        req_header.option,
    ) {
        Ok(e) => e,
        Err(_) => return Ok(None),
    };

    Ok(Some(VmessHandshakeData {
        client_stream: stream,
        out_stream,
        user,
        client_ip,
        target_host,
        target_port,
        is_udp,
        outbound_tag: outbound.tag,
        decrypter,
        encrypter,
        _conn_guard: Some(conn_guard),
    }))
}

async fn forward_vmess_stream(
    data: VmessHandshakeData,
    ctx: InboundContext,
) -> std::io::Result<()> {
    let VmessHandshakeData {
        client_stream,
        out_stream,
        user,
        client_ip,
        target_host,
        target_port,
        is_udp,
        outbound_tag,
        mut decrypter,
        mut encrypter,
        _conn_guard,
    } = data;

    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (tcp, udp) = match out_stream {
        VmessOutbound::Tcp(stream) => (Some(tokio::io::split(stream)), None),
        VmessOutbound::Udp(socket) => (None, Some(socket)),
    };
    let (mut out_read, mut out_write) = tcp.unzip();

    let start_time = Instant::now();
    let rate_limiter = ctx.rate_limiter.clone();
    let user_id = user.id;

    info!(
        "VMess: forward_vmess_stream active for user {} -> {}:{}",
        user_id, target_host, target_port
    );

    let is_auth_len = decrypter.is_authenticated_length();
    let idle = crate::conn::IdleTimeout::new(if is_udp {
        ctx.global_config.udp_timeout
    } else {
        ctx.global_config.tcp_timeout
    });

    let traffic = crate::conn::TrafficGuard::new(user_id, ctx.on_traffic.clone());
    let mut total_up = 0u64;
    let mut total_down = 0u64;

    let up_task = async {
        let mut len_block_18b = [0u8; 18];
        let mut len_block_2b = [0u8; 2];
        let mut payload_buf = vec![0u8; 65535];

        loop {
            let length = if is_auth_len {
                &mut len_block_18b[..]
            } else {
                &mut len_block_2b[..]
            };
            if idle.run(client_read.read_exact(length)).await.is_err() {
                break;
            }
            let chunk_len = match decrypter.decrypt_length(length) {
                Ok(length) => length,
                Err(e) => {
                    warn!(error = %e, "VMess invalid chunk length");
                    break;
                }
            };

            if chunk_len == 0 {
                info!("VMess: up_task received EOF marker from client");
                break;
            }
            if chunk_len > payload_buf.len() {
                warn!(
                    "VMess: up_task chunk_len {} exceeds payload_buf capacity {}",
                    chunk_len,
                    payload_buf.len()
                );
                break;
            }

            if let Err(e) = idle
                .run(client_read.read_exact(&mut payload_buf[..chunk_len]))
                .await
            {
                warn!("VMess: up_task read_exact payload chunk failed: {:?}", e);
                break;
            }

            let plain_len = match decrypter.decrypt_chunk_payload(&mut payload_buf[..chunk_len]) {
                Ok(l) => l,
                Err(e) => {
                    warn!("VMess: up_task decrypt_chunk_payload error: {:?}", e);
                    break;
                }
            };

            if plain_len == 0 {
                break;
            }

            rate_limiter.throttle(user_id, plain_len).await;

            let sent = match (&mut out_write, &udp) {
                (Some(writer), _) => {
                    let res = idle.run(writer.write_all(&payload_buf[..plain_len])).await;
                    if res.is_ok() {
                        let _ = idle.run(writer.flush()).await;
                    }
                    res
                }
                (_, Some(socket)) => idle
                    .run(socket.send(&payload_buf[..plain_len]))
                    .await
                    .map(|_| ()),
                _ => unreachable!(),
            };
            if let Err(e) = sent {
                warn!("VMess: up_task out_write failed: {:?}", e);
                break;
            }
            let wire_header_len = if is_auth_len { 18 } else { 2 };
            total_up += (wire_header_len + chunk_len) as u64;
            traffic.add((wire_header_len + chunk_len) as u64, 0);
        }
        if let Some(writer) = &mut out_write {
            let _ = writer.shutdown().await;
        }
        info!(
            "VMess: up_task completed with {} bytes transferred",
            total_up
        );
    };

    let down_task = async {
        let mut raw_buf = vec![0u8; if is_udp { 65535 } else { 16384 }];
        let mut enc_buf = Vec::with_capacity(16384 + 128);
        let mut chunk_count = 0u64;

        loop {
            let read_res = idle
                .run(async {
                    match (&mut out_read, &udp) {
                        (Some(reader), _) => reader.read(&mut raw_buf).await,
                        (_, Some(socket)) => socket.recv(&mut raw_buf).await.map(|(n, _)| n),
                        _ => unreachable!(),
                    }
                })
                .await;

            let n = match read_res {
                Ok(0) => break,
                Ok(n) => n,
                Err(e) => {
                    tracing::debug!(error = %e,"VMess outbound read ended");
                    break;
                }
            };
            chunk_count += 1;

            enc_buf.clear();
            if let Err(e) = encrypter.encrypt_chunk(&raw_buf[..n], &mut enc_buf) {
                warn!(
                    "VMess: down_task encrypt_chunk err on chunk #{}: {:?}",
                    chunk_count, e
                );
                break;
            }

            rate_limiter.throttle(user_id, enc_buf.len()).await;

            if let Err(e) = idle.run(client_write.write_all(&enc_buf)).await {
                warn!(
                    "VMess: down_task client_write err on chunk #{}: {:?}",
                    chunk_count, e
                );
                break;
            }
            if let Err(e) = idle.run(client_write.flush()).await {
                warn!(
                    "VMess: down_task client_write.flush err on chunk #{}: {:?}",
                    chunk_count, e
                );
                break;
            }
            total_down += enc_buf.len() as u64;
            traffic.add(0, enc_buf.len() as u64);
        }

        enc_buf.clear();
        if let Ok(()) = encrypter.encrypt_chunk(&[], &mut enc_buf) {
            info!(
                "VMess: down_task writing VMess EOF chunk (len={})",
                enc_buf.len()
            );
            if let Err(e) = idle.run(client_write.write_all(&enc_buf)).await {
                warn!("VMess: down_task write VMess EOF chunk failed: {:?}", e);
            } else {
                info!("VMess: down_task write VMess EOF chunk succeeded");
            }
        }

        info!("VMess: down_task calling client_write.flush()...");
        if let Err(e) = client_write.flush().await {
            warn!("VMess: down_task client_write.flush() failed: {:?}", e);
        } else {
            info!("VMess: down_task client_write.flush() succeeded");
        }

        info!("VMess: down_task calling client_write.shutdown()...");
        if let Err(e) = client_write.shutdown().await {
            warn!("VMess: down_task client_write.shutdown() failed: {:?}", e);
        } else {
            info!("VMess: down_task client_write.shutdown() succeeded");
        }

        info!(
            "VMess: down_task completed with {} bytes transferred in {} chunks",
            total_down, chunk_count
        );
    };

    if is_udp {
        tokio::select! { _ = up_task => {}, _ = down_task => {} }
    } else {
        tokio::join!(up_task, down_task);
    }
    info!(
        "VMess: stream forwarding ended for user {}, total_up={}, total_down={}",
        user_id, total_up, total_down
    );

    if total_down > 0 {
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    let duration = start_time.elapsed();

    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user.id,
        "vmess",
        if is_udp { "udp" } else { "tcp" },
        &client_ip.to_string(),
        &target_host,
        target_port,
        total_up,
        total_down,
        duration.as_millis() as i64,
        &outbound_tag,
        "connected",
    ));

    drop(_conn_guard);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::types::{
        GrpcTransportConfig, Http2TransportConfig, TcpTransportConfig, WebSocketTransportConfig,
        XHttpTransportConfig,
    };
    use crate::transport::TransportConfig;

    #[test]
    fn test_vmess_alpn_mapping() {
        let grpc_cfg = TransportConfig::Grpc(GrpcTransportConfig {
            service_name: "Tun".to_string(),
            authority: None,
            multi_mode: false,
            idle_timeout: Duration::from_secs(10),
            health_check_timeout: Duration::from_secs(10),
            permit_without_stream: false,
            initial_windows_size: 65535,
        });
        let h2_cfg = TransportConfig::LegacyHttp2(Http2TransportConfig {
            path: "/h2".to_string(),
            host: vec![],
        });
        let xhttp_cfg = TransportConfig::XHttp(XHttpTransportConfig {
            mode: "auto".to_string(),
            host: None,
            path: "/xhttp".to_string(),
            headers: std::collections::HashMap::new(),
            extra: None,
        });
        let ws_cfg = TransportConfig::WebSocket(WebSocketTransportConfig {
            path: "/ws".to_string(),
            host: None,
            headers: std::collections::HashMap::new(),
            heartbeat_period: None,
            early_data_header: None,
            max_early_data: 2048,
        });
        let tcp_cfg = TransportConfig::Tcp(TcpTransportConfig {
            header_type: crate::transport::TcpHeaderType::None,
            request: None,
            response: None,
        });

        let get_alpn = |t: &TransportConfig| match t {
            TransportConfig::Grpc(_) | TransportConfig::LegacyHttp2(_) => vec![b"h2".to_vec()],
            TransportConfig::XHttp(_) => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            _ => vec![b"http/1.1".to_vec()],
        };

        assert_eq!(get_alpn(&grpc_cfg), vec![b"h2".to_vec()]);
        assert_eq!(get_alpn(&h2_cfg), vec![b"h2".to_vec()]);
        assert_eq!(
            get_alpn(&xhttp_cfg),
            vec![b"h2".to_vec(), b"http/1.1".to_vec()]
        );
        assert_eq!(get_alpn(&ws_cfg), vec![b"http/1.1".to_vec()]);
        assert_eq!(get_alpn(&tcp_cfg), vec![b"http/1.1".to_vec()]);
    }
}
