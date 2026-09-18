use crate::conn::{bind_tcp_listener, read_proxy_protocol, BoxedStream, ProxyProtocolMode};
use crate::observability::AuditRecord;
use crate::panel::types::{NodeInfo, User};
use super::crypto::{
    create_vmess_response_header, decrypt_vmess_header, decrypt_vmess_header_length,
    VmessChunkDecrypter, VmessChunkEncrypter, VmessUserKeys, CMD_MUX, CMD_UDP,
};
use crate::protocol::{Inbound, InboundContext};
use crate::proxy::router::MatchContext;
use crate::security::TLSManager;
use crate::transport::{
    apply_transport, apply_transport_security, StreamSettings, TransportSecurityConfig,
};
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

        // Initialize TLSManager if TLS is configured
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
            _ => None,
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

        loop {
            tokio::select! {
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
                    tokio::spawn(async move {
                        let _ = handle_connection(stream, remote_addr, ctx, users, settings, tls_manager.as_deref(), force_md5, sem, def).await;
                    });
                }
            }
        }
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

    // 1. PROXY Protocol
    let proxy_mode = if settings.accept_proxy_protocol {
        ProxyProtocolMode::Strict
    } else {
        ctx.global_config.get_proxy_protocol_mode()
    };
    let (src_opt, stream) = match read_proxy_protocol(stream, proxy_mode).await {
        Ok(res) => res,
        Err(e) => {
            warn!("VMess: read_proxy_protocol failed from {}: {:?}", remote_addr, e);
            return Ok(());
        }
    };
    if let Some(src) = src_opt {
        remote_addr = src;
    }

    let client_ip = remote_addr.ip();
    if vmess_defense.is_banned(client_ip) {
        warn!("VMess: client_ip {} is banned by defense manager", client_ip);
        return Ok(());
    }

    // 2. Transport security (TLS)
    let sec_stream = match apply_transport_security(
        Box::new(stream),
        remote_addr,
        &settings.security,
        tls_manager,
        None,
        vec![],
    )
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return Ok(()),
        Err(e) => {
            warn!(
                "VMess transport security handshake failed from {}: {:?}",
                client_ip,
                e
            );
            return Ok(());
        }
    };

    // 3. Transport protocol (WS, gRPC, HTTPUpgrade, TCP)
    let stream = match apply_transport(sec_stream, &settings.transport).await {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "VMess transport handshake failed from {}: {:?}",
                client_ip,
                e
            );
            return Ok(());
        }
    };

    info!("VMess: transport handshake completed successfully from {}", client_ip);

    // 15-second handshake and outbound connection timeout
    let handshake_res = tokio::time::timeout(
        Duration::from_secs(15),
        perform_vmess_handshake(stream, remote_addr, local_ip, &ctx, &users, force_md5, decrypt_semaphore, vmess_defense),
    )
    .await;

    let handshake_data = match handshake_res {
        Ok(Ok(Some(data))) => data,
        Ok(Ok(None)) => {
            warn!("VMess: perform_vmess_handshake returned None for {}", client_ip);
            return Ok(());
        }
        Ok(Err(e)) => {
            warn!("VMess: perform_vmess_handshake error from {}: {:?}", client_ip, e);
            return Ok(());
        }
        Err(_) => {
            warn!("VMess: perform_vmess_handshake timed out for {}", client_ip);
            return Ok(());
        }
    };

    info!("VMess: handshake completed, entering forward_vmess_stream for {}", client_ip);
    // Forwarding phase: decoupled from 15-second handshake limit
    forward_vmess_stream(handshake_data, ctx).await
}

struct VmessHandshakeData {
    client_stream: BoxedStream,
    out_stream: BoxedStream,
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
        // Enforce VMessMD5-only mode when configured or alterId > 0
        vmess_defense.record_failure(client_ip);
        return Ok(None);
    }

    // 1. Read VMess AEAD 16-byte Auth ID
    let mut auth_id = [0u8; 16];
    if let Err(e) = stream.read_exact(&mut auth_id).await {
        warn!("VMess: failed to read 16-byte auth_id from {}: {:?}", client_ip, e);
        return Ok(None);
    }
    info!("VMess: read auth_id successfully from {}", client_ip);

    let now_sec = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let cached_user_id = ctx.ip_user_cache.get(&client_ip);
    let mut authed_entry = None;

    // Fast path: try cached user credential first (O(1) lookup)
    if let Some(uid) = cached_user_id {
        let guard = users.read();
        if let Some((keys, u)) = guard.iter().find(|(_, u)| u.id == uid) {
            if keys.validate_auth_id(&auth_id, now_sec) {
                authed_entry = Some((keys.cmd_key, u.clone()));
            }
        }
    }

    // Slow path: acquire concurrency semaphore and scan remaining users
    if authed_entry.is_none() {
        let _permit = decrypt_semaphore.acquire().await.map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Interrupted, e)
        })?;
        let guard = users.read();
        authed_entry = guard
            .iter()
            .find(|(keys, u)| Some(u.id) != cached_user_id && keys.validate_auth_id(&auth_id, now_sec))
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
            warn!("VMess: user auth failed for client_ip {} (users count: {})", client_ip, users.read().len());
            vmess_defense.record_failure(client_ip);
            return Ok(None);
        }
    };

    // Device limit check (async)
    if !ctx.device_limiter.check_and_record_async(user.id, client_ip).await {
        warn!("VMess: device limit rejected for user {}", user.id);
        return Ok(None);
    }

    // Connection limit check
    let conn_guard = match ctx.conn_limiter.try_acquire(user.id) {
        Some(g) => g,
        None => {
            warn!("VMess: connection limit rejected for user {}", user.id);
            return Ok(None);
        }
    };

    // 2. Read 18 bytes Encrypted Length + 8 bytes Connection Nonce
    let mut len_and_nonce = [0u8; 26];
    if let Err(e) = stream.read_exact(&mut len_and_nonce).await {
        warn!("VMess: failed to read len_and_nonce from {}: {:?}", client_ip, e);
        return Ok(None);
    }
    let mut enc_len_block = [0u8; 18];
    enc_len_block.copy_from_slice(&len_and_nonce[..18]);
    let mut conn_nonce = [0u8; 8];
    conn_nonce.copy_from_slice(&len_and_nonce[18..26]);

    let header_len = match decrypt_vmess_header_length(&cmd_key, &auth_id, &conn_nonce, &enc_len_block) {
        Ok(l) => l,
        Err(e) => {
            warn!("VMess: decrypt_vmess_header_length failed from {}: {:?}", client_ip, e);
            return Ok(None);
        }
    };
    info!("VMess: decrypted header_len: {} bytes", header_len);

    let mut header_buf = vec![0u8; header_len + 16];
    if let Err(e) = stream.read_exact(&mut header_buf).await {
        warn!("VMess: failed to read exact header_buf from {}: {:?}", client_ip, e);
        return Ok(None);
    }

    let req_header = match decrypt_vmess_header(
        &cmd_key,
        &auth_id,
        &enc_len_block,
        &conn_nonce,
        &header_buf,
    ) {
        Ok(h) => h,
        Err(e) => {
            warn!("VMess: decrypt_vmess_header failed from {}: {:?}", client_ip, e);
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

    // 3. Send VMess AEAD response header (38 bytes)
    let (resp_header_38b, resp_key, resp_nonce) = match create_vmess_response_header(
        &req_header.request_body_key,
        &req_header.request_body_nonce,
        req_header.response_header,
        req_header.option,
    ) {
        Ok(r) => r,
        Err(e) => {
            warn!("VMess: create_vmess_response_header failed from {}: {:?}", client_ip, e);
            return Ok(None);
        }
    };

    stream.write_all(&resp_header_38b).await?;
    info!("VMess: sent 38-byte response header to {}", client_ip);

    let target_host = req_header.target_host;
    let target_ip = req_header.target_ip;
    let target_port = req_header.target_port;
    let is_udp = req_header.command == CMD_UDP;

    // Audit check
    if ctx.audit.should_block(&target_host, target_ip, target_port) {
        warn!("VMess: audit blocked target {}:{}", target_host, target_port);
        return Ok(None);
    }

    // Match routing outbound
    let mctx = MatchContext {
        node_id: ctx.node_id,
        network: if is_udp { "udp" } else { "tcp" },
        target_host: &target_host,
        target_ip,
        target_port,
        inbound_local_ip: local_ip,
    };
    let outbound = ctx.router.match_outbound(&mctx);

    // Connect outbound
    let out_stream = match ctx
        .router
        .dialer()
        .dial(&outbound, &target_host, target_port, local_ip)
        .await
    {
        Ok(s) => s,
        Err(e) => {
            warn!("VMess: outbound dial failed to {}:{}: {:?}", target_host, target_port, e);
            return Ok(None);
        }
    };
    info!("VMess: outbound dial connected to {}:{}", target_host, target_port);

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
        out_stream: Box::new(out_stream),
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
    let (mut out_read, mut out_write) = tokio::io::split(out_stream);

    let start_time = Instant::now();
    let rate_limiter = ctx.rate_limiter.clone();
    let user_id = user.id;

    info!("VMess: forward_vmess_stream active for user {} -> {}:{}", user_id, target_host, target_port);

    let is_auth_len = decrypter.is_authenticated_length();
    let (down_tx, mut down_rx) = tokio::sync::oneshot::channel::<()>();

    // Client -> Outbound (Decryption worker)
    let up_task = async {
        let mut len_block_18b = [0u8; 18];
        let mut len_block_2b = [0u8; 2];
        let mut payload_buf = vec![0u8; 65535];
        let mut up = 0u64;
        let mut down_finished = false;

        loop {
            let chunk_len = if is_auth_len {
                let read_timeout = if down_finished {
                    Duration::from_millis(1000)
                } else {
                    Duration::from_secs(60)
                };

                let read_res: Option<std::io::Result<usize>> = if down_finished {
                    tokio::time::timeout(read_timeout, client_read.read_exact(&mut len_block_18b)).await.ok()
                } else {
                    tokio::select! {
                        biased;
                        res = client_read.read_exact(&mut len_block_18b) => {
                            Some(res)
                        }
                        _ = &mut down_rx => {
                            down_finished = true;
                            tokio::time::timeout(Duration::from_millis(1000), client_read.read_exact(&mut len_block_18b)).await.ok()
                        }
                        _ = tokio::time::sleep(read_timeout) => {
                            None
                        }
                    }
                };
                match read_res {
                    Some(Ok(_)) => {
                        match decrypter.decrypt_length(&len_block_18b) {
                            Ok(l) => l,
                            Err(e) => {
                                warn!("VMess: up_task decrypt_length error: {:?}", e);
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        info!("VMess: up_task client_read eof: {:?}", e);
                        break;
                    }
                    None => {
                        info!("VMess: up_task read timeout (down_finished={})", down_finished);
                        break;
                    }
                }
            } else {
                let read_timeout = if down_finished {
                    Duration::from_millis(1000)
                } else {
                    Duration::from_secs(60)
                };

                let read_res: Option<std::io::Result<usize>> = if down_finished {
                    tokio::time::timeout(read_timeout, client_read.read_exact(&mut len_block_2b)).await.ok()
                } else {
                    tokio::select! {
                        biased;
                        res = client_read.read_exact(&mut len_block_2b) => {
                            Some(res)
                        }
                        _ = &mut down_rx => {
                            down_finished = true;
                            tokio::time::timeout(Duration::from_millis(1000), client_read.read_exact(&mut len_block_2b)).await.ok()
                        }
                        _ = tokio::time::sleep(read_timeout) => {
                            None
                        }
                    }
                };
                match read_res {
                    Some(Ok(_)) => {
                        match decrypter.decrypt_length(&len_block_2b) {
                            Ok(l) => l,
                            Err(e) => {
                                warn!("VMess: up_task decrypt_length error: {:?}", e);
                                break;
                            }
                        }
                    }
                    Some(Err(e)) => {
                        info!("VMess: up_task client_read eof: {:?}", e);
                        break;
                    }
                    None => {
                        info!("VMess: up_task read timeout (down_finished={})", down_finished);
                        break;
                    }
                }
            };

            // 0 means EOF marker from client
            if chunk_len == 0 {
                info!("VMess: up_task received EOF marker from client");
                break;
            }
            if chunk_len > payload_buf.len() {
                warn!("VMess: up_task chunk_len {} exceeds payload_buf capacity {}", chunk_len, payload_buf.len());
                break;
            }

            if let Err(e) = client_read.read_exact(&mut payload_buf[..chunk_len]).await {
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

            // Rate limiter enforcement
            rate_limiter.throttle(user_id, plain_len).await;

            if let Err(e) = out_write.write_all(&payload_buf[..plain_len]).await {
                warn!("VMess: up_task out_write failed: {:?}", e);
                break;
            }
            let wire_header_len = if is_auth_len { 18 } else { 2 };
            up += (wire_header_len + chunk_len) as u64;
        }
        let _ = out_write.shutdown().await;
        info!("VMess: up_task completed with {} bytes transferred", up);
        up
    };

    // Outbound -> Client (Encryption worker)
    let down_task = async {
        let mut raw_buf = [0u8; 16384];
        let mut enc_buf = Vec::with_capacity(16384 + 128);
        let mut down = 0u64;
        let mut chunk_count = 0u64;

        loop {
            let read_res =
                tokio::time::timeout(Duration::from_secs(60), out_read.read(&mut raw_buf)).await;

            let n = match read_res {
                Ok(Ok(0)) => {
                    info!("VMess: down_task target returned EOF after {} chunks", chunk_count);
                    break;
                }
                Ok(Err(e)) => {
                    warn!("VMess: down_task target read err after {} chunks: {:?}", chunk_count, e);
                    break;
                }
                Err(_) => {
                    warn!("VMess: down_task target read timeout 60s after {} chunks", chunk_count);
                    break;
                }
                Ok(Ok(n)) => n,
            };
            chunk_count += 1;

            enc_buf.clear();
            if let Err(e) = encrypter.encrypt_chunk(&raw_buf[..n], &mut enc_buf) {
                warn!("VMess: down_task encrypt_chunk err on chunk #{}: {:?}", chunk_count, e);
                break;
            }

            // Rate limiter enforcement
            rate_limiter.throttle(user_id, enc_buf.len()).await;

            if let Err(e) = client_write.write_all(&enc_buf).await {
                warn!("VMess: down_task client_write err on chunk #{}: {:?}", chunk_count, e);
                break;
            }
            down += enc_buf.len() as u64;
        }

        // Send VMess EOF chunk (0-byte payload) to signal stream termination
        enc_buf.clear();
        if let Ok(()) = encrypter.encrypt_chunk(&[], &mut enc_buf) {
            info!("VMess: down_task writing VMess EOF chunk (len={})", enc_buf.len());
            if let Err(e) = client_write.write_all(&enc_buf).await {
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

        info!("VMess: down_task completed with {} bytes transferred in {} chunks", down, chunk_count);
        let _ = down_tx.send(());
        down
    };

    let (total_up, total_down) = tokio::join!(up_task, down_task);
    info!(
        "VMess: stream forwarding ended for user {}, total_up={}, total_down={}",
        user_id, total_up, total_down
    );

    // If downstream data was written, allow a brief drain window for OS kernel buffers
    // to be delivered and acknowledged by the client before dropping the socket fd.
    if total_down > 0 {
        tokio::time::sleep(Duration::from_millis(300)).await;
    }

    let duration = start_time.elapsed();

    if total_up > 0 || total_down > 0 {
        (ctx.on_traffic)(user.id, total_up, total_down);
    }

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
