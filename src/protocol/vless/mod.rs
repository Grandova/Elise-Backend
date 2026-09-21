pub mod encryption;
pub mod header;
pub mod mux;
pub mod timing;
pub mod vision;

pub use encryption::VlessEncryptionServer;
pub use header::{
    parse_vless_request_header, process_uuid, write_vless_response_header, VlessAddons,
    VlessRequestHeader,
};
pub use mux::handle_vless_mux;
pub use timing::{
    init_collector, is_timing_enabled, new_tracker, record_event, set_timing_enabled,
    take_collected_records, SharedTimingTracker, TimingRecord, VisionTimingEvent,
};
pub use vision::{
    TrafficState, VisionReader, VisionWriter, FLOW_VISION, VISION_CMD_CONTINUE, VISION_CMD_DIRECT,
    VISION_CMD_END,
};

use crate::conn::{bind_tcp_listener, read_proxy_protocol, BoxedStream, MonitoredStream};
use crate::observability::AuditRecord;
use crate::panel::types::{NodeInfo, User};
use crate::protocol::{Inbound, InboundContext};
use crate::proxy::router::MatchContext;
use crate::security::reality::RealityServer;
use crate::transport::security::apply_transport_security;
use crate::transport::serve_transport;
use crate::transport::types::{
    StreamSettings, TransportConfig, TransportSecurityConfig, VlessEncryptionConfig, VlessFlow,
    VlessNodeConfig,
};
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tracing::{error, info, warn};
use uuid::Uuid;

pub struct VlessInbound {
    users: Arc<RwLock<Arc<HashMap<[u8; 16], Arc<User>>>>>,
}

impl Default for VlessInbound {
    fn default() -> Self {
        Self {
            users: Arc::new(RwLock::new(Arc::new(HashMap::new()))),
        }
    }
}

impl VlessInbound {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Inbound for VlessInbound {
    fn protocol_type(&self) -> &'static str {
        "vless"
    }

    fn update_users(&self, users: Vec<User>) {
        let mut map = HashMap::with_capacity(users.len());
        for u in users {
            if let Ok(parsed_uuid) = Uuid::parse_str(&u.uuid) {
                map.insert(process_uuid(*parsed_uuid.as_bytes()), Arc::new(u));
            }
        }
        *self.users.write() = Arc::new(map);
    }

    async fn start(
        &self,
        ctx: InboundContext,
        node_info: NodeInfo,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> std::io::Result<()> {
        let node_config = match VlessNodeConfig::from_node_info(&node_info) {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("VLESS configuration error for node {}: {}", ctx.node_id, e);
                return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, e));
            }
        };

        let encryption_server = match &node_config.encryption {
            VlessEncryptionConfig::Mlkem768X25519Plus(mlkem) => {
                match VlessEncryptionServer::new(mlkem) {
                    Ok(srv) => {
                        tracing::info!(
                            "Node {}: VLESS Encryption server initialized (mode: {}, keys: {})",
                            ctx.node_id,
                            mlkem.xor_mode,
                            mlkem.server_keys.len()
                        );
                        Some(Arc::new(srv))
                    }
                    Err(e) => {
                        error!("Failed to initialize VLESS encryption server: {}", e);
                        return Err(e);
                    }
                }
            }
            VlessEncryptionConfig::None => None,
        };

        let reality_server = match &node_config.stream.security {
            TransportSecurityConfig::Reality(reality_cfg) => {
                let srv = RealityServer::new(reality_cfg.clone())
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
                Some(Arc::new(srv))
            }
            _ => None,
        };

        let tls_manager = match &node_config.stream.security {
            TransportSecurityConfig::Tls(tls_cfg) => {
                let mgr = crate::security::TLSManager::from_config(
                    tls_cfg,
                    ctx.global_config.auto_tls,
                    &ctx.global_config.fake_sni,
                )
                .map_err(|e| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("Failed to initialize TLS for VLESS inbound: {e}"),
                    )
                })?;
                Some(Arc::new(mgr))
            }
            _ => Some(ctx.tls_manager.clone()),
        };

        let bind_addr = format!("{}:{}", ctx.listen_addr, ctx.port);
        let listener = bind_tcp_listener(&bind_addr, ctx.global_config.mptcp).await?;
        info!(
            "VLESS inbound listening on {} (transport: {:?}, security: {:?}, encryption: {:?})",
            bind_addr,
            node_config.stream.transport,
            node_config.stream.security,
            node_config.encryption
        );

        let users = self.users.clone();
        let node_config = Arc::new(node_config);
        let stream_settings = Arc::new(node_config.stream.clone());

        let mut connections = tokio::task::JoinSet::new();
        ctx.mark_ready();
        loop {
            tokio::select! {
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(e)) = result { tracing::warn!(error = %e, "Connection task failed"); }
                }
                _ = shutdown_rx.recv() => {
                    info!("VLESS inbound on port {} stopping", ctx.port);
                    break;
                }
                accept_res = listener.accept() => {
                    let (stream, remote_addr) = match accept_res {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!("VLESS accept error: {:?}", e);
                            continue;
                        }
                    };
                    let _ = stream.set_nodelay(true);

                    let ctx = ctx.clone();
                    let users = users.clone();
                    let stream_settings = stream_settings.clone();
                    let encryption_server = encryption_server.clone();
                    let reality_server = reality_server.clone();
                    let tls_manager = tls_manager.clone();
                    let node_config = node_config.clone();

                    let tracker = Some(new_tracker(remote_addr));
                    record_event(&tracker, VisionTimingEvent::TcpAccept);

                    connections.spawn(async move {
                        let _ = handle_connection(
                            stream,
                            remote_addr,
                            ctx,
                            users,
                            stream_settings,
                            encryption_server,
                            tls_manager.as_deref(),
                            reality_server.as_deref(),
                            node_config,
                            tracker,
                        ).await;
                    });
                }
            }
        }
        drop(listener);
        crate::protocol::common::inbound::drain_connections(&mut connections).await;
        Ok(())
    }
}

struct VlessHandshakeData {
    stream: BoxedStream,
    client_ip: IpAddr,
    local_ip: Option<IpAddr>,
    remote_addr: SocketAddr,
    user: Arc<User>,
    _conn_guard: crate::limiter::ConnGuard,
    command: u8,
    is_vision: bool,
    uuid_bytes: [u8; 16],
    target_host: String,
    target_ip: Option<IpAddr>,
    target_port: u16,
    timing_tracker: Option<SharedTimingTracker>,
}

async fn handle_connection(
    stream: TcpStream,
    mut remote_addr: SocketAddr,
    ctx: InboundContext,
    users: Arc<RwLock<Arc<HashMap<[u8; 16], Arc<User>>>>>,
    stream_settings: Arc<StreamSettings>,
    encryption_server: Option<Arc<VlessEncryptionServer>>,
    tls_manager: Option<&crate::security::TLSManager>,
    reality_server: Option<&RealityServer>,
    node_config: Arc<VlessNodeConfig>,
    timing_tracker: Option<SharedTimingTracker>,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);
    let local_ip = stream.local_addr().ok().map(|s| s.ip());

    let (src_opt, stream) =
        read_proxy_protocol(stream, ctx.global_config.get_proxy_protocol_mode()).await?;
    if let Some(src) = src_opt {
        remote_addr = src;
    }

    let client_ip = remote_addr.ip();
    if ctx.defense.is_banned(client_ip) {
        return Ok(());
    }

    let stream: BoxedStream = Box::new(stream);
    let alpn = match &stream_settings.transport {
        TransportConfig::Grpc(_) | TransportConfig::LegacyHttp2(_) => {
            vec![b"h2".to_vec()]
        }
        TransportConfig::XHttp(_) => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        _ => vec![b"http/1.1".to_vec()],
    };
    let sec_stream = match apply_transport_security(
        stream,
        remote_addr,
        &stream_settings.security,
        tls_manager,
        reality_server,
        alpn,
    )
    .await
    {
        Ok(Some(s)) => {
            record_event(&timing_tracker, VisionTimingEvent::TlsHandshakeComplete);
            s
        }
        Ok(None) => return Ok(()),
        Err(e) => {
            warn!(
                "VLESS transport security error from {}: {:?}",
                remote_addr, e
            );
            return Ok(());
        }
    };

    let ctx_clone = ctx.clone();
    let users_clone = users.clone();
    let stream_settings_clone = stream_settings.clone();
    let enc_clone = encryption_server.clone();
    let conf_clone = node_config.clone();
    let timing_tracker_inner = timing_tracker.clone();

    let res = serve_transport(
        sec_stream,
        &stream_settings.transport,
        tls_manager,
        move |stream| {
            let ctx = ctx_clone.clone();
            let users = users_clone.clone();
            let stream_settings = stream_settings_clone.clone();
            let encryption_server = enc_clone.clone();
            let node_config = conf_clone.clone();
            let timing_tracker = timing_tracker_inner.clone();
            async move {
                let handshake_res = tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    perform_vless_stream_handshake(
                        stream,
                        remote_addr,
                        local_ip,
                        &ctx,
                        &users,
                        &stream_settings,
                        encryption_server.as_ref(),
                        &node_config,
                        &timing_tracker,
                    ),
                )
                .await;

                let handshake_data = match handshake_res {
                    Ok(Ok(Some(data))) => data,
                    _ => return,
                };

                let VlessHandshakeData {
                    stream,
                    client_ip,
                    local_ip,
                    remote_addr,
                    user,
                    _conn_guard,
                    command,
                    is_vision,
                    uuid_bytes,
                    target_host,
                    target_ip,
                    target_port,
                    timing_tracker,
                } = handshake_data;

                if command == 0x02 {
                    let _ = handle_vless_udp(
                        stream,
                        _conn_guard,
                        client_ip,
                        local_ip,
                        user,
                        ctx,
                        target_host,
                        target_ip,
                        target_port,
                    )
                    .await;
                    return;
                }

                if command == 0x03 {
                    let _ = handle_vless_mux(
                        stream,
                        _conn_guard,
                        client_ip,
                        local_ip,
                        user,
                        ctx,
                        remote_addr,
                    )
                    .await;
                    return;
                }

                if is_vision {
                    record_event(&timing_tracker, VisionTimingEvent::VisionStart);
                    let _ = handle_vless_vision_tcp(
                        stream,
                        uuid_bytes,
                        _conn_guard,
                        client_ip,
                        local_ip,
                        user,
                        ctx,
                        remote_addr,
                        target_host,
                        target_ip,
                        target_port,
                        timing_tracker,
                    )
                    .await;
                    return;
                }

                record_event(&timing_tracker, VisionTimingEvent::StandardStart);
                let _ = handle_vless_standard_tcp(
                    stream,
                    _conn_guard,
                    client_ip,
                    local_ip,
                    user,
                    ctx,
                    remote_addr,
                    target_host,
                    target_ip,
                    target_port,
                    timing_tracker,
                )
                .await;
            }
        },
    )
    .await;

    if let Err(e) = res {
        warn!("VLESS transport serve error from {}: {:?}", remote_addr, e);
    }
    Ok(())
}

async fn perform_vless_stream_handshake(
    stream: BoxedStream,
    remote_addr: SocketAddr,
    local_ip: Option<IpAddr>,
    ctx: &InboundContext,
    users: &Arc<RwLock<Arc<HashMap<[u8; 16], Arc<User>>>>>,
    stream_settings: &StreamSettings,
    encryption_server: Option<&Arc<VlessEncryptionServer>>,
    node_config: &VlessNodeConfig,
    timing_tracker: &Option<SharedTimingTracker>,
) -> std::io::Result<Option<VlessHandshakeData>> {
    let client_ip = remote_addr.ip();
    if ctx.defense.is_banned(client_ip) {
        return Ok(None);
    }

    let stream = if let Some(enc_srv) = encryption_server {
        tracing::debug!(
            "VLESS: Performing VLESS Encryption handshake with {}",
            remote_addr
        );
        match enc_srv.handshake(stream).await {
            Ok(s) => {
                tracing::debug!(
                    "VLESS: VLESS Encryption handshake succeeded with {}",
                    remote_addr
                );
                s
            }
            Err(e) => {
                warn!(
                    "VLESS encryption handshake error from {}: {:?}",
                    remote_addr, e
                );
                return Ok(None);
            }
        }
    } else {
        stream
    };

    let mut stream = stream;

    let req = match parse_vless_request_header(&mut stream).await {
        Ok(r) => {
            tracing::debug!(
                "VLESS: request header parsed from {}: cmd={}, host={}:{}",
                remote_addr,
                r.command,
                r.target_host,
                r.target_port
            );
            r
        }
        Err(e) => {
            warn!(
                "VLESS request header parse error from {}: {:?}",
                remote_addr, e
            );
            return Ok(None);
        }
    };

    let processed_uuid = process_uuid(req.uuid_bytes);
    let user = {
        let users_map = users.read().clone();
        match users_map.get(&processed_uuid).cloned() {
            Some(u) => {
                ctx.defense.record_success(remote_addr.ip());
                u
            }
            None => {
                ctx.defense.record_failure(remote_addr.ip());
                return Ok(None);
            }
        }
    };

    record_event(
        timing_tracker,
        VisionTimingEvent::VlessAuthComplete {
            flow: req.addons.flow.clone(),
        },
    );

    if !ctx
        .device_limiter
        .check_and_record_async(user.id, remote_addr.ip())
        .await
    {
        return Ok(None);
    }

    let conn_guard = match ctx.conn_limiter.try_acquire(user.id) {
        Some(g) => g,
        None => return Ok(None),
    };

    let user_flow_is_vision = user.flow.as_deref().unwrap_or("") == FLOW_VISION
        || matches!(node_config.flow, VlessFlow::Vision);
    let client_req_vision = req.addons.flow == FLOW_VISION;

    if client_req_vision && !user_flow_is_vision {
        warn!(
            "VLESS: Client requested Vision flow but user account does not permit it from {}",
            remote_addr
        );
        return Ok(None);
    }
    if !client_req_vision && user_flow_is_vision {
        warn!(
            "VLESS: User requires Vision flow but client did not request it from {}",
            remote_addr
        );
        return Ok(None);
    }

    let is_vision = client_req_vision;
    if is_vision {
        let is_tcp = matches!(stream_settings.transport, TransportConfig::Tcp(_));
        let is_tls_or_reality = matches!(
            stream_settings.security,
            TransportSecurityConfig::Tls(_) | TransportSecurityConfig::Reality(_)
        );
        if !is_tcp || !is_tls_or_reality {
            warn!(
                "VLESS: Vision flow requested on incompatible transport/security ({:?}/{:?}) from {}",
                stream_settings.transport, stream_settings.security, remote_addr
            );
            return Ok(None);
        }

        if req.command == 0x02 {
            warn!(
                "VLESS: Vision flow requested with unsupported UDP command from {}",
                remote_addr
            );
            return Ok(None);
        }
    }

    if req.command == 0x04 {
        warn!(
            "VLESS: Reverse proxy command 0x04 requested but not supported from {}",
            remote_addr
        );
        return Ok(None);
    }

    write_vless_response_header(&mut stream).await?;

    Ok(Some(VlessHandshakeData {
        stream,
        client_ip,
        local_ip,
        remote_addr,
        user,
        _conn_guard: conn_guard,
        command: req.command,
        is_vision,
        uuid_bytes: req.uuid_bytes,
        target_host: req.target_host,
        target_ip: req.target_ip,
        target_port: req.target_port,
        timing_tracker: timing_tracker.clone(),
    }))
}

async fn handle_vless_standard_tcp(
    stream: BoxedStream,
    _conn_guard: crate::limiter::ConnGuard,
    client_ip: IpAddr,
    local_ip: Option<IpAddr>,
    user: Arc<User>,
    ctx: InboundContext,
    remote_addr: SocketAddr,
    target_host: String,
    target_ip: Option<IpAddr>,
    target_port: u16,
    timing_tracker: Option<SharedTimingTracker>,
) -> std::io::Result<()> {
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

    record_event(&timing_tracker, VisionTimingEvent::OutboundConnectStart);
    let out_stream = match ctx
        .router
        .dialer()
        .dial(&outbound, dial_host, target_port, local_ip)
        .await
    {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };
    record_event(&timing_tracker, VisionTimingEvent::OutboundConnectComplete);

    let client_conn = MonitoredStream::new(stream, user.id, remote_addr);
    let _traffic = client_conn.traffic_guard(ctx.on_traffic.clone());
    let start_time = Instant::now();

    let mut timed_client = timing::TimingWrapper {
        inner: client_conn,
        timing: timing_tracker.clone(),
        on_first_read: None,
        on_first_write: Some(VisionTimingEvent::FirstVisionWrite),
    };

    let mut timed_out = timing::TimingWrapper {
        inner: out_stream,
        timing: timing_tracker.clone(),
        on_first_read: Some(VisionTimingEvent::FirstUpstreamResponse),
        on_first_write: Some(VisionTimingEvent::FirstOutboundWrite),
    };

    let _ = crate::conn::copy_bidirectional_throttled(
        &mut timed_client,
        &mut timed_out,
        user.id,
        Some(&ctx.rate_limiter),
        ctx.global_config.tcp_timeout,
    )
    .await;

    record_event(&timing_tracker, VisionTimingEvent::Finish);

    let duration = start_time.elapsed();
    let (up, down) = timed_client.inner.stats();

    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user.id,
        "vless",
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

async fn handle_vless_vision_tcp(
    stream: BoxedStream,
    uuid_bytes: [u8; 16],
    _conn_guard: crate::limiter::ConnGuard,
    client_ip: IpAddr,
    local_ip: Option<IpAddr>,
    user: Arc<User>,
    ctx: InboundContext,
    _remote_addr: SocketAddr,
    target_host: String,
    target_ip: Option<IpAddr>,
    target_port: u16,
    timing_tracker: Option<SharedTimingTracker>,
) -> std::io::Result<()> {
    let idle = crate::conn::IdleTimeout::new(ctx.global_config.tcp_timeout);
    let direct_control = stream.direct_control();
    let (client_read, client_write) = tokio::io::split(stream);
    let mut vision_reader = VisionReader::new(client_read, uuid_bytes);
    vision_reader.set_timing_tracker(timing_tracker.clone());
    vision_reader.set_direct_control(direct_control.clone());

    let (mut out_stream, sniff_buf, outbound) =
        if !ctx.global_config.sniff_redirect || target_ip.is_none() {
            if ctx.audit.should_block(&target_host, target_ip, target_port) {
                return Ok(());
            }
            let mctx = MatchContext {
                node_id: ctx.node_id,
                network: "tcp",
                target_host: &target_host,
                target_ip,
                target_port,
                inbound_local_ip: local_ip,
            };
            let outbound = ctx.router.match_outbound(&mctx);

            record_event(&timing_tracker, VisionTimingEvent::OutboundConnectStart);
            let dialer = ctx.router.dialer();
            let dial_fut = dialer.dial(&outbound, &target_host, target_port, local_ip);
            let tracker_clone = timing_tracker.clone();
            let read_fut = async {
                let mut buf = vec![0u8; 4096];
                let n = idle.run(vision_reader.read_payload(&mut buf)).await?;
                if n == 0 {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "Client EOF on first packet",
                    ));
                }
                buf.truncate(n);
                if buf.starts_with(&[0x16, 0x03]) && buf.get(5) == Some(&0x01) {
                    record_event(&tracker_clone, VisionTimingEvent::ClientHelloDetected);
                }
                Ok::<_, std::io::Error>(buf)
            };

            let (dial_res, read_res) = tokio::join!(dial_fut, read_fut);
            let s = match dial_res {
                Ok(s) => s,
                Err(_) => return Ok(()),
            };
            record_event(&timing_tracker, VisionTimingEvent::OutboundConnectComplete);
            let b = match read_res {
                Ok(b) => b,
                Err(_) => return Ok(()),
            };
            (s, b, outbound)
        } else {
            let mut buf = vec![0u8; 4096];
            let n = idle.run(vision_reader.read_payload(&mut buf)).await?;
            if n == 0 {
                return Ok(());
            }
            buf.truncate(n);

            if buf.starts_with(&[0x16, 0x03]) && buf.get(5) == Some(&0x01) {
                record_event(&timing_tracker, VisionTimingEvent::ClientHelloDetected);
            }

            let sniffed = if ctx.global_config.domain_sniff {
                crate::conn::sniff_domain(&buf)
            } else {
                None
            };

            let sniffed_host = sniffed.map(|(d, _)| d);
            let match_host = sniffed_host.as_deref().unwrap_or(&target_host);
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

            record_event(&timing_tracker, VisionTimingEvent::OutboundConnectStart);
            let s = match ctx
                .router
                .dialer()
                .dial(&outbound, dial_host, target_port, local_ip)
                .await
            {
                Ok(s) => s,
                Err(_) => return Ok(()),
            };
            record_event(&timing_tracker, VisionTimingEvent::OutboundConnectComplete);
            (s, buf, outbound)
        };

    ctx.rate_limiter.throttle(user.id, sniff_buf.len()).await;
    idle.run(out_stream.write_all(&sniff_buf)).await?;
    idle.run(out_stream.flush()).await?;
    record_event(&timing_tracker, VisionTimingEvent::FirstOutboundWrite);
    let initial_up = sniff_buf.len() as u64;
    let traffic = crate::conn::TrafficGuard::new(user.id, ctx.on_traffic.clone());
    traffic.add(initial_up, 0);

    let (mut out_read, mut out_write) = tokio::io::split(out_stream);
    let mut vision_writer = VisionWriter::new(client_write, uuid_bytes);
    vision_writer.set_timing_tracker(timing_tracker.clone());

    let writer_direct_control = direct_control;
    vision_writer.set_direct_control(writer_direct_control);

    let rate_limiter = ctx.rate_limiter.clone();
    let user_id = user.id;
    let start_time = Instant::now();

    let mut total_up = initial_up;
    let mut total_down = 0u64;

    let up_target = target_host.clone();
    let up_task = async {
        let mut buf = vec![0u8; 32768];
        loop {
            let read_res = idle.run(vision_reader.read_payload(&mut buf)).await;

            let n = match read_res {
                Ok(n) if n > 0 => n,
                Ok(_) => {
                    tracing::debug!(target_host = %up_target, "Vision uplink clean EOF");
                    break;
                }
                Err(e) => {
                    tracing::debug!(target_host = %up_target, error = %e, "Vision uplink read error or timeout");
                    break;
                }
            };

            rate_limiter.throttle(user_id, n).await;
            if let Err(e) = idle.run(out_write.write_all(&buf[..n])).await {
                tracing::debug!(target_host = %up_target, error = %e, "Vision uplink write error to upstream");
                break;
            }
            let _ = idle.run(out_write.flush()).await;
            total_up += n as u64;
            traffic.add(n as u64, 0);
        }
        let _ = out_write.shutdown().await;
    };

    let down_timing = timing_tracker.clone();
    let down_target = target_host.clone();
    let down_task = async {
        let mut buf = vec![0u8; 32768];
        let mut first_resp = true;
        loop {
            let read_res = idle.run(out_read.read(&mut buf)).await;

            let n = match read_res {
                Ok(n) if n > 0 => n,
                Ok(_) => {
                    tracing::debug!(target_host = %down_target, "Vision downlink clean EOF from upstream");
                    break;
                }
                Err(e) => {
                    tracing::debug!(target_host = %down_target, error = %e, "Vision downlink read error from upstream");
                    break;
                }
            };

            if first_resp {
                record_event(&down_timing, VisionTimingEvent::FirstUpstreamResponse);
                first_resp = false;
            }

            rate_limiter.throttle(user_id, n).await;
            if let Err(e) = idle.run(vision_writer.write_payload(&buf[..n])).await {
                tracing::debug!(target_host = %down_target, error = %e, "Vision downlink write error to client");
                break;
            }
            total_down += n as u64;
            traffic.add(0, n as u64);
        }
        let _ = vision_writer.shutdown().await;
    };

    tokio::join!(up_task, down_task);

    record_event(&timing_tracker, VisionTimingEvent::Finish);

    let duration = start_time.elapsed();

    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user.id,
        "vless",
        "tcp-vision",
        &client_ip.to_string(),
        &target_host,
        target_port,
        total_up,
        total_down,
        duration.as_millis() as i64,
        &outbound.tag,
        "connected",
    ));

    Ok(())
}

async fn handle_vless_udp(
    stream: BoxedStream,
    _conn_guard: crate::limiter::ConnGuard,
    client_ip: IpAddr,
    local_ip: Option<IpAddr>,
    user: Arc<User>,
    ctx: InboundContext,
    target_host: String,
    target_ip: Option<IpAddr>,
    target_port: u16,
) -> std::io::Result<()> {
    if ctx.audit.should_block(&target_host, target_ip, target_port) {
        return Ok(());
    }

    let mctx = MatchContext {
        node_id: ctx.node_id,
        network: "udp",
        target_host: &target_host,
        target_ip,
        target_port,
        inbound_local_ip: local_ip,
    };
    let outbound = ctx.router.match_outbound(&mctx);

    let udp_socket = Arc::new(
        ctx.router
            .dialer()
            .dial_udp_outbound(&outbound, &target_host, target_port, local_ip)
            .await?,
    );

    let idle = crate::conn::IdleTimeout::new(ctx.global_config.udp_timeout);
    let (mut client_read, mut client_write) = tokio::io::split(stream);
    let start_time = Instant::now();

    let sock_recv = udp_socket.clone();
    let sock_send = udp_socket;

    let rate_limiter = ctx.rate_limiter.clone();
    let user_id = user.id;

    let traffic = crate::conn::TrafficGuard::new(user_id, ctx.on_traffic.clone());
    let mut total_up = 0u64;
    let mut total_down = 0u64;

    let up_task = async {
        let mut len_buf = [0u8; 2];
        let mut payload = vec![0u8; 65535];

        loop {
            let read_res = idle.run(client_read.read_exact(&mut len_buf)).await;

            match read_res {
                Ok(_) => {}
                _ => break,
            }

            let length = u16::from_be_bytes(len_buf) as usize;
            if length == 0 {
                continue;
            }

            if length > payload.len() {
                payload.resize(length, 0);
            }

            if idle
                .run(client_read.read_exact(&mut payload[..length]))
                .await
                .is_err()
            {
                break;
            }

            rate_limiter.throttle(user_id, 2 + length).await;

            if idle.run(sock_send.send(&payload[..length])).await.is_err() {
                break;
            }

            total_up += (2 + length) as u64;
            traffic.add((2 + length) as u64, 0);
        }
    };

    let down_task = async {
        let mut buf = [0u8; 65535];
        let mut out_pkt = Vec::with_capacity(65535 + 4);

        loop {
            let recv_res = idle.run(sock_recv.recv(&mut buf)).await;

            let n = match recv_res {
                Ok((n, _)) => n,
                _ => break,
            };

            out_pkt.clear();
            out_pkt.extend_from_slice(&(n as u16).to_be_bytes());
            out_pkt.extend_from_slice(&buf[..n]);

            rate_limiter.throttle(user_id, out_pkt.len()).await;

            if idle.run(client_write.write_all(&out_pkt)).await.is_err() {
                break;
            }
            total_down += out_pkt.len() as u64;
            traffic.add(0, out_pkt.len() as u64);
        }
        let _ = client_write.shutdown().await;
    };

    tokio::select! { _ = up_task => {}, _ = down_task => {} }

    let duration = start_time.elapsed();

    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user.id,
        "vless",
        "udp",
        &client_ip.to_string(),
        &target_host,
        target_port,
        total_up,
        total_down,
        duration.as_millis() as i64,
        &outbound.tag,
        "connected",
    ));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::vless::timing::{
        init_collector, take_collected_records, LatencyStats, TimingRecord,
    };
    use std::time::Duration;

    fn context(on_traffic: crate::protocol::TrafficCallback) -> InboundContext {
        let geo = Arc::new(crate::geo::GeoEngine::default());
        let dialer = Arc::new(crate::proxy::router::OutboundDialer::new(
            Arc::new(crate::dns::DNSResolver::default()),
            None,
            None,
            false,
        ));
        let mut config = crate::config::GlobalConfig::default();
        config.domain_sniff = false;
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
            on_traffic,
            global_config: Arc::new(config),
            ip_user_cache: Arc::new(crate::limiter::IpUserCache::new(1, false, "")),
        }
    }

    #[tokio::test]
    async fn vision_half_close_preserves_other_direction_and_traffic() {
        for target_first in [false, true] {
            tokio::time::timeout(Duration::from_secs(5), async {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let port = listener.local_addr().unwrap().port();
                let target = tokio::spawn(async move {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    if target_first {
                        stream.write_all(b"reply").await.unwrap();
                        stream.shutdown().await.unwrap();
                    }
                    let mut data = Vec::new();
                    stream.read_to_end(&mut data).await.unwrap();
                    assert_eq!(data, b"firstlater");
                    if !target_first {
                        stream.write_all(b"reply").await.unwrap();
                    }
                });
                let traffic = Arc::new(parking_lot::Mutex::new(Vec::new()));
                let records = traffic.clone();
                let ctx = context(Arc::new(move |uid, up, down| {
                    records.lock().push((uid, up, down))
                }));
                let guard = ctx.conn_limiter.try_acquire(42).unwrap();
                let (client, server) = tokio::io::duplex(65536);
                let handler = tokio::spawn(handle_vless_vision_tcp(
                    Box::new(server),
                    [7; 16],
                    guard,
                    "127.0.0.1".parse().unwrap(),
                    None,
                    Arc::new(User {
                        id: 42,
                        ..Default::default()
                    }),
                    ctx,
                    "127.0.0.1:1".parse().unwrap(),
                    "127.0.0.1".into(),
                    None,
                    port,
                    None,
                ));
                let (read, write) = tokio::io::split(client);
                let mut reader = VisionReader::new(read, [7; 16]);
                let mut writer = VisionWriter::new(write, [7; 16]);
                writer.write_payload(b"first").await.unwrap();
                if !target_first {
                    writer.write_payload(b"later").await.unwrap();
                    writer.shutdown().await.unwrap();
                }
                let mut reply = Vec::new();
                let mut buf = [0; 128];
                loop {
                    let n = reader.read_payload(&mut buf).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    reply.extend_from_slice(&buf[..n]);
                }
                assert_eq!(reply, b"reply");
                if target_first {
                    writer.write_payload(b"later").await.unwrap();
                    writer.shutdown().await.unwrap();
                }
                handler.await.unwrap().unwrap();
                target.await.unwrap();
                assert_eq!(*traffic.lock(), vec![(42, 10, 5)]);
            })
            .await
            .unwrap();
        }
    }

    #[tokio::test]
    async fn udp_eof_keeps_both_traffic_counters() {
        tokio::time::timeout(Duration::from_secs(5), async {
            let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = socket.local_addr().unwrap().port();
            let target = tokio::spawn(async move {
                let mut buf = [0; 100];
                for _ in 0..2 {
                    let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
                    socket.send_to(&buf[..n], peer).await.unwrap();
                }
            });
            let traffic = Arc::new(parking_lot::Mutex::new(Vec::new()));
            let records = traffic.clone();
            let ctx = context(Arc::new(move |uid, up, down| {
                records.lock().push((uid, up, down))
            }));
            let guard = ctx.conn_limiter.try_acquire(42).unwrap();
            let (mut client, server) = tokio::io::duplex(1024);
            let handler = tokio::spawn(handle_vless_udp(
                Box::new(server),
                guard,
                "127.0.0.1".parse().unwrap(),
                None,
                Arc::new(User {
                    id: 42,
                    ..Default::default()
                }),
                ctx,
                "127.0.0.1".into(),
                None,
                port,
            ));
            for _ in 0..2 {
                client.write_all(b"\0\x04ping").await.unwrap();
                let mut reply = [0; 6];
                client.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"\0\x04ping");
            }
            client.shutdown().await.unwrap();
            handler.await.unwrap().unwrap();
            target.await.unwrap();
            assert_eq!(*traffic.lock(), vec![(42, 12, 12)]);
        })
        .await
        .unwrap();
    }

    #[test]
    fn test_vless_node_config_mapping_full() {
        let node_info = NodeInfo {
            id: 1,
            node_type: "vless".to_string(),
            server_port: 443,
            network: Some("tcp".to_string()),
            flow: Some("xtls-rprx-vision".to_string()),
            tls: Some(1),
            decryption: Some(
                "mlkem768x25519plus.native.600s.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
                    .to_string(),
            ),
            ..Default::default()
        };

        let cfg = VlessNodeConfig::from_node_info(&node_info).unwrap();
        assert_eq!(cfg.flow, VlessFlow::Vision);
        assert!(matches!(
            cfg.encryption,
            VlessEncryptionConfig::Mlkem768X25519Plus(_)
        ));
        assert!(matches!(cfg.stream.transport, TransportConfig::Tcp(_)));
    }

    #[test]
    fn test_vless_supports_reality_with_websocket() {
        let node_info = NodeInfo {
            id: 2,
            node_type: "vless".to_string(),
            server_port: 443,
            network: Some("ws".to_string()),
            tls: Some(2),
            server_key: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
            server_name: Some("example.com".to_string()),
            tls_settings: Some(serde_json::json!({
                "dest": "www.apple.com:443",
                "server_names": ["www.apple.com"],
                "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            })),
            ..Default::default()
        };

        let res = VlessNodeConfig::from_node_info(&node_info);
        assert!(res.is_ok());
    }

    #[test]
    fn test_vless_rejects_reality_with_mkcp() {
        let node_info = NodeInfo {
            id: 2,
            node_type: "vless".to_string(),
            server_port: 443,
            network: Some("mkcp".to_string()),
            tls: Some(2),
            tls_settings: Some(serde_json::json!({
                "dest": "www.apple.com:443",
                "server_names": ["www.apple.com"],
                "private_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            })),
            ..Default::default()
        };

        let res = VlessNodeConfig::from_node_info(&node_info);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("REALITY"));
    }

    #[test]
    fn test_vless_rejects_vision_on_websocket() {
        let node_info = NodeInfo {
            id: 3,
            node_type: "vless".to_string(),
            server_port: 443,
            network: Some("ws".to_string()),
            flow: Some("xtls-rprx-vision".to_string()),
            tls: Some(1),
            ..Default::default()
        };

        let res = VlessNodeConfig::from_node_info(&node_info);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("xtls-rprx-vision"));
    }

    #[test]
    fn test_vless_rejects_unknown_encryption() {
        let node_info = NodeInfo {
            id: 4,
            node_type: "vless".to_string(),
            server_port: 443,
            network: Some("tcp".to_string()),
            encryption: Some("des-ede3-cbc".to_string()),
            ..Default::default()
        };

        let res = VlessNodeConfig::from_node_info(&node_info);
        assert!(res.is_err());
        assert!(res.unwrap_err().to_lowercase().contains("unsupported"));
    }

    #[derive(Debug)]
    struct DangerousNoVerify;

    impl rustls::client::danger::ServerCertVerifier for DangerousNoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    async fn run_client_iteration(
        elise_addr: SocketAddr,
        target_port: u16,
        is_vision: bool,
        tls_connector: &tokio_rustls::TlsConnector,
    ) -> Result<Duration, Box<dyn std::error::Error + Send + Sync>> {
        let t0 = Instant::now();
        let tcp_stream = tokio::net::TcpStream::connect(elise_addr).await?;
        tcp_stream.set_nodelay(true)?;

        let server_name = rustls::pki_types::ServerName::try_from("localhost")?.to_owned();
        let mut tls_stream = tls_connector.connect(server_name, tcp_stream).await?;

        let mut header = Vec::new();
        header.push(0x00);
        if is_vision {
            header.extend_from_slice(&[2u8; 16]);
            let flow_bytes = b"xtls-rprx-vision";
            let mut addon_buf = Vec::new();
            addon_buf.push((1 << 3) | 2);
            addon_buf.push(flow_bytes.len() as u8);
            addon_buf.extend_from_slice(flow_bytes);
            header.push(addon_buf.len() as u8);
            header.extend_from_slice(&addon_buf);
        } else {
            header.extend_from_slice(&[1u8; 16]);
            header.push(0x00);
        }
        header.push(0x01);
        header.extend_from_slice(&target_port.to_be_bytes());
        header.push(0x01);
        header.extend_from_slice(&[127, 0, 0, 1]);

        tls_stream.write_all(&header).await?;
        tls_stream.flush().await?;

        let mut resp_header = [0u8; 2];
        tls_stream.read_exact(&mut resp_header).await?;
        assert_eq!(resp_header, [0x00, 0x00]);

        let mut client_hello = vec![0x16, 0x03, 0x01, 0x00, 0x2b, 0x01];
        client_hello.extend_from_slice(&[0xaa; 42]);

        let mut app_data = vec![0x17, 0x03, 0x03, 0x00, 0x1b];
        app_data.extend_from_slice(&[0xbb; 27]);

        if is_vision {
            let (read_half, write_half) = tokio::io::split(tls_stream);
            let mut writer = VisionWriter::new(write_half, [2u8; 16]);
            let mut reader = VisionReader::new(read_half, [2u8; 16]);

            writer.write_payload(&client_hello).await?;

            let mut buf = vec![0u8; 1024];
            let n = reader.read_payload(&mut buf).await?;
            assert!(n >= 6 && buf[0] == 0x16 && buf[5] == 0x02);

            let ttfb = t0.elapsed();

            writer.write_payload(&app_data).await?;

            let n = reader.read_payload(&mut buf).await?;
            assert!(n >= 5 && buf[0] == 0x17);

            writer.shutdown().await?;
            Ok(ttfb)
        } else {
            tls_stream.write_all(&client_hello).await?;
            tls_stream.flush().await?;

            let mut buf = vec![0u8; 1024];
            let n = tls_stream.read(&mut buf).await?;
            assert!(n >= 6 && buf[0] == 0x16 && buf[5] == 0x02);

            let ttfb = t0.elapsed();

            tls_stream.write_all(&app_data).await?;
            tls_stream.flush().await?;

            let n = tls_stream.read(&mut buf).await?;
            assert!(n >= 5 && buf[0] == 0x17);

            tls_stream.shutdown().await?;
            Ok(ttfb)
        }
    }

    fn print_benchmark_results(
        records: &[TimingRecord],
        none_client_ttfb: Vec<u64>,
        vision_client_ttfb: Vec<u64>,
    ) {
        let none_records: Vec<_> = records
            .iter()
            .filter(|r| r.flow != "xtls-rprx-vision")
            .collect();
        let vision_records: Vec<_> = records
            .iter()
            .filter(|r| r.flow == "xtls-rprx-vision")
            .collect();

        println!("\n=========================================================================================");
        println!(
            "              VLESS BENCHMARK RESULTS: flow=none (x{}) vs flow=vision (x{})",
            none_records.len(),
            vision_records.len()
        );
        println!("=========================================================================================");

        let print_row = |name: &str, s_none: &LatencyStats, s_vis: &LatencyStats| {
            let ratio_avg = if s_none.avg_us > 0 {
                s_vis.avg_us as f64 / s_none.avg_us as f64
            } else {
                0.0
            };
            let ratio_p50 = if s_none.p50_us > 0 {
                s_vis.p50_us as f64 / s_none.p50_us as f64
            } else {
                0.0
            };
            println!(
                "{:<38} | None: {:>5} / {:>5} / {:>5} / {:>5} / {:>5} µs | Vision: {:>5} / {:>5} / {:>5} / {:>5} / {:>5} µs | Ratio(avg/p50): {:.2}x / {:.2}x",
                name,
                s_none.min_us, s_none.p50_us, s_none.avg_us, s_none.p95_us, s_none.max_us,
                s_vis.min_us, s_vis.p50_us, s_vis.avg_us, s_vis.p95_us, s_vis.max_us,
                ratio_avg, ratio_p50
            );
        };

        println!("{:<38} | None (min/p50/avg/p95/max)                   | Vision (min/p50/avg/p95/max)                 | Ratios", "Milestone / Stage (µs)");
        println!("---------------------------------------+-----------------------------------------------+-----------------------------------------------+-----------------------");

        let c_none_stats = LatencyStats::compute(none_client_ttfb);
        let c_vis_stats = LatencyStats::compute(vision_client_ttfb);
        print_row(
            "Client Total TTFB (End-to-End)",
            &c_none_stats,
            &c_vis_stats,
        );

        let ttfb_none = LatencyStats::compute(
            none_records
                .iter()
                .filter_map(|r| r.total_ttfb_us())
                .collect(),
        );
        let ttfb_vis = LatencyStats::compute(
            vision_records
                .iter()
                .filter_map(|r| r.total_ttfb_us())
                .collect(),
        );
        print_row("Server Total TTFB (Accept->Write)", &ttfb_none, &ttfb_vis);

        let fin_none = LatencyStats::compute(
            none_records
                .iter()
                .filter_map(|r| r.total_finish_us())
                .collect(),
        );
        let fin_vis = LatencyStats::compute(
            vision_records
                .iter()
                .filter_map(|r| r.total_finish_us())
                .collect(),
        );
        print_row("Server Total Session Duration", &fin_none, &fin_vis);

        println!("---------------------------------------+-----------------------------------------------+-----------------------------------------------+-----------------------");
        println!("DETAILED STAGE DELTAS:");

        let s1_none = LatencyStats::compute(
            none_records
                .iter()
                .filter_map(|r| r.delta_tcp_to_tls())
                .collect(),
        );
        let s1_vis = LatencyStats::compute(
            vision_records
                .iter()
                .filter_map(|r| r.delta_tcp_to_tls())
                .collect(),
        );
        print_row("Stage 1: TCP Accept -> TLS Done", &s1_none, &s1_vis);

        let s2_none = LatencyStats::compute(
            none_records
                .iter()
                .filter_map(|r| r.delta_tls_to_auth())
                .collect(),
        );
        let s2_vis = LatencyStats::compute(
            vision_records
                .iter()
                .filter_map(|r| r.delta_tls_to_auth())
                .collect(),
        );
        print_row("Stage 2: TLS Done -> VLESS Auth", &s2_none, &s2_vis);

        let s3_none = LatencyStats::compute(
            none_records
                .iter()
                .filter_map(|r| r.delta_auth_to_outbound_start())
                .collect(),
        );
        let s3_vis = LatencyStats::compute(
            vision_records
                .iter()
                .filter_map(|r| r.delta_auth_to_outbound_start())
                .collect(),
        );
        print_row("Stage 3: VLESS Auth -> Outbound Start", &s3_none, &s3_vis);

        let s4_none = LatencyStats::compute(
            none_records
                .iter()
                .filter_map(|r| r.delta_outbound_dial())
                .collect(),
        );
        let s4_vis = LatencyStats::compute(
            vision_records
                .iter()
                .filter_map(|r| r.delta_outbound_dial())
                .collect(),
        );
        print_row("Stage 4: Outbound Dial (Connect)", &s4_none, &s4_vis);

        let s5_none = LatencyStats::compute(
            none_records
                .iter()
                .filter_map(|r| r.delta_outbound_to_first_write())
                .collect(),
        );
        let s5_vis = LatencyStats::compute(
            vision_records
                .iter()
                .filter_map(|r| r.delta_outbound_to_first_write())
                .collect(),
        );
        print_row(
            "Stage 5: Dial Done -> 1st Outbound Write",
            &s5_none,
            &s5_vis,
        );

        let s6_none = LatencyStats::compute(
            none_records
                .iter()
                .filter_map(|r| r.delta_outbound_write_to_upstream_resp())
                .collect(),
        );
        let s6_vis = LatencyStats::compute(
            vision_records
                .iter()
                .filter_map(|r| r.delta_outbound_write_to_upstream_resp())
                .collect(),
        );
        print_row("Stage 6: 1st Out Write -> Upstream Resp", &s6_none, &s6_vis);

        let s7_none = LatencyStats::compute(
            none_records
                .iter()
                .filter_map(|r| r.delta_upstream_resp_to_client_write())
                .collect(),
        );
        let s7_vis = LatencyStats::compute(
            vision_records
                .iter()
                .filter_map(|r| r.delta_upstream_resp_to_client_write())
                .collect(),
        );
        print_row("Stage 7: Upstream Resp -> Client Write", &s7_none, &s7_vis);

        let s8_none = LatencyStats::compute(
            none_records
                .iter()
                .filter_map(|r| r.delta_client_write_to_finish())
                .collect(),
        );
        let s8_vis = LatencyStats::compute(
            vision_records
                .iter()
                .filter_map(|r| r.delta_client_write_to_finish())
                .collect(),
        );
        print_row("Stage 8: Client Write -> Session Finish", &s8_none, &s8_vis);

        println!("=========================================================================================\n");
    }

    #[tokio::test]
    async fn benchmark_flow_none_vs_vision_timing() {
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_port = target_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = match target_listener.accept().await {
                    Ok(c) => c,
                    Err(_) => break,
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = match stream.read(&mut buf).await {
                        Ok(n) if n > 0 => n,
                        _ => return,
                    };
                    if buf[..n].starts_with(&[0x16, 0x03]) {
                        let mut server_hello = vec![0x16, 0x03, 0x03, 0x00, 0x2b, 0x02];
                        server_hello.extend_from_slice(&[0xcc; 42]);
                        let _ = stream.write_all(&server_hello).await;
                        let _ = stream.flush().await;
                    }
                    let n = match stream.read(&mut buf).await {
                        Ok(n) if n > 0 => n,
                        _ => return,
                    };
                    if buf[..n].starts_with(&[0x17, 0x03]) {
                        let mut app_reply = vec![0x17, 0x03, 0x03, 0x00, 0x1b];
                        app_reply.extend_from_slice(&[0xdd; 27]);
                        let _ = stream.write_all(&app_reply).await;
                        let _ = stream.flush().await;
                    }
                });
            }
        });

        let mut users_map = HashMap::new();
        users_map.insert(
            process_uuid([1u8; 16]),
            Arc::new(User {
                id: 1,
                uuid: "01010101-0101-0101-0101-010101010101".to_string(),
                flow: None,
                ..Default::default()
            }),
        );
        users_map.insert(
            process_uuid([2u8; 16]),
            Arc::new(User {
                id: 2,
                uuid: "02020202-0202-0202-0202-020202020202".to_string(),
                flow: Some("xtls-rprx-vision".to_string()),
                ..Default::default()
            }),
        );
        let users = Arc::new(RwLock::new(Arc::new(users_map)));

        let temp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_port = temp.local_addr().unwrap().port();
        drop(temp);

        let (ready_tx, mut ready_rx) = tokio::sync::watch::channel(false);
        let mut ctx = context(Arc::new(|_, _, _| {}));
        ctx.port = server_port;
        ctx.ready = Some(ready_tx);
        ctx.global_config = Arc::new({
            let mut cfg = (*ctx.global_config).clone();
            cfg.auto_tls = true;
            cfg
        });

        let node_info = NodeInfo {
            id: 1,
            node_type: "vless".to_string(),
            server_port,
            network: Some("tcp".to_string()),
            flow: Some("none".to_string()),
            tls: Some(1),
            tls_settings: Some(serde_json::json!({
                "server_name": "localhost",
                "allow_insecure": true,
            })),
            ..Default::default()
        };

        let inbound = VlessInbound {
            users: users.clone(),
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);
        tokio::spawn(async move {
            let _ = inbound.start(ctx, node_info, shutdown_rx).await;
        });

        while !*ready_rx.borrow() {
            ready_rx.changed().await.unwrap();
        }

        let mut client_tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DangerousNoVerify))
            .with_no_client_auth();
        client_tls_config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls_connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls_config));
        let server_addr: SocketAddr = format!("127.0.0.1:{}", server_port).parse().unwrap();

        init_collector();

        let mut none_client_ttfb = Vec::new();
        for _ in 0..20 {
            let ttfb = run_client_iteration(server_addr, target_port, false, &tls_connector)
                .await
                .expect("flow=none iteration failed");
            none_client_ttfb.push(ttfb.as_micros() as u64);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let mut vision_client_ttfb = Vec::new();
        for _ in 0..20 {
            let ttfb = run_client_iteration(server_addr, target_port, true, &tls_connector)
                .await
                .expect("flow=vision iteration failed");
            vision_client_ttfb.push(ttfb.as_micros() as u64);
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let _ = shutdown_tx.send(());
        tokio::time::sleep(Duration::from_millis(50)).await;
        let records = take_collected_records();

        print_benchmark_results(&records, none_client_ttfb, vision_client_ttfb);
    }

    #[tokio::test]
    async fn test_vless_encryption_stream_writer_control_is_present() {
        use crate::protocol::vless::encryption::aead::VlessAead;
        use crate::protocol::vless::encryption::stream::VlessEncryptionStream;

        let (s1, _s2) = tokio::io::duplex(65536);
        let united_key = vec![0x55u8; 96];
        let aead1 = VlessAead::new(b"ctx-1", &united_key, true);
        let peer_aead1 = VlessAead::new(b"ctx-2", &united_key, true);

        let enc_stream: crate::conn::BoxedStream = Box::new(VlessEncryptionStream::new(
            Box::new(s1),
            true,
            united_key,
            aead1,
            peer_aead1,
            None,
            None,
        ));

        assert!(enc_stream.is_vless_encryption());

        let direct_control = enc_stream.direct_control();
        assert!(direct_control.is_some());

        let writer_direct_control = direct_control;
        assert!(writer_direct_control.is_some());
    }
}
