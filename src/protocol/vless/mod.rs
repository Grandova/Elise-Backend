pub mod encryption;
pub mod header;
pub mod vision;

pub use encryption::VlessEncryptionServer;
pub use header::{
    parse_vless_request_header, process_uuid, write_vless_response_header, VlessAddons,
    VlessRequestHeader,
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
use crate::transport::apply_transport;
use crate::transport::security::apply_transport_security;
use crate::transport::types::{
    StreamSettings, TransportConfig, TransportSecurityConfig, VlessEncryptionConfig, VlessFlow,
    VlessNodeConfig,
};
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
                    Ok(srv) => Some(Arc::new(srv)),
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
            _ => None,
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

        loop {
            tokio::select! {
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

                    tokio::spawn(async move {
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
                        ).await;
                    });
                }
            }
        }
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
}

async fn handle_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    ctx: InboundContext,
    users: Arc<RwLock<Arc<HashMap<[u8; 16], Arc<User>>>>>,
    stream_settings: Arc<StreamSettings>,
    encryption_server: Option<Arc<VlessEncryptionServer>>,
    tls_manager: Option<&crate::security::TLSManager>,
    reality_server: Option<&RealityServer>,
    node_config: Arc<VlessNodeConfig>,
) -> std::io::Result<()> {
    let _ = stream.set_nodelay(true);

    // 15-second handshake timeout protection
    let handshake_res = tokio::time::timeout(
        std::time::Duration::from_secs(15),
        perform_vless_handshake(
            stream,
            remote_addr,
            &ctx,
            &users,
            &stream_settings,
            encryption_server.as_ref(),
            tls_manager,
            reality_server,
            &node_config,
        ),
    )
    .await;

    let handshake_data = match handshake_res {
        Ok(Ok(Some(data))) => data,
        _ => return Ok(()),
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
    } = handshake_data;

    if command == 0x02 {
        return handle_vless_udp(
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
    }

    if is_vision {
        return handle_vless_vision_tcp(
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
        )
        .await;
    }

    handle_vless_standard_tcp(
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
    )
    .await
}

async fn perform_vless_handshake(
    stream: TcpStream,
    mut remote_addr: SocketAddr,
    ctx: &InboundContext,
    users: &Arc<RwLock<Arc<HashMap<[u8; 16], Arc<User>>>>>,
    stream_settings: &StreamSettings,
    encryption_server: Option<&Arc<VlessEncryptionServer>>,
    tls_manager: Option<&crate::security::TLSManager>,
    reality_server: Option<&RealityServer>,
    node_config: &VlessNodeConfig,
) -> std::io::Result<Option<VlessHandshakeData>> {
    let local_ip = stream.local_addr().ok().map(|s| s.ip());

    // 1. PROXY Protocol
    let (src_opt, stream) =
        read_proxy_protocol(stream, ctx.global_config.get_proxy_protocol_mode()).await?;
    if let Some(src) = src_opt {
        remote_addr = src;
    }

    let client_ip = remote_addr.ip();
    if ctx.defense.is_banned(client_ip) {
        return Ok(None);
    }

    // 2. Layer 1: Transport Security (None / TLS / REALITY)
    let stream: BoxedStream = Box::new(stream);
    let alpn = match &stream_settings.transport {
        TransportConfig::Grpc(_) | TransportConfig::LegacyHttp2(_) => {
            vec![b"h2".to_vec()]
        }
        TransportConfig::XHttp(_) => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        _ => vec![b"http/1.1".to_vec()],
    };
    let stream = match apply_transport_security(
        stream,
        remote_addr,
        &stream_settings.security,
        tls_manager,
        reality_server,
        alpn,
    )
    .await
    {
        Ok(Some(s)) => s,
        Ok(None) => return Ok(None),
        Err(e) => {
            warn!(
                "VLESS transport security error from {}: {:?}",
                remote_addr, e
            );
            return Ok(None);
        }
    };

    // 3. Layer 2: Transport (RAW/TCP / WebSocket / gRPC / HttpUpgrade / XHTTP / H2)
    let stream = match apply_transport(stream, &stream_settings.transport).await {
        Ok(s) => s,
        Err(e) => {
            warn!("VLESS transport error from {}: {:?}", remote_addr, e);
            return Ok(None);
        }
    };

    // 4. Layer 3: VLESS Encryption (Optional mlkem768x25519plus)
    let stream = if let Some(enc_srv) = encryption_server {
        match enc_srv.handshake(stream).await {
            Ok(s) => s,
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

    // 5. Layer 4: VLESS Protocol Header
    let req = match parse_vless_request_header(&mut stream).await {
        Ok(r) => r,
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

    // Device limit check
    if !ctx
        .device_limiter
        .check_and_record_async(user.id, remote_addr.ip())
        .await
    {
        return Ok(None);
    }

    // Connection limit check
    let conn_guard = match ctx.conn_limiter.try_acquire(user.id) {
        Some(g) => g,
        None => return Ok(None),
    };

    // Flow validation:
    // 1) User's account flow must match client's requested flow
    // 2) Vision flow is ONLY permitted on RAW/TCP + TLS/REALITY
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
        // Enforce Vision underlay: must be RAW/TCP and TLS or REALITY
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

        // Vision strictly forbids UDP command 0x02
        if req.command == 0x02 {
            warn!(
                "VLESS: Vision flow requested with unsupported UDP command from {}",
                remote_addr
            );
            return Ok(None);
        }
    }

    // Reject unsupported multiplexing commands safely
    if req.command == 0x03 || req.command == 0x04 {
        warn!(
            "VLESS: Multiplexing command {} requested but Mux is disabled",
            req.command
        );
        return Ok(None);
    }

    // 6. Send VLESS Response Header: [Version 0x00][Addons Len 0x00]
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
    let start_time = Instant::now();

    let _ = crate::conn::copy_bidirectional_throttled(
        &mut client_conn,
        &mut out_stream,
        user.id,
        Some(&ctx.rate_limiter),
    )
    .await;

    let duration = start_time.elapsed();
    let (up, down) = client_conn.stats();

    if up > 0 || down > 0 {
        (ctx.on_traffic)(user.id, up, down);
    }

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
) -> std::io::Result<()> {
    let (client_read, client_write) = tokio::io::split(stream);
    let mut vision_reader = VisionReader::new(client_read, uuid_bytes);

    let mut sniff_buf = vec![0u8; 4096];
    let n = vision_reader.read_payload(&mut sniff_buf).await?;
    if n == 0 {
        return Ok(());
    }
    sniff_buf.truncate(n);

    let sniffed = if ctx.global_config.domain_sniff {
        crate::conn::sniff_domain(&sniff_buf)
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

    let mut out_stream = match ctx
        .router
        .dialer()
        .dial(&outbound, dial_host, target_port, local_ip)
        .await
    {
        Ok(s) => s,
        Err(_) => return Ok(()),
    };

    out_stream.write_all(&sniff_buf).await?;
    let initial_up = sniff_buf.len() as u64;

    let (mut out_read, mut out_write) = tokio::io::split(out_stream);
    let mut vision_writer = VisionWriter::new(client_write, uuid_bytes);

    let rate_limiter = ctx.rate_limiter.clone();
    let user_id = user.id;
    let start_time = Instant::now();

    let mut total_up = initial_up;
    let mut total_down = 0u64;

    let up_task = async {
        let mut buf = vec![0u8; 32768];
        let mut up = 0u64;
        loop {
            let read_res = tokio::time::timeout(
                std::time::Duration::from_secs(60),
                vision_reader.read_payload(&mut buf),
            )
            .await;

            let n = match read_res {
                Ok(Ok(n)) if n > 0 => n,
                _ => break,
            };

            rate_limiter.throttle(user_id, n).await;
            if out_write.write_all(&buf[..n]).await.is_err() {
                break;
            }
            up += n as u64;
        }
        let _ = out_write.shutdown().await;
        up
    };

    let down_task = async {
        let mut buf = vec![0u8; 32768];
        let mut down = 0u64;
        loop {
            let read_res =
                tokio::time::timeout(std::time::Duration::from_secs(60), out_read.read(&mut buf))
                    .await;

            let n = match read_res {
                Ok(Ok(n)) if n > 0 => n,
                _ => break,
            };

            rate_limiter.throttle(user_id, n).await;
            if vision_writer.write_payload(&buf[..n]).await.is_err() {
                break;
            }
            down += n as u64;
        }
        let _ = vision_writer.shutdown().await;
        down
    };

    tokio::select! {
        u = up_task => {
            total_up += u;
        }
        d = down_task => {
            total_down += d;
        }
    }

    let duration = start_time.elapsed();

    if total_up > 0 || total_down > 0 {
        (ctx.on_traffic)(user.id, total_up, total_down);
    }

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

    let bind_addr = match local_ip {
        Some(IpAddr::V4(v4)) => SocketAddr::new(IpAddr::V4(v4), 0),
        Some(IpAddr::V6(v6)) => SocketAddr::new(IpAddr::V6(v6), 0),
        None => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    };

    let udp_socket = match tokio::net::UdpSocket::bind(bind_addr).await {
        Ok(s) => Arc::new(s),
        Err(_) => return Ok(()),
    };

    let is_v4 = match bind_addr {
        SocketAddr::V4(_) => true,
        SocketAddr::V6(_) => false,
    };

    let dst_addr: SocketAddr = match target_ip {
        Some(ip) => SocketAddr::new(ip, target_port),
        None => {
            let mut matched = None;
            if let Ok(addrs) =
                tokio::net::lookup_host(format!("{}:{}", target_host, target_port)).await
            {
                for addr in addrs {
                    if addr.is_ipv4() == is_v4 {
                        matched = Some(addr);
                        break;
                    }
                    if matched.is_none() {
                        matched = Some(addr);
                    }
                }
            }
            match matched {
                Some(a) => a,
                None => return Ok(()),
            }
        }
    };

    if udp_socket.connect(dst_addr).await.is_err() {
        return Ok(());
    }

    let (mut client_read, mut client_write) = tokio::io::split(stream);
    let start_time = Instant::now();

    let sock_recv = udp_socket.clone();
    let sock_send = udp_socket;

    let rate_limiter = ctx.rate_limiter.clone();
    let user_id = user.id;

    let mut total_up = 0u64;
    let mut total_down = 0u64;

    let up_task = async {
        let mut len_buf = [0u8; 2];
        let mut payload = vec![0u8; 65535];
        let mut up = 0u64;

        loop {
            let read_res = tokio::time::timeout(
                std::time::Duration::from_secs(60),
                client_read.read_exact(&mut len_buf),
            )
            .await;

            match read_res {
                Ok(Ok(_)) => {}
                _ => break,
            }

            let length = u16::from_be_bytes(len_buf) as usize;
            if length == 0 {
                continue;
            }

            if length > payload.len() {
                payload.resize(length, 0);
            }

            if client_read
                .read_exact(&mut payload[..length])
                .await
                .is_err()
            {
                break;
            }

            rate_limiter.throttle(user_id, 2 + length).await;

            if sock_send.send(&payload[..length]).await.is_err() {
                break;
            }

            up += (2 + length) as u64;
        }
        up
    };

    let down_task = async {
        let mut buf = [0u8; 65535];
        let mut out_pkt = Vec::with_capacity(65535 + 4);
        let mut down = 0u64;

        loop {
            let recv_res =
                tokio::time::timeout(std::time::Duration::from_secs(60), sock_recv.recv(&mut buf))
                    .await;

            let n = match recv_res {
                Ok(Ok(n)) => n,
                _ => break,
            };

            out_pkt.clear();
            out_pkt.extend_from_slice(&(n as u16).to_be_bytes());
            out_pkt.extend_from_slice(&buf[..n]);

            rate_limiter.throttle(user_id, out_pkt.len()).await;

            if client_write.write_all(&out_pkt).await.is_err() {
                break;
            }
            down += out_pkt.len() as u64;
        }
        let _ = client_write.shutdown().await;
        down
    };

    tokio::select! {
        u = up_task => {
            total_up = u;
        }
        d = down_task => {
            total_down = d;
        }
    }

    let duration = start_time.elapsed();

    if total_up > 0 || total_down > 0 {
        (ctx.on_traffic)(user.id, total_up, total_down);
    }

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
            tls: Some(2), // REALITY
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
            tls: Some(2), // REALITY
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
}
