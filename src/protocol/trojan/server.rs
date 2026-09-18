use crate::conn::{bind_tcp_listener, read_proxy_protocol, BoxedStream, MonitoredStream};
use crate::observability::AuditRecord;
use crate::panel::types::{NodeInfo, User};
use crate::protocol::{Inbound, InboundContext};
use crate::proxy::router::MatchContext;
use crate::security::reality::RealityServer;
use crate::security::TLSManager;
use crate::transport::{
    apply_transport, apply_transport_security, StreamSettings, TransportSecurityConfig,
};
use async_trait::async_trait;
use parking_lot::RwLock;
use sha2::{Digest, Sha224};
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

pub struct TrojanInbound {
    users: Arc<RwLock<Arc<HashMap<String, Arc<User>>>>>, // hex(sha224(password)) -> User
}

impl Default for TrojanInbound {
    fn default() -> Self {
        Self {
            users: Arc::new(RwLock::new(Arc::new(HashMap::new()))),
        }
    }
}

impl TrojanInbound {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Inbound for TrojanInbound {
    fn protocol_type(&self) -> &'static str {
        "trojan"
    }

    fn update_users(&self, users: Vec<User>) {
        let mut map = HashMap::with_capacity(users.len());
        for u in users {
            let pass = u.password.as_deref().unwrap_or(&u.uuid);
            let mut hasher = Sha224::new();
            hasher.update(pass.as_bytes());
            let hash_hex = hex::encode(hasher.finalize());
            map.insert(hash_hex, Arc::new(u));
        }
        *self.users.write() = Arc::new(map);
    }

    async fn start(
        &self,
        ctx: InboundContext,
        node_info: NodeInfo,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> io::Result<()> {
        let settings = StreamSettings::from_node_info(&node_info)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        // Initialize Transport Security layer
        let (tls_manager, reality_server) = match &settings.security {
            TransportSecurityConfig::None => (None, None),
            TransportSecurityConfig::Tls(tls_cfg) => {
                let mgr = TLSManager::from_config(
                    tls_cfg,
                    ctx.global_config.auto_tls,
                    &ctx.global_config.fake_sni,
                )
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("Failed to initialize TLS for Trojan inbound: {e}"),
                    )
                })?;
                (Some(Arc::new(mgr)), None)
            }
            TransportSecurityConfig::Reality(reality_cfg) => {
                let srv = RealityServer::new(reality_cfg.clone()).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!("Failed to initialize REALITY for Trojan inbound: {e}"),
                    )
                })?;
                (None, Some(Arc::new(srv)))
            }
        };

        let settings = Arc::new(settings);
        let bind_addr = format!("{}:{}", ctx.listen_addr, ctx.port);
        let listener = bind_tcp_listener(&bind_addr, ctx.global_config.mptcp).await?;
        info!(
            "Trojan inbound listening on {} (transport: {:?}, security: {:?})",
            bind_addr,
            settings.transport.transport_type(),
            match &settings.security {
                TransportSecurityConfig::None => "None",
                TransportSecurityConfig::Tls(_) => "TLS",
                TransportSecurityConfig::Reality(_) => "REALITY",
            }
        );

        let users = self.users.clone();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("Trojan inbound on port {} stopping", ctx.port);
                    break;
                }
                accept_res = listener.accept() => {
                    let (stream, remote_addr) = match accept_res {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!("Trojan accept error: {:?}", e);
                            continue;
                        }
                    };
                    let _ = stream.set_nodelay(true);

                    let ctx = ctx.clone();
                    let users = users.clone();
                    let settings = settings.clone();
                    let tls_manager = tls_manager.clone();
                    let reality_server = reality_server.clone();

                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(
                            stream,
                            remote_addr,
                            ctx,
                            users,
                            settings,
                            tls_manager.as_deref(),
                            reality_server.as_deref(),
                        )
                        .await
                        {
                            debug!("Trojan connection ended from {}: {:?}", remote_addr, e);
                        }
                    });
                }
            }
        }
        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    remote_addr: SocketAddr,
    ctx: InboundContext,
    users: Arc<RwLock<Arc<HashMap<String, Arc<User>>>>>,
    settings: Arc<StreamSettings>,
    tls_manager: Option<&TLSManager>,
    reality_server: Option<&RealityServer>,
) -> io::Result<()> {
    tokio::time::timeout(
        Duration::from_secs(15),
        handle_connection_inner(
            stream,
            remote_addr,
            ctx,
            users,
            settings,
            tls_manager,
            reality_server,
        ),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "Trojan handshake timed out"))?
}

async fn handle_connection_inner(
    stream: TcpStream,
    mut remote_addr: SocketAddr,
    ctx: InboundContext,
    users: Arc<RwLock<Arc<HashMap<String, Arc<User>>>>>,
    settings: Arc<StreamSettings>,
    tls_manager: Option<&TLSManager>,
    reality_server: Option<&RealityServer>,
) -> io::Result<()> {
    let local_ip = stream.local_addr().ok().map(|s| s.ip());

    // 1. PROXY Protocol
    let (src_opt, stream): (Option<SocketAddr>, BoxedStream) =
        if settings.accept_proxy_protocol || ctx.global_config.proxy_protocol {
            let (src, ps) =
                read_proxy_protocol(stream, ctx.global_config.get_proxy_protocol_mode()).await?;
            (src, Box::new(ps))
        } else {
            (None, Box::new(stream))
        };
    if let Some(src) = src_opt {
        remote_addr = src;
    }

    let client_ip = remote_addr.ip();
    if ctx.defense.is_banned(client_ip) {
        return Ok(());
    }

    // 2. Transport Security (TLS, REALITY, or None)
    let alpn = match &settings.transport {
        crate::transport::TransportConfig::Grpc(_)
        | crate::transport::TransportConfig::LegacyHttp2(_) => {
            vec![b"h2".to_vec()]
        }
        crate::transport::TransportConfig::XHttp(_) => vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        _ => vec![b"http/1.1".to_vec()],
    };

    let sec_stream = match apply_transport_security(
        stream,
        remote_addr,
        &settings.security,
        tls_manager,
        reality_server,
        alpn,
    )
    .await?
    {
        Some(s) => s,
        None => return Ok(()), // Transparently fallbacked to dest (REALITY)
    };

    // 3. Transport Layer (RAW/TCP, WebSocket, gRPC, HttpUpgrade, XHTTP, LegacyHttp2)
    let stream = apply_transport(sec_stream, &settings.transport).await?;

    // 4. Trojan Protocol Core
    handle_trojan_protocol(stream, remote_addr, local_ip, ctx, users).await
}

async fn handle_trojan_protocol(
    mut stream: BoxedStream,
    remote_addr: SocketAddr,
    local_ip: Option<IpAddr>,
    ctx: InboundContext,
    users: Arc<RwLock<Arc<HashMap<String, Arc<User>>>>>,
) -> io::Result<()> {
    let client_ip = remote_addr.ip();

    // Read Trojan Header: [SHA224(password) 56 bytes] [\r\n 2 bytes] [CMD 1 byte] [ATYP 1 byte] [ADDR] [PORT 2 bytes] [\r\n 2 bytes]
    let mut hash_buf = [0u8; 56];
    stream.read_exact(&mut hash_buf).await?;
    let mut crlf = [0u8; 2];
    stream.read_exact(&mut crlf).await?;
    if &crlf != b"\r\n" {
        return Ok(());
    }
    let hash_str = String::from_utf8_lossy(&hash_buf).to_lowercase();

    let user = {
        let users_map = users.read().clone();
        match users_map.get(&hash_str).cloned() {
            Some(u) => {
                ctx.defense.record_success(client_ip);
                u
            }
            None => {
                ctx.defense.record_failure(client_ip);
                return Ok(()); // Password mismatch
            }
        }
    };

    // Device limit check
    if !ctx.device_limiter.check_and_record_async(user.id, client_ip).await {
        return Ok(());
    }

    // Connection limit check
    let conn_guard = match ctx.conn_limiter.try_acquire(user.id) {
        Some(g) => g,
        None => return Ok(()),
    };

    // Read Command (0x01 = CONNECT, 0x03 = UDP)
    let mut cmd_buf = [0u8; 1];
    stream.read_exact(&mut cmd_buf).await?;

    // Read Address Type (0x01 = IPv4, 0x03 = Domain, 0x04 = IPv6)
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

    // Read terminating CRLF
    let mut end_crlf = [0u8; 2];
    stream.read_exact(&mut end_crlf).await?;
    if &end_crlf != b"\r\n" {
        return Ok(());
    }

    if cmd_buf[0] == 0x03 {
        // Command 0x03: UDP ASSOCIATE
        return handle_trojan_udp(
            stream,
            conn_guard,
            remote_addr,
            local_ip,
            user,
            ctx,
            target_host,
            target_ip,
            target_port,
        )
        .await;
    }

    // Command 0x01: TCP CONNECT
    let (sniffed, stream) =
        crate::conn::sniff_async_stream(stream, target_ip, ctx.global_config.domain_sniff).await;
    let match_host = sniffed.as_deref().unwrap_or(&target_host);
    let dial_host = if ctx.global_config.sniff_redirect {
        match_host
    } else {
        &target_host
    };

    // Audit check
    if ctx.audit.should_block(match_host, target_ip, target_port) {
        return Ok(());
    }

    // Match routing outbound
    let mctx = MatchContext {
        node_id: ctx.node_id,
        network: "tcp",
        target_host: match_host,
        target_ip,
        target_port,
        inbound_local_ip: local_ip,
    };
    let outbound = ctx.router.match_outbound(&mctx);

    // Connect outbound via router's dialer
    let mut out_stream = match ctx
        .router
        .dialer()
        .dial(&outbound, dial_host, target_port, local_ip)
        .await
    {
        Ok(s) => s,
        Err(_e) => return Ok(()),
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
        "trojan",
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

const MAX_TROJAN_UDP_PAYLOAD: usize = 8192;

/// Handles Trojan UDP ASSOCIATE traffic.
/// Enforces strict router compliance: all outbound UDP requests go through `ctx.router.match_outbound`
/// and `ctx.router.dialer().dial_udp_outbound(...)`. Binds to raw OS sockets are forbidden.
/// Enforces 8192-byte max payload size per packet according to upstream Trojan specification.
#[allow(clippy::too_many_arguments)]
async fn handle_trojan_udp(
    stream: BoxedStream,
    _conn_guard: crate::limiter::ConnGuard,
    remote_addr: SocketAddr,
    local_ip: Option<IpAddr>,
    user: Arc<User>,
    ctx: InboundContext,
    initial_target_host: String,
    initial_target_ip: Option<IpAddr>,
    initial_target_port: u16,
) -> io::Result<()> {
    let client_ip = remote_addr.ip();
    let (mut client_read, mut client_write) = tokio::io::split(stream);
    let start_time = Instant::now();
    let user_id = user.id;

    // Channel for multiplexing downstream UDP responses back into client_write
    let (response_tx, mut response_rx) = mpsc::channel::<Vec<u8>>(256);
    let cancel_token = CancellationToken::new();

    // Active outbound sessions keyed by destination (host, port)
    let mut sessions: HashMap<(String, u16), mpsc::Sender<Vec<u8>>> = HashMap::new();

    let mut total_up = 0u64;
    let mut total_down = 0u64;

    // Initial destination audit check
    if ctx
        .audit
        .should_block(&initial_target_host, initial_target_ip, initial_target_port)
    {
        return Ok(());
    }

    let initial_mctx = MatchContext {
        node_id: ctx.node_id,
        network: "udp",
        target_host: &initial_target_host,
        target_ip: initial_target_ip,
        target_port: initial_target_port,
        inbound_local_ip: local_ip,
    };
    let initial_outbound = ctx.router.match_outbound(&initial_mctx);
    let last_outbound_tag = Arc::new(RwLock::new(initial_outbound.tag.clone()));

    // Writer task: forwards outbound UDP responses to client stream
    let write_cancel = cancel_token.clone();
    let write_task = async {
        let mut down_bytes = 0u64;
        while let Some(packet) = response_rx.recv().await {
            if client_write.write_all(&packet).await.is_err() {
                break;
            }
            down_bytes += packet.len() as u64;
        }
        let _ = client_write.shutdown().await;
        write_cancel.cancel();
        down_bytes
    };

    // Reader task: reads Trojan UDP frames from client
    let read_cancel = cancel_token.clone();
    let read_last_tag = last_outbound_tag.clone();
    let read_task = async {
        let mut atyp_buf = [0u8; 1];
        let mut port_buf = [0u8; 2];
        let mut len_buf = [0u8; 2];
        let mut crlf_buf = [0u8; 2];
        let mut payload = vec![0u8; MAX_TROJAN_UDP_PAYLOAD];
        let mut up_bytes = 0u64;

        loop {
            // 60-second idle timeout per packet
            let read_res = tokio::time::timeout(
                Duration::from_secs(60),
                client_read.read_exact(&mut atyp_buf),
            )
            .await;

            match read_res {
                Ok(Ok(_)) => {}
                _ => break, // Timeout or client disconnected
            }

            let (dst_host, dst_ip) = match atyp_buf[0] {
                0x01 => {
                    let mut ipv4 = [0u8; 4];
                    if client_read.read_exact(&mut ipv4).await.is_err() {
                        break;
                    }
                    let ip = IpAddr::V4(Ipv4Addr::from(ipv4));
                    (ip.to_string(), Some(ip))
                }
                0x03 => {
                    let mut l = [0u8; 1];
                    if client_read.read_exact(&mut l).await.is_err() {
                        break;
                    }
                    let mut domain_buf = vec![0u8; l[0] as usize];
                    if client_read.read_exact(&mut domain_buf).await.is_err() {
                        break;
                    }
                    let domain = String::from_utf8_lossy(&domain_buf).to_string();
                    let ip = domain.parse().ok();
                    (domain, ip)
                }
                0x04 => {
                    let mut ipv6 = [0u8; 16];
                    if client_read.read_exact(&mut ipv6).await.is_err() {
                        break;
                    }
                    let ip = IpAddr::V6(Ipv6Addr::from(ipv6));
                    (ip.to_string(), Some(ip))
                }
                _ => break,
            };

            if client_read.read_exact(&mut port_buf).await.is_err() {
                break;
            }
            let dst_port = u16::from_be_bytes(port_buf);

            if client_read.read_exact(&mut len_buf).await.is_err() {
                break;
            }
            let length = u16::from_be_bytes(len_buf) as usize;

            if client_read.read_exact(&mut crlf_buf).await.is_err() || &crlf_buf != b"\r\n" {
                break;
            }

            // Enforce 8192-byte max payload size
            if length > MAX_TROJAN_UDP_PAYLOAD {
                warn!(
                    "Trojan UDP packet length {} exceeds max allowed {} bytes, terminating",
                    length, MAX_TROJAN_UDP_PAYLOAD
                );
                break;
            }

            if client_read
                .read_exact(&mut payload[..length])
                .await
                .is_err()
            {
                break;
            }

            // Rate limiter enforcement
            ctx.rate_limiter.throttle(user_id, length + 7).await;

            let key = (dst_host.clone(), dst_port);
            let session_tx = match sessions.get(&key) {
                Some(tx) if !tx.is_closed() => tx.clone(),
                _ => {
                    // Cap active sessions to prevent unbounded memory/task leak
                    if sessions.len() >= 1024 {
                        sessions.retain(|_, s| !s.is_closed());
                        if sessions.len() >= 1024 {
                            continue;
                        }
                    }

                    // Match outbound route via router
                    let mctx = MatchContext {
                        node_id: ctx.node_id,
                        network: "udp",
                        target_host: &dst_host,
                        target_ip: dst_ip,
                        target_port: dst_port,
                        inbound_local_ip: local_ip,
                    };
                    let outbound = ctx.router.match_outbound(&mctx);
                    *read_last_tag.write() = outbound.tag.clone();

                    // Dial outbound UDP strictly through router dialer
                    let udp_outbound = match ctx
                        .router
                        .dialer()
                        .dial_udp_outbound(&outbound, &dst_host, dst_port, local_ip)
                        .await
                    {
                        Ok(s) => s,
                        Err(e) => {
                            debug!(
                                "Trojan UDP dial outbound error for {}:{}: {:?}",
                                dst_host, dst_port, e
                            );
                            continue;
                        }
                    };

                    let (req_tx, mut req_rx) = mpsc::channel::<Vec<u8>>(128);
                    let resp_tx = response_tx.clone();
                    let child_cancel = read_cancel.child_token();
                    let child_host = dst_host.clone();

                    tokio::spawn(async move {
                        let mut recv_buf = [0u8; MAX_TROJAN_UDP_PAYLOAD];
                        let idle_timeout = Duration::from_secs(60);

                        loop {
                            tokio::select! {
                                _ = child_cancel.cancelled() => break,
                                req = req_rx.recv() => {
                                    let Some(data) = req else { break; };
                                    if udp_outbound.send(&data).await.is_err() {
                                        break;
                                    }
                                }
                                recv_res = tokio::time::timeout(idle_timeout, udp_outbound.recv(&mut recv_buf)) => {
                                    match recv_res {
                                        Ok(Ok((n, src_addr))) if n > 0 => {
                                            // Frame into Trojan UDP packet
                                            let mut out_pkt = Vec::with_capacity(32 + n);
                                            match src_addr {
                                                shadowsocks::relay::socks5::Address::SocketAddress(sa) => {
                                                    match sa.ip() {
                                                        IpAddr::V4(v4) => {
                                                            out_pkt.push(0x01);
                                                            out_pkt.extend_from_slice(&v4.octets());
                                                        }
                                                        IpAddr::V6(v6) => {
                                                            out_pkt.push(0x04);
                                                            out_pkt.extend_from_slice(&v6.octets());
                                                        }
                                                    }
                                                    out_pkt.extend_from_slice(&sa.port().to_be_bytes());
                                                }
                                                shadowsocks::relay::socks5::Address::DomainNameAddress(ref d, p) => {
                                                    out_pkt.push(0x03);
                                                    out_pkt.push(d.len() as u8);
                                                    out_pkt.extend_from_slice(d.as_bytes());
                                                    out_pkt.extend_from_slice(&p.to_be_bytes());
                                                }
                                            }
                                            out_pkt.extend_from_slice(&(n as u16).to_be_bytes());
                                            out_pkt.extend_from_slice(b"\r\n");
                                            out_pkt.extend_from_slice(&recv_buf[..n]);

                                            if resp_tx.send(out_pkt).await.is_err() {
                                                break;
                                            }
                                        }
                                        _ => break,
                                    }
                                }
                            }
                        }
                        debug!("Trojan UDP session for {}:{} closed", child_host, dst_port);
                    });

                    sessions.insert(key, req_tx.clone());
                    req_tx
                }
            };

            let _ = session_tx.try_send(payload[..length].to_vec());
            up_bytes += (length + 7) as u64;
        }

        read_cancel.cancel();
        up_bytes
    };

    tokio::select! {
        u = read_task => {
            total_up = u;
        }
        d = write_task => {
            total_down = d;
        }
    }

    let duration = start_time.elapsed();

    if total_up > 0 || total_down > 0 {
        (ctx.on_traffic)(user.id, total_up, total_down);
    }

    let final_tag = last_outbound_tag.read().clone();
    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user.id,
        "trojan",
        "udp",
        &client_ip.to_string(),
        &initial_target_host,
        initial_target_port,
        total_up,
        total_down,
        duration.as_millis() as i64,
        &final_tag,
        "connected",
    ));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha224};

    #[test]
    fn test_trojan_password_hashing() {
        let password = "my_secret_password";
        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        let hash = hex::encode(hasher.finalize());
        assert_eq!(hash.len(), 56);

        let inbound = TrojanInbound::new();
        let user = User {
            id: 42,
            uuid: "test-uuid".to_string(),
            password: Some(password.to_string()),
            ..Default::default()
        };
        inbound.update_users(vec![user]);

        let found = inbound.users.read().get(&hash).cloned();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, 42);
    }

    #[test]
    fn test_trojan_udp_packet_framing() {
        // Build a sample Trojan UDP packet:
        // [0x01 (IPv4)] [192, 168, 1, 1] [80 (u16 BE)] [5 (len u16 BE)] [\r\n] [b"hello"]
        let mut pkt = Vec::new();
        pkt.push(0x01);
        pkt.extend_from_slice(&[192, 168, 1, 1]);
        pkt.extend_from_slice(&80u16.to_be_bytes());
        pkt.extend_from_slice(&5u16.to_be_bytes());
        pkt.extend_from_slice(b"\r\n");
        pkt.extend_from_slice(b"hello");

        assert_eq!(pkt.len(), 1 + 4 + 2 + 2 + 2 + 5);
        assert_eq!(&pkt[9..11], b"\r\n");
        assert_eq!(&pkt[11..], b"hello");
    }

    #[test]
    fn test_trojan_udp_oversized_limit() {
        assert_eq!(MAX_TROJAN_UDP_PAYLOAD, 8192);
    }
}
