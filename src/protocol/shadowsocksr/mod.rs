use crate::conn::{bind_tcp_listener, read_proxy_protocol, MonitoredStream};
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
use tracing::{info, warn};

pub struct ShadowsocksrInbound {
    users: Arc<RwLock<HashMap<String, User>>>,
}

impl Default for ShadowsocksrInbound {
    fn default() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
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
            let pwd = u.password.clone().unwrap_or_else(|| u.uuid.clone());
            map.insert(pwd, u);
        }
        *self.users.write() = map;
    }

    async fn start(
        &self,
        ctx: InboundContext,
        _node_info: NodeInfo,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> std::io::Result<()> {
        let bind_addr = format!("{}:{}", ctx.listen_addr, ctx.port);
        let listener = bind_tcp_listener(&bind_addr, ctx.global_config.mptcp).await?;
        info!("ShadowsocksR inbound listening on {}", bind_addr);

        let users = self.users.clone();

        loop {
            tokio::select! {
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
                    tokio::spawn(async move {
                        let _ = handle_connection(stream, remote_addr, ctx, users).await;
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
    users: Arc<RwLock<HashMap<String, User>>>,
) -> std::io::Result<()> {
    let local_ip = stream.local_addr().ok().map(|s| s.ip());

    // Proxy Protocol check (supports Auto, Strict, Off)
    let (src_opt, mut stream) =
        read_proxy_protocol(stream, ctx.global_config.get_proxy_protocol_mode()).await?;
    if let Some(src) = src_opt {
        remote_addr = src;
    }

    let client_ip = remote_addr.ip();
    if ctx.defense.is_banned(client_ip) {
        return Ok(());
    }

    let user = match users.read().values().next().cloned() {
        Some(u) => {
            ctx.defense.record_success(remote_addr.ip());
            u
        }
        None => {
            ctx.defense.record_failure(remote_addr.ip());
            return Ok(());
        }
    };

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
