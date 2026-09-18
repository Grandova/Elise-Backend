use crate::limiter::ConnGuard;
use crate::observability::AuditRecord;
use crate::protocol::InboundContext;
use crate::proxy::router::outbound::UdpOutbound;
use crate::proxy::router::MatchContext;
use shadowsocks::relay::socks5::Address;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

pub const UDP_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

pub struct UdpSession {
    socket: UdpOutbound,
    ctx: InboundContext,
    user_id: u32,
    remote: SocketAddr,
    host: String,
    port: u16,
    tag: String,
    protocol: &'static str,
    start: Instant,
    up: u64,
    down: u64,
    _guard: ConnGuard,
}

impl UdpSession {
    pub async fn connect(
        ctx: InboundContext,
        user_id: u32,
        remote: SocketAddr,
        host: String,
        port: u16,
        local_ip: Option<IpAddr>,
        protocol: &'static str,
    ) -> io::Result<Self> {
        let ip = host.parse().ok();
        if ctx.audit.should_block(&host, ip, port)
            || !ctx.device_limiter.check_and_record_async(user_id, remote.ip()).await
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "UDP audit/device limit rejected",
            ));
        }
        let guard = ctx.conn_limiter.try_acquire(user_id).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "UDP connection limit reached",
            )
        })?;
        let outbound = ctx.router.match_outbound(&MatchContext {
            node_id: ctx.node_id,
            network: "udp",
            target_host: &host,
            target_ip: ip,
            target_port: port,
            inbound_local_ip: local_ip,
        });
        let socket = tokio::time::timeout(
            Duration::from_secs(10),
            ctx.router
                .dialer()
                .dial_udp_outbound(&outbound, &host, port, local_ip),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "UDP outbound timeout"))??;
        Ok(Self {
            socket,
            ctx,
            user_id,
            remote,
            host,
            port,
            tag: outbound.tag,
            protocol,
            start: Instant::now(),
            up: 0,
            down: 0,
            _guard: guard,
        })
    }

    pub async fn relay(
        mut self,
        mut requests: mpsc::Receiver<Vec<u8>>,
        responses: mpsc::Sender<(Vec<u8>, Address, oneshot::Sender<()>)>,
        cancel: CancellationToken,
    ) -> io::Result<()> {
        let mut buffer = vec![0; 65536];
        let idle = tokio::time::sleep(UDP_IDLE_TIMEOUT);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                _ = &mut idle => return Ok(()),
                packet = requests.recv() => {
                    let Some(packet) = packet else { return Ok(()); };
                    tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        _ = &mut idle => return Ok(()),
                        result = async {
                            self.ctx.rate_limiter.throttle(self.user_id, packet.len()).await;
                            self.socket.send(&packet).await
                        } => {
                            match result {
                                Ok(n) => {
                                    self.up += n as u64;
                                    (self.ctx.on_traffic)(self.user_id, n as u64, 0);
                                }
                                Err(e) => {
                                    tracing::debug!(error = %e, "UDP outbound send failed");
                                }
                            }
                        }
                    }
                    idle.as_mut().reset(tokio::time::Instant::now() + UDP_IDLE_TIMEOUT);
                }
                result = self.socket.recv(&mut buffer) => {
                    let (n, address) = result?;
                    let (ack, delivered) = oneshot::channel();
                    tokio::select! {
                        _ = cancel.cancelled() => return Ok(()),
                        _ = &mut idle => return Ok(()),
                        result = async {
                            self.ctx.rate_limiter.throttle(self.user_id, n).await;
                            responses.send((buffer[..n].to_vec(), address, ack)).await.map_err(io::Error::other)?;
                            delivered.await.map_err(io::Error::other)
                        } => {
                            if let Err(e) = result {
                                if responses.is_closed() {
                                    return Ok(());
                                }
                                tracing::debug!(error = %e, "UDP response delivery dropped or timeout");
                            }
                        }
                    }
                    self.down += n as u64;
                    (self.ctx.on_traffic)(self.user_id, 0, n as u64);
                    idle.as_mut().reset(tokio::time::Instant::now() + UDP_IDLE_TIMEOUT);
                }
            }
        }
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.ctx.audit_logger.record(AuditRecord::new(
            self.ctx.node_id,
            self.user_id,
            self.protocol,
            "udp",
            &self.remote.ip().to_string(),
            &self.host,
            self.port,
            self.up,
            self.down,
            self.start.elapsed().as_millis() as i64,
            &self.tag,
            "closed",
        ));
    }
}
