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
            || !ctx
                .device_limiter
                .check_and_record_async(user_id, remote.ip())
                .await
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
        let idle_timeout = if self.ctx.global_config.udp_timeout == 0 {
            Duration::from_secs(u32::MAX as u64)
        } else {
            Duration::from_secs(self.ctx.global_config.udp_timeout)
        };
        let idle = tokio::time::sleep(idle_timeout);
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
                    idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
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
                                continue;
                            }
                        }
                    }
                    self.down += n as u64;
                    (self.ctx.on_traffic)(self.user_id, 0, n as u64);
                    idle.as_mut().reset(tokio::time::Instant::now() + idle_timeout);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn download_requires_delivery_ack_and_releases_session_on_exit() {
        tokio::time::timeout(Duration::from_secs(5), async {
            for exit in ["cancel", "closed", "idle"] {
                let totals = Arc::new(parking_lot::Mutex::new((0u64, 0u64)));
                let counted = Arc::new(tokio::sync::Notify::new());
                let geo = Arc::new(crate::geo::GeoEngine::default());
                let dialer = Arc::new(crate::proxy::router::OutboundDialer::new(
                    Arc::new(crate::dns::DNSResolver::default()),
                    None,
                    None,
                    false,
                ));
                let config = crate::config::GlobalConfig {
                    udp_timeout: 1,
                    ..Default::default()
                };
                let ctx = InboundContext {
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
                    tls_manager: Arc::new(crate::security::TLSManager::new(
                        false,
                        "localhost".into(),
                    )),
                    audit_logger: Arc::new(crate::observability::AuditLogger::new(None::<&str>)),
                    clickhouse_logger: Arc::new(crate::observability::ClickHouseLogger::new(
                        false,
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        None,
                    )),
                    on_traffic: {
                        let totals = totals.clone();
                        let counted = counted.clone();
                        Arc::new(move |_, up, down| {
                            let mut total = totals.lock();
                            total.0 += up;
                            total.1 += down;
                            if down > 0 {
                                counted.notify_one();
                            }
                        })
                    },
                    global_config: Arc::new(config),
                    ip_user_cache: Arc::new(crate::limiter::IpUserCache::new(1, false, "")),
                };
                ctx.conn_limiter.set_user_limit(42, 1);
                let upstream = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let delivery = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let session = UdpSession::connect(
                    ctx.clone(),
                    42,
                    "127.0.0.1:1234".parse().unwrap(),
                    "127.0.0.1".into(),
                    upstream.local_addr().unwrap().port(),
                    None,
                    "test",
                )
                .await
                .unwrap();
                let (requests, rx) = mpsc::channel(1);
                let (responses, mut received) = mpsc::channel(1);
                let cancel = CancellationToken::new();
                let relay = tokio::spawn(session.relay(rx, responses, cancel.clone()));
                requests.send(b"request".to_vec()).await.unwrap();
                let mut buffer = [0; 32];
                let (n, peer) = upstream.recv_from(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..n], b"request");
                upstream.send_to(b"undelivered", peer).await.unwrap();
                let (data, _, ack) = received.recv().await.unwrap();
                assert!(delivery.send_to(&data, "[::1]:9").await.is_err());
                drop(ack);
                upstream.send_to(b"delivered", peer).await.unwrap();
                let (data, _, ack) = received.recv().await.unwrap();
                assert_eq!(*totals.lock(), (7, 0));
                assert_eq!(data, b"delivered");
                delivery
                    .send_to(&data, client.local_addr().unwrap())
                    .await
                    .unwrap();
                ack.send(()).unwrap();
                let (n, _) = client.recv_from(&mut buffer).await.unwrap();
                assert_eq!(&buffer[..n], b"delivered");
                counted.notified().await;
                assert_eq!(*totals.lock(), (7, 9));
                upstream.send_to(b"pending", peer).await.unwrap();
                let (_, _, ack) = received.recv().await.unwrap();
                match exit {
                    "cancel" => cancel.cancel(),
                    "closed" => {
                        drop(received);
                        drop(ack);
                    }
                    _ => {
                        let _held_ack = ack;
                        tokio::time::sleep(Duration::from_millis(1100)).await;
                    }
                }
                relay.await.unwrap().unwrap();
                assert_eq!(*totals.lock(), (7, 9));
                assert_eq!(ctx.conn_limiter.get_total_active(), 0);
                assert!(ctx.conn_limiter.try_acquire(42).is_some());
            }
        })
        .await
        .unwrap();
    }
}
