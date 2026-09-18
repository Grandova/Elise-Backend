use crate::observability::AuditRecord;
use crate::panel::types::User;
use crate::protocol::InboundContext;
use crate::proxy::router::MatchContext;
use std::collections::HashMap;
use std::io::{self, Error, ErrorKind};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::debug;

pub const MAX_UDP_PAYLOAD_SIZE: usize = 65535;

/// Negotiates SOCKS5 handshake over a Mieru session stream and relays traffic.
/// Supports both TCP CONNECT (CMD=0x01) and SOCKS5 UDP ASSOCIATE (CMD=0x03).
pub async fn handle_socks5_session<R, W>(
    mut reader: R,
    mut writer: W,
    user: User,
    client_ip: IpAddr,
    ctx: InboundContext,
    _conn_guard: crate::limiter::ConnGuard,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    // Mieru authenticates the user in its encrypted transport; the client sends the request directly.
    let (cmd, target_host, target_ip, target_port) =
        tokio::time::timeout(Duration::from_secs(15), async {
            let mut req_hdr = [0u8; 4];
            reader.read_exact(&mut req_hdr).await?;

            if req_hdr[0] != 0x05 || req_hdr[2] != 0 {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "Invalid SOCKS version in request",
                ));
            }

            let cmd = req_hdr[1];
            let atyp = req_hdr[3];

            let (target_host, target_ip, target_port) = match atyp {
                0x01 => {
                    let mut addr_buf = [0u8; 6];
                    reader.read_exact(&mut addr_buf).await?;
                    let ip = IpAddr::V4(Ipv4Addr::new(
                        addr_buf[0],
                        addr_buf[1],
                        addr_buf[2],
                        addr_buf[3],
                    ));
                    let port = u16::from_be_bytes([addr_buf[4], addr_buf[5]]);
                    (ip.to_string(), Some(ip), port)
                }
                0x03 => {
                    let mut len_buf = [0u8; 1];
                    reader.read_exact(&mut len_buf).await?;
                    let domain_len = len_buf[0] as usize;
                    let mut domain_buf = vec![0u8; domain_len + 2];
                    reader.read_exact(&mut domain_buf).await?;
                    let domain = String::from_utf8_lossy(&domain_buf[..domain_len]).to_string();
                    let port =
                        u16::from_be_bytes([domain_buf[domain_len], domain_buf[domain_len + 1]]);
                    (domain, None, port)
                }
                0x04 => {
                    let mut addr_buf = [0u8; 18];
                    reader.read_exact(&mut addr_buf).await?;
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&addr_buf[..16]);
                    let ip = IpAddr::V6(Ipv6Addr::from(octets));
                    let port = u16::from_be_bytes([addr_buf[16], addr_buf[17]]);
                    (ip.to_string(), Some(ip), port)
                }
                _ => {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "Unsupported SOCKS5 address type",
                    ));
                }
            };

            Ok::<_, io::Error>((cmd, target_host, target_ip, target_port))
        })
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "Mieru SOCKS request timed out"))??;

    match cmd {
        0x01 => {
            // CMD = 0x01: TCP CONNECT
            handle_socks5_tcp_connect(
                reader,
                writer,
                user,
                client_ip,
                target_host,
                target_ip,
                target_port,
                ctx,
            )
            .await
        }
        0x03 => {
            // UDP destinations acquire their own shared session quota.
            drop(_conn_guard);
            handle_socks5_udp_associate(reader, writer, user, client_ip, ctx).await
        }
        _ => {
            // Send Command not supported
            let _ = writer
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            let _ = writer.flush().await;
            Err(Error::new(
                ErrorKind::InvalidData,
                format!("Unsupported SOCKS5 command {}", cmd),
            ))
        }
    }
}

/// Handle SOCKS5 TCP CONNECT forwarding
async fn handle_socks5_tcp_connect<R, W>(
    client_read: R,
    mut client_write: W,
    user: User,
    client_ip: IpAddr,
    target_host: String,
    target_ip: Option<IpAddr>,
    target_port: u16,
    ctx: InboundContext,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let start_time = Instant::now();
    let user_id = user.id;

    if ctx.audit.should_block(&target_host, target_ip, target_port) {
        let _ = client_write
            .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await;
        let _ = client_write.flush().await;
        return Ok(());
    }

    let mctx = MatchContext {
        node_id: ctx.node_id,
        network: "tcp",
        target_host: &target_host,
        target_ip,
        target_port,
        inbound_local_ip: None,
    };

    let outbound = ctx.router.match_outbound(&mctx);
    let outbound_res = ctx
        .router
        .dialer()
        .dial(&outbound, &target_host, target_port, None)
        .await;
    let outbound_stream = match outbound_res {
        Ok(s) => s,
        Err(e) => {
            let _ = client_write
                .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            let _ = client_write.flush().await;
            return Err(e);
        }
    };

    // Respond success: 05 00 00 01 00 00 00 00 00 00
    client_write
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    client_write.flush().await?;

    let mut outbound_stream = outbound_stream;
    let stream = tokio::io::join(client_read, client_write);
    let mut client =
        crate::conn::MonitoredStream::new(stream, user_id, std::net::SocketAddr::new(client_ip, 0));
    let _traffic = client.traffic_guard(ctx.on_traffic.clone());
    let result = crate::conn::copy_bidirectional_throttled(
        &mut client,
        &mut outbound_stream,
        user_id,
        Some(&ctx.rate_limiter),
        ctx.global_config.tcp_timeout,
    )
    .await;
    let (up_bytes, down_bytes) = client.stats();
    let duration = start_time.elapsed().as_millis() as i64;

    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user_id,
        "mieru-tcp",
        "tcp",
        &client_ip.to_string(),
        &target_host,
        target_port,
        up_bytes,
        down_bytes,
        duration,
        &outbound.tag,
        if result.is_ok() { "success" } else { "error" },
    ));

    result.map(|_| ())
}

/// Handle SOCKS5 UDP ASSOCIATE packet framing inside Mieru stream tunnel
/// Encapsulation: 0x00 || uint16(len) || SOCKS5_UDP_PACKET || 0xFF
async fn handle_socks5_udp_associate<R, W>(
    mut client_read: R,
    mut client_write: W,
    user: User,
    client_ip: IpAddr,
    ctx: InboundContext,
) -> io::Result<()>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    client_write
        .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        .await?;
    client_write.flush().await?;
    let (responses, mut response_rx) = mpsc::channel::<(
        Vec<u8>,
        shadowsocks::relay::socks5::Address,
        tokio::sync::oneshot::Sender<()>,
    )>(256);
    let cancel = CancellationToken::new();
    let _cancel = cancel.clone().drop_guard();
    let write_task = async {
        let _done = cancel.clone().drop_guard();
        loop {
            let (data, src_addr, ack) = tokio::select! {
                _ = cancel.cancelled() => break,
                response = response_rx.recv() => match response { Some(response) => response, None => break },
            };
            let mut socks5_pkt = vec![0, 0, 0];
            match src_addr {
                shadowsocks::relay::socks5::Address::SocketAddress(sa) => {
                    match sa.ip() {
                        IpAddr::V4(v4) => {
                            socks5_pkt.push(0x01);
                            socks5_pkt.extend_from_slice(&v4.octets());
                        }
                        IpAddr::V6(v6) => {
                            socks5_pkt.push(0x04);
                            socks5_pkt.extend_from_slice(&v6.octets());
                        }
                    }
                    socks5_pkt.extend_from_slice(&sa.port().to_be_bytes());
                }
                shadowsocks::relay::socks5::Address::DomainNameAddress(ref d, p) => {
                    socks5_pkt.push(0x03);
                    socks5_pkt.push(d.len() as u8);
                    socks5_pkt.extend_from_slice(d.as_bytes());
                    socks5_pkt.extend_from_slice(&p.to_be_bytes());
                }
            }

            socks5_pkt.extend_from_slice(&data);
            if socks5_pkt.len() > u16::MAX as usize {
                continue;
            }
            let mut frame = Vec::with_capacity(socks5_pkt.len() + 4);
            frame.push(0);
            frame.extend_from_slice(&(socks5_pkt.len() as u16).to_be_bytes());
            frame.extend_from_slice(&socks5_pkt);
            frame.push(0xff);
            tokio::select! {
                _ = cancel.cancelled() => break,
                result = async { client_write.write_all(&frame).await?; client_write.flush().await } => result?,
            }
            let _ = ack.send(());
        }
        Ok::<_, io::Error>(())
    };
    let read_task = async {
        let _done = cancel.clone().drop_guard();
        let mut workers = tokio::task::JoinSet::new();
        let mut sessions: HashMap<(String, u16), mpsc::Sender<Vec<u8>>> = HashMap::new();
        let mut pkt_buf = vec![0; MAX_UDP_PAYLOAD_SIZE];
        loop {
            let n = tokio::select! {
                _ = cancel.cancelled() => break,
                result = read_mieru_encapsulated_packet(&mut client_read, &mut pkt_buf) => match result {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) => { debug!(error = %e, "Invalid Mieru UDP frame"); break; }
                },
            };
            if n < 7 || pkt_buf[..3] != [0, 0, 0] {
                continue;
            }
            let atyp = pkt_buf[3];
            let (dst_host, dst_port, data_offset) = match atyp {
                0x01 => {
                    // IPv4
                    if n < 10 {
                        continue;
                    }
                    let ip = IpAddr::V4(Ipv4Addr::new(
                        pkt_buf[4], pkt_buf[5], pkt_buf[6], pkt_buf[7],
                    ));
                    let port = u16::from_be_bytes([pkt_buf[8], pkt_buf[9]]);
                    (ip.to_string(), port, 10)
                }
                0x03 => {
                    // Domain
                    let dlen = pkt_buf[4] as usize;
                    if n < 7 + dlen {
                        continue;
                    }
                    let domain = String::from_utf8_lossy(&pkt_buf[5..5 + dlen]).to_string();
                    let port = u16::from_be_bytes([pkt_buf[5 + dlen], pkt_buf[6 + dlen]]);
                    (domain, port, 7 + dlen)
                }
                0x04 => {
                    // IPv6
                    if n < 22 {
                        continue;
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&pkt_buf[4..20]);
                    let ip = IpAddr::V6(Ipv6Addr::from(octets));
                    let port = u16::from_be_bytes([pkt_buf[20], pkt_buf[21]]);
                    (ip.to_string(), port, 22)
                }
                _ => continue,
            };

            let key = (dst_host, dst_port);
            if dst_port == 0 {
                continue;
            }
            if sessions.get(&key).is_none_or(|tx| tx.is_closed()) {
                let session = match crate::conn::udp::UdpSession::connect(
                    ctx.clone(),
                    user.id,
                    std::net::SocketAddr::new(client_ip, 0),
                    key.0.clone(),
                    key.1,
                    None,
                    "mieru-udp-associate",
                )
                .await
                {
                    Ok(session) => session,
                    Err(e) => {
                        debug!(error = %e, "Mieru UDP rejected");
                        continue;
                    }
                };
                let (tx, requests) = mpsc::channel(256);
                sessions.insert(key.clone(), tx);
                let responses = responses.clone();
                let cancel = cancel.clone();
                while let Some(result) = workers.try_join_next() {
                    if let Err(e) = result {
                        tracing::warn!(error = %e, "Mieru UDP worker failed");
                    }
                }
                workers.spawn(async move {
                    let _ = session.relay(requests, responses, cancel).await;
                });
            }
            if let Some(tx) = sessions.get(&key) {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tx.send(pkt_buf[data_offset..n].to_vec()) => {},
                }
            }
        }
        cancel.cancel();
        while workers.join_next().await.is_some() {}
    };
    let (result, ()) = tokio::join!(write_task, read_task);
    result
}

/// Helper to read a single Mieru PacketOverStreamTunnel frame:
/// 0x00 || uint16(len) || packet || 0xFF
async fn read_mieru_encapsulated_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    buf: &mut [u8],
) -> io::Result<usize> {
    let mut delim = [0u8; 1];
    match reader.read_exact(&mut delim).await {
        Ok(_) => {}
        Err(e) if e.kind() == ErrorKind::UnexpectedEof => return Ok(0),
        Err(e) => return Err(e),
    }

    if delim[0] != 0x00 {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid packet prefix 0x{:02x}, expected 0x00", delim[0]),
        ));
    }

    let mut len_bytes = [0u8; 2];
    reader.read_exact(&mut len_bytes).await?;
    let len = u16::from_be_bytes(len_bytes) as usize;

    if len > buf.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "Encapsulated UDP packet length {} exceeds buffer limit {}",
                len,
                buf.len()
            ),
        ));
    }

    reader.read_exact(&mut buf[..len]).await?;

    reader.read_exact(&mut delim).await?;
    if delim[0] != 0xFF {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Invalid packet suffix 0x{:02x}, expected 0xFF", delim[0]),
        ));
    }

    Ok(len)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[tokio::test]
    async fn packet_over_stream_validates_delimiters_and_lengths() {
        let mut output = [0u8; 8];
        let mut valid = &[0, 0, 3, 1, 2, 3, 0xff][..];
        assert_eq!(
            read_mieru_encapsulated_packet(&mut valid, &mut output)
                .await
                .unwrap(),
            3
        );
        assert_eq!(&output[..3], &[1, 2, 3]);
        for frame in [
            vec![1],
            vec![0, 0, 1, 2, 0],
            vec![0, 0, 2, 1],
            vec![0, 0, 9],
        ] {
            assert!(
                read_mieru_encapsulated_packet(&mut frame.as_slice(), &mut output)
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn tcp_relay_preserves_half_close_and_accounts_on_abort() {
        for abort in [false, true] {
            let totals = Arc::new(parking_lot::Mutex::new((0u64, 0u64)));
            let geo = Arc::new(crate::geo::GeoEngine::default());
            let dialer = Arc::new(crate::proxy::router::OutboundDialer::new(
                Arc::new(crate::dns::DNSResolver::default()),
                None,
                None,
                false,
            ));
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
                on_traffic: {
                    let totals = totals.clone();
                    Arc::new(move |_, up, down| {
                        let mut total = totals.lock();
                        total.0 += up;
                        total.1 += down;
                    })
                },
                global_config: Arc::new(crate::config::GlobalConfig {
                    tcp_timeout: 2,
                    ..Default::default()
                }),
                ip_user_cache: Arc::new(crate::limiter::IpUserCache::new(1, false, "")),
            };
            for header in [[4, 1, 0, 1], [5, 1, 1, 1], [5, 1, 0, 255], [5, 1, 0, 1]] {
                let (mut client, relay) = tokio::io::duplex(64);
                let (read, write) = tokio::io::split(relay);
                let guard = ctx.conn_limiter.try_acquire(42).unwrap();
                let task = tokio::spawn(handle_socks5_session(
                    read,
                    write,
                    User {
                        id: 42,
                        ..Default::default()
                    },
                    "127.0.0.1".parse().unwrap(),
                    ctx.clone(),
                    guard,
                ));
                client.write_all(&header).await.unwrap();
                client.shutdown().await.unwrap();
                assert!(task.await.unwrap().is_err());
            }
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let (received, notified) = tokio::sync::oneshot::channel();
            let target = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut data = [0; 1024];
                socket.read_exact(&mut data).await.unwrap();
                received.send(()).unwrap();
                let mut rest = Vec::new();
                socket.read_to_end(&mut rest).await.unwrap();
                assert!(rest.is_empty());
                if !abort {
                    socket.write_all(b"reply").await.unwrap();
                }
            });
            let (mut client, relay) = tokio::io::duplex(65536);
            let (read, write) = tokio::io::split(relay);
            let guard = ctx.conn_limiter.try_acquire(42).unwrap();
            let task = tokio::spawn(handle_socks5_session(
                read,
                write,
                User {
                    id: 42,
                    ..Default::default()
                },
                "127.0.0.1".parse().unwrap(),
                ctx,
                guard,
            ));
            let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
            request.extend_from_slice(&address.port().to_be_bytes());
            client.write_all(&request).await.unwrap();
            let mut response = [0; 10];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(&response[..2], &[5, 0]);
            client.write_all(&[1; 1024]).await.unwrap();
            notified.await.unwrap();
            if abort {
                task.abort();
                assert!(task.await.unwrap_err().is_cancelled());
            } else {
                client.shutdown().await.unwrap();
                let mut reply = Vec::new();
                tokio::time::timeout(Duration::from_secs(3), client.read_to_end(&mut reply))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(reply, b"reply");
                task.await.unwrap().unwrap();
            }
            tokio::time::timeout(Duration::from_secs(3), target)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(*totals.lock(), (1024, if abort { 0 } else { 5 }));
        }
    }
}
