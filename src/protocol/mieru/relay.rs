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
    // 1. Read SOCKS5 greeting: 05 [nmethods] [methods...]
    let mut greeting_hdr = [0u8; 2];
    reader.read_exact(&mut greeting_hdr).await?;

    if greeting_hdr[0] != 0x05 {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid SOCKS version"));
    }

    let nmethods = greeting_hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    reader.read_exact(&mut methods).await?;

    if !methods.contains(&0x00) {
        // No acceptable methods
        writer.write_all(&[0x05, 0xFF]).await?;
        writer.flush().await?;
        return Err(Error::new(ErrorKind::InvalidData, "No acceptable auth method"));
    }

    // Reply 05 00 (No auth required)
    writer.write_all(&[0x05, 0x00]).await?;
    writer.flush().await?;

    // 2. Read SOCKS5 request: 05 [cmd] 00 [atyp] ...
    let mut req_hdr = [0u8; 4];
    reader.read_exact(&mut req_hdr).await?;

    if req_hdr[0] != 0x05 {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid SOCKS version in request"));
    }

    let cmd = req_hdr[1];
    let atyp = req_hdr[3];

    let (target_host, target_ip, target_port) = match atyp {
        0x01 => {
            let mut addr_buf = [0u8; 6];
            reader.read_exact(&mut addr_buf).await?;
            let ip = IpAddr::V4(Ipv4Addr::new(addr_buf[0], addr_buf[1], addr_buf[2], addr_buf[3]));
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
            let port = u16::from_be_bytes([domain_buf[domain_len], domain_buf[domain_len + 1]]);
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
            return Err(Error::new(ErrorKind::InvalidData, "Unsupported SOCKS5 address type"));
        }
    };

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
            // CMD = 0x03: UDP ASSOCIATE
            handle_socks5_udp_associate(
                reader,
                writer,
                user,
                client_ip,
                ctx,
            )
            .await
        }
        _ => {
            // Send Command not supported
            let _ = writer.write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            let _ = writer.flush().await;
            Err(Error::new(ErrorKind::InvalidData, format!("Unsupported SOCKS5 command {}", cmd)))
        }
    }
}

/// Handle SOCKS5 TCP CONNECT forwarding
async fn handle_socks5_tcp_connect<R, W>(
    mut client_read: R,
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
        let _ = client_write.write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
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
            let _ = client_write.write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            let _ = client_write.flush().await;
            return Err(e);
        }
    };

    // Respond success: 05 00 00 01 00 00 00 00 00 00
    client_write.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    client_write.flush().await?;

    let (mut out_read, mut out_write) = tokio::io::split(outbound_stream);

    let cancel_token = CancellationToken::new();
    let write_cancel = cancel_token.clone();

    let rate_limiter = ctx.rate_limiter.clone();
    let on_traffic_up = ctx.on_traffic.clone();
    let on_traffic_down = ctx.on_traffic.clone();

    // Client -> Outbound
    let up_rate_limiter = rate_limiter.clone();
    let up_task = async move {
        let mut buf = vec![0u8; 16384];
        let mut total_up = 0u64;
        loop {
            tokio::select! {
                _ = write_cancel.cancelled() => break,
                res = client_read.read(&mut buf) => {
                    match res {
                        Ok(0) => break,
                        Ok(n) => {
                            up_rate_limiter.throttle(user_id, n).await;
                            if out_write.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                            total_up += n as u64;
                            (on_traffic_up)(user_id, n as u64, 0);
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        let _ = out_write.shutdown().await;
        write_cancel.cancel();
        total_up
    };

    // Outbound -> Client
    let read_cancel = cancel_token.clone();
    let down_rate_limiter = rate_limiter.clone();
    let down_task = async move {
        let mut buf = vec![0u8; 16384];
        let mut total_down = 0u64;
        loop {
            tokio::select! {
                _ = read_cancel.cancelled() => break,
                res = out_read.read(&mut buf) => {
                    match res {
                        Ok(0) => break,
                        Ok(n) => {
                            down_rate_limiter.throttle(user_id, n).await;
                            if client_write.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                            let _ = client_write.flush().await;
                            total_down += n as u64;
                            (on_traffic_down)(user_id, 0, n as u64);
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        let _ = client_write.shutdown().await;
        read_cancel.cancel();
        total_down
    };

    let (up_bytes, down_bytes) = tokio::join!(up_task, down_task);
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
        "direct",
        "success",
    ));

    Ok(())
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
    let start_time = Instant::now();
    let user_id = user.id;

    // Send SOCKS5 UDP Associate success: BND.ADDR=0.0.0.0, BND.PORT=0
    client_write.write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
    client_write.flush().await?;

    let (response_tx, mut response_rx) = mpsc::channel::<Vec<u8>>(256);
    let cancel_token = CancellationToken::new();

    let mut sessions: HashMap<(String, u16), mpsc::Sender<Vec<u8>>> = HashMap::new();
    let rate_limiter = ctx.rate_limiter.clone();
    let on_traffic_up = ctx.on_traffic.clone();
    let on_traffic_down = ctx.on_traffic.clone();

    let write_cancel = cancel_token.clone();
    let write_task = async {
        let mut total_down = 0u64;
        while let Some(pkt) = response_rx.recv().await {
            rate_limiter.throttle(user_id, pkt.len()).await;
            if client_write.write_all(&pkt).await.is_err() {
                break;
            }
            if client_write.flush().await.is_err() {
                break;
            }
            total_down += pkt.len() as u64;
            (on_traffic_down)(user_id, 0, pkt.len() as u64);
        }
        let _ = client_write.shutdown().await;
        write_cancel.cancel();
        total_down
    };

    let read_cancel = cancel_token.clone();
    let read_task = async {
        let mut total_up = 0u64;
        let mut pkt_buf = vec![0u8; 65536];

        loop {
            tokio::select! {
                _ = read_cancel.cancelled() => break,
                read_res = read_mieru_encapsulated_packet(&mut client_read, &mut pkt_buf) => {
                    let n = match read_res {
                        Ok(0) => break,
                        Ok(len) => len,
                        Err(e) => {
                            debug!("Error reading encapsulated UDP packet: {:?}", e);
                            break;
                        }
                    };

                    rate_limiter.throttle(user_id, n).await;
                    total_up += n as u64;
                    (on_traffic_up)(user_id, n as u64, 0);

                    // Parse SOCKS5 UDP header: RSV(2) | FRAG(1) | ATYP(1) | DST.ADDR | DST.PORT | DATA
                    if n < 7 {
                        continue;
                    }
                    if pkt_buf[0] != 0x00 || pkt_buf[1] != 0x00 {
                        continue;
                    }
                    if pkt_buf[2] != 0x00 {
                        // Frag != 0 unsupported
                        continue;
                    }

                    let atyp = pkt_buf[3];
                    let (dst_host, dst_port, data_offset) = match atyp {
                        0x01 => {
                            // IPv4
                            if n < 10 { continue; }
                            let ip = IpAddr::V4(Ipv4Addr::new(pkt_buf[4], pkt_buf[5], pkt_buf[6], pkt_buf[7]));
                            let port = u16::from_be_bytes([pkt_buf[8], pkt_buf[9]]);
                            (ip.to_string(), port, 10)
                        }
                        0x03 => {
                            // Domain
                            let dlen = pkt_buf[4] as usize;
                            if n < 7 + dlen { continue; }
                            let domain = String::from_utf8_lossy(&pkt_buf[5..5 + dlen]).to_string();
                            let port = u16::from_be_bytes([pkt_buf[5 + dlen], pkt_buf[6 + dlen]]);
                            (domain, port, 7 + dlen)
                        }
                        0x04 => {
                            // IPv6
                            if n < 22 { continue; }
                            let mut octets = [0u8; 16];
                            octets.copy_from_slice(&pkt_buf[4..20]);
                            let ip = IpAddr::V6(Ipv6Addr::from(octets));
                            let port = u16::from_be_bytes([pkt_buf[20], pkt_buf[21]]);
                            (ip.to_string(), port, 22)
                        }
                        _ => continue,
                    };

                    let udp_data = pkt_buf[data_offset..n].to_vec();

                    if ctx.audit.should_block(&dst_host, None, dst_port) {
                        continue;
                    }

                    let key = (dst_host.clone(), dst_port);
                    if let Some(tx) = sessions.get(&key) {
                        if tx.send(udp_data.clone()).await.is_ok() {
                            continue;
                        }
                    }

                    // New outbound UDP session
                    let mctx = MatchContext {
                        node_id: ctx.node_id,
                        network: "udp",
                        target_host: &dst_host,
                        target_ip: None,
                        target_port: dst_port,
                        inbound_local_ip: None,
                    };
                    let outbound = ctx.router.match_outbound(&mctx);

                    let udp_outbound = match ctx.router.dialer().dial_udp_outbound(&outbound, &dst_host, dst_port, None).await {
                        Ok(s) => s,
                        Err(e) => {
                            debug!("Mieru UDP Associate outbound dial error for {}:{}: {:?}", dst_host, dst_port, e);
                            continue;
                        }
                    };

                    let (req_tx, mut req_rx) = mpsc::channel::<Vec<u8>>(128);
                    let resp_tx = response_tx.clone();
                    let child_cancel = read_cancel.child_token();
                    let child_host = dst_host.clone();

                    tokio::spawn(async move {
                        let mut recv_buf = [0u8; 65535];
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
                                            // Format into SOCKS5 UDP response
                                            let mut socks5_pkt = Vec::with_capacity(32 + n);
                                            socks5_pkt.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV(2) + FRAG(1)
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
                                            socks5_pkt.extend_from_slice(&recv_buf[..n]);

                                            // Encapsulate into Mieru PacketOverStreamTunnel frame:
                                            // 0x00 || uint16(len) || socks5_pkt || 0xFF
                                            let mut enc_frame = Vec::with_capacity(4 + socks5_pkt.len());
                                            enc_frame.push(0x00);
                                            enc_frame.extend_from_slice(&(socks5_pkt.len() as u16).to_be_bytes());
                                            enc_frame.extend_from_slice(&socks5_pkt);
                                            enc_frame.push(0xFF);

                                            if resp_tx.send(enc_frame).await.is_err() {
                                                break;
                                            }
                                        }
                                        _ => break,
                                    }
                                }
                            }
                        }
                        debug!("Mieru UDP Associate session for {}:{} terminated", child_host, dst_port);
                    });

                    let _ = req_tx.send(udp_data).await;
                    sessions.insert(key, req_tx);
                }
            }
        }
        read_cancel.cancel();
        total_up
    };

    let (down_bytes, up_bytes) = tokio::join!(write_task, read_task);
    let duration = start_time.elapsed().as_millis() as i64;

    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user_id,
        "mieru-udp-associate",
        "udp",
        &client_ip.to_string(),
        "udp-associate",
        0,
        up_bytes,
        down_bytes,
        duration,
        "direct",
        "success",
    ));

    Ok(())
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
            format!("Encapsulated UDP packet length {} exceeds buffer limit {}", len, buf.len()),
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
