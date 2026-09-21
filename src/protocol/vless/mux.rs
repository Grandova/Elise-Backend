use crate::conn::{BoxedStream, IdleTimeout, TrafficGuard};
use crate::limiter::ConnGuard;
use crate::panel::types::User;
use crate::protocol::InboundContext;
use crate::proxy::router::MatchContext;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::{debug, warn};

#[inline]
pub fn encode_mux_meta(session_id: u16, status: u8, option: u8) -> Vec<u8> {
    vec![
        0x00,
        0x04,
        (session_id >> 8) as u8,
        session_id as u8,
        status,
        option,
    ]
}

#[inline]
pub fn encode_mux_end(session_id: u16) -> Vec<u8> {
    encode_mux_meta(session_id, 3, 0)
}

#[inline]
pub fn encode_mux_data(session_id: u16, data: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(8 + data.len());
    frame.extend_from_slice(&[
        0x00,
        0x04,
        (session_id >> 8) as u8,
        session_id as u8,
        0x02,
        0x01,
        (data.len() >> 8) as u8,
        data.len() as u8,
    ]);
    frame.extend_from_slice(data);
    frame
}

pub fn parse_mux_address(atyp: u8, buf: &[u8]) -> io::Result<(String, Option<IpAddr>, usize)> {
    match atyp {
        0x01 => {
            if buf.len() < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated IPv4",
                ));
            }
            let ip = IpAddr::V4(Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]));
            Ok((ip.to_string(), Some(ip), 4))
        }
        0x02 => {
            if buf.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing domain length",
                ));
            }
            let len = buf[0] as usize;
            if buf.len() < 1 + len {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated domain",
                ));
            }
            let domain = String::from_utf8_lossy(&buf[1..1 + len]).to_string();
            let ip = domain.parse::<IpAddr>().ok();
            Ok((domain, ip, 1 + len))
        }
        0x03 => {
            if buf.len() < 16 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated IPv6",
                ));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&buf[..16]);
            let ip = IpAddr::V6(Ipv6Addr::from(octets));
            Ok((ip.to_string(), Some(ip), 16))
        }
        unknown => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid Mux address type: {unknown:#x}"),
        )),
    }
}

pub async fn handle_vless_mux(
    stream: BoxedStream,
    _conn_guard: ConnGuard,
    _client_ip: IpAddr,
    local_ip: Option<IpAddr>,
    user: Arc<User>,
    ctx: InboundContext,
    remote_addr: SocketAddr,
) -> io::Result<()> {
    debug!(
        "VLESS Mux: start handling multiplexed connection from {}",
        remote_addr
    );
    let (mut client_read, mut client_write) = tokio::io::split(stream);
    let (tx_out, mut rx_out) = mpsc::channel::<Vec<u8>>(128);

    let writer_task = async {
        while let Some(frame) = rx_out.recv().await {
            client_write.write_all(&frame).await?;
            client_write.flush().await?;
        }
        Ok::<_, io::Error>(())
    };

    let user_id = user.id;
    let rate_limiter = ctx.rate_limiter.clone();
    let traffic = Arc::new(TrafficGuard::new(user_id, ctx.on_traffic.clone()));
    let idle = IdleTimeout::new(ctx.global_config.tcp_timeout.max(300));

    let mut sessions: HashMap<u16, mpsc::Sender<Vec<u8>>> = HashMap::new();

    let reader_task = async {
        let mut meta_len_buf = [0u8; 2];
        loop {
            let read_res = idle.run(client_read.read_exact(&mut meta_len_buf)).await;
            match read_res {
                Ok(_) => {}
                Err(_) => break,
            }
            let meta_len = u16::from_be_bytes(meta_len_buf) as usize;
            if meta_len < 4 {
                if meta_len > 0 {
                    let mut dummy = vec![0u8; meta_len];
                    let _ = client_read.read_exact(&mut dummy).await;
                }
                continue;
            }

            let mut meta_buf = vec![0u8; meta_len];
            if idle
                .run(client_read.read_exact(&mut meta_buf))
                .await
                .is_err()
            {
                break;
            }

            let session_id = u16::from_be_bytes([meta_buf[0], meta_buf[1]]);
            let status = meta_buf[2];
            let option = meta_buf[3];

            let payload = if option & 0x01 != 0 {
                let mut data_len_buf = [0u8; 2];
                if idle
                    .run(client_read.read_exact(&mut data_len_buf))
                    .await
                    .is_err()
                {
                    break;
                }
                let data_len = u16::from_be_bytes(data_len_buf) as usize;
                let mut p = vec![0u8; data_len];
                if data_len > 0 && idle.run(client_read.read_exact(&mut p)).await.is_err() {
                    break;
                }
                p
            } else {
                Vec::new()
            };

            match status {
                1 => {
                    if meta_buf.len() < 8 {
                        continue;
                    }
                    let network = meta_buf[4];
                    let target_port = u16::from_be_bytes([meta_buf[5], meta_buf[6]]);
                    let atyp = meta_buf[7];
                    let (target_host, target_ip, _) = match parse_mux_address(atyp, &meta_buf[8..])
                    {
                        Ok(res) => res,
                        Err(e) => {
                            warn!(
                                "VLESS Mux: invalid target address in Session {}: {:?}",
                                session_id, e
                            );
                            let _ = tx_out.send(encode_mux_end(session_id)).await;
                            continue;
                        }
                    };

                    if ctx.audit.should_block(&target_host, target_ip, target_port) {
                        warn!(
                            "VLESS Mux: blocked target {}:{} for Session {}",
                            target_host, target_port, session_id
                        );
                        let _ = tx_out.send(encode_mux_end(session_id)).await;
                        continue;
                    }

                    if !payload.is_empty() {
                        rate_limiter.throttle(user_id, payload.len()).await;
                        traffic.add(payload.len() as u64, 0);
                    }

                    let (tx_sub, mut rx_sub) = mpsc::channel::<Vec<u8>>(64);
                    sessions.insert(session_id, tx_sub);

                    let mctx = MatchContext {
                        node_id: ctx.node_id,
                        network: if network == 2 { "udp" } else { "tcp" },
                        target_host: &target_host,
                        target_ip,
                        target_port,
                        inbound_local_ip: local_ip,
                    };
                    let outbound = ctx.router.match_outbound(&mctx);

                    let tx_out_clone = tx_out.clone();
                    let traffic_clone = traffic.clone();
                    let rate_limiter_clone = rate_limiter.clone();
                    let dialer = ctx.router.dialer();

                    if network == 2 {
                        tokio::spawn(async move {
                            match dialer
                                .dial_udp_outbound(&outbound, &target_host, target_port, local_ip)
                                .await
                            {
                                Ok(udp_socket) => {
                                    let socket = Arc::new(udp_socket);
                                    if !payload.is_empty() {
                                        let _ = socket.send(&payload).await;
                                    }

                                    let sock_send = socket.clone();
                                    let up = async {
                                        while let Some(data) = rx_sub.recv().await {
                                            if sock_send.send(&data).await.is_err() {
                                                break;
                                            }
                                        }
                                    };

                                    let sock_recv = socket;
                                    let down = async {
                                        let mut buf = vec![0u8; 65535];
                                        loop {
                                            let res = tokio::time::timeout(
                                                Duration::from_secs(60),
                                                sock_recv.recv(&mut buf),
                                            )
                                            .await;
                                            match res {
                                                Ok(Ok((n, _addr))) if n > 0 => {
                                                    rate_limiter_clone.throttle(user_id, n).await;
                                                    traffic_clone.add(0, n as u64);
                                                    let frame =
                                                        encode_mux_data(session_id, &buf[..n]);
                                                    if tx_out_clone.send(frame).await.is_err() {
                                                        break;
                                                    }
                                                }
                                                _ => break,
                                            }
                                        }
                                    };

                                    tokio::select! {
                                        _ = up => {},
                                        _ = down => {},
                                    }
                                    let _ = tx_out_clone.send(encode_mux_end(session_id)).await;
                                }
                                Err(e) => {
                                    warn!(
                                        "VLESS Mux: UDP dial failed for {}:{} - {:?}",
                                        target_host, target_port, e
                                    );
                                    let _ = tx_out_clone.send(encode_mux_end(session_id)).await;
                                }
                            }
                        });
                    } else {
                        tokio::spawn(async move {
                            match dialer
                                .dial(&outbound, &target_host, target_port, local_ip)
                                .await
                            {
                                Ok(mut tcp_stream) => {
                                    if !payload.is_empty() {
                                        if tcp_stream.write_all(&payload).await.is_err() {
                                            let _ =
                                                tx_out_clone.send(encode_mux_end(session_id)).await;
                                            return;
                                        }
                                    }

                                    let (mut tcp_read, mut tcp_write) =
                                        tokio::io::split(tcp_stream);
                                    let up = async {
                                        while let Some(data) = rx_sub.recv().await {
                                            if tcp_write.write_all(&data).await.is_err() {
                                                break;
                                            }
                                        }
                                        let _ = tcp_write.shutdown().await;
                                    };

                                    let down = async {
                                        let mut buf = vec![0u8; 16384];
                                        loop {
                                            match tcp_read.read(&mut buf).await {
                                                Ok(n) if n > 0 => {
                                                    rate_limiter_clone.throttle(user_id, n).await;
                                                    traffic_clone.add(0, n as u64);
                                                    let frame =
                                                        encode_mux_data(session_id, &buf[..n]);
                                                    if tx_out_clone.send(frame).await.is_err() {
                                                        break;
                                                    }
                                                }
                                                _ => break,
                                            }
                                        }
                                    };

                                    tokio::select! {
                                        _ = up => {},
                                        _ = down => {},
                                    }
                                    let _ = tx_out_clone.send(encode_mux_end(session_id)).await;
                                }
                                Err(e) => {
                                    warn!(
                                        "VLESS Mux: TCP dial failed for {}:{} - {:?}",
                                        target_host, target_port, e
                                    );
                                    let _ = tx_out_clone.send(encode_mux_end(session_id)).await;
                                }
                            }
                        });
                    }
                }
                2 => {
                    if let Some(tx_sub) = sessions.get(&session_id) {
                        if !payload.is_empty() {
                            rate_limiter.throttle(user_id, payload.len()).await;
                            traffic.add(payload.len() as u64, 0);
                            let _ = tx_sub.send(payload).await;
                        }
                    } else {
                        let _ = tx_out.send(encode_mux_end(session_id)).await;
                    }
                }
                3 => {
                    sessions.remove(&session_id);
                }
                4 => {
                    let _ = tx_out.send(encode_mux_meta(session_id, 4, 0)).await;
                }
                _ => {}
            }
        }
        Ok::<_, io::Error>(())
    };

    tokio::select! {
        res = reader_task => {
            if let Err(e) = res {
                debug!("VLESS Mux: reader task ended with: {:?}", e);
            }
        }
        res = writer_task => {
            if let Err(e) = res {
                debug!("VLESS Mux: writer task ended with: {:?}", e);
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_mux_meta_and_data() {
        let meta = encode_mux_meta(1, 2, 1);
        assert_eq!(meta, vec![0x00, 0x04, 0x00, 0x01, 0x02, 0x01]);

        let end = encode_mux_end(5);
        assert_eq!(end, vec![0x00, 0x04, 0x00, 0x05, 0x03, 0x00]);

        let data = encode_mux_data(2, b"hello");
        assert_eq!(
            data,
            vec![0x00, 0x04, 0x00, 0x02, 0x02, 0x01, 0x00, 0x05, b'h', b'e', b'l', b'l', b'o',]
        );
    }

    #[test]
    fn test_parse_mux_address() {
        let ipv4_buf = [127, 0, 0, 1];
        let (host, ip, len) = parse_mux_address(1, &ipv4_buf).unwrap();
        assert_eq!(host, "127.0.0.1");
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert_eq!(len, 4);

        let domain_buf = [
            10, b'g', b'o', b'o', b'g', b'l', b'e', b'.', b'c', b'o', b'm',
        ];
        let (host, ip, len) = parse_mux_address(2, &domain_buf).unwrap();
        assert_eq!(host, "google.com");
        assert_eq!(ip, None);
        assert_eq!(len, 11);
    }
}
