use crate::conn::ConnectionMeta;
use crate::panel::types::User;
use crate::protocol::InboundContext;
use crate::proxy::router::MatchContext;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

pub async fn handle_socks5_udp_associate<S: AsyncRead + AsyncWrite + Send + Unpin + 'static>(
    mut stream: S,
    meta: ConnectionMeta,
    user: User,
    _client_dst_host: String,
    _client_dst_port: u16,
    ctx: InboundContext,
) -> io::Result<()> {
    info!(
        "SOCKS5 UDP ASSOCIATE: user={} client_ip={}",
        user.id,
        meta.client_addr.ip()
    );

    // 1. Allocate local UDP socket for client association
    let udp_socket = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            let _ = stream
                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(e);
        }
    };

    let bnd_port = udp_socket.local_addr()?.port();

    // 2. Reply 0x00 succeeded, BND.ADDR = 0.0.0.0, BND.PORT = bnd_port
    let mut rep = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0];
    rep.extend_from_slice(&bnd_port.to_be_bytes());
    stream.write_all(&rep).await?;

    let cancel_token = CancellationToken::new();

    // 3. Outbound session map keyed by (dst_host, dst_port)
    let sessions: Arc<RwLock<HashMap<(String, u16), mpsc::Sender<Vec<u8>>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Channel for multiplexing downstream UDP responses back to client
    let (downstream_tx, mut downstream_rx) = mpsc::channel::<(Vec<u8>, SocketAddr)>(256);

    let client_udp_peer: Arc<RwLock<Option<SocketAddr>>> = Arc::new(RwLock::new(None));

    // Downstream sender task: forwards responses to client UDP socket
    let ds_udp = udp_socket.clone();
    let ds_peer = client_udp_peer.clone();
    let ds_cancel = cancel_token.clone();
    tokio::spawn(async move {
        while let Some((packet, dest)) = downstream_rx.recv().await {
            if ds_cancel.is_cancelled() {
                break;
            }
            let target = ds_peer.read().unwrap_or(dest);
            let _ = ds_udp.send_to(&packet, target).await;
        }
    });

    // Inbound receiver task: reads packets from client UDP socket
    let in_udp = udp_socket.clone();
    let in_cancel = cancel_token.clone();
    let in_peer = client_udp_peer.clone();
    let in_sessions = sessions.clone();
    let in_ctx = ctx.clone();
    let in_user_id = user.id;

    tokio::spawn(async move {
        let mut buf = vec![0u8; 65535];
        while !in_cancel.is_cancelled() {
            let (n, src) = match in_udp.recv_from(&mut buf).await {
                Ok(res) => res,
                Err(_) => break,
            };

            // Record first seen client UDP address
            if in_peer.read().is_none() {
                *in_peer.write() = Some(src);
            }

            if n < 7 {
                continue;
            }

            // RFC 1928 UDP packet parsing
            // +----+------+------+----------+----------+----------+
            // |RSV | FRAG | ATYP | DST.ADDR | DST.PORT |   DATA   |
            // +----+------+------+----------+----------+----------+
            // | 2  |  1   |  1   | Variable |    2     | Variable |
            // +----+------+------+----------+----------+----------+
            let frag = buf[2];
            if frag != 0x00 {
                // Ignore fragmented datagrams per standard RFC 1928 section 7
                continue;
            }

            let atyp = buf[3];
            let (target_host, target_ip, header_len) = match atyp {
                0x01 => {
                    if n < 10 {
                        continue;
                    }
                    let ip = Ipv4Addr::new(buf[4], buf[5], buf[6], buf[7]);
                    (ip.to_string(), Some(IpAddr::V4(ip)), 10)
                }
                0x03 => {
                    let dlen = buf[4] as usize;
                    if n < 5 + dlen + 2 {
                        continue;
                    }
                    let domain = String::from_utf8_lossy(&buf[5..5 + dlen]).to_string();
                    let ip = domain.parse::<IpAddr>().ok();
                    (domain, ip, 5 + dlen + 2)
                }
                0x04 => {
                    if n < 22 {
                        continue;
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&buf[4..20]);
                    let ip = Ipv6Addr::from(octets);
                    (ip.to_string(), Some(IpAddr::V6(ip)), 22)
                }
                _ => continue,
            };

            let port_idx = header_len - 2;
            let target_port = u16::from_be_bytes([buf[port_idx], buf[port_idx + 1]]);
            let payload = buf[header_len..n].to_vec();

            if in_ctx
                .audit
                .should_block(&target_host, target_ip, target_port)
            {
                continue;
            }

            // Per-packet routing
            let key = (target_host.clone(), target_port);
            let tx_opt = in_sessions.read().get(&key).cloned();

            let tx = match tx_opt {
                Some(tx) => tx,
                None => {
                    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(128);
                    let mctx = MatchContext {
                        node_id: in_ctx.node_id,
                        network: "udp",
                        target_host: &target_host,
                        target_ip,
                        target_port,
                        inbound_local_ip: None,
                    };
                    let outbound = in_ctx.router.match_outbound(&mctx);

                    let outbound_socket = match in_ctx
                        .router
                        .dialer()
                        .dial_udp_outbound(&outbound, &target_host, target_port, None)
                        .await
                    {
                        Ok(s) => s,
                        Err(e) => {
                            debug!(
                                "Failed to dial UDP outbound for SOCKS5 {}:{}: {:?}",
                                target_host, target_port, e
                            );
                            continue;
                        }
                    };

                    let out_cancel = in_cancel.clone();
                    let out_ds_tx = downstream_tx.clone();
                    let out_ctx = in_ctx.clone();

                    tokio::spawn(async move {
                        let mut recv_buf = vec![0u8; 65535];
                        loop {
                            tokio::select! {
                                _ = out_cancel.cancelled() => break,
                                packet = rx.recv() => {
                                    match packet {
                                        Some(p) => {
                                            out_ctx.rate_limiter.throttle(in_user_id, p.len()).await;
                                            (out_ctx.on_traffic)(in_user_id, p.len() as u64, 0);
                                            let _ = outbound_socket.send(&p).await;
                                        }
                                        None => break,
                                    }
                                }
                                res = outbound_socket.recv(&mut recv_buf) => {
                                    match res {
                                        Ok((len, src_addr)) => {
                                            out_ctx.rate_limiter.throttle(in_user_id, len).await;
                                            (out_ctx.on_traffic)(in_user_id, 0, len as u64);

                                            // Encapsulate response in RFC 1928 SOCKS5 UDP header
                                            let mut resp = Vec::with_capacity(len + 24);
                                            resp.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV, FRAG
                                            match src_addr {
                                                shadowsocks::relay::socks5::Address::SocketAddress(sa) => {
                                                    match sa.ip() {
                                                        IpAddr::V4(v4) => {
                                                            resp.push(0x01); // ATYP IPv4
                                                            resp.extend_from_slice(&v4.octets());
                                                        }
                                                        IpAddr::V6(v6) => {
                                                            resp.push(0x04); // ATYP IPv6
                                                            resp.extend_from_slice(&v6.octets());
                                                        }
                                                    }
                                                    resp.extend_from_slice(&sa.port().to_be_bytes());
                                                }
                                                shadowsocks::relay::socks5::Address::DomainNameAddress(domain, port) => {
                                                    resp.push(0x03); // ATYP Domain
                                                    resp.push(domain.len() as u8);
                                                    resp.extend_from_slice(domain.as_bytes());
                                                    resp.extend_from_slice(&port.to_be_bytes());
                                                }
                                            }
                                            resp.extend_from_slice(&recv_buf[..len]);

                                            let _ = out_ds_tx.send((resp, src)).await;
                                        }
                                        Err(_) => break,
                                    }
                                }
                            }
                        }
                    });

                    in_sessions.write().insert(key, tx.clone());
                    tx
                }
            };

            let _ = tx.send(payload).await;
        }
    });

    // 4. Lifetime bound to TCP control connection:
    // Wait for client TCP stream to close (EOF / error / shutdown)
    let mut tcp_buf = [0u8; 1];
    let _ = stream.read(&mut tcp_buf).await;

    // TCP closed -> Immediately cancel UDP session and tear down sockets
    cancel_token.cancel();
    debug!(
        "SOCKS5 UDP ASSOCIATE TCP stream closed for client {}, association destroyed",
        meta.client_addr
    );

    Ok(())
}
