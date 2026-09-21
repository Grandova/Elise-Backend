use crate::conn::read_proxy_protocol_with_meta;
use crate::panel::types::User;
use crate::protocol::InboundContext;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::debug;

use super::auth::negotiate_auth;
use super::tcp::handle_socks5_connect;
use super::udp::handle_socks5_udp_associate;

pub async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    ctx: InboundContext,
    users: Arc<RwLock<HashMap<String, User>>>,
) -> io::Result<()> {
    let handshake = async {
        let mode = ctx.global_config.get_proxy_protocol_mode();
        let trusted_proxies = ctx.global_config.trusted_proxies.as_deref();

        let (meta, mut stream) =
            read_proxy_protocol_with_meta(stream, peer_addr, mode, trusted_proxies).await?;

        debug!(
            "SOCKS5 accepted connection: transport_peer={}, client_addr={}, proxy_ver={:?}",
            meta.transport_peer_addr, meta.client_addr, meta.proxy_protocol_version
        );

        let client_ip = meta.client_addr.ip();
        if ctx.defense.is_banned(client_ip) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 client is banned",
            ));
        }

        let authenticated_user = negotiate_auth(&mut stream, client_ip, users, &ctx).await?;

        if !ctx
            .device_limiter
            .check_and_record_async(authenticated_user.id, client_ip)
            .await
        {
            let _ = stream
                .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 device limit reached",
            ));
        }

        let conn_guard = match ctx.conn_limiter.try_acquire(authenticated_user.id) {
            Some(g) => g,
            None => {
                let _ = stream
                    .write_all(&[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "SOCKS5 connection limit reached",
                ));
            }
        };

        let mut req_hdr = [0u8; 4];
        stream.read_exact(&mut req_hdr).await?;
        if req_hdr[0] != 0x05 || req_hdr[2] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid SOCKS request version: 0x{:02x}", req_hdr[0]),
            ));
        }

        let cmd = req_hdr[1];
        let atyp = req_hdr[3];

        let (target_host, target_ip) = match atyp {
            0x01 => {
                let mut ipv4 = [0u8; 4];
                stream.read_exact(&mut ipv4).await?;
                let ip = IpAddr::V4(Ipv4Addr::from(ipv4));
                (ip.to_string(), Some(ip))
            }
            0x03 => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await?;
                if len_buf[0] == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Empty SOCKS5 domain",
                    ));
                }
                let mut domain_buf = vec![0u8; len_buf[0] as usize];
                stream.read_exact(&mut domain_buf).await?;
                let domain = String::from_utf8_lossy(&domain_buf).to_string();
                let parsed_ip = domain.parse::<IpAddr>().ok();
                (domain, parsed_ip)
            }
            0x04 => {
                let mut ipv6 = [0u8; 16];
                stream.read_exact(&mut ipv6).await?;
                let ip = IpAddr::V6(Ipv6Addr::from(ipv6));
                (ip.to_string(), Some(ip))
            }
            _ => {
                let _ = stream
                    .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Unsupported SOCKS5 ATYP: 0x{:02x}", atyp),
                ));
            }
        };

        let mut port_buf = [0u8; 2];
        stream.read_exact(&mut port_buf).await?;
        let target_port = u16::from_be_bytes(port_buf);

        debug!(
            "SOCKS5 Request: cmd=0x{:02x} atyp=0x{:02x} dst={}:{}",
            cmd, atyp, target_host, target_port
        );

        Ok::<_, io::Error>((
            stream,
            meta,
            authenticated_user,
            conn_guard,
            cmd,
            target_host,
            target_ip,
            target_port,
        ))
    };
    let (
        mut stream,
        meta,
        authenticated_user,
        _conn_guard,
        cmd,
        target_host,
        target_ip,
        target_port,
    ) = tokio::time::timeout(std::time::Duration::from_secs(15), handshake)
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "SOCKS5 handshake timed out"))??;

    match cmd {
        0x01 => {
            handle_socks5_connect(
                stream,
                meta,
                authenticated_user,
                target_host,
                target_ip,
                target_port,
                ctx,
            )
            .await
        }
        0x03 => {
            handle_socks5_udp_associate(
                stream,
                meta,
                authenticated_user,
                target_host,
                target_port,
                ctx,
            )
            .await
        }
        _ => {
            let _ = stream
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("Unsupported SOCKS5 CMD: 0x{:02x}", cmd),
            ))
        }
    }
}
