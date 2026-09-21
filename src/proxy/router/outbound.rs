use crate::config::routes::OutboundConfig;
use crate::dns::DNSResolver;
use shadowsocks::relay::socks5::Address;
use std::io::{self, Cursor};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub struct UdpOutbound {
    socket: UdpSocket,
    control: Option<TcpStream>,
    target: Address,
}

impl UdpOutbound {
    pub async fn send(&self, payload: &[u8]) -> io::Result<usize> {
        if self.control.is_none() {
            return self.socket.send(payload).await;
        }
        let mut packet = vec![0, 0, 0];
        self.target.write_to_buf(&mut packet);
        packet.extend_from_slice(payload);
        if packet.len() > 65507 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "SOCKS5 UDP packet too large",
            ));
        }
        self.socket.send(&packet).await?;
        Ok(payload.len())
    }

    pub async fn recv(&self, buffer: &mut [u8]) -> io::Result<(usize, Address)> {
        let Some(control) = &self.control else {
            return self
                .socket
                .recv(buffer)
                .await
                .map(|n| (n, self.target.clone()));
        };
        let mut closed = [0];
        let n = tokio::select! {
            result = control.peek(&mut closed) => {
                result?;
                return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "SOCKS5 UDP control connection closed or sent unexpected data"));
            }
            result = self.socket.recv(buffer) => result?,
        };
        if n < 4 || buffer[..3] != [0, 0, 0] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Malformed or fragmented SOCKS5 UDP packet",
            ));
        }
        let mut cursor = Cursor::new(&buffer[3..n]);
        let address = Address::read_cursor(&mut cursor).map_err(io::Error::other)?;
        let offset = 3 + cursor.position() as usize;
        buffer.copy_within(offset..n, 0);
        Ok((n - offset, address))
    }
}

pub struct OutboundDialer {
    dns_resolver: Arc<DNSResolver>,
    out_ip_v4: Option<IpAddr>,
    out_ip_v6: Option<IpAddr>,
    auto_out_ip: bool,
    audit: parking_lot::RwLock<Option<Arc<crate::security::AuditController>>>,
}

impl OutboundDialer {
    pub fn new(
        dns_resolver: Arc<DNSResolver>,
        out_ip_v4: Option<IpAddr>,
        out_ip_v6: Option<IpAddr>,
        auto_out_ip: bool,
    ) -> Self {
        Self {
            dns_resolver,
            out_ip_v4,
            out_ip_v6,
            auto_out_ip,
            audit: parking_lot::RwLock::new(None),
        }
    }

    pub fn set_audit(&self, audit: Arc<crate::security::AuditController>) {
        *self.audit.write() = Some(audit);
    }

    async fn resolve_target(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        let audit = self.audit.read().clone();
        if audit
            .as_ref()
            .is_some_and(|a| a.should_block(host, host.parse().ok(), port))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Target blocked before DNS",
            ));
        }
        let mut addresses = self.dns_resolver.resolve(host, port).await?;
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "No target addresses",
            ));
        }
        if let Some(audit) = audit {
            addresses.retain(|address| !audit.should_block(host, Some(address.ip()), port));
            if addresses.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Resolved target blocked by audit",
                ));
            }
        }
        Ok(addresses)
    }

    pub fn dns_resolver(&self) -> &Arc<DNSResolver> {
        &self.dns_resolver
    }

    pub async fn dial(
        &self,
        outbound: &OutboundConfig,
        target_host: &str,
        target_port: u16,
        inbound_local_ip: Option<IpAddr>,
    ) -> std::io::Result<TcpStream> {
        let ntype = outbound.normalized_type();
        match ntype.as_str() {
            "block" => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "Blocked by outbound routing rule",
            )),
            "redirect" => {
                let redirect_host = outbound.target_host().unwrap_or(target_host);
                let redirect_port = match outbound.port {
                    Some(p) if p > 0 => p,
                    _ => target_port,
                };
                self.dial_direct(redirect_host, redirect_port, inbound_local_ip)
                    .await
            }
            "socks" => {
                let proxy_addr = outbound.target_host().unwrap_or("127.0.0.1");
                let proxy_port = outbound.port.unwrap_or(1080);
                let target =
                    Address::SocketAddress(self.resolve_target(target_host, target_port).await?[0]);
                self.dial_socks5(
                    proxy_addr,
                    proxy_port,
                    &target,
                    1,
                    outbound.username.as_deref(),
                    outbound.password.as_deref(),
                )
                .await
                .map(|(stream, _)| stream)
            }
            "http" => {
                let proxy_addr = outbound.target_host().unwrap_or("127.0.0.1");
                let proxy_port = outbound.port.unwrap_or(8080);
                let target = self.resolve_target(target_host, target_port).await?[0];
                self.dial_http_connect(
                    proxy_addr,
                    proxy_port,
                    &target.ip().to_string(),
                    target_port,
                    outbound.username.as_deref(),
                    outbound.password.as_deref(),
                )
                .await
            }
            "direct" => {
                self.dial_direct(target_host, target_port, inbound_local_ip)
                    .await
            }
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Unsupported TCP outbound",
            )),
        }
    }

    pub async fn dial_with_proxy_protocol(
        &self,
        outbound: &OutboundConfig,
        target_host: &str,
        target_port: u16,
        inbound_local_ip: Option<IpAddr>,
        client_addr: Option<SocketAddr>,
        proxy_protocol_version: Option<&str>,
    ) -> std::io::Result<TcpStream> {
        let mut stream = self
            .dial(outbound, target_host, target_port, inbound_local_ip)
            .await?;
        if let (Some(client), Some(proto_ver)) = (client_addr, proxy_protocol_version) {
            let target_addr = stream
                .peer_addr()
                .unwrap_or_else(|_| "127.0.0.1:80".parse().unwrap());
            let header = match proto_ver {
                "v1" => crate::conn::encode_proxy_protocol_v1(client, target_addr),
                "v2" => crate::conn::encode_proxy_protocol_v2(client, target_addr),
                _ => Vec::new(),
            };
            if !header.is_empty() {
                stream.write_all(&header).await?;
            }
        }
        Ok(stream)
    }

    pub async fn dial_direct(
        &self,
        target_host: &str,
        target_port: u16,
        inbound_local_ip: Option<IpAddr>,
    ) -> std::io::Result<TcpStream> {
        let addrs = self.resolve_target(target_host, target_port).await?;
        if addrs.is_empty() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Failed to resolve DNS for {}", target_host),
            ));
        }

        let bind_ip = if self.auto_out_ip {
            inbound_local_ip.or(self.out_ip_v4).or(self.out_ip_v6)
        } else {
            self.out_ip_v4.or(self.out_ip_v6)
        };

        for addr in addrs {
            let socket = match addr {
                SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
                SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
            };

            if let Some(ip) = bind_ip {
                if (ip.is_ipv4() && addr.is_ipv4()) || (ip.is_ipv6() && addr.is_ipv6()) {
                    let _ = socket.bind(SocketAddr::new(ip, 0));
                }
            }

            match socket.connect(addr).await {
                Ok(stream) => {
                    let _ = stream.set_nodelay(true);
                    return Ok(stream);
                }
                Err(_) => continue,
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!(
                "All resolved addresses failed for {}:{}",
                target_host, target_port
            ),
        ))
    }

    pub async fn dial_udp(
        &self,
        target_host: &str,
        target_port: u16,
        inbound_local_ip: Option<IpAddr>,
    ) -> std::io::Result<(UdpSocket, SocketAddr)> {
        let is_unspecified = target_host.is_empty() || target_host == "0.0.0.0" || target_port == 0;
        let target_addr = if is_unspecified {
            SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        } else {
            let addrs = self.resolve_target(target_host, target_port).await?;
            addrs.into_iter().next().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Failed to resolve UDP destination {}", target_host),
                )
            })?
        };

        self.bind_udp(target_addr, inbound_local_ip).await
    }

    async fn bind_udp(
        &self,
        target_addr: SocketAddr,
        inbound_local_ip: Option<IpAddr>,
    ) -> io::Result<(UdpSocket, SocketAddr)> {
        let bind_ip = if self.auto_out_ip {
            inbound_local_ip.or(self.out_ip_v4).or(self.out_ip_v6)
        } else {
            self.out_ip_v4.or(self.out_ip_v6)
        };

        let local_addr = match bind_ip {
            Some(ip) if ip.is_ipv4() && target_addr.is_ipv4() => SocketAddr::new(ip, 0),
            Some(ip) if ip.is_ipv6() && target_addr.is_ipv6() => SocketAddr::new(ip, 0),
            _ => {
                if target_addr.is_ipv4() {
                    "0.0.0.0:0".parse().unwrap()
                } else {
                    "[::]:0".parse().unwrap()
                }
            }
        };

        let socket = UdpSocket::bind(local_addr).await?;
        if target_addr.port() != 0 {
            socket.connect(target_addr).await?;
        }
        Ok((socket, target_addr))
    }

    pub async fn dial_udp_outbound(
        &self,
        outbound: &OutboundConfig,
        target_host: &str,
        target_port: u16,
        inbound_local_ip: Option<IpAddr>,
    ) -> std::io::Result<UdpOutbound> {
        match outbound.normalized_type().as_str() {
            "direct" => {
                let (socket, _) = self
                    .dial_udp(target_host, target_port, inbound_local_ip)
                    .await?;
                let target = match target_host.parse::<IpAddr>() {
                    Ok(ip) => Address::SocketAddress(SocketAddr::new(ip, target_port)),
                    Err(_) if target_host.is_empty() => Address::SocketAddress(SocketAddr::new(
                        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                        0,
                    )),
                    Err(_) => Address::DomainNameAddress(target_host.to_owned(), target_port),
                };
                Ok(UdpOutbound {
                    socket,
                    control: None,
                    target,
                })
            }
            "redirect" => {
                let (socket, _) = self
                    .dial_udp(
                        outbound.target_host().unwrap_or(target_host),
                        outbound.port.filter(|p| *p != 0).unwrap_or(target_port),
                        inbound_local_ip,
                    )
                    .await?;
                let target = match target_host.parse::<IpAddr>() {
                    Ok(ip) => Address::SocketAddress(SocketAddr::new(ip, target_port)),
                    Err(_) => Address::DomainNameAddress(target_host.to_owned(), target_port),
                };
                Ok(UdpOutbound {
                    socket,
                    control: None,
                    target,
                })
            }
            "socks" => {
                let target =
                    Address::SocketAddress(self.resolve_target(target_host, target_port).await?[0]);
                let proxy_host = outbound.target_host().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidInput, "Missing SOCKS5 proxy address")
                })?;
                let (control, relay) = self
                    .dial_socks5(
                        proxy_host,
                        outbound.port.unwrap_or(1080),
                        &Address::SocketAddress("0.0.0.0:0".parse().unwrap()),
                        3,
                        outbound.username.as_deref(),
                        outbound.password.as_deref(),
                    )
                    .await?;
                let relay_host = match &relay {
                    Address::SocketAddress(a) if a.ip().is_unspecified() => {
                        control.peer_addr()?.ip().to_string()
                    }
                    _ => relay.host(),
                };
                if relay.port() == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "SOCKS5 returned UDP port zero",
                    ));
                }
                let relay_addr = self
                    .dns_resolver
                    .resolve(&relay_host, relay.port())
                    .await?
                    .into_iter()
                    .next()
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotFound, "SOCKS5 relay DNS empty")
                    })?;
                let (socket, _) = self.bind_udp(relay_addr, inbound_local_ip).await?;
                Ok(UdpOutbound {
                    socket,
                    control: Some(control),
                    target,
                })
            }
            "block" => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "UDP blocked by routing rule",
            )),
            _ => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Unsupported UDP outbound; direct fallback is disabled",
            )),
        }
    }

    async fn dial_socks5(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target: &Address,
        command: u8,
        username: Option<&str>,
        password: Option<&str>,
    ) -> std::io::Result<(TcpStream, Address)> {
        if let Address::DomainNameAddress(host, _) = target {
            if host.is_empty() || host.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid SOCKS5 target domain",
                ));
            }
        }
        let mut stream = TcpStream::connect((proxy_host, proxy_port)).await?;
        let _ = stream.set_nodelay(true);

        if let (Some(u), Some(p)) = (username, password) {
            if u.is_empty() || p.is_empty() || u.len() > 255 || p.len() > 255 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid SOCKS5 credential length",
                ));
            }

            stream.write_all(&[0x05, 0x01, 0x02]).await?;
            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await?;
            if resp != [0x05, 0x02] {
                return Err(std::io::Error::other("Invalid SOCKS5 version"));
            }
            if resp[1] == 0x02 {
                let mut auth_req = vec![0x01, u.len() as u8];
                auth_req.extend_from_slice(u.as_bytes());
                auth_req.push(p.len() as u8);
                auth_req.extend_from_slice(p.as_bytes());
                stream.write_all(&auth_req).await?;

                let mut auth_resp = [0u8; 2];
                stream.read_exact(&mut auth_resp).await?;
                if auth_resp != [0x01, 0x00] {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::PermissionDenied,
                        "SOCKS5 authentication failed",
                    ));
                }
            }
        } else {
            stream.write_all(&[0x05, 0x01, 0x00]).await?;
            let mut resp = [0u8; 2];
            stream.read_exact(&mut resp).await?;
            if resp[0] != 0x05 || resp[1] != 0x00 {
                return Err(std::io::Error::other("SOCKS5 handshake rejected"));
            }
        }

        let mut req = vec![0x05, command, 0x00];
        target.write_to_buf(&mut req);
        stream.write_all(&req).await?;

        let mut reply_hdr = [0u8; 3];
        stream.read_exact(&mut reply_hdr).await?;
        if reply_hdr != [0x05, 0x00, 0x00] {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!("SOCKS5 server returned code {}", reply_hdr[1]),
            ));
        }

        let bound = Address::read_from(&mut stream)
            .await
            .map_err(io::Error::other)?;
        Ok((stream, bound))
    }

    async fn dial_http_connect(
        &self,
        proxy_host: &str,
        proxy_port: u16,
        target_host: &str,
        target_port: u16,
        username: Option<&str>,
        password: Option<&str>,
    ) -> std::io::Result<TcpStream> {
        let mut stream = TcpStream::connect((proxy_host, proxy_port)).await?;
        let _ = stream.set_nodelay(true);

        let mut req = format!(
            "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\nProxy-Connection: Keep-Alive\r\n",
            target_host, target_port, target_host, target_port
        );

        if let (Some(u), Some(p)) = (username, password) {
            let auth = format!("{}:{}", u, p);
            let encoded = base64_encode(auth.as_bytes());
            req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", encoded));
        }
        req.push_str("\r\n");

        stream.write_all(req.as_bytes()).await?;

        let mut resp_buf = [0u8; 1024];
        let n = stream.read(&mut resp_buf).await?;
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);

        if !resp_str.starts_with("HTTP/1.1 200") && !resp_str.starts_with("HTTP/1.0 200") {
            return Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionRefused,
                format!(
                    "HTTP Proxy CONNECT rejected: {}",
                    resp_str.lines().next().unwrap_or("")
                ),
            ));
        }

        Ok(stream)
    }
}

fn base64_encode(input: &[u8]) -> String {
    const CHARSET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as usize;
        let b1 = if i + 1 < input.len() {
            input[i + 1] as usize
        } else {
            0
        };
        let b2 = if i + 2 < input.len() {
            input[i + 2] as usize
        } else {
            0
        };

        out.push(CHARSET[b0 >> 2] as char);
        out.push(CHARSET[((b0 & 3) << 4) | (b1 >> 4)] as char);
        if i + 1 < input.len() {
            out.push(CHARSET[((b1 & 15) << 2) | (b2 >> 6)] as char);
        } else {
            out.push('=');
        }
        if i + 2 < input.len() {
            out.push(CHARSET[b2 & 63] as char);
        } else {
            out.push('=');
        }
        i += 3;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn dns_target_is_audited_and_whitelisted_domain_preserves_policy() {
        let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let resolver = Arc::new(DNSResolver::new(
            "ipv4_only",
            1,
            Some(&format!("udp://{}", dns.local_addr().unwrap())),
        ));
        let dns_task = tokio::spawn(async move {
            let mut query = [0; 512];
            let (n, peer) = dns.recv_from(&mut query).await.unwrap();
            let mut response = query[..n].to_vec();
            response[2] = 0x81;
            response[3] = 0x80;
            response[6] = 0;
            response[7] = 1;
            response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 127, 0, 0, 1]);
            dns.send_to(&response, peer).await.unwrap();
        });
        let dialer = OutboundDialer::new(resolver, None, None, false);
        let audit = Arc::new(crate::security::AuditController::new_with_options(
            "",
            "",
            Arc::new(crate::geo::GeoEngine::default()),
            vec![],
            true,
            false,
        ));
        assert!(!audit.should_block("private.test", None, 80));
        dialer.set_audit(audit.clone());
        assert_eq!(
            dialer
                .dial_direct("private.test", 80, None)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(
            dialer
                .dial_udp("private.test", 80, None)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        dns_task.await.unwrap();
        audit.reload_white_list("full:private.test");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = dialer
            .dial_direct("private.test", listener.local_addr().unwrap().port(), None)
            .await
            .unwrap();
        assert_eq!(stream.peer_addr().unwrap(), listener.local_addr().unwrap());
    }
}
