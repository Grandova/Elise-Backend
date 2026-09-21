use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

const V2_SIGNATURE: &[u8; 12] = b"\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyProtocolMode {
    Off,
    Auto,
    Strict,
}

impl ProxyProtocolMode {
    pub fn from_str_opt(val: &str) -> Self {
        match val.to_ascii_lowercase().as_str() {
            "strict" | "force" | "1" | "true" => Self::Strict,
            "auto" | "detect" => Self::Auto,
            _ => Self::Off,
        }
    }
}

pub struct PrefixedStream<S> {
    inner: S,
    prefix: Option<Vec<u8>>,
    pos: usize,
}

impl<S> PrefixedStream<S> {
    pub fn new(inner: S, prefix: Option<Vec<u8>>) -> Self {
        Self {
            inner,
            prefix,
            pos: 0,
        }
    }

    pub fn into_inner(self) -> (S, Option<Vec<u8>>) {
        (self.inner, self.prefix)
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if let Some(prefix) = &self.prefix {
            let p_len = prefix.len();
            if self.pos < p_len {
                let to_copy = std::cmp::min(p_len - self.pos, buf.remaining());
                buf.put_slice(&prefix[self.pos..self.pos + to_copy]);
                self.pos += to_copy;
                if self.pos >= p_len {
                    self.prefix = None;
                }
                return Poll::Ready(Ok(()));
            }
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConnectionMeta {
    pub transport_peer_addr: SocketAddr,
    pub client_addr: SocketAddr,
    pub proxy_destination_addr: Option<SocketAddr>,
    pub proxy_protocol_version: Option<u8>,
}

impl ConnectionMeta {
    pub fn new(peer_addr: SocketAddr) -> Self {
        Self {
            transport_peer_addr: peer_addr,
            client_addr: peer_addr,
            proxy_destination_addr: None,
            proxy_protocol_version: None,
        }
    }
}

pub async fn read_proxy_protocol_with_meta<S: AsyncRead + AsyncWrite + Unpin>(
    mut stream: S,
    peer_addr: SocketAddr,
    mode: ProxyProtocolMode,
    trusted_proxies: Option<&[ipnet::IpNet]>,
) -> io::Result<(ConnectionMeta, PrefixedStream<S>)> {
    let mut meta = ConnectionMeta::new(peer_addr);
    if mode == ProxyProtocolMode::Off {
        return Ok((meta, PrefixedStream::new(stream, None)));
    }

    let is_trusted = match trusted_proxies {
        Some(trusted) => trusted.iter().any(|net| net.contains(&peer_addr.ip())),
        None => true,
    };

    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];

    let n = stream.read(&mut chunk).await?;
    if n == 0 {
        return Ok((meta, PrefixedStream::new(stream, None)));
    }
    buf.extend_from_slice(&chunk[..n]);

    if buf.len() >= 12 && &buf[..12] == V2_SIGNATURE {
        while buf.len() < 16 {
            let mut b = [0u8; 1];
            stream.read_exact(&mut b).await?;
            buf.push(b[0]);
        }

        let version_cmd = buf[12];
        let fam_trans = buf[13];
        let payload_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;

        if (version_cmd >> 4) != 2 {
            if mode == ProxyProtocolMode::Strict {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Unsupported PROXY protocol version in v2 signature",
                ));
            }
            return Ok((meta, PrefixedStream::new(stream, Some(buf))));
        }

        let total_v2_len = 16 + payload_len;
        while buf.len() < total_v2_len {
            let needed = total_v2_len - buf.len();
            let mut temp = vec![0u8; needed];
            stream.read_exact(&mut temp).await?;
            buf.extend_from_slice(&temp);
        }

        let prefix = if buf.len() > total_v2_len {
            Some(buf[total_v2_len..].to_vec())
        } else {
            None
        };

        let cmd = version_cmd & 0x0F;
        if cmd == 0x01 {
            let fam = (fam_trans >> 4) & 0x0F;
            if fam == 0x01 && payload_len >= 12 {
                let src_ip = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
                let dst_ip = Ipv4Addr::new(buf[20], buf[21], buf[22], buf[23]);
                let src_port = u16::from_be_bytes([buf[24], buf[25]]);
                let dst_port = u16::from_be_bytes([buf[26], buf[27]]);
                let client = SocketAddr::new(IpAddr::V4(src_ip), src_port);
                let dest = SocketAddr::new(IpAddr::V4(dst_ip), dst_port);

                if is_trusted {
                    meta.client_addr = client;
                    meta.proxy_destination_addr = Some(dest);
                    meta.proxy_protocol_version = Some(2);
                } else if mode == ProxyProtocolMode::Strict {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("PROXY v2 from untrusted peer {} rejected", peer_addr),
                    ));
                }
                return Ok((meta, PrefixedStream::new(stream, prefix)));
            } else if fam == 0x02 && payload_len >= 36 {
                let mut s_octets = [0u8; 16];
                s_octets.copy_from_slice(&buf[16..32]);
                let src_ip = Ipv6Addr::from(s_octets);

                let mut d_octets = [0u8; 16];
                d_octets.copy_from_slice(&buf[32..48]);
                let dst_ip = Ipv6Addr::from(d_octets);

                let src_port = u16::from_be_bytes([buf[48], buf[49]]);
                let dst_port = u16::from_be_bytes([buf[50], buf[51]]);
                let client = SocketAddr::new(IpAddr::V6(src_ip), src_port);
                let dest = SocketAddr::new(IpAddr::V6(dst_ip), dst_port);

                if is_trusted {
                    meta.client_addr = client;
                    meta.proxy_destination_addr = Some(dest);
                    meta.proxy_protocol_version = Some(2);
                } else if mode == ProxyProtocolMode::Strict {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("PROXY v2 from untrusted peer {} rejected", peer_addr),
                    ));
                }
                return Ok((meta, PrefixedStream::new(stream, prefix)));
            }
        }

        meta.proxy_protocol_version = Some(2);
        return Ok((meta, PrefixedStream::new(stream, prefix)));
    }

    if buf.len() >= 6 && &buf[..6] == b"PROXY " {
        while !buf.windows(2).any(|w| w == b"\r\n") && buf.len() < 108 {
            let mut byte = [0u8; 1];
            if stream.read_exact(&mut byte).await.is_err() {
                break;
            }
            buf.push(byte[0]);
        }

        if let Some(pos) = buf.windows(2).position(|w| w == b"\r\n") {
            let line_bytes = &buf[..pos];
            let prefix = if buf.len() > pos + 2 {
                Some(buf[pos + 2..].to_vec())
            } else {
                None
            };

            if let Ok(line_str) = std::str::from_utf8(line_bytes) {
                let parts: Vec<&str> = line_str.split_whitespace().collect();
                if parts.len() >= 6 && (parts[1] == "TCP4" || parts[1] == "TCP6") {
                    if let (Ok(src_ip), Ok(dst_ip), Ok(src_port), Ok(dst_port)) = (
                        parts[2].parse::<IpAddr>(),
                        parts[3].parse::<IpAddr>(),
                        parts[4].parse::<u16>(),
                        parts[5].parse::<u16>(),
                    ) {
                        let client = SocketAddr::new(src_ip, src_port);
                        let dest = SocketAddr::new(dst_ip, dst_port);

                        if is_trusted {
                            meta.client_addr = client;
                            meta.proxy_destination_addr = Some(dest);
                            meta.proxy_protocol_version = Some(1);
                        } else if mode == ProxyProtocolMode::Strict {
                            return Err(io::Error::new(
                                io::ErrorKind::PermissionDenied,
                                format!("PROXY v1 from untrusted peer {} rejected", peer_addr),
                            ));
                        }
                        return Ok((meta, PrefixedStream::new(stream, prefix)));
                    }
                } else if parts.len() >= 2 && parts[1] == "UNKNOWN" {
                    meta.proxy_protocol_version = Some(1);
                    return Ok((meta, PrefixedStream::new(stream, prefix)));
                }
            }

            if mode == ProxyProtocolMode::Strict {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Malformed PROXY protocol v1 header",
                ));
            }
        }
    }

    if mode == ProxyProtocolMode::Strict {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PROXY protocol header required but not found",
        ));
    }

    Ok((meta, PrefixedStream::new(stream, Some(buf))))
}

pub async fn read_proxy_protocol<S: AsyncRead + AsyncWrite + Unpin>(
    stream: S,
    mode: ProxyProtocolMode,
) -> io::Result<(Option<SocketAddr>, PrefixedStream<S>)> {
    let dummy_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let (meta, stream) = read_proxy_protocol_with_meta(stream, dummy_addr, mode, None).await?;
    let src = if meta.proxy_protocol_version.is_some() && meta.client_addr != dummy_addr {
        Some(meta.client_addr)
    } else {
        None
    };
    Ok((src, stream))
}

pub fn encode_proxy_protocol_v1(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => format!(
            "PROXY TCP4 {} {} {} {}\r\n",
            s.ip(),
            d.ip(),
            s.port(),
            d.port()
        )
        .into_bytes(),
        (SocketAddr::V6(s), SocketAddr::V6(d)) => format!(
            "PROXY TCP6 {} {} {} {}\r\n",
            s.ip(),
            d.ip(),
            s.port(),
            d.port()
        )
        .into_bytes(),
        _ => b"PROXY UNKNOWN\r\n".to_vec(),
    }
}

pub fn encode_proxy_protocol_v2(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(32);
    buf.extend_from_slice(V2_SIGNATURE);

    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            buf.push(0x21);
            buf.push(0x11);
            buf.extend_from_slice(&12u16.to_be_bytes());
            buf.extend_from_slice(&s.ip().octets());
            buf.extend_from_slice(&d.ip().octets());
            buf.extend_from_slice(&s.port().to_be_bytes());
            buf.extend_from_slice(&d.port().to_be_bytes());
        }
        (SocketAddr::V6(s), SocketAddr::V6(d)) => {
            buf.push(0x21);
            buf.push(0x21);
            buf.extend_from_slice(&36u16.to_be_bytes());
            buf.extend_from_slice(&s.ip().octets());
            buf.extend_from_slice(&d.ip().octets());
            buf.extend_from_slice(&s.port().to_be_bytes());
            buf.extend_from_slice(&d.port().to_be_bytes());
        }
        _ => {
            buf.push(0x20);
            buf.push(0x00);
            buf.extend_from_slice(&0u16.to_be_bytes());
        }
    }

    buf
}

pub fn parse_proxy_protocol_datagram(
    data: &[u8],
    mode: ProxyProtocolMode,
) -> io::Result<(Option<SocketAddr>, &[u8])> {
    if mode == ProxyProtocolMode::Off || data.len() < 16 {
        return Ok((None, data));
    }

    if data.starts_with(V2_SIGNATURE) {
        let version_cmd = data[12];
        let fam_trans = data[13];
        let payload_len = u16::from_be_bytes([data[14], data[15]]) as usize;
        let total_header_len = 16 + payload_len;

        if (version_cmd >> 4) != 2 {
            if mode == ProxyProtocolMode::Strict {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Invalid PROXY v2 version in datagram",
                ));
            }
            return Ok((None, data));
        }

        if data.len() < total_header_len {
            if mode == ProxyProtocolMode::Strict {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "Truncated PROXY v2 datagram header",
                ));
            }
            return Ok((None, data));
        }

        let cmd = version_cmd & 0x0F;
        let payload = &data[16..total_header_len];
        let rest = &data[total_header_len..];

        if cmd == 0x01 {
            let fam = (fam_trans >> 4) & 0x0F;
            if fam == 0x01 && payload.len() >= 12 {
                let src_ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
                let src_port = u16::from_be_bytes([payload[8], payload[9]]);
                return Ok((Some(SocketAddr::new(IpAddr::V4(src_ip), src_port)), rest));
            } else if fam == 0x02 && payload.len() >= 36 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&payload[0..16]);
                let src_ip = Ipv6Addr::from(octets);
                let src_port = u16::from_be_bytes([payload[32], payload[33]]);
                return Ok((Some(SocketAddr::new(IpAddr::V6(src_ip), src_port)), rest));
            }
        }
        return Ok((None, rest));
    }

    if mode == ProxyProtocolMode::Strict {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PROXY header required for datagram in strict mode",
        ));
    }

    Ok((None, data))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_proxy_v1_parse() {
        let v1_data = b"PROXY TCP4 192.168.1.100 10.0.0.1 54321 443\r\nPayload";
        let cursor = Cursor::new(v1_data.to_vec());
        let (src, mut stream) = read_proxy_protocol(cursor, ProxyProtocolMode::Strict)
            .await
            .unwrap();

        assert_eq!(src, Some("192.168.1.100:54321".parse().unwrap()));
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert_eq!(&rest, b"Payload");
    }

    #[tokio::test]
    async fn test_proxy_v2_parse() {
        let src_addr: SocketAddr = "1.2.3.4:12345".parse().unwrap();
        let dst_addr: SocketAddr = "5.6.7.8:80".parse().unwrap();
        let mut v2_bytes = encode_proxy_protocol_v2(src_addr, dst_addr);
        v2_bytes.extend_from_slice(b"Hello Elise");

        let cursor = Cursor::new(v2_bytes);
        let (src, mut stream) = read_proxy_protocol(cursor, ProxyProtocolMode::Auto)
            .await
            .unwrap();

        assert_eq!(src, Some(src_addr));
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert_eq!(&rest, b"Hello Elise");
    }

    #[tokio::test]
    async fn test_auto_detect_fallback() {
        let direct_data = b"Direct TLS ClientHello Non-Proxy Data";
        let cursor = Cursor::new(direct_data.to_vec());
        let (src, mut stream) = read_proxy_protocol(cursor, ProxyProtocolMode::Auto)
            .await
            .unwrap();

        assert_eq!(src, None);
        let mut rest = Vec::new();
        stream.read_to_end(&mut rest).await.unwrap();
        assert_eq!(&rest, direct_data);
    }

    #[tokio::test]
    async fn test_meta_and_sticky_socks5_greeting_v1() {
        let peer_addr: SocketAddr = "127.0.0.1:9999".parse().unwrap();
        let client_addr: SocketAddr = "198.51.100.1:12345".parse().unwrap();
        let dst_addr: SocketAddr = "203.0.113.2:443".parse().unwrap();

        let mut data = encode_proxy_protocol_v1(client_addr, dst_addr);

        data.extend_from_slice(&[0x05, 0x01, 0x00]);

        let (meta, mut stream) = read_proxy_protocol_with_meta(
            Cursor::new(data),
            peer_addr,
            ProxyProtocolMode::Auto,
            None,
        )
        .await
        .unwrap();

        assert_eq!(meta.client_addr, client_addr);
        assert_eq!(meta.transport_peer_addr, peer_addr);
        assert_eq!(meta.proxy_protocol_version, Some(1));
        assert_eq!(meta.proxy_destination_addr, Some(dst_addr));

        let mut socks_greeting = [0u8; 3];
        stream.read_exact(&mut socks_greeting).await.unwrap();
        assert_eq!(&socks_greeting, &[0x05, 0x01, 0x00]);
    }

    #[tokio::test]
    async fn test_meta_and_sticky_socks5_greeting_v2() {
        let peer_addr: SocketAddr = "10.0.0.5:8888".parse().unwrap();
        let client_addr: SocketAddr = "192.0.2.77:54321".parse().unwrap();
        let dst_addr: SocketAddr = "10.0.0.1:1080".parse().unwrap();

        let mut data = encode_proxy_protocol_v2(client_addr, dst_addr);

        data.extend_from_slice(&[0x05, 0x02, 0x00, 0x02]);

        let (meta, mut stream) = read_proxy_protocol_with_meta(
            Cursor::new(data),
            peer_addr,
            ProxyProtocolMode::Auto,
            None,
        )
        .await
        .unwrap();

        assert_eq!(meta.client_addr, client_addr);
        assert_eq!(meta.transport_peer_addr, peer_addr);
        assert_eq!(meta.proxy_protocol_version, Some(2));
        assert_eq!(meta.proxy_destination_addr, Some(dst_addr));

        let mut socks_greeting = [0u8; 4];
        stream.read_exact(&mut socks_greeting).await.unwrap();
        assert_eq!(&socks_greeting, &[0x05, 0x02, 0x00, 0x02]);
    }

    #[tokio::test]
    async fn test_trusted_proxies_filter() {
        use ipnet::IpNet;
        let trusted_net: IpNet = "10.0.0.0/8".parse().unwrap();
        let trusted_list = vec![trusted_net];

        let trusted_peer: SocketAddr = "10.1.2.3:12345".parse().unwrap();
        let untrusted_peer: SocketAddr = "192.168.1.10:12345".parse().unwrap();
        let claimed_client: SocketAddr = "1.1.1.1:53".parse().unwrap();
        let dest: SocketAddr = "2.2.2.2:443".parse().unwrap();

        let data1 = encode_proxy_protocol_v1(claimed_client, dest);
        let (meta1, _) = read_proxy_protocol_with_meta(
            Cursor::new(data1),
            trusted_peer,
            ProxyProtocolMode::Auto,
            Some(&trusted_list),
        )
        .await
        .unwrap();
        assert_eq!(meta1.client_addr, claimed_client);

        let data2 = encode_proxy_protocol_v1(claimed_client, dest);
        let (meta2, _) = read_proxy_protocol_with_meta(
            Cursor::new(data2),
            untrusted_peer,
            ProxyProtocolMode::Auto,
            Some(&trusted_list),
        )
        .await
        .unwrap();
        assert_eq!(meta2.client_addr, untrusted_peer);

        let data3 = encode_proxy_protocol_v1(claimed_client, dest);
        let res3 = read_proxy_protocol_with_meta(
            Cursor::new(data3),
            untrusted_peer,
            ProxyProtocolMode::Strict,
            Some(&trusted_list),
        )
        .await;
        assert!(res3.is_err());
    }
}
