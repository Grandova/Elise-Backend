pub fn sniff_domain(buffer: &[u8]) -> Option<(String, &'static str)> {
    if buffer.is_empty() {
        return None;
    }

    // 1. Check TLS ClientHello (0x16 0x03 0x01/0x03)
    if buffer[0] == 0x16 && buffer.len() > 43 {
        if let Some(sni) = parse_tls_sni(buffer) {
            return Some((sni, "tls"));
        }
    }

    // 2. Check HTTP 1.x methods: GET, POST, HEAD, CONNECT, OPTIONS, PUT, DELETE
    let prefixes: &[&[u8]] = &[
        b"GET ",
        b"POST ",
        b"HEAD ",
        b"CONNECT ",
        b"OPTIONS ",
        b"PUT ",
        b"DELETE ",
    ];
    if prefixes.iter().any(|p| buffer.starts_with(p)) {
        if let Some(host) = parse_http_host(buffer) {
            return Some((host, "http"));
        }
    }

    // 3. Check QUIC Initial Packet (Long header bit 0x80 set)
    if (buffer[0] & 0x80) != 0 && buffer.len() > 40 {
        if let Some(sni) = parse_quic_sni(buffer) {
            return Some((sni, "quic"));
        }
    }

    None
}

pub fn parse_tls_sni(buf: &[u8]) -> Option<String> {
    // Record header (5 bytes): Type (1), Version (2), Length (2)
    if buf.len() < 5 || buf[0] != 0x16 {
        return None;
    }
    // Handshake header (4 bytes): Type (1) == 0x01 (ClientHello), Length (3)
    let pos = 5;
    if pos >= buf.len() || buf[pos] != 0x01 {
        return None;
    }
    parse_client_hello_body(&buf[pos..])
}

fn parse_client_hello_body(buf: &[u8]) -> Option<String> {
    if buf.len() < 4 + 2 + 32 {
        return None;
    }
    let mut pos = 4; // Skip type (1) + length (3)
    pos += 2 + 32; // Skip client version (2) + random (32)

    // Session ID
    if pos >= buf.len() {
        return None;
    }
    let session_id_len = buf[pos] as usize;
    pos += 1 + session_id_len;

    // Cipher Suites
    if pos + 2 > buf.len() {
        return None;
    }
    let cipher_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2 + cipher_len;

    // Compression methods
    if pos >= buf.len() {
        return None;
    }
    let comp_len = buf[pos] as usize;
    pos += 1 + comp_len;

    // Extensions length
    if pos + 2 > buf.len() {
        return None;
    }
    let ext_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
    pos += 2;

    let end_ext = (pos + ext_len).min(buf.len());
    while pos + 4 <= end_ext {
        let ext_type = u16::from_be_bytes([buf[pos], buf[pos + 1]]);
        let ext_size = u16::from_be_bytes([buf[pos + 2], buf[pos + 3]]) as usize;
        pos += 4;

        if ext_type == 0x0000 {
            // Server Name Indication (SNI)
            if pos + 2 <= end_ext {
                let list_len = u16::from_be_bytes([buf[pos], buf[pos + 1]]) as usize;
                let mut sni_pos = pos + 2;
                let list_end = (sni_pos + list_len).min(end_ext);
                while sni_pos + 3 <= list_end {
                    let name_type = buf[sni_pos];
                    let name_len =
                        u16::from_be_bytes([buf[sni_pos + 1], buf[sni_pos + 2]]) as usize;
                    sni_pos += 3;
                    if name_type == 0x00 && sni_pos + name_len <= list_end {
                        if let Ok(sni_str) = std::str::from_utf8(&buf[sni_pos..sni_pos + name_len])
                        {
                            return Some(sni_str.to_string());
                        }
                    }
                    sni_pos += name_len;
                }
            }
        }
        pos += ext_size;
    }

    None
}

fn parse_http_host(buf: &[u8]) -> Option<String> {
    if let Ok(text) = std::str::from_utf8(buf) {
        for line in text.lines() {
            let line = line.trim();
            if let Some(host_val) = line.strip_prefix("Host:") {
                let host = host_val.trim();
                let clean_host = host.split(':').next().unwrap_or(host);
                return Some(clean_host.to_string());
            }
        }
    }
    None
}

fn parse_quic_sni(buf: &[u8]) -> Option<String> {
    // Quick search for TLS ClientHello inside QUIC initial packet
    // TLS ClientHello header pattern: 0x01, length[3], 0x03, 0x03
    for i in 0..buf.len().saturating_sub(40) {
        if buf[i] == 0x01 && buf.get(i + 4) == Some(&0x03) && buf.get(i + 5) == Some(&0x03) {
            if let Some(sni) = parse_client_hello_body(&buf[i..]) {
                return Some(sni);
            }
        }
    }
    None
}

use crate::conn::proxy_protocol::PrefixedStream;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};

pub async fn sniff_async_stream<S>(
    mut stream: S,
    target_ip: Option<std::net::IpAddr>,
    sniff_enabled: bool,
) -> (Option<String>, PrefixedStream<S>)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !sniff_enabled || target_ip.is_none() {
        return (None, PrefixedStream::new(stream, None));
    }
    let mut buf = [0u8; 1024];
    match tokio::time::timeout(std::time::Duration::from_millis(150), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let prefix = buf[..n].to_vec();
            let sniffed = sniff_domain(&prefix).map(|(s, _)| s);
            (sniffed, PrefixedStream::new(stream, Some(prefix)))
        }
        _ => (None, PrefixedStream::new(stream, None)),
    }
}

pub async fn sniff_and_detect_stream<S>(
    mut stream: S,
    target_ip: Option<std::net::IpAddr>,
    sniff_enabled: bool,
    detect_packet: bool,
    audit: Option<&crate::security::AuditController>,
) -> std::io::Result<(Option<String>, PrefixedStream<S>)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    if !sniff_enabled && !detect_packet {
        return Ok((None, PrefixedStream::new(stream, None)));
    }
    let mut buf = [0u8; 1024];
    match tokio::time::timeout(std::time::Duration::from_millis(150), stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 => {
            let prefix = buf[..n].to_vec();
            if detect_packet {
                if let Some(aud) = audit {
                    if aud.should_block_payload(&prefix) {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "Blocked by payload audit rule",
                        ));
                    }
                }
            }
            let sniffed = if sniff_enabled && target_ip.is_some() {
                sniff_domain(&prefix).map(|(s, _)| s)
            } else {
                None
            };
            Ok((sniffed, PrefixedStream::new(stream, Some(prefix))))
        }
        _ => Ok((None, PrefixedStream::new(stream, None))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_http_sniffer() {
        let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let res = sniff_domain(req);
        assert_eq!(res, Some(("example.com".to_string(), "http")));
    }

    #[tokio::test]
    async fn test_sniff_async_stream() {
        use std::net::{IpAddr, Ipv4Addr};
        let (mut client, server) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            tokio::io::AsyncWriteExt::write_all(
                &mut client,
                b"GET / HTTP/1.1\r\nHost: api.ip.sb\r\n\r\n",
            )
            .await
            .unwrap();
        });

        let target_ip = Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        let (sniffed, mut stream) = sniff_async_stream(server, target_ip, true).await;
        assert_eq!(sniffed, Some("api.ip.sb".to_string()));

        let mut read_back = vec![0u8; 32];
        let n = tokio::io::AsyncReadExt::read(&mut stream, &mut read_back)
            .await
            .unwrap();
        assert!(read_back[..n].starts_with(b"GET / HTTP/1.1"));
    }
}
