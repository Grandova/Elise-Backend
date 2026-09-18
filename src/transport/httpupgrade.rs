use crate::conn::{BoxedStream, PrefixedStream};
use crate::transport::types::HttpUpgradeTransportConfig;
use base64::Engine;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_HTTP_UPGRADE_HEADER: usize = 12288;
const DOUBLE_CRLF: &[u8] = b"\r\n\r\n";

/// Implements Xray-compatible HttpUpgrade transport.
/// Performs HTTP/1.1 Upgrade handshake, validates path and host, responds with 101 Switching Protocols,
/// and returns the raw stream with any remaining unconsumed bytes prefixed.
pub async fn apply_httpupgrade_transport(
    mut stream: BoxedStream,
    config: &HttpUpgradeTransportConfig,
) -> io::Result<BoxedStream> {
    let mut header_buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    let mut header_end = None;

    while header_buf.len() < MAX_HTTP_UPGRADE_HEADER {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before HttpUpgrade request completed",
            ));
        }
        header_buf.extend_from_slice(&chunk[..n]);

        if let Some(pos) = find_subslice(&header_buf, DOUBLE_CRLF) {
            header_end = Some(pos);
            break;
        }
    }

    let end_idx = header_end.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "HttpUpgrade request headers exceeded max length (12288 bytes)",
        )
    })?;

    let header_str = String::from_utf8_lossy(&header_buf[..end_idx]);
    let mut lines = header_str.lines();

    // 1. Request line: GET /path HTTP/1.1
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty HttpUpgrade request"))?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 || parts[0].to_uppercase() != "GET" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid HttpUpgrade request line: {request_line}"),
        ));
    }
    let req_path = parts[1];

    if req_path != config.path {
        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .await;
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "HttpUpgrade path mismatch: expected '{}', got '{req_path}'",
                config.path
            ),
        ));
    }

    // Parse headers
    let mut connection_upgrade = false;
    let mut upgrade_websocket = false;
    let mut host_header = None;
    let mut early_data = Vec::new();

    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();

            if key == "connection" && val.to_ascii_lowercase().contains("upgrade") {
                connection_upgrade = true;
            } else if key == "upgrade" && val.to_ascii_lowercase() == "websocket" {
                upgrade_websocket = true;
            } else if key == "host" {
                host_header = Some(val.to_string());
            } else if key == "sec-websocket-protocol" {
                if let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(val.as_bytes())
                    .or_else(|_| base64::engine::general_purpose::STANDARD.decode(val.as_bytes()))
                {
                    if bytes.len() <= (config.max_early_data as usize).max(8192) {
                        early_data = bytes;
                    }
                }
            }
        }
    }

    if !connection_upgrade || !upgrade_websocket {
        let _ = stream
            .write_all(
                b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "HttpUpgrade missing Connection: Upgrade or Upgrade: websocket header",
        ));
    }

    if let Some(ref expected_host) = config.host {
        let clean_req_host = host_header.as_deref().map(|s| s.split(':').next().unwrap_or(s));
        let clean_expected = expected_host.split(':').next().unwrap_or(expected_host);
        if clean_req_host != Some(clean_expected) {
            let _ = stream
                .write_all(
                    b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!(
                    "HttpUpgrade host mismatch: expected '{expected_host}', got '{:?}'",
                    host_header
                ),
            ));
        }
    }

    // Send 101 Switching Protocols response
    let response =
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
    stream.write_all(response).await?;

    // Any remaining bytes after \r\n\r\n
    let unconsumed = header_buf[end_idx + 4..].to_vec();
    let prefix = if !early_data.is_empty() {
        let mut p = early_data;
        p.extend_from_slice(&unconsumed);
        Some(p)
    } else if !unconsumed.is_empty() {
        Some(unconsumed)
    } else {
        None
    };

    if let Some(p) = prefix {
        Ok(Box::new(PrefixedStream::new(stream, Some(p))))
    } else {
        Ok(stream)
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
