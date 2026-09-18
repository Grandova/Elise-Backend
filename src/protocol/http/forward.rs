use crate::conn::BoxedStream;
use crate::panel::types::User;
use crate::protocol::http::auth::RESP_502_BAD_GATEWAY;
use std::io;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tracing::{info, warn};

/// Check if a header name is a hop-by-hop header that must be stripped by proxies.
pub fn is_hop_by_hop_header(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "proxy-authorization"
            | "proxy-connection"
            | "proxy-authenticate"
            | "connection"
            | "keep-alive"
            | "upgrade"
            | "trailer"
            | "te"
    )
}

/// Parses target host, port and origin-form path from an absolute-form or origin-form request-target.
pub fn parse_target_and_path<'a>(
    target: &'a str,
    host_header: Option<&'a str>,
) -> Option<(String, u16, String)> {
    let trimmed = target.trim();
    if let Some(stripped) = trimmed.strip_prefix("http://") {
        let (authority, path) = match stripped.find('/') {
            Some(idx) => (&stripped[..idx], &stripped[idx..]),
            None => (stripped, "/"),
        };
        let (host, port) = if let Some(colon_idx) = authority.rfind(':') {
            let h = &authority[..colon_idx];
            let p = authority[colon_idx + 1..].parse::<u16>().ok()?;
            (h.to_string(), p)
        } else {
            (authority.to_string(), 80)
        };
        Some((host, port, path.to_string()))
    } else if let Some(h_hdr) = host_header {
        let (host, port) = if let Some(colon_idx) = h_hdr.rfind(':') {
            let h = &h_hdr[..colon_idx];
            let p = h_hdr[colon_idx + 1..].parse::<u16>().unwrap_or(80);
            (h.to_string(), p)
        } else {
            (h_hdr.to_string(), 80)
        };
        let path = if trimmed.starts_with('/') {
            trimmed.to_string()
        } else {
            format!("/{trimmed}")
        };
        Some((host, port, path))
    } else {
        None
    }
}

/// Handles standard HTTP forward proxy requests (e.g. GET http://example.com/path HTTP/1.1)
pub async fn handle_forward(
    mut client_stream: BoxedStream,
    method: &str,
    target: &str,
    version: &str,
    headers: &[(&str, &str)],
    leftover: &[u8],
    user: &User,
    conn_id: u64,
) -> io::Result<(u64, u64)> {
    let host_header = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("host"))
        .map(|(_, v)| *v);

    let (host, port, path) = match parse_target_and_path(target, host_header) {
        Some(res) => res,
        None => {
            warn!(
                "[HTTP FORWARD] conn={} user_id={} invalid target or missing host: {}",
                conn_id, user.id, target
            );
            let _ = client_stream.write_all(RESP_502_BAD_GATEWAY).await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid HTTP target URL",
            ));
        }
    };

    let target_addr = format!("{}:{}", host, port);
    let mut target_stream = match TcpStream::connect(&target_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!(
                "[HTTP FORWARD] conn={} user_id={} failed to connect to {}: {}",
                conn_id, user.id, target_addr, e
            );
            let _ = client_stream.write_all(RESP_502_BAD_GATEWAY).await;
            return Err(e);
        }
    };
    let _ = target_stream.set_nodelay(true);

    // Reconstruct HTTP request for target:
    // 1. Request-line: METHOD origin-form HTTP/version
    let mut rewritten_req = format!("{} {} {}\r\n", method, path, version);

    // 2. Add Host header if not already present
    let mut has_host = false;
    for (k, v) in headers {
        if is_hop_by_hop_header(k) {
            continue;
        }
        if k.eq_ignore_ascii_case("host") {
            has_host = true;
            rewritten_req.push_str(&format!("{}: {}\r\n", k, v));
        } else {
            rewritten_req.push_str(&format!("{}: {}\r\n", k, v));
        }
    }
    if !has_host {
        rewritten_req.push_str(&format!("Host: {}\r\n", target_addr));
    }
    rewritten_req.push_str("Connection: close\r\n\r\n");

    // Send rewritten headers to target
    target_stream.write_all(rewritten_req.as_bytes()).await?;
    let mut initial_up = rewritten_req.len() as u64;

    // Send leftover request body data if any
    if !leftover.is_empty() {
        target_stream.write_all(leftover).await?;
        initial_up += leftover.len() as u64;
    }
    target_stream.flush().await?;

    info!(
        "[HTTP FORWARD] conn={} user_id={} {} {} -> {}",
        conn_id, user.id, method, target, target_addr
    );

    // Stream response back to client and rest of body from client to target
    let (mut client_read, mut client_write) = tokio::io::split(client_stream);
    let (mut target_read, mut target_write) = target_stream.into_split();

    let client_to_target = async {
        tokio::io::copy(&mut client_read, &mut target_write).await
    };
    let target_to_client = async {
        tokio::io::copy(&mut target_read, &mut client_write).await
    };

    let (up_res, down_res) = tokio::join!(client_to_target, target_to_client);
    let up = up_res.unwrap_or(0) + initial_up;
    let down = down_res.unwrap_or(0);

    info!(
        "[HTTP FORWARD] conn={} user_id={} target={} finished (up={} bytes, down={} bytes)",
        conn_id, user.id, target_addr, up, down
    );

    Ok((up, down))
}
