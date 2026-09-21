use crate::conn::BoxedStream;
use crate::panel::types::User;
use crate::protocol::http::auth::RESP_502_BAD_GATEWAY;
use crate::protocol::InboundContext;
use std::io;
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tracing::warn;

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

pub async fn handle_forward(
    mut client_stream: BoxedStream,
    method: &str,
    target: &str,
    version: &str,
    headers: &[(&str, &str)],
    leftover: &[u8],
    user: &User,
    conn_id: u64,
    remote_addr: SocketAddr,
    ctx: &InboundContext,
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

    let mut rewritten_req = format!("{} {} {}\r\n", method, path, version);

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

    let mut prefix = rewritten_req.into_bytes();
    prefix.extend_from_slice(leftover);
    crate::protocol::http::connect::relay(
        client_stream,
        &host,
        port,
        prefix,
        user,
        remote_addr,
        ctx,
        false,
    )
    .await
}
