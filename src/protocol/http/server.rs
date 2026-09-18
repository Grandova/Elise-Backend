use crate::conn::{bind_tcp_listener, BoxedStream};
use crate::panel::types::{NodeInfo, User};
use crate::protocol::http::auth::{
    verify_basic_auth, RESP_400_BAD_REQUEST, RESP_407_AUTH_REQUIRED,
};
use crate::protocol::http::connect::handle_connect;
use crate::protocol::http::forward::handle_forward;
use crate::protocol::InboundContext;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

static NEXT_CONN_ID: AtomicU64 = AtomicU64::new(1001);

pub async fn run_http_server(
    ctx: InboundContext,
    node_info: NodeInfo,
    users: Arc<RwLock<HashMap<String, User>>>,
    mut shutdown_rx: broadcast::Receiver<()>,
) -> std::io::Result<()> {
    let is_tls = node_info.tls.unwrap_or(0) == 1;

    // Defense: ECH must never be enabled on Plain HTTP Proxy
    if !is_tls {
        if let Some(ts) = &node_info.tls_settings {
            if ts
                .get("ech")
                .and_then(|e| e.get("enabled"))
                .and_then(|v| v.as_bool())
                .unwrap_or(false)
            {
                error!(
                    "Invalid node configuration for node {}: ECH enabled on Plain HTTP Proxy (tls = 0)!",
                    node_info.id
                );
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Invalid node configuration: ECH cannot be enabled on Plain HTTP Proxy (tls = 0)",
                ));
            }
        }
    }

    let bind_addr = format!("{}:{}", ctx.listen_addr, ctx.port);
    let listener = bind_tcp_listener(&bind_addr, ctx.global_config.mptcp).await?;
    info!(
        "[HTTP Proxy] Inbound listening on {} (mode: {})",
        bind_addr,
        if is_tls { "HTTPS" } else { "Plain HTTP" }
    );

    let tls_manager = if is_tls {
        match crate::transport::StreamSettings::from_node_info(&node_info) {
            Ok(settings) => match settings.security {
                crate::transport::TransportSecurityConfig::Tls(ref tls_cfg) => {
                    match crate::security::TLSManager::from_config(
                        tls_cfg,
                        ctx.global_config.auto_tls,
                        &ctx.global_config.fake_sni,
                    ) {
                        Ok(mgr) => Some(Arc::new(mgr)),
                        Err(e) => {
                            warn!(
                                "Failed to initialize TLS from node_info: {e}, falling back to ctx.tls_manager"
                            );
                            Some(ctx.tls_manager.clone())
                        }
                    }
                }
                _ => Some(ctx.tls_manager.clone()),
            },
            Err(e) => {
                warn!("Failed to parse StreamSettings: {e}, falling back to ctx.tls_manager");
                Some(ctx.tls_manager.clone())
            }
        }
    } else {
        None
    };

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                info!("[HTTP Proxy] Inbound on port {} shutting down", ctx.port);
                break;
            }
            accept_res = listener.accept() => {
                let (tcp_stream, remote_addr) = match accept_res {
                    Ok(conn) => conn,
                    Err(e) => {
                        warn!("[HTTP Proxy] accept error: {:?}", e);
                        continue;
                    }
                };
                let _ = tcp_stream.set_nodelay(true);

                let ctx = ctx.clone();
                let users = users.clone();
                let tls_manager = tls_manager.clone();
                tokio::spawn(async move {
                    let conn_id = NEXT_CONN_ID.fetch_add(1, Ordering::Relaxed);
                    let boxed_stream: BoxedStream = if let Some(mgr) = tls_manager {
                        match mgr.accept_with_timeout(Box::new(tcp_stream), Duration::from_secs(15)).await {
                            Ok(s) => Box::new(s),
                            Err(e) => {
                                warn!("[HTTP Proxy] conn={} TLS handshake failed: {}", conn_id, e);
                                return;
                            }
                        }
                    } else {
                        Box::new(tcp_stream)
                    };

                    if let Err(e) = handle_http_connection(boxed_stream, remote_addr, ctx, users, conn_id).await {
                        warn!("[HTTP Proxy] conn={} connection error: {}", conn_id, e);
                    }
                });
            }
        }
    }
    Ok(())
}

async fn handle_http_connection(
    mut stream: BoxedStream,
    remote_addr: SocketAddr,
    ctx: InboundContext,
    users: Arc<RwLock<HashMap<String, User>>>,
    conn_id: u64,
) -> std::io::Result<()> {
    // Read request headers until \r\n\r\n (limit to 64 KiB)
    let mut buf = Vec::with_capacity(4096);
    let mut header_end_idx = None;

    let mut temp = [0u8; 2048];
    while buf.len() < 65536 {
        let n = stream.read(&mut temp).await?;
        if n == 0 {
            return Ok(()); // Client closed connection cleanly
        }
        buf.extend_from_slice(&temp[..n]);

        if let Some(pos) = find_header_end(&buf) {
            header_end_idx = Some(pos);
            break;
        }
    }

    let end_idx = match header_end_idx {
        Some(idx) => idx,
        None => {
            warn!("[HTTP Proxy] conn={} request headers exceeded limit or EOF without header delimiter", conn_id);
            let _ = stream.write_all(RESP_400_BAD_REQUEST).await;
            let _ = stream.flush().await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Header too large or truncated",
            ));
        }
    };

    let header_bytes = &buf[..end_idx];
    let leftover = &buf[end_idx + 4..]; // After \r\n\r\n

    let header_str = match std::str::from_utf8(header_bytes) {
        Ok(s) => s,
        Err(_) => {
            warn!("[HTTP Proxy] conn={} invalid UTF-8 in HTTP headers", conn_id);
            let _ = stream.write_all(RESP_400_BAD_REQUEST).await;
            let _ = stream.flush().await;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Invalid UTF-8 in headers",
            ));
        }
    };

    let mut lines = header_str.split("\r\n");
    let request_line = lines.next().unwrap_or("");
    let mut req_parts = request_line.split_whitespace();
    let method = req_parts.next().unwrap_or("");
    let target = req_parts.next().unwrap_or("");
    let version = req_parts.next().unwrap_or("HTTP/1.1");

    if method.is_empty() || target.is_empty() {
        warn!("[HTTP Proxy] conn={} malformed request line: '{}'", conn_id, request_line);
        let _ = stream.write_all(RESP_400_BAD_REQUEST).await;
        let _ = stream.flush().await;
        return Ok(());
    }

    let mut headers = Vec::new();
    let mut proxy_auth = None;

    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            if key.eq_ignore_ascii_case("proxy-authorization") {
                proxy_auth = Some(val);
            }
            headers.push((key, val));
        }
    }

    // Authenticate
    let user = match verify_basic_auth(proxy_auth, &users) {
        Ok(u) => u,
        Err(err) => {
            warn!(
                "[HTTP Proxy] conn={} peer={} auth failed: {:?} (header: {:?})",
                conn_id, remote_addr, err, proxy_auth
            );
            let _ = stream.write_all(RESP_407_AUTH_REQUIRED).await;
            let _ = stream.flush().await;
            return Ok(());
        }
    };

    info!(
        "[HTTP Proxy] conn={} peer={} user_id={} authenticated, method={} target={}",
        conn_id, remote_addr, user.id, method, target
    );

    // Route based on HTTP method
    if method.eq_ignore_ascii_case("CONNECT") {
        match handle_connect(stream, target, leftover, &user, conn_id).await {
            Ok((up, down)) => {
                (ctx.on_traffic)(user.id, up, down);
            }
            Err(e) => {
                warn!("[HTTP Proxy] conn={} CONNECT failed: {}", conn_id, e);
            }
        }
    } else if matches!(
        method.to_uppercase().as_str(),
        "GET" | "POST" | "HEAD" | "PUT" | "DELETE" | "OPTIONS" | "PATCH" | "TRACE"
    ) {
        match handle_forward(
            stream, method, target, version, &headers, leftover, &user, conn_id,
        )
        .await
        {
            Ok((up, down)) => {
                (ctx.on_traffic)(user.id, up, down);
            }
            Err(e) => {
                warn!("[HTTP Proxy] conn={} forward failed: {}", conn_id, e);
            }
        }
    } else {
        warn!("[HTTP Proxy] conn={} unsupported HTTP method: {}", conn_id, method);
        let _ = stream.write_all(RESP_400_BAD_REQUEST).await;
        let _ = stream.flush().await;
    }

    Ok(())
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}
