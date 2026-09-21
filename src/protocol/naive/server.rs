use super::auth::verify_auth;
use super::padding::NaivePaddedStream;
use crate::conn::{
    bind_tcp_listener, read_proxy_protocol, BoxedStream, MonitoredStream, PrefixedStream,
};
use crate::observability::AuditRecord;
use crate::panel::types::{NodeInfo, User};
use crate::protocol::{Inbound, InboundContext};
use crate::proxy::router::MatchContext;
use crate::transport::h2::H2RawStreamWrapper;
use async_trait::async_trait;
use bytes::Bytes;
use h2::server;
use h2::RecvStream;
use http::{Response, StatusCode};
use parking_lot::RwLock;
use rand::Rng;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::broadcast;
use tracing::{info, warn};

pub const CAMOUFLAGE_HTML: &[u8] = b"<!DOCTYPE html><html><head><title>Welcome</title></head><body><h1>Welcome to Elise Web Server</h1></body></html>\n";

pub struct NaiveInbound {
    users: Arc<RwLock<HashMap<String, User>>>,
}

impl Default for NaiveInbound {
    fn default() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl NaiveInbound {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Inbound for NaiveInbound {
    fn protocol_type(&self) -> &'static str {
        "naive"
    }

    fn update_users(&self, users: Vec<User>) {
        let mut map = HashMap::new();
        for u in users {
            let pass = u.password.clone().unwrap_or_else(|| u.uuid.clone());
            map.insert(format!("{}:{}", u.id, pass), u.clone());
            map.insert(format!("{}:{}", u.uuid, pass), u);
        }
        *self.users.write() = map;
    }

    async fn start(
        &self,
        ctx: InboundContext,
        node_info: NodeInfo,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> std::io::Result<()> {
        let bind_addr = format!("{}:{}", ctx.listen_addr, ctx.port);
        let listener = bind_tcp_listener(&bind_addr, ctx.global_config.mptcp).await?;
        if node_info.tls.is_some_and(|mode| mode > 1) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "This inbound supports plain TCP or TLS, not REALITY",
            ));
        }
        let is_tls = node_info.tls.unwrap_or(0) == 1;
        info!(
            "NaiveProxy inbound listening on {} (mode: {})",
            bind_addr,
            if is_tls { "TLS" } else { "Plain" }
        );

        let tls_manager = if is_tls {
            let settings = crate::transport::StreamSettings::from_node_info(&node_info)
                .map_err(std::io::Error::other)?;
            let crate::transport::TransportSecurityConfig::Tls(tls_cfg) = settings.security else {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    "Expected TLS configuration",
                ));
            };
            Some(Arc::new(
                crate::security::TLSManager::from_config(
                    &tls_cfg,
                    ctx.global_config.auto_tls,
                    &ctx.global_config.fake_sni,
                )
                .map_err(std::io::Error::other)?,
            ))
        } else {
            None
        };

        ctx.mark_ready();
        let users = self.users.clone();

        let mut connections = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(e)) = result { tracing::warn!(error = %e, "Connection task failed"); }
                }
                _ = shutdown_rx.recv() => {
                    info!("Naive inbound on port {} stopping", ctx.port);
                    break;
                }
                accept_res = listener.accept() => {
                    let (stream, remote_addr) = match accept_res {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!("Naive accept error: {:?}", e);
                            continue;
                        }
                    };
                    let _ = stream.set_nodelay(true);

                    let ctx = ctx.clone();
                    let node_info = node_info.clone();
                    let users = users.clone();
                    let tls_manager = tls_manager.clone();
                    connections.spawn(async move {
                        let _ = handle_connection(stream, remote_addr, ctx, node_info, users, tls_manager).await;
                    });
                }
            }
        }
        drop(listener);
        crate::protocol::common::inbound::drain_connections(&mut connections).await;
        Ok(())
    }
}

async fn handle_connection(
    stream: TcpStream,
    mut remote_addr: SocketAddr,
    ctx: InboundContext,
    node_info: NodeInfo,
    users: Arc<RwLock<HashMap<String, User>>>,
    tls_manager: Option<Arc<crate::security::TLSManager>>,
) -> std::io::Result<()> {
    let (src_opt, stream) =
        read_proxy_protocol(stream, ctx.global_config.get_proxy_protocol_mode()).await?;
    if let Some(src) = src_opt {
        remote_addr = src;
    }

    let client_ip = remote_addr.ip();
    if ctx.defense.is_banned(client_ip) {
        return Ok(());
    }

    let is_tls = node_info.tls.unwrap_or(0) == 1;

    if is_tls {
        let acceptor = match tls_manager.as_ref().and_then(|m| m.get_acceptor()) {
            Some(a) => a,
            None => {
                warn!(
                    "Naive TLS mode enabled on node {}, but TLS acceptor is not initialized",
                    ctx.node_id
                );
                return Ok(());
            }
        };

        let tls_stream = match acceptor.accept(stream).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Naive TLS handshake failed from {}: {:?}", remote_addr, e);
                return Ok(());
            }
        };

        let conn_id = tls_stream.get_ref().1.conn_id();
        let alpn = tls_stream.get_ref().1.alpn_protocol().map(|a| a.to_vec());
        let alpn_str = alpn
            .as_ref()
            .and_then(|a| core::str::from_utf8(a).ok())
            .unwrap_or("none");

        if alpn.as_deref() != Some(b"h2") {
            warn!(
                "[Naive] conn={} node={} peer={} ALPN mismatch: expected 'h2', got '{}'. Rejecting.",
                conn_id, ctx.node_id, remote_addr, alpn_str
            );
            return Ok(());
        }

        let mut stream: BoxedStream = Box::new(tls_stream);
        let mut peek = [0u8; 4];
        match stream.read_exact(&mut peek).await {
            Ok(_) => {
                let prefixed: BoxedStream =
                    Box::new(PrefixedStream::new(stream, Some(peek.to_vec())));
                if &peek == b"PRI " {
                    handle_h2_stream(prefixed, remote_addr, ctx, users, conn_id).await
                } else {
                    handle_http1_stream(prefixed, remote_addr, ctx, users, conn_id).await
                }
            }
            Err(e) => {
                warn!(
                    "[Naive] conn={} node={} peer={} read peek error: {:?}",
                    conn_id, ctx.node_id, remote_addr, e
                );
                Ok(())
            }
        }
    } else {
        static PLAIN_CONN_COUNTER: std::sync::atomic::AtomicU64 =
            std::sync::atomic::AtomicU64::new(10001);
        let conn_id = PLAIN_CONN_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        info!(
            "[Naive] conn={} node={} peer={} mode=plain",
            conn_id, ctx.node_id, remote_addr
        );

        let mut stream: BoxedStream = Box::new(stream);
        let mut peek = [0u8; 4];
        match stream.read_exact(&mut peek).await {
            Ok(_) => {
                let prefixed: BoxedStream =
                    Box::new(PrefixedStream::new(stream, Some(peek.to_vec())));
                if &peek == b"PRI " {
                    handle_h2_stream(prefixed, remote_addr, ctx, users, conn_id).await
                } else {
                    handle_http1_stream(prefixed, remote_addr, ctx, users, conn_id).await
                }
            }
            Err(_) => Ok(()),
        }
    }
}

async fn handle_h2_stream(
    stream: BoxedStream,
    remote_addr: SocketAddr,
    ctx: InboundContext,
    users: Arc<RwLock<HashMap<String, User>>>,
    conn_id: u64,
) -> std::io::Result<()> {
    let mut builder = server::Builder::default();
    builder.initial_window_size(4 * 1024 * 1024);
    builder.initial_connection_window_size(8 * 1024 * 1024);
    builder.max_concurrent_streams(1024);

    let mut connection = match builder.handshake(stream).await {
        Ok(c) => {
            info!(
                "[Naive] conn={} node={} peer={} h2=PASS",
                conn_id, ctx.node_id, remote_addr
            );
            c
        }
        Err(e) => {
            warn!(
                "[Naive] conn={} node={} peer={} Naive H2 handshake error: {e}",
                conn_id, ctx.node_id, remote_addr
            );
            return Ok(());
        }
    };

    while let Some(accept_res) = connection.accept().await {
        let (request, respond) = match accept_res {
            Ok(pair) => pair,
            Err(e) => {
                warn!(
                    "[Naive] conn={} node={} peer={} Naive H2 stream accept error: {e}",
                    conn_id, ctx.node_id, remote_addr
                );
                break;
            }
        };

        let ctx = ctx.clone();
        let users = users.clone();
        tokio::spawn(async move {
            let _ = process_h2_connect(request, respond, remote_addr, ctx, users, conn_id).await;
        });
    }

    Ok(())
}

async fn process_h2_connect(
    request: http::Request<RecvStream>,
    mut respond: h2::server::SendResponse<Bytes>,
    remote_addr: SocketAddr,
    ctx: InboundContext,
    users: Arc<RwLock<HashMap<String, User>>>,
    conn_id: u64,
) -> std::io::Result<()> {
    let client_ip = remote_addr.ip();

    if request.method() == http::Method::GET || request.method() == http::Method::HEAD {
        info!(
            "[Naive] conn={} node={} peer={} camouflage=PASS method={}",
            conn_id,
            ctx.node_id,
            remote_addr,
            request.method()
        );
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/html; charset=utf-8")
            .header("content-length", CAMOUFLAGE_HTML.len().to_string())
            .body(())
            .unwrap();
        let mut send_stream = match respond.send_response(resp, false) {
            Ok(s) => s,
            Err(_) => return Ok(()),
        };
        if request.method() == http::Method::GET {
            let _ = send_stream.send_data(Bytes::from_static(CAMOUFLAGE_HTML), true);
        } else {
            let _ = send_stream.send_data(Bytes::new(), true);
        }
        return Ok(());
    }

    if request.method() != http::Method::CONNECT {
        warn!(
            "[Naive] conn={} node={} peer={} invalid method: {}",
            conn_id,
            ctx.node_id,
            remote_addr,
            request.method()
        );
        let resp = Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .body(())
            .unwrap();
        let _ = respond.send_response(resp, true);
        return Ok(());
    }

    let target_str = match request.uri().authority().map(|a| a.as_str()) {
        Some(a) => a,
        None => {
            let resp = Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(())
                .unwrap();
            let _ = respond.send_response(resp, true);
            return Ok(());
        }
    };

    let (target_host, target_port) = match target_str.rsplit_once(':') {
        Some((h, p)) => {
            let h = h.trim_start_matches('[').trim_end_matches(']');
            (h.to_string(), p.parse::<u16>().unwrap_or(443))
        }
        None => (target_str.to_string(), 443),
    };

    let auth_header = request
        .headers()
        .get("proxy-authorization")
        .and_then(|h| h.to_str().ok());

    let user = match verify_auth(auth_header, &users) {
        Ok(u) => {
            ctx.defense.record_success(client_ip);
            info!(
                "[Naive] conn={} node={} peer={} auth=PASS user={}",
                conn_id, ctx.node_id, remote_addr, u.id
            );
            u
        }
        Err(err) => {
            warn!(
                "[Naive] conn={} node={} peer={} auth=REJECT (reason: {:?})",
                conn_id, ctx.node_id, remote_addr, err
            );
            let resp = Response::builder()
                .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
                .header("proxy-authenticate", "Basic realm=\"Elise\"")
                .body(())
                .unwrap();
            let _ = respond.send_response(resp, true);
            return Ok(());
        }
    };

    info!(
        "[Naive] conn={} node={} peer={} CONNECT=PASS target={}",
        conn_id, ctx.node_id, remote_addr, target_str
    );

    if !ctx
        .device_limiter
        .check_and_record_async(user.id, client_ip)
        .await
    {
        let resp = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(())
            .unwrap();
        let _ = respond.send_response(resp, true);
        return Ok(());
    }

    let _conn_guard = match ctx.conn_limiter.try_acquire(user.id) {
        Some(g) => g,
        None => {
            let resp = Response::builder()
                .status(StatusCode::TOO_MANY_REQUESTS)
                .body(())
                .unwrap();
            let _ = respond.send_response(resp, true);
            return Ok(());
        }
    };

    if ctx.audit.should_block(&target_host, None, target_port) {
        let resp = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(())
            .unwrap();
        let _ = respond.send_response(resp, true);
        return Ok(());
    }

    let mctx = MatchContext {
        node_id: ctx.node_id,
        network: "tcp",
        target_host: &target_host,
        target_ip: None,
        target_port,
        inbound_local_ip: None,
    };
    let outbound = ctx.router.match_outbound(&mctx);

    let mut out_stream = match ctx
        .router
        .dialer()
        .dial(&outbound, &target_host, target_port, None)
        .await
    {
        Ok(s) => {
            info!(
                "[Naive] conn={} node={} peer={} target_connection=PASS target={}:{}",
                conn_id, ctx.node_id, remote_addr, target_host, target_port
            );
            s
        }
        Err(e) => {
            warn!(
                "[Naive] conn={} node={} peer={} target_connection=FAIL target={}:{} error={:?}",
                conn_id, ctx.node_id, remote_addr, target_host, target_port, e
            );
            let resp = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(())
                .unwrap();
            let _ = respond.send_response(resp, true);
            return Ok(());
        }
    };

    let has_padding = request.headers().contains_key("padding");
    if has_padding {
        info!(
            "[Naive] conn={} node={} peer={} padding=PASS",
            conn_id, ctx.node_id, remote_addr
        );
    }

    let mut resp_builder = Response::builder().status(StatusCode::OK);
    if has_padding {
        let pad_len = rand::thread_rng().gen_range(30..=62);
        let pad_symbols: String = (0..pad_len)
            .map(|_| {
                const CHARS: &[u8] =
                    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                let idx = rand::thread_rng().gen_range(0..CHARS.len());
                CHARS[idx] as char
            })
            .collect();
        resp_builder = resp_builder.header("padding", pad_symbols);
    }

    let resp = resp_builder.body(()).unwrap();
    let send_stream = match respond.send_response(resp, false) {
        Ok(s) => s,
        Err(e) => {
            warn!("Failed to send H2 200 response: {e}");
            return Ok(());
        }
    };

    let recv_stream = request.into_body();
    let raw_h2_stream = H2RawStreamWrapper::new(recv_stream, send_stream);
    let padded_stream = NaivePaddedStream::new(raw_h2_stream, has_padding);
    let mut client_conn = MonitoredStream::new(Box::new(padded_stream), user.id, remote_addr);
    let _traffic = client_conn.traffic_guard(ctx.on_traffic.clone());

    let start_time = Instant::now();
    let _ = crate::conn::copy_bidirectional_throttled(
        &mut client_conn,
        &mut out_stream,
        user.id,
        Some(&ctx.rate_limiter),
        ctx.global_config.tcp_timeout,
    )
    .await;

    let duration = start_time.elapsed();
    let (up, down) = client_conn.stats();
    info!(
        "[Naive] conn={} node={} peer={} transfer completed up={} down={} duration_ms={}",
        conn_id,
        ctx.node_id,
        remote_addr,
        up,
        down,
        duration.as_millis()
    );

    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user.id,
        "naive",
        "tcp",
        &client_ip.to_string(),
        &target_host,
        target_port,
        up,
        down,
        duration.as_millis() as i64,
        &outbound.tag,
        "connected",
    ));

    Ok(())
}

async fn handle_http1_stream(
    mut stream: BoxedStream,
    remote_addr: SocketAddr,
    ctx: InboundContext,
    users: Arc<RwLock<HashMap<String, User>>>,
    conn_id: u64,
) -> std::io::Result<()> {
    let client_ip = remote_addr.ip();

    let mut header_buf = Vec::with_capacity(2048);
    let mut chunk = [0u8; 1024];
    let mut header_end = None;

    while header_buf.len() < 16384 {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Ok(());
        }
        header_buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_subslice(&header_buf, b"\r\n\r\n") {
            header_end = Some(pos);
            break;
        }
    }

    let end_idx = match header_end {
        Some(pos) => pos,
        None => {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    };

    let header_str = String::from_utf8_lossy(&header_buf[..end_idx]);
    let mut lines = header_str.lines();
    let request_line = match lines.next() {
        Some(l) => l,
        None => {
            let _ = stream
                .write_all(b"HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    };

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if !parts.is_empty() && (parts[0] == "GET" || parts[0] == "HEAD") {
        info!(
            "[Naive] conn={} node={} peer={} camouflage=PASS method={}",
            conn_id, ctx.node_id, remote_addr, parts[0]
        );
        let body = if parts[0] == "GET" {
            CAMOUFLAGE_HTML
        } else {
            b""
        };
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            CAMOUFLAGE_HTML.len()
        );
        let _ = stream.write_all(resp.as_bytes()).await;
        if !body.is_empty() {
            let _ = stream.write_all(body).await;
        }
        return Ok(());
    }

    if parts.len() < 2 || parts[0] != "CONNECT" {
        warn!(
            "[Naive] conn={} node={} peer={} invalid method: {:?}",
            conn_id,
            ctx.node_id,
            remote_addr,
            parts.first()
        );
        let _ = stream
            .write_all(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\n\r\n")
            .await;
        return Ok(());
    }

    let target = parts[1];
    let (target_host, target_port) = match target.rsplit_once(':') {
        Some((h, p)) => {
            let h = h.trim_start_matches('[').trim_end_matches(']');
            (h.to_string(), p.parse::<u16>().unwrap_or(443))
        }
        None => (target.to_string(), 443),
    };

    let mut auth_header: Option<String> = None;
    let mut has_padding = false;

    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            let k_lower = k.trim().to_ascii_lowercase();
            if k_lower == "proxy-authorization" {
                auth_header = Some(v.trim().to_string());
            } else if k_lower == "padding" {
                has_padding = true;
            }
        }
    }

    let user = match verify_auth(auth_header.as_deref(), &users) {
        Ok(u) => {
            ctx.defense.record_success(client_ip);
            info!(
                "[Naive] conn={} node={} peer={} auth=PASS user={}",
                conn_id, ctx.node_id, remote_addr, u.id
            );
            u
        }
        Err(err) => {
            warn!(
                "[Naive] conn={} node={} peer={} auth=REJECT (reason: {:?})",
                conn_id, ctx.node_id, remote_addr, err
            );
            let _ = stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Elise\"\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                .await;
            return Ok(());
        }
    };

    info!(
        "[Naive] conn={} node={} peer={} CONNECT=PASS target={}",
        conn_id, ctx.node_id, remote_addr, target
    );

    if !ctx
        .device_limiter
        .check_and_record_async(user.id, client_ip)
        .await
    {
        let _ = stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            .await;
        return Ok(());
    }

    let _conn_guard = match ctx.conn_limiter.try_acquire(user.id) {
        Some(g) => g,
        None => {
            let _ = stream
                .write_all(b"HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    };

    if ctx.audit.should_block(&target_host, None, target_port) {
        let _ = stream
            .write_all(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n")
            .await;
        return Ok(());
    }

    let mctx = MatchContext {
        node_id: ctx.node_id,
        network: "tcp",
        target_host: &target_host,
        target_ip: None,
        target_port,
        inbound_local_ip: None,
    };
    let outbound = ctx.router.match_outbound(&mctx);

    let mut out_stream = match ctx
        .router
        .dialer()
        .dial(&outbound, &target_host, target_port, None)
        .await
    {
        Ok(s) => {
            info!(
                "[Naive] conn={} node={} peer={} target_connection=PASS target={}:{}",
                conn_id, ctx.node_id, remote_addr, target_host, target_port
            );
            s
        }
        Err(e) => {
            warn!(
                "[Naive] conn={} node={} peer={} target_connection=FAIL target={}:{} error={:?}",
                conn_id, ctx.node_id, remote_addr, target_host, target_port, e
            );
            let _ = stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
                .await;
            return Ok(());
        }
    };

    if has_padding {
        info!(
            "[Naive] conn={} node={} peer={} padding=PASS",
            conn_id, ctx.node_id, remote_addr
        );
        let pad_len = rand::thread_rng().gen_range(30..=62);
        let pad_symbols: String = (0..pad_len)
            .map(|_| {
                const CHARS: &[u8] =
                    b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
                let idx = rand::thread_rng().gen_range(0..CHARS.len());
                CHARS[idx] as char
            })
            .collect();
        let resp = format!(
            "HTTP/1.1 200 Connection Established\r\nPadding: {}\r\n\r\n",
            pad_symbols
        );
        stream.write_all(resp.as_bytes()).await?;
    } else {
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
    }

    let unconsumed = header_buf[end_idx + 4..].to_vec();
    let stream: BoxedStream = if !unconsumed.is_empty() {
        Box::new(PrefixedStream::new(stream, Some(unconsumed)))
    } else {
        stream
    };

    let padded_stream = NaivePaddedStream::new(stream, has_padding);
    let mut client_conn = MonitoredStream::new(Box::new(padded_stream), user.id, remote_addr);
    let _traffic = client_conn.traffic_guard(ctx.on_traffic.clone());

    let start_time = Instant::now();
    let _ = crate::conn::copy_bidirectional_throttled(
        &mut client_conn,
        &mut out_stream,
        user.id,
        Some(&ctx.rate_limiter),
        ctx.global_config.tcp_timeout,
    )
    .await;

    let duration = start_time.elapsed();
    let (up, down) = client_conn.stats();
    info!(
        "[Naive] conn={} node={} peer={} transfer completed up={} down={} duration_ms={}",
        conn_id,
        ctx.node_id,
        remote_addr,
        up,
        down,
        duration.as_millis()
    );

    ctx.audit_logger.record(AuditRecord::new(
        ctx.node_id,
        user.id,
        "naive",
        "tcp",
        &client_ip.to_string(),
        &target_host,
        target_port,
        up,
        down,
        duration.as_millis() as i64,
        &outbound.tag,
        "connected",
    ));

    Ok(())
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
