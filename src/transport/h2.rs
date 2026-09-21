use crate::conn::{AutoFlushingStream, BoxedStream, PrefixedStream};
use crate::security::TLSManager;
use crate::transport::types::Http2TransportConfig;
use bytes::{Buf, Bytes, BytesMut};
use h2::server;
use h2::RecvStream;
use http::{Response, StatusCode};
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub fn is_http1_method(buf: &[u8; 4]) -> bool {
    let mut upper = [0u8; 4];
    upper.copy_from_slice(buf);
    upper.make_ascii_uppercase();
    (upper[..3] == *b"GET" && upper[3].is_ascii_whitespace())
        || (upper[..3] == *b"PUT" && upper[3].is_ascii_whitespace())
        || matches!(
            &upper,
            b"POST" | b"HEAD" | b"OPTI" | b"DELE" | b"PATC" | b"CONN" | b"TRAC"
        )
}

static FALLBACK_TLS_MANAGER: std::sync::OnceLock<Arc<TLSManager>> = std::sync::OnceLock::new();

fn get_fallback_tls_manager() -> Arc<TLSManager> {
    FALLBACK_TLS_MANAGER
        .get_or_init(|| Arc::new(TLSManager::new(true, "localhost".into())))
        .clone()
}

pub async fn apply_h2_transport(
    mut stream: BoxedStream,
    config: &Http2TransportConfig,
) -> io::Result<BoxedStream> {
    let mut probe_buf = [0u8; 4];
    stream.read_exact(&mut probe_buf).await?;

    if &probe_buf == b"PRI " {
        let prefixed = Box::new(PrefixedStream::new(stream, Some(probe_buf.to_vec())));
        return apply_h2_framed(prefixed, config).await;
    }

    if is_http1_method(&probe_buf) {
        return apply_h2_http1(stream, &probe_buf, config).await;
    }

    if probe_buf[0] == 0x16 && probe_buf[1] == 0x03 {
        tracing::info!(
            "apply_h2_transport: detected incoming TLS ClientHello; auto-negotiating TLS"
        );
        let prefixed = Box::new(PrefixedStream::new(stream, Some(probe_buf.to_vec())));
        let mgr = get_fallback_tls_manager();
        if mgr.get_acceptor().is_none() {
            let _ = mgr.generate_self_signed();
        }
        let tls_stream = mgr
            .accept_with_timeout(prefixed, Duration::from_secs(15))
            .await
            .map_err(|e| io::Error::new(io::ErrorKind::ConnectionAborted, e))?;
        return Box::pin(apply_h2_transport(Box::new(tls_stream), config)).await;
    }

    tracing::info!(
        "apply_h2_transport: probe bytes ({:02x?}) do not match HTTP/2, HTTP/1.1 or TLS; falling back to raw stream",
        probe_buf
    );
    Ok(Box::new(PrefixedStream::new(
        stream,
        Some(probe_buf.to_vec()),
    )))
}

fn validate_h2_path(path: &str, config_path: &str) -> bool {
    let norm_config = if config_path.starts_with('/') {
        config_path.to_string()
    } else {
        format!("/{}", config_path)
    };
    let normalized_config_path = norm_config.trim_end_matches('/');
    let normalized_req_path = path.trim_end_matches('/');

    if !normalized_config_path.is_empty()
        && normalized_req_path != normalized_config_path
        && !normalized_req_path.starts_with(normalized_config_path)
    {
        return false;
    }
    true
}

fn validate_h2_host(request: &http::Request<RecvStream>, hosts: &[String]) -> bool {
    let effective_hosts: Vec<&String> = hosts.iter().filter(|h| !h.trim().is_empty()).collect();
    if !effective_hosts.is_empty() {
        let req_host = request.uri().authority().map(|a| a.host()).or_else(|| {
            request
                .headers()
                .get("host")
                .and_then(|h| h.to_str().ok())
                .map(|h| h.split(':').next().unwrap_or(h))
        });

        if let Some(clean_req) = req_host {
            return effective_hosts.iter().any(|h| {
                let clean_h = h.split(':').next().unwrap_or(h);
                clean_h.eq_ignore_ascii_case(clean_req)
            });
        }
        return false;
    }
    true
}

pub async fn serve_h2<F, Fut>(
    mut stream: BoxedStream,
    config: &Http2TransportConfig,
    tls_manager: Option<&TLSManager>,
    mut handler: F,
) -> io::Result<()>
where
    F: FnMut(BoxedStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let mut probe_buf = [0u8; 4];
    stream.read_exact(&mut probe_buf).await?;

    if &probe_buf == b"PRI " {
        let prefixed = Box::new(PrefixedStream::new(stream, Some(probe_buf.to_vec())));
        return serve_h2_framed(prefixed, config, handler).await;
    }

    if is_http1_method(&probe_buf) {
        let single_stream = apply_h2_http1(stream, &probe_buf, config).await?;
        handler(single_stream).await;
        return Ok(());
    }

    if probe_buf[0] == 0x16 && probe_buf[1] == 0x03 {
        tracing::info!("serve_h2: detected incoming TLS ClientHello; auto-negotiating TLS");
        let prefixed = Box::new(PrefixedStream::new(stream, Some(probe_buf.to_vec())));
        let (tls_stream, used_mgr): (BoxedStream, Arc<TLSManager>) = if let Some(mgr) = tls_manager
        {
            let mgr_arc = Arc::new(mgr.clone());
            if mgr_arc.get_acceptor().is_none() {
                let _ = mgr_arc.generate_self_signed();
            }
            match mgr_arc
                .accept_with_timeout(prefixed, Duration::from_secs(15))
                .await
            {
                Ok(s) => (Box::new(s), mgr_arc),
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("BadCertificate") || err_str.contains("bad_certificate") {
                        tracing::warn!(
                            "H2 Auto-TLS: client rejected certificate (Alert 42 / BadCertificate). \
                             The client is verifying certificates against Root CAs but the server is using a self-signed certificate. \
                             To resolve, enable 'skip-cert-verify: true' (allow_insecure) in the client/panel, or configure a trusted domain certificate."
                        );
                    } else {
                        tracing::warn!("Auto-TLS handshake failed for H2 stream: {e}");
                    }
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, e));
                }
            }
        } else {
            let mgr = get_fallback_tls_manager();
            if mgr.get_acceptor().is_none() {
                let _ = mgr.generate_self_signed();
            }
            match mgr
                .accept_with_timeout(prefixed, Duration::from_secs(15))
                .await
            {
                Ok(s) => (Box::new(s), mgr),
                Err(e) => {
                    let err_str = e.to_string();
                    if err_str.contains("BadCertificate") || err_str.contains("bad_certificate") {
                        tracing::warn!(
                            "H2 Auto-TLS: client rejected certificate (Alert 42 / BadCertificate). \
                             The client is verifying certificates against Root CAs but the server is using a self-signed certificate. \
                             To resolve, enable 'skip-cert-verify: true' (allow_insecure) in the client/panel, or configure a trusted domain certificate."
                        );
                    } else {
                        tracing::warn!("Auto-TLS handshake failed for H2 stream: {e}");
                    }
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, e));
                }
            }
        };

        return Box::pin(serve_h2(tls_stream, config, Some(&used_mgr), handler)).await;
    }

    tracing::info!(
        "serve_h2: probe bytes ({:02x?}) do not match HTTP/2, HTTP/1.1 or TLS; falling back to raw stream",
        probe_buf
    );
    let raw_stream = Box::new(PrefixedStream::new(stream, Some(probe_buf.to_vec())));
    handler(raw_stream).await;
    Ok(())
}

async fn serve_h2_framed<F, Fut>(
    stream: BoxedStream,
    config: &Http2TransportConfig,
    mut handler: F,
) -> io::Result<()>
where
    F: FnMut(BoxedStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let mut builder = server::Builder::default();
    builder.initial_window_size(4 * 1024 * 1024);
    builder.initial_connection_window_size(8 * 1024 * 1024);
    builder.max_concurrent_streams(1024);

    let stream = Box::new(AutoFlushingStream::new(stream));
    let mut connection = builder.handshake(stream).await.map_err(|e| {
        io::Error::new(
            io::ErrorKind::ConnectionReset,
            format!("H2 handshake failed: {e}"),
        )
    })?;

    let mut tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(e)) = result {
                    tracing::debug!("H2 stream task ended with error: {e}");
                }
            }
            accept_res = connection.accept() => {
                let (request, mut respond) = match accept_res {
                    Some(Ok(pair)) => pair,
                    Some(Err(e)) => {
                        tracing::debug!("H2 connection accept ended: {e}");
                        break;
                    }
                    None => break,
                };

                let path = request.uri().path();
                if !validate_h2_path(path, &config.path) {
                    let resp = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(())
                        .unwrap();
                    let _ = respond.send_response(resp, true);
                    continue;
                }

                if !validate_h2_host(&request, &config.host) {
                    let resp = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(())
                        .unwrap();
                    let _ = respond.send_response(resp, true);
                    continue;
                }

                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/octet-stream")
                    .body(())
                    .unwrap();

                let send_stream = match respond.send_response(response, false) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("failed to send H2 response: {e}");
                        continue;
                    }
                };

                let recv_stream = request.into_body();
                let wrapped = Box::new(H2RawStreamWrapper {
                    recv_stream,
                    send_stream,
                    read_buf: BytesMut::new(),
                });

                let fut = handler(wrapped);
                tasks.spawn(fut);
            }
        }
    }

    while !tasks.is_empty() {
        tokio::select! {
            _ = tasks.join_next() => {},
            _ = std::future::poll_fn(|cx| connection.poll_closed(cx)) => {
                break;
            }
        }
    }

    Ok(())
}

async fn apply_h2_framed(
    stream: BoxedStream,
    config: &Http2TransportConfig,
) -> io::Result<BoxedStream> {
    let mut builder = server::Builder::default();
    builder.initial_window_size(4 * 1024 * 1024);
    builder.initial_connection_window_size(8 * 1024 * 1024);
    builder.max_concurrent_streams(1024);

    let stream = Box::new(AutoFlushingStream::new(stream));
    let mut connection = builder.handshake(stream).await.map_err(|e| {
        io::Error::new(
            io::ErrorKind::ConnectionReset,
            format!("H2 handshake failed: {e}"),
        )
    })?;

    let (request, mut respond) = match connection.accept().await {
        Some(Ok(pair)) => pair,
        Some(Err(e)) => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("failed to accept legacy H2 stream: {e}"),
            ));
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "H2 connection closed before stream was accepted",
            ));
        }
    };

    let path = request.uri().path();
    if !validate_h2_path(path, &config.path) {
        let resp = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .unwrap();
        let _ = respond.send_response(resp, true);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "Legacy H2 path mismatch: expected '{}', got '{path}'",
                config.path
            ),
        ));
    }

    if !validate_h2_host(&request, &config.host) {
        let resp = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .unwrap();
        let _ = respond.send_response(resp, true);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Legacy H2 host mismatch",
        ));
    }

    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/octet-stream")
        .body(())
        .unwrap();

    let send_stream = respond.send_response(response, false).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to send H2 response: {e}"),
        )
    })?;

    let recv_stream = request.into_body();

    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| {
            while let Poll::Ready(Some(res)) = connection.poll_accept(cx) {
                if let Ok((_req, mut resp)) = res {
                    let r = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(())
                        .unwrap();
                    let _ = resp.send_response(r, true);
                }
            }
            connection.poll_closed(cx)
        })
        .await;
    });

    Ok(Box::new(H2RawStreamWrapper {
        recv_stream,
        send_stream,
        read_buf: BytesMut::new(),
    }))
}

pub struct H2RawStreamWrapper {
    recv_stream: RecvStream,
    send_stream: h2::SendStream<Bytes>,
    read_buf: BytesMut,
}

impl H2RawStreamWrapper {
    pub fn new(recv_stream: RecvStream, send_stream: h2::SendStream<Bytes>) -> Self {
        Self {
            recv_stream,
            send_stream,
            read_buf: BytesMut::new(),
        }
    }
}

impl AsyncRead for H2RawStreamWrapper {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if !self.read_buf.is_empty() {
                let n = output.remaining().min(self.read_buf.len());
                output.put_slice(&self.read_buf[..n]);
                self.read_buf.advance(n);
                return Poll::Ready(Ok(()));
            }

            match Pin::new(&mut self.recv_stream).poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let _ = self
                        .recv_stream
                        .flow_control()
                        .release_capacity(chunk.len());
                    self.read_buf.extend_from_slice(&chunk);
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("H2 recv error: {e}"),
                    )));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H2RawStreamWrapper {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let mut avail = self.send_stream.capacity();
        if avail == 0 {
            self.send_stream.reserve_capacity(data.len().max(16384));
            match self.send_stream.poll_capacity(cx) {
                Poll::Ready(Some(Ok(new_cap))) => {
                    avail = new_cap;
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("H2 send capacity error: {e}"),
                    )));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "H2 send stream closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        if avail == 0 {
            return Poll::Pending;
        }

        let chunk_size = data.len().min(avail).min(16384);
        let to_send = Bytes::copy_from_slice(&data[..chunk_size]);

        self.send_stream.send_data(to_send, false).map_err(|e| {
            io::Error::new(io::ErrorKind::Other, format!("H2 send_data failed: {e}"))
        })?;

        if self.send_stream.capacity() < 32768 {
            self.send_stream.reserve_capacity(65536);
        }

        Poll::Ready(Ok(chunk_size))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let _ = self.send_stream.send_data(Bytes::new(), true);
        Poll::Ready(Ok(()))
    }
}

async fn apply_h2_http1(
    mut stream: BoxedStream,
    initial_bytes: &[u8],
    config: &Http2TransportConfig,
) -> io::Result<BoxedStream> {
    let mut header_buf = Vec::with_capacity(1024);
    header_buf.extend_from_slice(initial_bytes);

    let mut chunk = [0u8; 1024];
    let mut header_end = None;

    while header_buf.len() < 12288 {
        if let Some(pos) = find_subslice(&header_buf, b"\r\n\r\n") {
            header_end = Some(pos);
            break;
        }
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "connection closed before HTTP/1.1 request completed",
            ));
        }
        header_buf.extend_from_slice(&chunk[..n]);
    }

    let end_idx = header_end.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "HTTP request headers exceeded max length (12288 bytes)",
        )
    })?;

    let header_str = String::from_utf8_lossy(&header_buf[..end_idx]);
    let mut lines = header_str.lines();
    let request_line = lines
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty HTTP request"))?;
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("invalid HTTP request line: {request_line}"),
        ));
    }
    let req_path = parts[1];
    let norm_config = if config.path.starts_with('/') {
        config.path.clone()
    } else {
        format!("/{}", config.path)
    };
    let normalized_config_path = norm_config.trim_end_matches('/');
    let normalized_req_path = req_path.trim_end_matches('/');

    if !normalized_config_path.is_empty()
        && normalized_req_path != normalized_config_path
        && !normalized_req_path.starts_with(normalized_config_path)
    {
        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            .await;
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "HTTP path mismatch: expected '{}', got '{req_path}'",
                config.path
            ),
        ));
    }

    let effective_hosts: Vec<&String> = config
        .host
        .iter()
        .filter(|h| !h.trim().is_empty())
        .collect();
    if !effective_hosts.is_empty() {
        let mut host_header = None;
        for line in lines {
            if let Some((k, v)) = line.split_once(':') {
                if k.trim().eq_ignore_ascii_case("host") {
                    host_header = Some(v.trim());
                    break;
                }
            }
        }
        if let Some(host_val) = host_header {
            let clean_req = host_val.split(':').next().unwrap_or(host_val);
            if !effective_hosts.iter().any(|h| {
                let clean_h = h.split(':').next().unwrap_or(h);
                clean_h == clean_req
            }) {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await;
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("HTTP host mismatch: got '{host_val}'"),
                ));
            }
        }
    }

    let response = b"HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\n\r\n";
    stream.write_all(response).await?;
    stream.flush().await?;

    let unconsumed = header_buf[end_idx + 4..].to_vec();
    if !unconsumed.is_empty() {
        Ok(Box::new(PrefixedStream::new(stream, Some(unconsumed))))
    } else {
        Ok(stream)
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_h2_transport_handshake_and_framing() {
        let (client, server) = tokio::io::duplex(65536);
        let config = Http2TransportConfig {
            path: "/h2path".to_string(),
            host: vec!["example.com".to_string()],
        };

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let mut stream = apply_h2_transport(Box::new(server), &config)
                .await
                .expect("server h2 handshake");
            let mut buf = [0u8; 4];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            stream.write_all(b"pong").await.unwrap();
            stream.flush().await.unwrap();
            let _ = done_rx.await;
        });

        let (mut client_h2, conn) = h2::client::handshake(client)
            .await
            .expect("client h2 handshake");
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = http::Request::builder()
            .method("POST")
            .uri("http://example.com/h2path")
            .header("content-type", "application/octet-stream")
            .body(())
            .unwrap();

        let (response, mut send_stream) = client_h2.send_request(req, false).unwrap();
        let resp = response.await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);

        send_stream
            .send_data(Bytes::from_static(b"ping"), false)
            .unwrap();

        let mut resp_body = resp.into_body();
        let chunk = resp_body.data().await.unwrap().unwrap();
        assert_eq!(&chunk[..], b"pong");

        let _ = done_tx.send(());
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_h2_transport_raw_fallback() {
        let (mut client, server) = tokio::io::duplex(65536);
        let config = Http2TransportConfig {
            path: "/h2path".to_string(),
            host: vec![],
        };

        let (received_tx, received_rx) = tokio::sync::oneshot::channel();
        let mut received_tx = Some(received_tx);
        tokio::spawn(async move {
            serve_h2(Box::new(server), &config, None, move |mut stream| {
                let tx = received_tx.take();
                async move {
                    let mut buf = vec![0u8; 16];
                    stream.read_exact(&mut buf).await.unwrap();
                    if let Some(t) = tx {
                        let _ = t.send(buf);
                    }
                    stream.write_all(b"response_data").await.unwrap();
                    stream.flush().await.unwrap();
                }
            })
            .await
            .unwrap();
        });

        let raw_payload: [u8; 16] = [
            0xa3, 0x5b, 0x89, 0x1f, 0x04, 0x12, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11, 0x22,
            0x33, 0x44,
        ];
        client.write_all(&raw_payload).await.unwrap();
        client.flush().await.unwrap();

        let received = received_rx.await.unwrap();
        assert_eq!(received, raw_payload);

        let mut resp = [0u8; 13];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"response_data");
    }

    #[tokio::test]
    async fn test_h2_transport_http1_streaming() {
        let (mut client, server) = tokio::io::duplex(65536);
        let config = Http2TransportConfig {
            path: "/h2path".to_string(),
            host: vec!["example.com".to_string()],
        };

        let (received_tx, received_rx) = tokio::sync::oneshot::channel();
        let mut received_tx = Some(received_tx);
        tokio::spawn(async move {
            serve_h2(Box::new(server), &config, None, move |mut stream| {
                let tx = received_tx.take();
                async move {
                    let mut buf = vec![0u8; 4];
                    stream.read_exact(&mut buf).await.unwrap();
                    if let Some(t) = tx {
                        let _ = t.send(buf);
                    }
                    stream.write_all(b"pong").await.unwrap();
                    stream.flush().await.unwrap();
                }
            })
            .await
            .unwrap();
        });

        let req = b"PUT /h2path HTTP/1.1\r\nHost: example.com\r\n\r\nping";
        client.write_all(req).await.unwrap();
        client.flush().await.unwrap();

        let mut resp_header = Vec::new();
        let mut b = [0u8; 1];
        while !resp_header.ends_with(b"\r\n\r\n") {
            client.read_exact(&mut b).await.unwrap();
            resp_header.push(b[0]);
        }
        assert!(std::str::from_utf8(&resp_header)
            .unwrap()
            .contains("200 OK"));

        let received = received_rx.await.unwrap();
        assert_eq!(&received, b"ping");

        let mut pong = [0u8; 4];
        client.read_exact(&mut pong).await.unwrap();
        assert_eq!(&pong, b"pong");
    }

    #[derive(Debug)]
    struct DangerousNoVerify;
    impl rustls::client::danger::ServerCertVerifier for DangerousNoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &rustls::pki_types::CertificateDer<'_>,
            _intermediates: &[rustls::pki_types::CertificateDer<'_>],
            _server_name: &rustls::pki_types::ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &rustls::pki_types::CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    #[tokio::test]
    async fn test_h2_transport_tls_autonegotiation() {
        let (client, server) = tokio::io::duplex(65536);
        let config = Http2TransportConfig {
            path: "/h2path".to_string(),
            host: vec![],
        };

        let (received_tx, received_rx) = tokio::sync::oneshot::channel();
        let mut received_tx = Some(received_tx);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let mut done_rx = Some(done_rx);
        let server_task = tokio::spawn(async move {
            serve_h2(Box::new(server), &config, None, move |mut stream| {
                let tx = received_tx.take();
                let rx = done_rx.take();
                async move {
                    let mut buf = vec![0u8; 4];
                    stream.read_exact(&mut buf).await.unwrap();
                    if let Some(t) = tx {
                        let _ = t.send(buf);
                    }
                    stream.write_all(b"pong").await.unwrap();
                    stream.flush().await.unwrap();
                    if let Some(r) = rx {
                        let _ = r.await;
                    }
                }
            })
            .await
            .unwrap();
        });

        let mut client_tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(DangerousNoVerify))
            .with_no_client_auth();
        client_tls_config.alpn_protocols = vec![b"h2".to_vec()];

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_tls_config));
        let server_name = rustls::pki_types::ServerName::try_from("localhost")
            .unwrap()
            .to_owned();
        let tls_client = connector.connect(server_name, client).await.unwrap();

        let (mut client_h2, conn) = h2::client::handshake(tls_client).await.unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = http::Request::builder()
            .method("POST")
            .uri("https://localhost/h2path")
            .header("content-type", "application/octet-stream")
            .body(())
            .unwrap();

        let (response, mut send_stream) = client_h2.send_request(req, false).unwrap();
        let resp = response.await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);

        send_stream
            .send_data(Bytes::from_static(b"ping"), false)
            .unwrap();

        let mut resp_body = resp.into_body();
        let chunk = resp_body.data().await.unwrap().unwrap();
        assert_eq!(&chunk[..], b"pong");

        let received = received_rx.await.unwrap();
        assert_eq!(&received, b"ping");

        let _ = done_tx.send(());
        drop(send_stream);
        drop(client_h2);
        server_task.abort();
    }
}
