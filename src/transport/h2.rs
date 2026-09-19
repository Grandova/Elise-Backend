use crate::conn::{BoxedStream, PrefixedStream};
use crate::transport::types::Http2TransportConfig;
use bytes::{Buf, Bytes, BytesMut};
use h2::server;
use h2::RecvStream;
use http::{Response, StatusCode};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Implements Legacy HTTP/2 transport.
/// Detects connection preface:
/// - If preface starts with `PRI `, operates in true HTTP/2 framed mode with 4MB/8MB flow control.
/// - Otherwise, handles HTTP/1.1 streaming request (e.g. sing-box NoTLS `PUT /path HTTP/1.1`) and returns a raw bidirectional tunnel.
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

    apply_h2_http1(stream, &probe_buf, config).await
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
    let norm_config = if config.path.starts_with('/') {
        config.path.clone()
    } else {
        format!("/{}", config.path)
    };
    let normalized_config_path = norm_config.trim_end_matches('/');
    let normalized_req_path = path.trim_end_matches('/');

    if !normalized_config_path.is_empty()
        && normalized_req_path != normalized_config_path
        && !normalized_req_path.starts_with(normalized_config_path)
    {
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

    let effective_hosts: Vec<&String> = config
        .host
        .iter()
        .filter(|h| !h.trim().is_empty())
        .collect();
    if !effective_hosts.is_empty() {
        if let Some(auth) = request.uri().authority() {
            let clean_req = auth.host();
            if !effective_hosts.iter().any(|h| {
                let clean_h = h.split(':').next().unwrap_or(h);
                clean_h == clean_req
            }) {
                let resp = Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(resp, true);
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Legacy H2 host mismatch: got '{auth}'"),
                ));
            }
        }
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

    // Drive connection in background to service WINDOW_UPDATE, ACKs, and outgoing data flush
    tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| {
            while let Poll::Ready(Some(res)) = connection.poll_accept(cx) {
                if let Ok((_req, mut resp)) = res {
                    let r = Response::builder().status(StatusCode::OK).body(()).unwrap();
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

        self.send_stream.reserve_capacity(data.len());
        match self.send_stream.poll_capacity(cx) {
            Poll::Ready(Some(Ok(avail))) => {
                let chunk_size = data.len().min(avail);
                let to_send = Bytes::copy_from_slice(&data[..chunk_size]);

                self.send_stream.send_data(to_send, false).map_err(|e| {
                    io::Error::new(io::ErrorKind::Other, format!("H2 send_data failed: {e}"))
                })?;

                Poll::Ready(Ok(chunk_size))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("H2 send capacity error: {e}"),
            ))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "H2 send stream closed",
            ))),
            Poll::Pending => Poll::Pending,
        }
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

    // Send 200 OK response
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

/// A stream wrapper that flushes the inner stream immediately after every successful poll_write.
/// This prevents TLS records from being buffered indefinitely when using tokio_rustls + h2.
pub struct AutoFlushingStream<S> {
    inner: S,
}

impl<S> AutoFlushingStream<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for AutoFlushingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for AutoFlushingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                let _ = Pin::new(&mut self.inner).poll_flush(cx);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
