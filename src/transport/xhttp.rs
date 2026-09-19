use crate::conn::{AutoFlushingStream, BoxedStream, PrefixedStream};
use crate::transport::types::XHttpTransportConfig;
use bytes::{Buf, Bytes, BytesMut};
use h2::server;
use h2::RecvStream;
use http::{Response, StatusCode};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

/// Implements Xray-compatible XHTTP (SplitHTTP) transport.
/// Detects connection preface:
/// - If preface starts with `PRI `, operates in true HTTP/2 stream-one mode with 4MB/8MB flow control.
/// - Otherwise, operates in HTTP/1.1 chunked mode (Xray NoTLS mode) with bidirectional chunked streaming.
pub async fn apply_xhttp_transport(
    mut stream: BoxedStream,
    config: &XHttpTransportConfig,
) -> io::Result<BoxedStream> {
    let mut probe_buf = [0u8; 4];
    stream.read_exact(&mut probe_buf).await?;

    if &probe_buf == b"PRI " {
        let prefixed = Box::new(PrefixedStream::new(stream, Some(probe_buf.to_vec())));
        return apply_xhttp_h2(prefixed, config).await;
    }

    apply_xhttp_http1(stream, &probe_buf, config).await
}

async fn apply_xhttp_h2(
    stream: BoxedStream,
    config: &XHttpTransportConfig,
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
                format!("failed to accept XHTTP stream: {e}"),
            ));
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "H2 connection closed before XHTTP stream was accepted",
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
                "XHTTP path mismatch: expected prefix '{}', got '{path}'",
                config.path
            ),
        ));
    }

    if let Some(ref expected_host) = config.host {
        let clean_expected = expected_host.trim();
        if !clean_expected.is_empty() {
            if let Some(auth) = request.uri().authority() {
                let clean_req = auth.host();
                let clean_exp = clean_expected.split(':').next().unwrap_or(clean_expected);
                if clean_req != clean_exp {
                    let resp = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(())
                        .unwrap();
                    let _ = respond.send_response(resp, true);
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("XHTTP host mismatch: expected '{expected_host}', got '{auth}'"),
                    ));
                }
            }
        }
    }

    // Build XHTTP stream-one response headers
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("cache-control", "no-store")
        .header("x-accel-buffering", "no")
        .header("content-type", "text/event-stream")
        .body(())
        .unwrap();

    let send_stream = respond.send_response(response, false).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to send XHTTP response: {e}"),
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

    Ok(Box::new(XHttpStreamWrapper {
        recv_stream,
        send_stream,
        read_buf: BytesMut::new(),
    }))
}

pub struct XHttpStreamWrapper {
    recv_stream: RecvStream,
    send_stream: h2::SendStream<Bytes>,
    read_buf: BytesMut,
}

impl AsyncRead for XHttpStreamWrapper {
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
                        format!("XHTTP recv error: {e}"),
                    )));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for XHttpStreamWrapper {
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
                    io::Error::new(io::ErrorKind::Other, format!("XHTTP send_data failed: {e}"))
                })?;

                Poll::Ready(Ok(chunk_size))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("XHTTP send capacity error: {e}"),
            ))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "XHTTP send stream closed",
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

async fn apply_xhttp_http1(
    mut stream: BoxedStream,
    initial_bytes: &[u8],
    config: &XHttpTransportConfig,
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
                "XHTTP path mismatch: expected prefix '{}', got '{req_path}'",
                config.path
            ),
        ));
    }

    if let Some(ref expected_host) = config.host {
        let clean_expected = expected_host.trim();
        if !clean_expected.is_empty() {
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
                let clean_exp = clean_expected.split(':').next().unwrap_or(clean_expected);
                if clean_req != clean_exp {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await;
                    return Err(io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("XHTTP host mismatch: expected '{expected_host}', got '{host_val}'"),
                    ));
                }
            }
        }
    }

    // Send HTTP/1.1 200 OK with chunked transfer encoding and SSE headers
    let response = b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nX-Accel-Buffering: no\r\nTransfer-Encoding: chunked\r\n\r\n";
    stream.write_all(response).await?;
    stream.flush().await?;

    let unconsumed = header_buf[end_idx + 4..].to_vec();
    let mut initial_read_buf = BytesMut::new();
    if !unconsumed.is_empty() {
        initial_read_buf.extend_from_slice(&unconsumed);
    }

    Ok(Box::new(XHttpChunkedStream {
        inner: stream,
        state: ChunkState::ReadingLength,
        read_buf: initial_read_buf,
        write_buf: BytesMut::new(),
        has_sent_eof: false,
    }))
}

#[derive(Debug, PartialEq, Eq)]
enum ChunkState {
    ReadingLength,
    ReadingData(usize),
    ReadingCrlf,
    ReadingTrailer,
    Eof,
}

pub struct XHttpChunkedStream<S> {
    inner: S,
    state: ChunkState,
    read_buf: BytesMut,
    write_buf: BytesMut,
    has_sent_eof: bool,
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> AsyncRead for XHttpChunkedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            match self.state {
                ChunkState::ReadingLength => {
                    if let Some(pos) = find_subslice(&self.read_buf, b"\r\n") {
                        let line = &self.read_buf[..pos];
                        let line_str = match std::str::from_utf8(line) {
                            Ok(s) => s,
                            Err(_) => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "invalid chunk length utf-8",
                                )));
                            }
                        };
                        let hex_str = line_str.split(';').next().unwrap_or("").trim();
                        let chunk_len = match usize::from_str_radix(hex_str, 16) {
                            Ok(n) => n,
                            Err(e) => {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    format!("invalid chunk hex '{hex_str}': {e}"),
                                )));
                            }
                        };
                        self.read_buf.advance(pos + 2);

                        if chunk_len == 0 {
                            self.state = ChunkState::ReadingTrailer;
                        } else {
                            self.state = ChunkState::ReadingData(chunk_len);
                        }
                    } else {
                        let mut temp = [0u8; 8192];
                        let mut temp_buf = ReadBuf::new(&mut temp);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut temp_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = temp_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Ok(()));
                                }
                                self.read_buf.extend_from_slice(temp_buf.filled());
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                }
                ChunkState::ReadingData(rem) => {
                    if !self.read_buf.is_empty() {
                        let to_copy = output.remaining().min(self.read_buf.len()).min(rem);
                        output.put_slice(&self.read_buf[..to_copy]);
                        self.read_buf.advance(to_copy);
                        let next_rem = rem - to_copy;
                        if next_rem == 0 {
                            self.state = ChunkState::ReadingCrlf;
                        } else {
                            self.state = ChunkState::ReadingData(next_rem);
                        }
                        return Poll::Ready(Ok(()));
                    } else {
                        let mut temp = [0u8; 16384];
                        let mut temp_buf = ReadBuf::new(&mut temp);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut temp_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = temp_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "unexpected EOF while reading chunk body",
                                    )));
                                }
                                self.read_buf.extend_from_slice(temp_buf.filled());
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                }
                ChunkState::ReadingCrlf => {
                    if self.read_buf.len() >= 2 {
                        self.read_buf.advance(2);
                        self.state = ChunkState::ReadingLength;
                    } else {
                        let mut temp = [0u8; 512];
                        let mut temp_buf = ReadBuf::new(&mut temp);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut temp_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = temp_buf.filled().len();
                                if n == 0 {
                                    return Poll::Ready(Err(io::Error::new(
                                        io::ErrorKind::UnexpectedEof,
                                        "unexpected EOF while reading chunk CRLF",
                                    )));
                                }
                                self.read_buf.extend_from_slice(temp_buf.filled());
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                }
                ChunkState::ReadingTrailer => {
                    if let Some(pos) = find_subslice(&self.read_buf, b"\r\n") {
                        if pos == 0 {
                            self.read_buf.advance(2);
                            self.state = ChunkState::Eof;
                            return Poll::Ready(Ok(()));
                        } else {
                            self.read_buf.advance(pos + 2);
                        }
                    } else {
                        let mut temp = [0u8; 512];
                        let mut temp_buf = ReadBuf::new(&mut temp);
                        match Pin::new(&mut self.inner).poll_read(cx, &mut temp_buf) {
                            Poll::Ready(Ok(())) => {
                                let n = temp_buf.filled().len();
                                if n == 0 {
                                    self.state = ChunkState::Eof;
                                    return Poll::Ready(Ok(()));
                                }
                                self.read_buf.extend_from_slice(temp_buf.filled());
                            }
                            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                            Poll::Pending => return Poll::Pending,
                        }
                    }
                }
                ChunkState::Eof => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Send + Unpin> AsyncWrite for XHttpChunkedStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        while !this.write_buf.is_empty() {
            let n = match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => {
                    tracing::warn!("XHttpChunkedStream: poll_write inner drain error: {:?}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            };
            this.write_buf.advance(n);
        }

        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        let chunk_size = data.len().min(65536);
        let header = format!("{:X}\r\n", chunk_size);
        this.write_buf.reserve(header.len() + chunk_size + 2);
        this.write_buf.extend_from_slice(header.as_bytes());
        this.write_buf.extend_from_slice(&data[..chunk_size]);
        this.write_buf.extend_from_slice(b"\r\n");

        while !this.write_buf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => this.write_buf.advance(n),
                Poll::Ready(Err(e)) => {
                    tracing::warn!("XHttpChunkedStream: poll_write inner send error: {:?}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => break,
            }
        }

        Poll::Ready(Ok(chunk_size))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.write_buf.is_empty() {
            let n = match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => {
                    tracing::warn!("XHttpChunkedStream: poll_flush inner drain error: {:?}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            };
            this.write_buf.advance(n);
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.has_sent_eof {
            this.has_sent_eof = true;
            this.write_buf.extend_from_slice(b"0\r\n\r\n");
        }
        while !this.write_buf.is_empty() {
            let n = match Pin::new(&mut this.inner).poll_write(cx, &this.write_buf) {
                Poll::Ready(Ok(n)) => n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            };
            this.write_buf.advance(n);
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }
}

fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}
