use crate::conn::BoxedStream;
use crate::transport::types::GrpcTransportConfig;
use bytes::{Buf, Bytes, BytesMut};
use h2::server;
use h2::RecvStream;
use http::{Response, StatusCode};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Implements Xray-compatible gRPC transport over HTTP/2.
/// Performs H2 handshake, accepts the gRPC Tun stream, validates service name,
/// and returns an AsyncRead + AsyncWrite stream that handles gRPC message framing.
pub async fn apply_grpc_transport(
    stream: BoxedStream,
    config: &GrpcTransportConfig,
) -> io::Result<BoxedStream> {
    let mut h2_builder = server::Builder::new();
    if config.initial_windows_size > 0 {
        h2_builder.initial_window_size(config.initial_windows_size);
    }

    let mut connection = h2_builder.handshake(stream).await.map_err(|e| {
        io::Error::new(
            io::ErrorKind::ConnectionReset,
            format!("H2 handshake failed: {e}"),
        )
    })?;

    // Accept incoming gRPC stream
    let (request, mut respond) = match connection.accept().await {
        Some(Ok(stream_pair)) => stream_pair,
        Some(Err(e)) => {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("failed to accept gRPC H2 stream: {e}"),
            ));
        }
        None => {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "H2 connection closed before gRPC stream was accepted",
            ));
        }
    };

    let path = request.uri().path();
    let expected_service = &config.service_name;

    // Upstream Xray paths: "/{service_name}/Tun" or "/{service_name}/TunMulti"
    // If service_name is empty, Xray allows "/Tun" or "/GunService/Tun"
    let valid_path = if expected_service.is_empty() {
        path.ends_with("/Tun") || path.ends_with("/TunMulti")
    } else {
        path == format!("/{expected_service}/Tun")
            || path == format!("/{expected_service}/TunMulti")
    };

    if !valid_path {
        let resp = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .unwrap();
        let _ = respond.send_response(resp, true);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!(
                "gRPC path mismatch: requested '{path}', expected service '{expected_service}'"
            ),
        ));
    }

    // Check authority if configured
    if let Some(ref expected_auth) = config.authority {
        if let Some(auth) = request.uri().authority() {
            let clean_req = auth.host();
            let clean_expected = expected_auth.split(':').next().unwrap_or(expected_auth);
            if clean_req != clean_expected {
                let resp = Response::builder()
                    .status(StatusCode::NOT_FOUND)
                    .body(())
                    .unwrap();
                let _ = respond.send_response(resp, true);
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("gRPC authority mismatch: expected '{expected_auth}', got '{auth}'"),
                ));
            }
        }
    }

    // Send HTTP 200 OK gRPC response
    let response = Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "application/grpc")
        .header("grpc-encoding", "identity")
        .body(())
        .unwrap();

    let send_stream = respond.send_response(response, false).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("failed to send gRPC response: {e}"),
        )
    })?;

    let recv_stream = request.into_body();

    // Spawn background H2 connection driver
    tokio::spawn(async move {
        while let Some(res) = connection.accept().await {
            if let Ok((_req, mut resp)) = res {
                // Return 200/empty for health checks if needed
                let r = Response::builder().status(StatusCode::OK).body(()).unwrap();
                let _ = resp.send_response(r, true);
            }
        }
    });

    Ok(Box::new(GrpcStreamWrapper {
        recv_stream,
        send_stream,
        read_buf: BytesMut::new(),
        raw_recv_buf: BytesMut::new(),
    }))
}

pub struct GrpcStreamWrapper {
    recv_stream: RecvStream,
    send_stream: h2::SendStream<Bytes>,
    read_buf: BytesMut,
    raw_recv_buf: BytesMut,
}

impl AsyncRead for GrpcStreamWrapper {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            // If we have unconsumed payload in read_buf, copy it to output
            if !self.read_buf.is_empty() {
                let n = output.remaining().min(self.read_buf.len());
                output.put_slice(&self.read_buf[..n]);
                self.read_buf.advance(n);
                return Poll::Ready(Ok(()));
            }

            // Read next HTTP/2 DATA frame from recv_stream
            match Pin::new(&mut self.recv_stream).poll_data(cx) {
                Poll::Ready(Some(Ok(chunk))) => {
                    let _ = self
                        .recv_stream
                        .flow_control()
                        .release_capacity(chunk.len());
                    self.raw_recv_buf.extend_from_slice(&chunk);

                    // Reassemble gRPC messages from raw_recv_buf
                    while self.raw_recv_buf.len() >= 5 {
                        let msg_len = u32::from_be_bytes([
                            self.raw_recv_buf[1],
                            self.raw_recv_buf[2],
                            self.raw_recv_buf[3],
                            self.raw_recv_buf[4],
                        ]) as usize;

                        if self.raw_recv_buf.len() < 5 + msg_len {
                            // Wait for subsequent H2 DATA frames to complete the message
                            break;
                        }

                        // Consume 5-byte gRPC header
                        self.raw_recv_buf.advance(5);
                        let msg_bytes = self.raw_recv_buf.split_to(msg_len).freeze();

                        // Decode protobuf Hunk: tag 1 (0x0a), varint length, data
                        if let Some(payload) = decode_protobuf_hunk(&msg_bytes) {
                            self.read_buf.extend_from_slice(payload);
                        } else {
                            // Raw fallback
                            self.read_buf.extend_from_slice(&msg_bytes);
                        }
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("gRPC recv error: {e}"),
                    )));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Ok(())); // EOF
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for GrpcStreamWrapper {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Check send capacity
        self.send_stream.reserve_capacity(data.len() + 16);
        match self.send_stream.poll_capacity(cx) {
            Poll::Ready(Some(Ok(avail))) => {
                let chunk_size = data.len().min(avail).min(16384);
                let to_send = &data[..chunk_size];

                // Encode protobuf Hunk: [0x0a, varint_len, payload]
                let mut pb = Vec::with_capacity(chunk_size + 10);
                pb.push(0x0a);
                encode_varint(chunk_size as u64, &mut pb);
                pb.extend_from_slice(to_send);

                // Encode gRPC frame: [0x00, msg_len: 4B, pb]
                let mut frame = Vec::with_capacity(pb.len() + 5);
                frame.push(0x00); // uncompressed
                frame.extend_from_slice(&(pb.len() as u32).to_be_bytes());
                frame.extend_from_slice(&pb);

                self.send_stream
                    .send_data(Bytes::from(frame), false)
                    .map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, format!("gRPC send_data failed: {e}"))
                    })?;

                Poll::Ready(Ok(chunk_size))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                format!("gRPC send capacity error: {e}"),
            ))),
            Poll::Ready(None) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "gRPC send stream closed",
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

fn encode_varint(mut val: u64, buf: &mut Vec<u8>) {
    while val >= 0x80 {
        buf.push((val as u8 & 0x7F) | 0x80);
        val >>= 7;
    }
    buf.push(val as u8);
}

fn decode_protobuf_hunk(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.is_empty() {
        return None;
    }
    let mut cursor = 0;
    while cursor < bytes.len() {
        let tag = bytes[cursor];
        cursor += 1;
        let field_number = tag >> 3;
        let wire_type = tag & 0x07;

        if field_number == 1 && wire_type == 2 {
            // Length-delimited string/bytes
            let (len, len_bytes) = read_varint(&bytes[cursor..])?;
            cursor += len_bytes;
            let end = cursor + len as usize;
            if end <= bytes.len() {
                return Some(&bytes[cursor..end]);
            }
        }
    }
    None
}

fn read_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0;
    for (i, &b) in bytes.iter().enumerate() {
        result |= ((b & 0x7F) as u64) << shift;
        if (b & 0x80) == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
        if shift > 64 {
            return None;
        }
    }
    None
}
