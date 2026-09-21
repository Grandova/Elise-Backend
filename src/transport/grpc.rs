use crate::conn::{AutoFlushingStream, BoxedStream};
use crate::transport::types::GrpcTransportConfig;
use bytes::{Buf, Bytes, BytesMut};
use h2::server;
use h2::RecvStream;
use http::{Response, StatusCode};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

fn validate_grpc_path(path: &str, clean_service: &str) -> bool {
    let clean_path = path.trim_matches('/');
    if clean_service.is_empty() || clean_service.eq_ignore_ascii_case("GunService") {
        true
    } else {
        clean_path.eq_ignore_ascii_case(clean_service)
            || clean_path
                .to_ascii_lowercase()
                .starts_with(&format!("{}/", clean_service.to_ascii_lowercase()))
            || clean_path
                .to_ascii_lowercase()
                .ends_with(&format!("/{}", clean_service.to_ascii_lowercase()))
            || path
                .to_ascii_lowercase()
                .contains(&clean_service.to_ascii_lowercase())
            || path.ends_with("/Tun")
            || path.ends_with("/TunMulti")
    }
}

fn validate_grpc_authority(
    request: &http::Request<RecvStream>,
    expected_auth: &Option<String>,
) -> bool {
    if let Some(ref auth) = expected_auth {
        let clean_expected = auth.trim();
        if !clean_expected.is_empty() {
            let req_host = request.uri().authority().map(|a| a.host()).or_else(|| {
                request
                    .headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .map(|h| h.split(':').next().unwrap_or(h))
            });

            if let Some(clean_req) = req_host {
                let clean_exp = clean_expected.split(':').next().unwrap_or(clean_expected);
                return clean_req.eq_ignore_ascii_case(clean_exp);
            }
            return false;
        }
    }
    true
}

pub async fn serve_grpc<F, Fut>(
    stream: BoxedStream,
    config: &GrpcTransportConfig,
    mut handler: F,
) -> io::Result<()>
where
    F: FnMut(BoxedStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    let mut h2_builder = server::Builder::new();
    let win_size = if config.initial_windows_size > 0 {
        config.initial_windows_size
    } else {
        4 * 1024 * 1024
    };
    h2_builder.initial_window_size(win_size);
    h2_builder.initial_connection_window_size(win_size * 2);
    h2_builder.max_concurrent_streams(1024);

    let stream = Box::new(AutoFlushingStream::new(stream));
    let mut connection = h2_builder.handshake(stream).await.map_err(|e| {
        io::Error::new(
            io::ErrorKind::ConnectionReset,
            format!("H2 handshake failed: {e}"),
        )
    })?;

    let clean_service = config.service_name.trim_matches('/').to_string();
    let mut tasks = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            result = tasks.join_next(), if !tasks.is_empty() => {
                if let Some(Err(e)) = result {
                    tracing::debug!("gRPC stream task ended with error: {e}");
                }
            }
            accept_res = connection.accept() => {
                let (request, mut respond) = match accept_res {
                    Some(Ok(pair)) => pair,
                    Some(Err(e)) => {
                        tracing::debug!("H2 connection accept ended: {e}");
                        break;
                    }
                    None => {

                        break;
                    }
                };

                let path = request.uri().path();
                if !validate_grpc_path(path, &clean_service) {
                    let resp = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(())
                        .unwrap();
                    let _ = respond.send_response(resp, true);
                    tracing::warn!("gRPC path mismatch: requested '{path}', expected service '{clean_service}'");
                    continue;
                }

                if !validate_grpc_authority(&request, &config.authority) {
                    let resp = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(())
                        .unwrap();
                    let _ = respond.send_response(resp, true);
                    tracing::warn!("gRPC authority mismatch for path '{path}'");
                    continue;
                }

                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header("content-type", "application/grpc")
                    .header("grpc-encoding", "identity")
                    .body(())
                    .unwrap();

                let send_stream = match respond.send_response(response, false) {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("failed to send gRPC response: {e}");
                        continue;
                    }
                };

                let recv_stream = request.into_body();
                let wrapped_stream = Box::new(GrpcStreamWrapper {
                    recv_stream,
                    send_stream,
                    read_buf: BytesMut::new(),
                    raw_recv_buf: BytesMut::new(),
                });

                let fut = handler(wrapped_stream);
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

pub async fn apply_grpc_transport(
    stream: BoxedStream,
    config: &GrpcTransportConfig,
) -> io::Result<BoxedStream> {
    let mut h2_builder = server::Builder::new();
    let win_size = if config.initial_windows_size > 0 {
        config.initial_windows_size
    } else {
        4 * 1024 * 1024
    };
    h2_builder.initial_window_size(win_size);
    h2_builder.initial_connection_window_size(win_size * 2);
    h2_builder.max_concurrent_streams(1024);

    let stream = Box::new(AutoFlushingStream::new(stream));
    let mut connection = h2_builder.handshake(stream).await.map_err(|e| {
        io::Error::new(
            io::ErrorKind::ConnectionReset,
            format!("H2 handshake failed: {e}"),
        )
    })?;

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
    let clean_service = config.service_name.trim_matches('/');

    if !validate_grpc_path(path, clean_service) {
        let resp = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .unwrap();
        let _ = respond.send_response(resp, true);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("gRPC path mismatch: requested '{path}', expected service '{clean_service}'"),
        ));
    }

    if !validate_grpc_authority(&request, &config.authority) {
        let resp = Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(())
            .unwrap();
        let _ = respond.send_response(resp, true);
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("gRPC authority mismatch for path '{path}'"),
        ));
    }

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
                    self.raw_recv_buf.extend_from_slice(&chunk);

                    while self.raw_recv_buf.len() >= 5 {
                        let msg_len = u32::from_be_bytes([
                            self.raw_recv_buf[1],
                            self.raw_recv_buf[2],
                            self.raw_recv_buf[3],
                            self.raw_recv_buf[4],
                        ]) as usize;

                        if self.raw_recv_buf.len() < 5 + msg_len {
                            break;
                        }

                        self.raw_recv_buf.advance(5);
                        let msg_bytes = self.raw_recv_buf.split_to(msg_len).freeze();

                        if let Some(payload) = decode_protobuf_hunk(&msg_bytes) {
                            self.read_buf.extend_from_slice(payload);
                        } else {
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
                    return Poll::Ready(Ok(()));
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

        let mut avail = self.send_stream.capacity();
        if avail <= 16 {
            self.send_stream
                .reserve_capacity((data.len() + 32).max(16384));
            match self.send_stream.poll_capacity(cx) {
                Poll::Ready(Some(Ok(new_cap))) => {
                    avail = new_cap;
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::ConnectionReset,
                        format!("gRPC send capacity error: {e}"),
                    )));
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "gRPC send stream closed",
                    )));
                }
                Poll::Pending => return Poll::Pending,
            }
        }

        if avail <= 16 {
            return Poll::Pending;
        }

        let max_payload = (avail - 16).min(data.len()).min(16384);
        let to_send = &data[..max_payload];

        let mut pb = Vec::with_capacity(to_send.len() + 10);
        pb.push(0x0a);
        encode_varint(to_send.len() as u64, &mut pb);
        pb.extend_from_slice(to_send);

        let mut frame = Vec::with_capacity(pb.len() + 5);
        frame.push(0x00);
        frame.extend_from_slice(&(pb.len() as u32).to_be_bytes());
        frame.extend_from_slice(&pb);

        self.send_stream
            .send_data(Bytes::from(frame), false)
            .map_err(|e| {
                io::Error::new(io::ErrorKind::Other, format!("gRPC send_data failed: {e}"))
            })?;

        if self.send_stream.capacity() < 32768 {
            self.send_stream.reserve_capacity(65536);
        }

        Poll::Ready(Ok(to_send.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
        let _ = self.send_stream.send_trailers(trailers);
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn test_grpc_protobuf_hunk_roundtrip() {
        let payload = b"hello vmess over grpc payload test 1234567890";
        let mut pb = Vec::new();
        pb.push(0x0a);
        encode_varint(payload.len() as u64, &mut pb);
        pb.extend_from_slice(payload);

        let decoded = decode_protobuf_hunk(&pb).expect("should decode successfully");
        assert_eq!(decoded, payload);
    }

    #[test]
    fn test_grpc_varint_encoding() {
        let mut buf = Vec::new();
        encode_varint(1, &mut buf);
        assert_eq!(buf, vec![1]);

        buf.clear();
        encode_varint(300, &mut buf);
        let (val, len) = read_varint(&buf).unwrap();
        assert_eq!(val, 300);
        assert_eq!(len, buf.len());
    }

    #[tokio::test]
    async fn test_grpc_transport_handshake_and_framing() {
        let (client, server) = tokio::io::duplex(65536);
        let config = GrpcTransportConfig {
            service_name: "TestService".to_string(),
            authority: None,
            multi_mode: false,
            idle_timeout: std::time::Duration::from_secs(10),
            health_check_timeout: std::time::Duration::from_secs(10),
            permit_without_stream: false,
            initial_windows_size: 65535,
        };

        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let server_task = tokio::spawn(async move {
            let mut stream = apply_grpc_transport(Box::new(server), &config)
                .await
                .expect("server grpc handshake");
            let mut buf = [0u8; 5];
            stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping!");
            stream.write_all(b"pong!").await.unwrap();
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
            .uri("http://localhost/TestService/Tun")
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .unwrap();

        let (response, mut send_stream) = client_h2.send_request(req, false).unwrap();
        let resp = response.await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);

        let mut pb = Vec::new();
        pb.push(0x0a);
        encode_varint(5, &mut pb);
        pb.extend_from_slice(b"ping!");

        let mut frame = Vec::new();
        frame.push(0x00);
        frame.extend_from_slice(&(pb.len() as u32).to_be_bytes());
        frame.extend_from_slice(&pb);

        send_stream.send_data(Bytes::from(frame), false).unwrap();

        let mut resp_body = resp.into_body();
        let chunk = resp_body.data().await.unwrap().unwrap();
        let decoded = decode_protobuf_hunk(&chunk[5..]).expect("decode response hunk");
        assert_eq!(decoded, b"pong!");

        let _ = done_tx.send(());
        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_grpc_transport_multiplexing() {
        let (client, server) = tokio::io::duplex(131072);
        let config = GrpcTransportConfig {
            service_name: "MultiService".to_string(),
            authority: None,
            multi_mode: true,
            idle_timeout: std::time::Duration::from_secs(10),
            health_check_timeout: std::time::Duration::from_secs(10),
            permit_without_stream: false,
            initial_windows_size: 65535,
        };

        let server_task = tokio::spawn(async move {
            serve_grpc(Box::new(server), &config, |mut stream| async move {
                let mut buf = vec![0u8; 13];
                stream.read_exact(&mut buf).await.unwrap();
                if &buf == b"hello_stream1" {
                    stream.write_all(b"world_stream1").await.unwrap();
                } else if &buf == b"hello_stream2" {
                    stream.write_all(b"world_stream2").await.unwrap();
                }
                stream.flush().await.unwrap();
                stream.shutdown().await.unwrap();
            })
            .await
            .expect("serve_grpc completed");
        });

        let (mut client_h2, conn) = h2::client::handshake(client)
            .await
            .expect("client h2 handshake");
        let conn_task = tokio::spawn(async move {
            let _ = conn.await;
        });

        async fn do_grpc_stream(
            client_h2: &mut h2::client::SendRequest<Bytes>,
            req_data: &[u8],
        ) -> Vec<u8> {
            let req = http::Request::builder()
                .method("POST")
                .uri("http://localhost/MultiService/Tun")
                .header("content-type", "application/grpc")
                .header("te", "trailers")
                .body(())
                .unwrap();

            let (response, mut send_stream) = client_h2.send_request(req, false).unwrap();
            let resp = response.await.unwrap();
            assert_eq!(resp.status(), http::StatusCode::OK);

            let mut pb = Vec::new();
            pb.push(0x0a);
            encode_varint(req_data.len() as u64, &mut pb);
            pb.extend_from_slice(req_data);

            let mut frame = Vec::new();
            frame.push(0x00);
            frame.extend_from_slice(&(pb.len() as u32).to_be_bytes());
            frame.extend_from_slice(&pb);

            send_stream.send_data(Bytes::from(frame), false).unwrap();

            let mut resp_body = resp.into_body();
            let chunk = resp_body.data().await.unwrap().unwrap();
            let decoded = decode_protobuf_hunk(&chunk[5..]).expect("decode response hunk");
            decoded.to_vec()
        }

        let resp1 = do_grpc_stream(&mut client_h2, b"hello_stream1").await;
        assert_eq!(&resp1, b"world_stream1");

        let resp2 = do_grpc_stream(&mut client_h2, b"hello_stream2").await;
        assert_eq!(&resp2, b"world_stream2");

        drop(client_h2);
        let _ = conn_task.await;
        server_task.abort();
    }
}
