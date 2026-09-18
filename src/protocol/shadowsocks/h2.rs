use crate::conn::BoxedStream;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::ready;
use prost::Message;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinSet;
use tokio_util::codec::{Decoder, Encoder, FramedRead, FramedWrite};
use tokio_util::io::{SinkWriter, StreamReader};
use tokio_util::sync::CancellationToken;

pub async fn serve<F, Fut>(
    stream: BoxedStream,
    path: &str,
    grpc: bool,
    cancel: CancellationToken,
    handle: F,
) -> io::Result<()>
where
    F: Fn(BoxedStream) -> Fut,
    Fut: Future<Output = io::Result<()>> + Send + 'static,
{
    let mut builder = h2::server::Builder::new();
    builder
        .max_concurrent_streams(64)
        .max_header_list_size(16384)
        .max_send_buffer_size(65536);
    let mut connection = tokio::select! {
        _ = cancel.cancelled() => return Ok(()),
        result = tokio::time::timeout(Duration::from_secs(15), builder.handshake::<_, Bytes>(stream)) => result.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "HTTP/2 handshake timeout"))?.map_err(io::Error::other)?,
    };
    let children = cancel.child_token();
    let mut tasks = JoinSet::new();
    let result = async {
        loop {
            tokio::select! {
                _ = cancel.cancelled() => return Ok(()),
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(error)) = result { tracing::warn!(%error, "HTTP/2 SS task failed"); }
                }
                request = connection.accept() => {
                    let Some(request) = request else { return Ok(()); };
                    let (request, mut response) = request.map_err(io::Error::other)?;
                    let method = if grpc { http::Method::POST } else { http::Method::PUT };
                    let status = if request.uri().path() != path { 404 } else if request.method() != method { 405 } else if grpc && !matches!(request.headers().get("content-type").and_then(|v| v.to_str().ok()), Some("application/grpc" | "application/grpc+proto")) { 415 } else { 200 };
                    let mut headers = http::Response::builder().status(status).header("cache-control", "no-store");
                    if grpc { headers = headers.header("content-type", "application/grpc"); }
                    if grpc && request.headers().get("grpc-encoding").is_some_and(|v| v != "identity") {
                        response.send_response(headers.header("grpc-status", "12").body(()).map_err(io::Error::other)?, true).map_err(io::Error::other)?;
                        continue;
                    }
                    let headers = headers.body(()).map_err(io::Error::other)?;
                    let send = response.send_response(headers, status != 200).map_err(io::Error::other)?;
                    if status != 200 { continue; }
                    let stream = Stream { recv: request.into_body(), send, buffered: Bytes::new(), closed: false, grpc };
                    let stream: BoxedStream = if grpc {
                        let (reader, writer) = tokio::io::split(stream);
                        Box::new(tokio::io::join(StreamReader::new(FramedRead::new(reader, Gun)), SinkWriter::new(FramedWrite::new(writer, Gun))))
                    } else { Box::new(stream) };
                    let task = handle(stream);
                    let child = children.clone();
                    tasks.spawn(async move {
                        tokio::select! {
                            _ = child.cancelled() => {},
                            result = task => if let Err(error) = result { tracing::debug!(%error, "HTTP/2 SS stream ended"); },
                        }
                    });
                }
            }
        }
    }.await;
    children.cancel();
    while tasks.join_next().await.is_some() {}
    result
}

struct Stream {
    recv: h2::RecvStream,
    send: h2::SendStream<Bytes>,
    buffered: Bytes,
    closed: bool,
    grpc: bool,
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        output: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if output.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.buffered.is_empty() {
                let n = output.remaining().min(self.buffered.len());
                output.put_slice(&self.buffered[..n]);
                self.buffered.advance(n);
                self.recv
                    .flow_control()
                    .release_capacity(n)
                    .map_err(io::Error::other)?;
                return Poll::Ready(Ok(()));
            }
            match ready!(self.recv.poll_data(cx)) {
                Some(Ok(data)) => self.buffered = data,
                Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
                None => return Poll::Ready(Ok(())),
            }
        }
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let wanted = data.len().min(16384);
        self.send.reserve_capacity(wanted);
        let available = match ready!(self.send.poll_capacity(cx)) {
            Some(Ok(n)) => n,
            Some(Err(error)) => return Poll::Ready(Err(io::Error::other(error))),
            None => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
        };
        let n = wanted.min(available);
        if n == 0 {
            cx.waker().wake_by_ref();
            return Poll::Pending;
        }
        self.send
            .send_data(Bytes::copy_from_slice(&data[..n]), false)
            .map_err(io::Error::other)?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        // HTTP/2 owns the queued bytes; the connection driver flushes them.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            if self.grpc {
                let mut trailers = http::HeaderMap::new();
                trailers.insert("grpc-status", http::HeaderValue::from_static("0"));
                self.send
                    .send_trailers(trailers)
                    .map_err(io::Error::other)?;
            } else {
                self.send
                    .send_data(Bytes::new(), true)
                    .map_err(io::Error::other)?;
            }
            self.closed = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        if self.grpc && !self.closed {
            let mut trailers = http::HeaderMap::new();
            trailers.insert("grpc-status", http::HeaderValue::from_static("13"));
            let _ = self.send.send_trailers(trailers);
        }
    }
}

#[derive(Clone, PartialEq, Message)]
struct Hunk {
    #[prost(bytes = "bytes", tag = "1")]
    data: Bytes,
}

struct Gun;

impl Decoder for Gun {
    type Item = Bytes;
    type Error = io::Error;
    fn decode(&mut self, src: &mut BytesMut) -> io::Result<Option<Bytes>> {
        if src.len() < 5 {
            return Ok(None);
        }
        if src[0] != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Compressed Gun messages are unsupported",
            ));
        }
        let length = u32::from_be_bytes(src[1..5].try_into().unwrap()) as usize;
        if length > 4 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Gun message exceeds 4 MiB",
            ));
        }
        if src.len() < length + 5 {
            return Ok(None);
        }
        src.advance(5);
        let message = Hunk::decode(src.split_to(length))
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(Some(message.data))
    }
}

impl Encoder<&[u8]> for Gun {
    type Error = io::Error;
    fn encode(&mut self, data: &[u8], dst: &mut BytesMut) -> io::Result<()> {
        let message = Hunk {
            data: Bytes::copy_from_slice(data),
        };
        let length = message.encoded_len();
        if length > 4 * 1024 * 1024 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Gun message exceeds 4 MiB",
            ));
        }
        dst.put_u8(0);
        dst.put_u32(length as u32);
        message.encode(dst).map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn gun_rejects_compression_oversize_truncation_and_bad_protobuf() {
        let frame = [0, 0, 0, 0, 5, 0x0a, 3, b'a', b'b', b'c'];
        for end in 1..frame.len() {
            let mut buffer = BytesMut::from(&frame[..end]);
            assert!(Gun.decode(&mut buffer).unwrap().is_none());
            assert!(Gun.decode_eof(&mut buffer).is_err());
        }
        assert_eq!(
            Gun.decode(&mut BytesMut::from(&frame[..]))
                .unwrap()
                .unwrap(),
            &b"abc"[..]
        );
        for invalid in [
            &[1, 0, 0, 0, 0][..],
            &[0, 0, 0x40, 0, 1],
            &[0, 0, 0, 0, 2, 0x0a, 9],
        ] {
            assert!(Gun.decode(&mut BytesMut::from(invalid)).is_err());
        }
    }

    #[tokio::test]
    async fn gun_fin_returns_data_and_status_trailer() {
        let (client, server) = tokio::io::duplex(65536);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(serve(
            Box::new(server),
            "/GunService/Tun",
            true,
            cancel.clone(),
            |mut stream| async move {
                let mut data = Vec::new();
                stream.read_to_end(&mut data).await?;
                stream.write_all(&data).await?;
                stream.shutdown().await
            },
        ));
        let (mut client, connection) = h2::client::handshake(client).await.unwrap();
        let driver = tokio::spawn(connection);
        let request = http::Request::builder()
            .method("POST")
            .uri("https://localhost/GunService/Tun")
            .header("content-type", "application/grpc")
            .header("te", "trailers")
            .body(())
            .unwrap();
        let (response, mut send) = client.send_request(request, false).unwrap();
        // Empty Hunk followed by Hunk { data: "abc" }.
        send.send_data(
            Bytes::from_static(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 5, 0x0a, 3, b'a', b'b', b'c']),
            true,
        )
        .unwrap();
        let response = response.await.unwrap();
        assert_eq!(response.status(), 200);
        let mut body = response.into_body();
        let mut data = Vec::new();
        while let Some(chunk) = body.data().await {
            let chunk = chunk.unwrap();
            data.extend_from_slice(&chunk);
            body.flow_control().release_capacity(chunk.len()).unwrap();
        }
        assert_eq!(data, &[0, 0, 0, 0, 5, 0x0a, 3, b'a', b'b', b'c']);
        assert_eq!(body.trailers().await.unwrap().unwrap()["grpc-status"], "0");
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        driver.abort();
        let _ = driver.await;
    }

    #[tokio::test]
    async fn h2_end_stream_keeps_response_and_checks_request() {
        let (client, server) = tokio::io::duplex(65536);
        let cancel = CancellationToken::new();
        let task = tokio::spawn(serve(
            Box::new(server),
            "/ss",
            false,
            cancel.clone(),
            |mut stream| async move {
                let mut data = Vec::new();
                stream.read_to_end(&mut data).await?;
                stream.write_all(&data).await?;
                stream.shutdown().await
            },
        ));
        let (mut client, connection) = h2::client::handshake(client).await.unwrap();
        let driver = tokio::spawn(connection);
        for (method, path, status) in [
            ("PUT", "/wrong", 404),
            ("GET", "/ss", 405),
            ("PUT", "/ss", 200),
        ] {
            let request = http::Request::builder()
                .method(method)
                .uri(format!("https://localhost{path}"))
                .body(())
                .unwrap();
            let (response, mut send) = client.send_request(request, false).unwrap();
            send.send_data(Bytes::from_static(b"after FIN"), true)
                .unwrap();
            let response = response.await.unwrap();
            assert_eq!(response.status().as_u16(), status);
            if status == 200 {
                let mut body = response.into_body();
                let mut data = Vec::new();
                while let Some(chunk) = body.data().await {
                    let chunk = chunk.unwrap();
                    data.extend_from_slice(&chunk);
                    body.flow_control().release_capacity(chunk.len()).unwrap();
                }
                assert_eq!(data, b"after FIN");
            }
        }
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        driver.abort();
        let _ = driver.await;
    }
}
