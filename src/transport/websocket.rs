use crate::conn::{BoxedStream, PrefixedStream};
use crate::transport::types::WebSocketTransportConfig;
use base64::Engine;
use bytes::{Buf, Bytes};
use futures_util::{ready, Sink, Stream};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;

pub async fn apply_websocket_transport(
    stream: BoxedStream,
    config: &WebSocketTransportConfig,
) -> io::Result<BoxedStream> {
    let expected_path = config.path.clone();
    let expected_host = config.host.clone();
    let expected_headers = config.headers.clone();
    let early_header_name = config
        .early_data_header
        .clone()
        .unwrap_or_else(|| "sec-websocket-protocol".to_string())
        .to_ascii_lowercase();
    let max_early_data = if config.max_early_data > 0 {
        config.max_early_data as usize
    } else {
        8192
    };

    let mut early_data = Vec::new();

    #[allow(clippy::result_large_err)]
    let callback = |request: &Request, mut response: Response| {
        let host_header = request.headers().get("host").and_then(|v| v.to_str().ok());
        tracing::debug!(
            "WebSocket handshake incoming: URI='{}', Host={host_header:?}, Sec-WebSocket-Protocol={:?}",
            request.uri(),
            request.headers().get("sec-websocket-protocol")
        );

        let req_path = request
            .uri()
            .path()
            .split('?')
            .next()
            .unwrap_or("")
            .trim_matches('/');
        let exp_path = expected_path
            .split('?')
            .next()
            .unwrap_or(&expected_path)
            .trim_matches('/');
        if req_path != exp_path {
            tracing::warn!(
                "WebSocket handshake rejected: path mismatch. Client requested '{}' (normalized '{}'), server expected '{}' (normalized '{}')",
                request.uri().path(),
                req_path,
                expected_path,
                exp_path
            );
            return Err(tokio_tungstenite::tungstenite::http::Response::builder()
                .status(404)
                .body(None)
                .unwrap());
        }

        if let Some(ref h) = expected_host {
            let clean_expected = h.trim();
            if !clean_expected.is_empty() {
                let clean_host = host_header.map(|s| {
                    s.rsplit_once(':')
                        .filter(|(_, port)| port.parse::<u16>().is_ok())
                        .map_or(s, |(h, _)| h)
                        .trim()
                });
                let clean_exp = clean_expected
                    .rsplit_once(':')
                    .filter(|(_, port)| port.parse::<u16>().is_ok())
                    .map_or(clean_expected, |(h, _)| h)
                    .trim();
                if !clean_exp.is_empty()
                    && !clean_host.is_some_and(|actual| actual.eq_ignore_ascii_case(clean_exp))
                {
                    tracing::warn!(
                        "WebSocket handshake rejected: host mismatch. Client sent Host={host_header:?} (normalized {clean_host:?}), server expected '{clean_exp}'"
                    );
                    return Err(tokio_tungstenite::tungstenite::http::Response::builder()
                        .status(404)
                        .body(None)
                        .unwrap());
                }
            }
        }

        for (k, v) in &expected_headers {
            if k.eq_ignore_ascii_case("host") {
                continue;
            }
            let hdr_val = request.headers().get(k).and_then(|val| val.to_str().ok());
            if hdr_val != Some(v.as_str()) {
                tracing::warn!(
                    "WebSocket handshake rejected: custom header '{k}' mismatch. Client sent {hdr_val:?}, expected '{v}'"
                );
                return Err(tokio_tungstenite::tungstenite::http::Response::builder()
                    .status(400)
                    .body(None)
                    .unwrap());
            }
        }

        if let Some(early_val) = request
            .headers()
            .get(&early_header_name)
            .and_then(|v| v.to_str().ok())
        {
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(early_val.as_bytes())
                .or_else(|_| {
                    base64::engine::general_purpose::STANDARD.decode(early_val.as_bytes())
                });

            match decoded {
                Ok(bytes) if bytes.len() <= max_early_data => {
                    early_data = bytes;
                }
                _ => {
                    return Err(tokio_tungstenite::tungstenite::http::Response::builder()
                        .status(400)
                        .body(None)
                        .unwrap());
                }
            }
        }

        if let Some(proto) = request.headers().get("sec-websocket-protocol") {
            response
                .headers_mut()
                .insert("sec-websocket-protocol", proto.clone());
        }

        Ok(response)
    };

    let mut ws_config = WebSocketConfig::default();
    ws_config.max_message_size = Some(1024 * 1024);
    ws_config.max_frame_size = Some(1024 * 1024);

    let socket = tokio_tungstenite::accept_hdr_async_with_config(stream, callback, Some(ws_config))
        .await
        .map_err(io::Error::other)?;

    let ws = WebSocketStreamWrapper {
        socket,
        buffered: Bytes::new(),
    };

    if !early_data.is_empty() {
        Ok(Box::new(PrefixedStream::new(ws, Some(early_data))))
    } else {
        Ok(Box::new(ws))
    }
}

pub struct WebSocketStreamWrapper<S> {
    socket: tokio_tungstenite::WebSocketStream<S>,
    buffered: Bytes,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for WebSocketStreamWrapper<S> {
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
                return Poll::Ready(Ok(()));
            }
            match ready!(Stream::poll_next(Pin::new(&mut self.socket), cx)) {
                Some(Ok(Message::Binary(data))) => self.buffered = data,
                None | Some(Ok(Message::Close(_))) => return Poll::Ready(Ok(())),
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Ok(_)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Expected binary WebSocket frame in transport",
                    )));
                }
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for WebSocketStreamWrapper<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        ready!(Sink::poll_ready(Pin::new(&mut self.socket), cx)).map_err(io::Error::other)?;
        let n = data.len().min(16384);
        Sink::start_send(
            Pin::new(&mut self.socket),
            Message::Binary(Bytes::copy_from_slice(&data[..n])),
        )
        .map_err(io::Error::other)?;
        let _ = Sink::poll_flush(Pin::new(&mut self.socket), cx);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Sink::poll_flush(Pin::new(&mut self.socket), cx).map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Sink::poll_close(Pin::new(&mut self.socket), cx).map_err(io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::client_async;

    #[tokio::test]
    async fn test_websocket_transport_handshake_and_subprotocol() {
        let (client, server) = tokio::io::duplex(4096);
        let config = WebSocketTransportConfig {
            path: "/vmess-ws".to_string(),
            host: Some("example.com".to_string()),
            headers: std::collections::HashMap::new(),
            heartbeat_period: None,
            early_data_header: None,
            max_early_data: 2048,
        };

        let early_bytes = b"early_123";
        let early_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(early_bytes);

        let server_task = tokio::spawn(async move {
            let mut ws_stream = apply_websocket_transport(Box::new(server), &config)
                .await
                .expect("server ws handshake should succeed");

            let mut early_buf = [0u8; 9];
            ws_stream.read_exact(&mut early_buf).await.unwrap();
            assert_eq!(&early_buf, b"early_123");

            let mut frame_buf = [0u8; 10];
            ws_stream.read_exact(&mut frame_buf).await.unwrap();
            assert_eq!(&frame_buf, b"ping-hello");

            ws_stream.write_all(b"pong-world").await.unwrap();
            ws_stream.flush().await.unwrap();
        });

        let req = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri("ws://example.com/vmess-ws/")
            .header("Host", "example.com")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Protocol", &early_b64)
            .body(())
            .unwrap();

        let (mut client_ws, response) = client_async(req, client).await.expect("client handshake");
        assert_eq!(
            response
                .headers()
                .get("sec-websocket-protocol")
                .and_then(|v| v.to_str().ok()),
            Some(early_b64.as_str())
        );

        client_ws
            .send(Message::Binary(Bytes::from_static(b"ping-hello")))
            .await
            .unwrap();

        let msg = client_ws.next().await.unwrap().unwrap();
        assert_eq!(msg, Message::Binary(Bytes::from_static(b"pong-world")));

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_websocket_transport_accepts_any_host_when_unconfigured() {
        let (client, server) = tokio::io::duplex(4096);
        let config = WebSocketTransportConfig {
            path: "/".to_string(),
            host: None,
            headers: std::collections::HashMap::new(),
            heartbeat_period: None,
            early_data_header: None,
            max_early_data: 0,
        };

        let server_task = tokio::spawn(async move {
            let mut ws_stream = apply_websocket_transport(Box::new(server), &config)
                .await
                .expect("server ws handshake should succeed when host is None");

            let mut buf = [0u8; 4];
            ws_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");

            ws_stream.write_all(b"pong").await.unwrap();
            ws_stream.flush().await.unwrap();
        });

        let req = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri("ws://192.0.2.1:8000/")
            .header("Host", "example.com:8000")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(())
            .unwrap();

        let (mut client_ws, _resp) = client_async(req, client).await.expect("client handshake");
        client_ws
            .send(Message::Binary(Bytes::from_static(b"ping")))
            .await
            .unwrap();

        let msg = client_ws.next().await.unwrap().unwrap();
        assert_eq!(msg, Message::Binary(Bytes::from_static(b"pong")));

        server_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_websocket_transport_host_with_port_and_query_param() {
        let (client, server) = tokio::io::duplex(4096);
        let config = WebSocketTransportConfig {
            path: "/trojan-ws".to_string(),
            host: Some("example.com".to_string()),
            headers: std::collections::HashMap::new(),
            heartbeat_period: None,
            early_data_header: None,
            max_early_data: 0,
        };

        let server_task = tokio::spawn(async move {
            let mut ws_stream = apply_websocket_transport(Box::new(server), &config)
                .await
                .expect("server ws handshake should succeed with query param and port");

            let mut buf = [0u8; 4];
            ws_stream.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"test");

            ws_stream.write_all(b"ok!!").await.unwrap();
            ws_stream.flush().await.unwrap();
        });

        let req = tokio_tungstenite::tungstenite::handshake::client::Request::builder()
            .uri("ws://example.com:8000/trojan-ws?ed=2048")
            .header("Host", "example.com:8000")
            .header("Connection", "Upgrade")
            .header("Upgrade", "websocket")
            .header("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
            .header("Sec-WebSocket-Version", "13")
            .body(())
            .unwrap();

        let (mut client_ws, _resp) = client_async(req, client).await.expect("client handshake");
        client_ws
            .send(Message::Binary(Bytes::from_static(b"test")))
            .await
            .unwrap();

        let msg = client_ws.next().await.unwrap().unwrap();
        assert_eq!(msg, Message::Binary(Bytes::from_static(b"ok!!")));

        server_task.await.unwrap();
    }
}
