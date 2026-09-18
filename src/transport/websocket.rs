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
    let callback = |request: &Request, response: Response| {
        // 1. Path validation
        if request.uri().path() != expected_path {
            return Err(tokio_tungstenite::tungstenite::http::Response::builder()
                .status(404)
                .body(None)
                .unwrap());
        }

        // 2. Host header validation
        if let Some(ref h) = expected_host {
            let host_header = request.headers().get("host").and_then(|v| v.to_str().ok());
            let clean_host = host_header.map(|s| s.split(':').next().unwrap_or(s));
            let clean_expected = h.split(':').next().unwrap_or(h);
            if clean_host != Some(clean_expected) {
                return Err(tokio_tungstenite::tungstenite::http::Response::builder()
                    .status(404)
                    .body(None)
                    .unwrap());
            }
        }

        // 3. Custom headers validation
        for (k, v) in &expected_headers {
            let hdr_val = request.headers().get(k).and_then(|val| val.to_str().ok());
            if hdr_val != Some(v.as_str()) {
                return Err(tokio_tungstenite::tungstenite::http::Response::builder()
                    .status(400)
                    .body(None)
                    .unwrap());
            }
        }

        // 4. Early data extraction
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
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Sink::poll_flush(Pin::new(&mut self.socket), cx).map_err(io::Error::other)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Sink::poll_close(Pin::new(&mut self.socket), cx).map_err(io::Error::other)
    }
}
