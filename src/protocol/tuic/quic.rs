use super::config::{TuicCongestionControl, TuicTlsConfig};
use quinn::VarInt;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::info;

pub struct QuicStream {
    pub read: quinn::RecvStream,
    pub write: quinn::SendStream,
}

impl QuicStream {
    pub fn new(read: quinn::RecvStream, write: quinn::SendStream) -> Self {
        Self { read, write }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.read).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.write), cx, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.write), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.write), cx)
    }
}

pub fn create_tuic_endpoint(
    socket: std::net::UdpSocket,
    tls_config: &TuicTlsConfig,
    congestion: TuicCongestionControl,
    zero_rtt: bool,
) -> io::Result<quinn::Endpoint> {
    let mut rustls_cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            tls_config.certificates.clone(),
            tls_config.private_key.clone_key(),
        )
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

    rustls_cfg.alpn_protocols = tls_config.alpn.clone();
    rustls_cfg.max_early_data_size = if zero_rtt { 0xffffffff } else { 0 };

    let quic_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(rustls_cfg).map_err(io::Error::other)?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));

    let mut transport = quinn::TransportConfig::default();

    match congestion {
        TuicCongestionControl::Bbr => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
            info!("TUIC congestion controller = BBR");
        }
        TuicCongestionControl::Cubic => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
            info!("TUIC congestion controller = CUBIC");
        }
        TuicCongestionControl::NewReno => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
            info!("TUIC congestion controller = NEW_RENO");
        }
    }

    transport
        .max_concurrent_bidi_streams(VarInt::from_u32(10000))
        .max_concurrent_uni_streams(VarInt::from_u32(10000))
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()))
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .stream_receive_window(VarInt::from_u32(8 * 1024 * 1024))
        .receive_window(VarInt::from_u32(20 * 1024 * 1024))
        .send_window(20 * 1024 * 1024);

    transport.datagram_receive_buffer_size(Some(1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    transport.max_datagram_frame_size(Some(VarInt::from_u32(1400)));

    server_config.transport_config(Arc::new(transport));

    let runtime = Arc::new(quinn::TokioRuntime);
    let endpoint = quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        runtime,
    )?;

    Ok(endpoint)
}
