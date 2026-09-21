pub mod grpc;
pub mod h2;
pub mod httpupgrade;
pub mod security;
pub mod tcp;
pub mod types;
pub mod websocket;
pub mod xhttp;

use crate::conn::BoxedStream;
use std::io;

pub use grpc::{apply_grpc_transport, serve_grpc};
pub use h2::{apply_h2_transport, serve_h2};
pub use httpupgrade::apply_httpupgrade_transport;
pub use security::apply_transport_security;
pub use tcp::apply_tcp_transport;
pub use types::{
    ClientTlsProfile, EchClientConfig, EchConfig, EchServerConfig, RealityClientProfile,
    RealityServerConfig, StreamSettings, TcpHeaderType, TcpHttpRequestConfig,
    TcpHttpResponseConfig, TcpTransportConfig, TlsCertificateEntry, TlsFingerprint,
    TlsServerConfig, TransportConfig, TransportSecurityConfig, TransportType,
};
pub use websocket::apply_websocket_transport;
pub use xhttp::apply_xhttp_transport;

pub async fn apply_transport(
    stream: BoxedStream,
    transport_cfg: &TransportConfig,
) -> io::Result<BoxedStream> {
    match transport_cfg {
        TransportConfig::Tcp(cfg) => apply_tcp_transport(stream, cfg).await,
        TransportConfig::WebSocket(cfg) => apply_websocket_transport(stream, cfg).await,
        TransportConfig::Grpc(cfg) => apply_grpc_transport(stream, cfg).await,
        TransportConfig::HttpUpgrade(cfg) => apply_httpupgrade_transport(stream, cfg).await,
        TransportConfig::XHttp(cfg) => apply_xhttp_transport(stream, cfg).await,
        TransportConfig::LegacyHttp2(cfg) => apply_h2_transport(stream, cfg).await,
        TransportConfig::MKcp(_) => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "mKCP is a datagram transport running directly on UDP listener, not applicable to stream socket",
        )),
    }
}

pub async fn serve_transport<F, Fut>(
    stream: BoxedStream,
    transport_cfg: &TransportConfig,
    tls_manager: Option<&crate::security::TLSManager>,
    handler: F,
) -> io::Result<()>
where
    F: FnMut(BoxedStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    match transport_cfg {
        TransportConfig::Grpc(cfg) => serve_grpc(stream, cfg, handler).await,
        TransportConfig::LegacyHttp2(cfg) => serve_h2(stream, cfg, tls_manager, handler).await,
        _ => {
            let mut handler = handler;
            let s = apply_transport(stream, transport_cfg).await?;
            handler(s).await;
            Ok(())
        }
    }
}
