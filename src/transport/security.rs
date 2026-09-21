use crate::conn::BoxedStream;
use crate::security::reality::{RealityHandshakeResult, RealityServer};
use crate::security::TLSManager;
use crate::transport::types::TransportSecurityConfig;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

pub async fn apply_transport_security(
    stream: BoxedStream,
    remote_addr: SocketAddr,
    security_cfg: &TransportSecurityConfig,
    tls_manager: Option<&TLSManager>,
    reality_server: Option<&RealityServer>,
    alpn: Vec<Vec<u8>>,
) -> io::Result<Option<BoxedStream>> {
    match security_cfg {
        TransportSecurityConfig::None => Ok(Some(stream)),
        TransportSecurityConfig::Tls(_) => {
            let mgr = tls_manager.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "TLSManager not initialized for TLS security configuration",
                )
            })?;
            let tls_stream = mgr
                .accept_with_timeout(stream, Duration::from_secs(15))
                .await
                .map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        format!("TLS handshake failed: {e}"),
                    )
                })?;
            let drainable = crate::conn::DrainableTlsStream::new(tls_stream);
            Ok(Some(Box::new(drainable)))
        }
        TransportSecurityConfig::Reality(_) => {
            let r_server = reality_server.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::Other,
                    "RealityServer not initialized for REALITY security configuration",
                )
            })?;
            match r_server.accept(stream, remote_addr, alpn).await? {
                RealityHandshakeResult::Authenticated(s) => Ok(Some(s)),
                RealityHandshakeResult::Fallbacked => Ok(None),
            }
        }
    }
}
