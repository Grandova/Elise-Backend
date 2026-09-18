pub mod config;
pub mod quic;
pub mod v4;
pub mod v5;

pub use config::{
    EchClientConfig, EchServerConfig, TuicClientProfile, TuicCongestionControl, TuicCredential,
    TuicNodeConfig, TuicProtocolVersion, TuicRuntimeConfig, TuicTlsConfig, TuicUdpRelayMode,
    TuicUsers,
};
pub use quic::create_tuic_endpoint;
pub use v4::{TuicV4Address, TuicV4RelayMode, TuicV4Session, TUIC_V4_VERSION};
pub use v5::{TuicV5Address, TuicV5RelayMode, TuicV5Session, TUIC_V5_VERSION};

use crate::panel::types::{NodeInfo, User};
use crate::protocol::{Inbound, InboundContext};
use async_trait::async_trait;
use parking_lot::RwLock;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

pub struct TuicInbound {
    users: Arc<RwLock<TuicUsers>>,
    version: Arc<RwLock<TuicProtocolVersion>>,
}

impl Default for TuicInbound {
    fn default() -> Self {
        Self {
            users: Arc::new(RwLock::new(TuicUsers::default())),
            version: Arc::new(RwLock::new(TuicProtocolVersion::V5)),
        }
    }
}

impl TuicInbound {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Inbound for TuicInbound {
    fn protocol_type(&self) -> &'static str {
        "tuic"
    }

    fn update_users(&self, users: Vec<User>) {
        let version = *self.version.read();
        // Users are loaded before start() selects the configured protocol version.
        let mut new_users = TuicUsers::from_users(users.clone(), TuicProtocolVersion::V4);
        new_users.v5_users = TuicUsers::from_users(users, TuicProtocolVersion::V5).v5_users;
        *self.users.write() = new_users;
        debug!(
            "TUIC user snapshot updated (protocol version: {:?})",
            version
        );
    }

    async fn start(
        &self,
        ctx: InboundContext,
        node_info: NodeInfo,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> io::Result<()> {
        let config = TuicNodeConfig::from_node_info(&node_info, &ctx.listen_addr, ctx.port)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

        *self.version.write() = config.protocol;

        let bind_addr = format!("{}:{}", ctx.listen_addr, ctx.port);
        let std_socket = std::net::UdpSocket::bind(&bind_addr)?;
        std_socket.set_nonblocking(true)?;

        let endpoint = create_tuic_endpoint(
            std_socket,
            &config.tls,
            config.congestion,
            config.runtime.zero_rtt,
        )?;

        info!(
            "TUIC inbound listening on UDP {} (protocol: {:?}, congestion: {:?}, ALPN: {:?})",
            bind_addr,
            config.protocol,
            config.congestion,
            config
                .tls
                .alpn
                .iter()
                .map(|a| String::from_utf8_lossy(a).to_string())
                .collect::<Vec<_>>()
        );

        let cancel = CancellationToken::new();
        let mut conn_join_set = JoinSet::new();
        let protocol_version = config.protocol;
        let auth_timeout = config.runtime.auth_timeout;

        ctx.mark_ready();
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    info!("TUIC inbound on port {} stopping", ctx.port);
                    break;
                }
                Some(incoming) = endpoint.accept() => {
                    let ctx = ctx.clone();
                    let users = self.users.clone();
                    let cancel = cancel.clone();

                    conn_join_set.spawn(async move {
                        let connecting = match incoming.await {
                            Ok(c) => c,
                            Err(e) => {
                                debug!("TUIC QUIC handshake failed: {:?}", e);
                                return;
                            }
                        };

                        let remote_addr = connecting.remote_address();
                        let client_ip = remote_addr.ip();
                        if ctx.defense.is_banned(client_ip) {
                            let _ = connecting.close(quinn::VarInt::from_u32(0x101), b"Banned");
                            return;
                        }

                        match protocol_version {
                            TuicProtocolVersion::V4 => {
                                let v4_tokens = Arc::new(users.read().v4_tokens.clone());
                                let session = Arc::new(TuicV4Session::new(
                                    connecting,
                                    ctx,
                                    v4_tokens,
                                    auth_timeout,
                                    remote_addr,
                                    cancel,
                                ));
                                session.run().await;
                            }
                            TuicProtocolVersion::V5 => {
                                let v5_users = Arc::new(users.read().v5_users.clone());
                                let session = Arc::new(TuicV5Session::new(
                                    connecting,
                                    ctx,
                                    v5_users,
                                    auth_timeout,
                                    remote_addr,
                                    cancel,
                                ));
                                session.run().await;
                            }
                        }
                    });

                    // Periodically reap completed connection tasks
                    while conn_join_set.try_join_next().is_some() {}
                }
            }
        }

        // Graceful Drain: cancel -> timeout -> abort
        cancel.cancel();
        endpoint.close(quinn::VarInt::from_u32(0), b"Server Shutdown");

        let drain_timeout = Duration::from_secs(3);
        let _ = tokio::time::timeout(drain_timeout, async {
            while let Some(res) = conn_join_set.join_next().await {
                if let Err(e) = res {
                    if !e.is_cancelled() {
                        debug!("TUIC connection task ended with error: {:?}", e);
                    }
                }
            }
        })
        .await;

        conn_join_set.abort_all();
        while conn_join_set.join_next().await.is_some() {}
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_update_before_start_populates_both_versions() {
        let inbound = TuicInbound::new();
        inbound.update_users(vec![User {
            id: 42,
            uuid: "12345678-1234-4234-9234-123456789042".into(),
            password: Some("fixture".into()),
            ..Default::default()
        }]);
        assert_eq!(inbound.users.read().v4_tokens.len(), 1);
        assert_eq!(inbound.users.read().v5_users.len(), 1);
        inbound.update_users(Vec::new());
        assert!(inbound.users.read().v4_tokens.is_empty());
        assert!(inbound.users.read().v5_users.is_empty());
    }
}
