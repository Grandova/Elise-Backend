pub mod auth;
pub mod server;
pub mod tcp;
pub mod udp;

use crate::conn::bind_tcp_listener;
use crate::panel::types::{NodeInfo, User};
use crate::protocol::{Inbound, InboundContext};
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use tracing::{info, warn};

pub use server::handle_connection;

pub struct SocksInbound {
    users: Arc<RwLock<HashMap<String, User>>>,
}

impl Default for SocksInbound {
    fn default() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl SocksInbound {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Inbound for SocksInbound {
    fn protocol_type(&self) -> &'static str {
        "socks"
    }

    fn update_users(&self, users: Vec<User>) {
        let mut map = HashMap::new();
        for u in users {
            // Index by ID string and by UUID for flexible SOCKS5 username matching
            map.insert(u.id.to_string(), u.clone());
            map.insert(u.uuid.clone(), u);
        }
        *self.users.write() = map;
    }

    async fn start(
        &self,
        ctx: InboundContext,
        _node_info: NodeInfo,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> io::Result<()> {
        let bind_addr = format!("{}:{}", ctx.listen_addr, ctx.port);
        let listener = bind_tcp_listener(&bind_addr, ctx.global_config.mptcp).await?;
        info!("SOCKS5 inbound listening on {}", bind_addr);

        let users = self.users.clone();

        let mut connections = tokio::task::JoinSet::new();
        ctx.mark_ready();
        loop {
            tokio::select! {
                result = connections.join_next(), if !connections.is_empty() => {
                    if let Some(Err(e)) = result { tracing::warn!(error = %e, "Connection task failed"); }
                }
                _ = shutdown_rx.recv() => {
                    info!("SOCKS5 inbound on port {} stopping", ctx.port);
                    break;
                }
                accept_res = listener.accept() => {
                    let (stream, peer_addr) = match accept_res {
                        Ok(conn) => conn,
                        Err(e) => {
                            warn!("SOCKS5 accept error: {:?}", e);
                            continue;
                        }
                    };
                    let _ = stream.set_nodelay(true);

                    let ctx = ctx.clone();
                    let users = users.clone();
                    connections.spawn(async move {
                        if let Err(e) = handle_connection(stream, peer_addr, ctx, users).await {
                            tracing::debug!("SOCKS5 connection from {} closed: {:?}", peer_addr, e);
                        }
                    });
                }
            }
        }
        drop(listener);
        crate::protocol::common::inbound::drain_connections(&mut connections).await;
        Ok(())
    }
}
