pub mod crypto;
pub mod pattern;
pub mod proto;
pub mod relay;
pub mod session;
pub mod tcp;
pub mod udp;

pub use crypto::{
    check_user_hint, compute_user_hint, hash_password, pbkdf2_sha256_32, salts_from_time,
    MieruUser, MieruUserIndex,
};
pub use pattern::TrafficPatternExecutor;
pub use proto::TrafficPattern;
pub use session::{MieruSessionReader, MieruSessionState, MieruSessionWriter, MieruStreamCipher};

use crate::panel::types::{NodeInfo, User};
use crate::protocol::{Inbound, InboundContext};
use async_trait::async_trait;
use parking_lot::RwLock;
use std::io;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::{error, info};

pub struct MieruInbound {
    users: Arc<RwLock<MieruUserIndex>>,
}

impl Default for MieruInbound {
    fn default() -> Self {
        Self {
            users: Arc::new(RwLock::new(MieruUserIndex::new(Vec::new()))),
        }
    }
}

impl MieruInbound {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Inbound for MieruInbound {
    fn protocol_type(&self) -> &'static str {
        "mieru"
    }

    fn update_users(&self, users: Vec<User>) {
        let new_index = MieruUserIndex::new(users);
        *self.users.write() = new_index;
    }

    async fn start(
        &self,
        ctx: InboundContext,
        node_info: NodeInfo,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> io::Result<()> {
        // 1. Parse TrafficPattern if configured
        let local_pattern = ctx
            .global_config
            .raw_properties
            .get("mieru_traffic_pattern")
            .filter(|value| !value.trim().is_empty());
        let pattern_opt = if let Some(tp_str) = local_pattern.or(node_info.traffic_pattern.as_ref())
        {
            match TrafficPattern::from_base64(tp_str) {
                Ok(p) => {
                    info!(
                        node_id = ctx.node_id,
                        source = if local_pattern.is_some() {
                            "local"
                        } else {
                            "panel"
                        },
                        "Loaded Mieru TrafficPattern configuration"
                    );
                    p
                }
                Err(e) => {
                    error!(
                        "Node {}: Invalid traffic_pattern Base64 or Protobuf payload: {:?}",
                        ctx.node_id, e
                    );
                    return Err(e);
                }
            }
        } else {
            None
        };

        let pattern_exec = Arc::new(TrafficPatternExecutor::new(pattern_opt));

        // 2. Determine Transport: TCP or UDP
        let transport = node_info
            .transport
            .as_deref()
            .or_else(|| node_info.network.as_deref())
            .unwrap_or("TCP")
            .to_ascii_uppercase();

        info!(
            "Starting Mieru Inbound on port {} with transport={}",
            ctx.port, transport
        );

        match transport.as_str() {
            "UDP" => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Mieru UDP transport requires reliable delivery and is not supported",
            )),
            "TCP" => {
                tcp::start_tcp_server(ctx, self.users.clone(), pattern_exec, shutdown_rx).await
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Unsupported Mieru transport",
            )),
        }
    }
}
