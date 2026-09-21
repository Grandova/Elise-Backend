pub mod auth;
pub mod connect;
pub mod forward;
pub mod server;

pub use auth::{verify_basic_auth, AuthError};
pub use connect::handle_connect;
pub use forward::handle_forward;
pub use server::run_http_server;

use crate::panel::types::{NodeInfo, User};
use crate::protocol::{Inbound, InboundContext};
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::broadcast;

pub struct HttpInbound {
    users: Arc<RwLock<HashMap<String, User>>>,
}

impl Default for HttpInbound {
    fn default() -> Self {
        Self {
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl HttpInbound {
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl Inbound for HttpInbound {
    fn protocol_type(&self) -> &'static str {
        "http"
    }

    fn update_users(&self, users: Vec<User>) {
        let mut map = HashMap::new();
        for u in users {
            let pass = u.password.clone().unwrap_or_else(|| u.uuid.clone());
            map.insert(format!("{}:{}", u.id, pass), u.clone());
            map.insert(format!("{}:{}", u.uuid, pass), u);
        }
        *self.users.write() = map;
    }

    async fn start(
        &self,
        ctx: InboundContext,
        node_info: NodeInfo,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> std::io::Result<()> {
        run_http_server(ctx, node_info, self.users.clone(), shutdown_rx).await
    }
}
