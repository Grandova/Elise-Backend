use crate::config::GlobalConfig;
use crate::limiter::{ConnectionLimiter, DeviceLimiter, IpUserCache, RateLimiter};
use crate::observability::{AuditLogger, ClickHouseLogger};
use crate::panel::types::{NodeInfo, User};
use crate::proxy::router::Router;
use crate::security::{AttackDefenseManager, AuditController, TLSManager};
use async_trait::async_trait;
use std::sync::Arc;
use tokio::sync::broadcast;

pub type TrafficCallback = Arc<dyn Fn(u32, u64, u64) + Send + Sync>;

#[derive(Clone)]
pub struct InboundContext {
    pub node_id: u32,
    pub listen_addr: String,
    pub port: u16,
    pub router: Arc<Router>,
    pub rate_limiter: Arc<RateLimiter>,
    pub conn_limiter: Arc<ConnectionLimiter>,
    pub device_limiter: Arc<DeviceLimiter>,
    pub audit: Arc<AuditController>,
    pub defense: Arc<AttackDefenseManager>,
    pub tls_manager: Arc<TLSManager>,
    pub audit_logger: Arc<AuditLogger>,
    pub clickhouse_logger: Arc<ClickHouseLogger>,
    pub on_traffic: TrafficCallback,
    pub global_config: Arc<GlobalConfig>,
    pub ip_user_cache: Arc<IpUserCache>,
}

#[async_trait]
pub trait Inbound: Send + Sync {
    fn protocol_type(&self) -> &'static str;
    async fn start(
        &self,
        ctx: InboundContext,
        node_info: NodeInfo,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) -> std::io::Result<()>;
    fn update_users(&self, users: Vec<User>);
}
