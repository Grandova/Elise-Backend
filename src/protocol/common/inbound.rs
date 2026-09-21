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

pub(crate) async fn drain_connections(tasks: &mut tokio::task::JoinSet<()>) {
    let drained = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        while let Some(result) = tasks.join_next().await {
            if let Err(e) = result {
                tracing::warn!(error = %e, "Connection task failed");
            }
        }
    })
    .await;
    if drained.is_err() {
        tracing::warn!(
            remaining = tasks.len(),
            "Connection drain deadline exceeded"
        );
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
}

#[derive(Clone)]
pub struct InboundContext {
    pub ready: Option<tokio::sync::watch::Sender<bool>>,
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

impl InboundContext {
    pub fn mark_ready(&self) {
        if let Some(ready) = &self.ready {
            ready.send_replace(true);
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn connection_drain_waits_for_workers_and_observes_panics() {
        let done = Arc::new(std::sync::atomic::AtomicU32::new(0));
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..8 {
            let done = done.clone();
            tasks.spawn(async move {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
                done.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            });
        }
        tasks.spawn(async { panic!("connection failure fixture") });
        drain_connections(&mut tasks).await;
        assert!(tasks.is_empty());
        assert_eq!(done.load(std::sync::atomic::Ordering::Relaxed), 8);
    }
}
