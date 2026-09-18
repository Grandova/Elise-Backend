use crate::config::node::NodeConfig;
use crate::config::routes::RoutesConfig;
use crate::config::GlobalConfig;
use crate::dns::RuleBasedDNSManager;
use crate::limiter::{ConnectionLimiter, DeviceLimiter, IpUserCache, RateLimiter};
use crate::observability::{AuditLogger, ClickHouseLogger};
use crate::panel::create_panel_client;
use crate::proxy::node::NodeRunner;
use crate::proxy::router::{OutboundDialer, Router};
use crate::security::{AttackDefenseManager, AuditController, TLSManager};
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::broadcast;
use tracing::info;

pub struct MasterServer {
    global_config: Arc<GlobalConfig>,
    shutdown_tx: broadcast::Sender<()>,
}

impl MasterServer {
    pub fn new(global_config: GlobalConfig) -> Self {
        let (shutdown_tx, _) = broadcast::channel(16);
        Self {
            global_config: Arc::new(global_config),
            shutdown_tx,
        }
    }

    pub async fn run(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        info!(
            "Elise MasterServer initializing with {} configured node(s)",
            self.global_config.node_ids.len()
        );

        let panel_client = create_panel_client(
            &self.global_config.panel_type,
            &self.global_config.api_host,
            &self.global_config.api_key,
        );

        let dns_manager = Arc::new(RuleBasedDNSManager::new(
            &self.global_config.dns_strategy,
            self.global_config.dns_cache_time,
            self.global_config.default_dns.as_deref(),
            self.global_config.dns_file.clone(),
        ));
        let dns_resolver = dns_manager.resolver();

        let out_v4: Option<IpAddr> = self
            .global_config
            .out_ip_ipv4
            .as_deref()
            .and_then(|s| s.parse().ok());
        let out_v6: Option<IpAddr> = self
            .global_config
            .out_ip_ipv6
            .as_deref()
            .and_then(|s| s.parse().ok());

        let dialer = Arc::new(OutboundDialer::new(
            dns_resolver.clone(),
            out_v4,
            out_v6,
            self.global_config.auto_out_ip,
        ));

        let geo_engine = Arc::new(crate::geo::GeoEngine::new(
            self.global_config.geoip_file.clone(),
            self.global_config.geosite_file.clone(),
        ));

        let routes_config = RoutesConfig::load_from_file(&self.global_config.routes_file);
        let router = Arc::new(Router::new(routes_config, dialer, geo_engine.clone()));

        let rate_limiter = Arc::new(RateLimiter::new());
        let conn_limiter = Arc::new(ConnectionLimiter::new());
        let device_limiter = Arc::new(DeviceLimiter::new_with_redis(
            self.global_config.device_limit_window,
            self.global_config.device_limit_prefix_ipv4,
            self.global_config.device_limit_prefix_ipv6,
            self.global_config.get_redis_url(),
            self.global_config.conn_limit_expiry,
            self.global_config.redis_timeout_ms,
        ));
        let ip_user_cache = Arc::new(IpUserCache::new(
            self.global_config.ip_user_cache_time,
            self.global_config.ip_user_cache_save_enable,
            &self.global_config.ip_user_cache_save_dir,
        ));

        let audit = Arc::new(AuditController::new_with_options(
            &self.global_config.block_list,
            &self.global_config.white_list,
            geo_engine,
            self.global_config.forbidden_ports.clone(),
            self.global_config.ban_private_ip,
            self.global_config.forbidden_bit_torrent,
        ));

        router.dialer().set_audit(audit.clone());

        let defense = Arc::new(AttackDefenseManager::default());

        let tls_manager = Arc::new(TLSManager::new(
            self.global_config.auto_tls,
            self.global_config.fake_sni.clone(),
        ));

        let audit_logger = Arc::new(AuditLogger::new(
            self.global_config.audit_log_file.as_deref(),
        ));
        let clickhouse_logger = Arc::new(ClickHouseLogger::new(
            self.global_config.clickhouse_enabled,
            self.global_config.clickhouse_addr.clone(),
            self.global_config.clickhouse_db.clone(),
            self.global_config.clickhouse_table.clone(),
            self.global_config.clickhouse_user.clone(),
            self.global_config.clickhouse_password.clone(),
        ));

        let nodes_dir = find_nodes_dir();
        let mut node_handles = Vec::new();

        for (idx, &node_id) in self.global_config.node_ids.iter().enumerate() {
            let mut node_cfg = NodeConfig::load_for_node(&nodes_dir, node_id);
            if node_cfg.listen_addr.is_none() {
                node_cfg.listen_addr = Some(self.global_config.get_listen_ip_for_node(idx, None));
            }
            let runner = Arc::new(NodeRunner::new(
                node_id,
                panel_client.clone(),
                self.global_config.clone(),
                node_cfg,
                router.clone(),
                rate_limiter.clone(),
                conn_limiter.clone(),
                device_limiter.clone(),
                audit.clone(),
                defense.clone(),
                tls_manager.clone(),
                audit_logger.clone(),
                clickhouse_logger.clone(),
                ip_user_cache.clone(),
            ));

            let shutdown_sub = self.shutdown_tx.subscribe();
            node_handles.push(tokio::spawn(async move {
                runner.run(shutdown_sub).await;
            }));
        }

        info!(
            "All {} node runner(s) started successfully",
            node_handles.len()
        );

        // 业务监听成功后启动 pprof 服务
        let pprof_handle = crate::observability::PprofServer::start(
            &self.global_config.pprof_addr,
            self.shutdown_tx.subscribe(),
        );

        let mut shutdown = self.shutdown_tx.subscribe();
        #[cfg(unix)]
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => info!("SIGINT received, shutting down Elise MasterServer..."),
            _ = shutdown.recv() => {},
            _ = async {
                #[cfg(unix)]
                terminate.recv().await;
                #[cfg(not(unix))]
                std::future::pending::<()>().await;
            } => info!("SIGTERM received, shutting down Elise MasterServer..."),
        }

        let _ = self.shutdown_tx.send(());
        for handle in node_handles {
            let _ = handle.await;
        }

        if let Some(h) = pprof_handle {
            let _ = h.await;
        }

        ip_user_cache.save_to_disk();

        info!("Elise MasterServer terminated cleanly.");
        Ok(())
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

fn find_nodes_dir() -> std::path::PathBuf {
    let standard = std::path::PathBuf::from("/etc/elise/nodes");
    if standard.exists() || standard.parent().map(|p| p.exists()).unwrap_or(false) {
        return standard;
    }
    let local = std::path::PathBuf::from("./nodes");
    if local.exists() {
        return local;
    }
    standard
}
