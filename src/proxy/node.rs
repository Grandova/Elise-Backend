use crate::config::node::NodeConfig;
use crate::config::routes::RoutesConfig;
use crate::config::GlobalConfig;
use crate::limiter::{ConnectionLimiter, DeviceLimiter, IpUserCache, RateLimiter};
use crate::observability::{AuditLogger, ClickHouseLogger};
use crate::panel::types::{OnlineDeviceItem, TrafficItem};
use crate::panel::PanelClient;
use crate::protocol::{Inbound, InboundContext, TrafficCallback};
use crate::proxy::registry::create_inbound;
use crate::proxy::router::Router;
use crate::security::{AttackDefenseManager, AuditController, TLSManager};
use crate::stats::SystemCollector;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

pub struct NodeRunner {
    pub node_id: u32,
    panel_client: Arc<dyn PanelClient>,
    global_config: Arc<GlobalConfig>,
    node_config: NodeConfig,
    router: Arc<Router>,
    rate_limiter: Arc<RateLimiter>,
    conn_limiter: Arc<ConnectionLimiter>,
    device_limiter: Arc<DeviceLimiter>,
    audit: Arc<AuditController>,
    defense: Arc<AttackDefenseManager>,
    tls_manager: Arc<TLSManager>,
    audit_logger: Arc<AuditLogger>,
    clickhouse_logger: Arc<ClickHouseLogger>,
    pub ip_user_cache: Arc<IpUserCache>,
    traffic_buffer: Arc<Mutex<HashMap<u32, (u64, u64)>>>,
    sys_collector: Arc<SystemCollector>,
    synced_user_count: Arc<AtomicU32>,
}

impl NodeRunner {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: u32,
        panel_client: Arc<dyn PanelClient>,
        global_config: Arc<GlobalConfig>,
        node_config: NodeConfig,
        router: Arc<Router>,
        rate_limiter: Arc<RateLimiter>,
        conn_limiter: Arc<ConnectionLimiter>,
        device_limiter: Arc<DeviceLimiter>,
        audit: Arc<AuditController>,
        defense: Arc<AttackDefenseManager>,
        tls_manager: Arc<TLSManager>,
        audit_logger: Arc<AuditLogger>,
        clickhouse_logger: Arc<ClickHouseLogger>,
        ip_user_cache: Arc<IpUserCache>,
    ) -> Self {
        Self {
            node_id,
            panel_client,
            global_config,
            node_config,
            router,
            rate_limiter,
            conn_limiter,
            device_limiter,
            audit,
            defense,
            tls_manager,
            audit_logger,
            clickhouse_logger,
            ip_user_cache,
            traffic_buffer: Arc::new(Mutex::new(HashMap::new())),
            sys_collector: Arc::new(SystemCollector::new()),
            synced_user_count: Arc::new(AtomicU32::new(0)),
        }
    }

    pub async fn run(self: Arc<Self>, mut shutdown_rx: broadcast::Receiver<()>) {
        info!("Starting NodeRunner for Node ID {}", self.node_id);

        // Fetch initial node configuration
        let node_info = match self.panel_client.get_node_info(self.node_id).await {
            Ok(info) => info,
            Err(e) => {
                error!(
                    "Node {}: Failed to fetch node info from panel: {:?}",
                    self.node_id, e
                );
                return;
            }
        };

        // 自动维护节点独立配置文件 /etc/elise/nodes/node_{id}.conf
        let nodes_dir = if std::path::Path::new("/etc/elise/nodes").exists()
            || std::path::Path::new("/etc/elise").exists()
        {
            std::path::PathBuf::from("/etc/elise/nodes")
        } else {
            std::path::PathBuf::from("./nodes")
        };

        if let Err(e) = self.node_config.save_node_conf(&nodes_dir, &node_info) {
            warn!(
                "Node {}: Failed to save node config to {}: {}",
                self.node_id,
                nodes_dir.display(),
                e
            );
        } else {
            info!(
                "Node {}: Node config updated at {}/node_{}.conf",
                self.node_id,
                nodes_dir.display(),
                self.node_id
            );
        }

        // If panel supplied runtime routes / outbounds, apply them to router
        if let Some(panel_routes) = &node_info.routes {
            let custom_outbounds = node_info.custom_outbounds.as_deref().unwrap_or(&[]);
            let mut cfg = RoutesConfig::load_from_file(&self.global_config.routes_file);
            cfg.import_panel_routes(panel_routes, custom_outbounds);
            self.router.reload(cfg);
            info!(
                "Node {}: Applied runtime panel routes and custom outbounds",
                self.node_id
            );
        }

        let mut protocol_type = node_info.node_type.clone();
        if (protocol_type.eq_ignore_ascii_case("hysteria") || protocol_type.eq_ignore_ascii_case("hy"))
            && node_info.version == Some(2)
        {
            protocol_type = "hysteria2".to_string();
        }
        let port = (node_info.server_port as i32 + self.node_config.port_offset) as u16;
        let listen_addr = self
            .node_config
            .listen_addr
            .clone()
            .unwrap_or_else(|| self.global_config.listen_addr.clone());

        let inbound = create_inbound(&protocol_type);

        // Traffic callback
        let buf = self.traffic_buffer.clone();
        let sys_collector = self.sys_collector.clone();
        let on_traffic: TrafficCallback = Arc::new(move |user_id, up, down| {
            let mut map = buf.lock();
            let entry = map.entry(user_id).or_insert((0, 0));
            entry.0 += up;
            entry.1 += down;
            sys_collector.add_traffic(up, down);
        });

        // 应用节点独立的 [USER] 参数覆盖到 InboundContext 的 global_config 视图
        let mut node_effective_global = (*self.global_config).clone();
        if let Some(pp) = self.node_config.proxy_protocol {
            node_effective_global.proxy_protocol = pp;
            if pp && node_effective_global.proxy_protocol_mode == crate::conn::ProxyProtocolMode::Off {
                node_effective_global.proxy_protocol_mode = crate::conn::ProxyProtocolMode::Auto;
            }
        }
        if let Some(upp) = self.node_config.udp_proxy_protocol {
            node_effective_global.udp_proxy_protocol = upp;
        }
        if let Some(mptcp) = self.node_config.mptcp {
            node_effective_global.mptcp = mptcp;
        }
        if let Some(force_close) = self.node_config.force_close_ssl {
            if force_close {
                node_effective_global.auto_tls = false;
            }
        }

        let ctx = InboundContext {
            node_id: self.node_id,
            listen_addr,
            port,
            router: self.router.clone(),
            rate_limiter: self.rate_limiter.clone(),
            conn_limiter: self.conn_limiter.clone(),
            device_limiter: self.device_limiter.clone(),
            audit: self.audit.clone(),
            defense: self.defense.clone(),
            tls_manager: self.tls_manager.clone(),
            audit_logger: self.audit_logger.clone(),
            clickhouse_logger: self.clickhouse_logger.clone(),
            on_traffic,
            global_config: Arc::new(node_effective_global),
            ip_user_cache: self.ip_user_cache.clone(),
        };

        // Inbound server task
        let _inbound_task = {
            let inbound = inbound.clone();
            let shutdown_sub = shutdown_rx.resubscribe();
            tokio::spawn(async move {
                if let Err(e) = inbound.start(ctx, node_info, shutdown_sub).await {
                    error!("Inbound error: {:?}", e);
                }
            })
        };

        // Panel Sync Loop
        let _sync_task = {
            let runner = self.clone();
            let inbound = inbound.clone();
            let mut shutdown_sub = shutdown_rx.resubscribe();
            tokio::spawn(async move {
                let sync_secs = runner
                    .node_config
                    .check_interval
                    .unwrap_or(runner.global_config.node_sync_interval);
                let interval = Duration::from_secs(sync_secs.max(10));
                let mut ticker = tokio::time::interval(interval);
                loop {
                    tokio::select! {
                        _ = shutdown_sub.recv() => break,
                        _ = ticker.tick() => {
                            runner.sync_users(&inbound).await;
                        }
                    }
                }
            })
        };

        // Panel Report Loop & Memory Clean-up Sweep
        let _report_task = {
            let runner = self.clone();
            let mut shutdown_sub = shutdown_rx.resubscribe();
            tokio::spawn(async move {
                let report_secs = runner
                    .node_config
                    .submit_interval
                    .unwrap_or(runner.global_config.node_report_interval);
                let interval = Duration::from_secs(report_secs.max(10));
                let mut ticker = tokio::time::interval(interval);
                loop {
                    tokio::select! {
                        _ = shutdown_sub.recv() => break,
                        _ = ticker.tick() => {
                            runner.report_data().await;
                            runner.prune_memory_leaks();
                        }
                    }
                }
            })
        };

        // Remote Rules & Routes Sync Loop
        let _rules_sync_task = {
            let runner = self.clone();
            let mut shutdown_sub = shutdown_rx.resubscribe();
            tokio::spawn(async move {
                let client = reqwest::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .build()
                    .unwrap_or_default();
                let mut ticker = tokio::time::interval(Duration::from_secs(60));
                loop {
                    tokio::select! {
                        _ = shutdown_sub.recv() => break,
                        _ = ticker.tick() => {
                            if let Some(url) = &runner.global_config.routes_url {
                                match client.get(url).send().await {
                                    Ok(resp) if resp.status().is_success() => {
                                        if let Ok(text) = resp.text().await {
                                            let cfg = RoutesConfig::parse_content(&text);
                                            runner.router.reload(cfg);
                                            info!("Reloaded remote routes from {}", url);
                                        }
                                    }
                                    _ => {
                                        warn!(
                                            "Failed to fetch routes_url from {}, falling back to local routes file",
                                            url
                                        );
                                        let cfg = RoutesConfig::load_from_file(
                                            &runner.global_config.routes_file,
                                        );
                                        runner.router.reload(cfg);
                                    }
                                }
                            }
                            if let Some(url) = &runner.global_config.block_list_url {
                                if let Ok(resp) = client.get(url).send().await {
                                    if resp.status().is_success() {
                                        if let Ok(text) = resp.text().await {
                                            runner.audit.reload_block_list(&text);
                                            info!("Reloaded remote block_list from {}", url);
                                        }
                                    }
                                }
                            }
                            if let Some(url) = &runner.global_config.white_list_url {
                                if let Ok(resp) = client.get(url).send().await {
                                    if resp.status().is_success() {
                                        if let Ok(text) = resp.text().await {
                                            runner.audit.reload_white_list(&text);
                                            info!("Reloaded remote white_list from {}", url);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            })
        };

        // Local Rules & Routes 10s Hot-Reload Task
        let _local_watch_task = {
            let runner = self.clone();
            let mut shutdown_sub = shutdown_rx.resubscribe();
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(Duration::from_secs(10));
                let mut last_routes_mtime = None;
                let mut last_block_mtime = None;
                let mut last_white_mtime = None;

                loop {
                    tokio::select! {
                        _ = shutdown_sub.recv() => break,
                        _ = ticker.tick() => {
                            // 1. routes.toml
                            if runner.global_config.routes_url.is_none() {
                                if let Ok(meta) = std::fs::metadata(&runner.global_config.routes_file) {
                                    if let Ok(mtime) = meta.modified() {
                                        if let Some(prev) = last_routes_mtime {
                                            if mtime > prev {
                                                let cfg = RoutesConfig::load_from_file(&runner.global_config.routes_file);
                                                runner.router.reload(cfg);
                                                info!("Hot-reloaded local routes from {:?}", runner.global_config.routes_file);
                                            }
                                        }
                                        last_routes_mtime = Some(mtime);
                                    }
                                }
                            }

                            // 2. blockList
                            if runner.global_config.block_list_url.is_none() {
                                if let Ok(meta) = std::fs::metadata(&runner.global_config.block_list) {
                                    if let Ok(mtime) = meta.modified() {
                                        if let Some(prev) = last_block_mtime {
                                            if mtime > prev {
                                                if let Ok(content) = std::fs::read_to_string(&runner.global_config.block_list) {
                                                    runner.audit.reload_block_list(&content);
                                                    info!("Hot-reloaded local block_list from {:?}", runner.global_config.block_list);
                                                }
                                            }
                                        }
                                        last_block_mtime = Some(mtime);
                                    }
                                }
                            }

                            // 3. whiteList
                            if runner.global_config.white_list_url.is_none() {
                                if let Ok(meta) = std::fs::metadata(&runner.global_config.white_list) {
                                    if let Ok(mtime) = meta.modified() {
                                        if let Some(prev) = last_white_mtime {
                                            if mtime > prev {
                                                if let Ok(content) = std::fs::read_to_string(&runner.global_config.white_list) {
                                                    runner.audit.reload_white_list(&content);
                                                    info!("Hot-reloaded local white_list from {:?}", runner.global_config.white_list);
                                                }
                                            }
                                        }
                                        last_white_mtime = Some(mtime);
                                    }
                                }
                            }
                        }
                    }
                }
            })
        };

        // Trigger first user sync immediately
        self.sync_users(&inbound).await;

        let _ = shutdown_rx.recv().await;
        info!("NodeRunner {} shutting down", self.node_id);

        // Final traffic flush
        self.report_data().await;
    }

    async fn sync_users(&self, inbound: &Arc<dyn Inbound>) {
        match self.panel_client.get_users(self.node_id).await {
            Ok(users) => {
                info!(
                    "Node {}: Synced {} users from panel",
                    self.node_id,
                    users.len()
                );
                self.synced_user_count.store(users.len() as u32, Ordering::Relaxed);
                for u in &users {
                    let effective_speed = if self.global_config.user_speed_limit > 0 {
                        let config_bps = self.global_config.user_speed_limit * 1_000_000 / 8;
                        if u.speed_limit > 0 {
                            u.speed_limit.min(config_bps)
                        } else {
                            config_bps
                        }
                    } else {
                        u.speed_limit
                    };
                    self.rate_limiter.set_user_limit(u.id, effective_speed);

                    let effective_dev_limit = match (u.device_limit, self.global_config.user_conn_limit) {
                        (0, g) => g,
                        (p, 0) => p,
                        (p, g) => p.min(g),
                    };
                    self.device_limiter.set_user_limit(u.id, effective_dev_limit);

                    if self.global_config.user_tcp_limit > 0 {
                        self.conn_limiter.set_user_limit(u.id, self.global_config.user_tcp_limit);
                    }
                }
                inbound.update_users(users);
            }
            Err(e) => {
                warn!("Node {}: User sync failed: {:?}", self.node_id, e);
            }
        }

        // Synchronize global alivelist from panel
        if let Ok(alive_map) = self.panel_client.get_user_alivelist(self.node_id).await {
            if !alive_map.is_empty() {
                self.device_limiter.update_global_alive(alive_map);
            }
        }
    }

    async fn report_data(&self) {
        // 1. Collect & report traffic with threshold
        let min_traffic_bytes = self.global_config.submit_traffic_min_traffic * 1024;
        let min_alive_bytes = self.global_config.submit_alive_ip_min_traffic * 1024;

        let (items, active_users): (Vec<TrafficItem>, HashMap<u32, u64>) = {
            let mut buf = self.traffic_buffer.lock();
            let mut res = Vec::new();
            let mut active = HashMap::new();
            let mut retained = HashMap::new();

            for (user_id, (u, d)) in buf.drain() {
                let total = u + d;
                active.insert(user_id, total);
                if total >= min_traffic_bytes && total > 0 {
                    res.push(TrafficItem { user_id, u, d });
                } else if total > 0 {
                    // Retain in buffer until threshold is reached
                    retained.insert(user_id, (u, d));
                }
            }
            *buf = retained;
            (res, active)
        };

        if !items.is_empty() {
            if let Err(e) = self.panel_client.report_traffic(self.node_id, items).await {
                warn!("Node {}: Traffic report failed: {:?}", self.node_id, e);
            }
        }

        // 2. Collect & report online devices to panel with alive threshold
        let online_map = self.device_limiter.get_all_online_devices();
        if !online_map.is_empty() {
            let dev_items: Vec<OnlineDeviceItem> = online_map
                .into_iter()
                .filter(|(user_id, _)| {
                    if min_alive_bytes == 0 {
                        true
                    } else {
                        active_users.get(user_id).copied().unwrap_or(0) >= min_alive_bytes
                    }
                })
                .map(|(user_id, ips)| OnlineDeviceItem { user_id, ips })
                .collect();
            if !dev_items.is_empty() {
                let _ = self
                    .panel_client
                    .report_online_devices(self.node_id, dev_items)
                    .await;
            }
        }

        // 3. Collect & report system load and runtime metrics to panel
        let total_users = self.synced_user_count.load(Ordering::Relaxed);
        let active_user_count = active_users.len() as u32;
        let active_conns = self
            .conn_limiter
            .get_total_active()
            .max(self.device_limiter.get_all_online_devices().len() as u32);

        let mut report = self.sys_collector.collect(total_users, active_user_count);
        if active_conns > 0 && report.active_connections == 0 {
            report.active_connections = active_conns;
            report.total_connections = report.total_connections.max(active_conns as u64);
        }
        if let Err(e) = self
            .panel_client
            .report_node_status(self.node_id, &report)
            .await
        {
            tracing::debug!("Node {}: Status report failed: {:?}", self.node_id, e);
        }
    }

    fn prune_memory_leaks(&self) {
        self.device_limiter.prune_expired();
        self.conn_limiter.prune_idle();
        self.rate_limiter.prune_idle();
        self.defense.prune_expired();
        self.ip_user_cache.prune();
        self.ip_user_cache.save_to_disk();
    }
}
