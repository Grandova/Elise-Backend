use crate::config::node::NodeConfig;
use crate::config::routes::RoutesConfig;
use crate::config::GlobalConfig;
use crate::limiter::{ConnectionLimiter, DeviceLimiter, IpUserCache, RateLimiter};
use crate::observability::{AuditLogger, ClickHouseLogger};
use crate::panel::types::{NodeInfo, OnlineDeviceItem, TrafficItem, User};
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
    node_info: Mutex<Option<NodeInfo>>,
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
    report_lock: tokio::sync::Mutex<()>,
    traffic_path: std::path::PathBuf,
    traffic_file_lock: Mutex<Option<Arc<std::fs::File>>>,
    traffic_io_lock: Arc<Mutex<()>>,
    sys_collector: Arc<SystemCollector>,
    synced_user_count: Arc<AtomicU32>,
}

struct ActiveInbound {
    inbound: Arc<dyn Inbound>,
    stop: broadcast::Sender<()>,
    task: tokio::task::JoinHandle<std::io::Result<()>>,
}

impl ActiveInbound {
    async fn stop(&mut self) {
        let _ = self.stop.send(());
        if self.task.is_finished() {
            return;
        }
        if tokio::time::timeout(Duration::from_secs(32), &mut self.task)
            .await
            .is_err()
        {
            self.task.abort();
            let _ = (&mut self.task).await;
        }
    }
}

impl Drop for ActiveInbound {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        self.task.abort();
    }
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
        if global_config.user_speed_limit > 0 || global_config.node_speed_limit > 0 {
            warn!("Local user_speed_limit/node_speed_limit ignored; only panel user plan limits apply");
        }
        use sha2::Digest;
        let panel = format!(
            "{}:{}",
            global_config.panel_type.to_lowercase(),
            global_config.api_host.trim_end_matches('/')
        );
        let identity = format!("{:x}", sha2::Sha256::digest(panel.as_bytes()));
        let traffic_path = global_config
            .ip_user_cache_save_dir
            .join("traffic")
            .join(format!("{identity}-{node_id}.json"));
        Self {
            node_id,
            panel_client,
            global_config,
            node_config,
            router: Arc::new(router.fork()),
            node_info: Mutex::new(None),
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
            report_lock: tokio::sync::Mutex::new(()),
            traffic_path,
            traffic_file_lock: Mutex::new(None),
            traffic_io_lock: Arc::new(Mutex::new(())),
            sys_collector: Arc::new(SystemCollector::new()),
            synced_user_count: Arc::new(AtomicU32::new(0)),
        }
    }

    fn restore_pending(&self) -> std::io::Result<()> {
        let parent = self.traffic_path.parent().unwrap();
        std::fs::create_dir_all(parent)?;
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.traffic_path.with_extension("lock"))?;
        lock.try_lock().map_err(std::io::Error::other)?;
        let pending = match std::fs::read(&self.traffic_path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(std::io::Error::other)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => return Err(e),
        };
        *self.traffic_buffer.lock() = pending;
        *self.traffic_file_lock.lock() = Some(Arc::new(lock));
        Ok(())
    }

    async fn save_pending(&self) -> std::io::Result<()> {
        let Some(file_lock) = self.traffic_file_lock.lock().clone() else {
            return Ok(());
        };
        let path = self.traffic_path.clone();
        let buffer = self.traffic_buffer.clone();
        let io_lock = self.traffic_io_lock.clone();
        tokio::task::spawn_blocking(move || {
            use std::io::Write;
            let _file_lock = file_lock;
            // A cancelled reporting task cannot cancel blocking file I/O. Serialize
            // writers and snapshot inside the lock so a late write cannot regress state.
            let _guard = io_lock.lock();
            let pending = buffer.lock().clone();
            let bytes = serde_json::to_vec(&pending).map_err(std::io::Error::other)?;
            let temporary = path.with_extension("tmp");
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            drop(file);
            std::fs::rename(&temporary, &path)?;
            #[cfg(unix)]
            std::fs::File::open(path.parent().unwrap())?.sync_all()?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(std::io::Error::other)?
    }

    pub async fn run(self: Arc<Self>, mut shutdown_rx: broadcast::Receiver<()>) {
        info!("Starting NodeRunner for Node ID {}", self.node_id);
        if let Err(e) = self.restore_pending() {
            error!(node_id = self.node_id, error = %e, "Cannot open pending traffic store; node not started");
            return;
        }

        // Fetch initial node configuration
        let mut node_info = match self.panel_client.get_node_info(self.node_id).await {
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

        if let Err(e) = self
            .node_config
            .prepare_node_info(&nodes_dir, &mut node_info)
        {
            error!(node_id = self.node_id, error = %e, "Invalid node security configuration");
            return;
        }

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

        self.apply_node_routes(&node_info);

        let inbound_task = {
            let runner = self.clone();
            let shutdown_sub = shutdown_rx.resubscribe();
            tokio::spawn(async move {
                runner.run_inbound(node_info, shutdown_sub).await;
            })
        };

        // Panel Report Loop & Memory Clean-up Sweep
        let report_task = {
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
                            runner.report_data(false).await;
                            runner.prune_memory_leaks();
                        }
                    }
                }
            })
        };

        // Remote Rules & Routes Sync Loop
        let rules_sync_task = {
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
                                            runner.reload_routes(cfg);
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
                                        runner.reload_routes(cfg);
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
        let local_watch_task = {
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
                                                runner.reload_routes(cfg);
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

        let _ = shutdown_rx.recv().await;
        info!("NodeRunner {} shutting down", self.node_id);

        let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
        for mut task in [report_task, rules_sync_task, local_watch_task] {
            if tokio::time::timeout_at(deadline, &mut task).await.is_err() {
                task.abort();
                let _ = task.await;
            }
        }
        let mut inbound_task = inbound_task;
        if tokio::time::timeout(Duration::from_secs(35), &mut inbound_task)
            .await
            .is_err()
        {
            warn!("Node {}: Inbound drain timed out", self.node_id);
            inbound_task.abort();
            let _ = inbound_task.await;
        }

        // Ignore the batching threshold for the final bounded flush.
        let flushed = tokio::time::timeout(Duration::from_secs(35), async {
            for attempt in 0..3 {
                self.report_data(true).await;
                if self.traffic_buffer.lock().is_empty() {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1 << attempt)).await;
            }
        })
        .await;
        if flushed.is_err() || !self.traffic_buffer.lock().is_empty() {
            error!(
                "Node {}: Shutdown ended with unacknowledged pending traffic",
                self.node_id
            );
        }
        if let Err(e) = self.save_pending().await {
            error!(node_id = self.node_id, error = %e, "Final pending traffic snapshot failed");
        }
    }

    fn inbound_context(&self, node_info: &NodeInfo) -> std::io::Result<InboundContext> {
        let port = u16::try_from(
            i64::from(node_info.server_port) + i64::from(self.node_config.port_offset),
        )
        .ok()
        .filter(|port| *port > 0)
        .ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidInput, "Invalid node port")
        })?;
        let listen_addr = self
            .node_config
            .listen_addr
            .clone()
            .or_else(|| node_info.listen_ip.clone())
            .unwrap_or_else(|| self.global_config.listen_addr.clone());

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
        if let Some(pattern) = self
            .node_config
            .custom_settings
            .get("mieru_traffic_pattern")
        {
            if !pattern.trim().is_empty() {
                node_effective_global
                    .raw_properties
                    .insert("mieru_traffic_pattern".into(), pattern.clone());
            }
        }
        if let Some(pp) = self.node_config.proxy_protocol {
            node_effective_global.proxy_protocol = pp;
            if pp
                && node_effective_global.proxy_protocol_mode == crate::conn::ProxyProtocolMode::Off
            {
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

        Ok(InboundContext {
            ready: None,
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
        })
    }

    fn apply_node_routes(&self, node_info: &NodeInfo) {
        *self.node_info.lock() = Some(node_info.clone());
        self.reload_routes(RoutesConfig::load_from_file(
            &self.global_config.routes_file,
        ));
    }

    fn reload_routes(&self, mut cfg: RoutesConfig) {
        if let Some(info) = self.node_info.lock().as_ref() {
            let mut routes = info.routes.clone().unwrap_or_default();
            routes.extend(info.custom_routes.clone().unwrap_or_default());
            cfg.import_panel_routes(&routes, info.custom_outbounds.as_deref().unwrap_or(&[]));
        }
        self.router.reload(cfg);
    }

    async fn run_inbound(
        self: Arc<Self>,
        mut info: NodeInfo,
        mut shutdown: broadcast::Receiver<()>,
    ) {
        let mut users = Vec::new();
        let mut active = match self.launch_inbound(&info, &users).await {
            Ok(active) => active,
            Err(e) => {
                error!(node_id = self.node_id, error = %e, "Inbound startup failed");
                return;
            }
        };
        let mut retired = tokio::task::JoinSet::new();
        let interval = self
            .node_config
            .check_interval
            .unwrap_or(self.global_config.node_sync_interval)
            .max(10);
        let mut ticker = tokio::time::interval(Duration::from_secs(interval));
        loop {
            tokio::select! {
                biased;
                _ = shutdown.recv() => break,
                result = retired.join_next(), if !retired.is_empty() => {
                    if let Some(Err(e)) = result { warn!(error = %e, "Retired inbound task failed"); }
                }
                _ = ticker.tick() => {
                    let update = async {
                        if let Some(synced) = self.sync_users(&active.inbound).await { users = synced; }
                        let mut next = match self.panel_client.get_node_info(self.node_id).await {
                            Ok(next) => next,
                            Err(e) => { warn!(node_id = self.node_id, error = %e, "Node sync failed; keeping active configuration"); return; }
                        };
                        let nodes_dir = if std::path::Path::new("/etc/elise").exists() {
                            std::path::PathBuf::from("/etc/elise/nodes")
                        } else {
                            std::path::PathBuf::from("./nodes")
                        };
                        if let Err(e) = self.node_config.prepare_node_info(&nodes_dir, &mut next) {
                            warn!(node_id = self.node_id, error = %e, "Invalid node security update; keeping active configuration");
                            return;
                        }
                        if serde_json::to_value(&next).ok() == serde_json::to_value(&info).ok() && !active.task.is_finished() { return; }
                        let next_ctx = match self.inbound_context(&next) {
                            Ok(ctx) => ctx,
                            Err(e) => { warn!(error = %e, "Invalid node update; keeping active configuration"); return; }
                        };
                        let old_ctx = self.inbound_context(&info).expect("Previously validated context");
                        let same_address = next_ctx.port == old_ctx.port && next_ctx.listen_addr == old_ctx.listen_addr;
                        if same_address { active.stop().await; }
                        match self.launch_inbound(&next, &users).await {
                            Ok(candidate) => {
                                let mut old = std::mem::replace(&mut active, candidate);
                                retired.spawn(async move { old.stop().await; });
                                self.apply_node_routes(&next);
                                info = next;
                                if let Err(e) = self.node_config.save_node_conf(&nodes_dir, &info) {
                                    warn!(node_id = self.node_id, error = %e, "Failed to update node AUTO settings");
                                }
                                info!(node_id = self.node_id, port = info.server_port, "Node configuration reloaded");
                            }
                            Err(e) => {
                                warn!(node_id = self.node_id, error = %e, "Node update failed; keeping previous configuration");
                                if same_address {
                                    match self.launch_inbound(&info, &users).await {
                                        Ok(previous) => active = previous,
                                        Err(e) => error!(node_id = self.node_id, error = %e, "Failed to restore previous listener"),
                                    }
                                }
                            }
                        }
                    };
                    tokio::select! { biased; _ = shutdown.recv() => break, _ = update => {} }
                }
            }
        }
        active.stop().await;
        while retired.join_next().await.is_some() {}
    }

    async fn launch_inbound(
        &self,
        info: &NodeInfo,
        users: &[User],
    ) -> std::io::Result<ActiveInbound> {
        let mut ctx = self.inbound_context(info)?;
        let protocol = if (info.node_type.eq_ignore_ascii_case("hysteria")
            || info.node_type.eq_ignore_ascii_case("hy"))
            && info.version == Some(2)
        {
            "hysteria2"
        } else {
            &info.node_type
        };
        let inbound = create_inbound(protocol)?;
        inbound.update_users(users.to_vec());
        let (ready, mut ready_rx) = tokio::sync::watch::channel(false);
        ctx.ready = Some(ready);
        let (stop, rx) = broadcast::channel(1);
        let server = inbound.clone();
        let info = info.clone();
        let task = tokio::spawn(async move { server.start(ctx, info, rx).await });
        let mut active = ActiveInbound {
            inbound,
            stop,
            task,
        };
        tokio::select! {
            biased;
            result = &mut active.task => {
                return Err(match result {
                    Ok(Err(e)) => e,
                    other => std::io::Error::other(format!("Inbound stopped before ready: {other:?}")),
                });
            }
            result = ready_rx.changed() => {
                if result.is_err() || !*ready_rx.borrow() { return Err(std::io::Error::other("Inbound did not become ready")); }
            }
            _ = tokio::time::sleep(Duration::from_secs(30)) => {
                return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Inbound startup timed out"));
            }
        }
        Ok(active)
    }

    async fn sync_users(&self, inbound: &Arc<dyn Inbound>) -> Option<Vec<User>> {
        let mut synced = None;
        match self.panel_client.get_users(self.node_id).await {
            Ok(users) => {
                info!(
                    "Node {}: Synced {} users from panel",
                    self.node_id,
                    users.len()
                );
                self.synced_user_count
                    .store(users.len() as u32, Ordering::Relaxed);
                for u in &users {
                    self.rate_limiter.set_user_limit(u.id, u.speed_limit);

                    let effective_dev_limit =
                        match (u.device_limit, self.global_config.user_conn_limit) {
                            (0, g) => g,
                            (p, 0) => p,
                            (p, g) => p.min(g),
                        };
                    self.device_limiter
                        .set_user_limit(u.id, effective_dev_limit);

                    if self.global_config.user_tcp_limit > 0 {
                        self.conn_limiter
                            .set_user_limit(u.id, self.global_config.user_tcp_limit);
                    }
                }
                inbound.update_users(users.clone());
                synced = Some(users);
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
        synced
    }

    async fn report_data(&self, force: bool) {
        let _report_guard = self.report_lock.lock().await;
        // 1. Collect & report traffic with threshold
        let min_traffic_bytes = self.global_config.submit_traffic_min_traffic * 1024;
        let min_alive_bytes = self.global_config.submit_alive_ip_min_traffic * 1024;

        let (items, active_users): (Vec<TrafficItem>, HashMap<u32, u64>) = {
            let buf = self.traffic_buffer.lock();
            let mut res = Vec::new();
            let mut active = HashMap::new();
            for (&user_id, &(u, d)) in buf.iter() {
                let total = u + d;
                active.insert(user_id, total);
                if (force || total >= min_traffic_bytes) && total > 0 {
                    res.push(TrafficItem { user_id, u, d });
                }
            }
            (res, active)
        };

        if !items.is_empty() {
            if let Err(e) = self.save_pending().await {
                error!(node_id = self.node_id, error = %e, "Traffic batch not persisted; report deferred");
                return;
            }
            match self
                .panel_client
                .report_traffic(self.node_id, items.clone())
                .await
            {
                Ok(()) => {
                    let mut buf = self.traffic_buffer.lock();
                    for item in items {
                        if let Some(pending) = buf.get_mut(&item.user_id) {
                            pending.0 -= item.u;
                            pending.1 -= item.d;
                            if *pending == (0, 0) {
                                buf.remove(&item.user_id);
                            }
                        }
                    }
                }
                Err(e) => warn!(
                    "Node {}: Traffic report failed, pending traffic retained: {:?}",
                    self.node_id, e
                ),
            }
        }

        if let Err(e) = self.save_pending().await {
            error!(node_id = self.node_id, error = %e, "Failed to persist traffic acknowledgement");
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    fn runner(url: String) -> NodeRunner {
        let geo = Arc::new(crate::geo::GeoEngine::default());
        let dialer = Arc::new(crate::proxy::router::OutboundDialer::new(
            Arc::new(crate::dns::DNSResolver::default()),
            None,
            None,
            false,
        ));
        let mut config = crate::config::GlobalConfig::default();
        config.domain_sniff = false;
        NodeRunner::new(
            1,
            Arc::new(crate::panel::SSPanelClient::new(url, "fixture".into())),
            Arc::new(config),
            NodeConfig::default(),
            Arc::new(Router::new(Default::default(), dialer, geo.clone())),
            Arc::new(RateLimiter::new()),
            Arc::new(ConnectionLimiter::new()),
            Arc::new(DeviceLimiter::new(60, 32, 128, None)),
            Arc::new(AuditController::new("", "", geo)),
            Arc::new(AttackDefenseManager::default()),
            Arc::new(TLSManager::new(false, "localhost".into())),
            Arc::new(AuditLogger::new(None::<&str>)),
            Arc::new(ClickHouseLogger::new(
                false,
                String::new(),
                String::new(),
                String::new(),
                String::new(),
                None,
            )),
            Arc::new(IpUserCache::new(1, false, "")),
        )
    }

    #[tokio::test]
    async fn socks_requires_panel_users_and_limits_handshake_not_session() {
        tokio::time::timeout(Duration::from_secs(22), async {
            let runner = runner("http://127.0.0.1:1".into());
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let info = NodeInfo {
                node_type: "socks".into(),
                server_port: port,
                listen_ip: Some("127.0.0.1".into()),
                ..Default::default()
            };
            let mut active = runner.launch_inbound(&info, &[]).await.unwrap();
            let mut response = [0u8; 2];
            let mut unauth = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            unauth.write_all(b"\x05\x01\x00").await.unwrap();
            unauth.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 255]);
            drop(unauth);
            active.inbound.update_users(vec![User {
                id: 42,
                uuid: "test".into(),
                password: Some("pass".into()),
                ..Default::default()
            }]);
            let mut bad = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            bad.write_all(b"\x05\x01\x02").await.unwrap();
            bad.read_exact(&mut response).await.unwrap();
            bad.write_all(b"\x01\x04test\x05wrong").await.unwrap();
            bad.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [1, 1]);
            drop(bad);
            let mut silent = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target_port = echo.local_addr().unwrap().port();
            let target = tokio::spawn(async move {
                let (mut stream, _) = echo.accept().await.unwrap();
                let mut received = Vec::new();
                stream.read_to_end(&mut received).await.unwrap();
                assert_eq!(received, b"after-handshake-timeout");
                stream.write_all(b"half-close-response").await.unwrap();
            });
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            stream.write_all(b"\x05\x01\x02").await.unwrap();
            stream.read_exact(&mut response).await.unwrap();
            stream.write_all(b"\x01\x04test\x04pass").await.unwrap();
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [1, 0]);
            let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
            request.extend_from_slice(&target_port.to_be_bytes());
            stream.write_all(&request).await.unwrap();
            let mut response = [0; 10];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response[1], 0);
            tokio::time::sleep(Duration::from_secs(16)).await;
            assert_eq!(silent.read(&mut [0u8; 1]).await.unwrap(), 0);
            stream.write_all(b"after-handshake-timeout").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"half-close-response");
            target.await.unwrap();
            active.inbound.update_users(vec![]);
            let mut removed = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            removed.write_all(b"\x05\x02\x00\x02").await.unwrap();
            let mut response = [0u8; 2];
            removed.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 255]);
            drop(removed);
            active.stop().await;
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn socks_udp_control_close_and_idle_release_relay_socket() {
        let mut runner = runner("http://127.0.0.1:1".into());
        Arc::make_mut(&mut runner.global_config).udp_timeout = 1;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let info = NodeInfo {
            node_type: "socks".into(),
            server_port: port,
            listen_ip: Some("127.0.0.1".into()),
            ..Default::default()
        };
        let user = User {
            id: 42,
            uuid: "test".into(),
            password: Some("pass".into()),
            ..Default::default()
        };
        let mut active = runner.launch_inbound(&info, &[user]).await.unwrap();
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target_port = echo.local_addr().unwrap().port();
        let target = tokio::spawn(async move {
            let mut buf = [0u8; 128];
            for _ in 0..4 {
                let (n, peer) = echo.recv_from(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"udp-payload");
                echo.send_to(&buf[..n], peer).await.unwrap();
            }
        });
        for exit in ["close", "idle"] {
            let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .unwrap();
            stream.write_all(b"\x05\x01\x02").await.unwrap();
            let mut response = [0u8; 2];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [5, 2]);
            stream.write_all(b"\x01\x04test\x04pass").await.unwrap();
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [1, 0]);
            stream
                .write_all(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")
                .await
                .unwrap();
            let mut response = [0u8; 10];
            stream.read_exact(&mut response).await.unwrap();
            assert_eq!(&response[..4], &[5, 0, 0, 1]);
            let relay_port = u16::from_be_bytes([response[8], response[9]]);
            let client = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let malformed = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut packet = vec![0, 0, 1, 1, 127, 0, 0, 1];
            packet.extend_from_slice(&target_port.to_be_bytes());
            packet.extend_from_slice(b"udp-payload");
            malformed
                .send_to(&packet, ("127.0.0.1", relay_port))
                .await
                .unwrap();
            packet[2] = 0;
            for _ in 0..2 {
                client
                    .send_to(&packet, ("127.0.0.1", relay_port))
                    .await
                    .unwrap();
                let mut response = [0u8; 128];
                let (n, _) =
                    tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut response))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(&response[..n], &packet);
            }
            if exit == "idle" {
                let mut byte = [0u8; 1];
                assert_eq!(
                    tokio::time::timeout(Duration::from_secs(3), stream.read(&mut byte))
                        .await
                        .unwrap()
                        .unwrap(),
                    0
                );
            }
            drop(stream);
            tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Ok(socket) = tokio::net::UdpSocket::bind(("0.0.0.0", relay_port)).await {
                        drop(socket);
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            })
            .await
            .expect("UDP relay leaked after control closed");
        }
        tokio::time::timeout(Duration::from_secs(2), target)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(runner.traffic_buffer.lock().get(&42), Some(&(44, 44)));
        active.stop().await;
    }

    #[tokio::test]
    async fn tls_inbounds_respect_panel_certificate_policy() {
        let runner = runner("http://127.0.0.1:1".into());
        for protocol in ["vless", "vmess", "trojan", "http", "anytls", "naive"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            drop(listener);
            let mut info = NodeInfo {
                node_type: protocol.into(),
                server_port: port,
                tls: Some(1),
                listen_ip: Some("127.0.0.1".into()),
                tls_settings: Some(
                    serde_json::json!({"server_name":"localhost","allow_insecure":false}),
                ),
                ..Default::default()
            };
            let error = runner
                .launch_inbound(&info, &[])
                .await
                .err()
                .expect("missing certificate must fail");
            assert!(
                error.to_string().contains("TLS has no certificate"),
                "{protocol}: {error}"
            );
            info.tls_settings.as_mut().unwrap()["allow_insecure"] = serde_json::json!(true);
            let mut active = runner
                .launch_inbound(&info, &[])
                .await
                .unwrap_or_else(|e| panic!("{protocol}: {e}"));
            active.stop().await;
            info.tls_settings.as_mut().unwrap()["cert_file"] =
                serde_json::json!("/elise-missing-certificate.pem");
            info.tls_settings.as_mut().unwrap()["key_file"] =
                serde_json::json!("/elise-missing-private-key.pem");
            assert!(
                runner.launch_inbound(&info, &[]).await.is_err(),
                "{protocol} must not fall back from a broken certificate"
            );
        }
    }

    #[tokio::test]
    async fn mieru_pattern_overrides_reach_inbound() {
        use base64::prelude::*;
        use prost::Message;

        let pattern = BASE64_STANDARD.encode(
            crate::protocol::mieru::proto::TrafficPattern {
                seed: Some(42),
                ..Default::default()
            }
            .encode_to_vec(),
        );
        let mut runner = runner("http://127.0.0.1:1".into());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut info = NodeInfo {
            node_type: "mieru".into(),
            server_port: listener.local_addr().unwrap().port(),
            listen_ip: Some("127.0.0.1".into()),
            traffic_pattern: Some(pattern.clone()),
            ..Default::default()
        };
        drop(listener);
        let mut active = runner.launch_inbound(&info, &[]).await.unwrap();
        active.stop().await;

        info.traffic_pattern = Some("invalid".into());
        assert!(runner.launch_inbound(&info, &[]).await.is_err());
        runner.global_config = Arc::new(crate::config::GlobalConfig::parse(&format!(
            "mieru_traffic_pattern = {pattern}"
        )));
        let mut active = runner.launch_inbound(&info, &[]).await.unwrap();
        active.stop().await;

        runner
            .node_config
            .parse_content("[USER]\nmieru_traffic_pattern = invalid");
        assert!(runner.launch_inbound(&info, &[]).await.is_err());
        runner
            .node_config
            .parse_content(&format!("[USER]\nmieru_traffic_pattern = {pattern}"));
        runner.global_config = Arc::new(crate::config::GlobalConfig::parse(
            "mieru_traffic_pattern = invalid",
        ));
        let mut active = runner.launch_inbound(&info, &[]).await.unwrap();
        active.stop().await;

        runner
            .node_config
            .parse_content("[USER]\nmieru_traffic_pattern = ");
        runner.global_config = Arc::new(crate::config::GlobalConfig::parse(
            "mieru_traffic_pattern = ",
        ));
        assert!(runner.launch_inbound(&info, &[]).await.is_err());
        info.traffic_pattern = Some(pattern);
        let mut active = runner.launch_inbound(&info, &[]).await.unwrap();
        active.stop().await;
    }

    #[tokio::test]
    async fn inbound_readiness_reports_bind_and_config_failures() {
        let runner = runner("http://127.0.0.1:1".into());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let mut info = NodeInfo {
            node_type: "trojan".into(),
            server_port: port,
            listen_ip: Some("127.0.0.1".into()),
            tls_settings: Some(serde_json::json!({"allow_insecure":true})),
            ..Default::default()
        };
        let ctx = runner.inbound_context(&info).unwrap();
        assert!(Arc::ptr_eq(
            &ctx.rate_limiter,
            &runner.inbound_context(&info).unwrap().rate_limiter
        ));
        assert!(runner.launch_inbound(&info, &[]).await.is_err());
        drop(listener);
        let mut active = runner.launch_inbound(&info, &[]).await.unwrap();
        active.stop().await;
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .unwrap();
        drop(listener);
        info.node_type = "unknown-protocol".into();
        assert_eq!(
            runner
                .launch_inbound(&info, &[])
                .await
                .err()
                .unwrap()
                .kind(),
            std::io::ErrorKind::Unsupported
        );
        info.server_port = 0;
        assert!(runner.inbound_context(&info).is_err());
    }

    #[tokio::test]
    async fn traffic_retries_failures_and_serializes_ack_with_new_traffic() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let runner = Arc::new(runner(format!("http://{}", listener.local_addr().unwrap())));
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut started = Some(started_tx);
            let mut release = Some(release_rx);
            let mut requests = Vec::new();
            for step in 0..4 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut header = Vec::new();
                while !header.ends_with(b"\r\n\r\n") {
                    header.push(stream.read_u8().await.unwrap());
                }
                let header = String::from_utf8(header).unwrap().to_lowercase();
                let len: usize = header
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length:"))
                    .unwrap()
                    .trim()
                    .parse()
                    .unwrap();
                let mut body = vec![0; len];
                stream.read_exact(&mut body).await.unwrap();
                let items: Vec<TrafficItem> = serde_json::from_slice(&body).unwrap();
                requests.push((items[0].u, items[0].d));
                if step == 1 {
                    // Let the real reqwest timeout expire without acknowledging the request.
                    tokio::time::sleep(Duration::from_secs(16)).await;
                    continue;
                }
                if step == 2 {
                    started.take().unwrap().send(()).unwrap();
                    release.take().unwrap().await.unwrap();
                }
                let status = if step == 0 {
                    "500 Internal Server Error"
                } else {
                    "200 OK"
                };
                stream.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{{}}").as_bytes()).await.unwrap();
            }
            requests
        });
        runner.traffic_buffer.lock().insert(42, (100, 500));
        runner.report_data(false).await;
        assert_eq!(runner.traffic_buffer.lock()[&42], (100, 500));
        runner.report_data(false).await;
        assert_eq!(runner.traffic_buffer.lock()[&42], (100, 500));
        let r = runner.clone();
        let first = tokio::spawn(async move { r.report_data(false).await });
        started_rx.await.unwrap();
        *runner.traffic_buffer.lock().get_mut(&42).unwrap() = (130, 570);
        let r = runner.clone();
        let concurrent = tokio::spawn(async move { r.report_data(false).await });
        release_tx.send(()).unwrap();
        first.await.unwrap();
        concurrent.await.unwrap();
        assert!(runner.traffic_buffer.lock().is_empty());
        assert_eq!(
            server.await.unwrap(),
            vec![(100, 500), (100, 500), (100, 500), (30, 70)]
        );
    }
    #[tokio::test]
    async fn pending_traffic_survives_restart_and_rejects_conflicting_or_corrupt_state() {
        let dir = std::env::temp_dir().join(format!("elise-traffic-{}", uuid::Uuid::new_v4()));
        let path = dir.join("pending.json");
        let mut first = runner("http://127.0.0.1:1".into());
        first.traffic_path = path.clone();
        first.restore_pending().unwrap();
        first.traffic_buffer.lock().insert(42, (100, 500));
        first.save_pending().await.unwrap();
        let mut second = runner("http://127.0.0.1:1".into());
        second.traffic_path = path.clone();
        assert!(second.restore_pending().is_err());
        drop(first);
        second.restore_pending().unwrap();
        assert_eq!(second.traffic_buffer.lock()[&42], (100, 500));
        second.traffic_buffer.lock().insert(42, (130, 570));
        std::fs::create_dir(path.with_extension("tmp")).unwrap();
        assert!(second.save_pending().await.is_err());
        let stored: HashMap<u32, (u64, u64)> =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(stored[&42], (100, 500));
        std::fs::remove_dir(path.with_extension("tmp")).unwrap();
        second.save_pending().await.unwrap();
        drop(second);
        let mut restored = runner("http://127.0.0.1:1".into());
        restored.traffic_path = path.clone();
        restored.restore_pending().unwrap();
        assert_eq!(restored.traffic_buffer.lock()[&42], (130, 570));
        restored.traffic_buffer.lock().clear();
        restored.save_pending().await.unwrap();
        drop(restored);
        std::fs::write(&path, b"{bad-json").unwrap();
        let mut corrupt = runner("http://127.0.0.1:1".into());
        corrupt.traffic_path = path.clone();
        assert!(corrupt.restore_pending().is_err());
        assert!(corrupt.traffic_file_lock.lock().is_none());
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(path.with_extension("lock")).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }
}
