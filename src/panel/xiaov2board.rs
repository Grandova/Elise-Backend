use crate::panel::types::{NodeInfo, OnlineDeviceItem, TrafficItem, User};
use parking_lot::RwLock;
use reqwest::header::IF_NONE_MATCH;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

/// XiaoV2Board 客户端实现
/// 专门对接广泛使用的 xiaov2board (xiaov2b) 面板体系：
/// - 独立客户端，不与 wyx2685/v2board 混用
/// - 配置获取具备自适应双模式：优先请求 /api/v2/server/config，若返回 404/500（如常见 server is not exist）自动回退到经典 /api/v1/server/UniProxy/config
/// - 遇到 xhttp 传输模式自动规范化为 splithttp
/// - 用户列表接口：GET /api/v1/server/UniProxy/user
/// - 流量上报接口：POST /api/v1/server/UniProxy/push
/// - 在线设备接口：POST /api/v1/server/UniProxy/alive
/// - 活跃列表接口：GET /api/v1/server/UniProxy/alivelist
pub struct XiaoV2BoardClient {
    client: Client,
    base_url: String,
    token: String,
    etag: Arc<RwLock<Option<String>>>,
    cached_users: Arc<RwLock<Vec<User>>>,
}

impl XiaoV2BoardClient {
    pub fn new(base_url: String, token: String) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_default();

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            etag: Arc::new(RwLock::new(None)),
            cached_users: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 获取节点配置，优先探测 V2 接口，失败平滑降级至 V1
    pub async fn get_node_info(
        &self,
        node_id: u32,
    ) -> Result<NodeInfo, Box<dyn std::error::Error + Send + Sync>> {
        let v2_url = format!(
            "{}/api/v2/server/config?node_id={}&token={}",
            self.base_url, node_id, self.token
        );

        if let Ok(resp) = self.client.get(&v2_url).send().await {
            if resp.status().is_success() {
                if let Ok(val) = resp.json::<Value>().await {
                    let data = val.get("data").unwrap_or(&val);
                    if data.is_object() && (data.get("protocol").is_some() || data.get("server_type").is_some() || data.get("server_port").is_some()) {
                        return Ok(self.parse_v2_node_info(node_id, data));
                    }
                }
            }
        }

        // V2 不可用或报错，回退到经典 V1 UniProxy/config 接口
        let v1_url = format!(
            "{}/api/v1/server/UniProxy/config?node_id={}&token={}",
            self.base_url, node_id, self.token
        );
        let resp = self.client.get(&v1_url).send().await?;
        if !resp.status().is_success() {
            return Err(format!("XiaoV2Board API returned status {}", resp.status()).into());
        }

        let val: Value = resp.json().await?;
        let data = val.get("data").unwrap_or(&val);
        Ok(self.parse_v1_node_info(node_id, data))
    }

    fn parse_v2_node_info(&self, node_id: u32, data: &Value) -> NodeInfo {
        let mut node_type = data
            .get("protocol")
            .or_else(|| data.get("server_type"))
            .or_else(|| data.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("vless")
            .to_string();

        let version = data
            .get("version")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        if (node_type == "hysteria" || node_type == "hy") && version == Some(2) {
            node_type = "hysteria2".to_string();
        }

        let tls_val = data.get("tls_settings").or_else(|| data.get("tlsSettings"));

        let server_name = tls_val
            .and_then(|t| {
                t.get("server_name")
                    .and_then(|v| v.as_str())
                    .or_else(|| {
                        t.get("server_names")
                            .and_then(|arr| arr.as_array())
                            .and_then(|a| a.first())
                            .and_then(|v| v.as_str())
                    })
            })
            .or_else(|| data.get("server_name").and_then(|v| v.as_str()))
            .map(String::from);

        let short_ids = tls_val
            .and_then(|t| {
                t.get("short_ids")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect::<Vec<_>>()
                    })
                    .or_else(|| {
                        t.get("short_id")
                            .and_then(|v| v.as_str())
                            .map(|s| vec![s.to_string()])
                    })
            })
            .or_else(|| {
                data.get("short_ids").and_then(|v| v.as_array()).map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect::<Vec<_>>()
                })
            });

        let public_key = tls_val
            .and_then(|t| {
                t.get("private_key")
                    .or_else(|| t.get("public_key"))
                    .and_then(|v| v.as_str())
            })
            .or_else(|| data.get("public_key").and_then(|v| v.as_str()))
            .map(String::from);

        let nw_settings = data
            .get("network_settings")
            .or_else(|| data.get("networkSettings"))
            .cloned();

        let host = nw_settings
            .as_ref()
            .and_then(|nw| {
                nw.get("headers")
                    .and_then(|h| h.get("Host"))
                    .and_then(|v| v.as_str())
                    .or_else(|| nw.get("host").and_then(|v| v.as_str()))
            })
            .or_else(|| data.get("host").and_then(|v| v.as_str()))
            .map(String::from);

        let path = nw_settings
            .as_ref()
            .and_then(|nw| nw.get("path").and_then(|v| v.as_str()))
            .or_else(|| data.get("path").and_then(|v| v.as_str()))
            .map(String::from);

        let mut network = data
            .get("network")
            .or_else(|| data.get("transport"))
            .and_then(|v| v.as_str())
            .map(String::from);

        // 对 xiaov2board 下发的 xhttp 规范化为 splithttp
        if network.as_deref() == Some("xhttp") {
            network = Some("splithttp".to_string());
        }

        NodeInfo {
            id: node_id,
            node_type,
            server_port: data
                .get("server_port")
                .and_then(|v| v.as_u64())
                .unwrap_or(443) as u16,
            host,
            path,
            server_name,
            tls: data.get("tls").and_then(|v| v.as_u64()).map(|v| v as u8),
            network,
            cipher: data
                .get("cipher")
                .and_then(|v| v.as_str())
                .map(String::from),
            plugin: data
                .get("plugin")
                .and_then(|v| v.as_str())
                .map(String::from),
            plugin_opts: data.get("plugin_opts").cloned(),
            up_mbps: data
                .get("up_mbps")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            down_mbps: data
                .get("down_mbps")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            server_key: data
                .get("server_key")
                .and_then(|v| v.as_str())
                .map(String::from),
            short_ids,
            public_key,
            routes: data.get("routes").and_then(|v| v.as_array()).cloned(),
            custom_outbounds: data
                .get("custom_outbounds")
                .and_then(|v| v.as_array())
                .cloned(),
            custom_routes: data
                .get("custom_routes")
                .and_then(|v| v.as_array())
                .cloned(),
            cert_config: data.get("cert_config").cloned(),
            network_settings: nw_settings,
            obfs: data.get("obfs").and_then(|v| v.as_str()).map(String::from),
            obfs_password: data
                .get("obfs_password")
                .or_else(|| data.get("obfs-password"))
                .and_then(|v| v.as_str())
                .map(String::from),
            tls_settings: tls_val.cloned(),
            multiplex: data.get("multiplex").cloned(),
            utls: data.get("utls").cloned(),
            listen_ip: data
                .get("listen_ip")
                .and_then(|v| v.as_str())
                .map(String::from),
            rate: data.get("rate").and_then(|v| v.as_f64()),
            flow: data.get("flow").and_then(|v| v.as_str()).map(String::from),
            encryption: data
                .get("encryption")
                .and_then(|v| v.as_str())
                .map(String::from),
            decryption: data
                .get("decryption")
                .and_then(|v| v.as_str())
                .map(String::from),
            encryption_settings: data
                .get("encryption_settings")
                .or_else(|| data.get("encryptionSettings"))
                .cloned(),
            padding_scheme: data
                .get("padding_scheme")
                .or_else(|| data.get("paddingScheme"))
                .cloned(),
            version,
            congestion_control: data
                .get("congestion_control")
                .or_else(|| data.get("congestion-controller"))
                .and_then(|v| v.as_str())
                .map(String::from),
            alpn: data.get("alpn").cloned(),
            udp_relay_mode: data
                .get("udp_relay_mode")
                .or_else(|| data.get("udp-relay-mode"))
                .and_then(|v| v.as_str())
                .map(String::from),
            auth_timeout: data
                .get("auth_timeout")
                .and_then(|v| v.as_str())
                .map(String::from),
            heartbeat: data
                .get("heartbeat")
                .and_then(|v| v.as_str())
                .map(String::from),
            zero_rtt_handshake: data.get("zero_rtt_handshake").and_then(|v| v.as_bool()),
            ports: data
                .get("ports")
                .or_else(|| data.get("server_ports"))
                .and_then(|v| v.as_str())
                .map(String::from),
            hop_interval: data
                .get("hop_interval")
                .or_else(|| data.get("hopInterval"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            traffic_pattern: data
                .get("traffic_pattern")
                .or_else(|| data.get("trafficPattern"))
                .and_then(|v| v.as_str())
                .map(String::from),
            transport: data
                .get("transport")
                .or_else(|| data.get("network"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_ascii_uppercase()),
            ..Default::default()
        }
    }

    fn parse_v1_node_info(&self, node_id: u32, data: &Value) -> NodeInfo {
        let mut node_type = data
            .get("server_type")
            .or_else(|| data.get("protocol"))
            .or_else(|| data.get("node_type"))
            .or_else(|| data.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("vless")
            .to_string();

        let version = data
            .get("version")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        if (node_type == "hysteria" || node_type == "hy") && version == Some(2) {
            node_type = "hysteria2".to_string();
        }

        let mut network = data
            .get("network")
            .or_else(|| data.get("transport"))
            .and_then(|v| v.as_str())
            .map(String::from);

        if network.as_deref() == Some("xhttp") {
            network = Some("splithttp".to_string());
        }

        let short_ids = data.get("short_ids").and_then(|v| v.as_array()).map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect::<Vec<_>>()
        });

        NodeInfo {
            id: node_id,
            node_type,
            server_port: data
                .get("server_port")
                .and_then(|v| v.as_u64())
                .unwrap_or(443) as u16,
            host: data.get("host").and_then(|v| v.as_str()).map(String::from),
            path: data.get("path").and_then(|v| v.as_str()).map(String::from),
            server_name: data
                .get("server_name")
                .and_then(|v| v.as_str())
                .map(String::from),
            tls: data.get("tls").and_then(|v| v.as_u64()).map(|v| v as u8),
            network,
            cipher: data
                .get("cipher")
                .and_then(|v| v.as_str())
                .map(String::from),
            plugin: data
                .get("plugin")
                .and_then(|v| v.as_str())
                .map(String::from),
            plugin_opts: data.get("plugin_opts").cloned(),
            up_mbps: data
                .get("up_mbps")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            down_mbps: data
                .get("down_mbps")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            server_key: data
                .get("server_key")
                .and_then(|v| v.as_str())
                .map(String::from),
            short_ids,
            public_key: data
                .get("public_key")
                .and_then(|v| v.as_str())
                .map(String::from),
            routes: data.get("routes").and_then(|v| v.as_array()).cloned(),
            custom_outbounds: data
                .get("custom_outbounds")
                .and_then(|v| v.as_array())
                .cloned(),
            custom_routes: data
                .get("custom_routes")
                .and_then(|v| v.as_array())
                .cloned(),
            cert_config: data.get("cert_config").cloned(),
            network_settings: data
                .get("networkSettings")
                .or_else(|| data.get("network_settings"))
                .or_else(|| data.get("wsSettings"))
                .cloned(),
            obfs: data.get("obfs").and_then(|v| v.as_str()).map(String::from),
            obfs_password: data
                .get("obfs_password")
                .or_else(|| data.get("obfs-password"))
                .and_then(|v| v.as_str())
                .map(String::from),
            tls_settings: data
                .get("tls_settings")
                .or_else(|| data.get("tlsSettings"))
                .cloned(),
            multiplex: data.get("multiplex").cloned(),
            utls: data.get("utls").cloned(),
            listen_ip: data
                .get("listen_ip")
                .and_then(|v| v.as_str())
                .map(String::from),
            rate: data.get("rate").and_then(|v| v.as_f64()),
            flow: data.get("flow").and_then(|v| v.as_str()).map(String::from),
            encryption: data
                .get("encryption")
                .and_then(|v| v.as_str())
                .map(String::from),
            decryption: data
                .get("decryption")
                .and_then(|v| v.as_str())
                .map(String::from),
            encryption_settings: data
                .get("encryption_settings")
                .or_else(|| data.get("encryptionSettings"))
                .cloned(),
            padding_scheme: data
                .get("padding_scheme")
                .or_else(|| data.get("paddingScheme"))
                .cloned(),
            version,
            congestion_control: data
                .get("congestion_control")
                .or_else(|| data.get("congestion-controller"))
                .and_then(|v| v.as_str())
                .map(String::from),
            alpn: data.get("alpn").cloned(),
            udp_relay_mode: data
                .get("udp_relay_mode")
                .or_else(|| data.get("udp-relay-mode"))
                .and_then(|v| v.as_str())
                .map(String::from),
            auth_timeout: data
                .get("auth_timeout")
                .and_then(|v| v.as_str())
                .map(String::from),
            heartbeat: data
                .get("heartbeat")
                .and_then(|v| v.as_str())
                .map(String::from),
            zero_rtt_handshake: data.get("zero_rtt_handshake").and_then(|v| v.as_bool()),
            ports: data
                .get("ports")
                .or_else(|| data.get("server_ports"))
                .and_then(|v| v.as_str())
                .map(String::from),
            hop_interval: data
                .get("hop_interval")
                .or_else(|| data.get("hopInterval"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            traffic_pattern: data
                .get("traffic_pattern")
                .or_else(|| data.get("trafficPattern"))
                .and_then(|v| v.as_str())
                .map(String::from),
            transport: data
                .get("transport")
                .or_else(|| data.get("network"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_ascii_uppercase()),
            ..Default::default()
        }
    }

    /// 获取用户列表，支持 ETag 缓存
    pub async fn get_users(
        &self,
        node_id: u32,
    ) -> Result<Vec<User>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/api/v1/server/UniProxy/user?node_id={}&token={}",
            self.base_url, node_id, self.token
        );

        let mut req = self.client.get(&url);
        if let Some(etag) = self.etag.read().as_ref() {
            req = req.header(IF_NONE_MATCH, etag);
        }

        let resp = req.send().await?;

        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(self.cached_users.read().clone());
        }

        if !resp.status().is_success() {
            return Err(format!("XiaoV2Board API user sync returned status {}", resp.status()).into());
        }

        if let Some(new_etag) = resp.headers().get("ETag").and_then(|h| h.to_str().ok()) {
            *self.etag.write() = Some(new_etag.to_string());
        }

        let val: Value = resp.json().await?;
        let user_list = val
            .get("users")
            .or_else(|| val.get("data"))
            .and_then(|v| v.as_array());

        let mut users = Vec::new();
        if let Some(arr) = user_list {
            for item in arr {
                let id = item.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let uuid = item
                    .get("uuid")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let speed_limit = item
                    .get("speed_limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
                let device_limit = item
                    .get("device_limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;

                users.push(User {
                    id,
                    uuid,
                    speed_limit,
                    device_limit,
                    password: item
                        .get("password")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    method: item
                        .get("method")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    port: item.get("port").and_then(|v| v.as_u64()).map(|v| v as u16),
                    flow: item.get("flow").and_then(|v| v.as_str()).map(String::from),
                });
            }
        }

        *self.cached_users.write() = users.clone();
        Ok(users)
    }

    /// 上报用户流量
    pub async fn report_traffic(
        &self,
        node_id: u32,
        traffic: Vec<TrafficItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if traffic.is_empty() {
            return Ok(());
        }

        let url = format!(
            "{}/api/v1/server/UniProxy/push?node_id={}&token={}",
            self.base_url, node_id, self.token
        );

        let mut payload: HashMap<String, [u64; 2]> = HashMap::with_capacity(traffic.len());
        for item in traffic {
            payload.insert(item.user_id.to_string(), [item.u, item.d]);
        }

        let resp = self.client.post(&url).json(&payload).send().await?;

        if !resp.status().is_success() {
            return Err(format!(
                "XiaoV2Board API traffic report returned status {}",
                resp.status()
            )
            .into());
        }
        Ok(())
    }

    /// 上报在线设备 IP
    pub async fn report_online_devices(
        &self,
        node_id: u32,
        devices: Vec<OnlineDeviceItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if devices.is_empty() {
            return Ok(());
        }

        let url = format!(
            "{}/api/v1/server/UniProxy/alive?node_id={}&token={}",
            self.base_url, node_id, self.token
        );

        let mut payload: HashMap<String, Vec<String>> = HashMap::with_capacity(devices.len());
        for item in devices {
            payload.insert(item.user_id.to_string(), item.ips);
        }

        let _ = self.client.post(&url).json(&payload).send().await;
        Ok(())
    }

    /// 获取在线设备数列表
    pub async fn get_user_alivelist(
        &self,
        node_id: u32,
    ) -> Result<HashMap<u32, u32>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/api/v1/server/UniProxy/alivelist?node_id={}&token={}",
            self.base_url, node_id, self.token
        );
        let resp = match self.client.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return Ok(HashMap::new()),
        };

        if !resp.status().is_success() {
            return Ok(HashMap::new());
        }

        let val: Value = match resp.json().await {
            Ok(v) => v,
            Err(_) => return Ok(HashMap::new()),
        };

        let mut res = HashMap::new();
        let map_obj = val
            .get("alive")
            .or_else(|| val.get("data"))
            .or(Some(&val))
            .and_then(|v| v.as_object());

        if let Some(map) = map_obj {
            for (k, v) in map {
                if let (Ok(uid), Some(cnt)) = (k.parse::<u32>(), v.as_u64()) {
                    res.insert(uid, cnt as u32);
                }
            }
        }
        Ok(res)
    }
}

