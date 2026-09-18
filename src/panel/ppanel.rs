use crate::panel::types::{NodeInfo, OnlineDeviceItem, TrafficItem, User};
use parking_lot::RwLock;
use reqwest::header::IF_NONE_MATCH;
use reqwest::Client;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;

/// PPanel 客户端实现
/// 严格参考并对齐官方 perfect-panel/ppanel-node 规范：
/// - 节点配置：优先请求 GET /v2/server/{server_id}?secret_key={key}，完整解析 protocols 数组
/// - 兼容回退：老版 GET /api/v1/server/nodes/{node_id}?token={key}
/// - 用户列表：GET /v1/server/user?server_id={node_id}&secret_key={key}，支持 ETag 304 缓存
/// - 流量上报：POST /v1/server/push，Body: {"traffic": [{"uid": ..., "upload": ..., "download": ...}]}
/// - 在线设备：POST /v1/server/online，Body: {"users": [{"uid": ..., "ip": ...}]}
/// - 在线统计：GET /v1/server/alivelist?server_id={node_id}&secret_key={key}
pub struct PPanelClient {
    client: Client,
    base_url: String,
    key: String,
    cached_users: RwLock<HashMap<u32, Arc<tokio::sync::Mutex<(Option<String>, Vec<User>)>>>>,
}

impl PPanelClient {
    pub fn new(base_url: String, key: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
            base_url: base_url.trim_end_matches('/').to_string(),
            key,
            cached_users: RwLock::new(HashMap::new()),
        }
    }

    /// 获取节点配置，优先对接官方 ppanel-node 的 /v2/server/{server_id}
    pub async fn get_node_info(
        &self,
        node_id: u32,
    ) -> Result<NodeInfo, Box<dyn std::error::Error + Send + Sync>> {
        // 1. 尝试官方 V2 路径 (/v2/server/{node_id} 与 /api/v2/server/{node_id})
        for v2_path in [
            format!(
                "{}/v2/server/{}?secret_key={}",
                self.base_url, node_id, self.key
            ),
            format!(
                "{}/api/v2/server/{}?secret_key={}",
                self.base_url, node_id, self.key
            ),
        ] {
            if let Ok(resp) = self.client.get(&v2_path).send().await {
                if resp.status().is_success() {
                    if let Ok(val) = resp.json::<Value>().await {
                        let data = val.get("data").unwrap_or(&val);
                        if let Some(protocols) = data.get("protocols").and_then(|p| p.as_array()) {
                            // 查找第一个已启用的协议配置
                            for proto in protocols {
                                let enabled = proto
                                    .get("enable")
                                    .and_then(|e| e.as_bool())
                                    .unwrap_or(true);
                                if enabled {
                                    return Ok(self.parse_v2_protocol(node_id, proto, data));
                                }
                            }
                            if let Some(first) = protocols.first() {
                                return Ok(self.parse_v2_protocol(node_id, first, data));
                            }
                        } else if data.get("type").is_some() || data.get("protocol").is_some() {
                            return Ok(self.parse_v1_data(node_id, data));
                        }
                    }
                }
            }
        }

        // 2. 回退到经典老版接口 (/api/v1/server/nodes/{node_id})
        let v1_url = format!(
            "{}/api/v1/server/nodes/{}?token={}",
            self.base_url, node_id, self.key
        );
        let resp = self.client.get(&v1_url).send().await?;
        if !resp.status().is_success() {
            return Err(format!("PPanel API returned status {}", resp.status()).into());
        }

        let val: Value = resp.json().await?;
        let data = val.get("data").unwrap_or(&val);
        Ok(self.parse_v1_data(node_id, data))
    }

    fn parse_v2_protocol(&self, node_id: u32, proto: &Value, root_data: &Value) -> NodeInfo {
        let mut node_type = proto
            .get("type")
            .or_else(|| proto.get("protocol"))
            .and_then(|v| v.as_str())
            .unwrap_or("vless")
            .to_string();

        if node_type == "hysteria" {
            // 兼容 hysteria / hysteria2
            if proto.get("obfs_password").is_some() {
                node_type = "hysteria2".to_string();
            }
        }

        let security = proto
            .get("security")
            .and_then(|v| v.as_str())
            .unwrap_or("none");
        let tls = match security.to_ascii_lowercase().as_str() {
            "reality" => Some(2),
            "tls" => Some(1),
            _ => None,
        };

        let mut network = proto
            .get("transport")
            .or_else(|| proto.get("network"))
            .and_then(|v| v.as_str())
            .map(String::from);

        if network.as_deref() == Some("xhttp") {
            network = Some("splithttp".to_string());
        }

        let server_name = proto
            .get("sni")
            .or_else(|| proto.get("server_name"))
            .and_then(|v| v.as_str())
            .map(String::from);

        let short_ids = proto
            .get("reality_short_id")
            .and_then(|v| v.as_str())
            .map(|s| vec![s.to_string()]);

        let public_key = proto
            .get("reality_public_key")
            .or_else(|| proto.get("public_key"))
            .and_then(|v| v.as_str())
            .map(String::from);

        let up_mbps = proto
            .get("up_mbps")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let down_mbps = proto
            .get("down_mbps")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        let routes = root_data
            .get("block")
            .or_else(|| root_data.get("routes"))
            .and_then(|v| v.as_array())
            .cloned();
        let custom_outbounds = root_data
            .get("outbound")
            .and_then(|v| v.as_array())
            .cloned();

        NodeInfo {
            id: node_id,
            node_type,
            server_port: proto.get("port").and_then(|v| v.as_u64()).unwrap_or(443) as u16,
            host: proto.get("host").and_then(|v| v.as_str()).map(String::from),
            path: proto.get("path").and_then(|v| v.as_str()).map(String::from),
            server_name,
            tls,
            network,
            cipher: proto
                .get("cipher")
                .and_then(|v| v.as_str())
                .map(String::from),
            plugin: proto
                .get("plugin")
                .and_then(|v| v.as_str())
                .map(String::from),
            plugin_opts: proto.get("plugin_opts").cloned(),
            up_mbps,
            down_mbps,
            server_key: proto
                .get("server_key")
                .and_then(|v| v.as_str())
                .map(String::from),
            short_ids,
            public_key,
            routes,
            custom_outbounds,
            obfs_password: proto
                .get("obfs_password")
                .and_then(|v| v.as_str())
                .map(String::from),
            flow: proto.get("flow").and_then(|v| v.as_str()).map(String::from),
            congestion_control: proto
                .get("congestion_controller")
                .or_else(|| proto.get("congestion_control"))
                .and_then(|v| v.as_str())
                .map(String::from),
            padding_scheme: proto.get("padding_scheme").cloned(),
            encryption: proto
                .get("encryption")
                .and_then(|v| v.as_str())
                .map(String::from),
            rate: proto.get("ratio").and_then(|v| v.as_f64()),
            ..Default::default()
        }
    }

    fn parse_v1_data(&self, node_id: u32, data: &Value) -> NodeInfo {
        NodeInfo {
            id: node_id,
            node_type: data
                .get("type")
                .or_else(|| data.get("protocol"))
                .and_then(|v| v.as_str())
                .unwrap_or("vless")
                .to_string(),
            server_port: data
                .get("port")
                .or_else(|| data.get("server_port"))
                .and_then(|v| v.as_u64())
                .unwrap_or(443) as u16,
            host: data.get("host").and_then(|v| v.as_str()).map(String::from),
            path: data.get("path").and_then(|v| v.as_str()).map(String::from),
            server_name: data
                .get("server_name")
                .or_else(|| data.get("sni"))
                .and_then(|v| v.as_str())
                .map(String::from),
            tls: data.get("tls").and_then(|v| v.as_u64()).map(|v| v as u8),
            network: data
                .get("network")
                .or_else(|| data.get("transport"))
                .and_then(|v| v.as_str())
                .map(String::from),
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
            short_ids: None,
            public_key: data
                .get("public_key")
                .or_else(|| data.get("reality_public_key"))
                .and_then(|v| v.as_str())
                .map(String::from),
            ..Default::default()
        }
    }

    /// 获取用户列表，支持官方 /v1/server/user 与 ETag 缓存
    pub async fn get_users(
        &self,
        node_id: u32,
    ) -> Result<Vec<User>, Box<dyn std::error::Error + Send + Sync>> {
        let official_url = format!(
            "{}/v1/server/user?server_id={}&secret_key={}",
            self.base_url, node_id, self.key
        );

        let cache = self
            .cached_users
            .write()
            .entry(node_id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new((None, Vec::new()))))
            .clone();
        let mut cache = cache.lock().await;
        let mut req = self.client.get(&official_url);
        if let Some(etag) = cache.0.as_ref() {
            req = req.header(IF_NONE_MATCH, etag);
        }

        let resp = match req.send().await {
            Ok(r) if r.status().is_success() || r.status() == reqwest::StatusCode::NOT_MODIFIED => {
                r
            }
            _ => {
                // 回退到老版路径 /api/v1/server/nodes/{node_id}/users?token={key}
                let fallback_url = format!(
                    "{}/api/v1/server/nodes/{}/users?token={}",
                    self.base_url, node_id, self.key
                );
                let mut fallback_req = self.client.get(&fallback_url);
                if let Some(etag) = cache.0.as_ref() {
                    fallback_req = fallback_req.header(IF_NONE_MATCH, etag);
                }
                fallback_req.send().await?
            }
        };

        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            if cache.0.is_none() {
                return Err("Panel returned 304 without a cached ETag".into());
            }
            return Ok(cache.1.clone());
        }

        if !resp.status().is_success() {
            return Err(format!("PPanel API user sync returned status {}", resp.status()).into());
        }

        let new_etag = resp
            .headers()
            .get("ETag")
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);

        let val: Value = resp.json().await?;
        let user_list = val
            .get("data")
            .and_then(|d| d.get("users").or(Some(d)))
            .or_else(|| val.get("users"))
            .and_then(|v| v.as_array());

        if user_list.is_none() {
            return Err("Panel user response has no users array".into());
        }
        let mut users = Vec::new();
        if let Some(arr) = user_list {
            for item in arr {
                users.push(User {
                    id: item.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32,
                    uuid: item
                        .get("uuid")
                        .and_then(|v| v.as_str())
                        .unwrap_or_default()
                        .to_string(),
                    speed_limit: crate::panel::types::speed_limit_bps(item.get("speed_limit"))?,
                    device_limit: item
                        .get("device_limit")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32,
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

        *cache = (new_etag, users.clone());
        Ok(users)
    }

    /// 上报用户流量，对齐官方 ServerPushUserTrafficRequest {"traffic": [{"uid": ..., "upload": ..., "download": ...}]}
    pub async fn report_traffic(
        &self,
        node_id: u32,
        traffic: Vec<TrafficItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if traffic.is_empty() {
            return Ok(());
        }

        let official_url = format!(
            "{}/v1/server/push?server_id={}&secret_key={}",
            self.base_url, node_id, self.key
        );

        let payload = json!({
            "traffic": traffic.iter().map(|t| {
                json!({
                    "uid": t.user_id,
                    "upload": t.u,
                    "download": t.d,
                })
            }).collect::<Vec<_>>()
        });

        let resp = self.client.post(&official_url).json(&payload).send().await;
        match resp {
            Ok(r) if r.status().is_success() => return Ok(()),
            _ => {
                // 降级回退老版路径
                let fallback_url = format!(
                    "{}/api/v1/server/nodes/{}/traffic?token={}",
                    self.base_url, node_id, self.key
                );
                let _ = self.client.post(&fallback_url).json(&traffic).send().await;
            }
        }
        Ok(())
    }

    /// 上报在线设备 IP，对齐官方 UserOnlineBody {"users": [{"uid": ..., "ip": ...}]}
    pub async fn report_online_devices(
        &self,
        node_id: u32,
        devices: Vec<OnlineDeviceItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if devices.is_empty() {
            return Ok(());
        }

        let official_url = format!(
            "{}/v1/server/online?server_id={}&secret_key={}",
            self.base_url, node_id, self.key
        );

        let mut online_list = Vec::new();
        for dev in devices {
            for ip in dev.ips {
                online_list.push(json!({
                    "uid": dev.user_id,
                    "ip": ip,
                }));
            }
        }

        let payload = json!({
            "users": online_list,
        });

        let resp = self.client.post(&official_url).json(&payload).send().await;
        match resp {
            Ok(r) if r.status().is_success() => return Ok(()),
            _ => {
                // 降级回退老版路径
                let fallback_url = format!(
                    "{}/api/v1/server/nodes/{}/online?token={}",
                    self.base_url, node_id, self.key
                );
                let _ = self.client.post(&fallback_url).json(&payload).send().await;
            }
        }
        Ok(())
    }

    /// 获取在线用户数列表
    pub async fn get_user_alivelist(
        &self,
        node_id: u32,
    ) -> Result<HashMap<u32, u32>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/v1/server/alivelist?server_id={}&secret_key={}",
            self.base_url, node_id, self.key
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
