use crate::panel::types::{NodeInfo, OnlineDeviceItem, TrafficItem, User};
use reqwest::Client;
use serde_json::Value;

pub struct SSPanelClient {
    client: Client,
    base_url: String,
    key: String,
}

impl SSPanelClient {
    pub fn new(base_url: String, key: String) -> Self {
        Self {
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(15))
                .build()
                .unwrap_or_default(),
            base_url: base_url.trim_end_matches('/').to_string(),
            key,
        }
    }

    pub async fn get_node_info(
        &self,
        node_id: u32,
    ) -> Result<NodeInfo, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/mod_mu/nodes/{}/info?key={}",
            self.base_url, node_id, self.key
        );
        let resp = self.client.get(&url).send().await?;
        let val: Value = resp.json().await?;
        let data = val.get("data").unwrap_or(&val);

        let is_ssr = matches!(
            data.get("type").and_then(Value::as_str),
            Some("ssr" | "shadowsocksr")
        );

        Ok(NodeInfo {
            id: node_id,
            node_type: data
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or("shadowsocks")
                .to_string(),
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
            network: data
                .get("network")
                .and_then(|v| v.as_str())
                .map(String::from),
            cipher: data
                .get("cipher")
                .or_else(|| if is_ssr { data.get("method") } else { None })
                .and_then(|v| v.as_str())
                .map(String::from),
            plugin: data
                .get("plugin")
                .and_then(|v| v.as_str())
                .map(String::from),
            plugin_opts: data.get("plugin_opts").cloned(),
            up_mbps: None,
            down_mbps: None,
            server_key: if is_ssr {
                data.get("password")
                    .or_else(|| data.get("passwd"))
                    .and_then(Value::as_str)
                    .map(String::from)
            } else {
                None
            },
            network_settings: if is_ssr { Some(data.clone()) } else { None },
            obfs: if is_ssr {
                data.get("obfs").and_then(Value::as_str).map(String::from)
            } else {
                None
            },
            short_ids: None,
            public_key: None,
            ..Default::default()
        })
    }

    pub async fn get_users(
        &self,
        node_id: u32,
    ) -> Result<Vec<User>, Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/mod_mu/users?node_id={}&key={}",
            self.base_url, node_id, self.key
        );
        let resp = self.client.get(&url).send().await?.error_for_status()?;
        let val: Value = resp.json().await?;
        let user_list = val.get("data").and_then(|v| v.as_array());

        if user_list.is_none() {
            return Err("SSPanel user response has no users array".into());
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
                    speed_limit: crate::panel::types::speed_limit_bps(item.get("node_speedlimit"))?,
                    device_limit: item
                        .get("node_iplimit")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0) as u32,
                    password: item
                        .get("passwd")
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
        Ok(users)
    }

    pub async fn report_traffic(
        &self,
        node_id: u32,
        traffic: Vec<TrafficItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/mod_mu/users/traffic?node_id={}&key={}",
            self.base_url, node_id, self.key
        );
        self.client
            .post(&url)
            .json(&traffic)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn report_online_devices(
        &self,
        node_id: u32,
        devices: Vec<OnlineDeviceItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let url = format!(
            "{}/mod_mu/users/aliveip?node_id={}&key={}",
            self.base_url, node_id, self.key
        );
        let _ = self.client.post(&url).json(&devices).send().await;
        Ok(())
    }
}
