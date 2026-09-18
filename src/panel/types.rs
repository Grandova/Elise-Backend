use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct User {
    pub id: u32,
    pub uuid: String,
    pub speed_limit: u64,  // bytes per sec (0 = unlimited)
    pub device_limit: u32, // max devices (0 = unlimited)
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub method: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub flow: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeInfo {
    pub id: u32,
    pub node_type: String,
    pub server_port: u16,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub tls: Option<u8>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub cipher: Option<String>,
    #[serde(default)]
    pub plugin: Option<String>,
    #[serde(default)]
    pub plugin_opts: Option<serde_json::Value>,
    #[serde(default)]
    pub up_mbps: Option<u32>,
    #[serde(default)]
    pub down_mbps: Option<u32>,
    #[serde(default)]
    pub server_key: Option<String>,
    #[serde(default)]
    pub short_ids: Option<Vec<String>>,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default, alias = "alterId", alias = "alter_id")]
    pub alter_id: Option<u32>,
    #[serde(default)]
    pub routes: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub custom_outbounds: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub custom_routes: Option<Vec<serde_json::Value>>,
    #[serde(default)]
    pub cert_config: Option<serde_json::Value>,
    #[serde(default, alias = "networkSettings", alias = "transportSettings", alias = "transport_settings")]
    pub network_settings: Option<serde_json::Value>,
    #[serde(default)]
    pub obfs: Option<String>,
    #[serde(default, alias = "obfs-password", alias = "obfsPassword")]
    pub obfs_password: Option<String>,
    #[serde(default, alias = "tlsSettings")]
    pub tls_settings: Option<serde_json::Value>,
    #[serde(default)]
    pub multiplex: Option<serde_json::Value>,
    #[serde(default)]
    pub utls: Option<serde_json::Value>,
    #[serde(default)]
    pub listen_ip: Option<String>,
    #[serde(default)]
    pub rate: Option<f64>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub encryption: Option<String>,
    #[serde(default)]
    pub decryption: Option<String>,
    #[serde(default)]
    pub encryption_settings: Option<serde_json::Value>,
    #[serde(default, alias = "paddingScheme")]
    pub padding_scheme: Option<serde_json::Value>,
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub congestion_control: Option<String>,
    #[serde(default)]
    pub alpn: Option<serde_json::Value>,
    #[serde(default)]
    pub udp_relay_mode: Option<String>,
    #[serde(default)]
    pub auth_timeout: Option<String>,
    #[serde(default)]
    pub heartbeat: Option<String>,
    #[serde(default)]
    pub zero_rtt_handshake: Option<bool>,
    #[serde(default)]
    pub ports: Option<String>,
    #[serde(default, alias = "hopInterval", alias = "hop_interval")]
    pub hop_interval: Option<u32>,
    #[serde(default, alias = "traffic_pattern", alias = "trafficPattern")]
    pub traffic_pattern: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficItem {
    pub user_id: u32,
    pub u: u64,
    pub d: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnlineDeviceItem {
    pub user_id: u32,
    pub ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NodeStatusReport {
    pub cpu: f64,
    pub mem_total: u64,
    pub mem_used: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    pub disk_total: u64,
    pub disk_used: u64,
    pub uptime: u64,
    pub active_connections: u32,
    pub total_connections: u64,
    pub total_users: u32,
    pub active_users: u32,
    pub in_speed: u64,
    pub out_speed: u64,
    pub tasks_count: u32,
    pub kernel_status: bool,
}

