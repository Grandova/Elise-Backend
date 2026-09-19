use crate::panel::types::NodeInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransportType {
    RawTcp,
    WebSocket,
    Grpc,
    HttpUpgrade,
    XHttp,
    LegacyHttp2,
    MKcp,
}

#[derive(Debug, Clone)]
pub struct StreamSettings {
    pub transport: TransportConfig,
    pub security: TransportSecurityConfig,
    pub accept_proxy_protocol: bool,
    pub client_tls_profile: Option<ClientTlsProfile>,
    pub client_reality_profile: Option<RealityClientProfile>,
}

#[derive(Debug, Clone)]
pub enum TransportConfig {
    Tcp(TcpTransportConfig),
    WebSocket(WebSocketTransportConfig),
    Grpc(GrpcTransportConfig),
    HttpUpgrade(HttpUpgradeTransportConfig),
    XHttp(XHttpTransportConfig),
    LegacyHttp2(Http2TransportConfig),
    MKcp(MKcpTransportConfig),
}

impl TransportConfig {
    pub fn transport_type(&self) -> TransportType {
        match self {
            Self::Tcp(_) => TransportType::RawTcp,
            Self::WebSocket(_) => TransportType::WebSocket,
            Self::Grpc(_) => TransportType::Grpc,
            Self::HttpUpgrade(_) => TransportType::HttpUpgrade,
            Self::XHttp(_) => TransportType::XHttp,
            Self::LegacyHttp2(_) => TransportType::LegacyHttp2,
            Self::MKcp(_) => TransportType::MKcp,
        }
    }
}

#[derive(Debug, Clone)]
pub struct MKcpTransportConfig {
    pub mtu: u32,
    pub tti: u32,
    pub uplink_capacity: u32,
    pub downlink_capacity: u32,
    pub congestion: bool,
    pub read_buffer_size: u32,
    pub write_buffer_size: u32,
    pub seed: Option<String>,
    pub header_type: String,
}

#[derive(Debug, Clone)]
pub struct TcpTransportConfig {
    pub header_type: TcpHeaderType,
    pub request: Option<TcpHttpRequestConfig>,
    pub response: Option<TcpHttpResponseConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpHeaderType {
    None,
    Http,
}

#[derive(Debug, Clone)]
pub struct TcpHttpRequestConfig {
    pub version: String,
    pub method: String,
    pub path: Vec<String>,
    pub headers: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct TcpHttpResponseConfig {
    pub version: String,
    pub status: String,
    pub reason: String,
    pub headers: HashMap<String, Vec<String>>,
}

#[derive(Debug, Clone)]
pub struct WebSocketTransportConfig {
    pub path: String,
    pub host: Option<String>,
    pub headers: HashMap<String, String>,
    pub heartbeat_period: Option<Duration>,
    pub early_data_header: Option<String>,
    pub max_early_data: u32,
}

#[derive(Debug, Clone)]
pub struct GrpcTransportConfig {
    pub service_name: String,
    pub authority: Option<String>,
    pub multi_mode: bool,
    pub idle_timeout: Duration,
    pub health_check_timeout: Duration,
    pub permit_without_stream: bool,
    pub initial_windows_size: u32,
}

#[derive(Debug, Clone)]
pub struct HttpUpgradeTransportConfig {
    pub path: String,
    pub host: Option<String>,
    pub headers: HashMap<String, String>,
    pub max_early_data: u32,
}

#[derive(Debug, Clone)]
pub struct XHttpTransportConfig {
    pub mode: String,
    pub host: Option<String>,
    pub path: String,
    pub headers: HashMap<String, String>,
    pub extra: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct Http2TransportConfig {
    pub path: String,
    pub host: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum TransportSecurityConfig {
    None,
    Tls(TlsServerConfig),
    Reality(RealityServerConfig),
}

#[derive(Debug, Clone)]
pub struct RealityServerConfig {
    pub dest: String,
    pub server_names: Vec<String>,
    pub private_key: [u8; 32],
    pub short_ids: Vec<Vec<u8>>,
    pub xver: u8,
    pub max_time_diff_ms: u64,
    pub min_client_ver: Option<String>,
    pub max_client_ver: Option<String>,
    pub spider_x: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RealityClientProfile {
    pub server_name: Option<String>,
    pub server_port: Option<u16>,
    pub public_key: Option<String>,
    pub short_id: Option<String>,
    pub fingerprint: Option<TlsFingerprint>,
    pub spider_x: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlsCertificateEntry {
    pub cert_pem: Option<String>,
    pub key_pem: Option<String>,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EchServerConfig {
    pub enabled: bool,
    pub server_keys: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EchClientConfig {
    pub enabled: bool,
    pub config_list: Option<Vec<u8>>,
    pub dns_lookup: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct TlsServerConfig {
    pub server_name: Option<String>,
    pub allow_self_signed: bool,
    pub server_names: Vec<String>,
    pub reject_unknown_sni: bool,
    pub certificates: Vec<TlsCertificateEntry>,
    pub ech: Option<EchServerConfig>,
    pub alpn: Vec<String>,
    pub cert_config: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct ClientTlsProfile {
    pub server_name: Option<String>,
    pub fingerprint: Option<TlsFingerprint>,
    pub allow_insecure: bool,
    pub ech: Option<EchConfig>,
    pub ech_client: Option<EchClientConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsFingerprint {
    Chrome,
    Firefox,
    Safari,
    IOS,
    Android,
    Edge,
    Qq,
    _360,
    Random,
    Randomized,
}

impl TlsFingerprint {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "chrome" => Some(Self::Chrome),
            "firefox" => Some(Self::Firefox),
            "safari" => Some(Self::Safari),
            "ios" => Some(Self::IOS),
            "android" => Some(Self::Android),
            "edge" => Some(Self::Edge),
            "qq" => Some(Self::Qq),
            "360" | "_360" => Some(Self::_360),
            "random" => Some(Self::Random),
            "randomized" => Some(Self::Randomized),
            _ => None,
        }
    }
}

pub fn decode_base64_flexible(s: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let trimmed = s.trim();

    // If it is an existing file path, read it
    if std::path::Path::new(trimmed).exists() {
        if let Ok(content) = std::fs::read(trimmed) {
            if let Ok(text) = std::str::from_utf8(&content) {
                return decode_base64_flexible(text);
            } else {
                return Ok(content);
            }
        }
    }

    let clean: String = if trimmed.contains("-----BEGIN") {
        let mut b64 = String::new();
        let mut in_block = false;
        for line in trimmed.lines() {
            let l = line.trim();
            if l.starts_with("-----BEGIN") {
                in_block = true;
            } else if l.starts_with("-----END") {
                break;
            } else if in_block {
                b64.push_str(l);
            }
        }
        b64
    } else {
        trimmed.chars().filter(|c| !c.is_whitespace()).collect()
    };

    if let Ok(b) = base64::engine::general_purpose::STANDARD.decode(&clean) {
        return Ok(b);
    }
    if let Ok(b) = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&clean) {
        return Ok(b);
    }
    if let Ok(b) = base64::engine::general_purpose::URL_SAFE.decode(&clean) {
        return Ok(b);
    }
    base64::engine::general_purpose::STANDARD_NO_PAD
        .decode(&clean)
        .map_err(|e| format!("invalid base64: {e}"))
}

#[derive(Debug, Clone)]
pub struct EchConfig {
    pub enabled: bool,
    pub config: Option<String>,
    pub query_server_name: Option<String>,
    pub key: Option<String>,
}

impl StreamSettings {
    /// Parse and validate NodeInfo into unified StreamSettings with strict error boundaries.
    /// Rejects unknown transport, unsupported TLS mode, or invalid paths without silent fallback.
    pub fn from_node_info(node_info: &NodeInfo) -> Result<Self, String> {
        let network_str = node_info
            .network
            .as_deref()
            .or(node_info.transport.as_deref())
            .unwrap_or("tcp")
            .trim()
            .to_ascii_lowercase();

        // 1. AcceptProxyProtocol
        let mut accept_proxy_protocol = false;
        if let Some(ns) = &node_info.network_settings {
            if let Some(app) = ns.get("acceptProxyProtocol").and_then(|v| v.as_bool()) {
                accept_proxy_protocol = app;
            }
        }

        // 2. TransportConfig
        let transport = match network_str.as_str() {
            "tcp" | "raw" => {
                let mut header_type = TcpHeaderType::None;
                let mut http_req = None;
                let mut http_resp = None;

                if let Some(ns) = &node_info.network_settings {
                    if let Some(header_val) = ns.get("header") {
                        let htype_str = header_val
                            .get("type")
                            .and_then(|v| v.as_str())
                            .unwrap_or("none");
                        match htype_str.to_ascii_lowercase().as_str() {
                            "none" => header_type = TcpHeaderType::None,
                            "http" => {
                                header_type = TcpHeaderType::Http;

                                // Parse request config
                                let req_val = header_val.get("request");
                                let version = req_val
                                    .and_then(|r| r.get("version"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("1.1")
                                    .to_string();
                                let method = req_val
                                    .and_then(|r| r.get("method"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("GET")
                                    .to_string();

                                let mut path_list = Vec::new();
                                if let Some(paths) = req_val
                                    .and_then(|r| r.get("path"))
                                    .and_then(|v| v.as_array())
                                {
                                    for p in paths {
                                        if let Some(s) = p.as_str() {
                                            path_list.push(s.to_string());
                                        }
                                    }
                                }
                                if path_list.is_empty() {
                                    path_list.push("/".to_string());
                                }

                                let mut req_headers = HashMap::new();
                                if let Some(hdrs) = req_val
                                    .and_then(|r| r.get("headers"))
                                    .and_then(|v| v.as_object())
                                {
                                    for (k, v) in hdrs {
                                        let mut list = Vec::new();
                                        if let Some(arr) = v.as_array() {
                                            for item in arr {
                                                if let Some(s) = item.as_str() {
                                                    list.push(s.to_string());
                                                }
                                            }
                                        } else if let Some(s) = v.as_str() {
                                            list.push(s.to_string());
                                        }
                                        req_headers.insert(k.clone(), list);
                                    }
                                }

                                http_req = Some(TcpHttpRequestConfig {
                                    version,
                                    method,
                                    path: path_list,
                                    headers: req_headers,
                                });

                                // Parse response config
                                let resp_val = header_val.get("response");
                                let r_version = resp_val
                                    .and_then(|r| r.get("version"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("1.1")
                                    .to_string();
                                let r_status = resp_val
                                    .and_then(|r| r.get("status"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("200")
                                    .to_string();
                                let r_reason = resp_val
                                    .and_then(|r| r.get("reason"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("OK")
                                    .to_string();

                                let mut resp_headers = HashMap::new();
                                if let Some(hdrs) = resp_val
                                    .and_then(|r| r.get("headers"))
                                    .and_then(|v| v.as_object())
                                {
                                    for (k, v) in hdrs {
                                        let mut list = Vec::new();
                                        if let Some(arr) = v.as_array() {
                                            for item in arr {
                                                if let Some(s) = item.as_str() {
                                                    list.push(s.to_string());
                                                }
                                            }
                                        } else if let Some(s) = v.as_str() {
                                            list.push(s.to_string());
                                        }
                                        resp_headers.insert(k.clone(), list);
                                    }
                                }

                                http_resp = Some(TcpHttpResponseConfig {
                                    version: r_version,
                                    status: r_status,
                                    reason: r_reason,
                                    headers: resp_headers,
                                });
                            }
                            unknown => return Err(format!("unknown TCP header type: '{unknown}'")),
                        }
                    }
                }

                TransportConfig::Tcp(TcpTransportConfig {
                    header_type,
                    request: http_req,
                    response: http_resp,
                })
            }
            "ws" | "websocket" => {
                let mut path = node_info.path.clone().unwrap_or_else(|| "/".to_string());
                let mut host = node_info.host.clone();
                let mut headers = HashMap::new();
                let mut heartbeat_period = None;
                let mut early_data_header = None;
                let mut max_early_data = 0;

                if let Some(ns) = &node_info.network_settings {
                    if let Some(p) = ns.get("path").and_then(|v| v.as_str()) {
                        path = p.to_string();
                    }
                    if let Some(h) = ns
                        .get("headers")
                        .and_then(|v| v.get("Host"))
                        .and_then(|v| v.as_str())
                    {
                        host = Some(h.to_string());
                    } else if let Some(h) = ns.get("host").and_then(|v| v.as_str()) {
                        host = Some(h.to_string());
                    }
                    if let Some(hdrs) = ns.get("headers").and_then(|v| v.as_object()) {
                        for (k, v) in hdrs {
                            if let Some(s) = v.as_str() {
                                headers.insert(k.clone(), s.to_string());
                            }
                        }
                    }
                    if let Some(hp) = ns.get("heartbeatPeriod").and_then(|v| v.as_u64()) {
                        if hp > 0 {
                            heartbeat_period = Some(Duration::from_secs(hp));
                        }
                    }
                    if let Some(ed) = ns.get("max_early_data").and_then(|v| v.as_u64()) {
                        max_early_data = ed as u32;
                    }
                    if let Some(ed_h) = ns.get("early_data_header_name").and_then(|v| v.as_str()) {
                        early_data_header = Some(ed_h.to_string());
                    }
                }

                if !path.starts_with('/') {
                    return Err(format!("WebSocket path must start with '/', got '{path}'"));
                }

                TransportConfig::WebSocket(WebSocketTransportConfig {
                    path,
                    host,
                    headers,
                    heartbeat_period,
                    early_data_header,
                    max_early_data,
                })
            }
            "grpc" | "gun" => {
                let mut service_name = node_info
                    .path
                    .as_deref()
                    .map(|p| p.trim_start_matches('/').to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| "GunService".to_string());
                let mut authority = node_info.host.clone();
                let mut multi_mode = false;
                let mut idle_timeout = Duration::from_secs(60);
                let mut health_check_timeout = Duration::from_secs(20);
                let mut permit_without_stream = false;
                let mut initial_windows_size = 65535;

                if let Some(ns) = &node_info.network_settings {
                    if let Some(sn) = ns
                        .get("serviceName")
                        .or_else(|| ns.get("service_name"))
                        .and_then(|v| v.as_str())
                    {
                        service_name = sn.to_string();
                    }
                    if let Some(auth) = ns.get("authority").and_then(|v| v.as_str()) {
                        authority = Some(auth.to_string());
                    }
                    if let Some(mm) = ns.get("multiMode").and_then(|v| v.as_bool()) {
                        multi_mode = mm;
                    }
                    if let Some(it) = ns.get("idle_timeout").and_then(|v| v.as_u64()) {
                        if it > 0 {
                            idle_timeout = Duration::from_secs(it);
                        }
                    }
                    if let Some(hct) = ns.get("health_check_timeout").and_then(|v| v.as_u64()) {
                        if hct > 0 {
                            health_check_timeout = Duration::from_secs(hct);
                        }
                    }
                    if let Some(pws) = ns.get("permit_without_stream").and_then(|v| v.as_bool()) {
                        permit_without_stream = pws;
                    }
                    if let Some(iws) = ns.get("initial_windows_size").and_then(|v| v.as_u64()) {
                        if iws > 0 {
                            initial_windows_size = iws as u32;
                        }
                    }
                }

                if service_name.is_empty() || service_name.starts_with('/') {
                    return Err(format!("gRPC serviceName must be non-empty and not start with '/', got '{service_name}'"));
                }

                TransportConfig::Grpc(GrpcTransportConfig {
                    service_name,
                    authority,
                    multi_mode,
                    idle_timeout,
                    health_check_timeout,
                    permit_without_stream,
                    initial_windows_size,
                })
            }
            "httpupgrade" | "http-upgrade" | "http_upgrade" => {
                let mut path = node_info.path.clone().unwrap_or_else(|| "/".to_string());
                let mut host = node_info.host.clone();
                let mut headers = HashMap::new();
                let mut max_early_data = 0;

                if let Some(ns) = &node_info.network_settings {
                    if let Some(p) = ns.get("path").and_then(|v| v.as_str()) {
                        path = p.to_string();
                    }
                    if let Some(h) = ns.get("host").and_then(|v| v.as_str()) {
                        host = Some(h.to_string());
                    }
                    if let Some(hdrs) = ns.get("headers").and_then(|v| v.as_object()) {
                        for (k, v) in hdrs {
                            if let Some(s) = v.as_str() {
                                headers.insert(k.clone(), s.to_string());
                            }
                        }
                    }
                    if let Some(ed) = ns.get("max_early_data").and_then(|v| v.as_u64()) {
                        max_early_data = ed as u32;
                    }
                }

                if !path.starts_with('/') {
                    return Err(format!(
                        "HttpUpgrade path must start with '/', got '{path}'"
                    ));
                }

                TransportConfig::HttpUpgrade(HttpUpgradeTransportConfig {
                    path,
                    host,
                    headers,
                    max_early_data,
                })
            }
            "xhttp" | "splithttp" | "split_http" => {
                let mut mode = "auto".to_string();
                let mut host = node_info.host.clone();
                let mut path = node_info.path.clone().unwrap_or_else(|| "/".to_string());
                let mut headers = HashMap::new();
                let mut extra = None;

                if let Some(ns) = &node_info.network_settings {
                    if let Some(m) = ns.get("mode").and_then(|v| v.as_str()) {
                        mode = m.to_string();
                    }
                    if let Some(h) = ns.get("host").and_then(|v| v.as_str()) {
                        host = Some(h.to_string());
                    }
                    if let Some(p) = ns.get("path").and_then(|v| v.as_str()) {
                        path = p.to_string();
                    }
                    if let Some(hdrs) = ns.get("headers").and_then(|v| v.as_object()) {
                        for (k, v) in hdrs {
                            if let Some(s) = v.as_str() {
                                headers.insert(k.clone(), s.to_string());
                            }
                        }
                    }
                    extra = ns.get("extra").cloned();
                }

                TransportConfig::XHttp(XHttpTransportConfig {
                    mode,
                    host,
                    path,
                    headers,
                    extra,
                })
            }
            "h2" | "http" | "http2" => {
                let mut path = node_info.path.clone().unwrap_or_else(|| "/".to_string());
                let mut host_list = node_info.host.clone().map(|h| vec![h]).unwrap_or_default();

                if let Some(ns) = &node_info.network_settings {
                    if let Some(p) = ns.get("path").and_then(|v| v.as_str()) {
                        path = p.to_string();
                    }
                    if let Some(h) = ns.get("host") {
                        if let Some(arr) = h.as_array() {
                            for item in arr {
                                if let Some(s) = item.as_str() {
                                    host_list.push(s.to_string());
                                }
                            }
                        } else if let Some(s) = h.as_str() {
                            host_list.push(s.to_string());
                        }
                    }
                }

                TransportConfig::LegacyHttp2(Http2TransportConfig {
                    path,
                    host: host_list,
                })
            }
            "kcp" | "mkcp" => {
                let mut mtu = 1350;
                let mut tti = 50;
                let mut uplink_capacity = 5;
                let mut downlink_capacity = 20;
                let mut congestion = false;
                let mut read_buffer_size = 2;
                let mut write_buffer_size = 2;
                let mut seed = None;
                let mut header_type = "none".to_string();

                if let Some(ns) = &node_info.network_settings {
                    if let Some(m) = ns.get("mtu").and_then(|v| v.as_u64()) {
                        mtu = m as u32;
                    }
                    if let Some(t) = ns.get("tti").and_then(|v| v.as_u64()) {
                        tti = t as u32;
                    }
                    if let Some(uc) = ns.get("uplinkCapacity").and_then(|v| v.as_u64()) {
                        uplink_capacity = uc as u32;
                    }
                    if let Some(dc) = ns.get("downlinkCapacity").and_then(|v| v.as_u64()) {
                        downlink_capacity = dc as u32;
                    }
                    if let Some(c) = ns.get("congestion").and_then(|v| v.as_bool()) {
                        congestion = c;
                    }
                    if let Some(rb) = ns.get("readBufferSize").and_then(|v| v.as_u64()) {
                        read_buffer_size = rb as u32;
                    }
                    if let Some(wb) = ns.get("writeBufferSize").and_then(|v| v.as_u64()) {
                        write_buffer_size = wb as u32;
                    }
                    if let Some(s) = ns.get("seed").and_then(|v| v.as_str()) {
                        seed = Some(s.to_string());
                    }
                    if let Some(h) = ns
                        .get("header")
                        .and_then(|v| v.get("type"))
                        .and_then(|v| v.as_str())
                    {
                        header_type = h.to_string();
                    }
                }

                if mtu < 21 {
                    return Err("mKCP MTU must be at least 21".to_string());
                }
                if tti < 10 || tti > 1000 {
                    return Err("mKCP TTI must be between 10 and 1000".to_string());
                }

                TransportConfig::MKcp(MKcpTransportConfig {
                    mtu,
                    tti,
                    uplink_capacity,
                    downlink_capacity,
                    congestion,
                    read_buffer_size,
                    write_buffer_size,
                    seed,
                    header_type,
                })
            }
            unknown => return Err(format!("unsupported transport network: '{unknown}'")),
        };

        // 3. TLS / TransportSecurityConfig & ClientTlsProfile / RealityClientProfile
        let tls_mode = node_info.tls.unwrap_or(0);
        let mut client_reality_profile = None;
        let mut client_tls_profile = None;

        let security = match tls_mode {
            0 => TransportSecurityConfig::None,
            1 => {
                let server_name = node_info
                    .tls_settings
                    .as_ref()
                    .and_then(|ts| ts.get("server_name"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .or_else(|| node_info.server_name.clone())
                    .or_else(|| node_info.host.clone());

                let mut server_names = Vec::new();
                if let Some(ts) = &node_info.tls_settings {
                    if let Some(arr) = ts.get("server_names").and_then(|v| v.as_array()) {
                        for item in arr {
                            if let Some(s) = item.as_str() {
                                server_names.push(s.to_string());
                            }
                        }
                    }
                }

                let reject_unknown_sni = node_info
                    .cert_config
                    .as_ref()
                    .and_then(|cc| cc.get("reject_unknown_sni"))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                // Collect certificates from cert_config and tls_settings
                let mut certificates = Vec::new();
                if let Some(cc) = &node_info.cert_config {
                    if let Some(arr) = cc.get("certificates").and_then(|v| v.as_array()) {
                        for item in arr {
                            let cert_file = item
                                .get("certificateFile")
                                .or_else(|| item.get("cert_file"))
                                .or_else(|| item.get("certFile"))
                                .and_then(|v| v.as_str())
                                .map(String::from);
                            let key_file = item
                                .get("keyFile")
                                .or_else(|| item.get("key_file"))
                                .and_then(|v| v.as_str())
                                .map(String::from);
                            let cert_pem = item
                                .get("certificate")
                                .or_else(|| item.get("cert"))
                                .and_then(|v| v.as_str())
                                .map(String::from);
                            let key_pem =
                                item.get("key").and_then(|v| v.as_str()).map(String::from);
                            if cert_file.is_some()
                                || key_file.is_some()
                                || cert_pem.is_some()
                                || key_pem.is_some()
                            {
                                certificates.push(TlsCertificateEntry {
                                    cert_pem,
                                    key_pem,
                                    cert_file,
                                    key_file,
                                });
                            }
                        }
                    }
                    let cert_file = cc
                        .get("certificateFile")
                        .or_else(|| cc.get("cert_file"))
                        .or_else(|| cc.get("certFile"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let key_file = cc
                        .get("keyFile")
                        .or_else(|| cc.get("key_file"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let cert_pem = cc
                        .get("certificate")
                        .or_else(|| cc.get("cert"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let key_pem = cc.get("key").and_then(|v| v.as_str()).map(String::from);
                    if cert_file.is_some()
                        || key_file.is_some()
                        || cert_pem.is_some()
                        || key_pem.is_some()
                    {
                        certificates.push(TlsCertificateEntry {
                            cert_pem,
                            key_pem,
                            cert_file,
                            key_file,
                        });
                    }
                }
                if let Some(ts) = &node_info.tls_settings {
                    let cert_file = ts
                        .get("certificateFile")
                        .or_else(|| ts.get("cert_file"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let key_file = ts
                        .get("keyFile")
                        .or_else(|| ts.get("key_file"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let cert_pem = ts
                        .get("certificate")
                        .or_else(|| ts.get("cert"))
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let key_pem = ts.get("key").and_then(|v| v.as_str()).map(String::from);
                    if cert_file.is_some()
                        || key_file.is_some()
                        || cert_pem.is_some()
                        || key_pem.is_some()
                    {
                        certificates.push(TlsCertificateEntry {
                            cert_pem,
                            key_pem,
                            cert_file,
                            key_file,
                        });
                    }
                }

                // ALPN configuration
                let mut alpn = Vec::new();
                if let Some(ts) = &node_info.tls_settings {
                    if let Some(arr) = ts.get("alpn").and_then(|v| v.as_array()) {
                        for item in arr {
                            if let Some(s) = item.as_str() {
                                alpn.push(s.to_string());
                            }
                        }
                    }
                }

                // ECH configs
                let mut ech_server = None;
                let mut ech_client = None;
                if let Some(ts) = &node_info.tls_settings {
                    if let Some(ech_val) = ts.get("ech") {
                        let enabled = ech_val
                            .get("enabled")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                        let server_keys = ech_val
                            .get("server_keys")
                            .or_else(|| ech_val.get("key"))
                            .and_then(|v| v.as_str())
                            .map(|s| {
                                if s.contains("-----BEGIN ECH KEYS-----") {
                                    Ok(s.as_bytes().to_vec())
                                } else {
                                    decode_base64_flexible(s)
                                        .map_err(|e| format!("Invalid ECH server key: {e}"))
                                }
                            })
                            .transpose()?;
                        if enabled || server_keys.is_some() {
                            ech_server = Some(EchServerConfig {
                                enabled,
                                server_keys,
                            });
                        }

                        let config_list = ech_val
                            .get("config")
                            .or_else(|| ech_val.get("config_list"))
                            .and_then(|v| v.as_str())
                            .and_then(|s| decode_base64_flexible(s).ok());
                        let dns_lookup = ech_val
                            .get("query_server_name")
                            .or_else(|| ech_val.get("dns_lookup"))
                            .and_then(|v| v.as_str())
                            .map(String::from);
                        if enabled || config_list.is_some() || dns_lookup.is_some() {
                            ech_client = Some(EchClientConfig {
                                enabled,
                                config_list,
                                dns_lookup,
                            });
                        }
                    }
                }

                // Populate ClientTlsProfile (CLIENT_ONLY: never used by inbound server acceptor)
                if let Some(ts) = &node_info.tls_settings {
                    let server_name = ts
                        .get("server_name")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    let allow_insecure = ts
                        .get("allow_insecure")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);

                    let fingerprint = node_info
                        .utls
                        .as_ref()
                        .and_then(|u| u.get("fingerprint"))
                        .and_then(|v| v.as_str())
                        .and_then(TlsFingerprint::parse);

                    let ech = ts.get("ech").map(|ech_val| EchConfig {
                        enabled: ech_val
                            .get("enabled")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        config: ech_val
                            .get("config")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        query_server_name: ech_val
                            .get("query_server_name")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                        key: ech_val
                            .get("key")
                            .and_then(|v| v.as_str())
                            .map(String::from),
                    });

                    client_tls_profile = Some(ClientTlsProfile {
                        server_name,
                        fingerprint,
                        allow_insecure,
                        ech,
                        ech_client,
                    });
                }

                TransportSecurityConfig::Tls(TlsServerConfig {
                    server_name,
                    allow_self_signed: node_info
                        .tls_settings
                        .as_ref()
                        .and_then(|ts| ts.get("allow_insecure"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false),
                    server_names,
                    reject_unknown_sni,
                    certificates,
                    ech: ech_server,
                    alpn,
                    cert_config: node_info.cert_config.clone(),
                })
            }
            2 => {
                let node_type = node_info.node_type.trim().to_ascii_lowercase();
                if node_type == "vmess" {
                    return Err(
                        "VMess protocol does not support Reality TLS mode (tls=2)".to_string()
                    );
                }

                // Transport compatibility check: mKCP runs over UDP and cannot run on stream REALITY
                if transport.transport_type() == TransportType::MKcp {
                    return Err(
                        "REALITY security is strictly forbidden on mKCP transport".to_string()
                    );
                }

                let rs_opt = node_info.tls_settings.as_ref();
                let dest = rs_opt
                    .and_then(|rs| rs.get("dest"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .or_else(|| {
                        let s_name = rs_opt
                            .and_then(|rs| rs.get("server_name"))
                            .and_then(|v| v.as_str())
                            .or_else(|| node_info.server_name.as_deref())
                            .or_else(|| node_info.host.as_deref())?;
                        let s_port = rs_opt
                            .and_then(|rs| rs.get("server_port"))
                            .and_then(|v| {
                                v.as_u64()
                                    .or_else(|| v.as_str().and_then(|s| s.parse::<u64>().ok()))
                            })
                            .unwrap_or(443);
                        Some(format!("{s_name}:{s_port}"))
                    })
                    .ok_or_else(|| {
                        "REALITY security requires non-empty 'dest' setting".to_string()
                    })?;
                if dest.trim().is_empty() {
                    return Err("REALITY security requires non-empty 'dest' setting".to_string());
                }

                let priv_key_str = rs_opt
                    .and_then(|rs| rs.get("private_key"))
                    .and_then(|v| v.as_str())
                    .or_else(|| node_info.server_key.as_deref())
                    .ok_or_else(|| {
                        "REALITY security requires non-empty 'private_key' setting".to_string()
                    })?;

                let priv_bytes = decode_base64_flexible(priv_key_str)
                    .map_err(|e| format!("invalid REALITY private_key base64: {e}"))?;
                if priv_bytes.len() != 32 {
                    return Err(format!(
                        "REALITY private_key must be exactly 32 bytes, got {}",
                        priv_bytes.len()
                    ));
                }
                let mut private_key = [0u8; 32];
                private_key.copy_from_slice(&priv_bytes);

                let mut short_ids = Vec::new();
                if let Some(rs) = rs_opt {
                    if let Some(arr) = rs.get("short_ids").and_then(|v| v.as_array()) {
                        for item in arr {
                            if let Some(s) = item.as_str() {
                                let b = hex::decode(s).map_err(|e| {
                                    format!("invalid REALITY short_id hex '{s}': {e}")
                                })?;
                                if b.len() > 8 {
                                    return Err(format!(
                                        "REALITY short_id '{s}' exceeds maximum length of 8 bytes"
                                    ));
                                }
                                short_ids.push(b);
                            }
                        }
                    } else if let Some(s) = rs.get("short_id").and_then(|v| v.as_str()) {
                        if !s.is_empty() {
                            let b = hex::decode(s)
                                .map_err(|e| format!("invalid REALITY short_id hex '{s}': {e}"))?;
                            if b.len() > 8 {
                                return Err(format!(
                                    "REALITY short_id '{s}' exceeds maximum length of 8 bytes"
                                ));
                            }
                            short_ids.push(b);
                        }
                    }
                }
                if short_ids.is_empty() {
                    if let Some(sids) = &node_info.short_ids {
                        for s in sids {
                            let b = hex::decode(s)
                                .map_err(|e| format!("invalid REALITY short_id hex '{s}': {e}"))?;
                            if b.len() > 8 {
                                return Err(format!(
                                    "REALITY short_id '{s}' exceeds maximum length of 8 bytes"
                                ));
                            }
                            short_ids.push(b);
                        }
                    }
                }
                if short_ids.is_empty() {
                    short_ids.push(Vec::new());
                }

                let mut server_names = Vec::new();
                if let Some(rs) = rs_opt {
                    if let Some(arr) = rs.get("server_names").and_then(|v| v.as_array()) {
                        for item in arr {
                            if let Some(s) = item.as_str() {
                                server_names.push(s.to_string());
                            }
                        }
                    } else if let Some(s) = rs.get("server_name").and_then(|v| v.as_str()) {
                        server_names.push(s.to_string());
                    }
                }
                if server_names.is_empty() {
                    if let Some(sn) = &node_info.server_name {
                        server_names.push(sn.clone());
                    }
                }
                if server_names.is_empty() {
                    if let Some(host) = dest.split(':').next() {
                        if !host.is_empty() {
                            server_names.push(host.to_string());
                        }
                    }
                }

                let xver = rs_opt
                    .and_then(|rs| rs.get("xver"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u8;

                let max_time_diff_ms = rs_opt
                    .and_then(|rs| rs.get("max_time_diff"))
                    .and_then(|v| v.as_u64())
                    .unwrap_or(60000);

                let min_client_ver = rs_opt
                    .and_then(|rs| rs.get("min_client_ver"))
                    .and_then(|v| v.as_str())
                    .map(String::from);

                let max_client_ver = rs_opt
                    .and_then(|rs| rs.get("max_client_ver"))
                    .and_then(|v| v.as_str())
                    .map(String::from);

                let spider_x = rs_opt
                    .and_then(|rs| rs.get("spider_x"))
                    .and_then(|v| v.as_str())
                    .map(String::from);

                let fingerprint = node_info
                    .utls
                    .as_ref()
                    .and_then(|u| u.get("fingerprint"))
                    .and_then(|v| v.as_str())
                    .and_then(TlsFingerprint::parse);

                client_reality_profile = Some(RealityClientProfile {
                    server_name: rs_opt
                        .and_then(|rs| rs.get("server_name"))
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .or_else(|| node_info.server_name.clone()),
                    server_port: rs_opt
                        .and_then(|rs| rs.get("server_port"))
                        .and_then(|v| v.as_u64())
                        .map(|p| p as u16),
                    public_key: rs_opt
                        .and_then(|rs| rs.get("public_key"))
                        .and_then(|v| v.as_str())
                        .map(String::from)
                        .or_else(|| node_info.public_key.clone()),
                    short_id: rs_opt
                        .and_then(|rs| rs.get("short_id"))
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    fingerprint,
                    spider_x: spider_x.clone(),
                });

                TransportSecurityConfig::Reality(RealityServerConfig {
                    dest,
                    server_names,
                    private_key,
                    short_ids,
                    xver,
                    max_time_diff_ms,
                    min_client_ver,
                    max_client_ver,
                    spider_x,
                })
            }
            unknown => return Err(format!("unsupported TLS mode: {unknown}")),
        };

        Ok(Self {
            transport,
            security,
            accept_proxy_protocol,
            client_tls_profile,
            client_reality_profile,
        })
    }
}

/// Normalized VLESS node configuration parsed from panel NodeInfo.
#[derive(Debug, Clone)]
pub struct VlessNodeConfig {
    pub protocol: VlessProtocolConfig,
    pub encryption: VlessEncryptionConfig,
    pub flow: VlessFlow,
    pub stream: StreamSettings,
}

#[derive(Debug, Clone)]
pub struct VlessProtocolConfig {
    pub port: u16,
    pub listen_addr: String,
    pub fallbacks: Vec<VlessFallbackConfig>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VlessFlow {
    None,
    Vision, // "xtls-rprx-vision"
}

impl VlessFlow {
    pub fn parse(s: Option<&str>) -> Result<Self, String> {
        match s.map(|v| v.trim()) {
            None | Some("") | Some("none") => Ok(Self::None),
            Some("xtls-rprx-vision") | Some("xtls-rprx-vision-udp443") => Ok(Self::Vision),
            Some(unknown) => Err(format!("unsupported VLESS flow: '{unknown}'")),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VlessEncryptionConfig {
    None,
    Mlkem768X25519Plus(MlkemConfig),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlkemConfig {
    pub xor_mode: u32,
    pub seconds_from: i64,
    pub seconds_to: i64,
    pub server_padding: Option<String>,
    pub server_keys: Vec<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct VlessFallbackConfig {
    pub name: String,
    pub alpn: String,
    pub path: String,
    pub dest: String,
    pub xver: u8,
}

impl VlessEncryptionConfig {
    pub fn parse_dot_config(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
            return Ok(Self::None);
        }
        let parts: Vec<&str> = trimmed.split('.').collect();
        if parts.len() < 4 || parts[0] != "mlkem768x25519plus" {
            return Err(format!("unsupported VLESS decryption format: '{trimmed}'"));
        }
        let xor_mode = match parts[1] {
            "native" => 0,
            "xorpub" => 1,
            "random" => 2,
            unknown => return Err(format!("unknown VLESS encryption mode: '{unknown}'")),
        };
        let ticket_str = parts[2].trim_end_matches('s');
        let (seconds_from, seconds_to) = if let Some((from_s, to_s)) = ticket_str.split_once('-') {
            let from = from_s
                .parse::<i64>()
                .map_err(|e| format!("invalid ticket range from '{from_s}': {e}"))?;
            let to = to_s
                .parse::<i64>()
                .map_err(|e| format!("invalid ticket range to '{to_s}': {e}"))?;
            (from, to)
        } else if ticket_str.eq_ignore_ascii_case("0rtt") {
            (0, 0)
        } else {
            let secs = ticket_str
                .parse::<i64>()
                .map_err(|e| format!("invalid ticket seconds '{ticket_str}': {e}"))?;
            (secs, 0)
        };

        let (server_padding, key_str) = if parts.len() == 4 {
            (None, parts[3])
        } else {
            let padding = parts[3..parts.len() - 1].join(".");
            (Some(padding), parts[parts.len() - 1])
        };

        let key_bytes = decode_base64_flexible(key_str)
            .map_err(|e| format!("invalid VLESS decryption private_key base64: {e}"))?;
        if key_bytes.len() != 32 && key_bytes.len() != 64 && key_bytes.len() != 2400 {
            return Err(format!(
                "VLESS decryption private_key length must be 32, 64, or 2400 bytes, got {}",
                key_bytes.len()
            ));
        }

        Ok(Self::Mlkem768X25519Plus(MlkemConfig {
            xor_mode,
            seconds_from,
            seconds_to,
            server_padding,
            server_keys: vec![key_bytes],
        }))
    }

    pub fn from_panel_settings(node_info: &NodeInfo) -> Result<Self, String> {
        // Priority 1: explicit decryption dot-string
        if let Some(dec_str) = &node_info.decryption {
            if !dec_str.trim().is_empty() {
                return Self::parse_dot_config(dec_str);
            }
        }
        // Priority 2: encryption + encryption_settings
        if let Some(enc) = &node_info.encryption {
            let enc_trimmed = enc.trim();
            if enc_trimmed.is_empty() || enc_trimmed.eq_ignore_ascii_case("none") {
                return Ok(Self::None);
            }
            if !enc_trimmed.eq_ignore_ascii_case("mlkem768x25519plus") {
                return Err(format!("unsupported VLESS encryption method: '{enc}'"));
            }
            let es = node_info.encryption_settings.as_ref().ok_or_else(|| {
                "VLESS encryption mlkem768x25519plus requires encryption_settings".to_string()
            })?;

            let mode_str = es.get("mode").and_then(|v| v.as_str()).unwrap_or("native");
            let xor_mode = match mode_str {
                "native" => 0,
                "xorpub" => 1,
                "random" => 2,
                unknown => return Err(format!("unknown VLESS encryption mode: '{unknown}'")),
            };
            let ticket_str = es
                .get("ticket")
                .and_then(|v| v.as_str())
                .unwrap_or("600s")
                .trim_end_matches('s');
            let (seconds_from, seconds_to) =
                if let Some((from_s, to_s)) = ticket_str.split_once('-') {
                    let from = from_s
                        .parse::<i64>()
                        .map_err(|e| format!("invalid ticket range from '{from_s}': {e}"))?;
                    let to = to_s
                        .parse::<i64>()
                        .map_err(|e| format!("invalid ticket range to '{to_s}': {e}"))?;
                    (from, to)
                } else if ticket_str.eq_ignore_ascii_case("0rtt") {
                    (0, 0)
                } else {
                    let secs = ticket_str
                        .parse::<i64>()
                        .map_err(|e| format!("invalid ticket seconds '{ticket_str}': {e}"))?;
                    (secs, 0)
                };
            let server_padding = es
                .get("server_padding")
                .and_then(|v| v.as_str())
                .map(String::from);
            let priv_key_str = es
                .get("private_key")
                .and_then(|v| v.as_str())
                .ok_or_else(|| {
                    "VLESS encryption mlkem768x25519plus requires non-empty private_key".to_string()
                })?;
            let key_bytes = decode_base64_flexible(priv_key_str)
                .map_err(|e| format!("invalid VLESS decryption private_key base64: {e}"))?;
            if key_bytes.len() != 32 && key_bytes.len() != 64 && key_bytes.len() != 2400 {
                return Err(format!(
                    "VLESS decryption private_key length must be 32, 64, or 2400 bytes, got {}",
                    key_bytes.len()
                ));
            }
            return Ok(Self::Mlkem768X25519Plus(MlkemConfig {
                xor_mode,
                seconds_from,
                seconds_to,
                server_padding,
                server_keys: vec![key_bytes],
            }));
        }
        Ok(Self::None)
    }
}

impl VlessNodeConfig {
    pub fn from_node_info(node_info: &NodeInfo) -> Result<Self, String> {
        let stream = StreamSettings::from_node_info(node_info)?;
        let flow = VlessFlow::parse(node_info.flow.as_deref())?;
        let encryption = VlessEncryptionConfig::from_panel_settings(node_info)?;

        // Validation rule 1: Vision requires transport=tcp and security=tls or reality
        if flow == VlessFlow::Vision {
            if stream.transport.transport_type() != TransportType::RawTcp {
                return Err(format!(
                    "vless flow=xtls-rprx-vision requires transport=tcp, got {:?}",
                    stream.transport.transport_type()
                ));
            }
            match &stream.security {
                TransportSecurityConfig::Tls(_) | TransportSecurityConfig::Reality(_) => {}
                TransportSecurityConfig::None => {
                    return Err("vless flow=xtls-rprx-vision requires tls or reality".to_string());
                }
            }
        }

        // Fallbacks parsing from cert_config or network_settings if present
        let mut fallbacks = Vec::new();
        if let Some(cc) = &node_info.cert_config {
            if let Some(fbs) = cc.get("fallbacks").and_then(|v| v.as_array()) {
                for fb in fbs {
                    let name = fb
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let alpn = fb
                        .get("alpn")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let path = fb
                        .get("path")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let dest = fb
                        .get("dest")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    let xver = fb.get("xver").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
                    fallbacks.push(VlessFallbackConfig {
                        name,
                        alpn,
                        path,
                        dest,
                        xver,
                    });
                }
            }
        }

        // Validation rule 2: Encryption cannot be used with fallbacks (Xray-core invariant)
        if encryption != VlessEncryptionConfig::None && !fallbacks.is_empty() {
            return Err(
                "VLESS settings: fallbacks can not be used together with encryption".to_string(),
            );
        }

        let listen_addr = node_info
            .listen_ip
            .clone()
            .unwrap_or_else(|| "0.0.0.0".to_string());
        let port = node_info.server_port;

        Ok(Self {
            protocol: VlessProtocolConfig {
                port,
                listen_addr,
                fallbacks,
            },
            encryption,
            flow,
            stream,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_stream_settings_default_tcp_none() {
        let node = NodeInfo {
            id: 1,
            node_type: "vmess".to_string(),
            server_port: 10086,
            ..Default::default()
        };

        let settings = StreamSettings::from_node_info(&node).unwrap();
        assert!(!settings.accept_proxy_protocol);
        assert!(matches!(settings.security, TransportSecurityConfig::None));
        assert!(settings.client_tls_profile.is_none());

        match settings.transport {
            TransportConfig::Tcp(tcp) => {
                assert_eq!(tcp.header_type, TcpHeaderType::None);
                assert!(tcp.request.is_none());
                assert!(tcp.response.is_none());
            }
            _ => panic!("expected Tcp transport"),
        }
    }

    #[test]
    fn test_stream_settings_rejects_unknown_network() {
        let node = NodeInfo {
            id: 1,
            node_type: "vmess".to_string(),
            server_port: 10086,
            network: Some("unknown_proto".to_string()),
            ..Default::default()
        };

        let res = StreamSettings::from_node_info(&node);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("unsupported transport network: 'unknown_proto'"));
    }

    #[test]
    fn test_stream_settings_rejects_reality_tls() {
        let node = NodeInfo {
            id: 1,
            node_type: "vmess".to_string(),
            server_port: 10086,
            tls: Some(2),
            ..Default::default()
        };

        let res = StreamSettings::from_node_info(&node);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("does not support Reality TLS mode"));
    }

    #[test]
    fn test_stream_settings_tcp_http_camouflage() {
        let node = NodeInfo {
            id: 1,
            node_type: "vmess".to_string(),
            server_port: 10086,
            network: Some("tcp".to_string()),
            network_settings: Some(json!({
                "acceptProxyProtocol": true,
                "header": {
                    "type": "http",
                    "request": {
                        "version": "1.1",
                        "method": "GET",
                        "path": ["/video", "/stream"],
                        "headers": {
                            "Host": ["cdn.example.com", "img.example.com"]
                        }
                    },
                    "response": {
                        "version": "1.1",
                        "status": "200",
                        "reason": "OK",
                        "headers": {
                            "Content-Type": ["application/octet-stream"]
                        }
                    }
                }
            })),
            ..Default::default()
        };

        let settings = StreamSettings::from_node_info(&node).unwrap();
        assert!(settings.accept_proxy_protocol);

        match settings.transport {
            TransportConfig::Tcp(tcp) => {
                assert_eq!(tcp.header_type, TcpHeaderType::Http);
                let req = tcp.request.unwrap();
                assert_eq!(req.method, "GET");
                assert_eq!(req.path, vec!["/video", "/stream"]);
                assert_eq!(
                    req.headers.get("Host").unwrap(),
                    &vec!["cdn.example.com".to_string(), "img.example.com".to_string()]
                );

                let resp = tcp.response.unwrap();
                assert_eq!(resp.status, "200");
                assert_eq!(resp.reason, "OK");
                assert_eq!(
                    resp.headers.get("Content-Type").unwrap(),
                    &vec!["application/octet-stream".to_string()]
                );
            }
            _ => panic!("expected Tcp transport"),
        }
    }

    #[test]
    fn test_stream_settings_rejects_unknown_tcp_header_type() {
        let node = NodeInfo {
            id: 1,
            node_type: "vmess".to_string(),
            server_port: 10086,
            network: Some("tcp".to_string()),
            network_settings: Some(json!({
                "header": {
                    "type": "ftp"
                }
            })),
            ..Default::default()
        };

        let res = StreamSettings::from_node_info(&node);
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("unknown TCP header type: 'ftp'"));
    }

    #[test]
    fn test_stream_settings_ws_and_path_validation() {
        let valid_node = NodeInfo {
            id: 1,
            node_type: "vmess".to_string(),
            server_port: 10086,
            network: Some("ws".to_string()),
            network_settings: Some(json!({
                "path": "/my-ws-path",
                "headers": {
                    "Host": "ws.domain.com"
                },
                "heartbeatPeriod": 15
            })),
            ..Default::default()
        };

        let settings = StreamSettings::from_node_info(&valid_node).unwrap();
        match settings.transport {
            TransportConfig::WebSocket(ws) => {
                assert_eq!(ws.path, "/my-ws-path");
                assert_eq!(ws.host, Some("ws.domain.com".to_string()));
                assert_eq!(ws.heartbeat_period, Some(Duration::from_secs(15)));
            }
            _ => panic!("expected WebSocket transport"),
        }

        // Invalid path without leading slash
        let invalid_node = NodeInfo {
            id: 1,
            node_type: "vmess".to_string(),
            server_port: 10086,
            network: Some("ws".to_string()),
            network_settings: Some(json!({
                "path": "no_slash_path"
            })),
            ..Default::default()
        };

        let res = StreamSettings::from_node_info(&invalid_node);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("WebSocket path must start with '/'"));
    }

    #[test]
    fn test_stream_settings_grpc_and_service_name_validation() {
        let valid_node = NodeInfo {
            id: 1,
            node_type: "vmess".to_string(),
            server_port: 10086,
            network: Some("grpc".to_string()),
            network_settings: Some(json!({
                "serviceName": "TunService",
                "multiMode": true
            })),
            ..Default::default()
        };

        let settings = StreamSettings::from_node_info(&valid_node).unwrap();
        match settings.transport {
            TransportConfig::Grpc(grpc) => {
                assert_eq!(grpc.service_name, "TunService");
                assert!(grpc.multi_mode);
            }
            _ => panic!("expected Grpc transport"),
        }

        // Invalid serviceName with leading slash
        let invalid_node = NodeInfo {
            id: 1,
            node_type: "vmess".to_string(),
            server_port: 10086,
            network: Some("grpc".to_string()),
            network_settings: Some(json!({
                "serviceName": "/bad_service"
            })),
            ..Default::default()
        };

        let res = StreamSettings::from_node_info(&invalid_node);
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("gRPC serviceName must be non-empty and not start with '/'"));
    }

    #[test]
    fn test_stream_settings_client_tls_profile_separation() {
        let node = NodeInfo {
            id: 1,
            node_type: "vmess".to_string(),
            server_port: 443,
            tls: Some(1),
            tls_settings: Some(json!({
                "server_name": "secure.domain.com",
                "allow_insecure": true,
                "ech": {
                    "enabled": true,
                    "config": "AEn+fakeEchConfig",
                    "query_server_name": "doh.dns.com"
                }
            })),
            utls: Some(json!({
                "enabled": true,
                "fingerprint": "chrome"
            })),
            cert_config: Some(json!({
                "cert_mode": "file",
                "reject_unknown_sni": true
            })),
            ..Default::default()
        };

        let settings = StreamSettings::from_node_info(&node).unwrap();

        // Check SERVER_RUNTIME TransportSecurityConfig
        match &settings.security {
            TransportSecurityConfig::Tls(tls) => {
                assert_eq!(tls.server_name, Some("secure.domain.com".to_string()));
                assert!(tls.reject_unknown_sni);
                assert!(tls.cert_config.is_some());
            }
            _ => panic!("expected Tls security config"),
        }

        // Check CLIENT_ONLY profile separation
        let profile = settings.client_tls_profile.unwrap();
        assert_eq!(profile.server_name, Some("secure.domain.com".to_string()));
        assert!(profile.allow_insecure);
        assert_eq!(profile.fingerprint, Some(TlsFingerprint::Chrome));
        let ech = profile.ech.unwrap();
        assert!(ech.enabled);
        assert_eq!(ech.config, Some("AEn+fakeEchConfig".to_string()));
        assert_eq!(ech.query_server_name, Some("doh.dns.com".to_string()));
    }

    #[test]
    fn test_trojan_raw_tls_parsing() {
        let node = NodeInfo {
            id: 10,
            node_type: "trojan".to_string(),
            server_port: 443,
            network: Some("tcp".to_string()),
            tls: Some(1),
            tls_settings: Some(json!({
                "server_name": "trojan.example.com",
                "allow_insecure": false
            })),
            ..Default::default()
        };

        let settings = StreamSettings::from_node_info(&node).unwrap();
        assert!(matches!(settings.transport, TransportConfig::Tcp(_)));
        match &settings.security {
            TransportSecurityConfig::Tls(tls) => {
                assert_eq!(tls.server_name, Some("trojan.example.com".to_string()));
            }
            _ => panic!("expected Tls security config"),
        }
        assert!(settings.client_tls_profile.is_some());
        assert!(settings.client_reality_profile.is_none());
    }

    #[test]
    fn test_trojan_raw_reality_parsing() {
        use base64::Engine;
        let priv_key_raw = [42u8; 32];
        let priv_key_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(priv_key_raw);

        let node = NodeInfo {
            id: 11,
            node_type: "trojan".to_string(),
            server_port: 443,
            network: Some("tcp".to_string()),
            tls: Some(2),
            tls_settings: Some(json!({
                "dest": "www.apple.com:443",
                "server_name": "www.apple.com",
                "private_key": priv_key_b64,
                "public_key": "dummyPublicKeyBase64",
                "short_ids": ["0123456789abcdef", "fedcba9876543210"],
                "xver": 1,
                "max_time_diff": 30000,
                "spider_x": "/download"
            })),
            utls: Some(json!({
                "enabled": true,
                "fingerprint": "firefox"
            })),
            ..Default::default()
        };

        let settings = StreamSettings::from_node_info(&node).unwrap();
        assert!(matches!(settings.transport, TransportConfig::Tcp(_)));

        match &settings.security {
            TransportSecurityConfig::Reality(reality) => {
                assert_eq!(reality.dest, "www.apple.com:443");
                assert_eq!(reality.private_key, priv_key_raw);
                assert_eq!(reality.short_ids.len(), 2);
                assert_eq!(
                    reality.short_ids[0],
                    hex::decode("0123456789abcdef").unwrap()
                );
                assert_eq!(reality.xver, 1);
                assert_eq!(reality.max_time_diff_ms, 30000);
                assert_eq!(reality.spider_x, Some("/download".to_string()));
            }
            _ => panic!("expected Reality security config"),
        }

        let reality_profile = settings.client_reality_profile.unwrap();
        assert_eq!(
            reality_profile.server_name,
            Some("www.apple.com".to_string())
        );
        assert_eq!(
            reality_profile.public_key,
            Some("dummyPublicKeyBase64".to_string())
        );
        assert_eq!(reality_profile.fingerprint, Some(TlsFingerprint::Firefox));
        assert_eq!(reality_profile.spider_x, Some("/download".to_string()));
    }

    #[test]
    fn test_trojan_reality_illegal_combinations_rejected() {
        use base64::Engine;
        let priv_key_b64 = base64::engine::general_purpose::STANDARD.encode([1u8; 32]);

        // Reality + mKCP MUST fail (mKCP is UDP)
        let node_mkcp = NodeInfo {
            id: 12,
            node_type: "trojan".to_string(),
            server_port: 443,
            network: Some("mkcp".to_string()),
            tls: Some(2),
            tls_settings: Some(json!({
                "dest": "www.apple.com:443",
                "private_key": priv_key_b64
            })),
            ..Default::default()
        };
        let err_mkcp = StreamSettings::from_node_info(&node_mkcp).unwrap_err();
        assert!(err_mkcp.contains("REALITY security is strictly forbidden on mKCP transport"));
    }

    #[test]
    fn test_trojan_reality_legal_all_transports() {
        use base64::Engine;
        let priv_key_b64 = base64::engine::general_purpose::STANDARD.encode([5u8; 32]);

        for net in ["ws", "httpupgrade", "h2", "grpc", "xhttp", "tcp"] {
            let node = NodeInfo {
                id: 15,
                node_type: "trojan".to_string(),
                server_port: 443,
                network: Some(net.to_string()),
                network_settings: Some(json!({ "serviceName": "TrojanGrpc", "path": "/test" })),
                tls: Some(2),
                tls_settings: Some(json!({
                    "dest": "www.apple.com:443",
                    "private_key": priv_key_b64
                })),
                ..Default::default()
            };
            let settings = StreamSettings::from_node_info(&node).unwrap();
            assert!(matches!(
                settings.security,
                TransportSecurityConfig::Reality(_)
            ));
        }
    }

    #[test]
    fn test_trojan_reality_validation_errors() {
        use base64::Engine;

        // Missing dest
        let node_no_dest = NodeInfo {
            id: 17,
            node_type: "trojan".to_string(),
            server_port: 443,
            network: Some("tcp".to_string()),
            tls: Some(2),
            tls_settings: Some(json!({
                "private_key": base64::engine::general_purpose::STANDARD.encode([1u8; 32])
            })),
            ..Default::default()
        };
        assert!(StreamSettings::from_node_info(&node_no_dest)
            .unwrap_err()
            .contains("requires non-empty 'dest'"));

        // Missing private_key
        let node_no_key = NodeInfo {
            id: 18,
            node_type: "trojan".to_string(),
            server_port: 443,
            network: Some("tcp".to_string()),
            tls: Some(2),
            tls_settings: Some(json!({
                "dest": "www.apple.com:443"
            })),
            ..Default::default()
        };
        assert!(StreamSettings::from_node_info(&node_no_key)
            .unwrap_err()
            .contains("requires non-empty 'private_key'"));

        // Invalid private_key length (e.g. 16 bytes instead of 32)
        let node_bad_key_len = NodeInfo {
            id: 19,
            node_type: "trojan".to_string(),
            server_port: 443,
            network: Some("tcp".to_string()),
            tls: Some(2),
            tls_settings: Some(json!({
                "dest": "www.apple.com:443",
                "private_key": base64::engine::general_purpose::STANDARD.encode([1u8; 16])
            })),
            ..Default::default()
        };
        assert!(StreamSettings::from_node_info(&node_bad_key_len)
            .unwrap_err()
            .contains("must be exactly 32 bytes"));

        // Short id exceeds 8 bytes (e.g. 9 bytes = 18 hex chars)
        let node_long_short_id = NodeInfo {
            id: 20,
            node_type: "trojan".to_string(),
            server_port: 443,
            network: Some("tcp".to_string()),
            tls: Some(2),
            tls_settings: Some(json!({
                "dest": "www.apple.com:443",
                "private_key": base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
                "short_id": "0123456789abcdef01"
            })),
            ..Default::default()
        };
        assert!(StreamSettings::from_node_info(&node_long_short_id)
            .unwrap_err()
            .contains("exceeds maximum length of 8 bytes"));

        // REALITY dest synthesis from panel config (server_name + server_port without explicit dest)
        let node_panel_reality = NodeInfo {
            id: 21,
            node_type: "trojan".to_string(),
            server_port: 10443,
            network: Some("tcp".to_string()),
            tls: Some(2),
            tls_settings: Some(json!({
                "server_name": "www.apple.com",
                "server_port": 443,
                "private_key": base64::engine::general_purpose::STANDARD.encode([1u8; 32]),
                "short_id": "0123456789abcdef"
            })),
            ..Default::default()
        };
        let settings = StreamSettings::from_node_info(&node_panel_reality)
            .expect("REALITY dest should be synthesized from server_name and server_port");
        if let TransportSecurityConfig::Reality(rc) = settings.security {
            assert_eq!(rc.dest, "www.apple.com:443");
            assert_eq!(rc.server_names, vec!["www.apple.com"]);
        } else {
            panic!("expected Reality security config");
        }
    }

    #[test]
    fn test_tls_fingerprint_all_variants() {
        assert_eq!(
            TlsFingerprint::parse("chrome"),
            Some(TlsFingerprint::Chrome)
        );
        assert_eq!(
            TlsFingerprint::parse("firefox"),
            Some(TlsFingerprint::Firefox)
        );
        assert_eq!(
            TlsFingerprint::parse("safari"),
            Some(TlsFingerprint::Safari)
        );
        assert_eq!(TlsFingerprint::parse("ios"), Some(TlsFingerprint::IOS));
        assert_eq!(
            TlsFingerprint::parse("android"),
            Some(TlsFingerprint::Android)
        );
        assert_eq!(TlsFingerprint::parse("edge"), Some(TlsFingerprint::Edge));
        assert_eq!(TlsFingerprint::parse("qq"), Some(TlsFingerprint::Qq));
        assert_eq!(TlsFingerprint::parse("360"), Some(TlsFingerprint::_360));
        assert_eq!(TlsFingerprint::parse("_360"), Some(TlsFingerprint::_360));
        assert_eq!(
            TlsFingerprint::parse("random"),
            Some(TlsFingerprint::Random)
        );
        assert_eq!(
            TlsFingerprint::parse("randomized"),
            Some(TlsFingerprint::Randomized)
        );
        assert_eq!(TlsFingerprint::parse("unknown_browser"), None);
    }
}
