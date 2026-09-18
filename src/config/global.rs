use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct GlobalConfig {
    pub panel_type: String,
    pub api_host: String,
    pub api_key: String,
    pub node_ids: Vec<u32>,
    pub node_sync_interval: u64,
    pub node_report_interval: u64,
    pub auto_tls: bool,
    pub fake_sni: String,
    pub listen_strategy: String,
    pub listen_addr: String,

    pub routes_file: PathBuf,
    pub dns_file: PathBuf,
    pub block_list: PathBuf,
    pub white_list: PathBuf,
    pub geoip_file: Option<PathBuf>,
    pub geosite_file: Option<PathBuf>,

    pub proxy_protocol: bool,
    pub force_proxy_protocol: bool,
    pub udp_proxy_protocol: bool,
    pub proxy_protocol_mode: crate::conn::ProxyProtocolMode,
    pub outbound_proxy_protocol: Option<String>,
    pub trusted_proxies: Option<Vec<ipnet::IpNet>>,

    pub out_ip_ipv4: Option<String>,
    pub out_ip_ipv6: Option<String>,
    pub auto_out_ip: bool,
    pub dns_strategy: String,

    pub redis_url: Option<String>,
    pub device_limit_window: u64,
    pub device_limit_prefix_ipv4: u8,
    pub device_limit_prefix_ipv6: u8,

    pub log_level: String,
    pub log_file: Option<PathBuf>,
    pub audit_log_file: Option<PathBuf>,
    pub log_retention_days: u32,
    pub log_max_size_mb: u64,

    pub clickhouse_enabled: bool,
    pub clickhouse_addr: String,
    pub clickhouse_db: String,
    pub clickhouse_table: String,
    pub clickhouse_user: String,
    pub clickhouse_password: Option<String>,

    pub forbidden_ports: Vec<(u16, u16)>,
    pub ban_private_ip: bool,
    pub forbidden_bit_torrent: bool,
    pub domain_sniff: bool,
    pub sniff_redirect: bool,
    pub block_list_url: Option<String>,
    pub white_list_url: Option<String>,
    pub routes_url: Option<String>,

    pub submit_traffic_min_traffic: u64,
    pub submit_alive_ip_min_traffic: u64,
    pub user_conn_limit: u32,
    pub user_tcp_limit: u32,
    pub user_speed_limit: u64,
    pub node_speed_limit: u64,
    pub domain_audit_enable: bool,
    pub domain_audit_domains: Vec<String>,
    pub domain_audit_log_dir: Option<PathBuf>,
    pub domain_audit_retention_days: u32,

    pub pprof_addr: String,
    pub dns_env_vars: HashMap<String, String>,
    pub tcp_timeout: u64,
    pub udp_timeout: u64,
    pub mptcp: bool,
    pub default_dns: Option<String>,
    pub dns_cache_time: u64,
    pub log_file_dir: Option<PathBuf>,

    // Redis Enhanced IP/Device Limit
    pub redis_enable: bool,
    pub redis_addr: Option<String>,
    pub redis_password: Option<String>,
    pub redis_db: u8,
    pub redis_tls: bool,
    pub conn_limit_expiry: u64,
    pub redis_timeout_ms: u64,

    // Audit & Packet Detection
    pub detect_packet: bool,

    // IP Cache & Persistence
    pub ip_user_cache_time: u64,
    pub ip_user_cache_save_enable: bool,
    pub ip_user_cache_save_dir: PathBuf,

    // Shadowsocks Single-Port AEAD Optimization
    pub ss_decrypt_concurrency: usize,
    pub ss_invalid_access_enable: bool,
    pub ss_invalid_access_count: u32,
    pub ss_invalid_access_duration: u64,
    pub ss_invalid_access_forbidden_time: u64,

    // VMess AEAD Optimization & Mode Switch
    pub force_vmess_aead: bool,
    pub force_vmess_md5: bool,
    pub vmess_aead_invalid_access_enable: bool,
    pub vmess_aead_invalid_access_count: u32,
    pub vmess_aead_invalid_access_duration: u64,
    pub vmess_aead_invalid_access_forbidden_time: u64,

    pub raw_properties: HashMap<String, String>,
}

impl Default for GlobalConfig {
    fn default() -> Self {
        Self {
            panel_type: "xboard".to_string(),
            api_host: String::new(),
            api_key: String::new(),
            node_ids: vec![1],
            node_sync_interval: 60,
            node_report_interval: 60,
            auto_tls: true,
            fake_sni: "www.microsoft.com".to_string(),
            listen_strategy: "auto".to_string(),
            listen_addr: "0.0.0.0".to_string(),

            routes_file: PathBuf::from("/etc/elise/routes.toml"),
            dns_file: PathBuf::from("/etc/elise/dns.yml"),
            block_list: PathBuf::from("/etc/elise/blockList"),
            white_list: PathBuf::from("/etc/elise/whiteList"),
            geoip_file: None,
            geosite_file: None,

            proxy_protocol: false,
            force_proxy_protocol: false,
            udp_proxy_protocol: false,
            proxy_protocol_mode: crate::conn::ProxyProtocolMode::Off,
            outbound_proxy_protocol: None,
            trusted_proxies: None,

            out_ip_ipv4: None,
            out_ip_ipv6: None,
            auto_out_ip: false,
            dns_strategy: "ipv4_first".to_string(),

            redis_url: None,
            device_limit_window: 300,
            device_limit_prefix_ipv4: 32,
            device_limit_prefix_ipv6: 64,

            log_level: "info".to_string(),
            log_file: None,
            audit_log_file: None,
            log_retention_days: 7,
            log_max_size_mb: 100,

            clickhouse_enabled: false,
            clickhouse_addr: "http://127.0.0.1:8123".to_string(),
            clickhouse_db: "elise".to_string(),
            clickhouse_table: "access_log".to_string(),
            clickhouse_user: "default".to_string(),
            clickhouse_password: None,

            forbidden_ports: Vec::new(),
            ban_private_ip: false,
            forbidden_bit_torrent: true,
            domain_sniff: true,
            sniff_redirect: false,
            block_list_url: None,
            white_list_url: None,
            routes_url: None,

            submit_traffic_min_traffic: 0,
            submit_alive_ip_min_traffic: 0,
            user_conn_limit: 0,
            user_tcp_limit: 0,
            user_speed_limit: 0,
            node_speed_limit: 0,
            domain_audit_enable: false,
            domain_audit_domains: Vec::new(),
            domain_audit_log_dir: None,
            domain_audit_retention_days: 7,

            pprof_addr: "127.0.0.1:6060".to_string(),
            dns_env_vars: HashMap::new(),
            tcp_timeout: 300,
            udp_timeout: 300,
            mptcp: false,
            default_dns: None,
            dns_cache_time: 10,
            log_file_dir: None,

            redis_enable: false,
            redis_addr: None,
            redis_password: None,
            redis_db: 0,
            redis_tls: false,
            conn_limit_expiry: 60,
            redis_timeout_ms: 300,

            detect_packet: false,

            ip_user_cache_time: 1,
            ip_user_cache_save_enable: true,
            ip_user_cache_save_dir: PathBuf::from("/etc/elise"),

            ss_decrypt_concurrency: 8,
            ss_invalid_access_enable: false,
            ss_invalid_access_count: 30,
            ss_invalid_access_duration: 60,
            ss_invalid_access_forbidden_time: 600,

            force_vmess_aead: false,
            force_vmess_md5: false,
            vmess_aead_invalid_access_enable: false,
            vmess_aead_invalid_access_count: 30,
            vmess_aead_invalid_access_duration: 60,
            vmess_aead_invalid_access_forbidden_time: 600,

            raw_properties: HashMap::new(),
        }
    }
}

impl GlobalConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> std::io::Result<Self> {
        let content = fs::read_to_string(&path)?;
        let mut cfg = Self::parse(&content);
        cfg.apply_env_overrides();

        // Local files resolution priority:
        // CLI (applied later) > elise.conf explicit path > elise.conf parent directory fallback
        if let Some(parent) = path.as_ref().parent() {
            if !cfg.raw_properties.contains_key("dns_rules_file")
                && !cfg.raw_properties.contains_key("dns_file")
                && !cfg.raw_properties.contains_key("dns_path")
            {
                cfg.dns_file = parent.join("dns.yml");
            }
            if !cfg.raw_properties.contains_key("routes_file")
                && !cfg.raw_properties.contains_key("routes_path")
            {
                cfg.routes_file = parent.join("routes.toml");
            }
            if !cfg.raw_properties.contains_key("block_list_file")
                && !cfg.raw_properties.contains_key("block_list")
                && !cfg.raw_properties.contains_key("audit_block_list")
            {
                cfg.block_list = parent.join("blockList");
            }
            if !cfg.raw_properties.contains_key("white_list_file")
                && !cfg.raw_properties.contains_key("white_list")
                && !cfg.raw_properties.contains_key("audit_white_list")
            {
                cfg.white_list = parent.join("whiteList");
            }
            if !cfg.raw_properties.contains_key("ip_user_cache_save_dir") {
                cfg.ip_user_cache_save_dir = parent.to_path_buf();
            }
        }

        if !matches!(
            cfg.panel_type.as_str(),
            "xboard" | "v2board" | "xiaov2board" | "xiaov2b" | "ppanel" | "sspanel" | "sspanel-uim"
        ) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Unsupported panel type in configuration (type/panel_type)",
            ));
        }
        Ok(cfg)
    }

    pub fn parse(content: &str) -> Self {
        let mut cfg = Self::default();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                // Section header like [node_1]
                continue;
            }

            if let Some((k, v)) = line.split_once('=') {
                let key = k.trim().to_lowercase();
                let val = v
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .trim()
                    .to_string();
                cfg.raw_properties.insert(key.clone(), val.clone());
                cfg.apply_kv(&key, &val);
            }
        }

        cfg
    }

    pub fn apply_env_overrides(&mut self) {
        for (k, v) in std::env::vars() {
            let val = v.trim().to_string();
            if k.starts_with("DNS_") || k.starts_with("dns_") {
                self.dns_env_vars.insert(k.clone(), val.clone());
            }

            let key = k.to_ascii_lowercase();
            self.raw_properties.insert(key.clone(), val.clone());
            self.apply_kv(&key, &val);
        }
    }

    pub fn apply_kv(&mut self, key: &str, val: &str) {
        match key {
            "panel_type" | "type" => self.panel_type = val.to_lowercase(),
            "api_host" | "panel_url" | "webapi_url" => {
                self.api_host = val.trim_end_matches('/').to_string()
            }
            "api_key" | "panel_key" | "webapi_key" => self.api_key = val.to_string(),
            "node_id" | "node_ids" => {
                let parsed: Vec<u32> = val
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u32>().ok())
                    .collect();
                if !parsed.is_empty() {
                    self.node_ids = parsed;
                }
            }
            "node_sync_interval" | "check_interval" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.node_sync_interval = n.max(10);
                }
            }
            "node_report_interval" | "submit_interval" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.node_report_interval = n.max(10);
                }
            }
            "auto_tls" => self.auto_tls = val.eq_ignore_ascii_case("true") || val == "1",
            "fake_sni" => self.fake_sni = val.to_string(),
            "listen_strategy" | "multi_node_listen_strategy" => {
                self.listen_strategy = val.to_lowercase()
            }
            "listen_addr" | "listen" => self.listen_addr = val.to_string(),
            "pprof_addr" => self.pprof_addr = val.to_string(),

            "routes_file" | "routes_path" => self.routes_file = PathBuf::from(val),
            "dns_file" | "dns_path" | "dns_rules_file" => self.dns_file = PathBuf::from(val),
            "block_list" | "audit_block_list" | "block_list_file" => {
                self.block_list = PathBuf::from(val)
            }
            "white_list" | "audit_white_list" | "white_list_file" => {
                self.white_list = PathBuf::from(val)
            }
            "geoip_file" | "geoip_path" => self.geoip_file = Some(PathBuf::from(val)),
            "geosite_file" | "geosite_path" => self.geosite_file = Some(PathBuf::from(val)),

            "proxy_protocol" => {
                self.proxy_protocol = val.eq_ignore_ascii_case("true")
                    || val == "1"
                    || val.eq_ignore_ascii_case("auto");
                self.proxy_protocol_mode = crate::conn::ProxyProtocolMode::from_str_opt(val);
            }
            "force_proxy_protocol" => {
                let force = val.eq_ignore_ascii_case("true") || val == "1";
                self.force_proxy_protocol = force;
                if force {
                    self.proxy_protocol = true;
                    self.proxy_protocol_mode = crate::conn::ProxyProtocolMode::Strict;
                }
            }
            "udp_proxy_protocol" => {
                self.udp_proxy_protocol = val.eq_ignore_ascii_case("true") || val == "1";
            }
            "outbound_proxy_protocol" => {
                self.outbound_proxy_protocol = match val.to_ascii_lowercase().as_str() {
                    "v1" | "1" => Some("v1".to_string()),
                    "v2" | "2" => Some("v2".to_string()),
                    _ => None,
                };
            }
            "trusted_proxies" => {
                let nets: Vec<ipnet::IpNet> = val
                    .split(',')
                    .filter_map(|s| {
                        let s = s.trim();
                        if s.is_empty() {
                            None
                        } else if let Ok(net) = s.parse::<ipnet::IpNet>() {
                            Some(net)
                        } else if let Ok(ip) = s.parse::<std::net::IpAddr>() {
                            Some(ip.into())
                        } else {
                            None
                        }
                    })
                    .collect();
                if !nets.is_empty() {
                    self.proxy_protocol = true;
                    if self.proxy_protocol_mode == crate::conn::ProxyProtocolMode::Off {
                        self.proxy_protocol_mode = crate::conn::ProxyProtocolMode::Auto;
                    }
                    self.trusted_proxies = Some(nets);
                } else {
                    self.trusted_proxies = None;
                }
            }

            "out_ip_ipv4" => {
                self.out_ip_ipv4 = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                }
            }
            "out_ip_ipv6" => {
                self.out_ip_ipv6 = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                }
            }
            "auto_out_ip" => self.auto_out_ip = val.eq_ignore_ascii_case("true") || val == "1",
            "dns_strategy" => self.dns_strategy = val.to_lowercase(),

            "redis_url" => {
                self.redis_url = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                }
            }
            "redis_addr" => {
                self.redis_addr = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                };
            }
            "device_limit_window" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.device_limit_window = n;
                }
            }
            "device_limit_prefix_ipv4" | "user_ip_limit_cidr_prefix_v4" => {
                if let Ok(n) = val.parse::<u8>() {
                    self.device_limit_prefix_ipv4 = n.min(32);
                }
            }
            "device_limit_prefix_ipv6" | "user_ip_limit_cidr_prefix_v6" => {
                if let Ok(n) = val.parse::<u8>() {
                    self.device_limit_prefix_ipv6 = n.min(128);
                }
            }

            "log_level" => self.log_level = val.to_lowercase(),
            "log_file" => {
                self.log_file = if val.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(val))
                }
            }
            "log_file_dir" => {
                self.log_file_dir = if val.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(val))
                }
            }
            "audit_log_file" => {
                self.audit_log_file = if val.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(val))
                }
            }
            "log_retention_days" | "log_file_retention_days" => {
                if let Ok(n) = val.parse::<u32>() {
                    self.log_retention_days = n;
                }
            }
            "log_max_size_mb" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.log_max_size_mb = n;
                }
            }

            "clickhouse_enabled" | "access_log_enable" => {
                self.clickhouse_enabled = val.eq_ignore_ascii_case("true") || val == "1"
            }
            "clickhouse_addr" | "access_log_clickhouse_url" => {
                self.clickhouse_addr = val.to_string()
            }
            "clickhouse_db" | "access_log_clickhouse_database" => {
                self.clickhouse_db = val.to_string()
            }
            "clickhouse_table" | "access_log_clickhouse_table" => {
                self.clickhouse_table = val.to_string()
            }
            "clickhouse_user" | "access_log_clickhouse_username" => {
                self.clickhouse_user = val.to_string()
            }
            "clickhouse_password" | "access_log_clickhouse_password" => {
                self.clickhouse_password = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                }
            }

            "tcp_timeout" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.tcp_timeout = n;
                }
            }
            "udp_timeout" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.udp_timeout = n;
                }
            }
            "mptcp" => {
                self.mptcp = val.eq_ignore_ascii_case("true") || val == "1";
            }
            "default_dns" => {
                self.default_dns = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                };
            }
            "dns_cache_time" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.dns_cache_time = n;
                }
            }

            "forbidden_ports" => {
                self.forbidden_ports = parse_port_ranges(val);
            }
            "ban_private_ip" => {
                self.ban_private_ip = val.eq_ignore_ascii_case("true") || val == "1";
            }
            "forbidden_bit_torrent" => {
                self.forbidden_bit_torrent = val.eq_ignore_ascii_case("true") || val == "1";
            }
            "domain_sniff" => {
                self.domain_sniff =
                    !val.is_empty() && !val.eq_ignore_ascii_case("false") && val != "0";
            }
            "sniff_redirect" => {
                self.sniff_redirect = val.eq_ignore_ascii_case("true") || val == "1";
            }
            "block_list_url" => {
                self.block_list_url = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                };
            }
            "white_list_url" => {
                self.white_list_url = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                };
            }
            "routes_url" => {
                self.routes_url = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                };
            }

            "submit_traffic_min_traffic" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.submit_traffic_min_traffic = n;
                }
            }
            "submit_alive_ip_min_traffic" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.submit_alive_ip_min_traffic = n;
                }
            }
            "user_conn_limit" => {
                if let Ok(n) = val.parse::<u32>() {
                    self.user_conn_limit = n;
                }
            }
            "user_tcp_limit" => {
                if let Ok(n) = val.parse::<u32>() {
                    self.user_tcp_limit = n;
                }
            }
            "user_speed_limit" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.user_speed_limit = n;
                }
            }
            "node_speed_limit" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.node_speed_limit = n;
                }
            }
            "domain_audit_enable" => {
                self.domain_audit_enable = val.eq_ignore_ascii_case("true") || val == "1";
            }
            "domain_audit_domains" => {
                self.domain_audit_domains = val
                    .split([',', '\n'])
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "domain_audit_log_dir" => {
                self.domain_audit_log_dir = if val.is_empty() {
                    None
                } else {
                    Some(PathBuf::from(val))
                };
            }
            "domain_audit_retention_days" => {
                if let Ok(n) = val.parse::<u32>() {
                    self.domain_audit_retention_days = n;
                }
            }

            // Redis IP/Device Limit
            "redis_enable" => {
                self.redis_enable = val.eq_ignore_ascii_case("true") || val == "1";
            }
            "redis_password" | "redis_pass" => {
                self.redis_password = if val.is_empty() {
                    None
                } else {
                    Some(val.to_string())
                };
            }
            "redis_db" => {
                if let Ok(n) = val.parse::<u8>() {
                    self.redis_db = n;
                }
            }
            "redis_tls" => {
                self.redis_tls = val.eq_ignore_ascii_case("true") || val == "1";
            }
            "conn_limit_expiry" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.conn_limit_expiry = n;
                    self.device_limit_window = n; // synchronize window
                }
            }
            "redis_timeout_ms" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.redis_timeout_ms = n;
                }
            }

            // Audit
            "detect_packet" => {
                self.detect_packet = val.eq_ignore_ascii_case("true") || val == "1";
            }

            // IP User Cache
            "ip_user_cache_time" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.ip_user_cache_time = n;
                }
            }
            "ip_user_cache_save_enable" => {
                self.ip_user_cache_save_enable = val.eq_ignore_ascii_case("true") || val == "1";
            }
            "ip_user_cache_save_dir" => {
                if !val.is_empty() {
                    self.ip_user_cache_save_dir = PathBuf::from(val);
                }
            }

            // SS Single Port AEAD
            "ss_decrypt_concurrency" => {
                if let Ok(n) = val.parse::<usize>() {
                    self.ss_decrypt_concurrency = n.max(1);
                }
            }
            "ss_invalid_access_enable" => {
                self.ss_invalid_access_enable = val.eq_ignore_ascii_case("true") || val == "1";
            }
            "ss_invalid_access_count" => {
                if let Ok(n) = val.parse::<u32>() {
                    self.ss_invalid_access_count = n;
                }
            }
            "ss_invalid_access_duration" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.ss_invalid_access_duration = n;
                }
            }
            "ss_invalid_access_forbidden_time" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.ss_invalid_access_forbidden_time = n;
                }
            }

            // VMess AEAD
            "force_vmess_aead" => {
                self.force_vmess_aead = val.eq_ignore_ascii_case("true") || val == "1";
            }
            "force_vmess_md5" => {
                self.force_vmess_md5 = val.eq_ignore_ascii_case("true") || val == "1";
            }
            "vmess_aead_invalid_access_enable" => {
                self.vmess_aead_invalid_access_enable =
                    val.eq_ignore_ascii_case("true") || val == "1";
            }
            "vmess_aead_invalid_access_count" => {
                if let Ok(n) = val.parse::<u32>() {
                    self.vmess_aead_invalid_access_count = n;
                }
            }
            "vmess_aead_invalid_access_duration" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.vmess_aead_invalid_access_duration = n;
                }
            }
            "vmess_aead_invalid_access_forbidden_time" => {
                if let Ok(n) = val.parse::<u64>() {
                    self.vmess_aead_invalid_access_forbidden_time = n;
                }
            }

            _ => {}
        }
    }

    pub fn get_listen_ip_for_node(
        &self,
        node_index: usize,
        explicit_override: Option<&str>,
    ) -> String {
        if let Some(ip) = explicit_override {
            if !ip.is_empty() {
                return ip.to_string();
            }
        }

        let ips: Vec<&str> = self
            .listen_addr
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if ips.is_empty() {
            return "0.0.0.0".to_string();
        }

        if ips.len() == 1 || self.listen_strategy == "shared" {
            return ips[0].to_string();
        }

        ips[node_index % ips.len()].to_string()
    }

    pub fn get_redis_url(&self) -> Option<String> {
        if let Some(url) = &self.redis_url {
            return Some(url.clone());
        }
        if self.redis_enable {
            let addr = self.redis_addr.as_deref().unwrap_or("127.0.0.1:6379");
            let scheme = if self.redis_tls { "rediss" } else { "redis" };
            let clean_addr = addr.trim();
            if clean_addr.starts_with("redis://") || clean_addr.starts_with("rediss://") {
                return Some(clean_addr.to_string());
            }
            let auth = if let Some(pass) = &self.redis_password {
                format!(":{}@", pass)
            } else {
                "".to_string()
            };
            return Some(format!(
                "{}://{}{}/{}",
                scheme, auth, clean_addr, self.redis_db
            ));
        }
        None
    }

    pub fn get_proxy_protocol_mode(&self) -> crate::conn::ProxyProtocolMode {
        if self.force_proxy_protocol {
            crate::conn::ProxyProtocolMode::Strict
        } else if self.proxy_protocol || self.trusted_proxies.is_some() {
            if self.proxy_protocol_mode == crate::conn::ProxyProtocolMode::Off {
                crate::conn::ProxyProtocolMode::Auto
            } else {
                self.proxy_protocol_mode
            }
        } else {
            crate::conn::ProxyProtocolMode::Off
        }
    }
}

fn parse_port_ranges(val: &str) -> Vec<(u16, u16)> {
    let mut ranges = Vec::new();
    for part in val.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once('-') {
            if let (Ok(s), Ok(e)) = (start.trim().parse::<u16>(), end.trim().parse::<u16>()) {
                ranges.push((s, e));
            }
        } else if let Ok(p) = part.parse::<u16>() {
            ranges.push((p, p));
        }
    }
    ranges
}
