use crate::panel::types::NodeInfo;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Default)]
pub struct NodeConfig {
    pub node_id: u32,
    pub listen_addr: Option<String>,
    pub port_offset: i32,
    pub fake_sni: Option<String>,
    pub proxy_protocol: Option<bool>,
    pub udp_proxy_protocol: Option<bool>,
    pub mptcp: Option<bool>,
    pub force_close_ssl: Option<bool>,
    pub cert_file: Option<PathBuf>,
    pub key_file: Option<PathBuf>,
    pub cert_domain: Option<String>,
    pub check_interval: Option<u64>,
    pub submit_interval: Option<u64>,
    pub out_ip_ipv4: Option<String>,
    pub out_ip_ipv6: Option<String>,
    pub speed_limit: Option<u64>,
    pub stream_win_init: Option<u64>,
    pub stream_win_max: Option<u64>,
    pub conn_win_init: Option<u64>,
    pub conn_win_max: Option<u64>,
    pub custom_settings: HashMap<String, String>,
    pub raw_user_section: String,
}

impl NodeConfig {
    pub fn load_for_node<P: AsRef<Path>>(base_dir: P, node_id: u32) -> Self {
        let mut cfg = NodeConfig {
            node_id,
            ..Default::default()
        };

        let file_path = base_dir.as_ref().join(format!("node_{}.conf", node_id));
        if let Ok(content) = fs::read_to_string(&file_path) {
            cfg.parse_content(&content);
        }
        cfg
    }

    pub fn parse_content(&mut self, content: &str) {
        let mut in_user_section = false;
        let mut has_sections = false;
        let mut user_lines = Vec::new();

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.eq_ignore_ascii_case("[user]") {
                in_user_section = true;
                has_sections = true;
                continue;
            } else if trimmed.starts_with('[') && trimmed.ends_with(']') {
                in_user_section = false;
                has_sections = true;
                continue;
            }

            if in_user_section || !has_sections {
                if in_user_section {
                    user_lines.push(line.to_string());
                }

                if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
                    continue;
                }

                if let Some((k, v)) = trimmed.split_once('=') {
                    let key = k.trim().to_lowercase();
                    let val = v.trim().trim_matches('"').trim_matches('\'').trim().to_string();
                    match key.as_str() {
                        "listen_addr" | "listen" => self.listen_addr = Some(val.clone()),
                        "port_offset" => self.port_offset = val.parse().unwrap_or(0),
                        "fake_sni" => self.fake_sni = Some(val.clone()),
                        "proxy_protocol" => {
                            self.proxy_protocol = Some(val.eq_ignore_ascii_case("true") || val == "1" || val.eq_ignore_ascii_case("auto"));
                        }
                        "udp_proxy_protocol" => {
                            self.udp_proxy_protocol = Some(val.eq_ignore_ascii_case("true") || val == "1");
                        }
                        "mptcp" => {
                            self.mptcp = Some(val.eq_ignore_ascii_case("true") || val == "1");
                        }
                        "force_close_ssl" | "disable_tls" => {
                            self.force_close_ssl = Some(val.eq_ignore_ascii_case("true") || val == "1");
                        }
                        "cert_file" => self.cert_file = Some(PathBuf::from(val.clone())),
                        "key_file" => self.key_file = Some(PathBuf::from(val.clone())),
                        "cert_domain" => self.cert_domain = Some(val.clone()),
                        "check_interval" => self.check_interval = val.parse().ok(),
                        "submit_interval" => self.submit_interval = val.parse().ok(),
                        "out_ip_ipv4" => self.out_ip_ipv4 = Some(val.clone()),
                        "out_ip_ipv6" => self.out_ip_ipv6 = Some(val.clone()),
                        "speed_limit" => self.speed_limit = val.parse().ok(),
                        "stream_win_init" => self.stream_win_init = val.parse().ok(),
                        "stream_win_max" => self.stream_win_max = val.parse().ok(),
                        "conn_win_init" => self.conn_win_init = val.parse().ok(),
                        "conn_win_max" => self.conn_win_max = val.parse().ok(),
                        _ => {
                            self.custom_settings.insert(key, val);
                        }
                    }
                }
            }
        }

        if has_sections {
            self.raw_user_section = user_lines.join("\n").trim().to_string();
        }
    }

    pub fn save_node_conf<P: AsRef<Path>>(&self, nodes_dir: P, node_info: &NodeInfo) -> std::io::Result<()> {
        let dir = nodes_dir.as_ref();
        if !dir.exists() {
            let _ = fs::create_dir_all(dir);
        }

        let file_path = dir.join(format!("node_{}.conf", self.node_id));

        let user_part = if !self.raw_user_section.is_empty() {
            format!("[USER]\n{}\n", self.raw_user_section)
        } else {
            format!(
                r#"[USER]
# 用户自定义参数覆盖示例（取消注释后修改重启即生效）：
# listen_addr = 0.0.0.0
# port_offset = 0
# proxy_protocol = false
# force_close_ssl = false
# cert_file = /etc/elise/cert/node_{}.crt
# key_file = /etc/elise/cert/node_{}.key
# fake_sni = www.microsoft.com
# check_interval = 60
# submit_interval = 60
"#,
                self.node_id, self.node_id
            )
        };

        let content = format!(
            r#"# ==============================================================================
# Elise 节点独立配置文件 (Node ID: {})
# [AUTO] 区由 Elise 根据面板 API 下发信息自动维护生成，请勿手动编辑该区域。
# [USER] 区为用户自定义覆盖项，重启与更新配置时将完整保留。
# 覆盖优先级：面板 API > [USER] 自定义覆盖 > 主配置 elise.conf
# ==============================================================================

[AUTO]
node_id = {}
server_type = {}
server_port = {}

{}
"#,
            self.node_id,
            self.node_id,
            node_info.node_type,
            node_info.server_port,
            user_part.trim()
        );

        fs::write(file_path, content)
    }
}
