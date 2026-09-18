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
                    let val = v
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .trim()
                        .to_string();
                    match key.as_str() {
                        "listen_addr" | "listen" => self.listen_addr = Some(val.clone()),
                        "port_offset" => self.port_offset = val.parse().unwrap_or(0),
                        "fake_sni" => self.fake_sni = Some(val.clone()),
                        "proxy_protocol" => {
                            self.proxy_protocol = Some(
                                val.eq_ignore_ascii_case("true")
                                    || val == "1"
                                    || val.eq_ignore_ascii_case("auto"),
                            );
                        }
                        "udp_proxy_protocol" => {
                            self.udp_proxy_protocol =
                                Some(val.eq_ignore_ascii_case("true") || val == "1");
                        }
                        "mptcp" => {
                            self.mptcp = Some(val.eq_ignore_ascii_case("true") || val == "1");
                        }
                        "force_close_ssl" | "disable_tls" => {
                            self.force_close_ssl =
                                Some(val.eq_ignore_ascii_case("true") || val == "1");
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

    pub fn save_node_conf<P: AsRef<Path>>(
        &self,
        nodes_dir: P,
        node_info: &NodeInfo,
    ) -> std::io::Result<()> {
        let dir = nodes_dir.as_ref();
        if !dir.exists() {
            let _ = fs::create_dir_all(dir);
        }

        let file_path = dir.join(format!("node_{}.conf", self.node_id));

        let mut user_part = if !self.raw_user_section.is_empty() {
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

        let mut pattern = String::new();
        if node_info.node_type.eq_ignore_ascii_case("mieru") {
            pattern = format!(
                "traffic_pattern = {}\n",
                node_info.traffic_pattern.as_deref().unwrap_or("").trim()
            );
            if !user_part.lines().any(|line| {
                line.trim()
                    .trim_start_matches('#')
                    .trim()
                    .split_once('=')
                    .is_some_and(|(key, _)| {
                        key.trim().eq_ignore_ascii_case("mieru_traffic_pattern")
                    })
            }) {
                user_part.push_str(
                    "# Mieru 非空覆盖优先级：节点 [USER] > 主配置 > 面板；留空使用面板值。\n# mieru_traffic_pattern =\n",
                );
            }
        }

        let content = format!(
            r#"# ==============================================================================
# Elise 节点独立配置文件 (Node ID: {})
# [AUTO] 区由 Elise 根据面板 API 下发信息自动维护生成，请勿手动编辑该区域。
# [USER] 区为用户自定义覆盖项，重启与更新配置时将完整保留。
# 参数优先级按字段确定；[USER] 仅覆盖已接入的配置项。
# ==============================================================================

[AUTO]
node_id = {}
server_type = {}
server_port = {}
{}
{}
"#,
            self.node_id,
            self.node_id,
            node_info.node_type,
            node_info.server_port,
            pattern,
            user_part.trim()
        );

        fs::write(file_path, content)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;
    use prost::Message;

    #[test]
    fn mieru_config_refresh_preserves_local_overrides() {
        let dir = std::env::temp_dir().join(format!("elise-node-config-{}", uuid::Uuid::new_v4()));
        let mut info = NodeInfo {
            node_type: "mieru".into(),
            server_port: 5000,
            traffic_pattern: Some(
                BASE64_STANDARD.encode(
                    crate::protocol::mieru::proto::TrafficPattern {
                        seed: Some(42),
                        ..Default::default()
                    }
                    .encode_to_vec(),
                ),
            ),
            ..Default::default()
        };
        let mut cfg = NodeConfig {
            node_id: 26,
            ..Default::default()
        };
        cfg.parse_content("[USER]\n# existing comment\nlisten_addr = 127.0.0.1");
        cfg.save_node_conf(&dir, &info).unwrap();
        let path = dir.join("node_26.conf");
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains(&format!(
            "traffic_pattern = {}",
            info.traffic_pattern.as_deref().unwrap()
        )));
        assert!(content.contains("# existing comment\nlisten_addr = 127.0.0.1"));
        assert_eq!(content.matches("# mieru_traffic_pattern =").count(), 1);
        let mut reloaded = NodeConfig::load_for_node(&dir, 26);
        assert!(!reloaded
            .custom_settings
            .contains_key("mieru_traffic_pattern"));

        reloaded.parse_content(&content.replace(
            "# mieru_traffic_pattern =",
            &format!(
                "mieru_traffic_pattern = {}",
                info.traffic_pattern.as_deref().unwrap()
            ),
        ));
        info.traffic_pattern = None;
        reloaded.save_node_conf(&dir, &info).unwrap();
        let content = fs::read_to_string(&path).unwrap();
        assert!(content.contains("traffic_pattern = \n"));
        assert_eq!(content.matches("mieru_traffic_pattern =").count(), 1);
        assert_eq!(
            NodeConfig::load_for_node(&dir, 26)
                .custom_settings
                .get("mieru_traffic_pattern"),
            reloaded.custom_settings.get("mieru_traffic_pattern")
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn default_config_only_adds_pattern_for_mieru() {
        let dir = std::env::temp_dir().join(format!("elise-node-config-{}", uuid::Uuid::new_v4()));
        let cfg = NodeConfig {
            node_id: 1,
            ..Default::default()
        };
        for kind in ["mieru", "vless"] {
            cfg.save_node_conf(
                &dir,
                &NodeInfo {
                    node_type: kind.into(),
                    server_port: 1234,
                    ..Default::default()
                },
            )
            .unwrap();
            let content = fs::read_to_string(dir.join("node_1.conf")).unwrap();
            assert_eq!(content.contains("traffic_pattern ="), kind == "mieru");
            assert_eq!(
                content.contains("# mieru_traffic_pattern ="),
                kind == "mieru"
            );
        }
        fs::remove_dir_all(dir).unwrap();
    }
}
