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
    pub cert_mode: Option<String>,
    pub cert_key_length: Option<String>,
    pub acme_server: Option<String>,
    pub acme_email: Option<String>,
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

/// Normalizes certificate file paths to avoid common typos (such as /etc/eslise -> /etc/elise).
pub fn normalize_cert_path<P: AsRef<Path>>(path: P) -> PathBuf {
    let p_str = path.as_ref().to_string_lossy();
    if p_str.contains("/etc/eslise") || p_str.contains("\\etc\\eslise") {
        let fixed = p_str
            .replace("/etc/eslise", "/etc/elise")
            .replace("\\etc\\eslise", "\\etc\\elise");
        PathBuf::from(fixed)
    } else {
        path.as_ref().to_path_buf()
    }
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
                        "cert_file" => self.cert_file = Some(normalize_cert_path(val)),
                        "key_file" => self.key_file = Some(normalize_cert_path(val)),
                        "cert_domain" => self.cert_domain = Some(val.clone()),
                        "cert_mode" => self.cert_mode = Some(val.clone()),
                        "cert_key_length" => self.cert_key_length = Some(val.clone()),
                        "acme_server" => self.acme_server = Some(val.clone()),
                        "acme_email" | "email" => self.acme_email = Some(val.clone()),
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

    pub fn inherit_from_global(&mut self, global: &crate::config::GlobalConfig) {
        // 1. Per-node section overrides from main config [node_X]
        if let Some(overrides) = global.node_overrides.get(&self.node_id) {
            if self.cert_mode.is_none() {
                self.cert_mode = overrides.get("cert_mode").cloned();
            }
            if self.cert_domain.is_none() {
                self.cert_domain = overrides.get("cert_domain").cloned();
            }
            if self.cert_key_length.is_none() {
                self.cert_key_length = overrides.get("cert_key_length").cloned();
            }
            if self.acme_server.is_none() {
                self.acme_server = overrides.get("acme_server").cloned();
            }
            if self.acme_email.is_none() {
                self.acme_email = overrides
                    .get("acme_email")
                    .or_else(|| overrides.get("email"))
                    .cloned();
            }
            if self.cert_file.is_none() {
                self.cert_file = overrides.get("cert_file").map(normalize_cert_path);
            }
            if self.key_file.is_none() {
                self.key_file = overrides.get("key_file").map(normalize_cert_path);
            }
            if self.listen_addr.is_none() {
                self.listen_addr = overrides
                    .get("listen_addr")
                    .or_else(|| overrides.get("listen"))
                    .cloned();
            }
            if self.fake_sni.is_none() {
                self.fake_sni = overrides.get("fake_sni").cloned();
            }
        }

        // 2. Global defaults
        if self.cert_mode.is_none() {
            self.cert_mode = global.cert_mode.clone();
        }
        if self.cert_domain.is_none() {
            self.cert_domain = global.cert_domain.clone();
        }
        if self.cert_key_length.is_none() {
            self.cert_key_length = global.cert_key_length.clone();
        }
        if self.acme_server.is_none() {
            self.acme_server = global.acme_server.clone();
        }
        if self.acme_email.is_none() {
            self.acme_email = global.acme_email.clone();
        }
        if self.cert_file.is_none() {
            self.cert_file = global.cert_file.clone();
        }
        if self.key_file.is_none() {
            self.key_file = global.key_file.clone();
        }
    }

    pub fn prepare_node_info(&self, nodes_dir: &Path, info: &mut NodeInfo) -> std::io::Result<()> {
        use base64::prelude::*;
        use serde_json::json;
        use std::io::{Error, ErrorKind};

        if info.tls.is_none()
            && matches!(
                info.node_type.as_str(),
                "trojan" | "anytls" | "hysteria" | "hysteria2" | "tuic" | "naive"
            )
        {
            info.tls = Some(1);
        }

        if let Some(domain) = &self.cert_domain {
            if info
                .server_name
                .as_deref()
                .map(|s| s.is_empty())
                .unwrap_or(true)
            {
                info.server_name = Some(domain.clone());
            }
        }

        let domain = self
            .cert_domain
            .as_deref()
            .or(info.server_name.as_deref())
            .or(info.host.as_deref())
            .unwrap_or("node");

        let default_cert = if std::path::Path::new("/etc/elise").exists() {
            std::path::PathBuf::from(format!("/etc/elise/cert/{domain}.crt"))
        } else {
            nodes_dir
                .parent()
                .unwrap_or(nodes_dir)
                .join("cert")
                .join(format!("{domain}.crt"))
        };
        let default_key = if std::path::Path::new("/etc/elise").exists() {
            std::path::PathBuf::from(format!("/etc/elise/cert/{domain}.key"))
        } else {
            nodes_dir
                .parent()
                .unwrap_or(nodes_dir)
                .join("cert")
                .join(format!("{domain}.key"))
        };

        let cert = normalize_cert_path(self.cert_file.as_ref().unwrap_or(&default_cert));
        let key = normalize_cert_path(self.key_file.as_ref().unwrap_or(&default_key));

        if self.cert_file.is_some()
            || self.cert_mode.as_deref() == Some("http")
            || self.cert_mode.as_deref() == Some("acme")
        {
            info.cert_config.get_or_insert(json!({}))["cert_file"] = json!(cert);
            info.cert_config.get_or_insert(json!({}))["key_file"] = json!(key);
        }

        if !matches!(info.tls, Some(1 | 2)) {
            return Ok(());
        }
        let server_name = info.server_name.clone().or_else(|| info.host.clone());
        let ts = info.tls_settings.get_or_insert(json!({}));
        let ts = ts
            .as_object_mut()
            .ok_or_else(|| Error::new(ErrorKind::InvalidData, "tls_settings must be an object"))?;
        if let Some(domain) = &self.cert_domain {
            if !ts.contains_key("server_name")
                || ts
                    .get("server_name")
                    .and_then(|v| v.as_str())
                    .map(|s| s.is_empty())
                    .unwrap_or(true)
            {
                ts.insert("server_name".to_string(), json!(domain));
            }
        }
        if info.tls == Some(2) {
            let panel_public = ts
                .get("public_key")
                .and_then(|v| v.as_str())
                .or(info.public_key.as_deref())
                .unwrap_or("")
                .trim()
                .to_owned();
            let mut private = ts
                .get("private_key")
                .and_then(|v| v.as_str())
                .filter(|s| !s.trim().is_empty())
                .or(info.server_key.as_deref())
                .unwrap_or("")
                .trim()
                .to_owned();
            if private.is_empty() {
                private = Self::load_or_create_key(
                    &nodes_dir.join(format!("node_{}.reality.key", self.node_id)),
                    || {
                        if !panel_public.is_empty() {
                            return Err(Error::new(ErrorKind::InvalidData, "Panel supplied a REALITY public key without its private key; provide the matching private key in the panel"));
                        }
                        Ok(crate::security::generate_reality_keypair().private_key)
                    },
                )?;
            }
            let bytes = BASE64_URL_SAFE_NO_PAD
                .decode(private.trim_end_matches('='))
                .or_else(|_| BASE64_STANDARD.decode(&private))
                .map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "Invalid REALITY private key base64")
                })?;
            let secret: [u8; 32] = bytes.try_into().map_err(|_| {
                Error::new(
                    ErrorKind::InvalidData,
                    "REALITY private key must be 32 bytes",
                )
            })?;
            let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
            let public_text = BASE64_URL_SAFE_NO_PAD.encode(public.as_bytes());
            if !panel_public.is_empty() && panel_public.trim_end_matches('=') != public_text {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "REALITY public key does not match the private key",
                ));
            }
            ts.insert("private_key".into(), json!(private));
            ts.insert("public_key".into(), json!(public_text));
        } else if let Some(ech) = ts
            .get("ech")
            .filter(|e| e.get("enabled").and_then(|v| v.as_bool()) == Some(true))
            .cloned()
        {
            let name = ts
                .get("server_name")
                .and_then(|v| v.as_str())
                .or(server_name.as_deref())
                .unwrap_or("")
                .to_owned();
            let mut key = ech
                .get("server_keys")
                .or_else(|| ech.get("key"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_owned();
            if key.is_empty() {
                if let Some(path) = ech
                    .get("key_path")
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                {
                    key = fs::read_to_string(path)?;
                }
            }
            let config = if let Some(path) = ech
                .get("config_path")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
            {
                fs::read_to_string(path)?
            } else {
                ech.get("config")
                    .or_else(|| ech.get("config_list"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_owned()
            };
            if key.is_empty() {
                key = Self::load_or_create_key(
                    &nodes_dir.join(format!("node_{}.ech.key", self.node_id)),
                    || {
                        if !config.trim().is_empty() {
                            return Err(Error::new(ErrorKind::InvalidData, "Panel supplied ECH config without its server key; provide the matching ECH key in the panel"));
                        }
                        if rustls::pki_types::DnsName::try_from(name.as_str()).is_err() {
                            return Err(Error::new(
                                ErrorKind::InvalidData,
                                "ECH key generation requires a valid panel server_name",
                            ));
                        }
                        Ok(crate::security::EchKeyPair::generate(&name, 0).to_pem_ech_keys())
                    },
                )?;
            }
            let pair = crate::security::EchKeyPair::from_pem_or_bytes(key.as_bytes(), &name)
                .map_err(Error::other)?;
            let derived =
                x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(pair.private_key));
            if derived.to_bytes() != pair.public_key {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "ECH public key does not match the private key",
                ));
            }
            if !config.trim().is_empty() {
                let b64 = config
                    .lines()
                    .filter(|l| !l.trim().starts_with("-----"))
                    .map(str::trim)
                    .collect::<String>();
                let bytes = BASE64_STANDARD.decode(b64).map_err(|_| {
                    Error::new(ErrorKind::InvalidData, "Invalid ECH client config base64")
                })?;
                if bytes != pair.ech_config_list {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        "ECH client config does not match the server key",
                    ));
                }
            }
            let value = ts.get_mut("ech").unwrap();
            value["server_keys"] = json!(pair.to_pem_ech_keys());
            value["config"] = json!(BASE64_STANDARD.encode(pair.ech_config_list));
        }
        Ok(())
    }

    fn load_or_create_key(
        path: &Path,
        generate: impl FnOnce() -> std::io::Result<String>,
    ) -> std::io::Result<String> {
        use std::io::Write;
        fs::create_dir_all(path.parent().unwrap())?;
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(path.with_extension("lock"))?;
        lock.try_lock().map_err(std::io::Error::other)?;
        match fs::read_to_string(path) {
            Ok(key) => return Ok(key),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let key = generate()?;
        let temporary = path.with_extension("tmp");
        let mut file = options.truncate(true).open(&temporary)?;
        file.write_all(key.as_bytes())?;
        file.sync_all()?;
        drop(file);
        fs::rename(&temporary, path)?;
        #[cfg(unix)]
        fs::File::open(path.parent().unwrap())?.sync_all()?;
        tracing::warn!(path = %path.display(), "Generated persistent node key; copy the public configuration from node AUTO settings to the panel before connecting clients");
        Ok(key)
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

        let mut settings = serde_json::to_value(node_info).map_err(std::io::Error::other)?;
        if let Some(tls) = settings
            .get_mut("tls_settings")
            .and_then(|v| v.as_object_mut())
        {
            tls.remove("private_key");
            tls.remove("key");
            if let Some(ech) = tls.get_mut("ech").and_then(|v| v.as_object_mut()) {
                ech.remove("key");
                ech.remove("server_keys");
            }
        }
        for (key, value) in settings.as_object().unwrap() {
            if value.is_null()
                || matches!(
                    key.as_str(),
                    "id" | "node_type"
                        | "server_port"
                        | "traffic_pattern"
                        | "server_key"
                        | "decryption"
                        | "encryption_settings"
                        | "cert_config"
                )
            {
                continue;
            }
            pattern.push_str(&format!("{key} = {value}\n"));
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

        use std::io::Write;
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
            options.mode(0o600);
            if file_path.exists() {
                fs::set_permissions(&file_path, fs::Permissions::from_mode(0o600))?;
            }
        }
        options.open(file_path)?.write_all(content.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::prelude::*;
    use prost::Message;

    #[test]
    fn reality_keys_are_stable_panel_keys_win_and_mismatches_fail() {
        let dir = std::env::temp_dir().join(format!("elise-key-config-{}", uuid::Uuid::new_v4()));
        let cfg = NodeConfig {
            node_id: 7,
            ..Default::default()
        };
        let original = NodeInfo {
            node_type: "vless".into(),
            tls: Some(2),
            tls_settings: Some(
                serde_json::json!({"server_name":"www.example.com","server_port":443}),
            ),
            ..Default::default()
        };
        let mut first = original.clone();
        cfg.prepare_node_info(&dir, &mut first).unwrap();
        let mut restarted = original.clone();
        cfg.prepare_node_info(&dir, &mut restarted).unwrap();
        assert_eq!(first.tls_settings, restarted.tls_settings);
        assert!(crate::transport::types::StreamSettings::from_node_info(&first).is_ok());
        cfg.save_node_conf(&dir, &first).unwrap();
        let saved = fs::read_to_string(dir.join("node_7.conf")).unwrap();
        assert!(!saved.contains("private_key"));
        assert!(saved.contains(
            first.tls_settings.as_ref().unwrap()["public_key"]
                .as_str()
                .unwrap()
        ));
        let panel = crate::security::generate_reality_keypair();
        restarted.tls_settings.as_mut().unwrap()["private_key"] =
            serde_json::json!(panel.private_key);
        restarted.tls_settings.as_mut().unwrap()["public_key"] =
            serde_json::json!(panel.public_key);
        cfg.prepare_node_info(&dir, &mut restarted).unwrap();
        assert_ne!(first.tls_settings, restarted.tls_settings);
        restarted.tls_settings.as_mut().unwrap()["public_key"] = serde_json::json!("wrong");
        assert!(cfg
            .prepare_node_info(&dir, &mut restarted)
            .unwrap_err()
            .to_string()
            .contains("does not match"));
        let mut public_only = original.clone();
        public_only.tls_settings.as_mut().unwrap()["public_key"] =
            serde_json::json!(panel.public_key);
        let other = NodeConfig {
            node_id: 8,
            ..Default::default()
        };
        assert!(other.prepare_node_info(&dir, &mut public_only).is_err());
        assert!(!dir.join("node_8.reality.key").exists());
        fs::write(dir.join("node_7.reality.key"), "corrupt").unwrap();
        assert!(cfg.prepare_node_info(&dir, &mut original.clone()).is_err());
        assert_eq!(
            fs::read_to_string(dir.join("node_7.reality.key")).unwrap(),
            "corrupt"
        );
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn ech_keys_are_stable_and_pem_panel_keys_reach_tls() {
        let dir = std::env::temp_dir().join(format!("elise-ech-config-{}", uuid::Uuid::new_v4()));
        let cfg = NodeConfig {
            node_id: 9,
            ..Default::default()
        };
        let original = NodeInfo {
            node_type: "trojan".into(),
            tls_settings: Some(
                serde_json::json!({"server_name":"outer.example.com","ech":{"enabled":true}}),
            ),
            ..Default::default()
        };
        let mut first = original.clone();
        cfg.prepare_node_info(&dir, &mut first).unwrap();
        let mut restarted = original.clone();
        cfg.prepare_node_info(&dir, &mut restarted).unwrap();
        assert_eq!(first.tls_settings, restarted.tls_settings);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.join("node_9.ech.key"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        let panel = crate::security::EchKeyPair::generate("outer.example.com", 23);
        let mut from_panel = original.clone();
        let ech = &mut from_panel.tls_settings.as_mut().unwrap()["ech"];
        ech["key"] = serde_json::json!(panel.to_pem_ech_keys());
        ech["config"] = serde_json::json!(panel.to_pem_ech_configs());
        cfg.prepare_node_info(&dir, &mut from_panel).unwrap();
        let settings =
            crate::transport::types::StreamSettings::from_node_info(&from_panel).unwrap();
        let crate::transport::types::TransportSecurityConfig::Tls(tls) = settings.security else {
            panic!("expected TLS")
        };
        let parsed = crate::security::EchKeyPair::from_pem_or_bytes(
            tls.ech.unwrap().server_keys.as_ref().unwrap(),
            "outer.example.com",
        )
        .unwrap();
        assert_eq!(parsed, panel);
        cfg.save_node_conf(&dir, &from_panel).unwrap();
        let saved = fs::read_to_string(dir.join("node_9.conf")).unwrap();
        assert!(!saved.contains("ECH KEYS"));
        assert!(!saved.contains("server_keys"));
        assert!(saved.contains("config"));
        from_panel.tls_settings.as_mut().unwrap()["ech"]["config"] = serde_json::json!("AAAA");
        assert!(cfg.prepare_node_info(&dir, &mut from_panel).is_err());
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn all_protocol_auto_settings_preserve_user_and_do_not_include_server_secrets() {
        let dir = std::env::temp_dir().join(format!("elise-auto-config-{}", uuid::Uuid::new_v4()));
        let mut cfg = NodeConfig {
            node_id: 10,
            ..Default::default()
        };
        cfg.parse_content("[USER]\n# existing settings\nlisten_addr = 127.0.0.1");
        for kind in [
            "shadowsocks",
            "vmess",
            "vless",
            "trojan",
            "hysteria",
            "hysteria2",
            "tuic",
            "anytls",
            "naive",
            "http",
            "socks",
            "shadowsocksr",
            "mieru",
        ] {
            let mut info = NodeInfo {
                node_type: kind.into(),
                server_port: 12345,
                network: Some("tcp".into()),
                server_name: Some("node.example.com".into()),
                server_key: Some("server-secret".into()),
                ..Default::default()
            };
            cfg.prepare_node_info(&dir, &mut info).unwrap();
            cfg.save_node_conf(&dir, &info).unwrap();
            let saved = fs::read_to_string(dir.join("node_10.conf")).unwrap();
            assert!(saved.contains(&format!("server_type = {kind}")));
            assert!(saved.contains("network = \"tcp\""));
            assert!(!saved.contains("server-secret"));
            let loaded = NodeConfig::load_for_node(&dir, 10);
            assert_eq!(loaded.listen_addr.as_deref(), Some("127.0.0.1"));
            assert!(!loaded.custom_settings.contains_key("network"));
        }
        fs::remove_dir_all(dir).unwrap();
    }

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

    #[test]
    fn test_acme_config_inheritance_and_dynamic_cert_injection_to_node_info() {
        use crate::config::global::GlobalConfig;
        use std::path::PathBuf;

        // 1. Global config with custom ACME paths (e.g. /etc/eslise/my_cert.crt)
        let global_cfg = GlobalConfig {
            cert_domain: Some("ft.nksea.com".to_string()),
            cert_mode: Some("http".to_string()),
            cert_key_length: Some("ec-256".to_string()),
            acme_server: Some("letsencrypt".to_string()),
            cert_file: Some(PathBuf::from("/etc/eslise/my_cert.crt")),
            key_file: Some(PathBuf::from("/etc/eslise/my_cert.key")),
            ..Default::default()
        };

        // 2. Node config inherits from global
        let mut node_cfg = NodeConfig {
            node_id: 32,
            ..Default::default()
        };
        node_cfg.inherit_from_global(&global_cfg);

        assert_eq!(node_cfg.cert_domain.as_deref(), Some("ft.nksea.com"));
        assert_eq!(node_cfg.cert_mode.as_deref(), Some("http"));
        assert_eq!(
            node_cfg.cert_file,
            Some(PathBuf::from("/etc/eslise/my_cert.crt"))
        );
        assert_eq!(
            node_cfg.key_file,
            Some(PathBuf::from("/etc/eslise/my_cert.key"))
        );

        // 3. Simulated raw NodeInfo from panel (Xboard)
        // Panel does NOT provide cert_file or key_file, only tls = 1, server_name = "ft.nksea.com"
        let mut node_info = NodeInfo {
            id: 32,
            node_type: "anytls".to_string(),
            server_port: 8000,
            server_name: Some("ft.nksea.com".to_string()),
            tls: Some(1),
            tls_settings: Some(serde_json::json!({
                "allow_insecure": true,
                "server_name": "ft.nksea.com"
            })),
            ..Default::default()
        };

        // 4. prepare_node_info dynamically injects user's configured cert and key paths into cert_config
        node_cfg
            .prepare_node_info(Path::new("./nodes"), &mut node_info)
            .unwrap();

        let cert_config = node_info
            .cert_config
            .as_ref()
            .expect("cert_config should be present");
        // Paths are automatically normalized to /etc/elise even if configured with typo /etc/eslise
        assert_eq!(
            cert_config.get("cert_file").and_then(|v| v.as_str()),
            Some("/etc/elise/my_cert.crt")
        );
        assert_eq!(
            cert_config.get("key_file").and_then(|v| v.as_str()),
            Some("/etc/elise/my_cert.key")
        );
        assert_eq!(node_info.server_name.as_deref(), Some("ft.nksea.com"));
    }
}
