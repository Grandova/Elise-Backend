use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

fn default_outbound_tag() -> String {
    "direct".to_string()
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OutboundConfig {
    #[serde(default)]
    pub tag: String,
    #[serde(rename = "type")]
    pub outbound_type: String,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub uuid: Option<String>,
    #[serde(default)]
    pub alter_id: Option<u16>,
    #[serde(default)]
    pub cipher: Option<String>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub flow: Option<String>,
    #[serde(default)]
    pub security: Option<String>,
    #[serde(default)]
    pub tls: Option<bool>,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub ws_path: Option<String>,
    #[serde(default)]
    pub h2_path: Option<String>,
    #[serde(default)]
    pub h2_host: Option<String>,
    #[serde(default)]
    pub grpc_service_name: Option<String>,
    #[serde(default)]
    pub reality_public_key: Option<String>,
    #[serde(default)]
    pub reality_short_id: Option<String>,
    #[serde(default)]
    pub listen: Option<String>,
}

impl OutboundConfig {
    pub fn normalized_type(&self) -> String {
        let t = self.outbound_type.trim().to_lowercase();
        match t.as_str() {
            "freedom" => "direct".to_string(),
            "reject" => "block".to_string(),
            "socks5" => "socks".to_string(),
            "shadowsocks" => "ss".to_string(),
            _ => t,
        }
    }

    pub fn target_host(&self) -> Option<&str> {
        self.server.as_deref().or(self.address.as_deref())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TomlRouteEntry {
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default, rename = "Outs", alias = "outs")]
    pub outs: Vec<OutboundConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TomlRoutesFile {
    #[serde(default = "default_true")]
    pub enable: bool,
    #[serde(default)]
    pub routes: Vec<TomlRouteEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuleConfig {
    #[serde(default)]
    pub node_id: Vec<u32>,
    #[serde(default)]
    pub network: Option<String>,
    #[serde(default)]
    pub domain: Vec<String>,
    #[serde(default)]
    pub domain_suffix: Vec<String>,
    #[serde(default)]
    pub domain_keyword: Vec<String>,
    #[serde(default)]
    pub ip: Vec<String>,
    #[serde(default)]
    pub port: Vec<String>,
    pub outbound: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutesConfig {
    #[serde(default = "default_outbound_tag")]
    pub default_outbound: String,
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    #[serde(default)]
    pub toml_routes: Vec<TomlRouteEntry>,
}

impl Default for RoutesConfig {
    fn default() -> Self {
        Self {
            default_outbound: "direct".to_string(),
            outbounds: vec![
                OutboundConfig {
                    tag: "direct".to_string(),
                    outbound_type: "direct".to_string(),
                    ..Default::default()
                },
                OutboundConfig {
                    tag: "block".to_string(),
                    outbound_type: "block".to_string(),
                    ..Default::default()
                },
            ],
            rules: Vec::new(),
            toml_routes: Vec::new(),
        }
    }
}

impl RoutesConfig {
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Self {
        if let Ok(content) = fs::read_to_string(path) {
            return Self::parse_content(&content);
        }
        Self::default()
    }

    pub fn parse_content(content: &str) -> Self {
        if let Ok(toml_file) = toml::from_str::<TomlRoutesFile>(content) {
            if !toml_file.enable {
                return Self::default();
            }
            if !toml_file.routes.is_empty() {
                let mut outbounds = Vec::new();
                for (r_idx, r) in toml_file.routes.iter().enumerate() {
                    for (o_idx, out) in r.outs.iter().enumerate() {
                        let mut o = out.clone();
                        if o.tag.is_empty() {
                            o.tag = format!("route_{}_out_{}", r_idx, o_idx);
                        }
                        outbounds.push(o);
                    }
                }
                return Self {
                    default_outbound: "direct".to_string(),
                    outbounds,
                    rules: Vec::new(),
                    toml_routes: toml_file.routes,
                };
            }
        }

        if let Ok(cfg) = toml::from_str::<RoutesConfig>(content) {
            return cfg;
        }

        Self::default()
    }

    pub fn import_panel_routes(
        &mut self,
        panel_routes: &[serde_json::Value],
        custom_outbounds: &[serde_json::Value],
    ) {
        let mut new_outbounds = HashMap::new();

        for out_val in custom_outbounds {
            if let Ok(mut ob) = serde_json::from_value::<OutboundConfig>(out_val.clone()) {
                if ob.tag.is_empty() {
                    ob.tag = ob.normalized_type();
                }
                new_outbounds.insert(ob.tag.clone(), ob);
            }
        }

        new_outbounds
            .entry("direct".to_string())
            .or_insert_with(|| OutboundConfig {
                tag: "direct".to_string(),
                outbound_type: "direct".to_string(),
                ..Default::default()
            });
        new_outbounds
            .entry("block".to_string())
            .or_insert_with(|| OutboundConfig {
                tag: "block".to_string(),
                outbound_type: "block".to_string(),
                ..Default::default()
            });

        let mut converted_panel_routes = Vec::new();
        for r_val in panel_routes {
            let matches = r_val.get("match").and_then(|v| v.as_array());
            let action = r_val
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("direct");
            let action_val = r_val.get("action_value").and_then(|v| v.as_str());

            let rules_str: Vec<String> = matches
                .map(|arr| {
                    arr.iter()
                        .filter_map(|m| m.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            if rules_str.is_empty() {
                continue;
            }

            let target_out = match action {
                "block" | "reject" | "block_ip" | "block_port" => "block",
                "direct" | "freedom" => "direct",
                "proxy" | "route" => action_val.unwrap_or("direct"),
                _ => action_val.unwrap_or("direct"),
            };

            let mut outs = Vec::new();
            if let Some(ob) = new_outbounds.get(target_out) {
                outs.push(ob.clone());
            } else {
                outs.push(OutboundConfig {
                    tag: target_out.to_string(),
                    outbound_type: target_out.to_string(),
                    ..Default::default()
                });
            }

            converted_panel_routes.push(TomlRouteEntry {
                rules: rules_str,
                outs,
            });
        }

        converted_panel_routes.append(&mut self.toml_routes);
        self.toml_routes = converted_panel_routes;

        for (_, ob) in new_outbounds {
            if !self.outbounds.iter().any(|o| o.tag == ob.tag) {
                self.outbounds.push(ob);
            }
        }
    }
}
