pub mod outbound;

pub use outbound::OutboundDialer;

use crate::config::routes::{OutboundConfig, RoutesConfig, TomlRouteEntry};
use crate::geo::GeoEngine;
use ipnet::IpNet;
use parking_lot::RwLock;
use rand::seq::SliceRandom;
use regex::Regex;
use std::net::IpAddr;
use std::sync::Arc;

pub struct MatchContext<'a> {
    pub node_id: u32,
    pub network: &'a str,
    pub target_host: &'a str,
    pub target_ip: Option<IpAddr>,
    pub target_port: u16,
    pub inbound_local_ip: Option<IpAddr>,
}

#[derive(Clone)]
pub struct Router {
    config: Arc<RwLock<RoutesConfig>>,
    dialer: Arc<OutboundDialer>,
    geo_engine: Arc<GeoEngine>,
}

impl Router {
    pub fn new(
        config: RoutesConfig,
        dialer: Arc<OutboundDialer>,
        geo_engine: Arc<GeoEngine>,
    ) -> Self {
        Self {
            config: Arc::new(RwLock::new(config)),
            dialer,
            geo_engine,
        }
    }

    pub fn reload(&self, new_config: RoutesConfig) {
        *self.config.write() = new_config;
    }

    pub fn fork(&self) -> Self {
        Self::new(
            self.config.read().clone(),
            self.dialer.clone(),
            self.geo_engine.clone(),
        )
    }

    pub fn match_outbound(&self, ctx: &MatchContext) -> OutboundConfig {
        let cfg = self.config.read();
        let target_lower = ctx.target_host.to_lowercase();

        for route in &cfg.toml_routes {
            if self.match_toml_route(route, ctx, &target_lower) && !route.outs.is_empty() {
                let mut rng = rand::thread_rng();
                if let Some(selected) = route.outs.choose(&mut rng) {
                    return selected.clone();
                }
            }
        }

        for rule in &cfg.rules {
            if !rule.node_id.is_empty() && !rule.node_id.contains(&ctx.node_id) {
                continue;
            }

            if let Some(net) = &rule.network {
                if net != "all" && !net.eq_ignore_ascii_case(ctx.network) {
                    continue;
                }
            }

            if !rule.port.is_empty() {
                let mut port_match = false;
                for p in &rule.port {
                    if let Some((s, e)) = p.split_once('-') {
                        if let (Ok(start), Ok(end)) =
                            (s.trim().parse::<u16>(), e.trim().parse::<u16>())
                        {
                            if ctx.target_port >= start && ctx.target_port <= end {
                                port_match = true;
                                break;
                            }
                        }
                    } else if let Ok(port) = p.parse::<u16>() {
                        if ctx.target_port == port {
                            port_match = true;
                            break;
                        }
                    }
                }
                if !port_match {
                    continue;
                }
            }

            if !rule.domain.is_empty()
                && !rule
                    .domain
                    .iter()
                    .any(|d| d.eq_ignore_ascii_case(&target_lower))
            {
                continue;
            }

            if !rule.domain_suffix.is_empty() {
                let matched = rule.domain_suffix.iter().any(|sfx| {
                    target_lower == sfx.to_lowercase()
                        || target_lower.ends_with(&format!(".{}", sfx.to_lowercase()))
                });
                if !matched {
                    continue;
                }
            }

            if !rule.domain_keyword.is_empty() {
                let matched = rule
                    .domain_keyword
                    .iter()
                    .any(|kw| target_lower.contains(&kw.to_lowercase()));
                if !matched {
                    continue;
                }
            }

            if !rule.ip.is_empty() {
                if let Some(tip) = ctx.target_ip {
                    let matched = rule.ip.iter().any(|cidr_str| {
                        if let Ok(net) = cidr_str.parse::<IpNet>() {
                            net.contains(&tip)
                        } else {
                            false
                        }
                    });
                    if !matched {
                        continue;
                    }
                } else {
                    continue;
                }
            }

            if let Some(ob) = cfg.outbounds.iter().find(|o| o.tag == rule.outbound) {
                return ob.clone();
            }
        }

        cfg.outbounds
            .iter()
            .find(|o| o.tag == cfg.default_outbound)
            .cloned()
            .unwrap_or_else(|| OutboundConfig {
                tag: "direct".to_string(),
                outbound_type: "direct".to_string(),
                ..Default::default()
            })
    }

    fn match_toml_route(
        &self,
        route: &TomlRouteEntry,
        ctx: &MatchContext,
        target_lower: &str,
    ) -> bool {
        let mut node_filters = Vec::new();
        let mut network_filters = Vec::new();
        let mut port_filters = Vec::new();
        let mut dest_rules = Vec::new();

        for rule_str in &route.rules {
            let rule = rule_str.trim();
            if rule.is_empty() || rule.starts_with('#') {
                continue;
            }
            if let Some(node_str) = rule.strip_prefix("node_id:") {
                for part in node_str.split(',') {
                    if let Ok(id) = part.trim().parse::<u32>() {
                        node_filters.push(id);
                    }
                }
            } else if let Some(net_str) = rule.strip_prefix("network:") {
                network_filters.push(net_str.trim().to_lowercase());
            } else if let Some(port_str) = rule
                .strip_prefix("port:")
                .or_else(|| rule.strip_prefix("port_range:"))
            {
                for part in port_str.split(',') {
                    let p = part.trim();
                    if let Some((s, e)) = p.split_once('-') {
                        if let (Ok(start), Ok(end)) =
                            (s.trim().parse::<u16>(), e.trim().parse::<u16>())
                        {
                            port_filters.push((start, end));
                        }
                    } else if let Ok(port) = p.parse::<u16>() {
                        port_filters.push((port, port));
                    }
                }
            } else {
                dest_rules.push(rule);
            }
        }

        if !node_filters.is_empty() && !node_filters.contains(&ctx.node_id) {
            return false;
        }

        if !network_filters.is_empty() {
            let matched_net = network_filters
                .iter()
                .any(|n| n == "all" || n.eq_ignore_ascii_case(ctx.network));
            if !matched_net {
                return false;
            }
        }

        if !port_filters.is_empty() {
            let matched_port = port_filters
                .iter()
                .any(|&(start, end)| ctx.target_port >= start && ctx.target_port <= end);
            if !matched_port {
                return false;
            }
        }

        if dest_rules.is_empty() {
            return true;
        }

        for rule in dest_rules {
            if rule == "*" {
                return true;
            }

            if let Some(geosite) = rule.strip_prefix("geosite:") {
                let tag = geosite.trim().to_lowercase();
                if !target_lower.is_empty() && self.geo_engine.match_geosite(&tag, target_lower) {
                    return true;
                }
            } else if let Some(geoip) = rule.strip_prefix("geoip:") {
                let code = geoip.trim().to_uppercase();
                if let Some(tip) = ctx.target_ip {
                    if self.geo_engine.match_geoip(&code, tip) {
                        return true;
                    }
                }
            } else if let Some(domain) = rule
                .strip_prefix("domain:")
                .or_else(|| rule.strip_prefix("domain_suffix:"))
                .or_else(|| rule.strip_prefix("domain-suffix:"))
            {
                let sfx = domain.trim().to_lowercase();
                if !target_lower.is_empty()
                    && (target_lower == sfx || target_lower.ends_with(&format!(".{}", sfx)))
                {
                    return true;
                }
            } else if let Some(full) = rule.strip_prefix("full:") {
                let f = full.trim().to_lowercase();
                if !target_lower.is_empty() && target_lower == f {
                    return true;
                }
            } else if let Some(kw) = rule
                .strip_prefix("keyword:")
                .or_else(|| rule.strip_prefix("domain_keyword:"))
                .or_else(|| rule.strip_prefix("domain-keyword:"))
            {
                let k = kw.trim().to_lowercase();
                if !target_lower.is_empty() && target_lower.contains(&k) {
                    return true;
                }
            } else if let Some(re_str) = rule
                .strip_prefix("regexp:")
                .or_else(|| rule.strip_prefix("domain_regex:"))
            {
                if let Ok(re) = Regex::new(re_str.trim()) {
                    if !target_lower.is_empty() && re.is_match(target_lower) {
                        return true;
                    }
                }
            } else if let Some(ip_str) = rule
                .strip_prefix("ip:")
                .or_else(|| rule.strip_prefix("cidr:"))
                .or_else(|| rule.strip_prefix("ip_cidr:"))
            {
                if let Some(tip) = ctx.target_ip {
                    let s = ip_str.trim();
                    if let Ok(net) = s.parse::<IpNet>() {
                        if net.contains(&tip) {
                            return true;
                        }
                    } else if let Ok(exact_ip) = s.parse::<IpAddr>() {
                        if tip == exact_ip {
                            return true;
                        }
                    }
                }
            } else {
                if let Ok(net) = rule.parse::<IpNet>() {
                    if let Some(tip) = ctx.target_ip {
                        if net.contains(&tip) {
                            return true;
                        }
                    }
                } else if let Ok(exact_ip) = rule.parse::<IpAddr>() {
                    if let Some(tip) = ctx.target_ip {
                        if tip == exact_ip {
                            return true;
                        }
                    }
                } else if rule.contains('*') {
                    let escaped = regex::escape(rule).replace(r"\*", ".*");
                    if let Ok(re) = Regex::new(&format!("^{}$", escaped)) {
                        if !target_lower.is_empty() && re.is_match(target_lower) {
                            return true;
                        }
                    }
                } else if !target_lower.is_empty()
                    && (target_lower == rule.to_lowercase()
                        || target_lower.ends_with(&format!(".{}", rule.to_lowercase())))
                {
                    return true;
                }
            }
        }
        false
    }

    pub fn dialer(&self) -> Arc<OutboundDialer> {
        self.dialer.clone()
    }
}
