use crate::geo::GeoEngine;
use ipnet::IpNet;
use parking_lot::RwLock;
use regex::Regex;
use std::fs;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

pub enum RuleItem {
    Keyword(String),
    Regex(Regex),
    Cidr(IpNet),
    Ip(IpAddr),
    PortRange(u16, u16),
    DomainSuffix(String),
    FullDomain(String),
    GeoSite(String),
    GeoIp(String),
    NodeId(Vec<u32>),
    Network(String),
    All,
}

#[derive(Clone)]
pub struct RuleMatcher {
    items: Arc<RwLock<Vec<RuleItem>>>,
    geo_engine: Arc<GeoEngine>,
}

impl Default for RuleMatcher {
    fn default() -> Self {
        Self {
            items: Arc::new(RwLock::new(Vec::new())),
            geo_engine: Arc::new(GeoEngine::default()),
        }
    }
}

impl RuleMatcher {
    pub fn new(geo_engine: Arc<GeoEngine>) -> Self {
        Self {
            items: Arc::new(RwLock::new(Vec::new())),
            geo_engine,
        }
    }

    pub fn load_from_file<P: AsRef<Path>>(path: P, geo_engine: Arc<GeoEngine>) -> Self {
        let matcher = Self::new(geo_engine);
        if let Ok(content) = fs::read_to_string(path) {
            matcher.reload(&content);
        }
        matcher
    }

    pub fn reload(&self, content: &str) {
        let mut list = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            if line == "*" {
                list.push(RuleItem::All);
            } else if let Some(geosite) = line.strip_prefix("geosite:") {
                let tag = geosite.trim().to_lowercase();
                self.geo_engine.preload_site_group(&tag);
                list.push(RuleItem::GeoSite(tag));
            } else if let Some(geoip) = line.strip_prefix("geoip:") {
                let code = geoip.trim().to_uppercase();
                self.geo_engine.preload_country(&code);
                list.push(RuleItem::GeoIp(code));
            } else if let Some(domain) = line.strip_prefix("domain:") {
                list.push(RuleItem::DomainSuffix(domain.trim().to_lowercase()));
            } else if let Some(domain) = line
                .strip_prefix("domain_suffix:")
                .or_else(|| line.strip_prefix("domain-suffix:"))
            {
                list.push(RuleItem::DomainSuffix(domain.trim().to_lowercase()));
            } else if let Some(full) = line.strip_prefix("full:") {
                list.push(RuleItem::FullDomain(full.trim().to_lowercase()));
            } else if let Some(kw) = line
                .strip_prefix("keyword:")
                .or_else(|| line.strip_prefix("domain_keyword:"))
                .or_else(|| line.strip_prefix("domain-keyword:"))
            {
                list.push(RuleItem::Keyword(kw.trim().to_lowercase()));
            } else if let Some(re_str) = line
                .strip_prefix("regexp:")
                .or_else(|| line.strip_prefix("domain_regex:"))
            {
                if let Ok(re) = Regex::new(re_str.trim()) {
                    list.push(RuleItem::Regex(re));
                }
            } else if let Some(cidr_str) = line
                .strip_prefix("cidr:")
                .or_else(|| line.strip_prefix("ip_cidr:"))
            {
                if let Ok(net) = cidr_str.trim().parse::<IpNet>() {
                    list.push(RuleItem::Cidr(net));
                }
            } else if let Some(ip_str) = line.strip_prefix("ip:") {
                let s = ip_str.trim();
                if let Ok(net) = s.parse::<IpNet>() {
                    list.push(RuleItem::Cidr(net));
                } else if let Ok(ip) = s.parse::<IpAddr>() {
                    list.push(RuleItem::Ip(ip));
                }
            } else if let Some(port_str) = line.strip_prefix("port:") {
                for part in port_str.split(',') {
                    let p = part.trim();
                    if let Some((start, end)) = p.split_once('-') {
                        if let (Ok(s), Ok(e)) =
                            (start.trim().parse::<u16>(), end.trim().parse::<u16>())
                        {
                            list.push(RuleItem::PortRange(s, e));
                        }
                    } else if let Ok(port) = p.parse::<u16>() {
                        list.push(RuleItem::PortRange(port, port));
                    }
                }
            } else if let Some(node_str) = line.strip_prefix("node_id:") {
                let ids: Vec<u32> = node_str
                    .split(',')
                    .filter_map(|s| s.trim().parse::<u32>().ok())
                    .collect();
                if !ids.is_empty() {
                    list.push(RuleItem::NodeId(ids));
                }
            } else if let Some(net_str) = line.strip_prefix("network:") {
                list.push(RuleItem::Network(net_str.trim().to_lowercase()));
            } else {
                // Heuristic parsing for plain items
                if let Ok(net) = line.parse::<IpNet>() {
                    list.push(RuleItem::Cidr(net));
                } else if let Ok(ip) = line.parse::<IpAddr>() {
                    list.push(RuleItem::Ip(ip));
                } else if line.contains('*') {
                    let escaped = regex::escape(line).replace(r"\*", ".*");
                    if let Ok(re) = Regex::new(&format!("^{}$", escaped)) {
                        list.push(RuleItem::Regex(re));
                    }
                } else {
                    // Plain substring fallback rule
                    list.push(RuleItem::Keyword(line.to_lowercase()));
                }
            }
        }
        *self.items.write() = list;
    }

    pub fn matches(&self, domain: &str, ip: Option<IpAddr>, port: u16) -> bool {
        self.matches_full(domain, ip, port, None, None)
    }

    pub fn matches_full(
        &self,
        domain: &str,
        ip: Option<IpAddr>,
        port: u16,
        node_id: Option<u32>,
        network: Option<&str>,
    ) -> bool {
        let lower_domain = domain.to_lowercase();
        let items = self.items.read();

        for item in items.iter() {
            match item {
                RuleItem::All => return true,
                RuleItem::Keyword(kw) => {
                    if !lower_domain.is_empty() && lower_domain.contains(kw) {
                        return true;
                    }
                }
                RuleItem::Regex(re) => {
                    if !lower_domain.is_empty() && re.is_match(&lower_domain) {
                        return true;
                    }
                }
                RuleItem::DomainSuffix(suffix) => {
                    if !lower_domain.is_empty()
                        && (lower_domain == *suffix
                            || lower_domain.ends_with(&format!(".{}", suffix)))
                    {
                        return true;
                    }
                }
                RuleItem::FullDomain(full) => {
                    if !lower_domain.is_empty() && lower_domain == *full {
                        return true;
                    }
                }
                RuleItem::GeoSite(tag) => {
                    if !lower_domain.is_empty() && self.geo_engine.match_geosite(tag, &lower_domain)
                    {
                        return true;
                    }
                }
                RuleItem::GeoIp(country) => {
                    if let Some(target_ip) = ip {
                        if self.geo_engine.match_geoip(country, target_ip) {
                            return true;
                        }
                    }
                }
                RuleItem::Cidr(net) => {
                    if let Some(target_ip) = ip {
                        if net.contains(&target_ip) {
                            return true;
                        }
                    }
                }
                RuleItem::Ip(expected_ip) => {
                    if let Some(target_ip) = ip {
                        if target_ip == *expected_ip {
                            return true;
                        }
                    }
                }
                RuleItem::PortRange(start, end) => {
                    if port >= *start && port <= *end {
                        return true;
                    }
                }
                RuleItem::NodeId(ids) => {
                    if let Some(nid) = node_id {
                        if ids.contains(&nid) {
                            return true;
                        }
                    }
                }
                RuleItem::Network(net) => {
                    if let Some(n) = network {
                        if net == "all" || net.eq_ignore_ascii_case(n) {
                            return true;
                        }
                    }
                }
            }
        }
        false
    }

    pub fn matches_payload(&self, payload: &[u8]) -> bool {
        if payload.is_empty() {
            return false;
        }
        let items = self.items.read();
        for item in items.iter() {
            match item {
                RuleItem::Keyword(kw) => {
                    let kw_bytes = kw.as_bytes();
                    if !kw_bytes.is_empty()
                        && payload
                            .windows(kw_bytes.len())
                            .any(|w| w.eq_ignore_ascii_case(kw_bytes))
                    {
                        return true;
                    }
                }
                RuleItem::Regex(re) => {
                    if let Ok(text) = std::str::from_utf8(payload) {
                        if re.is_match(text) {
                            return true;
                        }
                    }
                }
                _ => {}
            }
        }
        false
    }
}

#[derive(Clone)]
pub struct AuditController {
    block_list: RuleMatcher,
    white_list: RuleMatcher,
    forbidden_ports: Arc<Vec<(u16, u16)>>,
    ban_private_ip: bool,
    forbidden_bit_torrent: bool,
}

impl AuditController {
    pub fn new<P1: AsRef<Path>, P2: AsRef<Path>>(
        block_path: P1,
        white_path: P2,
        geo_engine: Arc<GeoEngine>,
    ) -> Self {
        Self::new_with_options(block_path, white_path, geo_engine, Vec::new(), false, true)
    }

    pub fn new_with_options<P1: AsRef<Path>, P2: AsRef<Path>>(
        block_path: P1,
        white_path: P2,
        geo_engine: Arc<GeoEngine>,
        forbidden_ports: Vec<(u16, u16)>,
        ban_private_ip: bool,
        forbidden_bit_torrent: bool,
    ) -> Self {
        Self {
            block_list: RuleMatcher::load_from_file(block_path, geo_engine.clone()),
            white_list: RuleMatcher::load_from_file(white_path, geo_engine),
            forbidden_ports: Arc::new(forbidden_ports),
            ban_private_ip,
            forbidden_bit_torrent,
        }
    }

    pub fn reload_block_list(&self, content: &str) {
        self.block_list.reload(content);
    }

    pub fn reload_white_list(&self, content: &str) {
        self.white_list.reload(content);
    }

    pub fn is_private_ip(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                v4.is_private()
                    || v4.is_loopback()
                    || v4.is_link_local()
                    || v4.is_broadcast()
                    || v4.is_documentation()
                    || v4.is_unspecified()
            }
            IpAddr::V6(v6) => {
                v6.to_ipv4_mapped()
                    .is_some_and(|v4| Self::is_private_ip(IpAddr::V4(v4)))
                    || v6.is_loopback()
                    || v6.is_unspecified()
                    || (v6.segments()[0] & 0xfe00) == 0xfc00
                    || (v6.segments()[0] & 0xffc0) == 0xfe80
            }
        }
    }

    pub fn should_block(&self, domain: &str, ip: Option<IpAddr>, port: u16) -> bool {
        self.should_block_full(domain, ip, port, None, None)
    }

    pub fn should_block_full(
        &self,
        domain: &str,
        ip: Option<IpAddr>,
        port: u16,
        node_id: Option<u32>,
        network: Option<&str>,
    ) -> bool {
        // Whitelist has absolute priority
        if self
            .white_list
            .matches_full(domain, ip, port, node_id, network)
        {
            return false;
        }

        // Private IP blocking
        if self.ban_private_ip {
            if domain.eq_ignore_ascii_case("localhost") {
                return true;
            }
            if let Some(target_ip) = ip {
                if Self::is_private_ip(target_ip) {
                    return true;
                }
            }
        }

        // Forbidden ports
        for &(start, end) in self.forbidden_ports.iter() {
            if port >= start && port <= end {
                return true;
            }
        }

        // BitTorrent blocking
        if self.forbidden_bit_torrent {
            if (6881..=6889).contains(&port) {
                return true;
            }
            let lower = domain.to_lowercase();
            if lower.contains("torrent") || lower.contains("tracker") || lower.contains("peer_id") {
                return true;
            }
        }

        self.block_list
            .matches_full(domain, ip, port, node_id, network)
    }

    pub fn should_block_payload(&self, payload: &[u8]) -> bool {
        if payload.is_empty() {
            return false;
        }
        // Whitelist has absolute priority
        if self.white_list.matches_payload(payload) {
            return false;
        }
        self.block_list.matches_payload(payload)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_controller_security_rules() {
        let geo_engine = Arc::new(GeoEngine::default());
        let controller = AuditController::new_with_options(
            Path::new(""),
            Path::new(""),
            geo_engine,
            vec![(25, 25), (465, 465)],
            true, // ban_private_ip
            true, // forbidden_bit_torrent
        );

        for address in [
            "127.2.3.4",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.1.1",
            "::1",
            "fe80::1",
            "fd00::1",
            "::ffff:127.0.0.1",
            "::ffff:10.1.2.3",
        ] {
            assert!(
                controller.should_block("private.test", Some(address.parse().unwrap()), 80),
                "{address}"
            );
        }

        // Test private IP
        let lan_ip = "192.168.1.1".parse::<IpAddr>().unwrap();
        assert!(controller.should_block("internal.local", Some(lan_ip), 80));

        let loopback = "127.0.0.1".parse::<IpAddr>().unwrap();
        assert!(controller.should_block("localhost", Some(loopback), 80));

        // Test public IP on regular port - should not block
        let pub_ip = "1.1.1.1".parse::<IpAddr>().unwrap();
        assert!(!controller.should_block("one.one.one.one", Some(pub_ip), 443));

        // Test forbidden port 25
        assert!(controller.should_block("smtp.google.com", Some(pub_ip), 25));

        // Test BitTorrent port 6882
        assert!(controller.should_block("example.com", Some(pub_ip), 6882));

        // Test BitTorrent tracker domain
        assert!(controller.should_block("tracker.torrent.org", Some(pub_ip), 8080));
    }

    #[test]
    fn test_audit_payload_detection_and_whitelist_priority() {
        let geo_engine = Arc::new(GeoEngine::default());
        let controller = AuditController::new_with_options(
            Path::new(""),
            Path::new(""),
            geo_engine,
            vec![],
            false,
            false,
        );

        controller.reload_block_list("keyword:evil\nregexp:^GET /bad.*");
        controller.reload_white_list("keyword:evil_exempt");

        // Normal payload
        assert!(!controller.should_block_payload(b"GET /good HTTP/1.1\r\n"));

        // Blacklist keyword match
        assert!(controller.should_block_payload(b"POST /api HTTP/1.1\r\nHost: evil.com\r\n"));

        // Blacklist regex match
        assert!(controller.should_block_payload(b"GET /bad_path HTTP/1.1\r\n"));

        // Whitelist exempt priority: evil_exempt contains "evil", but matches whitelist
        assert!(
            !controller.should_block_payload(b"POST /api HTTP/1.1\r\nHost: evil_exempt.com\r\n")
        );
    }
}
