use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub enum DomainMatcher {
    Any,
    Full(String),
    Domain(String),
    Substring(String),
    Regexp(Regex),
    Geosite(String),
}

impl DomainMatcher {
    pub fn parse(raw: &str) -> Self {
        let raw = raw.trim();
        if raw == "*" {
            return DomainMatcher::Any;
        }
        if let Some(rest) = raw.strip_prefix("full:") {
            return DomainMatcher::Full(rest.to_lowercase());
        }
        if let Some(rest) = raw.strip_prefix("*.") {
            return DomainMatcher::Domain(rest.to_lowercase());
        }
        if let Some(rest) = raw.strip_prefix("domain:") {
            return DomainMatcher::Domain(rest.to_lowercase());
        }
        if let Some(rest) = raw.strip_prefix("regexp:") {
            if let Ok(re) = Regex::new(rest) {
                return DomainMatcher::Regexp(re);
            }
        }
        if let Some(rest) = raw.strip_prefix("geosite:") {
            return DomainMatcher::Geosite(rest.to_lowercase());
        }

        // Default: substring match (or domain suffix match)
        DomainMatcher::Substring(raw.to_lowercase())
    }

    pub fn matches(&self, domain: &str) -> bool {
        let d = domain.to_lowercase();
        match self {
            DomainMatcher::Any => true,
            DomainMatcher::Full(expected) => &d == expected,
            DomainMatcher::Domain(base) => {
                if &d == base {
                    return true;
                }
                d.ends_with(&format!(".{base}"))
            }
            DomainMatcher::Substring(sub) => d.contains(sub),
            DomainMatcher::Regexp(re) => re.is_match(&d),
            DomainMatcher::Geosite(cat) => {
                // Built-in common geosite category mappings
                match cat.as_str() {
                    "cn" => {
                        d.ends_with(".cn")
                            || d.contains("baidu.")
                            || d.contains("qq.")
                            || d.contains("taobao.")
                            || d.contains("alipay.")
                            || d.contains("jd.com")
                            || d.contains("bilibili.")
                            || d.contains("163.com")
                    }
                    "google" => {
                        d.contains("google") || d.contains("youtube") || d.contains("gstatic")
                    }
                    "netflix" => d.contains("netflix") || d.contains("nflxvideo"),
                    "openai" => d.contains("openai") || d.contains("chatgpt"),
                    "telegram" => d.contains("telegram") || d.contains("t.me"),
                    "geolocation-!cn" => {
                        !d.ends_with(".cn")
                            && !d.contains("baidu.")
                            && !d.contains("qq.")
                            && !d.contains("taobao.")
                    }
                    _ => false,
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct CompiledDnsRule {
    pub matchers: Vec<DomainMatcher>,
    pub servers: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct DnsRulesTable {
    pub strategy: Option<String>,
    pub cache_time: Option<u64>,
    pub cache_ttl: Option<u64>,
    pub default_servers: Vec<String>,
    pub rules: Vec<CompiledDnsRule>,
}

// ---------------------------------------------------------------------------
// Serde helper models for full syntax and shorthand syntax
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Serialize)]
struct FullYamlRuleItem {
    #[serde(default)]
    domains: Vec<String>,
    #[serde(default)]
    servers: Vec<String>,
    server: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
enum FullYamlServer {
    Address(String),
    Named { tag: String, address: String },
}

#[derive(Debug, Deserialize, Serialize)]
struct FullYamlConfig {
    strategy: Option<String>,
    cache_time: Option<u64>,
    cache_ttl: Option<u64>,
    #[serde(default)]
    servers: Vec<FullYamlServer>,
    #[serde(default)]
    rules: Vec<FullYamlRuleItem>,
}

impl DnsRulesTable {
    /// Parse YAML content supporting both full syntax and shorthand syntax.
    ///
    /// Syntax 1 (Full):
    /// ```yaml
    /// strategy: ipv4_first
    /// cache_time: 10
    /// servers:
    ///   - 8.8.8.8
    /// rules:
    ///   - domains:
    ///       - example.com
    ///       - domain:google.com
    ///     servers:
    ///       - 223.5.5.5
    /// ```
    ///
    /// Syntax 2 (Shorthand):
    /// ```yaml
    /// 223.5.5.5:
    ///   - example.com
    ///   - domain:google.com
    /// https://dns.google/dns-query:
    ///   - geosite:geolocation-!cn
    /// ```
    pub fn parse_yaml(content: &str) -> Result<Self, String> {
        let content = content.trim();
        if content.is_empty() {
            return Ok(Self::default());
        }

        // Try parsing full syntax first
        if let Ok(full) = serde_yaml::from_str::<FullYamlConfig>(content) {
            if full.strategy.is_some()
                || full.cache_time.is_some()
                || full.cache_ttl.is_some()
                || !full.servers.is_empty()
                || !full.rules.is_empty()
            {
                let mut named = HashMap::new();
                let mut default_servers = Vec::new();
                for server in full.servers {
                    match server {
                        FullYamlServer::Address(address) => default_servers.push(address),
                        FullYamlServer::Named { tag, address } => {
                            if tag.trim().is_empty() || address.trim().is_empty() {
                                return Err("DNS server tag and address must not be empty".into());
                            }
                            if named.insert(tag.clone(), address).is_some() {
                                return Err(format!("Duplicate DNS server tag: {tag}"));
                            }
                        }
                    }
                }
                let mut rules = Vec::new();
                for r in full.rules {
                    let matchers = r.domains.iter().map(|d| DomainMatcher::parse(d)).collect();
                    let mut servers = r.servers;
                    if let Some(tag) = r.server {
                        servers.push(
                            named
                                .get(&tag)
                                .cloned()
                                .ok_or_else(|| format!("Unknown DNS server tag: {tag}"))?,
                        );
                    }
                    rules.push(CompiledDnsRule { matchers, servers });
                }

                return Ok(DnsRulesTable {
                    strategy: full.strategy,
                    cache_time: full.cache_time,
                    cache_ttl: full.cache_ttl,
                    default_servers,
                    rules,
                });
            }
        }

        // Fallback: try parsing shorthand syntax (Map of server -> domains)
        if let Ok(shorthand) = serde_yaml::from_str::<HashMap<String, Vec<String>>>(content) {
            let mut rules = Vec::new();
            for (server, domains) in shorthand {
                let matchers = domains.iter().map(|d| DomainMatcher::parse(d)).collect();
                rules.push(CompiledDnsRule {
                    matchers,
                    servers: vec![server],
                });
            }
            return Ok(DnsRulesTable {
                strategy: None,
                cache_time: None,
                cache_ttl: None,
                default_servers: Vec::new(),
                rules,
            });
        }

        Err(
            "Failed to parse DNS rules YAML: format did not match full or shorthand schema"
                .to_string(),
        )
    }

    /// Match a domain against rules in order.
    /// Returns the servers slice of the first matching rule, or None.
    pub fn match_servers(&self, domain: &str) -> Option<&[String]> {
        for rule in &self.rules {
            for matcher in &rule.matchers {
                if matcher.matches(domain) {
                    return Some(&rule.servers);
                }
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_matcher_rules() {
        let m_sub = DomainMatcher::parse("example.com");
        assert!(m_sub.matches("example.com"));
        assert!(m_sub.matches("sub.example.com"));
        assert!(m_sub.matches("myexample.community"));

        let m_dom = DomainMatcher::parse("domain:google.com");
        assert!(m_dom.matches("google.com"));
        assert!(m_dom.matches("www.google.com"));
        assert!(m_dom.matches("mail.corp.google.com"));
        assert!(!m_dom.matches("fakegoogle.com"));

        let m_full = DomainMatcher::parse("full:www.facebook.com");
        assert!(m_full.matches("www.facebook.com"));
        assert!(!m_full.matches("m.facebook.com"));

        let m_regex = DomainMatcher::parse(r"regexp:.*\.twitter\.com");
        assert!(m_regex.matches("api.twitter.com"));
        assert!(!m_regex.matches("twitter.com"));

        let m_all = DomainMatcher::parse("*");
        assert!(m_all.matches("anything.xyz"));

        let m_geo = DomainMatcher::parse("geosite:cn");
        assert!(m_geo.matches("test.baidu.com"));
        assert!(m_geo.matches("gov.cn"));
        assert!(!m_geo.matches("google.com"));
    }

    #[test]
    fn shipped_dns_config_resolves_tags_and_wildcards() {
        let table = DnsRulesTable::parse_yaml(include_str!("../../example/dns.yml")).unwrap();
        assert_eq!(table.cache_ttl, Some(300));
        assert!(table.default_servers.is_empty());
        for (domain, server) in [
            ("www.github.com", "https://1.1.1.1/dns-query"),
            ("openai.com", "https://1.1.1.1/dns-query"),
            ("chatgpt.com", "https://dns.google/dns-query"),
            ("www.baidu.com", "udp://223.5.5.5:53"),
            ("notgithub.com", "https://dns.google/dns-query"),
        ] {
            assert_eq!(table.match_servers(domain), Some(&[server.to_owned()][..]));
        }
    }

    #[test]
    fn invalid_dns_server_references_are_rejected() {
        for (yaml, expected) in [
            ("{servers: [{tag: resolver, address: '1.1.1.1'}], rules: [{domains: ['*'], server: missing}]}", "Unknown DNS server tag: missing"),
            ("servers: [{tag: resolver, address: '1.1.1.1'}, {tag: resolver, address: '8.8.8.8'}]", "Duplicate DNS server tag: resolver"),
            ("servers: [{tag: resolver, address: ''}]", "DNS server tag and address must not be empty"),
        ] {
            assert_eq!(DnsRulesTable::parse_yaml(yaml).unwrap_err(), expected);
        }
    }

    #[test]
    fn test_parse_full_yaml() {
        let yaml = r#"
strategy: ipv4_first
cache_time: 15
servers:
  - 8.8.8.8
  - 1.1.1.1
rules:
  - domains:
      - domain:google.com
      - full:www.facebook.com
    servers:
      - 223.5.5.5
      - 119.29.29.29
  - domains:
      - "*"
    servers:
      - 1.0.0.1
"#;
        let table = DnsRulesTable::parse_yaml(yaml).unwrap();
        assert_eq!(table.strategy.as_deref(), Some("ipv4_first"));
        assert_eq!(table.cache_time, Some(15));
        assert_eq!(table.default_servers, vec!["8.8.8.8", "1.1.1.1"]);
        assert_eq!(table.rules.len(), 2);

        assert_eq!(
            table.match_servers("www.google.com"),
            Some(&["223.5.5.5".to_string(), "119.29.29.29".to_string()][..])
        );
        assert_eq!(
            table.match_servers("other.domain"),
            Some(&["1.0.0.1".to_string()][..])
        );
    }

    #[test]
    fn test_parse_shorthand_yaml() {
        let yaml = r#"
"223.5.5.5":
  - domain:qq.com
  - geosite:cn
"https://dns.google/dns-query":
  - domain:youtube.com
"#;
        let table = DnsRulesTable::parse_yaml(yaml).unwrap();
        assert_eq!(table.rules.len(), 2);
        assert!(table.match_servers("mail.qq.com").is_some());
        assert_eq!(
            table.match_servers("music.youtube.com"),
            Some(&["https://dns.google/dns-query".to_string()][..])
        );
    }
}
