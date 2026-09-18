use super::client::{parse_dns_endpoint, DnsClient};
use super::rules::DnsRulesTable;
use super::wire::{TYPE_A, TYPE_AAAA};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::lookup_host;

const MAX_DNS_CACHE_ENTRIES: usize = 10_000;

#[derive(Debug, Clone)]
struct CachedDnsEntry {
    ips: Vec<IpAddr>,
    expires_at: Instant,
}

#[derive(Clone)]
pub struct DNSResolver {
    strategy: Arc<RwLock<String>>,
    cache_ttl: Arc<RwLock<Duration>>,
    default_dns: Arc<RwLock<Vec<String>>>,
    rules_table: Arc<RwLock<Option<DnsRulesTable>>>,
    client: DnsClient,
    cache: Arc<RwLock<HashMap<String, CachedDnsEntry>>>,
}

impl Default for DNSResolver {
    fn default() -> Self {
        Self::new("ipv4_first", 10, None)
    }
}

impl DNSResolver {
    /// Create a new DNSResolver.
    /// `cache_time_minutes`: DNS cache duration in minutes (default: 10).
    pub fn new(strategy: &str, cache_time_minutes: u64, default_dns_str: Option<&str>) -> Self {
        let ttl_secs = cache_time_minutes.max(1) * 60;
        let default_servers = default_dns_str
            .map(|s| {
                s.split(',')
                    .map(|item| item.trim().to_string())
                    .filter(|item| !item.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        Self {
            strategy: Arc::new(RwLock::new(strategy.to_string())),
            cache_ttl: Arc::new(RwLock::new(Duration::from_secs(ttl_secs))),
            default_dns: Arc::new(RwLock::new(default_servers)),
            rules_table: Arc::new(RwLock::new(None)),
            client: DnsClient::new(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn set_rules_table(&self, table: Option<DnsRulesTable>) {
        if let Some(ref tbl) = table {
            if let Some(ref strat) = tbl.strategy {
                *self.strategy.write() = strat.clone();
            }
            if let Some(mins) = tbl.cache_time {
                *self.cache_ttl.write() = Duration::from_secs(mins.max(1) * 60);
            }
            if !tbl.default_servers.is_empty() {
                *self.default_dns.write() = tbl.default_servers.clone();
            }
        }
        *self.rules_table.write() = table;
    }

    pub fn update_config(&self, strategy: &str, cache_time_minutes: u64, default_dns: Option<&str>) {
        *self.strategy.write() = strategy.to_string();
        *self.cache_ttl.write() = Duration::from_secs(cache_time_minutes.max(1) * 60);
        if let Some(d) = default_dns {
            let servers: Vec<String> = d
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            *self.default_dns.write() = servers;
        }
    }

    /// Resolve a hostname to SocketAddr list using four-level resolution:
    /// Level 1: Runtime panel DNS (if any)
    /// Level 2: `dns.yml` rules (short-circuit: if matched rule servers fail, skip to Level 3)
    /// Level 3: `default_dns`
    /// Level 4: System native lookup_host
    pub async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self.resolve_with_runtime(host, port, None).await
    }

    pub async fn resolve_with_runtime(
        &self,
        host: &str,
        port: u16,
        runtime_dns: Option<&[String]>,
    ) -> io::Result<Vec<SocketAddr>> {
        // Fast path: if host is already an IP address, return immediately
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }

        let now = Instant::now();
        let strategy = self.strategy.read().clone();

        // 1. Check cache with read lock
        {
            let cache = self.cache.read();
            if let Some(entry) = cache.get(host) {
                if now < entry.expires_at {
                    return Ok(Self::apply_strategy(&entry.ips, port, &strategy));
                }
            }
        }

        // 2. Four-level resolution chain
        let resolved_ips = self.resolve_four_levels(host, runtime_dns).await?;

        // 3. Cache the resolved IPs
        if !resolved_ips.is_empty() {
            let cache_ttl = *self.cache_ttl.read();
            let mut cache = self.cache.write();

            if cache.len() >= MAX_DNS_CACHE_ENTRIES {
                cache.retain(|_, v| now < v.expires_at);
                if cache.len() >= MAX_DNS_CACHE_ENTRIES {
                    if let Some(key) = cache.keys().next().cloned() {
                        cache.remove(&key);
                    }
                }
            }

            cache.insert(
                host.to_string(),
                CachedDnsEntry {
                    ips: resolved_ips.clone(),
                    expires_at: now + cache_ttl,
                },
            );
        }

        let addrs = Self::apply_strategy(&resolved_ips, port, &strategy);
        if addrs.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("DNS resolution returned no suitable IP for '{host}' with strategy '{strategy}'"),
            ));
        }

        Ok(addrs)
    }

    async fn resolve_four_levels(
        &self,
        host: &str,
        runtime_dns: Option<&[String]>,
    ) -> io::Result<Vec<IpAddr>> {
        let strategy = self.strategy.read().clone();

        // Level 1: Runtime panel DNS
        if let Some(servers) = runtime_dns {
            if !servers.is_empty() {
                if let Ok(ips) = self.resolve_with_servers(servers, host, &strategy).await {
                    if !ips.is_empty() {
                        return Ok(ips);
                    }
                }
            }
        }

        // Level 2: dns.yml rule matching (with short-circuit behavior)
        let matched_servers = {
            let lock = self.rules_table.read();
            lock.as_ref().and_then(|t| t.match_servers(host).map(|s| s.to_vec()))
        };

        if let Some(servers) = matched_servers {
            if !servers.is_empty() {
                // Rule matched! Attempt to resolve using these servers.
                if let Ok(ips) = self.resolve_with_servers(&servers, host, &strategy).await {
                    if !ips.is_empty() {
                        return Ok(ips);
                    }
                }
                // Short-circuit: All servers in matched rule failed!
                // DO NOT check further rules. Directly fall back to Level 3 / Level 4.
                tracing::debug!(
                    "DNS rule servers failed for '{host}'. Short-circuiting directly to default/system DNS."
                );
            }
        }

        // Level 3: default_dns
        let default_servers = self.default_dns.read().clone();
        if !default_servers.is_empty() {
            if let Ok(ips) = self.resolve_with_servers(&default_servers, host, &strategy).await {
                if !ips.is_empty() {
                    return Ok(ips);
                }
            }
        }

        // Level 4: System native DNS lookup
        let addr_str = format!("{}:80", host);
        let addrs: Vec<SocketAddr> = lookup_host(&addr_str).await?.collect();
        let ips: Vec<IpAddr> = addrs.into_iter().map(|a| a.ip()).collect();
        Ok(ips)
    }

    async fn resolve_with_servers(
        &self,
        servers: &[String],
        domain: &str,
        strategy: &str,
    ) -> io::Result<Vec<IpAddr>> {
        for server_raw in servers {
            let endpoint = match parse_dns_endpoint(server_raw) {
                Ok(ep) => ep,
                Err(e) => {
                    tracing::warn!("Invalid DNS endpoint '{}': {e}", server_raw);
                    continue;
                }
            };

            let mut all_ips = Vec::new();
            match strategy {
                "ipv4_only" => {
                    if let Ok(ips) = self.client.query(&endpoint, domain, TYPE_A).await {
                        all_ips.extend(ips);
                    }
                }
                "ipv6_only" => {
                    if let Ok(ips) = self.client.query(&endpoint, domain, TYPE_AAAA).await {
                        all_ips.extend(ips);
                    }
                }
                _ => {
                    // ipv4_first or ipv6_first: query both A and AAAA
                    let (res_a, res_aaaa) = tokio::join!(
                        self.client.query(&endpoint, domain, TYPE_A),
                        self.client.query(&endpoint, domain, TYPE_AAAA)
                    );
                    if let Ok(ips) = res_a {
                        all_ips.extend(ips);
                    }
                    if let Ok(ips) = res_aaaa {
                        all_ips.extend(ips);
                    }
                }
            }

            if !all_ips.is_empty() {
                return Ok(all_ips);
            }
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            "All specified DNS servers failed to resolve domain",
        ))
    }

    pub fn prune_expired(&self) {
        let now = Instant::now();
        let mut cache = self.cache.write();
        cache.retain(|_, v| now < v.expires_at);
    }

    fn apply_strategy(ips: &[IpAddr], port: u16, strategy: &str) -> Vec<SocketAddr> {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();

        for ip in ips {
            match ip {
                IpAddr::V4(_) => v4.push(SocketAddr::new(*ip, port)),
                IpAddr::V6(_) => v6.push(SocketAddr::new(*ip, port)),
            }
        }

        match strategy {
            "ipv4_only" => v4,
            "ipv6_only" => v6,
            "ipv6_first" | "prefer_ipv6" => {
                v6.extend(v4);
                v6
            }
            _ => {
                // "ipv4_first" or "prefer_ipv4"
                v4.extend(v6);
                v4
            }
        }
    }
}

