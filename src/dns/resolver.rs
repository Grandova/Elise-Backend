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
            if let Some(seconds) = tbl.cache_ttl {
                *self.cache_ttl.write() = Duration::from_secs(seconds.max(1));
            } else if let Some(mins) = tbl.cache_time {
                *self.cache_ttl.write() = Duration::from_secs(mins.max(1) * 60);
            }
            if !tbl.default_servers.is_empty() {
                *self.default_dns.write() = tbl.default_servers.clone();
            }
        }
        *self.rules_table.write() = table;
        self.cache.write().clear();
    }

    pub fn update_config(
        &self,
        strategy: &str,
        cache_time_minutes: u64,
        default_dns: Option<&str>,
    ) {
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

    pub async fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        self.resolve_with_runtime(host, port, None).await
    }

    pub async fn resolve_with_runtime(
        &self,
        host: &str,
        port: u16,
        runtime_dns: Option<&[String]>,
    ) -> io::Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }

        let now = Instant::now();
        let strategy = self.strategy.read().clone();
        let host_lower = host.to_lowercase();

        {
            let cache = self.cache.read();
            if let Some(entry) = cache.get(&host_lower) {
                if now < entry.expires_at {
                    return Ok(Self::apply_strategy(&entry.ips, port, &strategy));
                }
            }
        }

        let resolved_ips = self.resolve_four_levels(host, runtime_dns).await?;

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
                host_lower,
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

        if let Some(servers) = runtime_dns {
            if !servers.is_empty() {
                if let Ok(ips) = self.resolve_with_servers(servers, host, &strategy).await {
                    if !ips.is_empty() {
                        return Ok(ips);
                    }
                }
            }
        }

        let matched_servers = {
            let lock = self.rules_table.read();
            lock.as_ref()
                .and_then(|t| t.match_servers(host).map(|s| s.to_vec()))
        };

        if let Some(servers) = matched_servers {
            if !servers.is_empty() {
                if let Ok(ips) = self.resolve_with_servers(&servers, host, &strategy).await {
                    if !ips.is_empty() {
                        return Ok(ips);
                    }
                }

                tracing::debug!(
                    "DNS rule servers failed for '{host}'. Short-circuiting directly to default/system DNS."
                );
            }
        }

        let default_servers = self.default_dns.read().clone();
        if !default_servers.is_empty() {
            if let Ok(ips) = self
                .resolve_with_servers(&default_servers, host, &strategy)
                .await
            {
                if !ips.is_empty() {
                    return Ok(ips);
                }
            }
        }

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
                v4.extend(v6);
                v4
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn tagged_dns_rules_query_selected_server_and_reload_cache() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for octet in [10, 20] {
                let mut buf = [0u8; 512];
                let (len, peer) = socket.recv_from(&mut buf).await.unwrap();
                assert_eq!(&buf[len - 4..len - 2], &[0, 1]);
                let mut reply = Vec::from(&buf[..len]);
                reply[2..4].copy_from_slice(&[0x81, 0x80]);
                reply[6..8].copy_from_slice(&[0, 1]);
                reply.extend_from_slice(&[
                    0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, octet,
                ]);
                socket.send_to(&reply, peer).await.unwrap();
            }
        });
        let resolver = DNSResolver::default();
        let table = DnsRulesTable::parse_yaml(&format!(
            "strategy: ipv4_only\ncache_ttl: 7\nservers: [{{tag: local, address: 'udp://{addr}'}}]\nrules: [{{domains: ['*.elise.invalid'], server: local}}]"
        )).unwrap();
        resolver.set_rules_table(Some(table.clone()));
        assert_eq!(*resolver.cache_ttl.read(), Duration::from_secs(7));
        for _ in 0..2 {
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                resolver.resolve("test.elise.invalid", 443),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(
                result,
                vec!["192.0.2.10:443".parse::<SocketAddr>().unwrap()]
            );
        }
        resolver.set_rules_table(Some(table));
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            resolver.resolve("test.elise.invalid", 443),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(
            result,
            vec!["192.0.2.20:443".parse::<SocketAddr>().unwrap()]
        );
        tokio::time::timeout(Duration::from_secs(3), server)
            .await
            .unwrap()
            .unwrap();
    }
}
