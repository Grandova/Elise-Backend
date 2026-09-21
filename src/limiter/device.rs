use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(feature = "distributed")]
use redis::aio::ConnectionManager;

const REDIS_DEVICE_LIMIT_LUA: &str = r#"
local cutoff = tonumber(ARGV[2]) - tonumber(ARGV[3])
redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', cutoff)
local score = redis.call('ZSCORE', KEYS[1], ARGV[1])
if score then
    redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
    redis.call('EXPIRE', KEYS[1], ARGV[3])
    return 1
end
local limit = tonumber(ARGV[4])
if limit and limit > 0 then
    local count = redis.call('ZCARD', KEYS[1])
    if count >= limit then
        return 0
    end
end
redis.call('ZADD', KEYS[1], ARGV[2], ARGV[1])
redis.call('EXPIRE', KEYS[1], ARGV[3])
return 1
"#;

#[derive(Clone)]
pub struct DeviceLimiter {
    window_duration: Duration,
    prefix_v4: u8,
    prefix_v6: u8,
    user_devices: Arc<Mutex<HashMap<u32, HashMap<String, Instant>>>>,
    user_limits: Arc<Mutex<HashMap<u32, u32>>>,
    global_alive: Arc<Mutex<HashMap<u32, u32>>>,
    redis_url: Option<String>,
    conn_limit_expiry: u64,
    redis_timeout: Duration,
    #[cfg(feature = "distributed")]
    redis_manager: Arc<tokio::sync::RwLock<Option<ConnectionManager>>>,
}

impl DeviceLimiter {
    pub fn new(window_secs: u64, prefix_v4: u8, prefix_v6: u8, redis_url: Option<String>) -> Self {
        Self::new_with_redis(
            window_secs,
            prefix_v4,
            prefix_v6,
            redis_url,
            window_secs,
            300,
        )
    }

    pub fn new_with_redis(
        window_secs: u64,
        prefix_v4: u8,
        prefix_v6: u8,
        redis_url: Option<String>,
        conn_limit_expiry: u64,
        redis_timeout_ms: u64,
    ) -> Self {
        Self {
            window_duration: Duration::from_secs(window_secs),
            prefix_v4: prefix_v4.min(32),
            prefix_v6: prefix_v6.min(128),
            user_devices: Arc::new(Mutex::new(HashMap::new())),
            user_limits: Arc::new(Mutex::new(HashMap::new())),
            global_alive: Arc::new(Mutex::new(HashMap::new())),
            redis_url,
            conn_limit_expiry: conn_limit_expiry.max(1),
            redis_timeout: Duration::from_millis(redis_timeout_ms.max(50)),
            #[cfg(feature = "distributed")]
            redis_manager: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    pub fn update_global_alive(&self, map: HashMap<u32, u32>) {
        *self.global_alive.lock() = map;
    }

    pub fn redis_url(&self) -> Option<&str> {
        self.redis_url.as_deref()
    }

    pub fn set_user_limit(&self, user_id: u32, limit: u32) {
        let mut map = self.user_limits.lock();
        if limit > 0 {
            map.insert(user_id, limit);
        } else {
            map.remove(&user_id);
        }
    }

    pub fn get_online_devices(&self, user_id: u32) -> Vec<String> {
        let now = Instant::now();
        let mut map = self.user_devices.lock();
        if let Some(devices) = map.get_mut(&user_id) {
            devices.retain(|_, last_seen| now.duration_since(*last_seen) <= self.window_duration);
            let res: Vec<String> = devices.keys().cloned().collect();
            if devices.is_empty() {
                map.remove(&user_id);
            }
            res
        } else {
            Vec::new()
        }
    }

    pub async fn get_online_devices_async(&self, user_id: u32) -> Vec<String> {
        #[cfg(feature = "distributed")]
        if let Some(url) = &self.redis_url {
            if let Ok(ips) = self.get_redis_online_devices(user_id, url).await {
                return ips;
            }
        }
        self.get_online_devices(user_id)
    }

    #[cfg(feature = "distributed")]
    async fn get_redis_online_devices(
        &self,
        user_id: u32,
        url: &str,
    ) -> redis::RedisResult<Vec<String>> {
        let mgr = {
            let manager_guard = self.redis_manager.read().await;
            manager_guard.clone()
        };

        let mut mgr = match mgr {
            Some(m) => m,
            None => {
                let mut write_guard = self.redis_manager.write().await;
                if write_guard.is_none() {
                    let client = redis::Client::open(url)?;
                    let m = client.get_connection_manager().await?;
                    *write_guard = Some(m);
                }
                write_guard.clone().unwrap()
            }
        };

        let key = format!("elise:user_ips:{}", user_id);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let cutoff = now.saturating_sub(self.conn_limit_expiry);

        let ips: Vec<String> = redis::cmd("ZRANGEBYSCORE")
            .arg(key)
            .arg(cutoff)
            .arg("+inf")
            .query_async(&mut mgr)
            .await?;

        Ok(ips)
    }

    pub fn get_all_online_devices(&self) -> HashMap<u32, Vec<String>> {
        let now = Instant::now();
        let mut map = self.user_devices.lock();
        let mut result = HashMap::new();

        map.retain(|&user_id, devices| {
            devices.retain(|_, last_seen| now.duration_since(*last_seen) <= self.window_duration);
            if devices.is_empty() {
                false
            } else {
                result.insert(user_id, devices.keys().cloned().collect());
                true
            }
        });

        result
    }

    pub fn check_and_record(&self, user_id: u32, ip: IpAddr) -> bool {
        let limit = self.user_limits.lock().get(&user_id).copied();
        let device_key = self.normalize_ip(ip);

        let now = Instant::now();
        let mut map = self.user_devices.lock();
        let devices = map.entry(user_id).or_default();

        devices.retain(|_, last_seen| now.duration_since(*last_seen) <= self.window_duration);

        if let Some(max_dev) = limit {
            if !devices.contains_key(&device_key) {
                let remote_devs = self.global_alive.lock().get(&user_id).copied().unwrap_or(0);
                if (devices.len() as u32 + remote_devs) >= max_dev {
                    return false;
                }
            }
        }

        devices.insert(device_key, now);
        true
    }

    pub async fn check_and_record_async(&self, user_id: u32, ip: IpAddr) -> bool {
        #[cfg(feature = "distributed")]
        if let Some(url) = &self.redis_url {
            let res =
                tokio::time::timeout(self.redis_timeout, self.check_redis(user_id, ip, url)).await;
            match res {
                Ok(Ok(allowed)) => {
                    if allowed {
                        self.check_and_record(user_id, ip);
                    }
                    return allowed;
                }
                Ok(Err(e)) => {
                    tracing::warn!(
                        user_id,
                        "Redis device limit check error, falling back to local: {}",
                        e
                    );
                }
                Err(_) => {
                    tracing::warn!(
                        user_id,
                        "Redis device limit check timed out after {}ms, falling back to local",
                        self.redis_timeout.as_millis()
                    );
                }
            }
        }
        self.check_and_record(user_id, ip)
    }

    #[cfg(feature = "distributed")]
    async fn check_redis(&self, user_id: u32, ip: IpAddr, url: &str) -> redis::RedisResult<bool> {
        let mgr = {
            let manager_guard = self.redis_manager.read().await;
            manager_guard.clone()
        };

        let mut mgr = match mgr {
            Some(m) => m,
            None => {
                let mut write_guard = self.redis_manager.write().await;
                if write_guard.is_none() {
                    let client = redis::Client::open(url)?;
                    let m = client.get_connection_manager().await?;
                    *write_guard = Some(m);
                }
                write_guard.clone().unwrap()
            }
        };

        let key = format!("elise:user_ips:{}", user_id);
        let device_key = self.normalize_ip(ip);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let limit = self.user_limits.lock().get(&user_id).copied().unwrap_or(0);

        let script = redis::Script::new(REDIS_DEVICE_LIMIT_LUA);
        let res: redis::RedisResult<i32> = script
            .key(key)
            .arg(device_key)
            .arg(now)
            .arg(self.conn_limit_expiry)
            .arg(limit)
            .invoke_async(&mut mgr)
            .await;

        match res {
            Ok(result) => Ok(result == 1),
            Err(e) => {
                if e.is_io_error() || e.is_connection_dropped() || e.is_connection_refusal() {
                    *self.redis_manager.write().await = None;
                }
                Err(e)
            }
        }
    }

    pub fn prune_expired(&self) {
        let now = Instant::now();
        let mut map = self.user_devices.lock();
        map.retain(|_, devices| {
            devices.retain(|_, last_seen| now.duration_since(*last_seen) <= self.window_duration);
            !devices.is_empty()
        });
    }

    pub fn normalize_ip(&self, ip: IpAddr) -> String {
        match ip.to_canonical() {
            IpAddr::V4(v4) => {
                if self.prefix_v4 >= 32 {
                    v4.to_string()
                } else if self.prefix_v4 == 0 {
                    "0.0.0.0/0".to_string()
                } else {
                    let mask = !((1u64 << (32 - self.prefix_v4)) - 1) as u32;
                    let masked = u32::from(v4) & mask;
                    format!("{}/{}", Ipv4Addr::from(masked), self.prefix_v4)
                }
            }
            IpAddr::V6(v6) => {
                if self.prefix_v6 >= 128 {
                    v6.to_string()
                } else if self.prefix_v6 == 0 {
                    "::/0".to_string()
                } else {
                    let mask = !((1u128 << (128 - self.prefix_v6)) - 1);
                    let masked = u128::from(v6) & mask;
                    format!("{}/{}", Ipv6Addr::from(masked), self.prefix_v6)
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_normalization() {
        let limiter = DeviceLimiter::new(60, 24, 64, None);
        let ip: IpAddr = "192.168.1.123".parse().unwrap();
        assert_eq!(limiter.normalize_ip(ip), "192.168.1.0/24");

        let limiter16 = DeviceLimiter::new(60, 16, 64, None);
        assert_eq!(limiter16.normalize_ip(ip), "192.168.0.0/16");
    }

    #[test]
    fn mapped_ipv4_uses_ipv4_device_identity() {
        let limiter = DeviceLimiter::new(60, 32, 64, None);
        let mapped = "::ffff:192.0.2.17".parse().unwrap();
        assert_eq!(limiter.normalize_ip(mapped), "192.0.2.17");
        assert_eq!(
            DeviceLimiter::new(60, 24, 64, None).normalize_ip(mapped),
            "192.0.2.0/24"
        );
        assert_eq!(
            limiter.normalize_ip("2001:db8:1:2::17".parse().unwrap()),
            "2001:db8:1:2::/64"
        );

        limiter.set_user_limit(12, 1);
        assert!(limiter.check_and_record(12, mapped));
        assert!(limiter.check_and_record(12, "192.0.2.17".parse().unwrap()));
        assert!(!limiter.check_and_record(12, "::ffff:192.0.2.18".parse().unwrap()));
        assert_eq!(limiter.get_online_devices(12), vec!["192.0.2.17"]);
    }

    #[test]
    fn test_device_limiter_pruning() {
        let limiter = DeviceLimiter::new(1, 32, 128, None);
        let ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(limiter.check_and_record(100, ip));
        assert_eq!(limiter.get_online_devices(100).len(), 1);

        std::thread::sleep(Duration::from_millis(1100));
        limiter.prune_expired();
        assert_eq!(limiter.get_online_devices(100).len(), 0);
    }
}
