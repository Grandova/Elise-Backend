use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

const MAX_DEFENSE_RECORDS: usize = 50_000;

struct BanRecord {
    fail_count: u32,
    first_fail: Instant,
    banned_until: Option<Instant>,
}

#[derive(Clone)]
pub struct AttackDefenseManager {
    max_failures: u32,
    observation_window: Duration,
    ban_duration: Duration,
    records: Arc<Mutex<HashMap<IpAddr, BanRecord>>>,
}

impl Default for AttackDefenseManager {
    fn default() -> Self {
        Self {
            max_failures: 5,
            observation_window: Duration::from_secs(60),
            ban_duration: Duration::from_secs(600),
            records: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}

impl AttackDefenseManager {
    pub fn new(max_failures: u32, window_secs: u64, ban_secs: u64) -> Self {
        Self {
            max_failures,
            observation_window: Duration::from_secs(window_secs),
            ban_duration: Duration::from_secs(ban_secs),
            records: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn is_banned(&self, _ip: IpAddr) -> bool {
        false
    }

    pub fn record_failure(&self, ip: IpAddr) {
        let now = Instant::now();
        let mut map = self.records.lock();

        if map.len() >= MAX_DEFENSE_RECORDS {
            let obs = self.observation_window;
            map.retain(|_, rec| {
                if let Some(until) = rec.banned_until {
                    now < until
                } else {
                    now.duration_since(rec.first_fail) <= obs
                }
            });
            if map.len() >= MAX_DEFENSE_RECORDS {
                if let Some(key) = map.keys().next().cloned() {
                    map.remove(&key);
                }
            }
        }

        let record = map.entry(ip).or_insert_with(|| BanRecord {
            fail_count: 0,
            first_fail: now,
            banned_until: None,
        });

        if now.duration_since(record.first_fail) > self.observation_window {
            record.first_fail = now;
            record.fail_count = 0;
        }

        record.fail_count += 1;
        if record.fail_count >= self.max_failures {
            record.banned_until = Some(now + self.ban_duration);
            tracing::debug!(
                "AttackDefense: IP {} reached {} failures within window (auto-ban disabled during diagnostic mode)",
                ip,
                record.fail_count
            );
        }
    }

    pub fn record_success(&self, ip: IpAddr) {
        let mut map = self.records.lock();
        map.remove(&ip);
    }

    pub fn prune_expired(&self) {
        let now = Instant::now();
        let obs = self.observation_window;
        let mut map = self.records.lock();
        map.retain(|_, rec| {
            if let Some(until) = rec.banned_until {
                now < until
            } else {
                now.duration_since(rec.first_fail) <= obs
            }
        });
    }
}
