use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistentEntry {
    ip: String,
    user_id: u32,
    timestamp: u64,
}

#[derive(Clone)]
pub struct IpUserCache {
    ttl: Duration,
    save_enable: bool,
    save_dir: PathBuf,
    cache: Arc<RwLock<HashMap<IpAddr, (u32, Instant)>>>,
}

impl IpUserCache {
    pub fn new<P: AsRef<Path>>(cache_hours: u64, save_enable: bool, save_dir: P) -> Self {
        let ttl_secs = cache_hours.max(1) * 3600;
        Self::new_with_duration(Duration::from_secs(ttl_secs), save_enable, save_dir)
    }

    pub fn new_with_duration<P: AsRef<Path>>(
        ttl: Duration,
        save_enable: bool,
        save_dir: P,
    ) -> Self {
        let s = Self {
            ttl,
            save_enable,
            save_dir: save_dir.as_ref().to_path_buf(),
            cache: Arc::new(RwLock::new(HashMap::new())),
        };

        if save_enable {
            s.load_from_disk();
        }

        s
    }

    pub fn get(&self, ip: &IpAddr) -> Option<u32> {
        let guard = self.cache.read();
        if let Some(&(user_id, instant)) = guard.get(ip) {
            if instant.elapsed() <= self.ttl {
                return Some(user_id);
            }
        }
        None
    }

    pub fn insert(&self, ip: IpAddr, user_id: u32) {
        let mut guard = self.cache.write();
        guard.insert(ip, (user_id, Instant::now()));
    }

    pub fn prune(&self) {
        let mut guard = self.cache.write();
        let ttl = self.ttl;
        guard.retain(|_, &mut (_, instant)| instant.elapsed() <= ttl);
    }

    pub fn save_to_disk(&self) {
        if !self.save_enable {
            return;
        }

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let entries: Vec<PersistentEntry> = {
            let guard = self.cache.read();
            let ttl = self.ttl;
            guard
                .iter()
                .filter(|(_, (_, instant))| instant.elapsed() <= ttl)
                .map(|(ip, (user_id, instant))| {
                    let elapsed = instant.elapsed().as_secs();
                    let ts = now_unix.saturating_sub(elapsed);
                    PersistentEntry {
                        ip: ip.to_string(),
                        user_id: *user_id,
                        timestamp: ts,
                    }
                })
                .collect()
        };

        let file_path = self.save_dir.join("ip_user_cache.json");
        if let Ok(json_str) = serde_json::to_string_pretty(&entries) {
            let _ = fs::create_dir_all(&self.save_dir);
            if let Err(e) = fs::write(&file_path, json_str) {
                warn!("Failed to persist IP user cache to {:?}: {}", file_path, e);
            } else {
                debug!(
                    "Persisted {} IP user cache entries to {:?}",
                    entries.len(),
                    file_path
                );
            }
        }
    }

    pub fn load_from_disk(&self) {
        let file_path = self.save_dir.join("ip_user_cache.json");
        if !file_path.exists() {
            return;
        }

        let Ok(data) = fs::read_to_string(&file_path) else {
            return;
        };

        let Ok(entries) = serde_json::from_str::<Vec<PersistentEntry>>(&data) else {
            return;
        };

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut loaded = 0;
        let mut guard = self.cache.write();
        for entry in entries {
            if let Ok(ip) = entry.ip.parse::<IpAddr>() {
                let age = now_unix.saturating_sub(entry.timestamp);
                if Duration::from_secs(age) <= self.ttl {
                    let instant = Instant::now()
                        .checked_sub(Duration::from_secs(age))
                        .unwrap_or_else(Instant::now);
                    guard.insert(ip, (entry.user_id, instant));
                    loaded += 1;
                }
            }
        }

        info!(
            "Loaded {} valid IP user cache entries from {:?}",
            loaded, file_path
        );
    }
}
