use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

const NUM_SHARDS: usize = 32;

struct TokenBucket {
    capacity: f64,
    tokens: f64,
    rate_per_sec: f64,
    last_update: Instant,
}

impl TokenBucket {
    fn new(rate_bytes_per_sec: u64) -> Self {
        let rate = rate_bytes_per_sec as f64;
        let capacity = (rate * 2.0).max(65536.0); // Minimum 64KB burst
        Self {
            capacity,
            tokens: capacity,
            rate_per_sec: rate,
            last_update: Instant::now(),
        }
    }

    fn replenish(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.last_update).as_secs_f64();
        self.last_update = now;
        self.tokens = (self.tokens + elapsed * self.rate_per_sec).min(self.capacity);
    }

    fn try_consume(&mut self, amount: usize) -> bool {
        let now = Instant::now();
        self.replenish(now);

        if self.tokens >= amount as f64 {
            self.tokens -= amount as f64;
            true
        } else {
            false
        }
    }
}

pub struct RateLimiter {
    shards: std::sync::Arc<[Mutex<HashMap<u32, TokenBucket>>; NUM_SHARDS]>,
    changed: std::sync::Arc<tokio::sync::Notify>,
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            shards: std::sync::Arc::new(std::array::from_fn(|_| Mutex::new(HashMap::new()))),
            changed: std::sync::Arc::new(tokio::sync::Notify::new()),
        }
    }

    #[inline]
    fn shard_idx(&self, user_id: u32) -> usize {
        (user_id as usize) % NUM_SHARDS
    }

    pub fn set_user_limit(&self, user_id: u32, speed_limit_bps: u64) {
        let idx = self.shard_idx(user_id);
        let mut shard = self.shards[idx].lock();
        if speed_limit_bps > 0 {
            shard
                .entry(user_id)
                .and_modify(|bucket| {
                    bucket.replenish(Instant::now());
                    bucket.rate_per_sec = speed_limit_bps as f64;
                    bucket.capacity = (bucket.rate_per_sec * 2.0).max(65536.0);
                    bucket.tokens = bucket.tokens.min(bucket.capacity);
                })
                .or_insert_with(|| TokenBucket::new(speed_limit_bps));
        } else {
            shard.remove(&user_id);
        }
        drop(shard);
        self.changed.notify_waiters();
    }

    pub fn is_limited(&self, user_id: u32) -> bool {
        let idx = self.shard_idx(user_id);
        self.shards[idx].lock().contains_key(&user_id)
    }

    pub fn allow(&self, user_id: u32, bytes: usize) -> bool {
        let idx = self.shard_idx(user_id);
        let mut shard = self.shards[idx].lock();
        if let Some(bucket) = shard.get_mut(&user_id) {
            bucket.try_consume(bytes)
        } else {
            true // No limit configured
        }
    }

    pub async fn throttle(&self, user_id: u32, bytes: usize) {
        let mut remaining = bytes;
        while remaining > 0 {
            let changed = self.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            let wait = {
                let mut shard = self.shards[self.shard_idx(user_id)].lock();
                let Some(bucket) = shard.get_mut(&user_id) else {
                    break;
                };
                let amount = remaining.min(bucket.capacity as usize);
                if bucket.try_consume(amount) {
                    remaining -= amount;
                    None
                } else {
                    Some(Duration::from_secs_f64(
                        (amount as f64 - bucket.tokens) / bucket.rate_per_sec,
                    ))
                }
            };
            if let Some(wait) = wait {
                tokio::select! {
                    _ = tokio::time::sleep(wait) => {},
                    _ = &mut changed => {},
                }
            }
        }
    }

    pub fn prune_idle(&self) {
        let now = Instant::now();
        for shard in self.shards.iter() {
            for bucket in shard.lock().values_mut() {
                bucket.replenish(now);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn concurrent_waiters_share_one_budget() {
        let limiter = std::sync::Arc::new(RateLimiter::new());
        limiter.set_user_limit(1, 8192);
        assert!(limiter.allow(1, 65536));
        let started = Instant::now();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..4 {
            let limiter = limiter.clone();
            tasks.spawn(async move {
                limiter.throttle(1, 16384).await;
            });
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        assert!(started.elapsed() >= Duration::from_millis(7900));
    }

    #[tokio::test]
    async fn update_keeps_budget_and_removing_limit_wakes_waiters() {
        let limiter = std::sync::Arc::new(RateLimiter::new());
        limiter.set_user_limit(1, 1);
        assert!(limiter.allow(1, 65536));
        limiter.set_user_limit(1, 1);
        assert!(!limiter.allow(1, 1));
        let l = limiter.clone();
        let task = tokio::spawn(async move {
            l.throttle(1, 16).await;
        });
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(!task.is_finished());
        limiter.set_user_limit(1, 0);
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
        limiter.set_user_limit(1, 1);
        {
            let mut shard = limiter.shards[limiter.shard_idx(1)].lock();
            shard.get_mut(&1).unwrap().last_update -= Duration::from_secs(7200);
        }
        limiter.prune_idle();
        assert!(limiter.is_limited(1));
    }

    #[tokio::test]
    async fn test_rate_limiter_sharded() {
        let limiter = RateLimiter::new();
        limiter.set_user_limit(1, 1000); // 1KB/s

        assert!(limiter.allow(1, 500));
        limiter.throttle(1, 100).await;
    }
}
