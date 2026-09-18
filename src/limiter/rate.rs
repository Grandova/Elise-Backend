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

    fn compute_wait_time(&mut self, amount: usize) -> Option<Duration> {
        let now = Instant::now();
        self.replenish(now);

        if self.tokens >= amount as f64 {
            self.tokens -= amount as f64;
            None
        } else {
            let deficit = (amount as f64) - self.tokens;
            self.tokens = 0.0;
            if self.rate_per_sec > 0.0 {
                let secs = (deficit / self.rate_per_sec).min(5.0); // max 5s throttle sleep
                Some(Duration::from_secs_f64(secs))
            } else {
                None
            }
        }
    }
}

pub struct RateLimiter {
    shards: [Mutex<HashMap<u32, TokenBucket>>; NUM_SHARDS],
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
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
            shard.insert(user_id, TokenBucket::new(speed_limit_bps));
        } else {
            shard.remove(&user_id);
        }
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
        let wait_opt = {
            let idx = self.shard_idx(user_id);
            let mut shard = self.shards[idx].lock();
            shard
                .get_mut(&user_id)
                .and_then(|b| b.compute_wait_time(bytes))
        };

        if let Some(wait) = wait_opt {
            tokio::time::sleep(wait).await;
        }
    }

    pub fn prune_idle(&self) {
        let now = Instant::now();
        for shard in &self.shards {
            let mut map = shard.lock();
            map.retain(|_, b| now.duration_since(b.last_update).as_secs() < 3600);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_rate_limiter_sharded() {
        let limiter = RateLimiter::new();
        limiter.set_user_limit(1, 1000); // 1KB/s

        assert!(limiter.allow(1, 500));
        limiter.throttle(1, 100).await;
    }
}
