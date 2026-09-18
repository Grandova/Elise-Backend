use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

#[derive(Clone, Default)]
pub struct ConnectionLimiter {
    active_conns: Arc<RwLock<HashMap<u32, Arc<AtomicU32>>>>,
    max_conns: Arc<RwLock<HashMap<u32, u32>>>,
}

impl ConnectionLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set_user_limit(&self, user_id: u32, limit: u32) {
        let mut map = self.max_conns.write();
        if limit > 0 {
            map.insert(user_id, limit);
        } else {
            map.remove(&user_id);
        }
    }

    pub fn try_acquire(&self, user_id: u32) -> Option<ConnGuard> {
        let max_limit = self.max_conns.read().get(&user_id).copied();

        // If no limit set for this user, allow without locking active_conns
        let limit = match max_limit {
            Some(l) if l > 0 => l,
            _ => return Some(ConnGuard { counter: None }),
        };

        // Check if counter already exists using fast read lock
        let counter = {
            let map = self.active_conns.read();
            map.get(&user_id).cloned()
        };

        let counter = match counter {
            Some(c) => c,
            None => {
                let mut map = self.active_conns.write();
                map.entry(user_id)
                    .or_insert_with(|| Arc::new(AtomicU32::new(0)))
                    .clone()
            }
        };

        // CAS loop to ensure atomic acquire under limit
        let mut cur = counter.load(Ordering::Relaxed);
        loop {
            if cur >= limit {
                return None;
            }
            match counter.compare_exchange_weak(cur, cur + 1, Ordering::AcqRel, Ordering::Relaxed) {
                Ok(_) => break,
                Err(actual) => cur = actual,
            }
        }

        Some(ConnGuard {
            counter: Some(counter),
        })
    }

    pub fn prune_idle(&self) {
        let mut map = self.active_conns.write();
        // A cloned zero counter may be between lookup and its acquire CAS.
        map.retain(|_, counter| {
            counter.load(Ordering::Relaxed) > 0 || Arc::strong_count(counter) > 1
        });
    }

    pub fn get_total_active(&self) -> u32 {
        let map = self.active_conns.read();
        map.values().map(|c| c.load(Ordering::Relaxed)).sum()
    }
}

pub struct ConnGuard {
    counter: Option<Arc<AtomicU32>>,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Some(c) = &self.counter {
            c.fetch_sub(1, Ordering::Release);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prune_keeps_an_acquire_in_progress() {
        let limiter = ConnectionLimiter::new();
        limiter.set_user_limit(1, 1);
        drop(limiter.try_acquire(1).unwrap());
        let pending = limiter.active_conns.read()[&1].clone();
        limiter.prune_idle();
        assert!(Arc::ptr_eq(&pending, &limiter.active_conns.read()[&1]));
        drop(pending);
        limiter.prune_idle();
        assert!(limiter.active_conns.read().is_empty());
    }

    #[test]
    fn concurrent_acquire_release_and_prune_never_exceeds_limit() {
        let limiter = ConnectionLimiter::new();
        limiter.set_user_limit(1, 1);
        let active = Arc::new(AtomicU32::new(0));
        let mut workers = Vec::new();
        for _ in 0..8 {
            let limiter = limiter.clone();
            let active = active.clone();
            workers.push(std::thread::spawn(move || {
                for _ in 0..10000 {
                    if let Some(guard) = limiter.try_acquire(1) {
                        assert_eq!(active.fetch_add(1, Ordering::SeqCst), 0);
                        std::thread::yield_now();
                        assert_eq!(active.fetch_sub(1, Ordering::SeqCst), 1);
                        drop(guard);
                    }
                    limiter.prune_idle();
                }
            }));
        }
        for worker in workers {
            worker.join().unwrap();
        }
        limiter.prune_idle();
        assert_eq!(limiter.get_total_active(), 0);
        assert!(limiter.active_conns.read().is_empty());
    }

    #[test]
    fn test_conn_limiter_concurrency() {
        let limiter = ConnectionLimiter::new();
        limiter.set_user_limit(1, 2);

        let g1 = limiter.try_acquire(1);
        assert!(g1.is_some());
        let g2 = limiter.try_acquire(1);
        assert!(g2.is_some());
        let g3 = limiter.try_acquire(1);
        assert!(g3.is_none());

        drop(g1);
        let g4 = limiter.try_acquire(1);
        assert!(g4.is_some());
    }
}
