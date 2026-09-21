use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub enum SessionError {
    ExpiredTicket,
    ReplayDetected,
}

pub struct ServerSession {
    pub pfs_key: [u8; 64],
    pub nfs_keys: HashSet<[u8; 32]>,
    pub expires_at: Instant,
}

const MAX_SESSIONS: usize = 16384;
const MAX_NFS_KEYS_PER_SESSION: usize = 256;
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub struct SessionStore {
    sessions: Arc<RwLock<HashMap<[u8; 16], ServerSession>>>,
    last_sweep: Arc<RwLock<Instant>>,
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl SessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
            last_sweep: Arc::new(RwLock::new(Instant::now())),
        }
    }

    pub fn insert(&self, ticket: [u8; 16], pfs_key: [u8; 64], ttl: Duration) {
        let now = Instant::now();
        let mut map = self.sessions.write();

        let should_sweep = {
            let last = *self.last_sweep.read();
            now.duration_since(last) > SWEEP_INTERVAL
        };
        if should_sweep || map.len() >= MAX_SESSIONS {
            map.retain(|_, s| s.expires_at > now);
            *self.last_sweep.write() = now;
        }

        if map.len() >= MAX_SESSIONS {
            tracing::warn!("SessionStore reached maximum capacity ({MAX_SESSIONS}), rejecting new 0-RTT ticket");
            return;
        }

        map.insert(
            ticket,
            ServerSession {
                pfs_key,
                nfs_keys: HashSet::new(),
                expires_at: now + ttl,
            },
        );
    }

    pub fn validate_and_record_nfs_key(
        &self,
        ticket: &[u8; 16],
        nfs_key: &[u8; 32],
    ) -> Result<[u8; 64], SessionError> {
        let mut map = self.sessions.write();
        let session = match map.get_mut(ticket) {
            Some(s) if s.expires_at > Instant::now() => s,
            _ => return Err(SessionError::ExpiredTicket),
        };

        if session.nfs_keys.len() >= MAX_NFS_KEYS_PER_SESSION {
            return Err(SessionError::ReplayDetected);
        }

        if !session.nfs_keys.insert(*nfs_key) {
            return Err(SessionError::ReplayDetected);
        }

        Ok(session.pfs_key)
    }

    pub fn clear(&self) {
        self.sessions.write().clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_store_replay_detection() {
        let store = SessionStore::new();
        let ticket = [0x55u8; 16];
        let pfs_key = [0xaau8; 64];
        let nfs_key1 = [0x11u8; 32];
        let nfs_key2 = [0x22u8; 32];

        store.insert(ticket, pfs_key, Duration::from_secs(60));

        let res = store.validate_and_record_nfs_key(&ticket, &nfs_key1);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), pfs_key);

        let replay = store.validate_and_record_nfs_key(&ticket, &nfs_key1);
        assert!(matches!(replay, Err(SessionError::ReplayDetected)));

        let res2 = store.validate_and_record_nfs_key(&ticket, &nfs_key2);
        assert!(res2.is_ok());
    }

    #[test]
    fn test_session_store_expiry() {
        let store = SessionStore::new();
        let ticket = [0x77u8; 16];
        let pfs_key = [0xbbu8; 64];
        let nfs_key = [0x33u8; 32];

        store.insert(ticket, pfs_key, Duration::from_millis(1));
        std::thread::sleep(Duration::from_millis(5));

        let res = store.validate_and_record_nfs_key(&ticket, &nfs_key);
        assert!(matches!(res, Err(SessionError::ExpiredTicket)));
    }
}
