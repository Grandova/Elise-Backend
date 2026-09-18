use crate::panel::types::User;
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag as XTag, XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;

pub const KEY_REFRESH_INTERVAL_SECS: i64 = 120;
pub const PBKDF2_ROUNDS: u32 = 64;
pub const NONCE_SIZE: usize = 24;
pub const METADATA_LENGTH: usize = 32;
pub const OVERHEAD: usize = 16;

/// Official Mieru password hashing: SHA256(raw_password || 0x00 || username)
pub fn hash_password(raw_password: &[u8], username: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(raw_password);
    hasher.update([0x00]); // 0x00 separator
    hasher.update(username);
    hasher.finalize().into()
}

/// Derive time-based salts (3 salts, each 32 bytes)
pub fn salts_from_time(now_sec: i64) -> [[u8; 32]; 3] {
    let interval = KEY_REFRESH_INTERVAL_SECS;
    let rounded = ((now_sec + interval / 2) / interval) * interval;
    let times = [rounded - interval, rounded, rounded + interval];

    let mut salts = [[0u8; 32]; 3];
    for (i, &t) in times.iter().enumerate() {
        let b = (t as u64).to_be_bytes();
        let mut hasher = Sha256::new();
        hasher.update(b);
        salts[i] = hasher.finalize().into();
    }
    salts
}

/// PBKDF2-HMAC-SHA256 implementation with fixed 32-byte output
pub fn pbkdf2_sha256_32(hashed_password: &[u8], salt: &[u8], rounds: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut hmac = <Hmac<Sha256> as Mac>::new_from_slice(hashed_password)
        .expect("HMAC can take key of any size");
    hmac.update(salt);
    hmac.update(&1u32.to_be_bytes()); // Block index 1
    let mut u = hmac.finalize().into_bytes();
    key.copy_from_slice(&u);

    for _ in 1..rounds {
        let mut next_hmac = <Hmac<Sha256> as Mac>::new_from_slice(hashed_password)
            .expect("HMAC can take key of any size");
        next_hmac.update(&u);
        u = next_hmac.finalize().into_bytes();
        for j in 0..32 {
            key[j] ^= u[j];
        }
    }
    key
}

/// Compute expected UserHint (first 4 bytes of SHA256(username || nonce[..16]))
pub fn compute_user_hint(username: &str, nonce_prefix_16: &[u8; 16]) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update(nonce_prefix_16);
    let hash = hasher.finalize();
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Check if the 24-byte Nonce contains the expected UserHint suffix for `username`
pub fn check_user_hint(username: &str, nonce: &[u8; 24]) -> bool {
    if username.is_empty() || username.len() > 32 {
        return false;
    }
    let mut nonce_prefix = [0u8; 16];
    nonce_prefix.copy_from_slice(&nonce[..16]);
    let expected = compute_user_hint(username, &nonce_prefix);
    expected == nonce[20..24]
}

/// Increment 24-byte big-endian nonce in-place
pub fn increment_nonce(nonce: &mut [u8; 24]) {
    for byte in nonce.iter_mut().rev() {
        let (val, overflow) = byte.overflowing_add(1);
        *byte = val;
        if !overflow {
            break;
        }
    }
}

/// Mieru user state with pre-calculated hashed password
#[derive(Clone, Debug)]
pub struct MieruUser {
    pub panel_user: User,
    pub username: String,
    pub hashed_password: [u8; 32],
}

impl MieruUser {
    pub fn from_panel_user(user: User) -> Self {
        // XBoard subscriptions use the same panel credential for both fields.
        let username = user
            .password
            .clone()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| user.uuid.clone());
        let hashed_password = hash_password(username.as_bytes(), username.as_bytes());
        Self {
            panel_user: user,
            username,
            hashed_password,
        }
    }
}

/// Multi-user index with time-window subkey caching to avoid PBKDF2 recalculation on every packet
#[derive(Clone)]
pub struct MieruUserIndex {
    users: Arc<Vec<MieruUser>>,
    // Cache: (user_id, salt) -> 32-byte derived key
    cached_keys: Arc<parking_lot::RwLock<HashMap<(u32, [u8; 32]), [u8; 32]>>>,
}

impl MieruUserIndex {
    pub fn new(panel_users: Vec<User>) -> Self {
        let users: Vec<MieruUser> = panel_users
            .into_iter()
            .map(MieruUser::from_panel_user)
            .collect();
        Self {
            users: Arc::new(users),
            cached_keys: Arc::new(parking_lot::RwLock::new(HashMap::new())),
        }
    }

    pub fn users(&self) -> &[MieruUser] {
        &self.users
    }

    /// Get or compute derived key for user with specific salt
    pub fn get_derived_key(&self, user: &MieruUser, salt: &[u8; 32]) -> [u8; 32] {
        let key_tuple = (user.panel_user.id, *salt);
        {
            let cache = self.cached_keys.read();
            if let Some(key) = cache.get(&key_tuple) {
                return *key;
            }
        }
        let derived = pbkdf2_sha256_32(&user.hashed_password, salt, PBKDF2_ROUNDS);
        let mut cache = self.cached_keys.write();
        cache.insert(key_tuple, derived);
        derived
    }

    /// Try to decrypt metadata using all salts and users.
    /// Fast-path: checks UserHint first.
    /// Fallback: tests users who don't have hint or hint didn't match.
    pub fn try_decrypt_metadata(
        &self,
        encrypted_meta_with_tag: &[u8], // 48 bytes (32 meta + 16 tag)
        recv_nonce: &[u8; 24],
        now_sec: i64,
    ) -> Option<(MieruUser, [u8; 32], [u8; 32])> {
        if encrypted_meta_with_tag.len() < 48 {
            return None;
        }

        let salts = salts_from_time(now_sec);
        let tag = XTag::from_slice(&encrypted_meta_with_tag[32..48]);
        let ciphertext = &encrypted_meta_with_tag[..32];

        // Pass 1: Users matching UserHint
        for user in self.users.iter() {
            if check_user_hint(&user.username, recv_nonce) {
                for salt in &salts {
                    let key = self.get_derived_key(user, salt);
                    if let Ok(cipher) = XChaCha20Poly1305::new_from_slice(&key) {
                        let mut buf = ciphertext.to_vec();
                        if cipher
                            .decrypt_in_place_detached(
                                XNonce::from_slice(recv_nonce),
                                b"",
                                &mut buf,
                                tag,
                            )
                            .is_ok()
                        {
                            let mut meta = [0u8; 32];
                            meta.copy_from_slice(&buf);
                            return Some((user.clone(), key, meta));
                        }
                    }
                }
            }
        }

        // Pass 2: Fallback for clients with UserHint disabled or legacy clients
        for user in self.users.iter() {
            for salt in &salts {
                let key = self.get_derived_key(user, salt);
                if let Ok(cipher) = XChaCha20Poly1305::new_from_slice(&key) {
                    let mut buf = ciphertext.to_vec();
                    if cipher
                        .decrypt_in_place_detached(
                            XNonce::from_slice(recv_nonce),
                            b"",
                            &mut buf,
                            tag,
                        )
                        .is_ok()
                    {
                        let mut meta = [0u8; 32];
                        meta.copy_from_slice(&buf);
                        return Some((user.clone(), key, meta));
                    }
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
    fn panel_credential_is_used_for_both_fields() {
        for password in [None, Some(String::new()), Some("panel-password".into())] {
            let user = User {
                id: 7,
                uuid: "panel-uuid".into(),
                password: password.clone(),
                ..Default::default()
            };
            let expected = password
                .filter(|s| !s.is_empty())
                .unwrap_or("panel-uuid".into());
            let user = MieruUser::from_panel_user(user);
            assert_eq!(user.username, expected);
            assert_eq!(
                user.hashed_password,
                hash_password(expected.as_bytes(), expected.as_bytes())
            );
        }
    }
}
