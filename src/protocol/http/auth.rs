use crate::panel::types::User;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    Missing,
    Malformed,
    InvalidCredentials,
}

/// Verify Basic Proxy-Authorization header credentials against current users table.
/// Supports both username:password, user_id:password, user_uuid:password, and uuid:uuid.
pub fn verify_basic_auth(
    auth_header: Option<&str>,
    users: &Arc<RwLock<HashMap<String, User>>>,
) -> Result<User, AuthError> {
    let header = auth_header.ok_or(AuthError::Missing)?;
    let trimmed = header.trim();
    if !trimmed.to_ascii_lowercase().starts_with("basic ") {
        return Err(AuthError::Malformed);
    }

    let b64_payload = trimmed[6..].trim();
    use base64::Engine;
    let decoded_bytes = base64::engine::general_purpose::STANDARD
        .decode(b64_payload)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(b64_payload))
        .map_err(|_| AuthError::Malformed)?;

    let creds_str = String::from_utf8(decoded_bytes).map_err(|_| AuthError::Malformed)?;
    let (username, password) = creds_str.split_once(':').ok_or(AuthError::Malformed)?;

    let guard = users.read();
    let query_key = format!("{}:{}", username, password);
    if let Some(user) = guard.get(&query_key) {
        return Ok(user.clone());
    }

    for user in guard.values() {
        let is_user_match = user.id.to_string() == username || user.uuid == username;
        let expected_pass = user.password.as_deref().unwrap_or(&user.uuid);
        if is_user_match && expected_pass == password {
            return Ok(user.clone());
        }
    }

    Err(AuthError::InvalidCredentials)
}

pub const RESP_407_AUTH_REQUIRED: &[u8] = b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Elise\"\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 30\r\nConnection: close\r\n\r\nProxy Authentication Required\n";

pub const RESP_400_BAD_REQUEST: &[u8] = b"HTTP/1.1 400 Bad Request\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 12\r\nConnection: close\r\n\r\nBad Request\n";

pub const RESP_502_BAD_GATEWAY: &[u8] = b"HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 12\r\nConnection: close\r\n\r\nBad Gateway\n";

pub const RESP_200_CONNECTION_ESTABLISHED: &[u8] = b"HTTP/1.1 200 Connection Established\r\n\r\n";
