use crate::panel::types::User;
use crate::protocol::InboundContext;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub async fn negotiate_auth<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    client_ip: IpAddr,
    users: Arc<RwLock<HashMap<String, User>>>,
    ctx: &InboundContext,
) -> io::Result<User> {
    // SOCKS5 Method Negotiation (RFC 1928 Section 3)
    let mut ver_nmethods = [0u8; 2];
    stream.read_exact(&mut ver_nmethods).await?;
    if ver_nmethods[0] != 0x05 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid SOCKS version: 0x{:02x}", ver_nmethods[0]),
        ));
    }

    let nmethods = ver_nmethods[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    let has_users = !users.read().is_empty();

    if !has_users {
        // No users configured in system: allow NO AUTH (0x00)
        if methods.contains(&0x00) {
            stream.write_all(&[0x05, 0x00]).await?;
            Ok(User {
                id: 0,
                uuid: "anonymous".to_string(),
                speed_limit: 0,
                device_limit: 0,
                password: None,
                method: None,
                port: None,
                flow: None,
            })
        } else {
            stream.write_all(&[0x05, 0xFF]).await?;
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "No acceptable SOCKS5 authentication methods (no-auth not supported by client)",
            ))
        }
    } else if methods.contains(&0x02) {
        // Method 0x02: USERNAME/PASSWORD (RFC 1929)
        stream.write_all(&[0x05, 0x02]).await?;

        // Read RFC 1929 subnegotiation request
        let mut auth_ver_ulen = [0u8; 2];
        stream.read_exact(&mut auth_ver_ulen).await?;
        if auth_ver_ulen[0] != 0x01 {
            let _ = stream.write_all(&[0x01, 0x01]).await;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("Invalid RFC 1929 auth version: 0x{:02x}", auth_ver_ulen[0]),
            ));
        }

        let ulen = auth_ver_ulen[1] as usize;
        let mut uname_bytes = vec![0u8; ulen];
        stream.read_exact(&mut uname_bytes).await?;
        let username = String::from_utf8_lossy(&uname_bytes).to_string();

        let mut plen_buf = [0u8; 1];
        stream.read_exact(&mut plen_buf).await?;
        let plen = plen_buf[0] as usize;
        let mut passwd_bytes = vec![0u8; plen];
        stream.read_exact(&mut passwd_bytes).await?;
        let password = String::from_utf8_lossy(&passwd_bytes).to_string();

        let matched_user = {
            let guard = users.read();
            guard.get(&username).and_then(|u| {
                let expected_pass = u.password.as_deref().unwrap_or(&u.uuid);
                if expected_pass == password {
                    Some(u.clone())
                } else {
                    None
                }
            })
        };

        match matched_user {
            Some(u) => {
                stream.write_all(&[0x01, 0x00]).await?;
                ctx.defense.record_success(client_ip);
                Ok(u)
            }
            None => {
                let _ = stream.write_all(&[0x01, 0x01]).await;
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("SOCKS5 RFC 1929 auth failed for user '{}'", username),
                ))
            }
        }
    } else {
        // Client does not offer 0x02 USER/PASS
        stream.write_all(&[0x05, 0xFF]).await?;
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 server requires USER/PASS (0x02) authentication",
        ))
    }
}
