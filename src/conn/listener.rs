use std::io;
use std::net::SocketAddr;
use tokio::net::{lookup_host, TcpListener};

/// Binds a TCP listener with optional MPTCP (Multipath TCP) support.
///
/// On Linux 5.6+ systems with `net.mptcp.enabled = 1`, setting `mptcp = true`
/// instantiates an MPTCP socket using `IPPROTO_MPTCP` (262).
/// If MPTCP is requested on an unsupported platform or system, an explicit error
/// is returned so the operator can adjust `mptcp=false`.
pub async fn bind_tcp_listener(addr_str: &str, mptcp: bool) -> io::Result<TcpListener> {
    if !mptcp {
        return TcpListener::bind(addr_str).await;
    }

    let addr: SocketAddr = if let Ok(sa) = addr_str.parse::<SocketAddr>() {
        sa
    } else {
        let mut addrs = lookup_host(addr_str).await?;
        addrs.next().ok_or_else(|| {
            io::Error::new(io::ErrorKind::AddrNotAvailable, "Failed to resolve bind address")
        })?
    };

    #[cfg(target_os = "linux")]
    {
        bind_mptcp_linux(addr)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = addr;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "MPTCP is only supported on Linux kernel 5.6+ with net.mptcp.enabled=1",
        ))
    }
}

#[cfg(target_os = "linux")]
fn bind_mptcp_linux(addr: SocketAddr) -> io::Result<TcpListener> {
    let domain = match addr {
        SocketAddr::V4(_) => socket2::Domain::IPV4,
        SocketAddr::V6(_) => socket2::Domain::IPV6,
    };

    // IPPROTO_MPTCP is defined as 262 (0x106) in Linux kernel >= 5.6 (include/uapi/linux/in.h)
    const IPPROTO_MPTCP: i32 = 262;
    let protocol = socket2::Protocol::from(IPPROTO_MPTCP);
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(protocol))
        .map_err(|e| {
            io::Error::new(
                e.kind(),
                format!(
                    "Failed to create MPTCP socket (IPPROTO_MPTCP 262). Ensure Linux kernel >= 5.6 and sysctl net.mptcp.enabled=1: {e}"
                ),
            )
        })?;

    socket.set_reuse_address(true)?;
    #[cfg(all(unix, not(target_os = "solaris"), not(target_os = "illumos")))]
    let _ = socket.set_reuse_port(true);
    socket.set_nonblocking(true)?;

    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let std_listener: std::net::TcpListener = socket.into();
    TcpListener::from_std(std_listener)
}
