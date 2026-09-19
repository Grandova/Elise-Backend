pub mod listener;
pub mod proxy_protocol;
pub mod sniffer;
pub mod udp;

pub use listener::bind_tcp_listener;
pub use proxy_protocol::{
    encode_proxy_protocol_v1, encode_proxy_protocol_v2, parse_proxy_protocol_datagram,
    read_proxy_protocol, read_proxy_protocol_with_meta, ConnectionMeta, PrefixedStream,
    ProxyProtocolMode,
};
pub use sniffer::{sniff_and_detect_stream, sniff_async_stream, sniff_domain};

use crate::limiter::RateLimiter;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

pub struct IdleTimeout {
    timeout: Duration,
    activity: tokio::sync::watch::Sender<tokio::time::Instant>,
}

impl IdleTimeout {
    pub fn new(seconds: u64) -> Self {
        let (activity, _) = tokio::sync::watch::channel(tokio::time::Instant::now());
        Self {
            timeout: Duration::from_secs(seconds),
            activity,
        }
    }

    pub async fn run<T>(
        &self,
        future: impl std::future::Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        let mut activity = self.activity.subscribe();
        let expired = async {
            if self.timeout.is_zero() {
                std::future::pending::<()>().await;
            }
            loop {
                let deadline = *activity.borrow_and_update() + self.timeout;
                tokio::select! {
                    _ = tokio::time::sleep_until(deadline) => break,
                    _ = activity.changed() => {},
                }
            }
        };
        tokio::select! {
            result = future => {
                if result.is_ok() { self.activity.send_replace(tokio::time::Instant::now()); }
                result
            },
            _ = expired => Err(io::Error::new(io::ErrorKind::TimedOut,"Session idle timeout")),
        }
    }
}

pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}
pub type BoxedStream = Box<dyn AsyncStream>;

/// MonitoredStream wraps the client inbound connection to track upload and download bandwidth.
/// Reading from the stream = client uploading to server.
/// Writing to the stream = server downloading/replying to client.
pub struct MonitoredStream<S> {
    inner: S,
    pub user_id: u32,
    pub client_addr: SocketAddr,
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
}

pub struct TrafficGuard {
    user_id: u32,
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
    on_traffic: crate::protocol::TrafficCallback,
}

impl TrafficGuard {
    pub fn new(user_id: u32, on_traffic: crate::protocol::TrafficCallback) -> Self {
        Self {
            user_id,
            upload: Arc::new(AtomicU64::new(0)),
            download: Arc::new(AtomicU64::new(0)),
            on_traffic,
        }
    }

    pub fn add(&self, up: u64, down: u64) {
        if up > 0 {
            self.upload.fetch_add(up, Ordering::Relaxed);
        }
        if down > 0 {
            self.download.fetch_add(down, Ordering::Relaxed);
        }
    }
}

impl Drop for TrafficGuard {
    fn drop(&mut self) {
        let up = self.upload.load(Ordering::Relaxed);
        let down = self.download.load(Ordering::Relaxed);
        if up > 0 || down > 0 {
            (self.on_traffic)(self.user_id, up, down);
        }
    }
}

impl<S> MonitoredStream<S> {
    pub fn new(inner: S, user_id: u32, client_addr: SocketAddr) -> Self {
        Self {
            inner,
            user_id,
            client_addr,
            upload: Arc::new(AtomicU64::new(0)),
            download: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn stats(&self) -> (u64, u64) {
        (
            self.upload.load(Ordering::Relaxed),
            self.download.load(Ordering::Relaxed),
        )
    }

    pub fn traffic_guard(&self, on_traffic: crate::protocol::TrafficCallback) -> TrafficGuard {
        TrafficGuard {
            user_id: self.user_id,
            upload: self.upload.clone(),
            download: self.download.clone(),
            on_traffic,
        }
    }

    pub fn upload_handle(&self) -> Arc<AtomicU64> {
        self.upload.clone()
    }

    pub fn download_handle(&self) -> Arc<AtomicU64> {
        self.download.clone()
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for MonitoredStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &poll {
            let read_bytes = (buf.filled().len() - before) as u64;
            // Data read from client is client upload
            self.upload.fetch_add(read_bytes, Ordering::Relaxed);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for MonitoredStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &poll {
            // Data written to client is client download
            self.download.fetch_add(*n as u64, Ordering::Relaxed);
        }
        poll
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Bidirectional copy with dynamic rate limits and a shared idle deadline.
pub async fn copy_bidirectional_throttled<A, B>(
    a: &mut A,
    b: &mut B,
    user_id: u32,
    rate_limiter: Option<&RateLimiter>,
    timeout: u64,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    const BUFFER_SIZE: usize = 32768; // 32KB optimal socket buffer size

    let idle = IdleTimeout::new(timeout);

    let (mut a_read, mut a_write) = tokio::io::split(a);
    let (mut b_read, mut b_write) = tokio::io::split(b);

    let a_to_b = async {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut total = 0u64;
        loop {
            let n = idle.run(a_read.read(&mut buf)).await?;
            if n == 0 {
                break;
            }
            idle.run(async {
                if let Some(limiter) = rate_limiter {
                    limiter.throttle(user_id, n).await;
                }
                b_write.write_all(&buf[..n]).await
            })
            .await?;
            idle.run(b_write.flush()).await?;
            total += n as u64;
        }
        idle.run(b_write.shutdown()).await?;
        Ok::<u64, io::Error>(total)
    };

    let b_to_a = async {
        let mut buf = vec![0u8; BUFFER_SIZE];
        let mut total = 0u64;
        loop {
            let n = idle.run(b_read.read(&mut buf)).await?;
            if n == 0 {
                break;
            }
            idle.run(async {
                if let Some(limiter) = rate_limiter {
                    limiter.throttle(user_id, n).await;
                }
                a_write.write_all(&buf[..n]).await
            })
            .await?;
            idle.run(a_write.flush()).await?;
            total += n as u64;
        }
        idle.run(a_write.shutdown()).await?;
        Ok::<u64, io::Error>(total)
    };

    let (res_a, res_b) = tokio::try_join!(a_to_b, b_to_a)?;
    if res_b > 0 {
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok((res_a, res_b))
}

/// A stream wrapper that flushes the inner stream immediately after every successful poll_write.
/// This prevents TLS records from being buffered indefinitely when using tokio_rustls + h2.
pub struct AutoFlushingStream<S> {
    inner: S,
}

impl<S> AutoFlushingStream<S> {
    pub fn new(inner: S) -> Self {
        Self { inner }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for AutoFlushingStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for AutoFlushingStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                let _ = Pin::new(&mut self.inner).poll_flush(cx);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn traffic_is_reported_once_when_connection_task_is_aborted() {
        let reports = Arc::new(parking_lot::Mutex::new(Vec::new()));
        let captured = reports.clone();
        let (mut client, server) = tokio::io::duplex(64);
        let (ready, received) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let mut stream = MonitoredStream::new(server, 42, "127.0.0.1:1234".parse().unwrap());
            let _traffic = stream.traffic_guard(Arc::new(move |id, up, down| {
                captured.lock().push((id, up, down))
            }));
            let mut data = [0; 4];
            stream.read_exact(&mut data).await.unwrap();
            stream.write_all(b"answer").await.unwrap();
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        client.write_all(b"data").await.unwrap();
        let mut answer = [0; 6];
        client.read_exact(&mut answer).await.unwrap();
        received.await.unwrap();
        assert!(reports.lock().is_empty());
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert_eq!(*reports.lock(), vec![(42, 4, 6)]);
    }

    #[tokio::test]
    async fn activity_in_either_direction_extends_idle_deadline() {
        let idle = IdleTimeout::new(1);
        let start = std::time::Instant::now();
        let waiting = idle.run(std::future::pending::<io::Result<()>>());
        let active = async {
            for _ in 0..3 {
                tokio::time::sleep(Duration::from_millis(600)).await;
                idle.run(async { Ok(()) }).await.unwrap();
            }
        };
        let (result, _) = tokio::join!(waiting, active);
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
        assert!(start.elapsed() >= Duration::from_millis(2700));
    }
}
