use parking_lot::Mutex;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

static TIMING_ENABLED: AtomicBool = AtomicBool::new(true);

pub fn set_timing_enabled(enabled: bool) {
    TIMING_ENABLED.store(enabled, Ordering::Relaxed);
}

pub fn is_timing_enabled() -> bool {
    TIMING_ENABLED.load(Ordering::Relaxed)
}

#[derive(Clone, Debug)]
pub struct TimingRecord {
    pub flow: String,
    pub remote_addr: SocketAddr,
    pub t_accept: Instant,
    pub t_tls_handshake: Option<Instant>,
    pub t_vless_auth: Option<Instant>,
    pub t_start: Option<Instant>,
    pub t_client_hello: Option<Instant>,
    pub t_outbound_connect_start: Option<Instant>,
    pub t_outbound_connect_complete: Option<Instant>,
    pub t_first_outbound_write: Option<Instant>,
    pub t_first_upstream_response: Option<Instant>,
    pub t_first_client_write: Option<Instant>,
    pub t_command_padding: Option<(Instant, &'static str)>,
    pub t_direct_copy_enabled: Option<Instant>,
    pub t_finish: Option<Instant>,
}

impl TimingRecord {
    pub fn new(remote_addr: SocketAddr) -> Self {
        Self {
            flow: "none".to_string(),
            remote_addr,
            t_accept: Instant::now(),
            t_tls_handshake: None,
            t_vless_auth: None,
            t_start: None,
            t_client_hello: None,
            t_outbound_connect_start: None,
            t_outbound_connect_complete: None,
            t_first_outbound_write: None,
            t_first_upstream_response: None,
            t_first_client_write: None,
            t_command_padding: None,
            t_direct_copy_enabled: None,
            t_finish: None,
        }
    }

    pub fn elapsed_us(&self, point: Option<Instant>) -> Option<u64> {
        point.map(|t| t.duration_since(self.t_accept).as_micros() as u64)
    }

    pub fn total_handshake_rtt_us(&self) -> u64 {
        self.t_first_client_write
            .or(self.t_finish)
            .unwrap_or(self.t_accept)
            .duration_since(self.t_accept)
            .as_micros() as u64
    }
}

pub type SharedTimingTracker = Arc<Mutex<TimingRecord>>;

pub fn new_tracker(remote_addr: SocketAddr) -> SharedTimingTracker {
    Arc::new(Mutex::new(TimingRecord::new(remote_addr)))
}

#[derive(Debug, Clone)]
pub enum VisionTimingEvent {
    TcpAccept,
    TlsHandshakeComplete,
    VlessAuthComplete { flow: String },
    VisionStart,
    StandardStart,
    ClientHelloDetected,
    OutboundConnectStart,
    OutboundConnectComplete,
    FirstOutboundWrite,
    FirstUpstreamResponse,
    FirstVisionWrite,
    CommandPaddingDirect,
    CommandPaddingEnd,
    DirectCopyEnabled,
    Finish,
}

static COLLECTOR: Mutex<Option<Vec<TimingRecord>>> = Mutex::new(None);

pub fn init_collector() {
    let mut guard = COLLECTOR.lock();
    *guard = Some(Vec::new());
}

pub fn take_collected_records() -> Vec<TimingRecord> {
    let mut guard = COLLECTOR.lock();
    guard.take().unwrap_or_default()
}

pub fn record_event(tracker: &Option<SharedTimingTracker>, event: VisionTimingEvent) {
    if !is_timing_enabled() {
        return;
    }
    let tracker = match tracker {
        Some(t) => t,
        None => return,
    };

    let now = Instant::now();
    let mut rec = tracker.lock();

    let prev_instant = rec
        .t_finish
        .or(rec.t_direct_copy_enabled)
        .or(rec.t_command_padding.map(|(t, _)| t))
        .or(rec.t_first_client_write)
        .or(rec.t_first_upstream_response)
        .or(rec.t_first_outbound_write)
        .or(rec.t_outbound_connect_complete)
        .or(rec.t_outbound_connect_start)
        .or(rec.t_client_hello)
        .or(rec.t_start)
        .or(rec.t_vless_auth)
        .or(rec.t_tls_handshake)
        .unwrap_or(rec.t_accept);

    let delta_us = now.duration_since(prev_instant).as_micros();
    let cum_us = now.duration_since(rec.t_accept).as_micros();

    let event_name = match &event {
        VisionTimingEvent::TcpAccept => "TCP accept",
        VisionTimingEvent::TlsHandshakeComplete => {
            rec.t_tls_handshake = Some(now);
            "Reality/TLS handshake complete"
        }
        VisionTimingEvent::VlessAuthComplete { flow } => {
            rec.flow = flow.clone();
            rec.t_vless_auth = Some(now);
            "VLESS auth complete"
        }
        VisionTimingEvent::VisionStart => {
            rec.t_start = Some(now);
            "Vision start"
        }
        VisionTimingEvent::StandardStart => {
            rec.t_start = Some(now);
            "Standard start"
        }
        VisionTimingEvent::ClientHelloDetected => {
            if rec.t_client_hello.is_none() {
                rec.t_client_hello = Some(now);
            }
            "ClientHello detected"
        }
        VisionTimingEvent::OutboundConnectStart => {
            rec.t_outbound_connect_start = Some(now);
            "outbound connect start"
        }
        VisionTimingEvent::OutboundConnectComplete => {
            rec.t_outbound_connect_complete = Some(now);
            "outbound connect complete"
        }
        VisionTimingEvent::FirstOutboundWrite => {
            rec.t_first_outbound_write = Some(now);
            "first outbound write"
        }
        VisionTimingEvent::FirstUpstreamResponse => {
            rec.t_first_upstream_response = Some(now);
            "first upstream response"
        }
        VisionTimingEvent::FirstVisionWrite => {
            rec.t_first_client_write = Some(now);
            "first Vision write"
        }
        VisionTimingEvent::CommandPaddingDirect => {
            rec.t_command_padding = Some((now, "CommandPaddingDirect"));
            "CommandPaddingDirect"
        }
        VisionTimingEvent::CommandPaddingEnd => {
            rec.t_command_padding = Some((now, "CommandPaddingEnd"));
            "CommandPaddingEnd"
        }
        VisionTimingEvent::DirectCopyEnabled => {
            rec.t_direct_copy_enabled = Some(now);
            "Direct Copy enabled"
        }
        VisionTimingEvent::Finish => {
            rec.t_finish = Some(now);
            "Session finished"
        }
    };

    tracing::info!(
        target: "elise::vision::timing",
        "[VISION_TIMING] [conn={} flow={}] {}: +{} µs (delta: +{} µs)",
        rec.remote_addr,
        rec.flow,
        event_name,
        cum_us,
        delta_us
    );

    if matches!(event, VisionTimingEvent::Finish) {
        if let Some(ref mut col) = *COLLECTOR.lock() {
            col.push(rec.clone());
        }
    }
}

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct TimingWrapper<S> {
    pub inner: S,
    pub timing: Option<SharedTimingTracker>,
    pub on_first_read: Option<VisionTimingEvent>,
    pub on_first_write: Option<VisionTimingEvent>,
}

impl<S: AsyncRead + Unpin> AsyncRead for TimingWrapper<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &res {
            if buf.filled().len() > before {
                if let Some(ev) = self.on_first_read.take() {
                    record_event(&self.timing, ev);
                }
            }
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for TimingWrapper<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                if let Some(ev) = self.on_first_write.take() {
                    record_event(&self.timing, ev);
                }
            }
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone, Default)]
pub struct LatencyStats {
    pub count: usize,
    pub min_us: u64,
    pub max_us: u64,
    pub avg_us: u64,
    pub p50_us: u64,
    pub p95_us: u64,
}

impl LatencyStats {
    pub fn compute(mut values: Vec<u64>) -> Self {
        if values.is_empty() {
            return Self::default();
        }
        values.sort_unstable();
        let count = values.len();
        let min_us = values[0];
        let max_us = values[count - 1];
        let sum: u64 = values.iter().sum();
        let avg_us = sum / count as u64;
        let p50_us = values[count / 2];
        let p95_idx = ((count as f64 * 0.95).ceil() as usize)
            .saturating_sub(1)
            .min(count - 1);
        let p95_us = values[p95_idx];
        Self {
            count,
            min_us,
            max_us,
            avg_us,
            p50_us,
            p95_us,
        }
    }
}

impl TimingRecord {
    pub fn delta_tcp_to_tls(&self) -> Option<u64> {
        self.t_tls_handshake
            .map(|t| t.duration_since(self.t_accept).as_micros() as u64)
    }
    pub fn delta_tls_to_auth(&self) -> Option<u64> {
        match (self.t_tls_handshake, self.t_vless_auth) {
            (Some(a), Some(b)) => Some(b.duration_since(a).as_micros() as u64),
            _ => None,
        }
    }
    pub fn delta_auth_to_outbound_start(&self) -> Option<u64> {
        match (self.t_vless_auth, self.t_outbound_connect_start) {
            (Some(a), Some(b)) => Some(b.duration_since(a).as_micros() as u64),
            _ => None,
        }
    }
    pub fn delta_outbound_dial(&self) -> Option<u64> {
        match (
            self.t_outbound_connect_start,
            self.t_outbound_connect_complete,
        ) {
            (Some(a), Some(b)) => Some(b.duration_since(a).as_micros() as u64),
            _ => None,
        }
    }
    pub fn delta_outbound_to_first_write(&self) -> Option<u64> {
        match (
            self.t_outbound_connect_complete,
            self.t_first_outbound_write,
        ) {
            (Some(a), Some(b)) => Some(b.duration_since(a).as_micros() as u64),
            _ => None,
        }
    }
    pub fn delta_outbound_write_to_upstream_resp(&self) -> Option<u64> {
        match (self.t_first_outbound_write, self.t_first_upstream_response) {
            (Some(a), Some(b)) => Some(b.duration_since(a).as_micros() as u64),
            _ => None,
        }
    }
    pub fn delta_upstream_resp_to_client_write(&self) -> Option<u64> {
        match (self.t_first_upstream_response, self.t_first_client_write) {
            (Some(a), Some(b)) => Some(b.duration_since(a).as_micros() as u64),
            _ => None,
        }
    }
    pub fn delta_client_write_to_finish(&self) -> Option<u64> {
        match (self.t_first_client_write, self.t_finish) {
            (Some(a), Some(b)) => Some(b.duration_since(a).as_micros() as u64),
            _ => None,
        }
    }
    pub fn total_ttfb_us(&self) -> Option<u64> {
        self.t_first_client_write
            .map(|t| t.duration_since(self.t_accept).as_micros() as u64)
    }
    pub fn total_finish_us(&self) -> Option<u64> {
        self.t_finish
            .map(|t| t.duration_since(self.t_accept).as_micros() as u64)
    }
}
