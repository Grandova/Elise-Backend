use crate::panel::types::NodeStatusReport;
use parking_lot::Mutex;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use sysinfo::{Disks, System};

#[derive(Clone)]
pub struct SystemCollector {
    sys: Arc<Mutex<System>>,
    last_collect_time: Arc<Mutex<Instant>>,
    last_in_bytes: Arc<AtomicU64>,
    last_out_bytes: Arc<AtomicU64>,
    active_connections: Arc<AtomicU32>,
    total_connections: Arc<AtomicU64>,
    cumulative_in_bytes: Arc<AtomicU64>,
    cumulative_out_bytes: Arc<AtomicU64>,
}

impl Default for SystemCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemCollector {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        Self {
            sys: Arc::new(Mutex::new(sys)),
            last_collect_time: Arc::new(Mutex::new(Instant::now())),
            last_in_bytes: Arc::new(AtomicU64::new(0)),
            last_out_bytes: Arc::new(AtomicU64::new(0)),
            active_connections: Arc::new(AtomicU32::new(0)),
            total_connections: Arc::new(AtomicU64::new(0)),
            cumulative_in_bytes: Arc::new(AtomicU64::new(0)),
            cumulative_out_bytes: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn inc_connection(&self) {
        self.total_connections.fetch_add(1, Ordering::Relaxed);
        self.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_connection(&self) {
        let _ = self
            .active_connections
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                Some(v.saturating_sub(1))
            });
    }

    pub fn add_traffic(&self, in_bytes: u64, out_bytes: u64) {
        self.cumulative_in_bytes
            .fetch_add(in_bytes, Ordering::Relaxed);
        self.cumulative_out_bytes
            .fetch_add(out_bytes, Ordering::Relaxed);
    }

    pub fn collect(&self, total_users: u32, active_users: u32) -> NodeStatusReport {
        let now = Instant::now();
        let (cpu, mem_total, mem_used, swap_total, swap_used, uptime) = {
            let mut sys = self.sys.lock();
            sys.refresh_cpu();
            sys.refresh_memory();
            let cpu = sys.global_cpu_info().cpu_usage() as f64;
            let mem_total = sys.total_memory();
            let mem_used = sys.used_memory();
            let swap_total = sys.total_swap();
            let swap_used = sys.used_swap();
            let uptime = System::uptime();
            (cpu, mem_total, mem_used, swap_total, swap_used, uptime)
        };

        let disks = Disks::new_with_refreshed_list();
        let mut disk_total = 0u64;
        let mut disk_used = 0u64;
        for disk in &disks {
            let t = disk.total_space();
            let a = disk.available_space();
            disk_total += t;
            disk_used += t.saturating_sub(a);
        }

        let mut last_time = self.last_collect_time.lock();
        let elapsed_secs = now.duration_since(*last_time).as_secs_f64().max(1.0);
        *last_time = now;

        let cur_in = self.cumulative_in_bytes.load(Ordering::Relaxed);
        let cur_out = self.cumulative_out_bytes.load(Ordering::Relaxed);

        let prev_in = self.last_in_bytes.swap(cur_in, Ordering::Relaxed);
        let prev_out = self.last_out_bytes.swap(cur_out, Ordering::Relaxed);

        let in_speed = ((cur_in.saturating_sub(prev_in)) as f64 / elapsed_secs) as u64;
        let out_speed = ((cur_out.saturating_sub(prev_out)) as f64 / elapsed_secs) as u64;

        let active_conn = self.active_connections.load(Ordering::Relaxed);
        let total_conn = self.total_connections.load(Ordering::Relaxed);

        let tasks_count = std::thread::available_parallelism()
            .map(|n| n.get() as u32 * 4)
            .unwrap_or(16)
            + active_conn;

        let kernel_status = Self::check_kernel_status();

        NodeStatusReport {
            cpu: (cpu * 10.0).round() / 10.0,
            mem_total,
            mem_used,
            swap_total,
            swap_used,
            disk_total,
            disk_used,
            uptime,
            active_connections: active_conn,
            total_connections: total_conn,
            total_users,
            active_users,
            in_speed,
            out_speed,
            tasks_count,
            kernel_status,
        }
    }

    fn check_kernel_status() -> bool {
        #[cfg(target_os = "linux")]
        {
            if let Ok(content) =
                std::fs::read_to_string("/proc/sys/net/ipv4/tcp_congestion_control")
            {
                if content.trim() == "bbr" {
                    return true;
                }
            }
            if let Ok(content) = std::fs::read_to_string("/proc/sys/net/mptcp/enabled") {
                if content.trim() == "1" {
                    return true;
                }
            }
        }
        true
    }
}
