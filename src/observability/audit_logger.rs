use chrono::Utc;
use serde::Serialize;
use std::fs::OpenOptions;
use std::io::Write;
use std::path::Path;
use tokio::sync::mpsc::{self, UnboundedSender};

#[derive(Debug, Clone, Serialize)]
pub struct AuditRecord {
    #[serde(rename = "time")]
    pub timestamp: String,
    pub node_id: u32,
    pub user_id: u32,
    pub protocol: String,
    pub network: String,
    pub client_ip: String,
    pub target_host: String,
    #[serde(default)]
    pub target_ip: String,
    pub target_port: u16,
    #[serde(default)]
    pub target: String,
    #[serde(default)]
    pub original_target: String,
    #[serde(default)]
    pub path: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub duration_ms: i64,
    pub outbound: String,
    pub status: String,
    #[serde(default)]
    pub source: String,
}

impl AuditRecord {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        node_id: u32,
        user_id: u32,
        protocol: &str,
        network: &str,
        client_ip: &str,
        target_host: &str,
        target_port: u16,
        upload_bytes: u64,
        download_bytes: u64,
        duration_ms: i64,
        outbound: &str,
        status: &str,
    ) -> Self {
        let target = format!("{}:{}", target_host, target_port);
        Self {
            timestamp: Utc::now().to_rfc3339(),
            node_id,
            user_id,
            protocol: protocol.to_string(),
            network: network.to_string(),
            client_ip: client_ip.to_string(),
            target_host: target_host.to_string(),
            target_ip: target_host.to_string(),
            target_port,
            target: target.clone(),
            original_target: target,
            path: String::new(),
            upload_bytes,
            download_bytes,
            duration_ms,
            outbound: outbound.to_string(),
            status: status.to_string(),
            source: "client".to_string(),
        }
    }
}

impl Default for AuditRecord {
    fn default() -> Self {
        Self {
            timestamp: Utc::now().to_rfc3339(),
            node_id: 0,
            user_id: 0,
            protocol: String::new(),
            network: "tcp".to_string(),
            client_ip: String::new(),
            target_host: String::new(),
            target_ip: String::new(),
            target_port: 0,
            target: String::new(),
            original_target: String::new(),
            path: String::new(),
            upload_bytes: 0,
            download_bytes: 0,
            duration_ms: 0,
            outbound: "direct".to_string(),
            status: "connected".to_string(),
            source: "local".to_string(),
        }
    }
}

#[derive(Clone)]
pub struct AuditLogger {
    tx: Option<UnboundedSender<AuditRecord>>,
}

impl AuditLogger {
    pub fn new<P: AsRef<Path>>(file_path: Option<P>) -> Self {
        if let Some(path) = file_path {
            let path_buf = path.as_ref().to_path_buf();
            if let Some(parent) = path_buf.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            let (tx, mut rx) = mpsc::unbounded_channel::<AuditRecord>();
            tokio::spawn(async move {
                while let Some(record) = rx.recv().await {
                    if let Ok(json_line) = serde_json::to_string(&record) {
                        if let Ok(mut file) =
                            OpenOptions::new().create(true).append(true).open(&path_buf)
                        {
                            let _ = writeln!(file, "{}", json_line);
                        }
                    }
                }
            });

            Self { tx: Some(tx) }
        } else {
            Self { tx: None }
        }
    }

    pub fn record(&self, mut record: AuditRecord) {
        if record.timestamp.is_empty() {
            record.timestamp = Utc::now().to_rfc3339();
        }
        if record.target.is_empty() {
            record.target = format!("{}:{}", record.target_host, record.target_port);
        }
        if record.original_target.is_empty() {
            record.original_target = record.target.clone();
        }
        if record.target_ip.is_empty() {
            record.target_ip = record.target_host.clone();
        }
        if record.source.is_empty() {
            record.source = "client".to_string();
        }
        if let Some(tx) = &self.tx {
            let _ = tx.send(record);
        }
    }
}
