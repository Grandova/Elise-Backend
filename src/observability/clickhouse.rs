use crate::observability::AuditRecord;
use std::time::Duration;
use tokio::sync::mpsc::{self, UnboundedSender};
use tracing::error;

#[derive(Clone)]
pub struct ClickHouseLogger {
    tx: Option<UnboundedSender<AuditRecord>>,
}

impl ClickHouseLogger {
    pub fn new(
        enabled: bool,
        addr: String,
        db: String,
        table: String,
        user: String,
        password: Option<String>,
    ) -> Self {
        if !enabled {
            return Self { tx: None };
        }

        let (tx, mut rx) = mpsc::unbounded_channel::<AuditRecord>();
        let client = reqwest::Client::new();
        let target_url = format!(
            "{}/?database={}&query=INSERT%20INTO%20{}%20FORMAT%20JSONEachRow",
            addr, db, table
        );

        tokio::spawn(async move {
            let mut batch = Vec::new();
            let mut interval = tokio::time::interval(Duration::from_secs(5));

            loop {
                tokio::select! {
                    Some(record) = rx.recv() => {
                        batch.push(record);
                        if batch.len() >= 500 {
                            Self::flush(&client, &target_url, &user, password.as_deref(), &mut batch).await;
                        }
                    }
                    _ = interval.tick() => {
                        if !batch.is_empty() {
                            Self::flush(&client, &target_url, &user, password.as_deref(), &mut batch).await;
                        }
                    }
                }
            }
        });

        Self { tx: Some(tx) }
    }

    async fn flush(
        client: &reqwest::Client,
        url: &str,
        user: &str,
        password: Option<&str>,
        batch: &mut Vec<AuditRecord>,
    ) {
        let mut body = String::new();
        for rec in batch.drain(..) {
            if let Ok(line) = serde_json::to_string(&rec) {
                body.push_str(&line);
                body.push('\n');
            }
        }

        let mut req = client.post(url).body(body);
        if !user.is_empty() {
            req = req.header("X-ClickHouse-User", user);
        }
        if let Some(pwd) = password {
            req = req.header("X-ClickHouse-Key", pwd);
        }

        if let Err(e) = req.send().await {
            error!("ClickHouse flush error: {:?}", e);
        }
    }

    pub fn record(&self, record: AuditRecord) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(record);
        }
    }
}
