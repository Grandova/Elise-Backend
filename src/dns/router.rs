use crate::dns::resolver::DNSResolver;
use crate::dns::rules::DnsRulesTable;
use parking_lot::RwLock;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::time::{sleep, Duration};
use tracing::{info, warn};

#[derive(Clone)]
pub struct RuleBasedDNSManager {
    resolver: Arc<DNSResolver>,
    dns_file: PathBuf,
    last_mtime: Arc<RwLock<Option<SystemTime>>>,
}

impl RuleBasedDNSManager {
    /// Create a new RuleBasedDNSManager with configuration and auto-start 10s hot reload.
    pub fn new(
        strategy: &str,
        cache_time_minutes: u64,
        default_dns: Option<&str>,
        dns_file: PathBuf,
    ) -> Self {
        let resolver = Arc::new(DNSResolver::new(strategy, cache_time_minutes, default_dns));

        let mgr = Self {
            resolver,
            dns_file,
            last_mtime: Arc::new(RwLock::new(None)),
        };

        // Perform initial load if file exists
        mgr.check_and_reload();

        // Spawn background file watcher task (10 seconds interval)
        let watcher_mgr = mgr.clone();
        tokio::spawn(async move {
            watcher_mgr.run_file_watcher().await;
        });

        mgr
    }

    pub fn resolver(&self) -> Arc<DNSResolver> {
        self.resolver.clone()
    }

    /// Explicitly reload DNS rules from content
    pub fn reload_content(&self, content: &str) -> Result<(), String> {
        let table = DnsRulesTable::parse_yaml(content)?;
        self.resolver.set_rules_table(Some(table));
        Ok(())
    }

    fn check_and_reload(&self) {
        if !self.dns_file.exists() {
            // File does not exist, ensure rules table is None
            if self.last_mtime.read().is_some() {
                *self.last_mtime.write() = None;
                self.resolver.set_rules_table(None);
                info!("DNS rules file removed; reverted to default/system DNS");
            }
            return;
        }

        let mtime = fs::metadata(&self.dns_file)
            .and_then(|m| m.modified())
            .ok();

        let changed = {
            let last = self.last_mtime.read();
            *last != mtime
        };

        if !changed {
            return;
        }

        *self.last_mtime.write() = mtime;

        match fs::read_to_string(&self.dns_file) {
            Ok(content) => match DnsRulesTable::parse_yaml(&content) {
                Ok(table) => {
                    info!(
                        "Successfully loaded/reloaded DNS rules from {} ({} rules compiled)",
                        self.dns_file.display(),
                        table.rules.len()
                    );
                    self.resolver.set_rules_table(Some(table));
                }
                Err(e) => {
                    warn!(
                        "Failed to parse DNS rules file {}: {}. Safely falling back to default/system DNS.",
                        self.dns_file.display(),
                        e
                    );
                    // Safe degradation: empty rules fallback
                    self.resolver.set_rules_table(None);
                }
            },
            Err(e) => {
                warn!(
                    "Failed to read DNS rules file {}: {}. Falling back to default/system DNS.",
                    self.dns_file.display(),
                    e
                );
                self.resolver.set_rules_table(None);
            }
        }
    }

    async fn run_file_watcher(&self) {
        loop {
            sleep(Duration::from_secs(10)).await;
            self.check_and_reload();
        }
    }
}

