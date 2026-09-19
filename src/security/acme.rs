use parking_lot::RwLock;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tracing::{error, info, warn};

use crate::config::node::NodeConfig;
use crate::panel::types::NodeInfo;

#[derive(Debug, Clone)]
pub struct AcmeConfig {
    pub domain: String,
    pub cert_mode: String,
    pub cert_key_length: String,
    pub acme_server: String,
    pub acme_email: Option<String>,
    pub cert_file: PathBuf,
    pub key_file: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CertStatus {
    Valid { not_after: i64 },
    NeedRenewal { not_after: i64 },
    Missing,
    Invalid(String),
}

/// Checks the expiration time of the certificate at `cert_path`.
/// If valid for more than `renew_before_days` days, returns `CertStatus::Valid`.
pub fn check_cert_validity(cert_path: &Path, renew_before_days: u64) -> CertStatus {
    if !cert_path.exists() {
        return CertStatus::Missing;
    }

    let pem_data = match std::fs::read_to_string(cert_path) {
        Ok(data) => data,
        Err(e) => return CertStatus::Invalid(format!("failed to read certificate: {e}")),
    };

    let (_, pem) = match x509_parser::pem::parse_x509_pem(pem_data.as_bytes()) {
        Ok(res) => res,
        Err(e) => return CertStatus::Invalid(format!("PEM parse error: {e}")),
    };

    let (_, cert) = match x509_parser::parse_x509_certificate(&pem.contents) {
        Ok(res) => res,
        Err(e) => return CertStatus::Invalid(format!("X.509 parse error: {e}")),
    };

    let not_after = cert.validity().not_after.timestamp();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    let renew_seconds = (renew_before_days as i64) * 86400;
    if not_after - now > renew_seconds {
        CertStatus::Valid { not_after }
    } else {
        CertStatus::NeedRenewal { not_after }
    }
}

/// Embedded HTTP-01 challenge responder for ACME verification on port 80.
struct Http01ChallengeServer {
    tokens: Arc<RwLock<HashMap<String, String>>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl Http01ChallengeServer {
    pub async fn start() -> Result<Self, String> {
        let tokens = Arc::new(RwLock::new(HashMap::<String, String>::new()));
        let listener = match TcpListener::bind("0.0.0.0:80").await {
            Ok(l) => l,
            Err(e) => {
                error!(
                    "ACME HTTP-01: Failed to bind port 80 (0.0.0.0:80): {}. \
                    Let's Encrypt HTTP-01 challenge requires incoming access on port 80.",
                    e
                );
                return Err(format!("Cannot bind port 80 for HTTP-01 challenge: {e}"));
            }
        };

        info!("ACME HTTP-01 challenge responder listening on 0.0.0.0:80");

        let (shutdown_tx, _) = broadcast::channel(1);
        let mut shutdown_rx = shutdown_tx.subscribe();
        let tokens_clone = tokens.clone();

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        info!("ACME HTTP-01 challenge server stopping");
                        break;
                    }
                    accept_res = listener.accept() => {
                        let (mut stream, remote_addr) = match accept_res {
                            Ok(res) => res,
                            Err(_) => continue,
                        };
                        let tokens = tokens_clone.clone();

                        tokio::spawn(async move {
                            let mut buf = [0u8; 2048];
                            let n = match stream.read(&mut buf).await {
                                Ok(n) if n > 0 => n,
                                _ => return,
                            };

                            let req_str = String::from_utf8_lossy(&buf[..n]);
                            let first_line = req_str.lines().next().unwrap_or("");
                            let mut parts = first_line.split_whitespace();
                            let method = parts.next().unwrap_or("");
                            let path = parts.next().unwrap_or("");

                            if method == "GET" && path.starts_with("/.well-known/acme-challenge/") {
                                let token = path.trim_start_matches("/.well-known/acme-challenge/");
                                let key_auth_opt = tokens.read().get(token).cloned();
                                if let Some(key_auth) = key_auth_opt {
                                    info!(
                                        remote = %remote_addr,
                                        token = %token,
                                        "ACME HTTP-01 challenge matched and responded successfully"
                                    );
                                    let resp = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                                        key_auth.len(),
                                        key_auth
                                    );
                                    let _ = stream.write_all(resp.as_bytes()).await;
                                    let _ = stream.flush().await;
                                    return;
                                }
                            }

                            // Return 404 for non-challenge requests
                            let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                            let _ = stream.write_all(not_found.as_bytes()).await;
                            let _ = stream.flush().await;
                        });
                    }
                }
            }
        });

        Ok(Self {
            tokens,
            shutdown_tx,
        })
    }

    pub fn add_token(&self, token: String, key_auth: String) {
        self.tokens.write().insert(token, key_auth);
    }

    pub fn stop(self) {
        let _ = self.shutdown_tx.send(());
    }
}

/// Requests a new certificate from Let's Encrypt / ZeroSSL via ACME HTTP-01.
pub async fn obtain_certificate(config: &AcmeConfig) -> Result<(), String> {
    info!(
        domain = %config.domain,
        server = %config.acme_server,
        key_length = %config.cert_key_length,
        cert_file = %config.cert_file.display(),
        key_file = %config.key_file.display(),
        "Starting ACME certificate request via HTTP-01"
    );

    let dir_url = match config.acme_server.to_ascii_lowercase().as_str() {
        "letsencrypt" | "le" | "lets_encrypt" | "production" => {
            instant_acme::LetsEncrypt::Production.url().to_string()
        }
        "letsencrypt_staging" | "staging" => instant_acme::LetsEncrypt::Staging.url().to_string(),
        "zerossl" => instant_acme::ZeroSsl::Production.url().to_string(),
        other => {
            if other.starts_with("http://") || other.starts_with("https://") {
                other.to_string()
            } else {
                instant_acme::LetsEncrypt::Production.url().to_string()
            }
        }
    };

    let email = config
        .acme_email
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|e| format!("mailto:{e}"))
        .unwrap_or_else(|| format!("mailto:admin@{}", config.domain));

    let contact = [email.as_str()];

    let (account, _) = instant_acme::Account::builder()
        .map_err(|e| format!("ACME builder error: {e}"))?
        .create(
            &instant_acme::NewAccount {
                contact: &contact,
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            dir_url,
            None,
        )
        .await
        .map_err(|e| format!("ACME account registration failed: {e}"))?;

    let identifier = instant_acme::Identifier::Dns(config.domain.clone());
    let mut order = account
        .new_order(&instant_acme::NewOrder::new(&[identifier]))
        .await
        .map_err(|e| format!("ACME new order failed: {e}"))?;

    // Start challenge server
    let challenge_server = Http01ChallengeServer::start().await?;
    tokio::time::sleep(Duration::from_millis(300)).await;

    let mut authorizations = order.authorizations();
    while let Some(authz_res) = authorizations.next().await {
        let mut authz = authz_res.map_err(|e| format!("ACME authorization error: {e}"))?;
        if authz.status == instant_acme::AuthorizationStatus::Valid {
            continue;
        }
        let mut challenge = authz
            .challenge(instant_acme::ChallengeType::Http01)
            .ok_or_else(|| "No HTTP-01 challenge found in ACME order".to_string())?;

        let token = challenge.token.clone();
        let key_auth = challenge.key_authorization().as_str().to_string();
        challenge_server.add_token(token, key_auth);

        challenge
            .set_ready()
            .await
            .map_err(|e| format!("Failed to set ACME challenge ready: {e}"))?;
    }

    let retry_policy = instant_acme::RetryPolicy::new()
        .initial_delay(Duration::from_millis(500))
        .backoff(1.5)
        .timeout(Duration::from_secs(60));

    let status = order
        .poll_ready(&retry_policy)
        .await
        .map_err(|e| format!("ACME poll order ready failed: {e}"))?;

    challenge_server.stop();

    if status != instant_acme::OrderStatus::Ready {
        return Err(format!("ACME order ended in unexpected status: {status:?}"));
    }

    // Generate cryptographic key pair according to configured key length
    let key_alg = match config.cert_key_length.to_ascii_lowercase().as_str() {
        "ec-384" | "p384" | "p-384" => &rcgen::PKCS_ECDSA_P384_SHA384,
        "rsa-2048" | "2048" | "rsa" => &rcgen::PKCS_RSA_SHA256,
        "rsa-4096" | "4096" => &rcgen::PKCS_RSA_SHA512,
        _ => &rcgen::PKCS_ECDSA_P256_SHA256,
    };

    let key_pair = rcgen::KeyPair::generate_for(key_alg)
        .map_err(|e| format!("Failed to generate private key: {e}"))?;

    let mut params = rcgen::CertificateParams::new(vec![config.domain.clone()])
        .map_err(|e| format!("Failed to create certificate params: {e}"))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, config.domain.clone());
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|e| format!("Failed to generate CSR: {e}"))?;

    let csr_der = csr.der();
    if csr_der
        .windows(b"rcgen self signed cert".len())
        .any(|window| window == b"rcgen self signed cert")
    {
        return Err("Generated CSR unexpectedly contains default rcgen subject name".to_string());
    }

    info!(
        domain = %config.domain,
        "ACME order finalizing with clean CSR (CN = domain, SAN = [domain])"
    );

    order
        .finalize_csr(csr_der)
        .await
        .map_err(|e| format!("ACME finalize CSR failed: {e}"))?;

    let retry_policy = instant_acme::RetryPolicy::new()
        .initial_delay(Duration::from_millis(500))
        .backoff(1.5)
        .timeout(Duration::from_secs(60));

    let cert_chain_pem = order
        .poll_certificate(&retry_policy)
        .await
        .map_err(|e| format!("ACME poll certificate failed: {e}"))?;

    let private_key_pem = key_pair.serialize_pem();

    // Ensure target directories exist and write files
    if let Some(parent) = config.cert_file.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                format!("Failed to create cert directory {}: {e}", parent.display())
            })?;
        }
    }
    if let Some(parent) = config.key_file.parent() {
        if !parent.as_os_str().is_empty() {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|e| format!("Failed to create key directory {}: {e}", parent.display()))?;
        }
    }

    tokio::fs::write(&config.cert_file, cert_chain_pem.as_bytes())
        .await
        .map_err(|e| {
            format!(
                "Failed to write cert_file {}: {e}",
                config.cert_file.display()
            )
        })?;

    tokio::fs::write(&config.key_file, private_key_pem.as_bytes())
        .await
        .map_err(|e| {
            format!(
                "Failed to write key_file {}: {e}",
                config.key_file.display()
            )
        })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&config.key_file, std::fs::Permissions::from_mode(0o600));
    }

    info!(
        cert_file = %config.cert_file.display(),
        key_file = %config.key_file.display(),
        "ACME certificate and private key issued and saved successfully"
    );

    Ok(())
}

/// Ensures that a valid ACME certificate exists for the node.
/// Evaluates user-configured paths (never hardcoded), checks certificate validity,
/// requests a new certificate if needed, and updates `NodeConfig` with the actual file paths.
pub async fn ensure_acme_certificate(
    node_cfg: &mut NodeConfig,
    node_info: &NodeInfo,
) -> Result<AcmeConfig, String> {
    // 1. Determine domain
    let domain = node_cfg
        .cert_domain
        .clone()
        .or_else(|| node_info.server_name.clone())
        .or_else(|| node_info.host.clone())
        .or_else(|| {
            node_info
                .tls_settings
                .as_ref()
                .and_then(|ts| ts.get("server_name"))
                .and_then(|v| v.as_str())
                .map(String::from)
        })
        .ok_or_else(|| {
            "ACME is enabled (cert_mode = http), but no domain specified in cert_domain or panel server_name".to_string()
        })?;

    // 2. Determine cert_file and key_file from user configuration.
    // If not specified, dynamically compute sensible defaults based on domain and environment.
    let cert_file = match &node_cfg.cert_file {
        Some(path) => crate::config::node::normalize_cert_path(path),
        None => {
            if Path::new("/etc/elise").exists() {
                PathBuf::from(format!("/etc/elise/cert/{domain}.crt"))
            } else {
                PathBuf::from(format!("./cert/{domain}.crt"))
            }
        }
    };

    let key_file = match &node_cfg.key_file {
        Some(path) => crate::config::node::normalize_cert_path(path),
        None => {
            if Path::new("/etc/elise").exists() {
                PathBuf::from(format!("/etc/elise/cert/{domain}.key"))
            } else {
                PathBuf::from(format!("./cert/{domain}.key"))
            }
        }
    };

    let cert_key_length = node_cfg
        .cert_key_length
        .clone()
        .unwrap_or_else(|| "ec-256".to_string());

    let acme_server = node_cfg
        .acme_server
        .clone()
        .unwrap_or_else(|| "letsencrypt".to_string());

    let acme_config = AcmeConfig {
        domain,
        cert_mode: node_cfg
            .cert_mode
            .clone()
            .unwrap_or_else(|| "http".to_string()),
        cert_key_length,
        acme_server,
        acme_email: node_cfg.acme_email.clone(),
        cert_file: cert_file.clone(),
        key_file: key_file.clone(),
    };

    // Update node_cfg so prepare_node_info and subsequent logic knows the exact paths
    node_cfg.cert_file = Some(cert_file.clone());
    node_cfg.key_file = Some(key_file.clone());
    if node_cfg.cert_domain.is_none() {
        node_cfg.cert_domain = Some(acme_config.domain.clone());
    }

    // 3. Check certificate validity (renew if less than 30 days remaining)
    match check_cert_validity(&cert_file, 30) {
        CertStatus::Valid { not_after } => {
            info!(
                domain = %acme_config.domain,
                cert_file = %cert_file.display(),
                not_after = not_after,
                "Existing ACME certificate is valid (expires in > 30 days), skipping renewal"
            );
            Ok(acme_config)
        }
        status => {
            warn!(
                domain = %acme_config.domain,
                cert_file = %cert_file.display(),
                status = ?status,
                "Certificate missing, invalid, or expiring within 30 days; obtaining new certificate via ACME"
            );
            obtain_certificate(&acme_config).await?;
            Ok(acme_config)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, KeyPair};
    use std::fs;
    use x509_parser::prelude::FromDer;

    #[test]
    fn test_check_cert_validity_missing() {
        let p = Path::new("non_existent_cert_path_99999.crt");
        assert_eq!(check_cert_validity(p, 30), CertStatus::Missing);
    }

    #[test]
    fn test_check_cert_validity_invalid_content() {
        let dir = std::env::temp_dir().join(format!("elise-acme-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("invalid.crt");
        fs::write(&cert_path, "not a pem certificate").unwrap();

        match check_cert_validity(&cert_path, 30) {
            CertStatus::Invalid(_) => {}
            other => panic!("Expected CertStatus::Invalid, got {:?}", other),
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_check_cert_validity_valid_cert() {
        let dir = std::env::temp_dir().join(format!("elise-acme-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("valid.crt");

        let params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        fs::write(&cert_path, cert.pem()).unwrap();

        match check_cert_validity(&cert_path, 30) {
            CertStatus::Valid { not_after } => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                assert!(not_after > now + 30 * 86400);
            }
            other => panic!("Expected CertStatus::Valid, got {:?}", other),
        }

        // A huge renew_before_days (e.g., 1000000 days, > 2700 years) triggers NeedRenewal
        match check_cert_validity(&cert_path, 1_000_000) {
            CertStatus::NeedRenewal { not_after } => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs() as i64;
                assert!(not_after > now);
            }
            other => panic!("Expected CertStatus::NeedRenewal, got {:?}", other),
        }

        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn test_ensure_acme_certificate_skips_when_valid() {
        let dir = std::env::temp_dir().join(format!("elise-acme-test-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("my_cert.crt");
        let key_path = dir.join("my_cert.key");

        let params = CertificateParams::new(vec!["ft.nksea.com".to_string()]).unwrap();
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        fs::write(&cert_path, cert.pem()).unwrap();
        fs::write(&key_path, key_pair.serialize_pem()).unwrap();

        let mut node_cfg = NodeConfig {
            node_id: 32,
            cert_domain: Some("ft.nksea.com".to_string()),
            cert_mode: Some("http".to_string()),
            cert_file: Some(cert_path.clone()),
            key_file: Some(key_path.clone()),
            ..Default::default()
        };

        let node_info = NodeInfo {
            id: 32,
            node_type: "anytls".to_string(),
            server_port: 8000,
            server_name: Some("ft.nksea.com".to_string()),
            tls: Some(1),
            ..Default::default()
        };

        let result = ensure_acme_certificate(&mut node_cfg, &node_info).await;
        assert!(
            result.is_ok(),
            "ensure_acme_certificate failed: {:?}",
            result.err()
        );
        let acme_cfg = result.unwrap();
        assert_eq!(acme_cfg.domain, "ft.nksea.com");
        assert_eq!(acme_cfg.cert_file, cert_path);
        assert_eq!(acme_cfg.key_file, key_path);

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn test_acme_csr_does_not_contain_rcgen_default_cn() {
        let domain = "ft.nksea.com";
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()]).unwrap();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, domain.to_string());
        let csr = params.serialize_request(&key_pair).unwrap();
        let pem = csr.pem().unwrap();
        assert!(
            !pem.contains("rcgen self signed cert"),
            "CSR PEM must not contain rcgen self signed cert"
        );

        let csr_der = csr.der();
        assert!(
            !csr_der
                .windows(b"rcgen self signed cert".len())
                .any(|w| w == b"rcgen self signed cert"),
            "CSR DER must not contain rcgen default CN"
        );

        // Verify subject contains the real domain
        let (_, parsed_csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(
                csr_der.as_ref(),
            )
            .expect("Failed to parse generated CSR DER");
        let subject = parsed_csr.certification_request_info.subject.to_string();
        assert!(
            subject.contains("ft.nksea.com"),
            "Subject should contain domain ft.nksea.com: {}",
            subject
        );
        assert!(
            !subject.contains("rcgen self signed cert"),
            "Subject must not contain rcgen self signed cert: {}",
            subject
        );
    }

    #[tokio::test]
    async fn test_ensure_acme_certificate_normalizes_typo_path() {
        let mut node_cfg = NodeConfig {
            node_id: 32,
            cert_domain: Some("ft.nksea.com".to_string()),
            cert_mode: Some("http".to_string()),
            // Intentionally provide path with /etc/eslise/ typo
            cert_file: Some(PathBuf::from("/etc/eslise/my_cert.crt")),
            key_file: Some(PathBuf::from("/etc/eslise/my_cert.key")),
            ..Default::default()
        };

        let node_info = NodeInfo {
            id: 32,
            node_type: "anytls".to_string(),
            server_port: 8000,
            server_name: Some("ft.nksea.com".to_string()),
            tls: Some(1),
            ..Default::default()
        };

        // When normalizing, check_cert_validity will be called on /etc/elise/my_cert.crt
        // Even if obtain_certificate fails (in test environment without port 80 / LE server),
        // node_cfg cert_file/key_file must be normalized to /etc/elise/...
        let _ = ensure_acme_certificate(&mut node_cfg, &node_info).await;
        assert_eq!(
            node_cfg.cert_file,
            Some(PathBuf::from("/etc/elise/my_cert.crt"))
        );
        assert_eq!(
            node_cfg.key_file,
            Some(PathBuf::from("/etc/elise/my_cert.key"))
        );
    }
}
