use parking_lot::RwLock;
use rcgen::{CertificateParams, KeyPair};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer,
};
use rustls::server::ResolvesServerCertUsingSni;
use rustls::sign::CertifiedKey;
use rustls::ServerConfig;
use std::fs;
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::server::TlsStream;
use tokio_rustls::TlsAcceptor;

use crate::transport::types::TlsServerConfig;

/// Parses all PEM-encoded certificates (X.509) from the input string.
pub fn parse_pem_certificates(pem_data: &str) -> Result<Vec<CertificateDer<'static>>, String> {
    let mut certs = Vec::new();
    let mut in_cert = false;
    let mut b64_buf = String::new();

    for line in pem_data.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN CERTIFICATE-----")
            || trimmed.starts_with("-----BEGIN X509 CERTIFICATE-----")
        {
            in_cert = true;
            b64_buf.clear();
        } else if trimmed.starts_with("-----END CERTIFICATE-----")
            || trimmed.starts_with("-----END X509 CERTIFICATE-----")
        {
            if in_cert {
                let der = base64_decode_clean(&b64_buf)
                    .map_err(|e| format!("failed to decode base64 certificate DER: {e}"))?;
                certs.push(CertificateDer::from(der));
                in_cert = false;
                b64_buf.clear();
            }
        } else if in_cert {
            b64_buf.push_str(trimmed);
        }
    }

    if certs.is_empty() {
        return Err(
            "no valid PEM certificate blocks (-----BEGIN CERTIFICATE-----) found".to_string(),
        );
    }
    Ok(certs)
}

/// Parses a private key from PEM data. Supports PKCS#8, PKCS#1 (RSA), and SEC1 (EC).
pub fn parse_pem_private_key(pem_data: &str) -> Result<PrivateKeyDer<'static>, String> {
    let mut in_key = false;
    let mut key_type = "";
    let mut b64_buf = String::new();

    for line in pem_data.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("-----BEGIN ") && trimmed.ends_with("-----") {
            let label = trimmed
                .trim_start_matches("-----BEGIN ")
                .trim_end_matches("-----")
                .trim();
            if label == "PRIVATE KEY"
                || label == "PKCS8 PRIVATE KEY"
                || label == "RSA PRIVATE KEY"
                || label == "EC PRIVATE KEY"
            {
                in_key = true;
                key_type = match label {
                    "PRIVATE KEY" | "PKCS8 PRIVATE KEY" => "pkcs8",
                    "RSA PRIVATE KEY" => "pkcs1",
                    "EC PRIVATE KEY" => "sec1",
                    _ => "pkcs8",
                };
                b64_buf.clear();
            }
        } else if trimmed.starts_with("-----END ") && trimmed.ends_with("-----") {
            if in_key {
                let der = base64_decode_clean(&b64_buf)
                    .map_err(|e| format!("failed to decode base64 private key DER: {e}"))?;
                let key_der = match key_type {
                    "pkcs8" => PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(der)),
                    "pkcs1" => PrivateKeyDer::Pkcs1(PrivatePkcs1KeyDer::from(der)),
                    "sec1" => PrivateSec1KeyDer::from(der).into(),
                    _ => return Err(format!("unknown private key type: {key_type}")),
                };
                return Ok(key_der);
            }
        } else if in_key {
            b64_buf.push_str(trimmed);
        }
    }

    Err("no supported PEM private key block found (PKCS#8, PKCS#1 RSA, or SEC1 EC)".to_string())
}

fn base64_decode_clean(b64: &str) -> Result<Vec<u8>, String> {
    use base64::Engine;
    let clean: String = b64.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD
        .decode(&clean)
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&clean))
        .map_err(|e| format!("base64 decode error: {e}"))
}

/// Loads certificates and private key from PEM string or file paths.
pub fn load_cert_and_key(
    cert_source: &str,
    key_source: &str,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), String> {
    let cert_pem =
        if cert_source.contains("BEGIN CERTIFICATE") || cert_source.contains("BEGIN X509") {
            cert_source.to_string()
        } else {
            fs::read_to_string(Path::new(cert_source))
                .map_err(|e| format!("failed to read certificate file '{cert_source}': {e}"))?
        };

    let key_pem = if key_source.contains("BEGIN ") && key_source.contains("PRIVATE KEY") {
        key_source.to_string()
    } else {
        fs::read_to_string(Path::new(key_source))
            .map_err(|e| format!("failed to read private key file '{key_source}': {e}"))?
    };

    let certs = parse_pem_certificates(&cert_pem)?;
    let key = parse_pem_private_key(&key_pem)?;
    Ok((certs, key))
}

/// Builds a verified `Arc<ServerConfig>` from `TlsServerConfig`.
/// Fails fast if any certificate or private key fails to parse, if the key does not match
/// the certificate, or if invalid ECH settings are provided.
pub fn build_server_config(
    config: &TlsServerConfig,
    auto_tls: bool,
    default_sni: &str,
) -> Result<Arc<ServerConfig>, String> {
    let mut ech_keys_parsed: Option<Arc<Vec<rustls::server::EchServerConfigAndKey>>> = None;

    // ECH verification & activation:
    if let Some(ech) = &config.ech {
        if ech.enabled {
            match &ech.server_keys {
                Some(keys) if !keys.is_empty() => {
                    let outer_sni = config.server_name.as_deref().unwrap_or(default_sni);
                    let ech_keypair =
                        crate::security::EchKeyPair::from_pem_or_bytes(keys, outer_sni)
                            .map_err(|e| format!("invalid ECH server_keys: {e}"))?;
                    tracing::info!(
                        "TLS Server ECH enabled: public_name='{}', config_id={}",
                        ech_keypair.public_name,
                        ech_keypair.config_id
                    );
                    ech_keys_parsed = Some(Arc::new(vec![ech_keypair.into_rustls()]));
                }
                _ => {
                    return Err(
                        "TLS Server ECH is enabled, but no ech_server_keys were provided. \
                         Cannot pretend server supports ECH without server keys. \
                         Rejecting invalid ECH configuration."
                            .to_string(),
                    );
                }
            }
        }
    }

    // ALPN protocols
    let alpn_protocols: Vec<Vec<u8>> = if !config.alpn.is_empty() {
        config.alpn.iter().map(|s| s.as_bytes().to_vec()).collect()
    } else {
        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
    };

    // Collect and validate all certificate entries
    let mut loaded_certs: Vec<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> = Vec::new();

    for entry in &config.certificates {
        let cert_source = entry
            .cert_pem
            .as_deref()
            .or_else(|| entry.cert_file.as_deref());
        let key_source = entry
            .key_pem
            .as_deref()
            .or_else(|| entry.key_file.as_deref());

        if let (Some(cs), Some(ks)) = (cert_source, key_source) {
            let (certs, key) = load_cert_and_key(cs, ks)?;
            loaded_certs.push((certs, key));
        }
    }

    // If no certificates were provided
    if loaded_certs.is_empty() {
        if auto_tls && config.allow_self_signed {
            let sni = config.server_name.as_deref().unwrap_or(default_sni);
            tracing::info!(
                "TLSManager: No certificates provided; generating 10-year self-signed ECDSA P-256 certificate for SNI '{}'",
                sni
            );
            let mut params = CertificateParams::new(vec![sni.to_string(), "localhost".to_string()])
                .map_err(|e| format!("failed to create self-signed cert params: {e}"))?;
            params.not_before = rcgen::date_time_ymd(2024, 1, 1);
            params.not_after = rcgen::date_time_ymd(2034, 1, 1);

            let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
                .map_err(|e| format!("failed to generate ECDSA keypair: {e}"))?;
            let cert = params
                .self_signed(&key_pair)
                .map_err(|e| format!("failed to sign self-signed cert: {e}"))?;

            let cert_der = CertificateDer::from(cert.der().to_vec());
            let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
            loaded_certs.push((vec![cert_der], key_der));
        } else {
            return Err(
                "TLS has no certificate: self-signed generation requires auto_tls=true and panel allow_insecure=true. \
                 Supply a trusted certificate when the client verifies certificates."
                    .to_string(),
            );
        }
    }

    // Build ServerConfig
    let mut server_config = if config.reject_unknown_sni {
        // SNI resolver with strict rejection of unknown SNIs
        let mut resolver = ResolvesServerCertUsingSni::new();

        let snis: Vec<&str> = if !config.server_names.is_empty() {
            config.server_names.iter().map(|s| s.as_str()).collect()
        } else if let Some(sn) = &config.server_name {
            vec![sn.as_str()]
        } else {
            vec![default_sni]
        };

        for (certs, key) in loaded_certs {
            let signing_key =
                rustls::crypto::ring::sign::any_supported_type(&key).map_err(|e| {
                    format!("private key verification failed (unsupported or invalid key): {e}")
                })?;
            let certified_key = CertifiedKey::new(certs, signing_key);

            for sni in &snis {
                resolver
                    .add(sni, certified_key.clone())
                    .map_err(|e| format!("failed to add certificate for SNI '{sni}': {e}"))?;
            }
        }

        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(resolver));
        cfg.alpn_protocols = alpn_protocols;
        cfg
    } else {
        // Single certificate or default fallback
        let (certs, key) = loaded_certs.into_iter().next().unwrap();
        let mut cfg = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|e| {
                format!(
                    "failed to configure TLS certificate (key/cert mismatch or invalid cert): {e}"
                )
            })?;
        cfg.alpn_protocols = alpn_protocols;
        cfg
    };

    if let Some(keys) = ech_keys_parsed {
        server_config.set_ech_server_keys(keys);
    }

    if std::env::var_os("SSLKEYLOGFILE").is_some() {
        server_config.key_log = Arc::new(rustls::KeyLogFile::new());
    }

    Ok(Arc::new(server_config))
}

#[derive(Clone)]
pub struct TLSManager {
    acceptor: Arc<RwLock<Option<TlsAcceptor>>>,
    current_config: Arc<RwLock<Option<TlsServerConfig>>>,
    auto_tls: bool,
    fake_sni: String,
}

impl TLSManager {
    pub fn new(auto_tls: bool, fake_sni: String) -> Self {
        let mgr = Self {
            acceptor: Arc::new(RwLock::new(None)),
            current_config: Arc::new(RwLock::new(None)),
            auto_tls,
            fake_sni,
        };

        if auto_tls {
            let _ = mgr.generate_self_signed();
        }

        mgr
    }

    /// Builds a TLSManager initialized directly from a `TlsServerConfig`.
    pub fn from_config(
        config: &TlsServerConfig,
        auto_tls: bool,
        fake_sni: &str,
    ) -> Result<Self, String> {
        let server_cfg = build_server_config(config, auto_tls, fake_sni)?;
        let acceptor = TlsAcceptor::from(server_cfg);

        Ok(Self {
            acceptor: Arc::new(RwLock::new(Some(acceptor))),
            current_config: Arc::new(RwLock::new(Some(config.clone()))),
            auto_tls,
            fake_sni: fake_sni.to_string(),
        })
    }

    pub fn get_acceptor(&self) -> Option<TlsAcceptor> {
        self.acceptor.read().clone()
    }

    pub fn is_auto_tls(&self) -> bool {
        self.auto_tls
    }

    pub fn generate_self_signed(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let mut params =
            CertificateParams::new(vec![self.fake_sni.clone(), "localhost".to_string()])?;
        // 10 years validity
        params.not_before = rcgen::date_time_ymd(2024, 1, 1);
        params.not_after = rcgen::date_time_ymd(2034, 1, 1);

        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
        let cert = params.self_signed(&key_pair)?;

        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        self.update_certificate(vec![cert_der], key_der)?;
        tracing::info!(
            "TLSManager: Generated 10-year self-signed ECDSA P-256 TLS certificate for SNI {}",
            self.fake_sni
        );
        Ok(())
    }

    pub fn update_certificate(
        &self,
        cert_ders: Vec<Vec<u8>>,
        key_der: Vec<u8>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let cert_chain: Vec<CertificateDer<'static>> =
            cert_ders.into_iter().map(CertificateDer::from).collect();

        let priv_key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

        let mut server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, priv_key)?;
        server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        *self.acceptor.write() = Some(acceptor);
        Ok(())
    }

    /// Atomically reloads TLS configuration without interrupting existing connections.
    pub fn reload_from_config(&self, config: &TlsServerConfig) -> Result<(), String> {
        let server_cfg = build_server_config(config, self.auto_tls, &self.fake_sni)?;
        let acceptor = TlsAcceptor::from(server_cfg);
        *self.acceptor.write() = Some(acceptor);
        *self.current_config.write() = Some(config.clone());
        tracing::info!("TLSManager: Hot reload of TLS server configuration completed successfully");
        Ok(())
    }

    /// Performs TLS server handshake with an explicit timeout.
    pub async fn accept_with_timeout<S>(
        &self,
        stream: S,
        timeout: Duration,
    ) -> io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let acceptor = self
            .get_acceptor()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "TLS acceptor not initialized"))?;

        match tokio::time::timeout(timeout, acceptor.accept(stream)).await {
            Ok(Ok(tls_stream)) => Ok(tls_stream),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "TLS server handshake timed out after {}s",
                    timeout.as_secs()
                ),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::types::{EchServerConfig, TlsCertificateEntry};

    #[test]
    fn test_parse_pem_and_build_server_config() {
        // Generate valid ECDSA cert and key via rcgen
        let mut params =
            CertificateParams::new(vec!["example.com".to_string(), "localhost".to_string()])
                .unwrap();
        params.not_before = rcgen::date_time_ymd(2025, 1, 1);
        params.not_after = rcgen::date_time_ymd(2026, 1, 1);
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let cert_pem = cert.pem();
        let key_pem = key_pair.serialize_pem();

        let cert_ders = parse_pem_certificates(&cert_pem).unwrap();
        assert_eq!(cert_ders.len(), 1);

        let priv_key = parse_pem_private_key(&key_pem).unwrap();
        assert!(matches!(priv_key, PrivateKeyDer::Pkcs8(_)));

        let cfg = TlsServerConfig {
            server_name: Some("example.com".to_string()),
            server_names: vec!["example.com".to_string()],
            allow_self_signed: true,
            reject_unknown_sni: false,
            certificates: vec![TlsCertificateEntry {
                cert_pem: Some(cert_pem),
                key_pem: Some(key_pem),
                cert_file: None,
                key_file: None,
            }],
            ech: None,
            alpn: vec!["h2".to_string(), "http/1.1".to_string()],
            cert_config: None,
        };

        let server_config = build_server_config(&cfg, false, "example.com").unwrap();
        assert_eq!(server_config.alpn_protocols.len(), 2);
    }

    #[test]
    fn test_server_ech_without_keys_fails_fast() {
        let cfg = TlsServerConfig {
            server_name: Some("example.com".to_string()),
            server_names: vec![],
            allow_self_signed: true,
            reject_unknown_sni: false,
            certificates: vec![],
            ech: Some(EchServerConfig {
                enabled: true,
                server_keys: None,
            }),
            alpn: vec![],
            cert_config: None,
        };

        let res = build_server_config(&cfg, true, "example.com");
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .contains("TLS Server ECH is enabled, but no ech_server_keys were provided"));
    }

    #[test]
    fn test_server_ech_with_valid_keys_succeeds() {
        let ech_pair = crate::security::EchKeyPair::generate("outer.example.com", 0);
        let pem_keys = ech_pair.to_pem_ech_keys();

        let cfg = TlsServerConfig {
            server_name: Some("secret.internal".to_string()),
            server_names: vec!["secret.internal".to_string()],
            allow_self_signed: true,
            reject_unknown_sni: false,
            certificates: vec![],
            ech: Some(EchServerConfig {
                enabled: true,
                server_keys: Some(pem_keys.into_bytes()),
            }),
            alpn: vec!["h2".to_string()],
            cert_config: None,
        };

        let server_config = build_server_config(&cfg, true, "secret.internal").unwrap();
        assert!(server_config.ech_server_keys.is_some());
        let keys = server_config.ech_server_keys.as_ref().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].public_name, "outer.example.com");
        assert_eq!(keys[0].config_id, 0);
    }

    #[test]
    fn test_reject_unknown_sni_resolver() {
        let params = CertificateParams::new(vec!["node1.example.com".to_string()]).unwrap();
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();

        let cfg = TlsServerConfig {
            server_name: Some("node1.example.com".to_string()),
            server_names: vec!["node1.example.com".to_string()],
            allow_self_signed: true,
            reject_unknown_sni: true,
            certificates: vec![TlsCertificateEntry {
                cert_pem: Some(cert.pem()),
                key_pem: Some(key_pair.serialize_pem()),
                cert_file: None,
                key_file: None,
            }],
            ech: None,
            alpn: vec!["h2".to_string()],
            cert_config: None,
        };

        let server_config = build_server_config(&cfg, false, "node1.example.com").unwrap();
        assert_eq!(server_config.alpn_protocols, vec![b"h2".to_vec()]);
    }

    #[test]
    fn test_no_cert_without_auto_tls_fails_fast() {
        let cfg = TlsServerConfig {
            server_name: Some("example.com".to_string()),
            server_names: vec![],
            allow_self_signed: true,
            reject_unknown_sni: false,
            certificates: vec![],
            ech: None,
            alpn: vec![],
            cert_config: None,
        };

        let res = build_server_config(&cfg, false, "example.com");
        assert!(res.is_err());
        assert!(res.unwrap_err().contains("TLS has no certificate"));
    }
}
