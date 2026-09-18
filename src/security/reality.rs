use crate::conn::{
    encode_proxy_protocol_v1, encode_proxy_protocol_v2, BoxedStream, PrefixedStream,
};
use crate::transport::types::RealityServerConfig;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes256Gcm;
use hmac::{Hmac, Mac};
use rand::rngs::OsRng;
use sha2::{Sha256, Sha512};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct RealityKeyPair {
    pub private_key: String,
    pub public_key: String,
}

pub fn generate_reality_keypair() -> RealityKeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    let priv_bytes = secret.to_bytes();
    let pub_bytes = public.to_bytes();

    RealityKeyPair {
        private_key: base64_url_encode(&priv_bytes),
        public_key: base64_url_encode(&pub_bytes),
    }
}

pub fn generate_short_id(len_bytes: usize) -> String {
    let mut bytes = vec![0u8; len_bytes];
    rand::RngCore::fill_bytes(&mut OsRng, &mut bytes);
    hex::encode(bytes)
}

fn base64_url_encode(input: &[u8]) -> String {
    const URL_SAFE_CHARSET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut i = 0;
    while i < input.len() {
        let b0 = input[i] as usize;
        let b1 = if i + 1 < input.len() {
            input[i + 1] as usize
        } else {
            0
        };
        let b2 = if i + 2 < input.len() {
            input[i + 2] as usize
        } else {
            0
        };

        out.push(URL_SAFE_CHARSET[b0 >> 2] as char);
        out.push(URL_SAFE_CHARSET[((b0 & 3) << 4) | (b1 >> 4)] as char);
        if i + 1 < input.len() {
            out.push(URL_SAFE_CHARSET[((b1 & 15) << 2) | (b2 >> 6)] as char);
        }
        if i + 2 < input.len() {
            out.push(URL_SAFE_CHARSET[b2 & 63] as char);
        }
        i += 3;
    }
    out
}

#[derive(Clone)]
pub struct RealityServer {
    config: Arc<RealityServerConfig>,
    ed25519_key_der: Vec<u8>,
    cert_template_der: Vec<u8>,
    ed25519_pubkey: [u8; 32],
}

pub enum RealityHandshakeResult {
    Authenticated(BoxedStream),
    Fallbacked,
}

impl RealityServer {
    pub fn new(config: RealityServerConfig) -> Result<Self, String> {
        let sni = config
            .server_names
            .first()
            .cloned()
            .unwrap_or_else(|| "www.apple.com".to_string());

        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| format!("failed to generate Ed25519 keypair for REALITY: {e}"))?;
        let params = rcgen::CertificateParams::new(vec![sni])
            .map_err(|e| format!("failed to generate cert params: {e}"))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| format!("failed to generate self-signed cert: {e}"))?;

        let cert_der = cert.der().to_vec();
        let key_der = key_pair.serialize_der();

        // Extract raw 32-byte Ed25519 public key from key_pair
        let mut pubkey_bytes = [0u8; 32];
        let pub_raw = key_pair.public_key_raw();
        if pub_raw.len() >= 32 {
            pubkey_bytes.copy_from_slice(&pub_raw[pub_raw.len() - 32..]);
        }

        Ok(Self {
            config: Arc::new(config),
            ed25519_key_der: key_der,
            cert_template_der: cert_der,
            ed25519_pubkey: pubkey_bytes,
        })
    }

    pub async fn accept(
        &self,
        mut stream: BoxedStream,
        remote_addr: SocketAddr,
        alpn_protocols: Vec<Vec<u8>>,
    ) -> io::Result<RealityHandshakeResult> {
        // 1. Read TLS Record Header (5 bytes: 0x16, 0x03, 0x01..0x03, length: u16)
        let mut header = [0u8; 5];
        if stream.read_exact(&mut header).await.is_err() || header[0] != 0x16 {
            debug!(
                "REALITY: Non-TLS connection from {}, proxying to dest {}",
                remote_addr, self.config.dest
            );
            self.fallback(stream, remote_addr, header.to_vec()).await?;
            return Ok(RealityHandshakeResult::Fallbacked);
        }

        let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
        if record_len > 16384 {
            warn!("REALITY: oversized TLS record len: {record_len}");
            self.fallback(stream, remote_addr, header.to_vec()).await?;
            return Ok(RealityHandshakeResult::Fallbacked);
        }

        // 2. Read full ClientHello record
        let mut client_hello_record = vec![0u8; 5 + record_len];
        client_hello_record[..5].copy_from_slice(&header);
        if stream
            .read_exact(&mut client_hello_record[5..])
            .await
            .is_err()
        {
            return Ok(RealityHandshakeResult::Fallbacked);
        }

        // 3. Authenticate ClientHello
        let auth_res = self.verify_client_hello(&client_hello_record);
        let auth_key = match auth_res {
            Ok(key) => key,
            Err(e) => {
                debug!(
                    "REALITY: Auth failed from {}: {}, proxying to dest {}",
                    remote_addr, e, self.config.dest
                );
                self.fallback(stream, remote_addr, client_hello_record)
                    .await?;
                return Ok(RealityHandshakeResult::Fallbacked);
            }
        };

        // 4. Authenticated: Prepare TLS 1.3 handshake with patched certificate
        let patched_cert = self.create_patched_certificate(&auth_key)?;
        let cert_chain = vec![rustls::pki_types::CertificateDer::from(patched_cert)];
        let priv_key = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(self.ed25519_key_der.clone()),
        );

        let provider = rustls::crypto::ring::default_provider();
        let raw_signing_key = provider
            .key_provider
            .load_private_key(priv_key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

        let reality_signing_key = Arc::new(RealitySigningKey {
            inner: raw_signing_key,
        });

        let certified_key = Arc::new(rustls::sign::CertifiedKey::new(
            cert_chain,
            reality_signing_key,
        ));

        let resolver = Arc::new(RealityCertResolver { key: certified_key });

        let mut server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_cert_resolver(resolver);

        if !alpn_protocols.is_empty() {
            server_config.alpn_protocols = alpn_protocols;
        }

        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let prefixed_stream = PrefixedStream::new(stream, Some(client_hello_record));

        let tls_stream = acceptor.accept(prefixed_stream).await.map_err(|e| {
            warn!(
                "REALITY: TLS 1.3 handshake error with {}: {:?}",
                remote_addr, e
            );
            e
        })?;

        info!(
            "REALITY: Successfully authenticated and established TLS 1.3 with {}",
            remote_addr
        );
        Ok(RealityHandshakeResult::Authenticated(Box::new(tls_stream)))
    }

    fn verify_client_hello(&self, record: &[u8]) -> Result<[u8; 32], String> {
        if record.len() < 5 + 4 + 2 + 32 + 1 + 32 {
            return Err("ClientHello record too short".to_string());
        }

        // In record, handshake payload starts at index 5
        let handshake = &record[5..];
        if handshake[0] != 0x01 {
            return Err("Not a ClientHello handshake".to_string());
        }

        // Offset in handshake payload:
        // handshake[0] = 0x01 (type)
        // handshake[1..4] = 3-byte length
        // handshake[4..6] = legacy_version (0x0303)
        // handshake[6..38] = 32-byte Random
        // handshake[38] = session_id length (must be 32)
        // handshake[39..71] = 32-byte SessionId (where encrypted data lives)
        let random = &handshake[6..38];
        let session_id_len = handshake[38] as usize;
        if session_id_len != 32 || handshake.len() < 39 + 32 {
            return Err(format!("Invalid SessionID length: {session_id_len}"));
        }
        let ciphertext = &handshake[39..71];

        log_client_hello_info(handshake);

        // Parse extensions to extract KeyShare (X25519)
        let client_keyshare = parse_x25519_key_share(handshake)?;

        // ECDH with server private key
        let secret = StaticSecret::from(self.config.private_key);
        let public = PublicKey::from(client_keyshare);
        let shared_secret = secret.diffie_hellman(&public);

        // HKDF-SHA256: salt = random[..20], info = "REALITY"
        let salt = &random[..20];
        let hk = hkdf::Hkdf::<Sha256>::new(Some(salt), shared_secret.as_bytes());
        let mut auth_key = [0u8; 32];
        hk.expand(b"REALITY", &mut auth_key)
            .map_err(|e| format!("HKDF expand failed: {e}"))?;

        // Construct AAD: full handshake with byte 39..71 zeroed out
        let mut aad = handshake.to_vec();
        aad[39..71].fill(0);

        // AES-256-GCM decrypt SessionId
        let nonce = &random[20..32];
        let cipher = Aes256Gcm::new_from_slice(&auth_key)
            .map_err(|e| format!("AES-256-GCM init failed: {e}"))?;
        let payload = Payload {
            msg: ciphertext,
            aad: &aad,
        };
        let plaintext = cipher
            .decrypt(aes_gcm::Nonce::from_slice(nonce), payload)
            .map_err(|e| format!("REALITY AEAD authentication decrypt failed: {e}"))?;

        if plaintext.len() != 16 {
            return Err(format!(
                "Decrypted plaintext length != 16: {}",
                plaintext.len()
            ));
        }

        // Verify timestamp
        let timestamp =
            u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as u32;

        let diff_ms = (now.abs_diff(timestamp) as u64) * 1000;
        if diff_ms > self.config.max_time_diff_ms {
            return Err(format!(
                "Timestamp expired: diff {}ms > max {}ms",
                diff_ms, self.config.max_time_diff_ms
            ));
        }

        // Verify short_id
        let client_short_id = &plaintext[8..16];
        let mut matched = false;
        for sid in &self.config.short_ids {
            if sid.is_empty() {
                // Empty short_id matches if client sent all zeros or empty
                if client_short_id.iter().all(|&b| b == 0) {
                    matched = true;
                    break;
                }
            } else if sid.len() <= 8 && &client_short_id[..sid.len()] == sid.as_slice() {
                matched = true;
                break;
            }
        }

        if !matched {
            return Err(format!(
                "ShortId mismatch: got hex '{}'",
                hex::encode(client_short_id)
            ));
        }

        Ok(auth_key)
    }

    fn create_patched_certificate(&self, auth_key: &[u8; 32]) -> io::Result<Vec<u8>> {
        let mut cert = self.cert_template_der.clone();
        if cert.len() < 64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Certificate DER too short to patch signature",
            ));
        }

        type HmacSha512 = Hmac<Sha512>;
        let mut mac = <HmacSha512 as hmac::Mac>::new_from_slice(auth_key)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        mac.update(&self.ed25519_pubkey);
        let hmac_res = mac.finalize().into_bytes();

        let sig_start = cert.len() - 64;
        cert[sig_start..].copy_from_slice(&hmac_res);
        Ok(cert)
    }

    async fn fallback(
        &self,
        mut client_stream: BoxedStream,
        remote_addr: SocketAddr,
        buffered_bytes: Vec<u8>,
    ) -> io::Result<()> {
        let mut dest_stream = TcpStream::connect(&self.config.dest).await.map_err(|e| {
            warn!(
                "REALITY fallback: failed to connect to {}: {:?}",
                self.config.dest, e
            );
            e
        })?;

        // Optional PROXY Protocol header to dest
        if self.config.xver == 1 {
            let dest_addr = dest_stream.peer_addr().unwrap_or(remote_addr);
            let p1 = encode_proxy_protocol_v1(remote_addr, dest_addr);
            let _ = dest_stream.write_all(&p1).await;
        } else if self.config.xver == 2 {
            let dest_addr = dest_stream.peer_addr().unwrap_or(remote_addr);
            let p2 = encode_proxy_protocol_v2(remote_addr, dest_addr);
            let _ = dest_stream.write_all(&p2).await;
        }

        if !buffered_bytes.is_empty() {
            dest_stream.write_all(&buffered_bytes).await?;
        }

        tokio::spawn(async move {
            let _ = tokio::io::copy_bidirectional(&mut client_stream, &mut dest_stream).await;
        });

        Ok(())
    }
}

fn log_client_hello_info(handshake: &[u8]) {
    if handshake.len() < 39 {
        return;
    }
    let sid_len = handshake[38] as usize;
    let mut pos = 39 + sid_len;
    if pos + 2 > handshake.len() {
        return;
    }
    let cs_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cs_len;
    if pos + 1 > handshake.len() {
        return;
    }
    let comp_len = handshake[pos] as usize;
    pos += 1 + comp_len;
    if pos + 2 > handshake.len() {
        return;
    }
    let ext_total_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;
    let end = (pos + ext_total_len).min(handshake.len());
    while pos + 4 <= end {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let ext_len = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > end {
            break;
        }
        if ext_type == 0x000d && ext_len >= 2 {
            let sig_data = &handshake[pos..pos + ext_len];
            let sig_len = u16::from_be_bytes([sig_data[0], sig_data[1]]) as usize;
            let mut sigs = Vec::new();
            let mut s = 2;
            while s + 2 <= 2 + sig_len && s + 2 <= sig_data.len() {
                sigs.push(u16::from_be_bytes([sig_data[s], sig_data[s + 1]]));
                s += 2;
            }
            info!("REALITY: ClientHello signature algorithms: {:04x?}", sigs);
        }
        pos += ext_len;
    }
}

#[derive(Debug)]
struct RealitySigningKey {
    inner: Arc<dyn rustls::sign::SigningKey>,
}

impl rustls::sign::SigningKey for RealitySigningKey {
    fn choose_scheme(
        &self,
        _offered: &[rustls::SignatureScheme],
    ) -> Option<Box<dyn rustls::sign::Signer>> {
        // Force Ed25519 scheme for REALITY, aligning with Xray-core / sing-box protocol invariant
        self.inner
            .choose_scheme(&[rustls::SignatureScheme::ED25519])
    }

    fn algorithm(&self) -> rustls::SignatureAlgorithm {
        self.inner.algorithm()
    }
}

#[derive(Debug)]
struct RealityCertResolver {
    key: Arc<rustls::sign::CertifiedKey>,
}

impl rustls::server::ResolvesServerCert for RealityCertResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(self.key.clone())
    }
}

fn parse_x25519_key_share(handshake: &[u8]) -> Result<[u8; 32], String> {
    if handshake.len() < 39 {
        return Err("Handshake truncated".to_string());
    }
    let sid_len = handshake[38] as usize;
    let mut pos = 39 + sid_len;

    if pos + 2 > handshake.len() {
        return Err("Truncated before cipher suites".to_string());
    }
    let cs_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2 + cs_len;

    if pos + 1 > handshake.len() {
        return Err("Truncated before compression methods".to_string());
    }
    let comp_len = handshake[pos] as usize;
    pos += 1 + comp_len;

    if pos + 2 > handshake.len() {
        return Err("No extensions present in ClientHello".to_string());
    }
    let ext_total_len = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]) as usize;
    pos += 2;

    let end = (pos + ext_total_len).min(handshake.len());
    while pos + 4 <= end {
        let ext_type = u16::from_be_bytes([handshake[pos], handshake[pos + 1]]);
        let ext_len = u16::from_be_bytes([handshake[pos + 2], handshake[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > end {
            break;
        }

        // Extension 0x0033: key_share
        if ext_type == 0x0033 {
            let ext_data = &handshake[pos..pos + ext_len];
            if ext_data.len() >= 2 {
                let client_shares_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                let mut sp = 2;
                let send = (sp + client_shares_len).min(ext_data.len());
                while sp + 4 <= send {
                    let group = u16::from_be_bytes([ext_data[sp], ext_data[sp + 1]]);
                    let key_len = u16::from_be_bytes([ext_data[sp + 2], ext_data[sp + 3]]) as usize;
                    sp += 4;

                    if sp + key_len > send {
                        break;
                    }

                    // Group 0x001d = X25519
                    if group == 0x001d && key_len == 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&ext_data[sp..sp + 32]);
                        return Ok(key);
                    }

                    // Group 0x45ac = X25519MLKEM768 (X25519 is the last 32 bytes)
                    if group == 0x45ac && key_len >= 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(&ext_data[sp + key_len - 32..sp + key_len]);
                        return Ok(key);
                    }

                    sp += key_len;
                }
            }
        }

        // Extension 0x000d: signature_algorithms
        if ext_type == 0x000d {
            let ext_data = &handshake[pos..pos + ext_len];
            if ext_data.len() >= 2 {
                let sig_len = u16::from_be_bytes([ext_data[0], ext_data[1]]) as usize;
                let mut sigs = Vec::new();
                let mut s = 2;
                while s + 2 <= 2 + sig_len && s + 2 <= ext_data.len() {
                    sigs.push(u16::from_be_bytes([ext_data[s], ext_data[s + 1]]));
                    s += 2;
                }
                info!("REALITY: ClientHello signature algorithms: {:04x?}", sigs);
            }
        }

        pos += ext_len;
    }

    Err("KeyShare extension (X25519) not found in ClientHello".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reality_keypair_generation() {
        let kp = generate_reality_keypair();
        assert!(!kp.private_key.is_empty());
        assert!(!kp.public_key.is_empty());
    }

    #[test]
    fn test_reality_short_id() {
        let sid = generate_short_id(8);
        assert_eq!(sid.len(), 16);
    }

    #[test]
    fn test_reality_server_init() {
        let config = RealityServerConfig {
            dest: "www.apple.com:443".to_string(),
            server_names: vec!["www.apple.com".to_string()],
            private_key: [7u8; 32],
            short_ids: vec![vec![1, 2, 3, 4]],
            xver: 0,
            max_time_diff_ms: 60000,
            min_client_ver: None,
            max_client_ver: None,
            spider_x: None,
        };

        let server = RealityServer::new(config);
        assert!(server.is_ok());
    }

    #[test]
    fn test_reality_auth_handshake_flow() {
        // 1. Setup Server
        let server_secret = StaticSecret::random_from_rng(OsRng);
        let server_public = PublicKey::from(&server_secret);
        let valid_short_id = vec![0x12, 0x34, 0x56, 0x78];

        let config = RealityServerConfig {
            dest: "www.apple.com:443".to_string(),
            server_names: vec!["www.apple.com".to_string()],
            private_key: server_secret.to_bytes(),
            short_ids: vec![valid_short_id.clone()],
            xver: 0,
            max_time_diff_ms: 60000,
            min_client_ver: None,
            max_client_ver: None,
            spider_x: None,
        };
        let server = RealityServer::new(config).unwrap();

        // 2. Client generates ephemeral X25519 key
        let client_secret = StaticSecret::random_from_rng(OsRng);
        let client_public = PublicKey::from(&client_secret);

        // 3. Client builds ClientHello
        let mut random = [0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut random);

        let shared_secret = client_secret.diffie_hellman(&server_public);
        let hk = hkdf::Hkdf::<Sha256>::new(Some(&random[..20]), shared_secret.as_bytes());
        let mut client_auth_key = [0u8; 32];
        hk.expand(b"REALITY", &mut client_auth_key).unwrap();

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() as u32;

        let mut plaintext = [0u8; 16];
        plaintext[0..3].copy_from_slice(&[1, 8, 0]);
        plaintext[4..8].copy_from_slice(&now.to_be_bytes());
        plaintext[8..12].copy_from_slice(&valid_short_id);

        let mut handshake = Vec::new();
        handshake.push(0x01); // ClientHello
        handshake.extend_from_slice(&[0, 0, 0]); // length placeholder
        handshake.extend_from_slice(&[0x03, 0x03]); // legacy version
        handshake.extend_from_slice(&random); // 32 bytes random
        handshake.push(32); // session_id length
        let session_id_offset = handshake.len();
        handshake.extend_from_slice(&[0u8; 32]); // placeholder for session_id

        // Cipher suites
        handshake.extend_from_slice(&2u16.to_be_bytes());
        handshake.extend_from_slice(&[0x13, 0x01]);

        // Compression
        handshake.push(1);
        handshake.push(0);

        // Extensions
        let mut extensions = Vec::new();
        // KeyShare extension (0x0033)
        extensions.extend_from_slice(&0x0033u16.to_be_bytes());
        let mut keyshare_data = Vec::new();
        let client_shares_len = 2 + 2 + 32;
        keyshare_data.extend_from_slice(&(client_shares_len as u16).to_be_bytes());
        keyshare_data.extend_from_slice(&0x001du16.to_be_bytes()); // X25519
        keyshare_data.extend_from_slice(&32u16.to_be_bytes());
        keyshare_data.extend_from_slice(client_public.as_bytes());

        extensions.extend_from_slice(&(keyshare_data.len() as u16).to_be_bytes());
        extensions.extend_from_slice(&keyshare_data);

        handshake.extend_from_slice(&(extensions.len() as u16).to_be_bytes());
        handshake.extend_from_slice(&extensions);

        // Patch length in handshake header
        let hs_len = (handshake.len() - 4) as u32;
        handshake[1] = (hs_len >> 16) as u8;
        handshake[2] = (hs_len >> 8) as u8;
        handshake[3] = hs_len as u8;

        // Encrypt session_id with AAD = handshake (where session_id is currently 0s)
        let cipher = Aes256Gcm::new_from_slice(&client_auth_key).unwrap();
        let nonce = &random[20..32];
        let payload = Payload {
            msg: &plaintext,
            aad: &handshake,
        };
        let ciphertext = cipher
            .encrypt(aes_gcm::Nonce::from_slice(nonce), payload)
            .unwrap();
        assert_eq!(ciphertext.len(), 32);

        // Patch ciphertext into session_id
        handshake[session_id_offset..session_id_offset + 32].copy_from_slice(&ciphertext);

        // Build TLS Record Header: [0x16, 0x03, 0x01, len:2]
        let mut record = Vec::new();
        record.extend_from_slice(&[0x16, 0x03, 0x01]);
        record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
        record.extend_from_slice(&handshake);

        // Verify with server!
        let auth_res = server.verify_client_hello(&record);
        assert!(
            auth_res.is_ok(),
            "REALITY auth failed: {:?}",
            auth_res.err()
        );
        assert_eq!(auth_res.unwrap(), client_auth_key);

        // Test corrupted ciphertext fails
        let mut bad_record = record.clone();
        bad_record[5 + session_id_offset] ^= 0xff;
        assert!(server.verify_client_hello(&bad_record).is_err());
    }

    #[test]
    fn test_ring_supported_schemes() {
        let provider = rustls::crypto::ring::default_provider();
        let schemes = provider
            .signature_verification_algorithms
            .supported_schemes();
        println!("Supported signature schemes in ring: {:?}", schemes);

        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
        let pkcs8 = rustls::pki_types::PrivateKeyDer::Pkcs8(
            rustls::pki_types::PrivatePkcs8KeyDer::from(kp.serialize_der()),
        );
        let key = provider.key_provider.load_private_key(pkcs8).unwrap();
        println!("Key algorithm: {:?}", key.algorithm());
        println!("Key choose_scheme with empty: {:?}", key.choose_scheme(&[]));
        println!(
            "Key choose_scheme with [ED25519]: {:?}",
            key.choose_scheme(&[rustls::SignatureScheme::ED25519])
        );
    }
}
