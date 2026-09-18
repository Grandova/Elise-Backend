use base64::Engine;
use rand::rngs::OsRng;
use rustls::server::EchServerConfigAndKey;
use x25519_dalek::{PublicKey, StaticSecret};

/// Represents an ECH server key pair and associated RFC draft-18 metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EchKeyPair {
    /// The ECH configuration ID.
    pub config_id: u8,
    /// The outer cover domain name (public name).
    pub public_name: String,
    /// The 32-byte X25519 private key.
    pub private_key: [u8; 32],
    /// The 32-byte X25519 public key.
    pub public_key: [u8; 32],
    /// The wire-encoded ECHConfig byte sequence (starting with 0xfe0d version).
    pub raw_ech_config: Vec<u8>,
    /// The wire-encoded ECHConfigList byte sequence (2-byte length prefix + ECHConfig).
    pub ech_config_list: Vec<u8>,
}

impl EchKeyPair {
    /// Generates a fresh random X25519 keypair and creates a RFC draft-18 ECHConfigList.
    pub fn generate(public_name: &str, config_id: u8) -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        let private_key: [u8; 32] = secret.to_bytes();
        let public_key: [u8; 32] = public.to_bytes();

        Self::from_raw_keys(config_id, public_name, private_key, public_key)
    }

    /// Creates an EchKeyPair given explicit private and public key bytes.
    pub fn from_raw_keys(
        config_id: u8,
        public_name: &str,
        private_key: [u8; 32],
        public_key: [u8; 32],
    ) -> Self {
        let mut contents = Vec::new();
        contents.push(config_id);
        // kem_id: 0x0020 (DHKEM(X25519, HKDF-SHA256))
        contents.extend_from_slice(&0x0020u16.to_be_bytes());
        // public_key len: 32 (0x0020)
        contents.extend_from_slice(&32u16.to_be_bytes());
        contents.extend_from_slice(&public_key);
        // cipher_suites: 8 bytes
        contents.extend_from_slice(&8u16.to_be_bytes());
        contents.extend_from_slice(&1u16.to_be_bytes()); // KDF: HKDF-SHA256
        contents.extend_from_slice(&1u16.to_be_bytes()); // AEAD: AES-128-GCM
        contents.extend_from_slice(&1u16.to_be_bytes()); // KDF: HKDF-SHA256
        contents.extend_from_slice(&3u16.to_be_bytes()); // AEAD: ChaCha20-Poly1305
                                                         // maximum_name_length: 0
        contents.push(0);
        // public_name: 1 byte len + bytes
        let name_bytes = public_name.as_bytes();
        contents.push(name_bytes.len() as u8);
        contents.extend_from_slice(name_bytes);
        // extensions: 0 bytes (length = 0)
        contents.extend_from_slice(&0u16.to_be_bytes());

        // Build ECHConfig:
        // ECHVersion version: 0xfe0d
        // uint16 length: contents.len()
        // contents
        let mut raw_ech_config = Vec::new();
        raw_ech_config.extend_from_slice(&0xfe0du16.to_be_bytes());
        raw_ech_config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        raw_ech_config.extend_from_slice(&contents);

        // Build ECHConfigList:
        // uint16 length: raw_ech_config.len()
        // raw_ech_config
        let mut ech_config_list = Vec::new();
        ech_config_list.extend_from_slice(&(raw_ech_config.len() as u16).to_be_bytes());
        ech_config_list.extend_from_slice(&raw_ech_config);

        Self {
            config_id,
            public_name: public_name.to_string(),
            private_key,
            public_key,
            raw_ech_config,
            ech_config_list,
        }
    }

    /// Returns the PEM-encoded ECHConfigList string (-----BEGIN ECH CONFIGS-----).
    /// This is used directly by client configurations like sing-box `tls.ech.config`.
    pub fn to_pem_ech_configs(&self) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(&self.ech_config_list);
        format!("-----BEGIN ECH CONFIGS-----\n{b64}\n-----END ECH CONFIGS-----\n")
    }

    /// Returns the PEM-encoded ECH KEYS string (-----BEGIN ECH KEYS-----).
    /// This matches sing-box / BoringSSL format:
    /// `0x0020 || private_key || uint16(ech_config_len) || raw_ech_config`
    pub fn to_pem_ech_keys(&self) -> String {
        let mut key_bytes = Vec::new();
        key_bytes.extend_from_slice(&32u16.to_be_bytes());
        key_bytes.extend_from_slice(&self.private_key);
        key_bytes.extend_from_slice(&(self.raw_ech_config.len() as u16).to_be_bytes());
        key_bytes.extend_from_slice(&self.raw_ech_config);

        let b64 = base64::engine::general_purpose::STANDARD.encode(&key_bytes);
        format!("-----BEGIN ECH KEYS-----\n{b64}\n-----END ECH KEYS-----\n")
    }

    /// Parses an EchKeyPair from either:
    /// 1. PEM string containing -----BEGIN ECH KEYS----- ... -----END ECH KEYS-----
    /// 2. Base64-encoded ECH KEYS binary
    /// 3. Raw binary bytes of ECH KEYS format
    /// 4. Raw 32-byte private key (with `default_public_name` used to construct ECHConfig)
    pub fn from_pem_or_bytes(input: &[u8], default_public_name: &str) -> Result<Self, String> {
        let bytes = if let Ok(s) = std::str::from_utf8(input) {
            let trimmed = s.trim();
            if trimmed.contains("BEGIN ECH KEYS") {
                // Extract base64 inside PEM block
                let mut b64 = String::new();
                let mut in_block = false;
                for line in trimmed.lines() {
                    let l = line.trim();
                    if l.starts_with("-----BEGIN ECH KEYS-----") {
                        in_block = true;
                    } else if l.starts_with("-----END ECH KEYS-----") {
                        break;
                    } else if in_block {
                        b64.push_str(l);
                    }
                }
                base64::engine::general_purpose::STANDARD
                    .decode(&b64)
                    .map_err(|e| format!("invalid base64 in ECH KEYS PEM: {e}"))?
            } else if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(trimmed) {
                decoded
            } else {
                input.to_vec()
            }
        } else {
            input.to_vec()
        };

        // Case 1: Raw 32-byte private key
        if bytes.len() == 32 {
            let mut priv_bytes = [0u8; 32];
            priv_bytes.copy_from_slice(&bytes);
            let secret = StaticSecret::from(priv_bytes);
            let public = PublicKey::from(&secret);
            return Ok(Self::from_raw_keys(
                0,
                default_public_name,
                priv_bytes,
                public.to_bytes(),
            ));
        }

        // Case 2: sing-box ECH KEYS binary format
        // uint16 priv_len (must be 32)
        // 32-byte private key
        // uint16 ech_config_len
        // ech_config bytes
        if bytes.len() >= 36 {
            let priv_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
            if priv_len == 32 && bytes.len() >= 4 + priv_len {
                let mut priv_key = [0u8; 32];
                priv_key.copy_from_slice(&bytes[2..34]);

                let cfg_len = u16::from_be_bytes([bytes[34], bytes[35]]) as usize;
                if bytes.len() >= 36 + cfg_len {
                    let raw_ech_config = bytes[36..36 + cfg_len].to_vec();

                    // Parse ECHConfig
                    if raw_ech_config.len() >= 4 {
                        let version = u16::from_be_bytes([raw_ech_config[0], raw_ech_config[1]]);
                        if version != 0xfe0d {
                            return Err(format!(
                                "unsupported ECH version 0x{version:04x}, expected 0xfe0d (draft-18)"
                            ));
                        }

                        let content_len =
                            u16::from_be_bytes([raw_ech_config[2], raw_ech_config[3]]) as usize;
                        if raw_ech_config.len() >= 4 + content_len {
                            let contents = &raw_ech_config[4..4 + content_len];
                            if contents.len() >= 7 {
                                let config_id = contents[0];
                                let kem_id = u16::from_be_bytes([contents[1], contents[2]]);
                                if kem_id != 0x0020 {
                                    return Err(format!(
                                        "unsupported ECH KEM 0x{kem_id:04x}, expected 0x0020 (X25519)"
                                    ));
                                }

                                let pub_len =
                                    u16::from_be_bytes([contents[3], contents[4]]) as usize;
                                if pub_len != 32 || contents.len() < 5 + pub_len + 2 {
                                    return Err("invalid public key in ECH config".to_string());
                                }

                                let mut pub_key = [0u8; 32];
                                pub_key.copy_from_slice(&contents[5..37]);

                                let cs_len =
                                    u16::from_be_bytes([contents[37], contents[38]]) as usize;
                                let offset = 39 + cs_len;
                                if contents.len() >= offset + 2 {
                                    let name_len = contents[offset + 1] as usize;
                                    if contents.len() >= offset + 2 + name_len {
                                        let public_name = std::str::from_utf8(
                                            &contents[offset + 2..offset + 2 + name_len],
                                        )
                                        .map_err(|e| format!("invalid UTF-8 in public name: {e}"))?
                                        .to_string();

                                        let mut ech_config_list = Vec::new();
                                        ech_config_list.extend_from_slice(
                                            &(raw_ech_config.len() as u16).to_be_bytes(),
                                        );
                                        ech_config_list.extend_from_slice(&raw_ech_config);

                                        return Ok(Self {
                                            config_id,
                                            public_name,
                                            private_key: priv_key,
                                            public_key: pub_key,
                                            raw_ech_config,
                                            ech_config_list,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Err(format!(
            "failed to parse ECH server keys (length: {} bytes)",
            bytes.len()
        ))
    }

    /// Converts this keypair into a rustls `EchServerConfigAndKey`.
    pub fn into_rustls(self) -> EchServerConfigAndKey {
        EchServerConfigAndKey::new(
            self.config_id,
            self.public_name,
            self.private_key,
            self.public_key,
            self.raw_ech_config,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ech_keypair_generation_and_pem_roundtrip() {
        let key = EchKeyPair::generate("outer.example.com", 1);
        assert_eq!(key.config_id, 1);
        assert_eq!(key.public_name, "outer.example.com");

        let pem_configs = key.to_pem_ech_configs();
        assert!(pem_configs.starts_with("-----BEGIN ECH CONFIGS-----"));
        assert!(pem_configs.trim().ends_with("-----END ECH CONFIGS-----"));

        let pem_keys = key.to_pem_ech_keys();
        assert!(pem_keys.starts_with("-----BEGIN ECH KEYS-----"));
        assert!(pem_keys.trim().ends_with("-----END ECH KEYS-----"));

        // Parse PEM back
        let parsed = EchKeyPair::from_pem_or_bytes(pem_keys.as_bytes(), "fallback.com").unwrap();
        assert_eq!(parsed.config_id, 1);
        assert_eq!(parsed.public_name, "outer.example.com");
        assert_eq!(parsed.private_key, key.private_key);
        assert_eq!(parsed.public_key, key.public_key);
        assert_eq!(parsed.raw_ech_config, key.raw_ech_config);
        assert_eq!(parsed.ech_config_list, key.ech_config_list);
    }

    #[test]
    fn test_ech_parse_singbox_golden_vector() {
        let pem_keys = "\
-----BEGIN ECH KEYS-----\n\
ACCRYboT6MRws9AXCGdBufPK4HzQ5jfi4lA1tjh8rPFD3ABL/g0ARwAAIAAg4q6R\n\
8q92CzXkdPfnTmcucmR1KdX6+cE0W44lvniu6lgACAABAAEAAQADABRvdXRlci5j\n\
bG91ZGZsYXJlLmNvbQAA\n\
-----END ECH KEYS-----";

        let parsed = EchKeyPair::from_pem_or_bytes(pem_keys.as_bytes(), "fallback.com").unwrap();
        assert_eq!(parsed.config_id, 0);
        assert_eq!(parsed.public_name, "outer.cloudflare.com");
        assert_eq!(
            hex::encode(parsed.private_key),
            "9161ba13e8c470b3d017086741b9f3cae07cd0e637e2e25035b6387cacf143dc"
        );
        assert_eq!(
            hex::encode(parsed.public_key),
            "e2ae91f2af760b35e474f7e74e672e72647529d5faf9c1345b8e25be78aeea58"
        );

        let pem_configs = parsed.to_pem_ech_configs();
        assert!(pem_configs.contains("AEv+DQBHAAAgACDirpHyr3YLNeR09+dOZy5yZHUp1fr5wTRbjiW+eK7qWAAIAAEAAQABAAMAFG91dGVyLmNsb3VkZmxhcmUuY29tAAA="));
        let expected_raw = base64::engine::general_purpose::STANDARD
            .decode("AEv+DQBHAAAgACDirpHyr3YLNeR09+dOZy5yZHUp1fr5wTRbjiW+eK7qWAAIAAEAAQABAAMAFG91dGVyLmNsb3VkZmxhcmUuY29tAAA=")
            .unwrap();
        assert_eq!(parsed.ech_config_list, expected_raw);
    }
}
