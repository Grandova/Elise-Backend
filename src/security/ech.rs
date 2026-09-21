use base64::Engine;
use rand::rngs::OsRng;
use rustls::server::EchServerConfigAndKey;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EchKeyPair {
    pub config_id: u8,

    pub public_name: String,

    pub private_key: [u8; 32],

    pub public_key: [u8; 32],

    pub raw_ech_config: Vec<u8>,

    pub ech_config_list: Vec<u8>,
}

impl EchKeyPair {
    pub fn generate(public_name: &str, config_id: u8) -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);

        let private_key: [u8; 32] = secret.to_bytes();
        let public_key: [u8; 32] = public.to_bytes();

        Self::from_raw_keys(config_id, public_name, private_key, public_key)
    }

    pub fn from_raw_keys(
        config_id: u8,
        public_name: &str,
        private_key: [u8; 32],
        public_key: [u8; 32],
    ) -> Self {
        let mut contents = Vec::new();
        contents.push(config_id);

        contents.extend_from_slice(&0x0020u16.to_be_bytes());

        contents.extend_from_slice(&32u16.to_be_bytes());
        contents.extend_from_slice(&public_key);

        contents.extend_from_slice(&8u16.to_be_bytes());
        contents.extend_from_slice(&1u16.to_be_bytes());
        contents.extend_from_slice(&1u16.to_be_bytes());
        contents.extend_from_slice(&1u16.to_be_bytes());
        contents.extend_from_slice(&3u16.to_be_bytes());

        contents.push(0);

        let name_bytes = public_name.as_bytes();
        contents.push(name_bytes.len() as u8);
        contents.extend_from_slice(name_bytes);

        contents.extend_from_slice(&0u16.to_be_bytes());

        let mut raw_ech_config = Vec::new();
        raw_ech_config.extend_from_slice(&0xfe0du16.to_be_bytes());
        raw_ech_config.extend_from_slice(&(contents.len() as u16).to_be_bytes());
        raw_ech_config.extend_from_slice(&contents);

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

    pub fn to_pem_ech_configs(&self) -> String {
        let b64 = base64::engine::general_purpose::STANDARD.encode(&self.ech_config_list);
        format!("-----BEGIN ECH CONFIGS-----\n{b64}\n-----END ECH CONFIGS-----\n")
    }

    pub fn to_pem_ech_keys(&self) -> String {
        let mut key_bytes = Vec::new();
        key_bytes.extend_from_slice(&32u16.to_be_bytes());
        key_bytes.extend_from_slice(&self.private_key);
        key_bytes.extend_from_slice(&(self.raw_ech_config.len() as u16).to_be_bytes());
        key_bytes.extend_from_slice(&self.raw_ech_config);

        let b64 = base64::engine::general_purpose::STANDARD.encode(&key_bytes);
        format!("-----BEGIN ECH KEYS-----\n{b64}\n-----END ECH KEYS-----\n")
    }

    pub fn from_pem_or_bytes(input: &[u8], default_public_name: &str) -> Result<Self, String> {
        let bytes = if let Ok(s) = std::str::from_utf8(input) {
            let trimmed = s.trim();
            if trimmed.contains("BEGIN ECH KEYS") {
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

        if bytes.len() >= 36 {
            let priv_len = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
            if priv_len == 32 && bytes.len() >= 4 + priv_len {
                let mut priv_key = [0u8; 32];
                priv_key.copy_from_slice(&bytes[2..34]);

                let cfg_len = u16::from_be_bytes([bytes[34], bytes[35]]) as usize;
                if bytes.len() >= 36 + cfg_len {
                    let raw_ech_config = bytes[36..36 + cfg_len].to_vec();

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
