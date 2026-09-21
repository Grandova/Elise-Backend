pub mod aead;
pub mod handshake;
pub mod kdf;
pub mod mlkem768;
pub mod session;
pub mod stream;
pub mod xor;

pub use aead::VlessAead;
pub use handshake::{perform_server_handshake, HandshakeServerConfig};
pub use session::SessionStore;
pub use stream::VlessEncryptionStream;

use crate::conn::BoxedStream;
use crate::transport::types::MlkemConfig;
use std::io;
use std::sync::Arc;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Clone)]
pub struct VlessEncryptionServer {
    config: Arc<HandshakeServerConfig>,
}

impl VlessEncryptionServer {
    pub fn new(mlkem: &MlkemConfig) -> io::Result<Self> {
        let priv_bytes = match mlkem.server_keys.first() {
            Some(k) => k.clone(),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "empty VLESS encryption server keys",
                ))
            }
        };

        let (pub_bytes, is_valid_len) = if priv_bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&priv_bytes);
            let secret = StaticSecret::from(arr);
            let public = PublicKey::from(&secret);
            (public.to_bytes().to_vec(), true)
        } else if priv_bytes.len() == 64 {
            let mut arr = [0u8; 64];
            arr.copy_from_slice(&priv_bytes);
            let (public, _) = mlkem768::keygen_from_seed(&arr);
            (public.ek.to_vec(), true)
        } else if priv_bytes.len() == mlkem768::MLKEM768_DK_SIZE {
            let ek = priv_bytes[1152..1152 + mlkem768::MLKEM768_EK_SIZE].to_vec();
            (ek, true)
        } else {
            (Vec::new(), false)
        };

        if !is_valid_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "invalid VLESS encryption private_key length: {} (expected 32, 64, or 2400)",
                    priv_bytes.len()
                ),
            ));
        }

        let config = HandshakeServerConfig {
            nfs_private_key: priv_bytes,
            nfs_public_key: pub_bytes,
            xor_mode: mlkem.xor_mode,
            seconds_from: mlkem.seconds_from,
            seconds_to: mlkem.seconds_to,
            session_store: Arc::new(SessionStore::new()),
        };

        Ok(Self {
            config: Arc::new(config),
        })
    }

    pub async fn handshake(&self, stream: BoxedStream) -> io::Result<BoxedStream> {
        let enc_stream = perform_server_handshake(stream, &self.config).await?;
        Ok(Box::new(enc_stream))
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct VlessEncKeyPair {
    pub decryption: String,
    pub encryption: String,
}

pub fn generate_vlessenc_x25519() -> VlessEncKeyPair {
    use base64::Engine;
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut priv_bytes = [0u8; 32];
    OsRng.fill_bytes(&mut priv_bytes);

    priv_bytes[0] &= 248;
    priv_bytes[31] &= 127;
    priv_bytes[31] |= 64;

    let secret = StaticSecret::from(priv_bytes);
    let public = PublicKey::from(&secret);

    let priv_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(priv_bytes);
    let pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.to_bytes());

    VlessEncKeyPair {
        decryption: format!("mlkem768x25519plus.native.600s.{priv_b64}"),
        encryption: format!("mlkem768x25519plus.native.0rtt.{pub_b64}"),
    }
}

pub fn generate_vlessenc_mlkem768() -> VlessEncKeyPair {
    use base64::Engine;
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut seed = [0u8; 64];
    OsRng.fill_bytes(&mut seed);
    let (public, _) = mlkem768::keygen_from_seed(&seed);

    let priv_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(seed);
    let pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.ek);

    VlessEncKeyPair {
        decryption: format!("mlkem768x25519plus.native.600s.{priv_b64}"),
        encryption: format!("mlkem768x25519plus.native.0rtt.{pub_b64}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::types::VlessEncryptionConfig;
    use base64::Engine;

    #[test]
    fn test_vlessenc_generation_and_parse_roundtrip() {
        let x25519_pair = generate_vlessenc_x25519();
        assert!(x25519_pair
            .decryption
            .starts_with("mlkem768x25519plus.native.600s."));
        assert!(x25519_pair
            .encryption
            .starts_with("mlkem768x25519plus.native.0rtt."));

        let x25519_dec_key = x25519_pair.decryption.split('.').nth(3).unwrap();
        let x25519_enc_key = x25519_pair.encryption.split('.').nth(3).unwrap();
        assert_eq!(
            x25519_dec_key.len(),
            43,
            "X25519 private key in RawURLEncoding must be 43 chars"
        );
        assert_eq!(
            x25519_enc_key.len(),
            43,
            "X25519 public key in RawURLEncoding must be 43 chars"
        );
        assert!(
            !x25519_dec_key.contains('='),
            "RawURLEncoding must not contain padding '='"
        );
        assert!(
            !x25519_enc_key.contains('='),
            "RawURLEncoding must not contain padding '='"
        );
        assert!(!x25519_dec_key.contains('+') && !x25519_dec_key.contains('/'));
        assert!(!x25519_enc_key.contains('+') && !x25519_enc_key.contains('/'));

        let cfg = VlessEncryptionConfig::parse_dot_config(&x25519_pair.decryption).unwrap();
        match cfg {
            VlessEncryptionConfig::Mlkem768X25519Plus(mlkem) => {
                let srv = VlessEncryptionServer::new(&mlkem).unwrap();
                let pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(&srv.config.nfs_public_key);
                assert_eq!(x25519_enc_key, pub_b64);
            }
            _ => panic!("Expected Mlkem768X25519Plus"),
        }

        let mlkem_pair = generate_vlessenc_mlkem768();
        assert!(mlkem_pair
            .decryption
            .starts_with("mlkem768x25519plus.native.600s."));
        assert!(mlkem_pair
            .encryption
            .starts_with("mlkem768x25519plus.native.0rtt."));

        let mlkem_dec_key = mlkem_pair.decryption.split('.').nth(3).unwrap();
        let mlkem_enc_key = mlkem_pair.encryption.split('.').nth(3).unwrap();
        assert_eq!(
            mlkem_dec_key.len(),
            86,
            "ML-KEM-768 seed in RawURLEncoding must be 86 chars"
        );
        assert_eq!(
            mlkem_enc_key.len(),
            1579,
            "ML-KEM-768 public key in RawURLEncoding must be 1579 chars"
        );
        assert!(!mlkem_dec_key.contains('='));
        assert!(!mlkem_enc_key.contains('='));
        assert!(!mlkem_dec_key.contains('+') && !mlkem_dec_key.contains('/'));
        assert!(!mlkem_enc_key.contains('+') && !mlkem_enc_key.contains('/'));

        let cfg2 = VlessEncryptionConfig::parse_dot_config(&mlkem_pair.decryption).unwrap();
        match cfg2 {
            VlessEncryptionConfig::Mlkem768X25519Plus(mlkem) => {
                let srv = VlessEncryptionServer::new(&mlkem).unwrap();
                let pub_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(&srv.config.nfs_public_key);
                assert_eq!(mlkem_enc_key, pub_b64);
            }
            _ => panic!("Expected Mlkem768X25519Plus"),
        }
    }

    #[test]
    fn test_parse_official_xray_output() {
        let official_x25519_dec =
            "mlkem768x25519plus.native.600s.2ExUwPwTcsnt2DPrKPJbJ4TKtyXxVLBIIAAUPRYRA3o";
        let official_x25519_enc =
            "mlkem768x25519plus.native.0rtt.eMwsT4uQCDOZlFw1Zpsn3OIHbrXvN9jJSL4bQMKdkEY";

        let cfg = VlessEncryptionConfig::parse_dot_config(official_x25519_dec)
            .expect("Elise must parse official Xray X25519 decryption string");
        match cfg {
            VlessEncryptionConfig::Mlkem768X25519Plus(mlkem) => {
                let srv = VlessEncryptionServer::new(&mlkem).unwrap();
                let derived_pub = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(&srv.config.nfs_public_key);
                let official_pub = official_x25519_enc.split('.').nth(3).unwrap();
                assert_eq!(
                    derived_pub, official_pub,
                    "Derived public key must match official Xray encryption key"
                );
            }
            _ => panic!("Expected Mlkem768X25519Plus"),
        }

        let official_mlkem_dec = "mlkem768x25519plus.native.600s.asJuiy9eYBidIW1Q--R5ut4m2xcPh09ABPoXAenpYAFswWz_u18-h8EOsDa0SuGFlN1gJww4s0eGOZc-nJPYPw";
        let cfg2 = VlessEncryptionConfig::parse_dot_config(official_mlkem_dec)
            .expect("Elise must parse official Xray ML-KEM-768 decryption string");
        match cfg2 {
            VlessEncryptionConfig::Mlkem768X25519Plus(mlkem) => {
                let srv = VlessEncryptionServer::new(&mlkem).unwrap();
                assert_eq!(srv.config.nfs_public_key.len(), 1184);
            }
            _ => panic!("Expected Mlkem768X25519Plus"),
        }
    }

    #[test]
    fn test_directionality_and_invalid_length_rejection() {
        let fake_client_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([7u8; 1184]);
        let reversed_config = format!("mlkem768x25519plus.native.600s.{fake_client_key}");
        let err = VlessEncryptionConfig::parse_dot_config(&reversed_config).unwrap_err();
        assert!(
            err.contains("1184"),
            "Error must clearly identify 1184-byte client key"
        );
        assert!(
            err.contains("client public key") || err.contains("encryption"),
            "Error must explain directionality mismatch"
        );

        let invalid_key = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1u8; 10]);
        let invalid_config = format!("mlkem768x25519plus.native.600s.{invalid_key}");
        let err2 = VlessEncryptionConfig::parse_dot_config(&invalid_config).unwrap_err();
        assert!(err2.contains("10"));
    }

    #[test]
    fn test_legacy_standard_base64_decoding_fallback() {
        let mut key = [42u8; 32];
        key[0] &= 248;
        key[31] &= 127;
        key[31] |= 64;
        let std_b64 = base64::engine::general_purpose::STANDARD.encode(key);
        assert!(std_b64.ends_with('='));
        let legacy_config = format!("mlkem768x25519plus.native.600s.{std_b64}");
        let cfg = VlessEncryptionConfig::parse_dot_config(&legacy_config)
            .expect("Should accept legacy standard base64 with padding");
        match cfg {
            VlessEncryptionConfig::Mlkem768X25519Plus(mlkem) => {
                assert_eq!(mlkem.server_keys[0], key);
            }
            _ => panic!("Expected Mlkem768X25519Plus"),
        }
    }
}
