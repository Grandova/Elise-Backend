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

/// Server-side manager for VLESS Encryption (`mlkem768x25519plus`).
#[derive(Clone)]
pub struct VlessEncryptionServer {
    config: Arc<HandshakeServerConfig>,
}

impl VlessEncryptionServer {
    /// Creates a new encryption server from normalized MlkemConfig.
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

    /// Performs VLESS Encryption handshake on an established stream.
    pub async fn handshake(&self, stream: BoxedStream) -> io::Result<BoxedStream> {
        let enc_stream = perform_server_handshake(stream, &self.config).await?;
        Ok(Box::new(enc_stream))
    }
}
