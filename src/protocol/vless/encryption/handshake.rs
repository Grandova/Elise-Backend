use super::aead::{VlessAead, MAX_NONCE};
use super::mlkem768::{self, MLKEM768_CIPHERTEXT_SIZE, MLKEM768_EK_SIZE};
use super::session::SessionStore;
use super::stream::VlessEncryptionStream;
use super::xor::{Aes256Ctr, XorFilter};
use crate::conn::BoxedStream;
use rand::rngs::OsRng;
use rand::Rng;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct HandshakeServerConfig {
    pub nfs_private_key: Vec<u8>,
    pub nfs_public_key: Vec<u8>,
    pub xor_mode: u32,
    pub seconds_from: i64,
    pub seconds_to: i64,
    pub session_store: Arc<SessionStore>,
}

pub async fn perform_server_handshake(
    mut stream: BoxedStream,
    cfg: &HandshakeServerConfig,
) -> io::Result<VlessEncryptionStream> {
    let is_mlkem_auth = cfg.nfs_private_key.len() > 32;
    let relay_len = if is_mlkem_auth { 1088 } else { 32 };

    let mut iv_and_relays = vec![0u8; 16 + relay_len];
    stream.read_exact(&mut iv_and_relays).await?;

    let (iv, relays) = iv_and_relays.split_at_mut(16);

    if cfg.xor_mode > 0 {
        let mut ctr = Aes256Ctr::new(&cfg.nfs_public_key, iv);
        ctr.xor_keystream(relays);
    }

    let nfs_key = if !is_mlkem_auth {
        if relays.len() < 32 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "relays too short for X25519",
            ));
        }
        if relays[31] > 127 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "the highest bit of the last byte of peer X25519 pubkey is not 0",
            ));
        }
        let mut peer_pub_bytes = [0u8; 32];
        peer_pub_bytes.copy_from_slice(&relays[..32]);
        let peer_pub = PublicKey::from(peer_pub_bytes);

        let mut priv_bytes = [0u8; 32];
        priv_bytes.copy_from_slice(&cfg.nfs_private_key[..32]);
        let priv_secret = StaticSecret::from(priv_bytes);

        priv_secret.diffie_hellman(&peer_pub).to_bytes().to_vec()
    } else {
        if relays.len() < MLKEM768_CIPHERTEXT_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "relays too short for ML-KEM-768 ciphertext",
            ));
        }
        let mut ct = [0u8; MLKEM768_CIPHERTEXT_SIZE];
        ct.copy_from_slice(&relays[..MLKEM768_CIPHERTEXT_SIZE]);
        let ss = mlkem768::decapsulate(&cfg.nfs_private_key, &ct)?;
        ss.to_vec()
    };

    let mut encrypted_length = [0u8; 18];
    stream.read_exact(&mut encrypted_length).await?;

    let mut use_aes = true;
    let mut nfs_aead = VlessAead::new(iv, &nfs_key, use_aes);
    let decrypted_length = match nfs_aead.open(None, &encrypted_length, &[]) {
        Ok(d) => d,
        Err(_) => {
            use_aes = false;
            nfs_aead = VlessAead::new(iv, &nfs_key, use_aes);
            nfs_aead.open(None, &encrypted_length, &[])?
        }
    };

    if decrypted_length.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid decrypted length field",
        ));
    }
    let length = ((decrypted_length[0] as usize) << 8) | (decrypted_length[1] as usize);

    if length == 32 {
        if cfg.seconds_from == 0 && cfg.seconds_to == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "0-RTT is not allowed",
            ));
        }
        let mut encrypted_ticket = [0u8; 32];
        stream.read_exact(&mut encrypted_ticket).await?;

        let ticket_bytes = nfs_aead.open(None, &encrypted_ticket, &[])?;
        if ticket_bytes.len() != 16 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid ticket length",
            ));
        }
        let mut ticket = [0u8; 16];
        ticket.copy_from_slice(&ticket_bytes);

        let mut nfs_key_32 = [0u8; 32];
        nfs_key_32.copy_from_slice(&nfs_key[..32]);

        let pfs_key = cfg
            .session_store
            .validate_and_record_nfs_key(&ticket, &nfs_key_32)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("0-RTT ticket validation failed: {e:?}"),
                )
            })?;

        let mut united_key = Vec::with_capacity(64 + 32);
        united_key.extend_from_slice(&pfs_key);
        united_key.extend_from_slice(&nfs_key);

        let mut pre_write = [0u8; 16];
        rand::RngCore::fill_bytes(&mut OsRng, &mut pre_write);

        let aead = VlessAead::new(&pre_write, &united_key, use_aes);
        let peer_aead = VlessAead::new(&encrypted_ticket, &united_key, use_aes);

        let xor_filter = if cfg.xor_mode == 2 {
            Some(XorFilter::new(
                Aes256Ctr::new(&united_key, &pre_write),
                Aes256Ctr::new(&united_key, iv),
                16,
                0,
            ))
        } else {
            None
        };

        return Ok(VlessEncryptionStream::new(
            stream,
            use_aes,
            united_key,
            aead,
            peer_aead,
            Some(pre_write.to_vec()),
            xor_filter,
        ));
    }

    if length < MLKEM768_EK_SIZE + 32 + 16 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "1-RTT public key length too short",
        ));
    }

    let mut encrypted_pfs_pub = vec![0u8; length];
    stream.read_exact(&mut encrypted_pfs_pub).await?;

    let decrypted_pfs_pub = nfs_aead.open(None, &encrypted_pfs_pub, &[])?;
    if decrypted_pfs_pub.len() < MLKEM768_EK_SIZE + 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "decrypted pfs pubkey buffer too short",
        ));
    }

    let mut client_mlkem_ek = [0u8; MLKEM768_EK_SIZE];
    client_mlkem_ek.copy_from_slice(&decrypted_pfs_pub[..MLKEM768_EK_SIZE]);

    let mut client_x25519_pub_bytes = [0u8; 32];
    client_x25519_pub_bytes
        .copy_from_slice(&decrypted_pfs_pub[MLKEM768_EK_SIZE..MLKEM768_EK_SIZE + 32]);
    let client_x25519_pub = PublicKey::from(client_x25519_pub_bytes);

    let (mlkem_ss, encapsulated_pfs_key) = mlkem768::encapsulate(&client_mlkem_ek);

    let server_x25519_priv = StaticSecret::random_from_rng(OsRng);
    let server_x25519_pub = PublicKey::from(&server_x25519_priv);
    let x25519_ss = server_x25519_priv
        .diffie_hellman(&client_x25519_pub)
        .to_bytes();

    let mut pfs_key = [0u8; 64];
    pfs_key[..32].copy_from_slice(&mlkem_ss);
    pfs_key[32..].copy_from_slice(&x25519_ss);

    let mut pfs_public_key = Vec::with_capacity(1088 + 32);
    pfs_public_key.extend_from_slice(&encapsulated_pfs_key);
    pfs_public_key.extend_from_slice(server_x25519_pub.as_bytes());

    let mut united_key = Vec::with_capacity(64 + 32);
    united_key.extend_from_slice(&pfs_key);
    united_key.extend_from_slice(&nfs_key);

    let mut aead = VlessAead::new(&pfs_public_key, &united_key, use_aes);
    let peer_aead = VlessAead::new(
        &decrypted_pfs_pub[..MLKEM768_EK_SIZE + 32],
        &united_key,
        use_aes,
    );

    let mut ticket = [0u8; 16];
    rand::RngCore::fill_bytes(&mut OsRng, &mut ticket);

    let seconds = if cfg.seconds_to == 0 {
        cfg.seconds_from * rand::thread_rng().gen_range(50..=100) / 100
    } else {
        rand::thread_rng().gen_range(cfg.seconds_from..=cfg.seconds_to)
    };

    ticket[0] = (seconds >> 8) as u8;
    ticket[1] = seconds as u8;

    if seconds > 0 {
        cfg.session_store
            .insert(ticket, pfs_key, Duration::from_secs(seconds.max(0) as u64));
    }

    let pfs_kx_len = 1088 + 32 + 16;
    let enc_ticket_len = 32;
    let pad_len = 18 + rand::thread_rng().gen_range(100..400);

    let mut server_hello = Vec::with_capacity(pfs_kx_len + enc_ticket_len + pad_len);

    let sealed_pfs = nfs_aead.seal(Some(&MAX_NONCE), &pfs_public_key, &[])?;
    server_hello.extend_from_slice(&sealed_pfs);

    let sealed_ticket = aead.seal(None, &ticket, &[])?;
    server_hello.extend_from_slice(&sealed_ticket);

    let pad_payload_len = pad_len - 18;
    let len_bytes = [(pad_payload_len >> 8) as u8, pad_payload_len as u8];
    let sealed_pad_len = aead.seal(None, &len_bytes, &[])?;
    server_hello.extend_from_slice(&sealed_pad_len);

    let dummy_pad = vec![0u8; pad_payload_len.saturating_sub(16)];
    let sealed_pad_body = aead.seal(None, &dummy_pad, &[])?;
    server_hello.extend_from_slice(&sealed_pad_body);

    stream.write_all(&server_hello).await?;
    stream.flush().await?;

    let mut enc_resp_len = [0u8; 18];
    stream.read_exact(&mut enc_resp_len).await?;
    let dec_resp_len = nfs_aead.open(None, &enc_resp_len, &[])?;
    if dec_resp_len.len() >= 2 {
        let resp_len = ((dec_resp_len[0] as usize) << 8) | (dec_resp_len[1] as usize);
        if resp_len > 0 && resp_len <= 65535 {
            let mut enc_resp_pad = vec![0u8; resp_len];
            stream.read_exact(&mut enc_resp_pad).await?;
            let _ = nfs_aead.open(None, &enc_resp_pad, &[]);
        }
    }

    let xor_filter = if cfg.xor_mode == 2 {
        Some(XorFilter::new(
            Aes256Ctr::new(&united_key, &ticket),
            Aes256Ctr::new(&united_key, iv),
            0,
            0,
        ))
    } else {
        None
    };

    Ok(VlessEncryptionStream::new(
        stream, use_aes, united_key, aead, peer_aead, None, xor_filter,
    ))
}
