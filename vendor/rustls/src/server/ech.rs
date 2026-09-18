use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use crate::enums::CipherSuite;
use crate::msgs::codec::{Codec, Reader};
use crate::msgs::enums::ExtensionType;
use crate::msgs::handshake::{
    ClientExtensions, ClientHelloPayload, EncryptedClientHello, EncryptedClientHelloOuter, Random,
    SessionId,
};

/// Server-side ECH configuration and private key.
#[derive(Clone, Debug)]
pub struct EchServerConfigAndKey {
    /// The config ID matching the ECHConfig.
    pub config_id: u8,
    /// The public name of the outer cover domain.
    pub public_name: String,
    /// The server's X25519 private key (32 bytes).
    pub private_key: [u8; 32],
    /// The server's X25519 public key (32 bytes).
    pub public_key: [u8; 32],
    /// The raw serialized ECHConfig payload bytes.
    pub raw_ech_config: Vec<u8>,
}

impl EchServerConfigAndKey {
    /// Constructs a new ECH server key config for DHKEM(X25519, HKDF-SHA256).
    pub fn new(
        config_id: u8,
        public_name: String,
        private_key: [u8; 32],
        public_key: [u8; 32],
        raw_ech_config: Vec<u8>,
    ) -> Self {
        Self {
            config_id,
            public_name,
            private_key,
            public_key,
            raw_ech_config,
        }
    }
}

/// Decrypts an incoming ClientHelloOuter containing ECH if supported, returning
/// `(effective_client_hello, Option<inner_random>)`.
///
/// If ECH was accepted and decrypted, `effective_client_hello` is the reconstructed
/// `ClientHelloInner`, and `Option<inner_random>` is `Some(inner_random)` for computing
/// `accept_confirmation`.
///
/// If ECH was not offered or decryption failed, returns the original `outer_hello` and `None`.
pub(crate) fn process_server_ech(
    outer_hello: ClientHelloPayload,
    raw_outer_ch: Option<&[u8]>,
    server_keys: Option<&Arc<Vec<EchServerConfigAndKey>>>,
    conn_id: u64,
) -> (ClientHelloPayload, Option<Random>, Option<Vec<u8>>) {
    let keys = match server_keys {
        Some(k) if !k.is_empty() => k,
        _ => return (outer_hello, None, None),
    };

    let ech_outer = match &outer_hello.encrypted_client_hello {
        Some(EncryptedClientHello::Outer(outer)) => outer.clone(),
        _ => return (outer_hello, None, None),
    };

    crate::log::info!("[ECH] conn={} offered=true config_id={}", conn_id, ech_outer.config_id);

    // Find matching key by config_id
    let matching_key = match keys.iter().find(|k| k.config_id == ech_outer.config_id) {
        Some(k) => k,
        None => {
            crate::log::warn!("[ECH] conn={} no matching key for config_id {}, ech=rejected", conn_id, ech_outer.config_id);
            return (outer_hello, None, None);
        }
    };

    // Only support X25519 enc (32 bytes)
    if ech_outer.enc.0.len() != 32 {
        crate::log::warn!("[ECH] conn={} enc len != 32 ({}), ech=rejected", conn_id, ech_outer.enc.0.len());
        return (outer_hello, None, None);
    }
    let mut enc_bytes = [0u8; 32];
    enc_bytes.copy_from_slice(&ech_outer.enc.0);

    let kdf_id = u16::from(ech_outer.cipher_suite.kdf_id);
    let aead_id = u16::from(ech_outer.cipher_suite.aead_id);

    // KDF must be HKDF-SHA256 (0x0001)
    if kdf_id != 0x0001 {
        crate::log::warn!("[ECH] conn={} unsupported kdf {:#x}, ech=rejected", conn_id, kdf_id);
        return (outer_hello, None, None);
    }

    // info = b"tls ech\0" || raw_ech_config
    let mut info = Vec::with_capacity(8 + matching_key.raw_ech_config.len());
    info.extend_from_slice(b"tls ech\0");
    info.extend_from_slice(&matching_key.raw_ech_config);

    // Prepare AAD: ClientHelloOuter with encrypted_client_hello payload set to zeros of length ciphertext.len()
    let payload_len = ech_outer.payload.0.len();
    let aad = if let Some(raw_ch) = raw_outer_ch {
        if let Some(wire_aad) = compute_ech_aad(raw_ch, payload_len) {
            wire_aad
        } else {
            let placeholder_ext = EncryptedClientHello::Outer(EncryptedClientHelloOuter {
                cipher_suite: ech_outer.cipher_suite,
                config_id: ech_outer.config_id,
                enc: ech_outer.enc.clone(),
                payload: crate::msgs::base::PayloadU16::new(vec![0u8; payload_len]),
            });
            let mut outer_for_aad = outer_hello.clone();
            outer_for_aad.encrypted_client_hello = Some(placeholder_ext);
            outer_for_aad.get_encoding()
        }
    } else {
        let placeholder_ext = EncryptedClientHello::Outer(EncryptedClientHelloOuter {
            cipher_suite: ech_outer.cipher_suite,
            config_id: ech_outer.config_id,
            enc: ech_outer.enc.clone(),
            payload: crate::msgs::base::PayloadU16::new(vec![0u8; payload_len]),
        });
        let mut outer_for_aad = outer_hello.clone();
        outer_for_aad.encrypted_client_hello = Some(placeholder_ext);
        outer_for_aad.get_encoding()
    };

    // Perform HPKE Open
    let plaintext = match hpke_open(
        0x0020, // DHKEM(X25519, HKDF-SHA256)
        kdf_id,
        aead_id,
        &matching_key.private_key,
        &enc_bytes,
        &info,
        &aad,
        &ech_outer.payload.0,
    ) {
        Ok(pt) => {
            crate::log::debug!("[ECH] conn={} hpke_open=true pt_len={}", conn_id, pt.len());
            pt
        }
        Err(e) => {
            crate::log::warn!("[ECH] conn={} hpke_open=false error={}, ech=rejected", conn_id, e);
            return (outer_hello, None, None);
        }
    };

    // Parse EncodedClientHelloInner from plaintext
    let mut reader = Reader::init(&plaintext);
    let inner_parsed = match parse_inner_client_hello(&mut reader) {
        Ok(ch) => {
            let inner_sni_str = ch.server_name.as_ref().map(|s| match s {
                crate::msgs::handshake::ServerNamePayload::SingleDnsName(d) => d.as_ref(),
                _ => "unknown",
            }).unwrap_or("none");
            crate::log::info!("[ECH] conn={} inner_sni={}", conn_id, inner_sni_str);
            ch
        }
        Err(e) => {
            crate::log::warn!("[ECH] conn={} parse_inner_client_hello=false error={:?}, ech=rejected", conn_id, e);
            return (outer_hello, None, None);
        }
    };

    let inner_random = inner_parsed.random;

    // Reconstruct ClientHelloInner:
    let mut inner_hello = inner_parsed;
    inner_hello.session_id = outer_hello.session_id;

    // Expand outer_extensions if present
    if let Some(compressed) = inner_hello.extensions.encrypted_client_hello_outer.take() {
        for ext_type in compressed {
            copy_extension_from_outer(&outer_hello.extensions, &mut inner_hello.extensions, ext_type);
        }
    }

    let wire_inner_hs = if let Some(raw_ch) = raw_outer_ch {
        reconstruct_client_hello_inner_wire(raw_ch, &plaintext)
    } else {
        None
    };

    crate::log::debug!("[ECH] conn={} reconstructed wire_inner_hs is_some={} len={}", conn_id, wire_inner_hs.is_some(), wire_inner_hs.as_ref().map(|w| w.len()).unwrap_or(0));

    (inner_hello, Some(inner_random), wire_inner_hs)
}

/// Helper to parse EncodedClientHelloInner without rejecting trailing zero padding.
fn parse_inner_client_hello(r: &mut Reader<'_>) -> Result<ClientHelloPayload, crate::error::InvalidMessage> {
    use crate::msgs::enums::Compression;
    use crate::ProtocolVersion;

    let client_version = ProtocolVersion::read(r)?;
    let random = Random::read(r)?;
    let session_id = SessionId::read(r)?;
    let cipher_suites = Vec::<CipherSuite>::read(r)?;
    let compression_methods = Vec::<Compression>::read(r)?;
    let extensions = Box::new(ClientExtensions::read(r)?.into_owned());

    Ok(ClientHelloPayload {
        client_version,
        random,
        session_id,
        cipher_suites,
        compression_methods,
        extensions,
    })
}

/// Copies an extension from Outer to Inner for ECH extension compression.
fn copy_extension_from_outer(
    outer_exts: &ClientExtensions<'static>,
    inner_exts: &mut ClientExtensions<'static>,
    ext_type: ExtensionType,
) {
    match ext_type {
        ExtensionType::ServerName => {
            if inner_exts.server_name.is_none() {
                inner_exts.server_name = outer_exts.server_name.clone();
            }
        }
        ExtensionType::KeyShare => {
            if inner_exts.key_shares.is_none() {
                inner_exts.key_shares = outer_exts.key_shares.clone();
            }
        }
        ExtensionType::SupportedVersions => {
            if inner_exts.supported_versions.is_none() {
                inner_exts.supported_versions = outer_exts.supported_versions.clone();
            }
        }
        ExtensionType::ALProtocolNegotiation => {
            if inner_exts.protocols.is_none() {
                inner_exts.protocols = outer_exts.protocols.clone();
            }
        }
        ExtensionType::SignatureAlgorithms => {
            if inner_exts.signature_schemes.is_none() {
                inner_exts.signature_schemes = outer_exts.signature_schemes.clone();
            }
        }
        ExtensionType::EllipticCurves => {
            if inner_exts.named_groups.is_none() {
                inner_exts.named_groups = outer_exts.named_groups.clone();
            }
        }
        _ => {}
    }
}

/// Computes ClientHelloOuterAAD directly from raw wire bytes of ClientHelloOuter.
///
/// Per RFC draft-ietf-tls-esni-18 section 5.1 / RFC 9849:
/// The AAD is the exact serialized ClientHelloOuter bytes, with the ECH payload
/// replaced by zeros of equal length.
pub(crate) fn compute_ech_aad(raw_ch: &[u8], payload_len: usize) -> Option<Vec<u8>> {
    if raw_ch.len() < 2 + 32 + 1 + 2 + 1 + 2 {
        return None;
    }
    let mut offset = 2 + 32;
    let sid_len = raw_ch[offset] as usize;
    offset += 1 + sid_len;
    if raw_ch.len() < offset + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([raw_ch[offset], raw_ch[offset + 1]]) as usize;
    offset += 2 + cs_len;
    if raw_ch.len() < offset + 1 {
        return None;
    }
    let comp_len = raw_ch[offset] as usize;
    offset += 1 + comp_len;
    if raw_ch.len() < offset + 2 {
        return None;
    }
    let exts_len = u16::from_be_bytes([raw_ch[offset], raw_ch[offset + 1]]) as usize;
    offset += 2;
    let exts_end = offset + exts_len;
    if raw_ch.len() < exts_end {
        return None;
    }

    while offset + 4 <= exts_end {
        let ext_type = u16::from_be_bytes([raw_ch[offset], raw_ch[offset + 1]]);
        let ext_len = u16::from_be_bytes([raw_ch[offset + 2], raw_ch[offset + 3]]) as usize;
        offset += 4;
        if offset + ext_len > exts_end {
            return None;
        }

        if ext_type == 0xfe0d {
            let ext_data = &raw_ch[offset..offset + ext_len];
            if ext_data.len() < 1 + 4 + 1 + 2 {
                return None;
            }
            if ext_data[0] != 0 {
                return None; // EchClientHelloType::ClientHelloOuter = 0
            }
            let enc_len = u16::from_be_bytes([ext_data[6], ext_data[7]]) as usize;
            let payload_header_offset = 1 + 4 + 1 + 2 + enc_len;
            if ext_data.len() < payload_header_offset + 2 {
                return None;
            }
            let reported_payload_len = u16::from_be_bytes([
                ext_data[payload_header_offset],
                ext_data[payload_header_offset + 1],
            ]) as usize;

            if reported_payload_len != payload_len {
                return None;
            }

            let payload_start = offset + payload_header_offset + 2;
            if payload_start + payload_len > raw_ch.len() {
                return None;
            }

            let mut aad = raw_ch.to_vec();
            aad[payload_start..payload_start + payload_len].fill(0);
            return Some(aad);
        }

        offset += ext_len;
    }

    None
}

/// Reconstructs the exact wire bytes of ClientHelloInner as a Handshake message
/// (HandshakeType::ClientHello || Length || ClientHelloInner) from the raw outer ClientHello
/// and the decrypted plaintext (EncodedClientHelloInner).
///
/// Per RFC draft-ietf-tls-esni-18 / RFC 9849 Section 5.1:
/// - Strips trailing padding from EncodedClientHelloInner
/// - Replaces legacy_session_id with the legacy_session_id from ClientHelloOuter
/// - Expands ech_outer_extensions (0xfd00) with the referenced extensions from ClientHelloOuter
/// - Wraps the reconstructed ClientHello with 4-byte Handshake header (type=1, 3-byte len)
pub(crate) fn reconstruct_client_hello_inner_wire(
    raw_outer_ch: &[u8],
    plaintext: &[u8],
) -> Option<Vec<u8>> {
    if plaintext.len() < 35 {
        return None;
    }
    let version_and_random = &plaintext[..34];
    let sid_len = plaintext[34] as usize;
    if sid_len != 0 {
        return None;
    }
    let mut offset = 35;
    if plaintext.len() < offset + 2 {
        return None;
    }
    let cs_len = u16::from_be_bytes([plaintext[offset], plaintext[offset + 1]]) as usize;
    offset += 2 + cs_len;
    if plaintext.len() < offset + 1 {
        return None;
    }
    let comp_len = plaintext[offset] as usize;
    offset += 1 + comp_len;
    if plaintext.len() < offset + 2 {
        return None;
    }
    let exts_len = u16::from_be_bytes([plaintext[offset], plaintext[offset + 1]]) as usize;
    offset += 2;
    if plaintext.len() < offset + exts_len {
        return None;
    }

    let cs_and_comp = &plaintext[35..offset - 2];
    let exts_data = &plaintext[offset..offset + exts_len];

    // Extract outer_sid from raw_outer_ch
    if raw_outer_ch.len() < 35 {
        return None;
    }
    let outer_sid_len = raw_outer_ch[34] as usize;
    if raw_outer_ch.len() < 35 + outer_sid_len {
        return None;
    }
    let outer_sid = &raw_outer_ch[34..35 + outer_sid_len];

    // Parse outer extensions
    let mut outer_off = 35 + outer_sid_len;
    if raw_outer_ch.len() < outer_off + 2 {
        return None;
    }
    let outer_cs_len =
        u16::from_be_bytes([raw_outer_ch[outer_off], raw_outer_ch[outer_off + 1]]) as usize;
    outer_off += 2 + outer_cs_len;
    if raw_outer_ch.len() < outer_off + 1 {
        return None;
    }
    let outer_comp_len = raw_outer_ch[outer_off] as usize;
    outer_off += 1 + outer_comp_len;
    if raw_outer_ch.len() < outer_off + 2 {
        return None;
    }
    let outer_exts_len =
        u16::from_be_bytes([raw_outer_ch[outer_off], raw_outer_ch[outer_off + 1]]) as usize;
    outer_off += 2;
    if raw_outer_ch.len() < outer_off + outer_exts_len {
        return None;
    }
    let outer_exts_data = &raw_outer_ch[outer_off..outer_off + outer_exts_len];

    // Reconstruct extensions: replace 0xfd00 with outer extensions
    let mut reconstructed_exts = Vec::with_capacity(exts_data.len() + 64);
    let mut i = 0;
    while i + 4 <= exts_data.len() {
        let etype = u16::from_be_bytes([exts_data[i], exts_data[i + 1]]);
        let elen = u16::from_be_bytes([exts_data[i + 2], exts_data[i + 3]]) as usize;
        if i + 4 + elen > exts_data.len() {
            return None;
        }

        if etype == 0xfd00 {
            let ref_data = &exts_data[i + 4..i + 4 + elen];
            if ref_data.is_empty() {
                return None;
            }
            let ref_len = ref_data[0] as usize;
            if ref_data.len() < 1 + ref_len {
                return None;
            }
            let mut j = 1;
            while j + 2 <= 1 + ref_len {
                let ref_type = u16::from_be_bytes([ref_data[j], ref_data[j + 1]]);
                let mut found = false;
                let mut oi = 0;
                while oi + 4 <= outer_exts_data.len() {
                    let o_type = u16::from_be_bytes([outer_exts_data[oi], outer_exts_data[oi + 1]]);
                    let o_len =
                        u16::from_be_bytes([outer_exts_data[oi + 2], outer_exts_data[oi + 3]]) as usize;
                    if oi + 4 + o_len > outer_exts_data.len() {
                        return None;
                    }
                    if o_type == ref_type {
                        reconstructed_exts.extend_from_slice(&outer_exts_data[oi..oi + 4 + o_len]);
                        found = true;
                        break;
                    }
                    oi += 4 + o_len;
                }
                if !found {
                    return None;
                }
                j += 2;
            }
        } else {
            reconstructed_exts.extend_from_slice(&exts_data[i..i + 4 + elen]);
        }
        i += 4 + elen;
    }

    let mut ch_body = Vec::with_capacity(
        34 + outer_sid.len() + cs_and_comp.len() + 2 + reconstructed_exts.len(),
    );
    ch_body.extend_from_slice(version_and_random);
    ch_body.extend_from_slice(outer_sid);
    ch_body.extend_from_slice(cs_and_comp);
    ch_body.extend_from_slice(&(reconstructed_exts.len() as u16).to_be_bytes());
    ch_body.extend_from_slice(&reconstructed_exts);

    let body_len = ch_body.len();
    let mut hs_msg = Vec::with_capacity(4 + body_len);
    hs_msg.push(0x01); // HandshakeType::ClientHello
    hs_msg.push((body_len >> 16) as u8);
    hs_msg.push((body_len >> 8) as u8);
    hs_msg.push(body_len as u8);
    hs_msg.extend_from_slice(&ch_body);

    Some(hs_msg)
}

/// RFC 9180 HPKE Base Mode Decryption
/// Supports:
/// - KEM: 0x0020 (DHKEM(X25519, HKDF-SHA256))
/// - KDF: 0x0001 (HKDF-SHA256)
/// - AEAD: 0x0001 (AES-128-GCM) and 0x0003 (ChaCha20-Poly1305)
pub fn hpke_open(
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    sk_r: &[u8; 32],
    pk_e: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, &'static str> {
    if kem_id != 0x0020 || kdf_id != 0x0001 {
        return Err("unsupported KEM or KDF");
    }

    // 1. DHKEM(X25519, HKDF-SHA256) Decap
    let server_secret = x25519_dalek::StaticSecret::from(*sk_r);
    let server_pub = x25519_dalek::PublicKey::from(&server_secret);
    let client_ephemeral = x25519_dalek::PublicKey::from(*pk_e);
    let dh = server_secret.diffie_hellman(&client_ephemeral);

    // kem_context = enc || pkR
    let mut kem_context = [0u8; 64];
    kem_context[..32].copy_from_slice(pk_e);
    kem_context[32..].copy_from_slice(server_pub.as_bytes());

    let kem_suite_id = b"KEM\x00\x20";

    // eae_prk = LabeledExtract(kem_suite_id, salt="", "eae_prk", dh)
    let mut labeled_ikm = Vec::with_capacity(7 + 5 + 7 + 32);
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(kem_suite_id);
    labeled_ikm.extend_from_slice(b"eae_prk");
    labeled_ikm.extend_from_slice(dh.as_bytes());

    let (_, hk_kem) = hkdf::Hkdf::<sha2::Sha256>::extract(None, &labeled_ikm);

    // shared_secret = LabeledExpand(kem_suite_id, eae_prk, "shared_secret", kem_context, 32)
    let mut labeled_info = Vec::with_capacity(2 + 7 + 5 + 13 + 64);
    labeled_info.extend_from_slice(&32u16.to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(kem_suite_id);
    labeled_info.extend_from_slice(b"shared_secret");
    labeled_info.extend_from_slice(&kem_context);

    let mut shared_secret = [0u8; 32];
    hk_kem
        .expand(&labeled_info, &mut shared_secret)
        .map_err(|_| "HKDF expand shared_secret failed")?;

    // 2. Key Schedule (Base Mode)
    let mut hpke_suite_id = [0u8; 10];
    hpke_suite_id[0..4].copy_from_slice(b"HPKE");
    hpke_suite_id[4..6].copy_from_slice(&kem_id.to_be_bytes());
    hpke_suite_id[6..8].copy_from_slice(&kdf_id.to_be_bytes());
    hpke_suite_id[8..10].copy_from_slice(&aead_id.to_be_bytes());

    // psk_id_hash = LabeledExtract(hpke_suite_id, salt="", "psk_id_hash", "")
    let mut psk_ikm = Vec::new();
    psk_ikm.extend_from_slice(b"HPKE-v1");
    psk_ikm.extend_from_slice(&hpke_suite_id);
    psk_ikm.extend_from_slice(b"psk_id_hash");
    let (psk_id_hash, _) = hkdf::Hkdf::<sha2::Sha256>::extract(None, &psk_ikm);

    // info_hash = LabeledExtract(hpke_suite_id, salt="", "info_hash", info)
    let mut info_ikm = Vec::new();
    info_ikm.extend_from_slice(b"HPKE-v1");
    info_ikm.extend_from_slice(&hpke_suite_id);
    info_ikm.extend_from_slice(b"info_hash");
    info_ikm.extend_from_slice(info);
    let (info_hash, _) = hkdf::Hkdf::<sha2::Sha256>::extract(None, &info_ikm);

    // key_schedule_context = 0x00 || psk_id_hash || info_hash
    let mut key_schedule_context = Vec::with_capacity(1 + 32 + 32);
    key_schedule_context.push(0x00);
    key_schedule_context.extend_from_slice(&psk_id_hash);
    key_schedule_context.extend_from_slice(&info_hash);

    // secret = LabeledExtract(hpke_suite_id, salt=shared_secret, "secret", "")
    let mut secret_ikm = Vec::new();
    secret_ikm.extend_from_slice(b"HPKE-v1");
    secret_ikm.extend_from_slice(&hpke_suite_id);
    secret_ikm.extend_from_slice(b"secret");
    let (_, hk_secret) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(&shared_secret), &secret_ikm);

    let key_len = match aead_id {
        0x0001 => 16, // AES-128-GCM
        0x0002 => 32, // AES-256-GCM
        0x0003 => 32, // ChaCha20-Poly1305
        _ => return Err("unsupported AEAD ID"),
    };

    let mut key_info = Vec::new();
    key_info.extend_from_slice(&(key_len as u16).to_be_bytes());
    key_info.extend_from_slice(b"HPKE-v1");
    key_info.extend_from_slice(&hpke_suite_id);
    key_info.extend_from_slice(b"key");
    key_info.extend_from_slice(&key_schedule_context);

    let mut key = vec![0u8; key_len];
    hk_secret
        .expand(&key_info, &mut key)
        .map_err(|_| "HKDF expand key failed")?;

    let mut nonce_info = Vec::new();
    nonce_info.extend_from_slice(&12u16.to_be_bytes());
    nonce_info.extend_from_slice(b"HPKE-v1");
    nonce_info.extend_from_slice(&hpke_suite_id);
    nonce_info.extend_from_slice(b"base_nonce");
    nonce_info.extend_from_slice(&key_schedule_context);

    let mut base_nonce = [0u8; 12];
    hk_secret
        .expand(&nonce_info, &mut base_nonce)
        .map_err(|_| "HKDF expand base_nonce failed")?;

    // 3. AEAD Open
    match aead_id {
        0x0001 => {
            use aes_gcm::aead::{Aead, KeyInit, Payload};
            let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key).map_err(|_| "init aes-gcm failed")?;
            let nonce = aes_gcm::Nonce::from_slice(&base_nonce);
            cipher
                .decrypt(nonce, Payload { msg: ciphertext, aad })
                .map_err(|_| "aes-gcm decrypt failed")
        }
        0x0003 => {
            use chacha20poly1305::aead::{Aead, KeyInit, Payload};
            let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key)
                .map_err(|_| "init chacha failed")?;
            let nonce = chacha20poly1305::Nonce::from_slice(&base_nonce);
            cipher
                .decrypt(nonce, Payload { msg: ciphertext, aad })
                .map_err(|_| "chacha decrypt failed")
        }
        _ => Err("unsupported AEAD"),
    }
}

/// RFC 9180 HPKE Base Mode Encryption (Client-side helper for testing)
pub fn hpke_seal(
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    pk_r: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), &'static str> {
    if kem_id != 0x0020 || kdf_id != 0x0001 {
        return Err("unsupported KEM or KDF");
    }

    // Ephemeral key pair (deterministic for test helper)
    let ephemeral_secret = x25519_dalek::StaticSecret::from([0x5au8; 32]);
    let ephemeral_pub = x25519_dalek::PublicKey::from(&ephemeral_secret);
    let recipient_pub = x25519_dalek::PublicKey::from(*pk_r);
    let dh = ephemeral_secret.diffie_hellman(&recipient_pub);

    let enc = ephemeral_pub.as_bytes().to_vec();

    // kem_context = enc || pkR
    let mut kem_context = [0u8; 64];
    kem_context[..32].copy_from_slice(&enc);
    kem_context[32..].copy_from_slice(pk_r);

    let kem_suite_id = b"KEM\x00\x20";

    let mut labeled_ikm = Vec::new();
    labeled_ikm.extend_from_slice(b"HPKE-v1");
    labeled_ikm.extend_from_slice(kem_suite_id);
    labeled_ikm.extend_from_slice(b"eae_prk");
    labeled_ikm.extend_from_slice(dh.as_bytes());

    let (_, hk_kem) = hkdf::Hkdf::<sha2::Sha256>::extract(None, &labeled_ikm);

    let mut labeled_info = Vec::new();
    labeled_info.extend_from_slice(&32u16.to_be_bytes());
    labeled_info.extend_from_slice(b"HPKE-v1");
    labeled_info.extend_from_slice(kem_suite_id);
    labeled_info.extend_from_slice(b"shared_secret");
    labeled_info.extend_from_slice(&kem_context);

    let mut shared_secret = [0u8; 32];
    hk_kem
        .expand(&labeled_info, &mut shared_secret)
        .map_err(|_| "HKDF expand shared_secret failed")?;

    let mut hpke_suite_id = [0u8; 10];
    hpke_suite_id[0..4].copy_from_slice(b"HPKE");
    hpke_suite_id[4..6].copy_from_slice(&kem_id.to_be_bytes());
    hpke_suite_id[6..8].copy_from_slice(&kdf_id.to_be_bytes());
    hpke_suite_id[8..10].copy_from_slice(&aead_id.to_be_bytes());

    let mut psk_ikm = Vec::new();
    psk_ikm.extend_from_slice(b"HPKE-v1");
    psk_ikm.extend_from_slice(&hpke_suite_id);
    psk_ikm.extend_from_slice(b"psk_id_hash");
    let (psk_id_hash, _) = hkdf::Hkdf::<sha2::Sha256>::extract(None, &psk_ikm);

    let mut info_ikm = Vec::new();
    info_ikm.extend_from_slice(b"HPKE-v1");
    info_ikm.extend_from_slice(&hpke_suite_id);
    info_ikm.extend_from_slice(b"info_hash");
    info_ikm.extend_from_slice(info);
    let (info_hash, _) = hkdf::Hkdf::<sha2::Sha256>::extract(None, &info_ikm);

    let mut key_schedule_context = Vec::with_capacity(1 + 32 + 32);
    key_schedule_context.push(0x00);
    key_schedule_context.extend_from_slice(&psk_id_hash);
    key_schedule_context.extend_from_slice(&info_hash);

    let mut secret_ikm = Vec::new();
    secret_ikm.extend_from_slice(b"HPKE-v1");
    secret_ikm.extend_from_slice(&hpke_suite_id);
    secret_ikm.extend_from_slice(b"secret");
    let (_, hk_secret) = hkdf::Hkdf::<sha2::Sha256>::extract(Some(&shared_secret), &secret_ikm);

    let key_len = match aead_id {
        0x0001 => 16,
        0x0002 => 32,
        0x0003 => 32,
        _ => return Err("unsupported AEAD ID"),
    };

    let mut key_info = Vec::new();
    key_info.extend_from_slice(&(key_len as u16).to_be_bytes());
    key_info.extend_from_slice(b"HPKE-v1");
    key_info.extend_from_slice(&hpke_suite_id);
    key_info.extend_from_slice(b"key");
    key_info.extend_from_slice(&key_schedule_context);

    let mut key = vec![0u8; key_len];
    hk_secret
        .expand(&key_info, &mut key)
        .map_err(|_| "HKDF expand key failed")?;

    let mut nonce_info = Vec::new();
    nonce_info.extend_from_slice(&12u16.to_be_bytes());
    nonce_info.extend_from_slice(b"HPKE-v1");
    nonce_info.extend_from_slice(&hpke_suite_id);
    nonce_info.extend_from_slice(b"base_nonce");
    nonce_info.extend_from_slice(&key_schedule_context);

    let mut base_nonce = [0u8; 12];
    hk_secret
        .expand(&nonce_info, &mut base_nonce)
        .map_err(|_| "HKDF expand base_nonce failed")?;

    let ciphertext = match aead_id {
        0x0001 => {
            use aes_gcm::aead::{Aead, KeyInit, Payload};
            let cipher = aes_gcm::Aes128Gcm::new_from_slice(&key).map_err(|_| "init aes-gcm failed")?;
            let nonce = aes_gcm::Nonce::from_slice(&base_nonce);
            cipher
                .encrypt(nonce, Payload { msg: plaintext, aad })
                .map_err(|_| "aes-gcm encrypt failed")?
        }
        0x0003 => {
            use chacha20poly1305::aead::{Aead, KeyInit, Payload};
            let cipher = chacha20poly1305::ChaCha20Poly1305::new_from_slice(&key)
                .map_err(|_| "init chacha failed")?;
            let nonce = chacha20poly1305::Nonce::from_slice(&base_nonce);
            cipher
                .encrypt(nonce, Payload { msg: plaintext, aad })
                .map_err(|_| "chacha encrypt failed")?
        }
        _ => return Err("unsupported AEAD"),
    };

    Ok((enc, ciphertext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hpke_roundtrip_aes128() {
        let sk = [42u8; 32];
        let static_sec = x25519_dalek::StaticSecret::from(sk);
        let pk = x25519_dalek::PublicKey::from(&static_sec);

        let info = b"tls ech\0test_config";
        let aad = b"test_aad_outer_hello";
        let pt = b"GET / HTTP/1.1\r\nHost: secret.internal\r\n\r\n";

        let (enc, ct) = hpke_seal(0x0020, 0x0001, 0x0001, pk.as_bytes(), info, aad, pt).unwrap();

        let mut enc_bytes = [0u8; 32];
        enc_bytes.copy_from_slice(&enc);

        let decrypted = hpke_open(0x0020, 0x0001, 0x0001, &sk, &enc_bytes, info, aad, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }

    #[test]
    fn test_hpke_roundtrip_chacha20() {
        let sk = [99u8; 32];
        let static_sec = x25519_dalek::StaticSecret::from(sk);
        let pk = x25519_dalek::PublicKey::from(&static_sec);

        let info = b"tls ech\0test_config";
        let aad = b"test_aad_outer_hello";
        let pt = b"HTTP/2 CONNECT secret.internal:443";

        let (enc, ct) = hpke_seal(0x0020, 0x0001, 0x0003, pk.as_bytes(), info, aad, pt).unwrap();

        let mut enc_bytes = [0u8; 32];
        enc_bytes.copy_from_slice(&enc);

        let decrypted = hpke_open(0x0020, 0x0001, 0x0003, &sk, &enc_bytes, info, aad, &ct).unwrap();
        assert_eq!(decrypted, pt);
    }
}
