use crate::protocol::mieru::proto::TrafficPattern;
use rand::Rng;
use std::io::{self, Error, ErrorKind};
use std::time::Duration;

pub const LOW_ENTROPY_CHUNK_LEN: usize = 8;

pub fn pdep_generic(x: u64, mut mask: u64) -> u64 {
    let mut result = 0u64;
    let mut src_bit = 1u64;
    while mask != 0 {
        let mask_bit = mask & mask.wrapping_neg();
        if (x & src_bit) != 0 {
            result |= mask_bit;
        }
        mask &= mask - 1;
        src_bit <<= 1;
    }
    result
}

pub fn pext_generic(x: u64, mut mask: u64) -> u64 {
    let mut result = 0u64;
    let mut result_bit = 1u64;
    while mask != 0 {
        let mask_bit = mask & mask.wrapping_neg();
        if (x & mask_bit) != 0 {
            result |= result_bit;
        }
        mask &= mask - 1;
        result_bit <<= 1;
    }
    result
}

pub fn repeat_u32(v: u32) -> u64 {
    ((v as u64) << 32) | (v as u64)
}

fn rotate_mask(initial_mask: u64, rotation: i32, chunk_index: usize) -> u64 {
    if rotation == 0 || chunk_index == 0 {
        return initial_mask;
    }
    if rotation <= 15 {
        // Rotate right
        initial_mask.rotate_right(((chunk_index % 64) * rotation as usize) as u32)
    } else {
        // Rotate left (high nibble / 16)
        initial_mask.rotate_left(((chunk_index % 64) * (rotation as usize / 16)) as u32)
    }
}

fn low_bits(n: usize) -> u64 {
    if n >= 64 {
        u64::MAX
    } else {
        (1u64 << n) - 1
    }
}

struct LowEntropyParams {
    source_bytes_per_chunk: usize,
    _half_mask_ones: u32,
}

fn get_low_entropy_params(mode: i32) -> io::Result<LowEntropyParams> {
    match mode {
        1 => Ok(LowEntropyParams { source_bytes_per_chunk: 4, _half_mask_ones: 16 }),
        2 => Ok(LowEntropyParams { source_bytes_per_chunk: 5, _half_mask_ones: 20 }),
        3 => Ok(LowEntropyParams { source_bytes_per_chunk: 6, _half_mask_ones: 24 }),
        4 => Ok(LowEntropyParams { source_bytes_per_chunk: 7, _half_mask_ones: 28 }),
        _ => Err(Error::new(ErrorKind::InvalidData, format!("Invalid low entropy mode {}", mode))),
    }
}

/// Generates a valid half mask for a given low entropy mode
pub fn generate_half_mask(mode: i32) -> u32 {
    let ones = match mode {
        1 => 16,
        2 => 20,
        3 => 24,
        4 => 28,
        _ => 16,
    };
    ((1u64 << ones) - 1) as u32
}

pub fn low_entropy_encoded_len(extracted_len: usize, mode: i32) -> io::Result<usize> {
    let params = get_low_entropy_params(mode)?;
    if extracted_len == 0 {
        return Err(Error::new(ErrorKind::InvalidData, "Invalid extracted payload len 0"));
    }
    let mut chunk_count = extracted_len / params.source_bytes_per_chunk;
    if extracted_len % params.source_bytes_per_chunk != 0 {
        chunk_count += 1;
    }
    if chunk_count > (u16::MAX as usize / LOW_ENTROPY_CHUNK_LEN) {
        return Err(Error::new(ErrorKind::InvalidData, "Encoded payload length exceeds u16 limit"));
    }
    Ok(chunk_count * LOW_ENTROPY_CHUNK_LEN)
}

/// Encode ciphertext payload into low-entropy format
pub fn encode_low_entropy(
    src: &[u8],
    mode: i32,
    half_mask: u32,
    rotation: i32,
    padding_bit: u8,
) -> io::Result<Vec<u8>> {
    let params = get_low_entropy_params(mode)?;
    let encoded_len = low_entropy_encoded_len(src.len(), mode)?;
    let mut encoded = vec![0u8; encoded_len];
    let initial_mask = repeat_u32(half_mask);

    let mut chunk_idx = 0;
    let mut src_offset = 0;
    while src_offset < src.len() {
        let mut source_len = params.source_bytes_per_chunk;
        if src.len() - src_offset < source_len {
            source_len = src.len() - src_offset;
        }

        let mut scratch = [0u8; 8];
        scratch[8 - source_len..].copy_from_slice(&src[src_offset..src_offset + source_len]);
        let source = u64::from_be_bytes(scratch);

        let chunk_mask = rotate_mask(initial_mask, rotation, chunk_idx);
        let data_mask = pdep_generic(low_bits(source_len * 8), chunk_mask);
        let mut chunk = pdep_generic(source, chunk_mask);
        if padding_bit == 1 {
            chunk |= !data_mask;
        }

        encoded[chunk_idx * 8..(chunk_idx + 1) * 8].copy_from_slice(&chunk.to_be_bytes());

        chunk_idx += 1;
        src_offset += params.source_bytes_per_chunk;
    }

    Ok(encoded)
}

/// Decode low-entropy payload into original ciphertext body
pub fn decode_low_entropy(
    encoded: &[u8],
    extracted_len: usize,
    mode: i32,
    half_mask: u32,
    rotation: i32,
) -> io::Result<Vec<u8>> {
    let params = get_low_entropy_params(mode)?;
    let expected_len = low_entropy_encoded_len(extracted_len, mode)?;
    if encoded.len() != expected_len {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("Encoded payload len is {}, expected {}", encoded.len(), expected_len),
        ));
    }

    let mut decoded = vec![0u8; extracted_len];
    let initial_mask = repeat_u32(half_mask);
    let mut inferred_padding_bit: Option<u8> = None;

    let mut chunk_idx = 0;
    let mut dst_offset = 0;
    while dst_offset < extracted_len {
        let mut source_len = params.source_bytes_per_chunk;
        if extracted_len - dst_offset < source_len {
            source_len = extracted_len - dst_offset;
        }

        let chunk = u64::from_be_bytes(
            encoded[chunk_idx * 8..(chunk_idx + 1) * 8]
                .try_into()
                .unwrap(),
        );
        let chunk_mask = rotate_mask(initial_mask, rotation, chunk_idx);
        let data_mask = pdep_generic(low_bits(source_len * 8), chunk_mask);
        let padding_mask = !data_mask;
        let padding = chunk & padding_mask;

        if chunk_idx == 0 {
            if padding == 0 {
                inferred_padding_bit = Some(0);
            } else if padding == padding_mask {
                inferred_padding_bit = Some(1);
            } else {
                return Err(Error::new(ErrorKind::InvalidData, "Mixed padding bits in chunk 0"));
            }
        } else {
            let p_bit = inferred_padding_bit.unwrap_or(0);
            if (p_bit == 0 && padding != 0) || (p_bit == 1 && padding != padding_mask) {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    format!("Non-uniform padding bits in chunk {}", chunk_idx),
                ));
            }
        }

        let source = pext_generic(chunk, chunk_mask);
        let scratch = source.to_be_bytes();
        decoded[dst_offset..dst_offset + source_len].copy_from_slice(&scratch[8 - source_len..]);

        chunk_idx += 1;
        dst_offset += params.source_bytes_per_chunk;
    }

    Ok(decoded)
}

/// Helper for managing and executing active TrafficPattern settings
#[derive(Clone, Debug, Default)]
pub struct TrafficPatternExecutor {
    pattern: Option<TrafficPattern>,
}

impl TrafficPatternExecutor {
    pub fn new(pattern: Option<TrafficPattern>) -> Self {
        Self { pattern }
    }

    pub fn pattern(&self) -> Option<&TrafficPattern> {
        self.pattern.as_ref()
    }

    /// Check if TCP fragmentation is enabled
    pub fn is_tcp_fragment_enabled(&self) -> bool {
        self.pattern
            .as_ref()
            .and_then(|p| p.tcp_fragment.as_ref())
            .and_then(|f| f.enable)
            .unwrap_or(false)
    }

    /// Get max sleep ms between TCP fragments
    pub fn max_tcp_sleep_ms(&self) -> u32 {
        self.pattern
            .as_ref()
            .and_then(|p| p.tcp_fragment.as_ref())
            .and_then(|f| f.max_sleep_ms)
            .unwrap_or(0)
            .max(0) as u32
    }

    /// Slice a buffer into fragments according to Mieru TCP fragment rules
    pub fn fragment_tcp_buffer<'a>(&self, data: &'a [u8]) -> Vec<&'a [u8]> {
        if !self.is_tcp_fragment_enabled() || data.len() <= 1 {
            return vec![data];
        }

        let mut slices = Vec::new();
        let mut remaining = data;
        let mut rng = rand::thread_rng();

        while !remaining.is_empty() {
            let min_len = (data.len() as f64).sqrt() as usize + 1;
            let max_len = min_len.max(data.len() / 2);
            let chunk_len = if max_len > min_len {
                rng.gen_range(min_len..=max_len)
            } else {
                min_len
            };
            let to_send = chunk_len.min(remaining.len());
            slices.push(&remaining[..to_send]);
            remaining = &remaining[to_send..];
        }

        slices
    }

    /// Random sleep duration between TCP fragments
    pub fn next_tcp_fragment_sleep(&self) -> Option<Duration> {
        let max_ms = self.max_tcp_sleep_ms();
        if max_ms == 0 {
            return None;
        }
        let ms = rand::thread_rng().gen_range(0..=max_ms);
        if ms > 0 {
            Some(Duration::from_millis(ms as u64))
        } else {
            None
        }
    }

    /// Apply NoncePattern rules to the first 16 bytes of a 24-byte Nonce
    pub fn apply_nonce_pattern(&self, nonce: &mut [u8; 24], is_udp: bool, is_first: bool) {
        let pattern = match self.pattern.as_ref().and_then(|p| p.nonce.as_ref()) {
            Some(p) => p,
            None => return,
        };

        if is_udp && !is_first && !pattern.apply_to_all_udp_packet.unwrap_or(false) {
            return;
        }

        let nonce_type = pattern.r#type.unwrap_or(0);
        let min_len = pattern.min_len.unwrap_or(0).clamp(0, 12) as usize;
        let max_len = pattern.max_len.unwrap_or(12).clamp(min_len as i32, 12) as usize;

        let mut rng = rand::thread_rng();
        let len = if max_len > min_len {
            rng.gen_range(min_len..=max_len)
        } else {
            min_len
        };

        match nonce_type {
            1 => {
                // Printable ASCII 0x20..=0x7E
                for b in nonce[..len].iter_mut() {
                    *b = rng.gen_range(0x20..=0x7E);
                }
            }
            2 => {
                // Printable ASCII subset: digits and ASCII letters
                const SUBSET: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
                for b in nonce[..len].iter_mut() {
                    *b = SUBSET[rng.gen_range(0..SUBSET.len())];
                }
            }
            3 => {
                // Fixed: select random from customHexStrings
                if !pattern.custom_hex_strings.is_empty() {
                    let idx = rng.gen_range(0..pattern.custom_hex_strings.len());
                    if let Ok(bytes) = hex::decode(&pattern.custom_hex_strings[idx]) {
                        let fill_len = bytes.len().min(12);
                        nonce[..fill_len].copy_from_slice(&bytes[..fill_len]);
                    }
                }
            }
            _ => {} // 0 = Random, leave random bytes as is
        }
    }

    /// Generate random middle padding bytes (padding 1)
    pub fn generate_middle_padding(&self) -> Vec<u8> {
        let max_len = self
            .pattern
            .as_ref()
            .and_then(|p| p.padding.as_ref())
            .and_then(|pad| pad.max_middle_padding_len)
            .unwrap_or(0)
            .clamp(0, 255) as usize;

        if max_len == 0 {
            return Vec::new();
        }
        let len = rand::thread_rng().gen_range(0..=max_len);
        let mut buf = vec![0u8; len];
        rand::thread_rng().fill(&mut buf[..]);
        buf
    }

    /// Generate random end padding bytes (padding 2)
    pub fn generate_end_padding(&self) -> Vec<u8> {
        let max_len = self
            .pattern
            .as_ref()
            .and_then(|p| p.padding.as_ref())
            .and_then(|pad| pad.max_end_padding_len)
            .unwrap_or(0)
            .clamp(0, 255) as usize;

        if max_len == 0 {
            return Vec::new();
        }
        let len = rand::thread_rng().gen_range(0..=max_len);
        let mut buf = vec![0u8; len];
        rand::thread_rng().fill(&mut buf[..]);
        buf
    }
}
