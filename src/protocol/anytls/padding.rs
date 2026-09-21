use md5::Digest;
use std::collections::HashMap;
use tokio::io::AsyncWriteExt;

pub const DEFAULT_PADDING_SCHEME: &str = "stop=8\n0=30-30\n1=100-400\n2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n3=9-9,500-1000\n4=500-1000\n5=500-1000\n6=500-1000\n7=500-1000";

pub const CMD_WASTE: u8 = 0;
pub const FRAME_OVERHEAD: usize = 7;
pub const MAX_FRAME_SIZE: usize = 0xffff;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaddingRange {
    CheckMark,

    Range(u16, u16),

    Exact(u16),
}

#[derive(Debug, Clone)]
pub struct CompiledPaddingScheme {
    pub raw: String,
    pub md5_bytes: [u8; 16],
    pub md5_hex: String,
    pub stop: u32,
    pub records: HashMap<u32, Vec<PaddingRange>>,
}

impl CompiledPaddingScheme {
    pub fn parse(raw: &str) -> Result<Self, String> {
        let mut stop: Option<u32> = None;
        let mut records: HashMap<u32, Vec<PaddingRange>> = HashMap::new();

        for line in raw.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("Invalid padding scheme line, missing '=': {line}"))?;
            let key = key.trim();
            let value = value.trim();

            if key == "stop" {
                let s = value
                    .parse::<i64>()
                    .map_err(|e| format!("Invalid stop value '{value}': {e}"))?;
                if s < 0 {
                    return Err(format!("Invalid negative stop value: {s}"));
                }
                stop = Some(s as u32);
                continue;
            }

            let packet_id = key
                .parse::<u32>()
                .map_err(|e| format!("Invalid packet id '{key}': {e}"))?;
            let mut ranges = Vec::new();
            for item in value.split(',') {
                let item = item.trim();
                if item == "c" {
                    ranges.push(PaddingRange::CheckMark);
                    continue;
                }
                let (min_s, max_s) = item.split_once('-').ok_or_else(|| {
                    format!("Invalid padding range item '{item}' in line: {line}")
                })?;
                let mut min_val = min_s
                    .trim()
                    .parse::<u16>()
                    .map_err(|e| format!("Invalid min size '{min_s}': {e}"))?;
                let mut max_val = max_s
                    .trim()
                    .parse::<u16>()
                    .map_err(|e| format!("Invalid max size '{max_s}': {e}"))?;
                if min_val > max_val {
                    std::mem::swap(&mut min_val, &mut max_val);
                }
                if min_val == 0 || max_val == 0 {
                    continue;
                }
                if min_val == max_val {
                    ranges.push(PaddingRange::Exact(min_val));
                } else {
                    ranges.push(PaddingRange::Range(min_val, max_val));
                }
            }
            if !ranges.is_empty() {
                records.insert(packet_id, ranges);
            }
        }

        let stop = stop.ok_or_else(|| "Missing 'stop' in padding scheme".to_string())?;

        let mut hasher = md5::Md5::new();
        md5::Digest::update(&mut hasher, raw.as_bytes());
        let md5_bytes: [u8; 16] = md5::Digest::finalize(hasher).into();
        let md5_hex = hex::encode(md5_bytes);

        Ok(Self {
            raw: raw.to_string(),
            md5_bytes,
            md5_hex,
            stop,
            records,
        })
    }

    pub fn generate_record_payload_sizes(&self, packet: u32) -> Option<Vec<i32>> {
        let ranges = self.records.get(&packet)?;
        if ranges.is_empty() {
            return None;
        }
        let mut sizes = Vec::with_capacity(ranges.len());
        for item in ranges {
            match item {
                PaddingRange::CheckMark => {
                    sizes.push(-1);
                }
                PaddingRange::Exact(val) => {
                    sizes.push(*val as i32);
                }
                PaddingRange::Range(min, max) => {
                    let min_u = *min as u32;
                    let max_u = *max as u32;
                    let diff = max_u - min_u;
                    let offset = if diff > 0 {
                        rand::random::<u32>() % diff
                    } else {
                        0
                    };
                    sizes.push((min_u + offset) as i32);
                }
            }
        }
        Some(sizes)
    }
}

pub async fn write_padded_frame<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    data: &[u8],
    packet_count: &mut u32,
    send_padding: &mut bool,
    scheme: &CompiledPaddingScheme,
) -> std::io::Result<()> {
    *packet_count += 1;
    if *packet_count >= scheme.stop {
        *send_padding = false;
        return writer.write_all(data).await;
    }

    let sizes_opt = scheme.generate_record_payload_sizes(*packet_count);
    let sizes = match sizes_opt {
        Some(s) => s,
        None => {
            return writer.write_all(data).await;
        }
    };

    let mut remaining_data = data;

    for size in sizes {
        if size == -1 {
            if remaining_data.is_empty() {
                return Ok(());
            }
            continue;
        }

        let target_size = size as usize;
        if remaining_data.len() > target_size {
            writer.write_all(&remaining_data[..target_size]).await?;
            remaining_data = &remaining_data[target_size..];
            continue;
        }

        let waste_count = (target_size + MAX_FRAME_SIZE - 1) / MAX_FRAME_SIZE;
        let mut record = Vec::with_capacity(target_size + waste_count * FRAME_OVERHEAD);

        if !remaining_data.is_empty() {
            record.extend_from_slice(remaining_data);
            remaining_data = &[];
            let mut remaining_pad = target_size.saturating_sub(record.len());
            while remaining_pad > FRAME_OVERHEAD {
                let waste_len = (remaining_pad - FRAME_OVERHEAD).min(MAX_FRAME_SIZE);
                record.push(CMD_WASTE);
                record.extend_from_slice(&0u32.to_be_bytes());
                record.extend_from_slice(&(waste_len as u16).to_be_bytes());
                record.resize(record.len() + waste_len, 0);
                remaining_pad -= FRAME_OVERHEAD + waste_len;
            }
        } else {
            let mut remaining_pad = target_size;
            while remaining_pad > 0 {
                let waste_len = remaining_pad.min(MAX_FRAME_SIZE);
                record.push(CMD_WASTE);
                record.extend_from_slice(&0u32.to_be_bytes());
                record.extend_from_slice(&(waste_len as u16).to_be_bytes());
                record.resize(record.len() + waste_len, 0);
                remaining_pad -= waste_len;
            }
        }

        writer.write_all(&record).await?;
    }

    if !remaining_data.is_empty() {
        writer.write_all(remaining_data).await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compiled_padding_scheme_default() {
        let scheme = CompiledPaddingScheme::parse(DEFAULT_PADDING_SCHEME).unwrap();
        assert_eq!(scheme.stop, 8);
        assert_eq!(scheme.records.len(), 8);

        let r0 = scheme.records.get(&0).unwrap();
        assert_eq!(r0.len(), 1);
        assert_eq!(r0[0], PaddingRange::Exact(30));

        let r2 = scheme.records.get(&2).unwrap();
        assert_eq!(r2.len(), 9);
        assert_eq!(r2[0], PaddingRange::Range(400, 500));
        assert_eq!(r2[1], PaddingRange::CheckMark);

        assert_eq!(scheme.md5_hex.len(), 32);
        assert_eq!(scheme.md5_bytes.len(), 16);
    }

    #[test]
    fn test_compiled_padding_scheme_invalid() {
        assert!(CompiledPaddingScheme::parse("stop=-1\n0=10-20").is_err());

        assert!(CompiledPaddingScheme::parse("0=10-20").is_err());

        assert!(CompiledPaddingScheme::parse("invalid_line").is_err());
    }

    #[test]
    fn test_generate_payload_sizes() {
        let scheme = CompiledPaddingScheme::parse(DEFAULT_PADDING_SCHEME).unwrap();
        let sizes = scheme.generate_record_payload_sizes(2).unwrap();
        assert_eq!(sizes.len(), 9);

        assert!(sizes[0] >= 400 && sizes[0] < 500);

        assert_eq!(sizes[1], -1);
    }
}
