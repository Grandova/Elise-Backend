use base64::prelude::*;
use prost::encoding::{decode_key, skip_field, DecodeContext, WireType};
use prost::Message;
use std::io::{self, Error, ErrorKind};

/// Official Mieru TrafficPattern Protobuf schema
#[derive(Clone, PartialEq, Message)]
pub struct TrafficPattern {
    #[prost(int32, optional, tag = "1")]
    pub seed: Option<i32>,

    #[prost(bool, optional, tag = "2")]
    pub unlock_all: Option<bool>,

    #[prost(message, optional, tag = "3")]
    pub tcp_fragment: Option<TcpFragment>,

    #[prost(message, optional, tag = "4")]
    pub nonce: Option<NoncePattern>,

    #[prost(message, optional, tag = "5")]
    pub padding: Option<PaddingPattern>,

    #[prost(message, optional, tag = "6")]
    pub low_entropy: Option<LowEntropyPattern>,
}

#[derive(Clone, PartialEq, Message)]
pub struct TcpFragment {
    #[prost(bool, optional, tag = "1")]
    pub enable: Option<bool>,

    #[prost(int32, optional, tag = "2")]
    pub max_sleep_ms: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct NoncePattern {
    #[prost(int32, optional, tag = "1")]
    pub r#type: Option<i32>,

    #[prost(bool, optional, tag = "2")]
    pub apply_to_all_udp_packet: Option<bool>,

    #[prost(int32, optional, tag = "3")]
    pub min_len: Option<i32>,

    #[prost(int32, optional, tag = "4")]
    pub max_len: Option<i32>,

    #[prost(string, repeated, tag = "5")]
    pub custom_hex_strings: Vec<String>,
}

#[derive(Clone, PartialEq, Message)]
pub struct PaddingPattern {
    #[prost(int32, optional, tag = "1")]
    pub max_middle_padding_len: Option<i32>,

    #[prost(int32, optional, tag = "2")]
    pub max_end_padding_len: Option<i32>,
}

#[derive(Clone, PartialEq, Message)]
pub struct LowEntropyPattern {
    #[prost(int32, optional, tag = "1")]
    pub mode: Option<i32>,

    #[prost(int32, optional, tag = "2")]
    pub mask_rotation: Option<i32>,
}

impl TrafficPattern {
    /// Decodes and validates a TrafficPattern from a Base64 string.
    /// If `s` is empty or all whitespace, returns `Ok(None)`.
    /// If `s` is invalid Base64 or corrupted Protobuf, returns an `io::Error`.
    pub fn from_base64(s: &str) -> io::Result<Option<Self>> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Ok(None);
        }

        let bytes = BASE64_STANDARD.decode(trimmed).map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("Failed to base64 decode traffic_pattern: {}", e),
            )
        })?;

        let mut pattern = Self::default();
        let result = (|| -> Result<(), prost::DecodeError> {
            let mut input = bytes.as_slice();
            while !input.is_empty() {
                let (tag, wire_type) = decode_key(&mut input)?;
                let expected = match tag {
                    1 | 2 => Some(WireType::Varint),
                    3..=6 => Some(WireType::LengthDelimited),
                    _ => None,
                };
                // Go protobuf treats a known tag with a different wire type as unknown.
                // XBoard can supply such fields; never reinterpret them as a traffic mode.
                if expected.is_none() || expected != Some(wire_type) {
                    skip_field(wire_type, tag, &mut input, DecodeContext::default())?;
                    tracing::warn!(tag, ?wire_type, "Ignoring unknown Mieru TrafficPattern field, matching upstream protobuf behavior");
                } else {
                    pattern.merge_field(tag, wire_type, &mut input, DecodeContext::default())?;
                }
            }
            Ok(())
        })();
        result.map_err(|e| {
            Error::new(
                ErrorKind::InvalidData,
                format!("Failed to protobuf decode traffic_pattern: {}", e),
            )
        })?;

        pattern.validate()?;
        Ok(Some(pattern))
    }

    /// Validates fields against official Mieru rules.
    pub fn validate(&self) -> io::Result<()> {
        if let Some(ref frag) = self.tcp_fragment {
            if let Some(ms) = frag.max_sleep_ms {
                if ms < 0 || ms > 100 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("tcpFragment.maxSleepMs {} exceeds limit [0, 100]", ms),
                    ));
                }
            }
        }

        if let Some(ref nonce) = self.nonce {
            if let Some(t) = nonce.r#type {
                if t < 0 || t > 3 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("nonce.type {} is invalid", t),
                    ));
                }
            }
            if let Some(max_l) = nonce.max_len {
                if max_l < 0 || max_l > 12 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("nonce.maxLen {} exceeds limit [0, 12]", max_l),
                    ));
                }
            }
            if let Some(min_l) = nonce.min_len {
                let max_l = nonce.max_len.unwrap_or(12);
                if min_l < 0 || min_l > max_l {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("nonce.minLen {} is invalid (maxLen is {})", min_l, max_l),
                    ));
                }
            }
            for hex_str in &nonce.custom_hex_strings {
                if hex_str.len() > 24 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "custom hex string {} exceeds 24 characters (12 bytes)",
                            hex_str
                        ),
                    ));
                }
                if hex::decode(hex_str).is_err() {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "custom hex string {} contains invalid hex characters",
                            hex_str
                        ),
                    ));
                }
            }
        }

        if let Some(ref padding) = self.padding {
            if let Some(m) = padding.max_middle_padding_len {
                if m < 0 || m > 255 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("padding.maxMiddlePaddingLen {} exceeds limit [0, 255]", m),
                    ));
                }
            }
            if let Some(e) = padding.max_end_padding_len {
                if e < 0 || e > 255 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("padding.maxEndPaddingLen {} exceeds limit [0, 255]", e),
                    ));
                }
            }
        }

        if let Some(ref le) = self.low_entropy {
            if let Some(mode) = le.mode {
                if mode < 0 || mode > 4 {
                    return Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("lowEntropy.mode {} is invalid", mode),
                    ));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn traffic_pattern_fields_and_unknown_wire_types() {
        // A known field with the wrong wire type is skipped, as in Go protobuf.
        let unknown = [0x0a, 0x02, 0x08, 0x01];
        assert_eq!(
            TrafficPattern::from_base64(&BASE64_STANDARD.encode(unknown)).unwrap(),
            Some(TrafficPattern::default())
        );
        for enable in [false, true] {
            let expected = TrafficPattern {
                tcp_fragment: Some(TcpFragment {
                    enable: Some(enable),
                    max_sleep_ms: Some(5),
                }),
                ..Default::default()
            };
            let mut bytes = unknown.to_vec();
            bytes.extend(expected.encode_to_vec());
            assert_eq!(
                TrafficPattern::from_base64(&BASE64_STANDARD.encode(bytes)).unwrap(),
                Some(expected)
            );
        }
    }

    #[test]
    fn rejects_malformed_patterns_without_fallback() {
        assert!(TrafficPattern::from_base64("not-base64").is_err());
        for bytes in [
            vec![0x0a, 0x02, 0x08],
            vec![0x00],
            vec![0x0e],
            vec![0x1a, 0x02, 0x08],
            TrafficPattern {
                tcp_fragment: Some(TcpFragment {
                    enable: None,
                    max_sleep_ms: Some(128),
                }),
                ..Default::default()
            }
            .encode_to_vec(),
        ] {
            let input = BASE64_STANDARD.encode(bytes);
            assert!(TrafficPattern::from_base64(&input).is_err(), "{input}");
        }
        assert_eq!(TrafficPattern::from_base64("  ").unwrap(), None);
    }
}
