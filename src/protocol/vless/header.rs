use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

#[inline]
pub fn process_uuid(mut id: [u8; 16]) -> [u8; 16] {
    id[6] = 0;
    id[7] = 0;
    id
}

#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct VlessAddons {
    pub flow: String,
    pub seed: Vec<u8>,
}

impl VlessAddons {
    pub fn parse(mut buf: &[u8]) -> Self {
        let mut addons = VlessAddons::default();
        while !buf.is_empty() {
            let (tag_wire, rest) = match read_uvarint(buf) {
                Some(res) => res,
                None => break,
            };
            let wire_type = tag_wire & 0x07;
            let field_num = tag_wire >> 3;
            buf = rest;

            match wire_type {
                0 => match read_uvarint(buf) {
                    Some((_, rest)) => buf = rest,
                    None => break,
                },
                1 => {
                    if buf.len() < 8 {
                        break;
                    }
                    buf = &buf[8..];
                }
                2 => {
                    let (len, rest) = match read_uvarint(buf) {
                        Some(res) => res,
                        None => break,
                    };
                    let len = len as usize;
                    if rest.len() < len {
                        break;
                    }
                    let data = &rest[..len];
                    buf = &rest[len..];

                    if field_num == 1 {
                        addons.flow = String::from_utf8_lossy(data).to_string();
                    } else if field_num == 2 {
                        addons.seed = data.to_vec();
                    }
                }
                5 => {
                    if buf.len() < 4 {
                        break;
                    }
                    buf = &buf[4..];
                }
                _ => break,
            }
        }
        addons
    }
}

fn read_uvarint(mut buf: &[u8]) -> Option<(u64, &[u8])> {
    let mut value = 0u64;
    let mut shift = 0;
    while !buf.is_empty() {
        let b = buf[0];
        buf = &buf[1..];
        value |= ((b & 0x7F) as u64) << shift;
        if (b & 0x80) == 0 {
            return Some((value, buf));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

#[derive(Debug, Clone)]
pub struct VlessRequestHeader {
    pub version: u8,
    pub uuid_bytes: [u8; 16],
    pub addons: VlessAddons,
    pub command: u8,
    pub target_port: u16,
    pub target_host: String,
    pub target_ip: Option<IpAddr>,
}

pub async fn parse_vless_request_header<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> io::Result<VlessRequestHeader> {
    let mut ver = [0u8; 1];
    stream.read_exact(&mut ver).await?;
    if ver[0] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported VLESS protocol version: {}", ver[0]),
        ));
    }

    let mut uuid_bytes = [0u8; 16];
    stream.read_exact(&mut uuid_bytes).await?;

    let mut addon_len = [0u8; 1];
    stream.read_exact(&mut addon_len).await?;
    let addons = if addon_len[0] > 0 {
        let mut addon_buf = vec![0u8; addon_len[0] as usize];
        stream.read_exact(&mut addon_buf).await?;
        VlessAddons::parse(&addon_buf)
    } else {
        VlessAddons::default()
    };

    let mut cmd_buf = [0u8; 1];
    stream.read_exact(&mut cmd_buf).await?;
    let command = cmd_buf[0];

    let (target_port, target_host, target_ip) = match command {
        0x01 | 0x02 => {
            let mut port_buf = [0u8; 2];
            stream.read_exact(&mut port_buf).await?;
            let target_port = u16::from_be_bytes(port_buf);

            let mut atyp_buf = [0u8; 1];
            stream.read_exact(&mut atyp_buf).await?;

            let (target_host, target_ip) = match atyp_buf[0] {
                0x01 => {
                    let mut ipv4 = [0u8; 4];
                    stream.read_exact(&mut ipv4).await?;
                    let ip = IpAddr::V4(Ipv4Addr::from(ipv4));
                    (ip.to_string(), Some(ip))
                }
                0x02 => {
                    let mut len_buf = [0u8; 1];
                    stream.read_exact(&mut len_buf).await?;
                    let mut domain_buf = vec![0u8; len_buf[0] as usize];
                    stream.read_exact(&mut domain_buf).await?;
                    let domain = String::from_utf8_lossy(&domain_buf).to_string();
                    (domain, None)
                }
                0x03 => {
                    let mut ipv6 = [0u8; 16];
                    stream.read_exact(&mut ipv6).await?;
                    let ip = IpAddr::V6(Ipv6Addr::from(ipv6));
                    (ip.to_string(), Some(ip))
                }
                unknown => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid VLESS address type: {unknown:#x}"),
                    ))
                }
            };
            (target_port, target_host, target_ip)
        }
        0x03 => (0, "v1.mux.cool".to_string(), None),
        0x04 => (0, "v1.rvs.cool".to_string(), None),
        unknown => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported VLESS command: {unknown:#x}"),
            ));
        }
    };

    Ok(VlessRequestHeader {
        version: ver[0],
        uuid_bytes,
        addons,
        command,
        target_port,
        target_host,
        target_ip,
    })
}

pub async fn write_vless_response_header<W: AsyncWrite + Unpin>(stream: &mut W) -> io::Result<()> {
    stream.write_all(&[0x00, 0x00]).await?;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_process_uuid_masking() {
        let original: [u8; 16] = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
            0x77, 0x88,
        ];
        let processed = process_uuid(original);
        assert_eq!(processed[6], 0);
        assert_eq!(processed[7], 0);
        assert_eq!(processed[0], 0x12);
        assert_eq!(processed[15], 0x88);
    }

    #[test]
    fn test_addons_parse_vision() {
        let mut data = vec![0x0au8, 0x10];
        data.extend_from_slice(b"xtls-rprx-vision");

        let addons = VlessAddons::parse(&data);
        assert_eq!(addons.flow, "xtls-rprx-vision");
        assert!(addons.seed.is_empty());
    }

    #[tokio::test]
    async fn test_parse_vless_request_header_mux() {
        let mut raw = vec![0x00];
        raw.extend_from_slice(&[1u8; 16]);
        raw.push(0x00);
        raw.push(0x03);
        raw.extend_from_slice(&[0x00, 0x0c, 0x35, 0x01]);

        let mut cursor = std::io::Cursor::new(raw);
        let header = parse_vless_request_header(&mut cursor).await.unwrap();

        assert_eq!(header.version, 0);
        assert_eq!(header.command, 0x03);
        assert_eq!(header.target_host, "v1.mux.cool");
        assert_eq!(header.target_port, 0);
        assert_eq!(header.target_ip, None);

        use std::io::Read;
        let mut rest = Vec::new();
        Read::read_to_end(&mut cursor, &mut rest).unwrap();
        assert_eq!(rest, vec![0x00, 0x0c, 0x35, 0x01]);
    }

    #[tokio::test]
    async fn test_parse_vless_request_header_rvs() {
        let mut raw = vec![0x00];
        raw.extend_from_slice(&[2u8; 16]);
        raw.push(0x00);
        raw.push(0x04);
        raw.extend_from_slice(&[0xaa, 0xbb]);

        let mut cursor = std::io::Cursor::new(raw);
        let header = parse_vless_request_header(&mut cursor).await.unwrap();

        assert_eq!(header.version, 0);
        assert_eq!(header.command, 0x04);
        assert_eq!(header.target_host, "v1.rvs.cool");
        assert_eq!(header.target_port, 0);

        use std::io::Read;
        let mut rest = Vec::new();
        Read::read_to_end(&mut cursor, &mut rest).unwrap();
        assert_eq!(rest, vec![0xaa, 0xbb]);
    }

    #[tokio::test]
    async fn test_parse_vless_request_header_tcp_ipv4() {
        let mut raw = vec![0x00];
        raw.extend_from_slice(&[3u8; 16]);
        raw.push(0x00);
        raw.push(0x01);
        raw.extend_from_slice(&443u16.to_be_bytes());
        raw.push(0x01);
        raw.extend_from_slice(&[1, 1, 1, 1]);

        let mut cursor = std::io::Cursor::new(raw);
        let header = parse_vless_request_header(&mut cursor).await.unwrap();

        assert_eq!(header.command, 0x01);
        assert_eq!(header.target_port, 443);
        assert_eq!(header.target_host, "1.1.1.1");
        assert_eq!(
            header.target_ip,
            Some(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))
        );
    }

    #[tokio::test]
    async fn test_parse_vless_request_header_udp_domain() {
        let mut raw = vec![0x00];
        raw.extend_from_slice(&[4u8; 16]);
        raw.push(0x00);
        raw.push(0x02);
        raw.extend_from_slice(&53u16.to_be_bytes());
        raw.push(0x02);
        let domain = b"dns.google";
        raw.push(domain.len() as u8);
        raw.extend_from_slice(domain);

        let mut cursor = std::io::Cursor::new(raw);
        let header = parse_vless_request_header(&mut cursor).await.unwrap();

        assert_eq!(header.command, 0x02);
        assert_eq!(header.target_port, 53);
        assert_eq!(header.target_host, "dns.google");
    }
}
