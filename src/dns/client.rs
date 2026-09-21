use super::wire::{build_query, parse_response};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream, UdpSocket};
use tokio_rustls::rustls::pki_types::ServerName;
use tokio_rustls::TlsConnector;

const DNS_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsEndpoint {
    Udp { host: String, port: u16 },
    Tcp { host: String, port: u16 },
    Dot { host: String, port: u16 },
    Doh { url: String },
}

pub fn parse_dns_endpoint(raw: &str) -> io::Result<DnsEndpoint> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "DNS server address cannot be empty",
        ));
    }

    if raw.starts_with("https://") {
        return Ok(DnsEndpoint::Doh {
            url: raw.to_string(),
        });
    }

    if let Some(rest) = raw
        .strip_prefix("tcp-tls://")
        .or_else(|| raw.strip_prefix("tls://"))
        .or_else(|| raw.strip_prefix("dot://"))
    {
        let (host, port) = parse_host_port(rest, 853)?;
        return Ok(DnsEndpoint::Dot { host, port });
    }

    if let Some(rest) = raw.strip_prefix("tcp://") {
        let (host, port) = parse_host_port(rest, 53)?;
        return Ok(DnsEndpoint::Tcp { host, port });
    }

    let udp_str = raw.strip_prefix("udp://").unwrap_or(raw);
    let (host, port) = parse_host_port(udp_str, 53)?;
    Ok(DnsEndpoint::Udp { host, port })
}

fn parse_host_port(input: &str, default_port: u16) -> io::Result<(String, u16)> {
    let input = input.trim();
    if input.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Host cannot be empty",
        ));
    }

    if input.starts_with('[') {
        if let Some(end_bracket) = input.find(']') {
            let host = input[1..end_bracket].to_string();
            let rest = &input[end_bracket + 1..];
            let port = if let Some(colon) = rest.strip_prefix(':') {
                colon.parse::<u16>().map_err(|e| {
                    io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid port: {e}"))
                })?
            } else {
                default_port
            };
            return Ok((host, port));
        }
    }

    let colon_count = input.chars().filter(|c| *c == ':').count();
    if colon_count == 1 {
        let (h, p) = input.split_once(':').unwrap();
        let port = p.parse::<u16>().map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidInput, format!("Invalid port: {e}"))
        })?;
        return Ok((h.to_string(), port));
    } else if colon_count > 1 {
        return Ok((input.to_string(), default_port));
    }

    Ok((input.to_string(), default_port))
}

#[derive(Clone)]
pub struct DnsClient {
    http_client: reqwest::Client,
    tls_connector: TlsConnector,
}

impl Default for DnsClient {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsClient {
    pub fn new() -> Self {
        let http_client = reqwest::Client::builder()
            .timeout(DNS_TIMEOUT)
            .pool_idle_timeout(Duration::from_secs(15))
            .pool_max_idle_per_host(10)
            .tcp_keepalive(Duration::from_secs(30))
            .build()
            .unwrap_or_default();

        let client_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
        .with_no_client_auth();

        let tls_connector = TlsConnector::from(Arc::new(client_config));

        Self {
            http_client,
            tls_connector,
        }
    }

    pub async fn query(
        &self,
        endpoint: &DnsEndpoint,
        domain: &str,
        qtype: u16,
    ) -> io::Result<Vec<IpAddr>> {
        let id = rand::random::<u16>();
        let query_bytes = build_query(domain, qtype, id)?;

        match endpoint {
            DnsEndpoint::Udp { host, port } => {
                tokio::time::timeout(DNS_TIMEOUT, self.query_udp(host, *port, &query_bytes, id))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "UDP DNS query timed out")
                    })?
            }
            DnsEndpoint::Tcp { host, port } => {
                tokio::time::timeout(DNS_TIMEOUT, self.query_tcp(host, *port, &query_bytes, id))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "TCP DNS query timed out")
                    })?
            }
            DnsEndpoint::Dot { host, port } => {
                tokio::time::timeout(DNS_TIMEOUT, self.query_dot(host, *port, &query_bytes, id))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "DoT DNS query timed out")
                    })?
            }
            DnsEndpoint::Doh { url } => {
                tokio::time::timeout(DNS_TIMEOUT, self.query_doh(url, &query_bytes))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "DoH DNS query timed out")
                    })?
            }
        }
    }

    async fn resolve_server_addr(host: &str, port: u16) -> io::Result<SocketAddr> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(ip, port));
        }
        let addr_str = format!("{}:{}", host, port);
        let mut addrs = lookup_host(&addr_str).await?;
        addrs
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "DNS server host lookup failed"))
    }

    async fn query_udp(
        &self,
        host: &str,
        port: u16,
        query: &[u8],
        expected_id: u16,
    ) -> io::Result<Vec<IpAddr>> {
        let target_addr = Self::resolve_server_addr(host, port).await?;
        let bind_addr: SocketAddr = if target_addr.is_ipv6() {
            "[::]:0".parse().unwrap()
        } else {
            "0.0.0.0:0".parse().unwrap()
        };

        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(target_addr).await?;
        socket.send(query).await?;

        let mut buf = [0u8; 1024];
        let n = socket.recv(&mut buf).await?;
        let resp = &buf[..n];

        if resp.len() >= 2 {
            let resp_id = u16::from_be_bytes([resp[0], resp[1]]);
            if resp_id != expected_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS transaction ID mismatch",
                ));
            }
        }

        parse_response(resp)
    }

    async fn query_tcp(
        &self,
        host: &str,
        port: u16,
        query: &[u8],
        expected_id: u16,
    ) -> io::Result<Vec<IpAddr>> {
        let target_addr = Self::resolve_server_addr(host, port).await?;
        let mut stream = TcpStream::connect(target_addr).await?;
        stream.set_nodelay(true)?;

        let len_prefix = (query.len() as u16).to_be_bytes();
        stream.write_all(&len_prefix).await?;
        stream.write_all(query).await?;
        stream.flush().await?;

        let mut resp_len_buf = [0u8; 2];
        stream.read_exact(&mut resp_len_buf).await?;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

        let mut resp = vec![0u8; resp_len];
        stream.read_exact(&mut resp).await?;

        if resp.len() >= 2 {
            let resp_id = u16::from_be_bytes([resp[0], resp[1]]);
            if resp_id != expected_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS transaction ID mismatch",
                ));
            }
        }

        parse_response(&resp)
    }

    async fn query_dot(
        &self,
        host: &str,
        port: u16,
        query: &[u8],
        expected_id: u16,
    ) -> io::Result<Vec<IpAddr>> {
        let target_addr = Self::resolve_server_addr(host, port).await?;
        let tcp_stream = TcpStream::connect(target_addr).await?;
        tcp_stream.set_nodelay(true)?;

        let server_name = ServerName::try_from(host.to_string())
            .unwrap_or_else(|_| ServerName::try_from("dns.server").unwrap());

        let mut tls_stream = self
            .tls_connector
            .connect(server_name, tcp_stream)
            .await
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::ConnectionRefused,
                    format!("DoT TLS error: {e}"),
                )
            })?;

        let len_prefix = (query.len() as u16).to_be_bytes();
        tls_stream.write_all(&len_prefix).await?;
        tls_stream.write_all(query).await?;
        tls_stream.flush().await?;

        let mut resp_len_buf = [0u8; 2];
        tls_stream.read_exact(&mut resp_len_buf).await?;
        let resp_len = u16::from_be_bytes(resp_len_buf) as usize;

        let mut resp = vec![0u8; resp_len];
        tls_stream.read_exact(&mut resp).await?;

        if resp.len() >= 2 {
            let resp_id = u16::from_be_bytes([resp[0], resp[1]]);
            if resp_id != expected_id {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "DNS transaction ID mismatch",
                ));
            }
        }

        parse_response(&resp)
    }

    async fn query_doh(&self, url: &str, query: &[u8]) -> io::Result<Vec<IpAddr>> {
        let mut last_err = None;
        for attempt in 0..2 {
            let send_res = self
                .http_client
                .post(url)
                .header("Content-Type", "application/dns-message")
                .header("Accept", "application/dns-message")
                .body(query.to_vec())
                .send()
                .await;

            match send_res {
                Ok(resp) => {
                    if !resp.status().is_success() {
                        return Err(io::Error::new(
                            io::ErrorKind::Other,
                            format!("DoH server returned HTTP status {}", resp.status()),
                        ));
                    }

                    let bytes = resp.bytes().await.map_err(|e| {
                        io::Error::new(io::ErrorKind::Other, format!("DoH body error: {e}"))
                    })?;

                    return parse_response(&bytes);
                }
                Err(e) => {
                    if attempt == 0 {
                        tracing::debug!(
                            "DoH query to {} failed on first attempt ({}), retrying with fresh connection...",
                            url, e
                        );
                    }
                    last_err = Some(e);
                }
            }
        }

        Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "DoH HTTP request error: {}",
                last_err
                    .map(|e| e.to_string())
                    .unwrap_or_else(|| "unknown".into())
            ),
        ))
    }
}

#[derive(Debug)]
struct InsecureCertVerifier;

impl rustls::client::danger::ServerCertVerifier for InsecureCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_dns_endpoint() {
        assert_eq!(
            parse_dns_endpoint("8.8.8.8").unwrap(),
            DnsEndpoint::Udp {
                host: "8.8.8.8".to_string(),
                port: 53
            }
        );
        assert_eq!(
            parse_dns_endpoint("8.8.8.8:12345").unwrap(),
            DnsEndpoint::Udp {
                host: "8.8.8.8".to_string(),
                port: 12345
            }
        );
        assert_eq!(
            parse_dns_endpoint("udp://dns.google:53").unwrap(),
            DnsEndpoint::Udp {
                host: "dns.google".to_string(),
                port: 53
            }
        );
        assert_eq!(
            parse_dns_endpoint("tcp://1.1.1.1:53").unwrap(),
            DnsEndpoint::Tcp {
                host: "1.1.1.1".to_string(),
                port: 53
            }
        );
        assert_eq!(
            parse_dns_endpoint("tcp-tls://dns.google:853").unwrap(),
            DnsEndpoint::Dot {
                host: "dns.google".to_string(),
                port: 853
            }
        );
        assert_eq!(
            parse_dns_endpoint("https://dns.google/dns-query").unwrap(),
            DnsEndpoint::Doh {
                url: "https://dns.google/dns-query".to_string()
            }
        );
    }
}
