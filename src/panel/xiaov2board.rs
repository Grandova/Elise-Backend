use crate::panel::types::{NodeInfo, OnlineDeviceItem, TrafficItem, User};
use parking_lot::RwLock;
use reqwest::header::IF_NONE_MATCH;
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

pub struct XiaoV2BoardClient {
    client: Client,
    base_url: String,
    token: String,
    cached_users: RwLock<HashMap<u32, Arc<tokio::sync::Mutex<(Option<String>, Vec<User>)>>>>,
}

impl XiaoV2BoardClient {
    pub fn new(base_url: String, token: String) -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_default();

        Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            token,
            cached_users: RwLock::new(HashMap::new()),
        }
    }

    pub async fn get_node_info(
        &self,
        node_id: u32,
    ) -> Result<NodeInfo, Box<dyn std::error::Error + Send + Sync>> {
        let resp = self
            .request(reqwest::Method::GET, "/api/v2/server/config", node_id)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        if !resp.status().is_success() {
            return Err(format!("XiaoV2Board config API returned status {}", resp.status()).into());
        }

        let val: Value = resp.json().await?;
        if val.get("status").and_then(Value::as_str) == Some("fail") {
            let reason = match val.get("message").and_then(Value::as_str) {
                Some("token is null") => "token is null: configure the panel server token",
                Some("token is error") => "token is error: check the panel server token",
                Some("server is not exist") => {
                    "server is not exist: check node_id in the panel v2node list"
                }
                _ => "panel rejected the node configuration request",
            };
            return Err(format!("XiaoV2Board config API: {reason}").into());
        }
        let data = val.get("data").unwrap_or(&val);
        let protocol = data
            .get("protocol")
            .or_else(|| data.get("server_type"))
            .or_else(|| data.get("type"));
        if protocol.and_then(Value::as_str).is_none_or(str::is_empty)
            || !matches!(
                data.get("server_port").and_then(Value::as_u64),
                Some(1..=65535)
            )
        {
            return Err(
                "Invalid XiaoV2Board config: missing protocol or invalid server_port".into(),
            );
        }
        Ok(self.parse_v2_node_info(node_id, data))
    }

    fn request(
        &self,
        method: reqwest::Method,
        path: &str,
        node_id: u32,
    ) -> reqwest::RequestBuilder {
        self.client
            .request(method, format!("{}{}", self.base_url, path))
            .query(&[
                ("node_type", "v2node"),
                ("node_id", &node_id.to_string()),
                ("token", &self.token),
            ])
    }

    fn parse_v2_node_info(&self, node_id: u32, data: &Value) -> NodeInfo {
        let mut node_type = data
            .get("protocol")
            .or_else(|| data.get("server_type"))
            .or_else(|| data.get("type"))
            .and_then(|v| v.as_str())
            .unwrap_or("vless")
            .to_string();

        let version = data
            .get("version")
            .and_then(|v| v.as_u64())
            .map(|v| v as u32);

        if (node_type == "hysteria" || node_type == "hy") && version == Some(2) {
            node_type = "hysteria2".to_string();
        }

        let tls_val = data.get("tls_settings").or_else(|| data.get("tlsSettings"));

        let server_name = tls_val
            .and_then(|t| {
                t.get("server_name").and_then(|v| v.as_str()).or_else(|| {
                    t.get("server_names")
                        .and_then(|arr| arr.as_array())
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_str())
                })
            })
            .or_else(|| data.get("server_name").and_then(|v| v.as_str()))
            .map(String::from);

        let short_ids = tls_val
            .and_then(|t| {
                t.get("short_ids")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|x| x.as_str().map(String::from))
                            .collect::<Vec<_>>()
                    })
                    .or_else(|| {
                        t.get("short_id")
                            .and_then(|v| v.as_str())
                            .map(|s| vec![s.to_string()])
                    })
            })
            .or_else(|| {
                data.get("short_ids").and_then(|v| v.as_array()).map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(String::from))
                        .collect::<Vec<_>>()
                })
            });

        let public_key = tls_val
            .and_then(|t| t.get("public_key").and_then(|v| v.as_str()))
            .or_else(|| data.get("public_key").and_then(|v| v.as_str()))
            .map(String::from);

        let nw_settings = data
            .get("network_settings")
            .or_else(|| data.get("networkSettings"))
            .cloned();

        let host = nw_settings
            .as_ref()
            .and_then(|nw| {
                nw.get("headers")
                    .and_then(|h| h.get("Host"))
                    .and_then(|v| v.as_str())
                    .or_else(|| nw.get("host").and_then(|v| v.as_str()))
            })
            .or_else(|| data.get("host").and_then(|v| v.as_str()))
            .map(String::from);

        let path = nw_settings
            .as_ref()
            .and_then(|nw| nw.get("path").and_then(|v| v.as_str()))
            .or_else(|| data.get("path").and_then(|v| v.as_str()))
            .map(String::from);

        let mut network = data
            .get("network")
            .or_else(|| data.get("transport"))
            .and_then(|v| v.as_str())
            .map(String::from);

        if network.as_deref() == Some("xhttp") {
            network = Some("splithttp".to_string());
        }

        NodeInfo {
            id: node_id,
            node_type,
            server_port: data
                .get("server_port")
                .and_then(|v| v.as_u64())
                .unwrap_or(443) as u16,
            host,
            path,
            server_name,
            tls: data.get("tls").and_then(|v| v.as_u64()).map(|v| v as u8),
            network,
            cipher: data
                .get("cipher")
                .and_then(|v| v.as_str())
                .map(String::from),
            plugin: data
                .get("plugin")
                .and_then(|v| v.as_str())
                .map(String::from),
            plugin_opts: data.get("plugin_opts").cloned(),
            up_mbps: data
                .get("up_mbps")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            down_mbps: data
                .get("down_mbps")
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            server_key: data
                .get("server_key")
                .and_then(|v| v.as_str())
                .map(String::from),
            short_ids,
            public_key,
            routes: data.get("routes").and_then(|v| v.as_array()).cloned(),
            custom_outbounds: data
                .get("custom_outbounds")
                .and_then(|v| v.as_array())
                .cloned(),
            custom_routes: data
                .get("custom_routes")
                .and_then(|v| v.as_array())
                .cloned(),
            cert_config: data.get("cert_config").cloned(),
            network_settings: nw_settings,
            obfs: data.get("obfs").and_then(|v| v.as_str()).map(String::from),
            obfs_password: data
                .get("obfs_password")
                .or_else(|| data.get("obfs-password"))
                .and_then(|v| v.as_str())
                .map(String::from),
            tls_settings: tls_val.cloned(),
            multiplex: data.get("multiplex").cloned(),
            utls: data.get("utls").cloned(),
            listen_ip: data
                .get("listen_ip")
                .and_then(|v| v.as_str())
                .map(String::from),
            rate: data.get("rate").and_then(|v| v.as_f64()),
            flow: data.get("flow").and_then(|v| v.as_str()).map(String::from),
            encryption: data
                .get("encryption")
                .and_then(|v| v.as_str())
                .map(String::from),
            decryption: data
                .get("decryption")
                .and_then(|v| v.as_str())
                .map(String::from),
            encryption_settings: data
                .get("encryption_settings")
                .or_else(|| data.get("encryptionSettings"))
                .cloned(),
            padding_scheme: data
                .get("padding_scheme")
                .or_else(|| data.get("paddingScheme"))
                .cloned(),
            version,
            congestion_control: data
                .get("congestion_control")
                .or_else(|| data.get("congestion-controller"))
                .and_then(|v| v.as_str())
                .map(String::from),
            alpn: data.get("alpn").cloned(),
            udp_relay_mode: data
                .get("udp_relay_mode")
                .or_else(|| data.get("udp-relay-mode"))
                .and_then(|v| v.as_str())
                .map(String::from),
            auth_timeout: data
                .get("auth_timeout")
                .and_then(|v| v.as_str())
                .map(String::from),
            heartbeat: data
                .get("heartbeat")
                .and_then(|v| v.as_str())
                .map(String::from),
            zero_rtt_handshake: data.get("zero_rtt_handshake").and_then(|v| v.as_bool()),
            ports: data
                .get("ports")
                .or_else(|| data.get("server_ports"))
                .and_then(|v| v.as_str())
                .map(String::from),
            hop_interval: data
                .get("hop_interval")
                .or_else(|| data.get("hopInterval"))
                .and_then(|v| v.as_u64())
                .map(|v| v as u32),
            traffic_pattern: data
                .get("traffic_pattern")
                .or_else(|| data.get("trafficPattern"))
                .and_then(|v| v.as_str())
                .map(String::from),
            transport: data
                .get("transport")
                .or_else(|| data.get("network"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_ascii_uppercase()),
            ..Default::default()
        }
    }

    pub async fn get_users(
        &self,
        node_id: u32,
    ) -> Result<Vec<User>, Box<dyn std::error::Error + Send + Sync>> {
        let cache = self
            .cached_users
            .write()
            .entry(node_id)
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new((None, Vec::new()))))
            .clone();
        let mut cache = cache.lock().await;
        let mut req = self.request(
            reqwest::Method::GET,
            "/api/v1/server/UniProxy/user",
            node_id,
        );
        if let Some(etag) = cache.0.as_ref() {
            req = req.header(IF_NONE_MATCH, etag);
        }

        let resp = req.send().await.map_err(reqwest::Error::without_url)?;

        if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
            if cache.0.is_none() {
                return Err("Panel returned 304 without a cached ETag".into());
            }
            return Ok(cache.1.clone());
        }

        if !resp.status().is_success() {
            return Err(format!(
                "XiaoV2Board API user sync returned status {}",
                resp.status()
            )
            .into());
        }

        let new_etag = resp
            .headers()
            .get("ETag")
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);

        let val: Value = resp.json().await?;
        let user_list = val
            .get("users")
            .or_else(|| val.get("data"))
            .and_then(|v| v.as_array());

        if user_list.is_none() {
            return Err("Panel user response has no users array".into());
        }
        let mut users = Vec::new();
        if let Some(arr) = user_list {
            for item in arr {
                let id = item.get("id").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let uuid = item
                    .get("uuid")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let speed_limit = crate::panel::types::speed_limit_bps(item.get("speed_limit"))?;
                let device_limit = item
                    .get("device_limit")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0) as u32;

                users.push(User {
                    id,
                    uuid,
                    speed_limit,
                    device_limit,
                    password: item
                        .get("password")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    method: item
                        .get("method")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    port: item.get("port").and_then(|v| v.as_u64()).map(|v| v as u16),
                    flow: item.get("flow").and_then(|v| v.as_str()).map(String::from),
                });
            }
        }

        *cache = (new_etag, users.clone());
        Ok(users)
    }

    pub async fn report_traffic(
        &self,
        node_id: u32,
        traffic: Vec<TrafficItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if traffic.is_empty() {
            return Ok(());
        }

        let mut payload: HashMap<String, [u64; 2]> = HashMap::with_capacity(traffic.len());
        for item in traffic {
            payload.insert(item.user_id.to_string(), [item.u, item.d]);
        }

        let resp = self
            .request(
                reqwest::Method::POST,
                "/api/v1/server/UniProxy/push",
                node_id,
            )
            .json(&payload)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;

        if !resp.status().is_success() {
            return Err(format!(
                "XiaoV2Board API traffic report returned status {}",
                resp.status()
            )
            .into());
        }
        Ok(())
    }

    pub async fn report_online_devices(
        &self,
        node_id: u32,
        devices: Vec<OnlineDeviceItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if devices.is_empty() {
            return Ok(());
        }

        let mut payload: HashMap<String, Vec<String>> = HashMap::with_capacity(devices.len());
        for item in devices {
            payload.insert(item.user_id.to_string(), item.ips);
        }

        let resp = self
            .request(
                reqwest::Method::POST,
                "/api/v1/server/UniProxy/alive",
                node_id,
            )
            .json(&payload)
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        if !resp.status().is_success() {
            return Err(format!(
                "XiaoV2Board API online report returned status {}",
                resp.status()
            )
            .into());
        }
        Ok(())
    }

    pub async fn get_user_alivelist(
        &self,
        node_id: u32,
    ) -> Result<HashMap<u32, u32>, Box<dyn std::error::Error + Send + Sync>> {
        let resp = self
            .request(
                reqwest::Method::GET,
                "/api/v1/server/UniProxy/alivelist",
                node_id,
            )
            .send()
            .await
            .map_err(reqwest::Error::without_url)?;
        if !resp.status().is_success() {
            return Err(format!(
                "XiaoV2Board API alive list returned status {}",
                resp.status()
            )
            .into());
        }
        let val: Value = resp.json().await?;

        let mut res = HashMap::new();
        let map_obj = val
            .get("alive")
            .or_else(|| val.get("data"))
            .or(Some(&val))
            .and_then(|v| v.as_object());

        if let Some(map) = map_obj {
            for (k, v) in map {
                if let (Ok(uid), Some(cnt)) = (k.parse::<u32>(), v.as_u64()) {
                    res.insert(uid, cnt as u32);
                }
            }
        }
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // Contract from wyx2685-v2board 7e77de9: V2 ServerController and V1 UniProxyController.
    async fn fixture(
        token: &str,
        replies: Vec<(
            &'static str,
            &'static str,
            &'static str,
            &'static str,
            Value,
        )>,
    ) -> (XiaoV2BoardClient, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = XiaoV2BoardClient::new(
            format!("http://{}", listener.local_addr().unwrap()),
            token.into(),
        );
        let token = token.to_owned();
        let server = tokio::spawn(async move {
            for (method, path, status, body, expected_body) in replies {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut headers = Vec::new();
                while !headers.ends_with(b"\r\n\r\n") {
                    headers.push(socket.read_u8().await.unwrap());
                }
                let headers = String::from_utf8(headers).unwrap();
                let mut line = headers.lines().next().unwrap().split_whitespace();
                assert_eq!(line.next().unwrap(), method);
                let url = reqwest::Url::parse(&format!("http://localhost{}", line.next().unwrap()))
                    .unwrap();
                assert_eq!(url.path(), path);
                let query: HashMap<_, _> = url.query_pairs().into_owned().collect();
                assert_eq!(query.get("node_id").map(String::as_str), Some("242"));
                assert_eq!(query.get("node_type").map(String::as_str), Some("v2node"));
                assert_eq!(query.get("token"), Some(&token));
                if method == "POST" {
                    let len = headers
                        .lines()
                        .find_map(|l| {
                            let (key, value) = l.split_once(':')?;
                            key.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().unwrap())
                        })
                        .unwrap();
                    let mut bytes = vec![0; len];
                    socket.read_exact(&mut bytes).await.unwrap();
                    assert_eq!(
                        serde_json::from_slice::<Value>(&bytes).unwrap(),
                        expected_body
                    );
                }
                socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).as_bytes()).await.unwrap();
            }
            assert!(
                tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                    .await
                    .is_err(),
                "unexpected legacy fallback request"
            );
        });
        (client, server)
    }

    #[tokio::test]
    async fn v2node_contract_covers_sync_traffic_and_online_ips() {
        let (client, server) = fixture("key+with&reserved=#?", vec![
            ("GET", "/api/v2/server/config", "200 OK", r#"{"protocol":"vless","server_port":12345,"tls":2,"network":"tcp","flow":"xtls-rprx-vision","tls_settings":{"server_name":"example.com","private_key":"panel-private-key","short_id":"abcd"},"encryption":"none"}"#, Value::Null),
            ("GET", "/api/v1/server/UniProxy/user", "200 OK", r#"{"users":[{"id":12,"uuid":"test-uuid","speed_limit":8,"device_limit":3}]}"#, Value::Null),
            ("POST", "/api/v1/server/UniProxy/push", "200 OK", r#"{"data":true}"#, serde_json::json!({"12":[104857600u64,524288000u64]})),
            ("POST", "/api/v1/server/UniProxy/alive", "200 OK", r#"{"data":true}"#, serde_json::json!({"12":["192.0.2.1","2001:db8::1"]})),
            ("GET", "/api/v1/server/UniProxy/alivelist", "200 OK", r#"{"alive":{"12":2}}"#, Value::Null),
        ]).await;
        let info = client.get_node_info(242).await.unwrap();
        assert_eq!(info.node_type, "vless");
        assert_eq!(info.server_port, 12345);
        assert_eq!(info.tls, Some(2));
        assert_eq!(info.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(
            info.tls_settings.unwrap()["private_key"],
            "panel-private-key"
        );
        let users = client.get_users(242).await.unwrap();
        assert_eq!(users[0].id, 12);
        assert_eq!(users[0].speed_limit, 1_000_000);
        assert_eq!(users[0].device_limit, 3);
        client
            .report_traffic(
                242,
                vec![TrafficItem {
                    user_id: 12,
                    u: 104857600,
                    d: 524288000,
                }],
            )
            .await
            .unwrap();
        client
            .report_online_devices(
                242,
                vec![OnlineDeviceItem {
                    user_id: 12,
                    ips: vec!["192.0.2.1".into(), "2001:db8::1".into()],
                }],
            )
            .await
            .unwrap();
        assert_eq!(
            client.get_user_alivelist(242).await.unwrap().get(&12),
            Some(&2)
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn config_business_errors_do_not_fall_back_or_create_default_nodes() {
        for (body, expected) in [
            (
                r#"{"status":"fail","message":"token is null"}"#,
                "token is null",
            ),
            (
                r#"{"status":"fail","message":"token is error"}"#,
                "token is error",
            ),
            (
                r#"{"status":"fail","message":"server is not exist"}"#,
                "server is not exist",
            ),
            (
                r#"{"status":"fail","message":"untrusted secret-value"}"#,
                "rejected",
            ),
            (r#"{}"#, "Invalid"),
            (r#"{"protocol":"vless"}"#, "Invalid"),
            (r#"{"protocol":"vless","server_port":65536}"#, "Invalid"),
        ] {
            let (client, server) = fixture(
                "fixture",
                vec![("GET", "/api/v2/server/config", "200 OK", body, Value::Null)],
            )
            .await;
            let error = client.get_node_info(242).await.unwrap_err().to_string();
            assert!(error.contains(expected), "{error}");
            assert!(!error.contains("secret-value"));
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn http_500_and_failed_reports_are_not_success() {
        for status in ["500 Internal Server Error", "403 Forbidden"] {
            let (client, server) = fixture(
                "fixture",
                vec![
                    ("GET", "/api/v2/server/config", status, "{}", Value::Null),
                    (
                        "POST",
                        "/api/v1/server/UniProxy/push",
                        status,
                        "{}",
                        serde_json::json!({"12":[1,2]}),
                    ),
                    (
                        "POST",
                        "/api/v1/server/UniProxy/alive",
                        status,
                        "{}",
                        serde_json::json!({"12":["192.0.2.1"]}),
                    ),
                    (
                        "GET",
                        "/api/v1/server/UniProxy/alivelist",
                        status,
                        "{}",
                        Value::Null,
                    ),
                ],
            )
            .await;
            assert!(client
                .get_node_info(242)
                .await
                .unwrap_err()
                .to_string()
                .contains(status));
            assert!(client
                .report_traffic(
                    242,
                    vec![TrafficItem {
                        user_id: 12,
                        u: 1,
                        d: 2
                    }]
                )
                .await
                .is_err());
            assert!(client
                .report_online_devices(
                    242,
                    vec![OnlineDeviceItem {
                        user_id: 12,
                        ips: vec!["192.0.2.1".into()]
                    }]
                )
                .await
                .is_err());
            assert!(client.get_user_alivelist(242).await.is_err());
            server.await.unwrap();
        }
    }
}
