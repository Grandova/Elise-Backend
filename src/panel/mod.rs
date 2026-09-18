pub mod ppanel;
pub mod sspanel;
pub mod types;
pub mod v2board;
pub mod xboard;
pub mod xiaov2board;

pub use ppanel::PPanelClient;
pub use sspanel::SSPanelClient;
pub use types::{NodeInfo, NodeStatusReport, OnlineDeviceItem, TrafficItem, User};
pub use v2board::V2BoardClient;
pub use xboard::XboardClient;
pub use xiaov2board::XiaoV2BoardClient;

use async_trait::async_trait;
use std::sync::Arc;

#[async_trait]
pub trait PanelClient: Send + Sync {
    async fn get_node_info(
        &self,
        node_id: u32,
    ) -> Result<NodeInfo, Box<dyn std::error::Error + Send + Sync>>;
    async fn get_users(
        &self,
        node_id: u32,
    ) -> Result<Vec<User>, Box<dyn std::error::Error + Send + Sync>>;
    async fn report_traffic(
        &self,
        node_id: u32,
        traffic: Vec<TrafficItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn report_online_devices(
        &self,
        node_id: u32,
        devices: Vec<OnlineDeviceItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>;
    async fn get_user_alivelist(
        &self,
        _node_id: u32,
    ) -> Result<std::collections::HashMap<u32, u32>, Box<dyn std::error::Error + Send + Sync>> {
        Ok(std::collections::HashMap::new())
    }
    async fn report_node_status(
        &self,
        _node_id: u32,
        _status: &NodeStatusReport,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        Ok(())
    }
}

#[async_trait]
impl PanelClient for XboardClient {
    async fn get_node_info(
        &self,
        node_id: u32,
    ) -> Result<NodeInfo, Box<dyn std::error::Error + Send + Sync>> {
        self.get_node_info(node_id).await
    }
    async fn get_users(
        &self,
        node_id: u32,
    ) -> Result<Vec<User>, Box<dyn std::error::Error + Send + Sync>> {
        self.get_users(node_id).await
    }
    async fn report_traffic(
        &self,
        node_id: u32,
        traffic: Vec<TrafficItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.report_traffic(node_id, traffic).await
    }
    async fn report_online_devices(
        &self,
        node_id: u32,
        devices: Vec<OnlineDeviceItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.report_online_devices(node_id, devices).await
    }
    async fn get_user_alivelist(
        &self,
        node_id: u32,
    ) -> Result<std::collections::HashMap<u32, u32>, Box<dyn std::error::Error + Send + Sync>> {
        self.get_user_alivelist(node_id).await
    }
    async fn report_node_status(
        &self,
        node_id: u32,
        status: &NodeStatusReport,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.report_node_status(node_id, status).await
    }
}

#[async_trait]
impl PanelClient for V2BoardClient {
    async fn get_node_info(
        &self,
        node_id: u32,
    ) -> Result<NodeInfo, Box<dyn std::error::Error + Send + Sync>> {
        self.get_node_info(node_id).await
    }
    async fn get_users(
        &self,
        node_id: u32,
    ) -> Result<Vec<User>, Box<dyn std::error::Error + Send + Sync>> {
        self.get_users(node_id).await
    }
    async fn report_traffic(
        &self,
        node_id: u32,
        traffic: Vec<TrafficItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.report_traffic(node_id, traffic).await
    }
    async fn report_online_devices(
        &self,
        node_id: u32,
        devices: Vec<OnlineDeviceItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.report_online_devices(node_id, devices).await
    }
    async fn get_user_alivelist(
        &self,
        node_id: u32,
    ) -> Result<std::collections::HashMap<u32, u32>, Box<dyn std::error::Error + Send + Sync>> {
        self.get_user_alivelist(node_id).await
    }
}

#[async_trait]
impl PanelClient for PPanelClient {
    async fn get_node_info(
        &self,
        node_id: u32,
    ) -> Result<NodeInfo, Box<dyn std::error::Error + Send + Sync>> {
        self.get_node_info(node_id).await
    }
    async fn get_users(
        &self,
        node_id: u32,
    ) -> Result<Vec<User>, Box<dyn std::error::Error + Send + Sync>> {
        self.get_users(node_id).await
    }
    async fn report_traffic(
        &self,
        node_id: u32,
        traffic: Vec<TrafficItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.report_traffic(node_id, traffic).await
    }
    async fn report_online_devices(
        &self,
        node_id: u32,
        devices: Vec<OnlineDeviceItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.report_online_devices(node_id, devices).await
    }
    async fn get_user_alivelist(
        &self,
        node_id: u32,
    ) -> Result<std::collections::HashMap<u32, u32>, Box<dyn std::error::Error + Send + Sync>> {
        self.get_user_alivelist(node_id).await
    }
}

#[async_trait]
impl PanelClient for SSPanelClient {
    async fn get_node_info(
        &self,
        node_id: u32,
    ) -> Result<NodeInfo, Box<dyn std::error::Error + Send + Sync>> {
        self.get_node_info(node_id).await
    }
    async fn get_users(
        &self,
        node_id: u32,
    ) -> Result<Vec<User>, Box<dyn std::error::Error + Send + Sync>> {
        self.get_users(node_id).await
    }
    async fn report_traffic(
        &self,
        node_id: u32,
        traffic: Vec<TrafficItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.report_traffic(node_id, traffic).await
    }
    async fn report_online_devices(
        &self,
        node_id: u32,
        devices: Vec<OnlineDeviceItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.report_online_devices(node_id, devices).await
    }
}

#[async_trait]
impl PanelClient for XiaoV2BoardClient {
    async fn get_node_info(
        &self,
        node_id: u32,
    ) -> Result<NodeInfo, Box<dyn std::error::Error + Send + Sync>> {
        self.get_node_info(node_id).await
    }
    async fn get_users(
        &self,
        node_id: u32,
    ) -> Result<Vec<User>, Box<dyn std::error::Error + Send + Sync>> {
        self.get_users(node_id).await
    }
    async fn report_traffic(
        &self,
        node_id: u32,
        traffic: Vec<TrafficItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.report_traffic(node_id, traffic).await
    }
    async fn report_online_devices(
        &self,
        node_id: u32,
        devices: Vec<OnlineDeviceItem>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.report_online_devices(node_id, devices).await
    }
    async fn get_user_alivelist(
        &self,
        node_id: u32,
    ) -> Result<std::collections::HashMap<u32, u32>, Box<dyn std::error::Error + Send + Sync>> {
        self.get_user_alivelist(node_id).await
    }
}

pub fn create_panel_client(panel_type: &str, url: &str, key: &str) -> Arc<dyn PanelClient> {
    match panel_type.to_lowercase().as_str() {
        "v2board" => Arc::new(V2BoardClient::new(url.to_string(), key.to_string())),
        "xiaov2board" | "xiaov2b" => {
            Arc::new(XiaoV2BoardClient::new(url.to_string(), key.to_string()))
        }
        "ppanel" => Arc::new(PPanelClient::new(url.to_string(), key.to_string())),
        "sspanel" | "sspanel-uim" => Arc::new(SSPanelClient::new(url.to_string(), key.to_string())),
        _ => Arc::new(XboardClient::new(url.to_string(), key.to_string())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn panel_reality_keys_reach_shared_transport_without_manual_config() {
        for panel in ["xboard", "v2board", "xiaov2board", "ppanel"] {
            let pair = crate::security::generate_reality_keypair();
            let expected = pair.public_key.clone();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = create_panel_client(
                panel,
                &format!("http://{}", listener.local_addr().unwrap()),
                "fixture",
            );
            let data = if panel == "ppanel" {
                serde_json::json!({"protocols":[{
                    "enable":true,"type":"vless","port":12345,"security":"reality","transport":"tcp",
                    "sni":"www.example.com","reality_server_addr":"www.example.com","reality_server_port":443,
                    "reality_private_key":pair.private_key,"reality_public_key":pair.public_key,"reality_short_id":"01"
                }]})
            } else {
                serde_json::json!({
                    "server_type":"vless","type":"vless","server_port":12345,"tls":2,"network":"tcp",
                    "tls_settings":{"server_name":"www.example.com","server_port":443,
                    "private_key":pair.private_key,"public_key":pair.public_key,"short_id":"01"}
                })
            };
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(socket.read_u8().await.unwrap());
                }
                let body = serde_json::json!({"data":data}).to_string();
                socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            });
            let mut info = client.get_node_info(1).await.unwrap();
            let dir =
                std::env::temp_dir().join(format!("elise-panel-keys-{}", uuid::Uuid::new_v4()));
            let cfg = crate::config::NodeConfig {
                node_id: 1,
                ..Default::default()
            };
            cfg.prepare_node_info(&dir, &mut info).unwrap();
            assert!(!dir.join("node_1.reality.key").exists(), "{panel}");
            let stream = crate::transport::types::StreamSettings::from_node_info(&info).unwrap();
            assert_eq!(
                stream.client_reality_profile.unwrap().public_key.as_deref(),
                Some(expected.as_str()),
                "{panel}"
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn all_panel_plan_limits_use_mbps_and_reject_invalid_values() {
        for panel in ["xboard", "v2board", "xiaov2board", "ppanel", "sspanel"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = create_panel_client(
                panel,
                &format!("http://{}", listener.local_addr().unwrap()),
                "fixture",
            );
            let server = tokio::spawn(async move {
                for speed in [
                    serde_json::json!(100),
                    serde_json::json!(-1),
                    serde_json::Value::Null,
                    serde_json::json!(0),
                ] {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        request.push(socket.read_u8().await.unwrap());
                    }
                    let user = serde_json::json!({"id":42,"uuid":"fixture","speed_limit":speed,"node_speedlimit":speed});
                    let body =
                        serde_json::json!({"users":[user.clone()],"data":[user]}).to_string();
                    socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
                }
            });
            assert_eq!(
                client.get_users(1).await.unwrap()[0].speed_limit,
                12_500_000,
                "{panel}"
            );
            assert!(client.get_users(1).await.is_err(), "{panel}");
            assert_eq!(
                client.get_users(1).await.unwrap()[0].speed_limit,
                0,
                "{panel}"
            );
            assert_eq!(
                client.get_users(1).await.unwrap()[0].speed_limit,
                0,
                "{panel}"
            );
            server.await.unwrap();
        }
        assert_eq!(
            types::speed_limit_bps(Some(&serde_json::json!(0.5))).unwrap(),
            62_500
        );
        assert_eq!(types::speed_limit_bps(None).unwrap(), 0);
        for invalid in [
            serde_json::json!("100"),
            serde_json::json!(-1),
            serde_json::json!(u64::MAX),
        ] {
            assert!(types::speed_limit_bps(Some(&invalid)).is_err());
        }
    }

    #[tokio::test]
    async fn panel_user_caches_are_atomic_and_isolated() {
        for panel in ["xboard", "v2board", "xiaov2board", "ppanel"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = create_panel_client(
                panel,
                &format!("http://{}", listener.local_addr().unwrap()),
                "fixture",
            );
            let server = tokio::spawn(async move {
                let mut hits = std::collections::HashMap::new();
                for _ in 0..12 {
                    let (mut socket, _) = listener.accept().await.unwrap();
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        request.push(socket.read_u8().await.unwrap());
                    }
                    let request = String::from_utf8(request).unwrap().to_lowercase();
                    let node = if request.contains("node_id=2") || request.contains("server_id=2") {
                        2
                    } else {
                        1
                    };
                    let hit = hits.entry(node).or_insert(0);
                    *hit += 1;
                    let has_etag = request.contains("if-none-match: \"same\"");
                    assert_eq!(
                        has_etag,
                        *hit > 1 && *hit < 10,
                        "{panel} node {node} hit {hit}"
                    );
                    let (status, etag, body) = match *hit {
                        1 => ("200 OK", "ETag: \"same\"\r\n", format!(r#"{{"users":[{{"id":{node},"uuid":"fixture","speed_limit":1}}],"data":[{{"id":{node},"uuid":"fixture","speed_limit":1}}]}}"#)),
                        3 => ("200 OK", "ETag: \"bad\"\r\n", "{".to_owned()),
                        5 => ("200 OK", "ETag: \"bad\"\r\n", r#"{"users":[{"id":1,"speed_limit":-1}],"data":[{"id":1,"speed_limit":-1}]}"#.to_owned()),
                        7 => ("200 OK", "ETag: \"bad\"\r\n", "{}".to_owned()),
                        9 => ("200 OK", "", r#"{"users":[],"data":[]}"#.to_owned()),
                        _ => ("304 Not Modified", "", String::new()),
                    };
                    socket.write_all(format!("HTTP/1.1 {status}\r\n{etag}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
                }
            });
            for _ in 0..2 {
                let (a, b) = tokio::join!(client.get_users(1), client.get_users(2));
                assert_eq!(a.unwrap()[0].id, 1, "{panel}");
                assert_eq!(b.unwrap()[0].id, 2, "{panel}");
            }
            for _ in 0..3 {
                assert!(client.get_users(1).await.is_err(), "{panel}");
                let users = client.get_users(1).await.unwrap();
                assert_eq!(users[0].id, 1, "{panel}");
                assert_eq!(users[0].speed_limit, 125_000, "{panel}");
            }
            assert!(client.get_users(1).await.unwrap().is_empty(), "{panel}");
            assert!(client.get_users(1).await.is_err(), "{panel}");
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn sspanel_rejects_failed_or_missing_user_lists() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = create_panel_client(
            "sspanel",
            &format!("http://{}", listener.local_addr().unwrap()),
            "fixture",
        );
        let server = tokio::spawn(async move {
            for (status, body) in [
                ("500 Internal Server Error", r#"{"data":[]}"#),
                ("200 OK", "{}"),
                ("200 OK", r#"{"data":[]}"#),
            ] {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(socket.read_u8().await.unwrap());
                }
                socket.write_all(format!("HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).as_bytes()).await.unwrap();
            }
        });
        assert!(client.get_users(1).await.is_err());
        assert!(client.get_users(1).await.is_err());
        assert!(client.get_users(1).await.unwrap().is_empty());
        server.await.unwrap();
    }
}
