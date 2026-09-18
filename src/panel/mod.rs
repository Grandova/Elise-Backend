pub mod ppanel;
pub mod sspanel;
pub mod types;
pub mod v2board;
pub mod xiaov2board;
pub mod xboard;

pub use ppanel::PPanelClient;
pub use sspanel::SSPanelClient;
pub use types::{NodeInfo, NodeStatusReport, OnlineDeviceItem, TrafficItem, User};
pub use v2board::V2BoardClient;
pub use xiaov2board::XiaoV2BoardClient;
pub use xboard::XboardClient;

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
        "sspanel" | "sspanel-uim" => {
            Arc::new(SSPanelClient::new(url.to_string(), key.to_string()))
        }
        _ => Arc::new(XboardClient::new(url.to_string(), key.to_string())),
    }
}
