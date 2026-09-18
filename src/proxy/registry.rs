use crate::protocol::anytls::AnytlsInbound;
use crate::protocol::http::HttpInbound;
use crate::protocol::hysteria1::Hysteria1Inbound;
use crate::protocol::hysteria2::Hysteria2Inbound;
use crate::protocol::mieru::MieruInbound;
use crate::protocol::naive::NaiveInbound;
use crate::protocol::shadowsocks::ShadowsocksInbound;
use crate::protocol::shadowsocksr::ShadowsocksrInbound;
use crate::protocol::socks::SocksInbound;
use crate::protocol::trojan::TrojanInbound;
use crate::protocol::tuic::TuicInbound;
use crate::protocol::vless::VlessInbound;
use crate::protocol::vmess::VmessInbound;
use crate::protocol::Inbound;
use std::sync::Arc;

pub fn create_inbound(protocol_name: &str) -> Arc<dyn Inbound> {
    match protocol_name.to_lowercase().as_str() {
        "vless" => Arc::new(VlessInbound::new()),
        "vmess" | "v2ray" => Arc::new(VmessInbound::new()),
        "trojan" => Arc::new(TrojanInbound::new()),
        "ss" | "shadowsocks" => Arc::new(ShadowsocksInbound::new()),
        "ssr" | "shadowsocksr" => Arc::new(ShadowsocksrInbound::new()),
        "socks" | "socks5" => Arc::new(SocksInbound::new()),
        "hysteria" | "hy1" | "hysteria1" => Arc::new(Hysteria1Inbound::new()),
        "hysteria2" | "hy2" => Arc::new(Hysteria2Inbound::new()),
        "tuic" => Arc::new(TuicInbound::new()),
        "anytls" => Arc::new(AnytlsInbound::new()),
        "naive" | "naiveproxy" => Arc::new(NaiveInbound::new()),
        "http" | "https" => Arc::new(HttpInbound::new()),
        "mieru" => Arc::new(MieruInbound::new()),
        _ => Arc::new(VlessInbound::new()),
    }
}
