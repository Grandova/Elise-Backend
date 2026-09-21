pub mod config;
pub mod conn;
pub mod dns;
pub mod geo;
pub mod limiter;
pub mod observability;
pub mod panel;
pub mod protocol;
pub mod proxy;
pub mod security;
pub mod stats;
pub mod transport;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const APP_NAME: &str = "Elise Core";
