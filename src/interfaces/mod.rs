use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::Result;
use async_trait::async_trait;
pub use peer::Peer;
pub use stock::Stock;

use crate::IpType;

#[cfg(target_os = "linux")]
mod lxd;
mod peer;
mod stock;

#[async_trait(?Send)]
pub trait Interface {
    async fn get_ip(&self, family: IpType) -> Result<HashMap<String, Vec<IpAddr>>>; // prefix -> [ip]
}
