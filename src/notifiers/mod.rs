use std::net::IpAddr;

use anyhow::Result;
use async_trait::async_trait;
pub use email::Email;
pub use webhook::Webhook;

mod email;
mod webhook;

#[async_trait(?Send)]
pub trait Notifier {
    async fn send(&self, new_ips: &[IpAddr]) -> Result<()>;
}
