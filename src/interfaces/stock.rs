use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{bail, Result};
use async_trait::async_trait;
use pnet::datalink;

use super::Interface;
use crate::IpType;

pub struct Stock {
    prefix: String,
    name: String,
}

impl Stock {
    pub fn create<T: AsRef<str>, N: AsRef<str>>(prefix: T, name: N) -> Result<Stock> {
        Ok(Stock {
            prefix: prefix.as_ref().to_owned(),
            name: name.as_ref().to_owned(),
        })
    }
}

#[async_trait(?Send)]
impl Interface for Stock {
    async fn get_ip(&self, family: IpType) -> Result<HashMap<String, Vec<IpAddr>>> {
        if let Some(interface) = datalink::interfaces()
            .into_iter()
            .find(|interface| interface.name == self.name)
        {
            let result = interface
                .ips
                .into_iter()
                .map(|ip| ip.ip())
                // TODO: Switch to `IpAddr::is_global` once stable: https://github.com/rust-lang/rust/issues/27709
                .filter(is_global)
                .filter(|ip| {
                    if family == IpType::V4 && ip.is_ipv4() {
                        return true;
                    }
                    if family == IpType::V6 && ip.is_ipv6() {
                        return true;
                    }
                    false
                })
                .collect::<Vec<IpAddr>>();
            if !result.is_empty() {
                return Ok(HashMap::from([(self.prefix.clone(), result)]));
            }
            bail!("can't find global address for {}", family)
        } else {
            bail!("can't find except interface")
        }
    }
}

#[inline]
fn is_global(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(ip) => !(ip.is_unspecified() || ip.is_private() || ip.is_loopback() || ip.is_link_local()),
        IpAddr::V6(ip) => !(ip.is_loopback() || ip.is_unspecified()),
    }
}
