use std::collections::HashMap;
use std::net::IpAddr;

use anyhow::{bail, Result};
use async_trait::async_trait;
use pnet::datalink;

use super::Interface;
use crate::{IpAddrWithPrefix, IpType};

pub struct LXD {
    name: String,
}

impl LXD {
    pub fn create<N: AsRef<str>>(name: N) -> Result<LXD> {
        Ok(LXD {
            name: name.as_ref().to_owned(),
        })
    }
}

#[async_trait]
impl Interface for LXD {
    async fn get_ip(&self, family: IpType) -> Result<HashMap<String, Vec<IpAddr>>> {
        bail!("can't find except interface")
    }
}
