use std::net::{IpAddr, Ipv4Addr};

use anyhow::{bail, Result};
use async_trait::async_trait;
use pnet::datalink;

use super::Interface;
use crate::IpType;

pub struct Stock {
    name: String,
}

impl Stock {
    pub fn create<N: AsRef<str>>(name: N) -> Result<Stock> {
        Ok(Stock {
            name: name.as_ref().to_owned(),
        })
    }
}

#[async_trait(?Send)]
impl Interface for Stock {
    async fn get_ip(&self, family: IpType) -> Result<Vec<IpAddr>> {
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
                return Ok(result);
            }
            bail!("can't find global address for {}", family)
        } else {
            bail!("can't find except interface")
        }
    }
}

// Copied from `std::net::IpAddr::is_global`
#[inline]
fn is_global(addr: &IpAddr) -> bool {
    !match addr {
        IpAddr::V4(ip) => {
            ip.octets()[0] == 0 // "This network"
            || ip.is_private()
            || (ip.octets()[0] == 100 && (ip.octets()[1] & 0b1100_0000 == 0b0100_0000))
            || ip.is_loopback()
            || ip.is_link_local()
            // addresses reserved for future protocols (`192.0.0.0/24`)
            // .9 and .10 are documented as globally reachable so they're excluded
            || (
                ip.octets()[0] == 192 && ip.octets()[1] == 0 && ip.octets()[2] == 0
                && ip.octets()[3] != 9 && ip.octets()[3] != 10
            )
            || ip.is_documentation()
            || (ip.octets()[0] == 198 && (ip.octets()[1] & 0xfe) == 18)
            || (ip.octets()[0] & 240 == 240 && !ip.is_broadcast())
            || (u32::from_be_bytes(ip.octets()) == u32::from_be_bytes(Ipv4Addr::BROADCAST.octets()))
        },
        IpAddr::V6(ip) => {
            ip.is_unspecified()
            || ip.is_loopback()
            // IPv4-mapped Address (`::ffff:0:0/96`)
            || matches!(ip.segments(), [0, 0, 0, 0, 0, 0xffff, _, _])
            // IPv4-IPv6 Translat. (`64:ff9b:1::/48`)
            || matches!(ip.segments(), [0x64, 0xff9b, 1, _, _, _, _, _])
            // Discard-Only Address Block (`100::/64`)
            || matches!(ip.segments(), [0x100, 0, 0, 0, _, _, _, _])
            // IETF Protocol Assignments (`2001::/23`)
            || (matches!(ip.segments(), [0x2001, b, _, _, _, _, _, _] if b < 0x200)
                && !(
                    // Port Control Protocol Anycast (`2001:1::1`)
                    u128::from_be_bytes(ip.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0001
                    // Traversal Using Relays around NAT Anycast (`2001:1::2`)
                    || u128::from_be_bytes(ip.octets()) == 0x2001_0001_0000_0000_0000_0000_0000_0002
                    // AMT (`2001:3::/32`)
                    || matches!(ip.segments(), [0x2001, 3, _, _, _, _, _, _])
                    // AS112-v6 (`2001:4:112::/48`)
                    || matches!(ip.segments(), [0x2001, 4, 0x112, _, _, _, _, _])
                    // ORCHIDv2 (`2001:20::/28`)
                    // Drone Remote ID Protocol Entity Tags (DETs) Prefix (`2001:30::/28`)`
                    || matches!(ip.segments(), [0x2001, b, _, _, _, _, _, _] if (0x20..=0x3F).contains(&b))
                ))
            // 6to4 (`2002::/16`) – it's not explicitly documented as globally reachable,
            // IANA says N/A.
            || matches!(ip.segments(), [0x2002, _, _, _, _, _, _, _])
            || (ip.segments()[0] == 0x2001 && ip.segments()[1] == 0xdb8)
            || (ip.segments()[0] & 0xfe00) == 0xfc00
            || (ip.segments()[0] & 0xffc0) == 0xfe80
        },
    }
}
