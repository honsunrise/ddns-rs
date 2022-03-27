use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::net::IpAddr;

use addr::parse_dns_name;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use log::info;

pub use self::cloudflare::Cloudflare;
pub use self::fake::Fake;
pub use self::godaddy::Godaddy;
use crate::IpType;

mod cloudflare;
mod fake;
mod godaddy;

#[async_trait(?Send)]
pub trait Provider {
    type DNSRecord: AsRef<IpAddr> + Eq + PartialEq;

    async fn get_dns_record(&self, family: IpType) -> Result<HashMap<String, Vec<(Self::DNSRecord, IpAddr)>>>;
    async fn create_dns_record<P: AsRef<str> + Send>(&self, prefix: P, ip: &IpAddr, ttl: u32) -> Result<()>;
    async fn update_dns_record(&self, record: &Self::DNSRecord, ip: &IpAddr) -> Result<()>;
    async fn delete_dns_record(&self, record: &Self::DNSRecord) -> Result<()>;
}

#[derive(Debug, Clone)]
struct HashSetItem<'a, T: Provider> {
    ip: &'a IpAddr,
    ref_record: Option<&'a T::DNSRecord>,
}

impl<'a, T: Provider> Hash for HashSetItem<'a, T> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.ip.hash(state)
    }
}

impl<'a, T: Provider> PartialOrd for HashSetItem<'a, T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.ip.partial_cmp(other.ip)
    }
}

impl<'a, T: Provider> PartialEq<Self> for HashSetItem<'a, T> {
    fn eq(&self, other: &Self) -> bool {
        self.ip.eq(other.ip)
    }
}

impl<'a, T: Provider> Eq for HashSetItem<'a, T> {}

#[async_trait(?Send)]
pub(crate) trait DynProvider {
    async fn check_and_update(
        &self,
        new_ips_group: &HashMap<String, Vec<IpAddr>>,
        ttl: u32,
        force: bool,
        family: IpType,
    ) -> Result<Vec<(String, IpAddr)>>;
}

#[async_trait(?Send)]
impl<P> DynProvider for P
where
    P: Provider,
{
    async fn check_and_update(
        &self,
        new_ips_groups: &HashMap<String, Vec<IpAddr>>,
        ttl: u32,
        force: bool,
        family: IpType,
    ) -> Result<Vec<(String, IpAddr)>> {
        let mut real_used_ips = vec![];
        let dns_records_groups = self.get_dns_record(family).await?;
        if dns_records_groups.is_empty() {
            info!("remote dns record(s) is empty");
        } else {
            let ips_str = dns_records_groups
                .iter()
                .flat_map(|(prefix, ips)| ips.iter().map(move |ip| format!("{} -> {}", prefix, ip.1)))
                .collect::<Vec<_>>()
                .join(", ");
            info!("got dns record(s) from remote: [{}]", ips_str);
        }
        for (prefix, new_ips) in new_ips_groups {
            match dns_records_groups.get(prefix) {
                Some(dns_records) => {
                    let local_set: HashSet<_> = new_ips
                        .iter()
                        .map(|ip| HashSetItem::<'_, P> {
                            ip,
                            ref_record: None,
                        })
                        .collect();
                    let remote_set: HashSet<_> = dns_records
                        .iter()
                        .map(|(record, ip)| HashSetItem::<'_, P> {
                            ip,
                            ref_record: Some(record),
                        })
                        .collect();
                    let mut news: Vec<_> = local_set.difference(&remote_set).collect();
                    let mut olds: Vec<_> = remote_set.difference(&local_set).collect();
                    if force {
                        let sames: Vec<_> = remote_set.intersection(&local_set).collect();
                        for item in sames {
                            let record = item.ref_record.unwrap();
                            let ip = item.ip;
                            info!("force updating dns record to {}", ip);
                            self.update_dns_record(record, ip).await?;
                            real_used_ips.push((prefix.clone(), *ip));
                        }
                    }
                    while let (Some(old_item), Some(new_item)) = (olds.get(0), news.get(0)) {
                        let record = old_item.ref_record.unwrap();
                        let new_ip = new_item.ip;
                        olds.remove(0);
                        news.remove(0);
                        info!("updating dns record to {}", new_ip);
                        self.update_dns_record(record, new_ip).await?;
                        real_used_ips.push((prefix.clone(), *new_ip));
                    }
                    for old_item in olds {
                        info!("target ip {} not belong to this interface, delete it", old_item.ip);
                        self.delete_dns_record(old_item.ref_record.unwrap()).await?;
                    }
                    for new_item in news {
                        info!("target ip {} not exist in dns provider, create it", new_item.ip);
                        self.create_dns_record(prefix, new_item.ip, ttl).await?;
                        real_used_ips.push((prefix.clone(), *new_item.ip));
                    }
                },
                None => {
                    for ip in new_ips {
                        info!("target ip {} not exist in dns provider, create it", ip);
                        self.create_dns_record(prefix, ip, ttl).await?;
                        real_used_ips.push((prefix.clone(), *ip));
                    }
                },
            }
        }
        if real_used_ips.is_empty() {
            info!("remote and local are the same nothing to do");
        }
        Ok(real_used_ips)
    }
}

#[inline]
pub(crate) fn record_type_from_ip(ip: &IpAddr) -> &'static str {
    match ip {
        IpAddr::V4(_) => "A",
        IpAddr::V6(_) => "AAAA",
    }
}

#[inline]
pub(crate) fn get_dns_prefix_root<D: AsRef<str>>(dns: D) -> Result<(String, String)> {
    let dns = dns.as_ref();
    let result = parse_dns_name(dns).map_err(|err| anyhow!("illegal dns name {}", err))?;
    let prefix = result.prefix().unwrap_or("@");
    let root = result.root().ok_or(anyhow!("illegal dns name"))?;
    Ok((prefix.to_owned(), root.to_owned()))
}

#[cfg(test)]
mod tests {
    use anyhow::Result;

    use super::get_dns_prefix_root;

    #[test]
    fn test_get_dns_root_prefix() -> Result<()> {
        assert!(get_dns_prefix_root("").is_err());
        assert!(get_dns_prefix_root("a").is_err());
        assert_eq!(get_dns_prefix_root("a.b")?, ("@".to_owned(), "a.b".to_owned()));
        assert_eq!(get_dns_prefix_root("a.b.c")?, ("a".to_owned(), "b.c".to_owned()));
        assert_eq!(get_dns_prefix_root("a.b.c.d")?, ("a.b".to_owned(), "c.d".to_owned()));
        Ok(())
    }
}
