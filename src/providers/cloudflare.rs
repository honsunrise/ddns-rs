use std::fmt::{Display, Formatter};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{bail, ensure, Result};
use async_trait::async_trait;
use log::{debug, warn};
use reqwest::{Client, Method};
use serde::{Deserialize, Serialize};

use super::Provider;
use crate::IpType;

const API_ENDPOINT: &str = "https://api.cloudflare.com/client/v4";

#[derive(PartialOrd, Eq, PartialEq, Hash, Debug, Clone)]
pub struct DNSRecord {
    pub id: String,
    pub ip: IpAddr,
}

impl Display for DNSRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Dns {} with ip {}", self.id, self.ip)
    }
}

impl AsRef<IpAddr> for DNSRecord {
    #[inline]
    fn as_ref(&self) -> &IpAddr {
        &self.ip
    }
}

async fn send_request<Q: Serialize + ?Sized, B: Serialize + ?Sized, T: serde::de::DeserializeOwned>(
    client: &Client,
    token: &str,
    method: Method,
    api: impl AsRef<str>,
    query: &Q,
    body: &B,
) -> Result<T> {
    #[derive(Deserialize, Debug)]
    pub struct CfError {
        pub code: u16,
        pub message: String,
    }

    impl Display for CfError {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}: {}", self.code, self.message)
        }
    }

    #[derive(Deserialize, Debug)]
    pub struct CfOnlyResult<ResultType> {
        pub result: ResultType,
    }

    #[derive(Deserialize, Debug, Default)]
    pub struct CfOnlyErrors {
        pub errors: Vec<CfError>,
    }

    let api = api.as_ref();
    let response = client
        .request(method, format!("{API_ENDPOINT}/{api}"))
        .header("Authorization", format!("Bearer {token}"))
        .query(query)
        .json(body)
        .send()
        .await?;
    let status = response.status();
    if status.is_success() {
        Ok(response.json::<CfOnlyResult<T>>().await?.result)
    } else {
        let result = response.json::<CfOnlyErrors>().await?;
        bail!("{status}: {:#?}", result.errors)
    }
}

#[derive(Deserialize, Debug)]
pub struct Zone {
    // we only care about the id and name
    pub id: String,
    pub name: String,
}

impl Display for Zone {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Zone {} with id: {}", self.name, self.id)
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(tag = "type")]
#[allow(clippy::upper_case_acronyms)]
enum DnsContent {
    A { content: Ipv4Addr },
    AAAA { content: Ipv6Addr },
}

pub struct Cloudflare {
    client: Client,
    dns: String,
    token: String,
    zone_identifier: String,
    proxied: bool,
}

impl Cloudflare {
    pub async fn create<T: AsRef<str>, D: AsRef<str>>(token: T, dns: D, proxied: bool) -> Result<Self> {
        let token = token.as_ref();
        let dns = dns.as_ref();
        let zone_name = if dns.ends_with('.') {
            let mut v = dns.rsplit('.').skip(1).take(2).collect::<Vec<_>>();
            v.reverse();
            v.join(".")
        } else {
            let mut v = dns.rsplit('.').take(2).collect::<Vec<_>>();
            v.reverse();
            v.join(".")
        };

        debug!("zone name is {}", zone_name);

        let client = reqwest::Client::builder().build()?;

        let zone_response: Vec<Zone> = send_request(
            &client,
            token,
            Method::GET,
            "zones",
            &[("name", zone_name.as_str()), ("status", "active")],
            &(),
        )
        .await?;

        ensure!(!zone_response.is_empty(), "can't find zone with {zone_name}");

        if zone_response.len() > 1 {
            warn!("more than one zone: {zone_response:#?}");
        }

        Ok(Cloudflare {
            client,
            dns: dns.to_owned(),
            token: token.to_owned(),
            zone_identifier: zone_response.into_iter().next().unwrap().id,
            proxied,
        })
    }
}

#[async_trait(?Send)]
impl Provider for Cloudflare {
    type DNSRecord = DNSRecord;

    async fn get_dns_record(&self, family: IpType) -> Result<Vec<Self::DNSRecord>> {
        #[derive(Serialize)]
        #[serde(rename_all = "lowercase")]
        struct ListDnsParams<'a> {
            name: &'a str,
            page: u32,
            per_page: u32,
            type_: &'a str,
        }

        #[derive(Deserialize, Debug)]
        struct DnsRecord {
            pub id: String,
            #[serde(flatten)]
            pub content: DnsContent,
        }

        let mut result = vec![];
        let mut current_page = 1;
        loop {
            let dns_result: Vec<DnsRecord> = send_request(
                &self.client,
                &self.token,
                Method::GET,
                format!("zones/{}/dns_records", self.zone_identifier),
                &ListDnsParams {
                    name: &self.dns,
                    page: current_page,
                    per_page: 50,
                    type_: match family {
                        IpType::V4 => "A",
                        IpType::V6 => "AAAA",
                    },
                },
                &(),
            )
            .await?;

            if dns_result.is_empty() {
                break;
            }

            for dns in &dns_result {
                match (family, &dns.content) {
                    (IpType::V6, DnsContent::AAAA { content: ip }) => {
                        result.push(DNSRecord {
                            id: dns.id.clone(),
                            ip: IpAddr::V6(*ip),
                        });
                    },
                    (IpType::V4, DnsContent::A { content: ip }) => {
                        result.push(DNSRecord {
                            id: dns.id.clone(),
                            ip: IpAddr::V4(*ip),
                        });
                    },
                    _ => {},
                }
            }

            if dns_result.len() < 50 {
                break;
            }
            current_page += 1;
        }
        Ok(result)
    }

    async fn create_dns_record(&self, ip: &IpAddr, ttl: u32) -> Result<()> {
        #[derive(Serialize)]
        struct CreateDnsParams<'a> {
            #[serde(flatten)]
            content: DnsContent,
            name: &'a str,
            ttl: u32,
            proxied: bool,
        }

        let content = match *ip {
            IpAddr::V6(ip) => DnsContent::AAAA { content: ip },
            IpAddr::V4(ip) => DnsContent::A { content: ip },
        };
        send_request::<_, _, serde_json::Value>(
            &self.client,
            &self.token,
            Method::POST,
            format!("zones/{}/dns_records", self.zone_identifier),
            &(),
            &CreateDnsParams {
                content,
                name: &self.dns,
                ttl,
                proxied: self.proxied,
            },
        )
        .await?;
        Ok(())
    }

    async fn update_dns_record(&self, record: &Self::DNSRecord, ip: &IpAddr) -> Result<()> {
        #[derive(Serialize)]
        struct UpdateDnsParams<'a> {
            #[serde(flatten)]
            content: DnsContent,
            name: &'a str,
            id: &'a str,
        }

        let content = match *ip {
            IpAddr::V6(ip) => DnsContent::AAAA { content: ip },
            IpAddr::V4(ip) => DnsContent::A { content: ip },
        };
        send_request::<_, _, serde_json::Value>(
            &self.client,
            &self.token,
            Method::PATCH,
            format!("zones/{}/dns_records/{}", self.zone_identifier, record.id),
            &(),
            &UpdateDnsParams {
                content,
                name: &self.dns,
                id: &record.id,
            },
        )
        .await?;
        Ok(())
    }

    async fn delete_dns_record(&self, record: &Self::DNSRecord) -> Result<()> {
        send_request::<_, _, serde_json::Value>(
            &self.client,
            &self.token,
            Method::DELETE,
            format!("zones/{}/dns_records/{}", self.zone_identifier, record.id),
            &(),
            &(),
        )
        .await?;
        Ok(())
    }
}
