use std::collections::HashMap;
use std::net::IpAddr;

use chrono::{DateTime, Utc};
use trust_dns_proto::rr::{Name, RecordType};


#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PerSourceStats {
    pub count: u64,
    pub type_to_count: HashMap<RecordType, u64>,
}
impl PerSourceStats {
    pub fn new() -> Self {
        Self {
            count: 0,
            type_to_count: HashMap::new(),
        }
    }
}


#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsStats {
    pub total_count: u64,
    pub source_to_stats: HashMap<IpAddr, PerSourceStats>,
    pub top_level_domains: Vec<(DateTime<Utc>, IpAddr, RecordType, String)>,
}
impl DnsStats {
    pub fn new() -> Self {
        Self {
            total_count: 0,
            source_to_stats: HashMap::new(),
            top_level_domains: Vec::new(),
        }
    }

    pub fn add_query(&mut self, timestamp: DateTime<Utc>, source: IpAddr, record_type: RecordType, name: Name) {
        self.total_count += 1;

        let per_source_stats = self.source_to_stats
            .entry(source)
            .or_insert_with(|| PerSourceStats::new());
        per_source_stats.count += 1;
        let per_type_count = per_source_stats.type_to_count
            .entry(record_type)
            .or_insert(0);
        *per_type_count += 1;

        let name_parts: Vec<&[u8]> = name.iter().collect();
        if name_parts.len() == 1 {
            // it's a top-level domain
            if let Ok(tld) = String::from_utf8(Vec::from(name_parts[0])) {
                self.top_level_domains.push((timestamp, source, record_type, tld));
            }
        }
    }
}
