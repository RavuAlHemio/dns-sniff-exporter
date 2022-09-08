use std::net::{Ipv4Addr, Ipv6Addr};


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
// as defined in RFC791 section 3.1
pub struct Ipv4Header {
    pub version: u8,
    // header length is implicit (how many elements of at the beginning of self.options are Some(_)?)
    // length is stored as the number of 32-bit words!
    pub type_of_service: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags_and_fragment_offset: u16,
    pub time_to_live: u8,
    pub protocol: u8,
    pub header_checksum: u16,
    pub source_address: Ipv4Addr,
    pub destination_address: Ipv4Addr,
    pub options: [Option<[u8; 4]>; 10], // up to 10 words of 32 bits each
}
impl Default for Ipv4Header {
    fn default() -> Self {
        Self {
            version: Default::default(),
            type_of_service: Default::default(),
            total_length: Default::default(),
            identification: Default::default(),
            flags_and_fragment_offset: Default::default(),
            time_to_live: Default::default(),
            protocol: Default::default(),
            header_checksum: Default::default(),
            source_address: Ipv4Addr::UNSPECIFIED,
            destination_address: Ipv4Addr::UNSPECIFIED,
            options: Default::default(),
        }
    }
}


// as defined in RFC8200 section 3
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16, // in bytes
    pub next_header: u8, // comparable with protocol
    pub hop_limit: u8, // comparable with time_to_live
    pub source_address: Ipv6Addr,
    pub destination_address: Ipv6Addr,
}
impl Default for Ipv6Header {
    fn default() -> Self {
        Self {
            version: Default::default(),
            traffic_class: Default::default(),
            flow_label: Default::default(),
            payload_length: Default::default(),
            next_header: Default::default(),
            hop_limit: Default::default(),
            source_address: Ipv6Addr::UNSPECIFIED,
            destination_address: Ipv6Addr::UNSPECIFIED,
        }
    }
}
