use std::net::{Ipv4Addr, Ipv6Addr};

use crate::bytes::TryFromBytes;


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
impl Ipv4Header {
    pub fn try_take(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < 20 {
            None
        } else {
            let version = (bytes[0] & 0b1111_0000) >> 4;
            if version != 4 {
                return None;
            }

            let header_length_w32 = bytes[0] & 0b0000_1111;
            let header_length_bytes = usize::from(header_length_w32) * (32 / 8);
            if header_length_bytes < 20 {
                return None;
            }
            if bytes.len() < header_length_bytes {
                return None;
            }

            let type_of_service = bytes[1];
            let total_length = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
            let identification = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
            let flags_and_fragment_offset = u16::from_be_bytes(bytes[6..8].try_into().unwrap());
            let time_to_live = bytes[8];
            let protocol = bytes[9];
            let header_checksum = u16::from_be_bytes(bytes[10..12].try_into().unwrap());
            let source_address = Ipv4Addr::try_from_bytes(&bytes[12..16]).unwrap();
            let destination_address = Ipv4Addr::try_from_bytes(&bytes[16..20]).unwrap();

            let mut options = [None; 10];
            let mut i = 0;
            while 20 + (i * 4) < header_length_bytes {
                options[i] = Some(bytes[20+(i*4)..20+(i*4)+4].try_into().unwrap());
                i += 1;
            }

            let header = Self {
                version,
                type_of_service,
                total_length,
                identification,
                flags_and_fragment_offset,
                time_to_live,
                protocol,
                header_checksum,
                source_address,
                destination_address,
                options,
            };
            Some((header, &bytes[header_length_bytes..]))
        }
    }
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


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
impl Ipv6Header {
    pub fn try_take(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < 40 {
            None
        } else {
            let first_field = u32::from_be_bytes(bytes[0..4].try_into().unwrap());

            let version = ((first_field & 0b11110000_00000000_00000000_00000000) >> 28).try_into().unwrap();
            if version != 6 {
                return None;
            }
            let traffic_class = ((first_field & 0b00001111_11110000_00000000_00000000) >> 20).try_into().unwrap();
            let flow_label = first_field & 0b00000000_00001111_11111111_11111111;

            let payload_length = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
            let next_header = bytes[6];
            let hop_limit = bytes[7];

            let source_address = Ipv6Addr::try_from_bytes(&bytes[8..24]).unwrap();
            let destination_address = Ipv6Addr::try_from_bytes(&bytes[24..40]).unwrap();

            let header = Self {
                version,
                traffic_class,
                flow_label,
                payload_length,
                next_header,
                hop_limit,
                source_address,
                destination_address,
            };
            Some((header, &bytes[40..]))
        }
    }
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


// managed by IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
