use std::net::{Ipv4Addr, Ipv6Addr};

use crate::bytes::TryFromBytes;
use crate::packet::PacketDissection;


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
    pub fn try_take(bytes: &[u8]) -> PacketDissection<Self> {
        if bytes.len() < 20 {
            return PacketDissection::TooShort;
        }

        let version = (bytes[0] & 0b1111_0000) >> 4;
        if version != 4 {
            return PacketDissection::WrongType;
        }

        let header_length_w32 = bytes[0] & 0b0000_1111;
        let header_length_bytes = usize::from(header_length_w32) * (32 / 8);
        if header_length_bytes < 20 {
            return PacketDissection::TooShort;
        }
        if bytes.len() < header_length_bytes {
            return PacketDissection::TooShort;
        }

        let full_checksum = internet_checksum(bytes[0..header_length_bytes].iter().map(|b| *b));
        if full_checksum != 0xFFFF {
            return PacketDissection::IncorrectChecksum;
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
        PacketDissection::Success { header, rest: &bytes[header_length_bytes..] }
    }

    /// Returns the representation of this IPv4 header as the pseudo-header which is "mixed into"
    /// TCP and UDP checksum calculation.
    ///
    /// The pseudo-header is defined in RFC9293 (TCP) for IPv4.
    pub fn to_pseudo_header(&self) -> [u8; 12] {
        let src_addr_bytes = self.source_address.octets();
        let dest_addr_bytes = self.destination_address.octets();

        let mut l4_length = self.total_length - 20;
        for option in &self.options {
            if option.is_some() {
                l4_length -= 4;
            }
        }
        let l4_length_bytes = l4_length.to_be_bytes();

        let mut pseudo_header = [0u8; 12];
        pseudo_header[0..4].copy_from_slice(&src_addr_bytes);
        pseudo_header[4..8].copy_from_slice(&dest_addr_bytes);
        // pseudo_header[8] remains 0
        pseudo_header[9] = self.protocol;
        pseudo_header[10..12].copy_from_slice(&l4_length_bytes);

        pseudo_header
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
    pub fn try_take(bytes: &[u8]) -> PacketDissection<Self> {
        if bytes.len() < 40 {
            return PacketDissection::TooShort;
        }

        let first_field = u32::from_be_bytes(bytes[0..4].try_into().unwrap());

        let version = ((first_field & 0b11110000_00000000_00000000_00000000) >> 28).try_into().unwrap();
        if version != 6 {
            return PacketDissection::WrongType;
        }
        let traffic_class = ((first_field & 0b00001111_11110000_00000000_00000000) >> 20).try_into().unwrap();
        let flow_label = first_field & 0b00000000_00001111_11111111_11111111;

        let payload_length = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        let next_header = bytes[6];
        let hop_limit = bytes[7];

        // IPv6 has no built-in checksum; the responsibility is left to layer-4 protocols

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

        PacketDissection::Success { header, rest: &bytes[40..] }
    }

    /// Returns the representation of this IPv6 header as the pseudo-header which is "mixed into"
    /// TCP and UDP checksum calculation.
    ///
    /// The pseudo-header is defined in RFC8200 (IPv6) for IPv6.
    pub fn to_pseudo_header(&self) -> [u8; 40] {
        let src_addr_bytes = self.source_address.octets();
        let dest_addr_bytes = self.destination_address.octets();

        let l4_length: u32 = (self.payload_length - 40).into();
        let l4_length_bytes = l4_length.to_be_bytes();

        let mut pseudo_header = [0u8; 40];
        pseudo_header[0..16].copy_from_slice(&src_addr_bytes);
        pseudo_header[16..32].copy_from_slice(&dest_addr_bytes);
        pseudo_header[32..36].copy_from_slice(&l4_length_bytes);
        // pseudo_header[36..39] remain 0
        pseudo_header[39] = self.next_header;

        pseudo_header
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


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum IpHeader {
    V4(Ipv4Header),
    V6(Ipv6Header),
}
impl IpHeader {
    pub fn inner_protocol(&self) -> u8 {
        match self {
            Self::V4(h) => h.protocol,
            Self::V6(h) => h.next_header,
        }
    }

    pub fn to_pseudo_header(&self) -> ([u8; 40], usize) {
        match self {
            Self::V4(h) => {
                let mut buf = [0u8; 40];
                let ph = h.to_pseudo_header();
                buf[0..12].copy_from_slice(&ph);
                (buf, 12)
            },
            Self::V6(h) => {
                (h.to_pseudo_header(), 40)
            },
        }
    }
}


// managed by IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml#protocol-numbers-1
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;


/// Performs ones' complement addition on two u16s.
///
/// Ones' complement addition on two's complement machines is done by "end-around carry", i.e.
/// adding carry bits as the least significant bit to the result.
#[inline]
pub fn ones_complement_add(a: u16, b: u16) -> u16 {
    let (mut sum, mut carry) = a.overflowing_add(b);
    // worst case: 0xFFFF + 0xFFFF = 0x1FFFE (overflows)
    // => 0xFFFE + 0x0001 = 0xFFFF (does not overflow)
    // => no need to worry about carry more than once
    if carry {
        sum += 1;
    }
    sum
}


/// Calculates the Internet checksum for the bytes in the given iterator.
///
/// The Internet checksum is called for in RFCs such as RFC768 (UDP), RFC791 (IPv4) and
/// RFC793/RFC9293 (TCP). RFC1071 contains additional tips for computing these checksums.
pub fn internet_checksum<I: IntoIterator<Item = u8>>(bytes: I) -> u16 {
    let mut checksum = 0;
    let mut iterator = bytes.into_iter();
    loop {
        // gimme two bytes
        let top_byte = match iterator.next() {
            Some(b) => b,
            None => break, // we're out of bytes; stop
        };
        let bottom_byte = match iterator.next() {
            Some(b) => b,
            None => 0x00, // odd byte at end; pad with zero bits on the right, says RFC9293 section 3.1
        };
        let word = ((top_byte as u16) << 8) | (bottom_byte as u16);

        // checksum is calculated in ones' complement
        checksum = ones_complement_add(checksum, word);
    }

    if checksum == 0xFFFF {
        0xFFFF
    } else {
    // actual ones' complement
    checksum ^ 0xFFFF
    }
}


#[cfg(test)]
mod tests {
    use super::{internet_checksum, ones_complement_add};

    #[test]
    fn test_ones_complement_add() {
        assert_eq!(ones_complement_add(0xF000, 0x1009), 0x000A);
    }

    #[test]
    fn test_internet_checksum() {
        let bs: [u8; 20] = [
            0x45, 0x00, 0x00, 0x5d, 0x36, 0x4d, 0x00, 0x00,
            0x3c, 0x11, 0x36, 0xb5, 0x80, 0x82, 0x04, 0x03,
            0x80, 0x82, 0x0c, 0x87,
        ];
        assert_eq!(internet_checksum(bs), 0xFFFF);
    }
}
