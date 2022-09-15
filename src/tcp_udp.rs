use std::convert::TryInto;

use bitflags::bitflags;

use crate::ip::internet_checksum;
use crate::packet::PacketDissection;


#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
// as defined in RFC9293 section 3.1
pub struct TcpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgement_number: u32,
    // data offset is implicit (how many elements of at the beginning of self.options are Some(_)?)
    // offset is stored as the number of 32-bit words!
    pub flags: TcpFlags,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: [Option<[u8; 4]>; 10], // up to 10 words of 32 bits each
}
impl TcpHeader {
    pub fn try_take<'b, 'h>(bytes: &'b [u8], pseudo_header: &'h [u8]) -> PacketDissection<'b, Self> {
        if bytes.len() < 20 {
            return PacketDissection::TooShort;
        }

        let source_port = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        let destination_port = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        let sequence_number = u32::from_be_bytes(bytes[4..8].try_into().unwrap());
        let acknowledgement_number = u32::from_be_bytes(bytes[8..12].try_into().unwrap());

        let data_offset_w32 = (bytes[12] & 0b1111_0000) >> 4;
        let data_offset_bytes = usize::from(data_offset_w32) * 4;
        if data_offset_bytes < 20 {
            return PacketDissection::TooShort;
        }
        if bytes.len() < data_offset_bytes {
            return PacketDissection::TooShort;
        }

        let full_checksum = internet_checksum(
            pseudo_header.iter().map(|b| *b)
                .chain(bytes.iter().map(|b| *b))
        );
        if full_checksum != 0xFFFF {
            return PacketDissection::IncorrectChecksum;
        }

        let flags = TcpFlags::from_bits(bytes[13]).unwrap();
        let window = u16::from_be_bytes(bytes[14..16].try_into().unwrap());
        let checksum = u16::from_be_bytes(bytes[16..18].try_into().unwrap());
        let urgent_pointer = u16::from_be_bytes(bytes[18..20].try_into().unwrap());

        let mut options = [None; 10];
        let mut i = 0;
        while 20 + (i * 4) < data_offset_bytes {
            options[i] = Some(bytes[20+(i*4)..20+(i*4)+4].try_into().unwrap());
            i += 1;
        }

        let header = Self {
            source_port,
            destination_port,
            sequence_number,
            acknowledgement_number,
            flags,
            window,
            checksum,
            urgent_pointer,
            options,
        };
        PacketDissection::Success { header, rest: &bytes[data_offset_bytes..] }
    }
}


bitflags! {
    #[derive(Default)]
    // managed by IANA: https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml (section "TCP Header Flags")
    pub struct TcpFlags: u8 {
        const FIN = 0b0000_0001;
        const SYN = 0b0000_0010;
        const RST = 0b0000_0100;
        const PSH = 0b0000_1000;
        const ACK = 0b0001_0000;
        const URG = 0b0010_0000;
        const ECE = 0b0100_0000;
        const CWR = 0b1000_0000;
    }
}


#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
// as defined in RFC768, "Format" section
pub struct UdpHeader {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
}
impl UdpHeader {
    pub fn try_take<'b, 'h>(bytes: &'b [u8], pseudo_header: &'h [u8]) -> PacketDissection<'b, Self> {
        if bytes.len() < 8 {
            return PacketDissection::TooShort;
        }

        let source_port = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
        let destination_port = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
        let length = u16::from_be_bytes(bytes[4..6].try_into().unwrap());
        let checksum = u16::from_be_bytes(bytes[6..8].try_into().unwrap());

        let full_checksum = internet_checksum(
            pseudo_header.iter().map(|b| *b)
                .chain(bytes.iter().map(|b| *b))
        );
        if full_checksum != 0xFFFF {
            return PacketDissection::IncorrectChecksum;
        }

        let header = Self {
            source_port,
            destination_port,
            length,
            checksum,
        };
        PacketDissection::Success { header, rest: &bytes[8..] }
    }
}
