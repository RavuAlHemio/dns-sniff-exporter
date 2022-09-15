use pcap::{Packet, PacketHeader};


pub struct OwnedPacket {
    pub header: PacketHeader,
    pub data: Vec<u8>,
}
impl<'a> From<Packet<'a>> for OwnedPacket {
    fn from(p: Packet<'a>) -> Self {
        OwnedPacket {
            header: p.header.clone(),
            data: p.data.into(),
        }
    }
}


#[derive(Debug)]
pub enum PacketDissection<'a, H> {
    Success { header: H, rest: &'a [u8] },
    TooShort,
    WrongType,
    IncorrectChecksum,
}
