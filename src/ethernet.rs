use from_to_repr::FromToRepr;
use macaddr::MacAddr6;

use crate::bytes::TryFromBytes;


#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
// definition taken from Wikipedia because I'm not throwing money into IEEE's undeserving maw
pub struct EthernetHeader {
    pub destination: MacAddr6,
    pub source: MacAddr6,
    pub ethertype: u16,
}
impl EthernetHeader {
    pub fn try_take(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < 14 {
            None
        } else {
            let destination = MacAddr6::try_from_bytes(&bytes[0..6]).unwrap();
            let source = MacAddr6::try_from_bytes(&bytes[6..12]).unwrap();
            let ethertype = u16::from_be_bytes(bytes[12..14].try_into().unwrap());
            let header = Self {
                destination,
                source,
                ethertype,
            };
            Some((header, &bytes[14..]))
        }
    }
}

// managed by IEEE: https://regauth.standards.ieee.org/standards-ra-web/pub/view.html ("Ethertype")
pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_VLAN_TAG: u16 = 0x8100;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;


#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VlanTagHeader {
    pub priority_code_point: PriorityCodePoint,
    pub drop_eligible_indicator: bool,
    pub vlan_id: u16,
    pub ethertype: u16,
}
impl VlanTagHeader {
    pub fn try_take(bytes: &[u8]) -> Option<(Self, &[u8])> {
        if bytes.len() < 4 {
            None
        } else {
            let tci = u16::from_be_bytes(bytes[0..2].try_into().unwrap());
            let priority_code_point = ((tci & 0b1110_0000_0000_0000) >> 13).try_into().unwrap();
            let drop_eligible_indicator = (tci & 0b0001_0000_0000_0000) != 0;
            let vlan_id = tci & 0b0000_1111_1111_1111;

            let ethertype = u16::from_be_bytes(bytes[2..4].try_into().unwrap());
            let header = Self {
                priority_code_point,
                drop_eligible_indicator,
                vlan_id,
                ethertype,
            };
            Some((header, &bytes[14..]))
        }
    }
}


#[derive(Clone, Copy, Debug, Eq, FromToRepr, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u16)]
pub enum PriorityCodePoint {
    BestEffort = 0b000,
    Background = 0b001,
    ExcellentEffort = 0b010,
    CriticalApplication = 0b011,
    Video = 0b100,
    Voice = 0b101,
    InternetworkControl = 0b110,
    NetworkControl = 0b111,
}
impl Default for PriorityCodePoint {
    fn default() -> Self { Self::BestEffort }
}
