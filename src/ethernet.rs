use std::net::{Ipv4Addr, Ipv6Addr};

use macaddr::MacAddr6;


#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct EthernetHeader {
    pub destination: MacAddr6,
    pub source: MacAddr6,
    pub ethertype: u16,
}

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const ETHERTYPE_VLAN_TAG: u16 = 0x8100;
pub const ETHERTYPE_IPV6: u16 = 0x86DD;


#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VlanTag {
    pub priority_code_point: PriorityCodePoint,
    pub drop_eligible_indicator: bool,
    pub vlan_id: u16,
}


#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
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
