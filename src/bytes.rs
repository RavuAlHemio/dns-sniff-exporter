use std::net::{Ipv4Addr, Ipv6Addr};

use macaddr::MacAddr6;


pub trait TryFromBytes : Sized {
    fn try_from_bytes(bytes: &[u8]) -> Option<Self>;
}

impl TryFromBytes for Ipv4Addr {
    fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        let bs: [u8; 4] = bytes[0..4].try_into().ok()?;
        Some(Self::from(bs))
    }
}

impl TryFromBytes for Ipv6Addr {
    fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        let bs: [u8; 16] = bytes[0..16].try_into().ok()?;
        Some(Self::from(bs))
    }
}

impl TryFromBytes for MacAddr6 {
    fn try_from_bytes(bytes: &[u8]) -> Option<Self> {
        let bs: [u8; 6] = bytes[0..6].try_into().ok()?;
        Some(Self::from(bs))
    }
}
