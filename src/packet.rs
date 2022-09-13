use std::fmt;
use std::time::{Duration, Instant};

use pcap::{Capture, Device, Error as PcapError, Packet, PacketHeader};
use tokio::sync::mpsc;
use tracing::{debug, error, warn};

use crate::ethernet::{
    EthernetHeader, ETHERTYPE_IPV4, ETHERTYPE_IPV6, ETHERTYPE_VLAN_TAG, VlanTagHeader,
};
use crate::ip::{Ipv4Header, Ipv6Header};


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


pub enum PacketDissection<'a, H> {
    Success { header: H, rest: &'a [u8] },
    TooShort,
    IncorrectChecksum,
}


#[derive(Debug, Eq, PartialEq)]
pub enum SamplingError {
    GetInterfaceList(pcap::Error),
    InterfaceIndexTooHigh { index: usize, count: usize },
    ConvertCaptureDevice(pcap::Error),
    OpenCaptureDevice(pcap::Error),
    SetFilter(pcap::Error),
}
impl fmt::Display for SamplingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::GetInterfaceList(e)
                => write!(f, "error getting interface list: {}", e),
            Self::InterfaceIndexTooHigh { index, count }
                => write!(f, "requested device with index {} but system only lists {} devices", index, count),
            Self::ConvertCaptureDevice(e)
                => write!(f, "failed to convert the device into a capture: {}", e),
            Self::OpenCaptureDevice(e)
                => write!(f, "failed to open the capture device: {}", e),
            Self::SetFilter(e)
                => write!(f, "failed to set capture filter: {}", e),
        }
    }
}
impl std::error::Error for SamplingError {
}


pub async fn collect_sample(
    interface_index: usize,
    sample_duration: Duration,
    filter: Option<&str>,
    buffer_size: Option<usize>,
) -> Result<(), SamplingError> {
    // get device
    let mut device_list = Device::list()
        .map_err(|e| SamplingError::GetInterfaceList(e))?;
    if interface_index >= device_list.len() {
        return Err(SamplingError::InterfaceIndexTooHigh { index: interface_index, count: device_list.len() });
    }

    let device = device_list.swap_remove(interface_index);
    debug!("capturing on {}", device.desc.as_ref().map(|d| d.as_str()).unwrap_or(device.name.as_str()));
    let cap_inact = Capture::from_device(device)
        .map_err(|e| SamplingError::ConvertCaptureDevice(e))?
        .timeout(1000);
    let mut cap = cap_inact
        .open().map_err(|e| SamplingError::OpenCaptureDevice(e))?;
    if let Some(f) = filter {
        cap.filter(f, true)
            .map_err(|e| SamplingError::SetFilter(e))?;
    }

    let (packet_sender, mut packet_receiver) = mpsc::channel(buffer_size.unwrap_or(32));

    let packet_handler_handle = tokio::task::spawn_blocking(move || {
        let start_time = Instant::now();
        while Instant::now() - start_time < sample_duration {
            let packet = match cap.next_packet() {
                Ok(p) => OwnedPacket::from(p),
                Err(PcapError::TimeoutExpired) => continue,
                Err(e) => {
                    error!("error while capturing packets: {}", e);
                    break;
                },
            };
            if let Err(e) = packet_sender.blocking_send(packet) {
                error!("error enqueuing packet: {}", e);
            }
        }
    });

    while let Some(packet) = packet_receiver.recv().await {
        // FIXME: assuming Ethernet Layer-2 encapsulation
        let (eth, rest) = match EthernetHeader::try_take(&packet.data) {
            Some(pr) => pr,
            None => {
                warn!("non-Ethernet frame slipped through the cracks: {:?}", packet.data.as_slice());
                continue;
            },
        };

        let ip_bytes = match eth.ethertype {
            ETHERTYPE_VLAN_TAG => {
                // try to unpack
                let (_tag, rest) = match VlanTagHeader::try_take(&rest) {
                    Some(pr) => pr,
                    None => {
                        warn!("VLAN-tagged Ethernet frame but failed to extract header: {:?}", packet.data.as_slice());
                        continue;
                    },
                };

                let (inner_eth, rest) = match EthernetHeader::try_take(rest) {
                    Some(pr) => pr,
                    None => {
                        warn!("VLAN tag detected but failed to decode inner Ethernet payload: {:?}", packet.data.as_slice());
                        continue;
                    },
                };
                if inner_eth.ethertype != ETHERTYPE_IPV4 && inner_eth.ethertype != ETHERTYPE_IPV6 {
                    warn!("VLAN-tagged Ethernet frame with unknown (inner) ethertype 0x{:04X} slipped through the cracks: {:?}", inner_eth.ethertype, packet.data.as_slice());
                    continue;
                }
                rest
            },
            ETHERTYPE_IPV4|ETHERTYPE_IPV6 => {
                rest
            },
            other => {
                warn!("Ethernet frame with unknown ethertype 0x{:04X} slipped through the cracks: {:?}", other, packet.data.as_slice());
                continue;
            },
        };

        // check IP version by peeking
        if ip_bytes.len() < 1 {
            warn!("Ethernet frame ends before IP header");
            continue;
        }
        let ip_version = (ip_bytes[0] & 0b1111_0000) >> 4;
        match ip_version {
            4 => {
                let (ip_header, rest) = match Ipv4Header::try_take(ip_bytes) {
                    Some(pr) => pr,
                    None => {
                        warn!("failed to parse IPv4 header of: {:?}", packet.data.as_slice());
                        continue;
                    },
                };
            },
            6 => {
                let (ip_header, rest) = match Ipv6Header::try_take(ip_bytes) {
                    Some(pr) => pr,
                    None => {
                        warn!("failed to parse IPv6 header of: {:?}", packet.data.as_slice());
                        continue;
                    },
                };
            },
            other => {
                warn!("Ethernet frame with IP packet with unexpected version {} slipped through the cracks: {:?}", other, packet.data.as_slice());
                continue;
            },
        }
    }

    if let Err(e) = packet_handler_handle.await {
        error!("packet handler panicked: {}", e);
    }

    Ok(())
}
