mod ethernet;
mod ip;


use clap::Parser;
use pcap::{Capture, Device, Error as PcapError};


#[derive(Parser)]
struct Opts {
    interface_index: Option<usize>,
}


fn hexdump(bs: &[u8]) {
    let mut i = 0;

    while i < bs.len() {
        print!("{:08x}  ", i);
        for j in 0..16 {
            if i + j < bs.len() {
                print!("{:02x} ", bs[i + j]);
            } else {
                print!("   ");
            }

            if j == 8 {
                print!(" ");
            }
        }

        print!(" |");

        for j in 0..16 {
            if i + j >= bs.len() {
                break;
            }

            let b = bs[i + j];
            if b >= 0x20 && b <= 0x7E {
                print!("{}", b as char);
            } else {
                print!(".");
            }
        }

        println!("|");

        i += 16;
    }
}


fn main() {
    let opts = Opts::parse();

    // get devices
    let mut device_list = Device::list()
        .expect("failed to get device list");
    if device_list.len() == 0 {
        panic!("no capture devices available");
    }

    let interface_index = match opts.interface_index {
        Some(ii) => ii,
        None => {
            for (i, device) in device_list.into_iter().enumerate() {
                println!("{}: {}", i, device.desc.as_ref().map(|d| d.as_str()).unwrap_or(device.name.as_str()));
            }
            return;
        },
    };
    if interface_index >= device_list.len() {
        panic!("interface index {} too large for number of devices ({})", interface_index, device_list.len());
    }

    let dev = device_list.swap_remove(interface_index);
    eprintln!("will capture on {}", dev.desc.as_ref().map(|d| d.as_str()).unwrap_or(dev.name.as_str()));
    let cap_inact = Capture::from_device(dev)
        .expect("failed to convert capture device")
        .timeout(1000);
    let mut cap = cap_inact
        .open().expect("failed to open capture device");
    cap.filter("udp port 53", true)
        .expect("failed to set capture device filter");
    println!("datalink is {:?}", cap.get_datalink());

    loop {
        let packet = match cap.next_packet() {
            Ok(p) => p,
            Err(PcapError::TimeoutExpired) => continue,
            Err(_) => break,
        };
        println!("{:?}", packet.header);
        hexdump(&packet.data);
    }
}
