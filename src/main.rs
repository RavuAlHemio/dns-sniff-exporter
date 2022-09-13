mod bytes;
mod dns;
mod ethernet;
mod ip;
mod packet;
mod tcp_udp;


use std::time::{Duration, Instant};

use clap::Parser;
use pcap::Device;
use tokio::sync::mpsc;
use tracing::error;

use crate::packet::OwnedPacket;


#[derive(Parser)]
struct Opts {
    interface_index: Option<usize>,
    #[clap(default_value = "32")] buffer_size: usize,
    #[clap(default_value = "60")] sample_secs: u64,
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


#[tokio::main]
async fn main() {
    // set up tracing
    let (stdout_non_blocking, _guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .lossy(false)
        .finish(std::io::stdout());
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(stdout_non_blocking)
        .init();

    // parse options
    let opts = Opts::parse();

    let interface_index = match opts.interface_index {
        Some(ii) => ii,
        None => {
            let mut device_list = Device::list()
                .expect("failed to obtain device list");
            for (i, device) in device_list.into_iter().enumerate() {
                println!("{}: {}", i, device.desc.as_ref().map(|d| d.as_str()).unwrap_or(device.name.as_str()));
            }
            return;
        },
    };
}
