// Copyright 2021 Oxide Computer Company

use std::mem::MaybeUninit;
use socket2::{Socket, Domain, Type, Protocol, SockAddr};
use anyhow::Result;
use std::net::{Ipv6Addr, SocketAddrV6};
use std::str::FromStr;
use icmpv6::{RouterSolicitation, RouterAdvertisement, RDPMessage};
use ron::ser::{to_string_pretty, PrettyConfig};

use clap::{AppSettings, Clap};

#[derive(Clap)]
#[clap(
    version = "0.1", 
    author = "Ryan Goodfellow <ryan.goodfellow@oxide.computer>"
)]
#[clap(setting = AppSettings::ColoredHelp)]
#[clap(setting = AppSettings::InferSubcommands)]
struct Opts {
    #[clap(short, long, default_value = "ff02::a1f7")]
    multicast_group: String,

    #[clap(short, long, parse(from_occurrences))]
    verbose: i32,

    #[clap(subcommand)]
    subcmd: SubCommand,
}

#[derive(Clap)]
enum SubCommand {
    Watch(Watch),
    Advertise(Advertise),
    Solicit(Solicit),
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
struct Watch { 
    #[clap(short, long)]
    count: u32,
}

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
struct Advertise { }

#[derive(Clap)]
#[clap(setting = AppSettings::ColoredHelp)]
struct Solicit { }

fn main() {

    let opts: Opts = Opts::parse();
    match opts.subcmd {
        SubCommand::Watch(ref w) => {
            match run_watch(&opts, &w) {
                Ok(()) => {},
                Err(e) => println!("{}", e),
            }
        },
        SubCommand::Advertise(ref a) => {
            match run_advertise(&opts, &a) {
                Ok(()) => {},
                Err(e) => println!("{}", e),
            }
        }
        SubCommand::Solicit(ref s) => {
            match run_solicit(&opts, &s) {
                Ok(()) => {},
                Err(e) => println!("{}", e),
            }
        }
    }

}

fn run_advertise(opts: &Opts, _a: &Advertise) -> Result<()> {

    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    let maddr = opts.multicast_group.as_str();
    let mc = Ipv6Addr::from_str(maddr)?;
    let sa = SockAddr::from(SocketAddrV6::new(mc, 0, 0, 0));

    let ra = RouterAdvertisement::new(
        1,          //hop limit
        false,      // managed address (dhcpv6)
        false,      // other stateful (stateless dhcpv6)
        0,          // not a default router
        100,        // consider this router reachable for 100 ms
        0,          // No retrans timer specified
        None,       // no source address,
        Some(9216), // jumbo frames ftw
        None,       // no prefix info
    );
    let wire = ra.wire();

    //TODO set multicast out interface

    let bytes_sent = socket.send_to(wire.as_slice(), &sa)?;
    println!("sent {} bytes", bytes_sent);

    Ok(())

}

fn run_solicit(opts: &Opts, _s: &Solicit) -> Result<()> {

    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    let maddr = opts.multicast_group.as_str();
    let mc = Ipv6Addr::from_str(maddr)?;
    let sa = SockAddr::from(SocketAddrV6::new(mc, 0, 0, 0));

    let rs = RouterSolicitation::new(None);
    let wire = rs.wire();

    //TODO set multicast out interface

    let bytes_sent = socket.send_to(wire.as_slice(), &sa)?;
    println!("sent {} bytes", bytes_sent);

    Ok(())

}

fn run_watch(opts: &Opts, w: &Watch) -> Result<()> {

    let socket = Socket::new(Domain::IPV6, Type::RAW, Some(Protocol::ICMPV6))?;
    let maddr = opts.multicast_group.as_str();
    let mc = Ipv6Addr::from_str(maddr)?;
    socket.join_multicast_v6(&mc, 0)?;

    let mut count: u32 = 0;
    loop {
        let mut buf: [u8; 1024] = [0;1024];
        let mut _buf = unsafe{ 
            &mut(*buf.as_mut_ptr().cast::<[MaybeUninit<u8>; 1024]>()) 
        };

        let (sz, sender) = socket.recv_from(_buf)?;
        let senderv6 = match sender.as_socket_ipv6() {
            Some(v6) => Some(*v6.ip()),
            _ => None,
        };

        match icmpv6::parse_icmpv6(&buf[..sz]) {
            Some(packet) => {
                let m = RDPMessage{
                    from: senderv6,
                    packet: packet,
                };
                let pretty = PrettyConfig::new()
                    .with_separate_tuple_members(true)
                    .with_enumerate_arrays(true);
                println!("{}", to_string_pretty(&m, pretty)?);
            }
            None => {
                println!("unrecognized packet")
            }
        }
        count += 1;
        if w.count > 0 && count >= w.count {
            break;
        }
    }

    Ok(())

}
