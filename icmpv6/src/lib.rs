// Copyright 2021 Oxide Computer Company

use std::net::Ipv6Addr;
use std::convert::TryInto;
use std::mem::size_of;
use serde::{Serialize, Deserialize};
use schemars::JsonSchema;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
pub struct RDPMessage {
    pub from: Option<Ipv6Addr>,
    pub packet: ICMPv6Packet,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct ICMPv6Header {
    pub typ: ICMPv6Type,
    pub code: u8,
    pub checksum: u16,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, JsonSchema, PartialEq)]
#[repr(u8)]
pub enum ICMPv6Type {
    Reserved = 0,
    DestinationUnreachable = 1,
    PacketTooBig = 2,
    TimeExceeded = 3,
    ParameterProblem = 4,
    Unassigned5x99 = 5,
    PrivateExperimentation100 = 100,
    PrivateExperimentation101 = 101,
    Unassigned102x126 = 102,
    ReservedForExpansionOfICMPv6ErrorMessages = 127,
    EchoRequest = 128,
    EchoReply = 129,
    MulticastListenerQuery = 130,
    MulticastListenerReport = 131,
    MulticastListenerDone = 132,
    RouterSolicitation = 133,
    RouterAdvertisement = 134,
    NeighborSolicitation = 135,
    NeighborAdvertisement = 136,
    RedirectMessage = 137,
    RouterRenumbering = 138,
    ICMPNodeInformationQuery = 139,
    ICMPNodeInformationResponse = 140,
    InverseNeighborDiscoverySolicitationMessage = 141,
    InverseNeighborDiscoveryAdvertisementMessage = 142,
    Version2MulticastListenerReport = 143,
    HomeAgentAddressDiscoveryRequestMessage = 144,
    HomeAgentAddressDiscoveryReplyMessage = 145,
    MobilePrefixSolicitation = 146,
    MobilePrefixAdvertisement = 147,
    CertificationPathSolicitationMessage = 148,
    CertificationPathAdvertisementMessage = 149,
    ICMPMessagesUtilizedByExperimentalMobilityProtocols = 150,
    MulticastRouterAdvertisement = 151,
    MulticastRouterSolicitation = 152,
    MulticastRouterTermination = 153,
    FMIPv6Messages = 154,
    RPLControlMessage = 155,
    ILNPv6LocatorUpdateMessage = 156,
    DuplicateAddressRequest = 157,
    DuplicateAddressConfirmation = 158,
    MPLControlMessage = 159,
    ExtendedEchoRequest = 160,
    ExtendedEchoReply = 161,
    Unassigned162x199 = 162,
    PrivateExperimentation200 = 200,
    PrivateExperimentation201 = 201,
    ReservedForExpansionOfICMPv6InformationalMessages = 255,
}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[repr(u8)]
pub enum NDPOptionType {
    SourceLinkLayerAddress = 1,
    TargetLinkLayerAddress = 2,
    PrefixInformation = 3,
    RedirectHeader = 4,
    MTU = 5,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[repr(C)]
pub struct RouterSolicitation {
    pub icmpv6_header: ICMPv6Header,
    pub reserved: u32,
    pub source_address: Option<Ipv6Addr>,
}

impl RouterSolicitation {

    pub fn new(src: Option<Ipv6Addr>) -> Self {

        RouterSolicitation {
            icmpv6_header: ICMPv6Header{
                typ: ICMPv6Type::RouterSolicitation,
                code: 0,
                checksum: 0,
            },
            reserved: 0,
            source_address: src,
        }

    }

    pub fn wire(&self) -> Vec<u8> {
        let mut v = vec!(
            self.icmpv6_header.typ as u8, 
            self.icmpv6_header.code,
            (self.icmpv6_header.checksum & 0x0f) as u8,
            (self.icmpv6_header.checksum & 0xf0) as u8,
            0,0,0,0, //reserved
        );

        match self.source_address {
            Some(addr) => {
                let sz = size_of::<NDPOptionType>()+size_of::<Ipv6Addr>();
                v.push(NDPOptionType::SourceLinkLayerAddress as u8);
                v.push(sz as u8);
                v.extend_from_slice(&addr.octets());
            },
            None => {},
        }

        v
    }

}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct RouterAdvertisement {
    pub icmpv6_header: ICMPv6Header,
    pub hop_limit: u8,
    pub managed_address: bool,
    pub other_stateful: bool,
    pub router_lifetime: u16,
    pub reachable_time: u32,
    pub retransmission_timer: u32,
    pub source_address: Option<Ipv6Addr>,
    pub mtu: Option<u16>,
    pub prefix_info: Option<PrefixInfo>,
}

impl RouterAdvertisement {

    pub fn new(
        hop_limit: u8,
        managed_address: bool,
        other_stateful: bool,
        router_lifetime: u16,
        reachable_time: u32,
        retransmission_timer: u32,
        src: Option<Ipv6Addr>,
        mtu: Option<u16>,
        prefix_info: Option<PrefixInfo>,
    ) -> Self {

        RouterAdvertisement{
            icmpv6_header: ICMPv6Header{
                typ: ICMPv6Type::RouterAdvertisement,
                code: 0,
                checksum: 0,
            },
            hop_limit,
            managed_address,
            other_stateful,
            router_lifetime,
            reachable_time,
            retransmission_timer,
            source_address: src,
            mtu,
            prefix_info
        }
    }

    pub fn wire(&self) -> Vec<u8> {
        let mut v = vec!(
            self.icmpv6_header.typ as u8, 
            self.icmpv6_header.code,
            (self.icmpv6_header.checksum & 0x0f) as u8,
            (self.icmpv6_header.checksum & 0xf0) as u8,
            self.hop_limit,
        );

        let mut mo : u8 = 0b00000000;
        if self.managed_address {
            mo |= 0b10000000
        }
        if self.other_stateful {
            mo |= 0b01000000
        }
        v.push(mo);

        v.extend_from_slice(&self.router_lifetime.to_be_bytes());
        v.extend_from_slice(&self.reachable_time.to_be_bytes());
        v.extend_from_slice(&self.retransmission_timer.to_be_bytes());

        match self.source_address {
            Some(addr) => {
                let sz = size_of::<NDPOptionType>()+size_of::<Ipv6Addr>();
                v.push(NDPOptionType::SourceLinkLayerAddress as u8);
                v.push(sz as u8);
                v.extend_from_slice(&addr.octets());
            },
            None => {},
        }

        match self.mtu {
            Some(mtu) => {
                let sz = size_of::<NDPOptionType>()+size_of::<u16>();
                v.push(NDPOptionType::MTU as u8);
                v.push(sz as u8);
                v.extend_from_slice(&mtu.to_be_bytes());
            },
            None => {},
        }

        //TODO prefix info

        v
    }

}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct PrefixInfo {
    pub length: u8,
    pub on_link: bool,
    pub autonomous: bool,
    pub valid_lifetime: u32,
    pub preferred_lifetime: u32,
    //pub prefix: [u8; 128], TODO serializable

}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum ICMPv6Packet {
    RouterSolicitation(RouterSolicitation),
    RouterAdvertisement(RouterAdvertisement),
}

impl ICMPv6Packet {
    pub fn wire(&self) -> Vec<u8> {
        match self {
            Self::RouterSolicitation(rs) => rs.wire(),
            Self::RouterAdvertisement(ra) => ra.wire(),
        }
    }
}

pub fn parse_icmpv6(buf: &[u8]) -> Option<ICMPv6Packet> {

    if buf.len() < 4 {
        return None
    }

    match buf[0] {

        133 => Some(ICMPv6Packet::RouterSolicitation(
                RouterSolicitation{
                    icmpv6_header: ICMPv6Header{
                        typ: ICMPv6Type::RouterSolicitation,
                        code: buf[1],
                        checksum: u16::from_be_bytes(buf[2..4]
                            .try_into()
                            .expect("slice into buf")
                        ),
                    },
                    reserved: 0,
                    source_address: None, //TODO
                })
        ),

        134 => Some(ICMPv6Packet::RouterAdvertisement(
                RouterAdvertisement{
                    icmpv6_header: ICMPv6Header{
                        typ: ICMPv6Type::RouterAdvertisement,
                        code: buf[1],
                        checksum: u16::from_be_bytes(buf[2..4]
                            .try_into()
                            .expect("slice into buf")
                        ),
                    },
                    hop_limit: buf[4],
                    managed_address: 0b10000000&buf[5] != 0,
                    other_stateful: 0b01000000&buf[5] != 0,
                    router_lifetime: u16::from_be_bytes(buf[6..8]
                        .try_into()
                        .expect("slice into buf")
                    ),
                    reachable_time: u32::from_be_bytes(buf[8..12]
                        .try_into()
                        .expect("slice into buf")
                    ), 
                    retransmission_timer: u32::from_be_bytes(buf[12..16]
                        .try_into()
                        .expect("slice into buf")
                    ), 
                    source_address: None, //TODO
                    mtu: None, //TODO
                    prefix_info: None, //TODO
                })
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
