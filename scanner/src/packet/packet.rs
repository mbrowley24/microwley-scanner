use pnet::
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        icmp::IcmpPacket,
        icmpv6::Icmpv6Packet,
        ipv4::{self, Ipv4Packet},
        ipv6::{self, Ipv6Packet},
        Packet,
        tcp::TcpPacket,
        udp::UdpPacket,
    };


pub struct Packet{
    pub protocol : EtherType,
    pub layer_2 : EthernetPacket,
    pub ipv4: Option<Ipv4Packet>,
    pub ipv6: Option<Ipv6Packet>,
    pub tcp: Optional<TcpPacket>,
    pub udp: Optional<UdpPacket>,
    pub icmpv4 : Optional<IcmpPacket>,
    pub icmpv6 : Optional<Icmpv6Packet>,
}


impl Packet {
    //new packet 
    pub fn new() -> Self{

        Self
    }

    //setters
    pub fn set_protocol(&mut self, protocol: EtherType){
        self.protocol = protocol;
    }

    pub fn set_layer_2(&mut self, ethernet : EthernetPacket){
        self.layer_2 = EthernetPacket;
    }

    pub fn set_ipv4(&mut self, ipv4: Ipv4Packet) {
        self.ipv4 = Some(ipv4);
        self.ipv6 = None;
    }

    pub fn set_ipv6(&mut self, ipv6 :Ipv6Packet){
        self.ipv6 = Some(ipv6);
        self.ipv4 = None;
    }

    pub fn set_tcp(&mut self, tcp: TcpPacket){
        self.tcp = Some(tcp);
        self.udp = None;
        self.icmp = None;
    }   

    pub fn set_udp(&mut self, udp: UdpPacket){
        self.udp = udp;
        self.tcp = None;
        self.icmp = None;
    }

    pub fn icmpv4(&mut self, icmp : IcmpPacket){
        self.icmpv4 = icmp;
        self.tcp = None;
        self.udp = None;
        self.icmpv6 = None;
    }

    pub fn icmpv6(&mut self, icmp : Icmpv6Packet){
        self.icmpv6 = Some(icmp);
        self.tcp = None;
        self.udp = None;
        self.icmpv4 = None;
    }
}