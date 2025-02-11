use std::net::{Ipv4Addr, Ipv6Addr};
pub struct EthernetData {
    ethernet_frame : [u8],
}

impl EthernetData {

    pub fn new(packet : [u8]) -> Self{

        Self{
            ethernet_frame : packet,
        }
    }
    pub fn get_ethernet(&self) -> &[u8] {
        &self.ethernet_frame
    }

    pub fn get_packet(&self, packet : &[u8]) -> &[u8] {

    }

    pub fn get_ip_addresses(&self, ) -> Ipv4Addr {


    }


}