use std::net::{Ipv4Addr, Ipv6Addr};



pub struct Frame{
    dst_mac    : [u8; 6],
    src_mac    : [u8; 6],
    ether_type : u16,
}

pub struct Packet {
    version         : u8,
    type_of_service : u8,
    total_length    : u16,
    identification  : u16,
    flags_fragment  : u16,
    ttl             : u8,
    protocol        : u8,
    checksum        : u16,
    src_ip_address  : [u8; 4],
    dst_ip_address  : [u8; 4],
}



pub struct Segment {
    src_port    : u16,
    dst_port    : u16,
    seq_num     : u32,
    ack_num     : u32,
    flags       : u16,
    window_size : u16,
    checksum    : u16,
    urgent_ptr  : u16,
}

pub fn mac_address_formatter(mac_address : &[u8]) -> String{

    mac_address.iter()
        .map(|x| format!("{:02x}", x))
        .collect::<Vec<String>>()
        .join(":")
}

impl Frame{
    pub fn new(frame : &[u8]) -> Self{



        Self {
            dst_mac    : frame[0..4].try_into().unwrap_or([0; 6]),
            src_mac    : frame[6..12].try_into().unwrap_or([0; 6]),
            ether_type : u16::from_be_bytes(frame[12..14].try_into().unwrap_or([0;2])),
        }
    }

    pub fn mac_addresses(&self) -> (String, String) {

        let dst = self.dst_mac
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<Vec<String>>()
            .join(":");

        let src = self.src_mac
            .iter()
            .map(|x| format!("{:02x}", x))
            .collect::<Vec<String>>()
            .join(":");

        (dst, src)
    }

    pub fn is_ipv4(&self) -> bool{

        match self.ether_type >> 4{
            4 => true,
            _ => false
        }
    }
}

impl Packet{
    pub fn new(frame : &[u8]) -> Self{

        Self{
            version         : frame[14],
            type_of_service : frame[15],

            total_length    : u16::from_be_bytes(frame[16..=17]
                                .try_into()
                                .unwrap_or([0; 2])
            ),

            identification  : u16::from_be_bytes(
                                    frame[18..=19]
                                        .try_into()
                                        .unwrap_or([0; 2])
            ),

            flags_fragment  : u16::from_be_bytes(
                                    frame[20..=21]
                                        .try_into()
                                        .unwrap_or([0; 2])
            ),

            ttl             : frame[22],
            protocol        : frame[23],
            checksum        : u16::from_be_bytes(
                                    frame[24..=25]
                                        .try_into()
                                        .unwrap_or([0; 2])
            ),

            src_ip_address  : frame[26..=29].try_into().unwrap_or([0; 4]),
            dst_ip_address  : frame[30..=33].try_into().unwrap_or([0; 4]),
        }
    }

    pub fn ip_v4(&self) -> (Ipv4Addr, Ipv4Addr){

        // println!("in here")
        // println!("{:#?}", self.src_ip_address);
        // println!("{:#?}", self.dst_ip_address);

        return (Ipv4Addr::new(self.src_ip_address[0],
                              self.src_ip_address[1],
                              self.src_ip_address[2],
                              self.src_ip_address[3]),

                Ipv4Addr::new(self.dst_ip_address[0],
                              self.dst_ip_address[1],
                              self.dst_ip_address[2],
                              self.dst_ip_address[3])
        )
    }


}

// impl Segment{
//
//     pub fn new(frame : &[u8]) -> Self {
//
//         Self{
//
//         }
//     }
// }