mod modules;

use modules::menu;
use pnet::{
    datalink::{self, Channel::Ethernet, EtherType, MacAddr},
    packet::{
        ethernet::{EtherTypes, EthernetPacket},
        icmp::{IcmpPacket},
        icmpv6::{Icmpv6Packet},
        ipv4::{self, Ipv4Packet},
        ipv6::{self, Ipv6Packet},
        Packet,
        tcp::TcpPacket,
        udp::UdpPacket,
    },
};




fn main() {

    menu::master_menu();
    // println!("{}", input);
    // let network_interfaces = get_interfaces();

    // let mut interface_list: Vec<String> = Vec::new();    

    // for iface in network_interfaces{

    //     println!("{:?}", iface);
    // }

//     let interfaces = datalink::interfaces();
// //     println!("{}", interfaces.len());
// //     // println!("{:#?}", interfaces);
//     let interface = interfaces.into_iter()
//     .filter(|iface| iface.is_up() && !iface.is_loopback() && iface.ips.len() > 0)
//     .next()
//     .expect("no suitable interfaces found");

// //     println!("interface: {:#?}", interface.mac);

//    let (_, mut rx) = match datalink::channel(&interface, Default::default()){
//     Ok(Ethernet(tx, rx)) => (tx, rx),
//     Ok(_) => panic!("Unhanlded channlel type"),
//     Err(e) => panic!("failed to create channel: {}", e),
//    };


//    println!("captuing packets");

//    loop{
//     match rx.next(){
//         Ok(packet) =>{
            
//             //Layer 2
//             if let Some(eth_packet) = EthernetPacket::new(packet){
                
//                 println!("Packet");
//                 println!("Source MAC: {}", eth_packet.get_source());
//                 println!("Destination MAC: {} ", eth_packet.get_destination());
//                 println!("EtherType: {:?} ", eth_packet.get_ethertype());

//                 //layer 3
//                 if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
//                     if let Some(ipv4_packet) = Ipv4Packet::new(eth_packet.payload()){

//                         if let Some(icmp_v4) = IcmpPacket::new(ipv4_packet.payload()){

//                             println!("icmp: {:#?}", icmp_v4.get_icmp_code());
//                             println!("icmp type: {:#?}", icmp_v4.get_icmp_type());
//                         }

//                     }

//                 }
                
//             }
           

//             match TcpPacket::new(packet){

//                 Some(tcp_packet) =>{
//                     println!("Source port: {}", tcp_packet.get_source());
//                     println!("Destination post : {}", tcp_packet.get_destination());
//                     println!("Sequence number")
//                 },

//                 None => println!("no tcp info"),
//             }

//             match UdpPacket::new(packet){

//                 Some(udp_packet) =>{
//                     println!("Source port: {}", udp_packet.get_source());
//                     println!("Destination port: {}", udp_packet.get_destination());
//                     println!("Payload length: {}", udp_packet.get_length());
//                 }

//                 None => println!("no udp info")
//             }
//         }

//         Err(e) => eprintln!("Failed to capture packet: {}", e),
//     }
//    } 
}
