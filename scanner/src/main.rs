use pnet::{datalink::{self, Channel::Ethernet}, packet::ethernet::{EthernetPacket}};


fn main() {

    let interfaces = datalink::interfaces();
    println!("{}", interfaces.len());
    // println!("{:#?}", interfaces);
    let interface = interfaces.into_iter()
    .filter(|iface| iface.is_up() && !iface.is_loopback() && iface.ips.len() > 0)
    .next()
    .expect("no suitable interfaces found");

    println!("interface: {:#?}", interface);

   let (_, mut rx) = match datalink::channel(&interface, Default::default()){
    Ok(Ethernet(tx, rx)) => (tx, rx),
    Ok(_) => panic!("Unhanlded channlel type"),
    Err(e) => panic!("failed to create channel: {}", e),
   };


   println!("captuing packets");

//    loop{
//     match rx.next(){
//         Ok(packet) =>{
//             if let Some(eth_packet) = EthernetPacket::new(packet){

//                 println!("Packet");
//                 println!("Source MAC: {}", eth_packet.get_source());
//                 println!("Destination MAC: {} ", eth_packet.get_destination());
//                 println!("EtherType: {:?} ", eth_packet.get_ethertype());
//             }
//         }

//         Err(e) => eprintln!("Failed to capture packet: {}", e),
//     }
//    } 
}
