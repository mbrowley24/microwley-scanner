
use super::socket;








pub fn start_capture_process(){

}


pub fn raw_byte_steam(byte_stream: &[u8]){

    if byte_stream.len() < 14 {
        println!("Segment too short");
        return;
    }

    // let frame = data_type::Frame::new(byte_stream);
    //
    // let (dest_mac, src_mac) = frame.mac_addresses();
    //
    // let packet = data_type::Packet::new(byte_stream);
    // let (src_ip, dst_ip) = packet.ip_v4();
    //
    // println!("🔹 Destination MAC: {:02x?}", dest_mac);
    // println!("🔹 Source MAC: {:02x?}", src_mac);
    // println!(" Source IP: {:?}", src_ip);
    // println!(" Destination MAC: {:?}", dst_ip);





    // println!("{:?}", &segment[0..6]);
    // // **LAYER 2: Ethernet Header**
    // let dest_mac : [u8; 6] = segment[0..6];
    // let src_mac = segment[6..12];
    // let ether_type = u16::from_be_bytes([segment[12], segment[13]]);
    //
    // println!("🔹 Layer 2 - Ethernet");
    // // println!("   📡 Destination MAC: {}", mac_address_formatter(dest_mac));
    // // println!("   🎯 Source MAC: {}", mac_address_formatter(src_mac));
    // println!("   🔗 EtherType: {:#06x}", ether_type);
    // println!("read {:?} segment", ether_type);
    // let src_port = u16::from_be_bytes([segment[0], segment[1]]);
    // let dst_port = u16::from_be_bytes([segment[2], segment[3]]);
    // let seq_num = u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]);
    // let ack_num = u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]);
    //

    // println!("🔹 Source Port: {}", src_port);
    // println!("🔹 Destination Port: {}", dst_port);
    // println!("📌 Sequence Number: {}", seq_num);
    // println!("📌 Acknowledgment Number: {}", ack_num);
}