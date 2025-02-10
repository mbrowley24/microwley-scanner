use std::ffi::CString;

use std::io;

use std::mem;

use std::os::raw::*;

use std::ptr;



use libc::{

      bind, c_void, ifreq, ioctl, recvfrom, sockaddr_ll, socket, AF_PACKET, ETH_P_ALL, IFNAMSIZ,

      SIOCGIFINDEX, SOCK_RAW,

};



/// Specify the network interface manually (e.g., "eth0" or "wlan0")

const INTERFACE_NAME: &str = "enp1s0"; // Change to your desired interface


fn decode_tcp_segment(segment: &[u8]){

      if segment.len() < 20 {
            println!("Segment too short");
            return;
      }

      let src_port = u16::from_be_bytes([segment[0], segment[1]]);
      let dst_port = u16::from_be_bytes([segment[2], segment[3]]);
      let seq_num = u32::from_be_bytes([segment[4], segment[5], segment[6], segment[7]]);
      let ack_num = u32::from_be_bytes([segment[8], segment[9], segment[10], segment[11]]);

      println!("🔹 Source Port: {}", src_port);
      println!("🔹 Destination Port: {}", dst_port);
      println!("📌 Sequence Number: {}", seq_num);
      println!("📌 Acknowledgment Number: {}", ack_num);
}


pub fn start_sniffer() -> io::Result<()> {

      unsafe {

            // Create raw socket

            let sock = socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as c_int);

            if sock < 0 {

                  panic!("Failed to create raw socket");

                }



            // Get interface index

            let iface_index = get_interface_index(sock, INTERFACE_NAME)?;

            println!("Using interface: {} (index: {})", INTERFACE_NAME, iface_index);



            // Bind socket to the chosen interface

            let mut addr: sockaddr_ll = mem::zeroed();

            addr.sll_family = AF_PACKET as u16;

            addr.sll_protocol = (ETH_P_ALL as u16).to_be();

            addr.sll_ifindex = iface_index as i32;



            if bind(sock, &addr as *const _ as *const _, mem::size_of::<sockaddr_ll>() as u32) < 0 {

                  panic!("Failed to bind socket to interface");

                }



            println!("Listening on {}", INTERFACE_NAME);



            // Packet buffer

            let mut buffer = [0u8; 65535];

            let mut addr_len = mem::size_of::<sockaddr_ll>() as u32;



            loop {

                  let received = recvfrom(

                        sock,

                        buffer.as_mut_ptr() as *mut c_void,

                        buffer.len(),

                        0,

                        &mut addr as *mut _ as *mut _,

                        &mut addr_len,

                      );



                  if received > 0 {

                        println!("Captured packet: {} bytes", received);

                        decode_tcp_segment(&buffer[..received as usize]);
                        //print_packet(&buffer[..received as usize]);

                      }

                }

          }

}



/// Retrieves the index of a network interface by name

fn get_interface_index(sock: c_int, interface_name: &str) -> io::Result<i32> {

      let mut ifr: ifreq = unsafe { mem::zeroed() };

      let iface_cstr = CString::new(interface_name).unwrap();



      unsafe {

            ptr::copy_nonoverlapping(iface_cstr.as_ptr(), ifr.ifr_name.as_mut_ptr(), IFNAMSIZ);

            if ioctl(sock, SIOCGIFINDEX, &mut ifr) < 0 {

                  panic!("Failed to get interface index for {}", interface_name);

                }

          }



      Ok(unsafe { ifr.ifr_ifru.ifru_ifindex })

}



fn print_packet(data: &[u8]) {

      print!("Packet Data: ");

      for byte in data.iter().take(64) {

            print!("{:02X} ", byte);

          }

      println!();

}

