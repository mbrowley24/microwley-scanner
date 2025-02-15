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




fn mac_address_formatter(mac_address : &[u8]) -> String{

      mac_address.iter()
          .map(|x| format!("{:02x}", x))
          .collect::<Vec<String>>()
          .join(":")
}

//bind socket to interface
unsafe fn addr_struct(iface_idx: i32) -> sockaddr_ll{

      // Bind socket to the chosen interface
      let mut addr: sockaddr_ll = mem::zeroed();

      addr.sll_family = AF_PACKET as u16;

      addr.sll_protocol = (ETH_P_ALL as u16).to_be();

      //replace with an input
      addr.sll_ifindex = iface_idx;

      addr
}


unsafe fn bind_socket_to_interface(socket: c_int, addr : sockaddr_ll){

      if bind(socket, &addr as *const _ as *const _, mem::size_of::<sockaddr_ll>() as u32) < 0 {

            panic!("Failed to bind socket to interface");

      }
}

unsafe fn new_socket() -> Some(c_int){

      let sock = socket(AF_PACKET, SOCK_RAW, (ETH_P_ALL as u16).to_be() as c_int);

      if sock < 0 {

            return None

      }

      Some(sock)

}

pub fn start_sniffer() -> io::Result<()> {

      unsafe {

            // Create raw socket

            if let Some(sock) = new_socket() {

                  // Get interface index and bind to socket
                  let iface_index = get_interface_index(sock, INTERFACE_NAME)?;


                  println!("Using interface: {} (index: {})", INTERFACE_NAME, iface_index);

                  // Bind socket to the chosen interface
                  let addr = addr_struct(iface_index);






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

                              raw_byte_steam(&buffer[..received as usize]);

                        }

                  }

            }else{
                  println!("Using null socket");
                  Err("error").expect("TODO: panic message")
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

