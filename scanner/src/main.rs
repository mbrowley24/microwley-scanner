mod mbcap;

use libc::if_nametoindex;
use std::ffi::CString;




fn main() {



    fn get_interface_index(interface: &str) -> Option<u32> {
        let cstr = CString::new(interface).unwrap();
        let index = unsafe { if_nametoindex(cstr.as_ptr()) };
        if index == 0 {
            None // Interface not found
        } else {
            Some(index)
        }
    }

    let if_index = get_interface_index("enp1s0").expect("shit"); // Change this to your interface index (use `ip link` to find it)

    println!("this index of {}", if_index);


    println!("AF_XDP Packet Sniffer started...");
    // modules::socket::receive_packets(fd);
}
