use crate::modules::{
    menu::{self, previous_menu, parse_string_to_num_selection_u16, parse_string_to_num_u32},
    filter::{self, Filter},
    interface::{
        self,
        Interface
    },
};
use::pnet::datalink::NetworkInterface;
use::std::io::{
    self,
    Write,
};




pub fn packet_capture(menu: &mut String){

    let mut  stdin = io::stdin();

    //Packet capture main menu returns and interface
    let iface_option: Option<Interface> = interface::interface_menu(menu);

    let mut traffic_filter = Filter::new();

    traffic_filter.filter_menu();

    if let Some(mut iface) = iface_option  {

        iface.capture(traffic_filter);

    }

    //menu.clear();
    //menu.push_str("0");


    

    
    
}




//loop through options and user input. This function will provide feedback to the user
//if there are input issues
fn packet_capture_menu_loop(capture_opt: &mut String,
                            interfaces : &Vec<NetworkInterface>,
                            menu: &mut String, 
                            iface_idx : &mut usize){
    
    
}