use crate::modules::{
    menu::{self, previous_menu, parse_string_to_num_selection_u16, parse_string_to_num_u32},
    filter::{self, Filter},
    interface::{
        self,
        Interface
    },
};
use::pnet::datalink::NetworkInterface;




pub fn packet_capture(menu: &mut String){

    //Pakcet capture main menu returns and interface
    let iface_option: Option<Interface> = interface::interface_menu(menu);

    let mut traffic_filter = Filter::new();

    traffic_filter.filter_ip_version_menu();

    traffic_filter.source_ip_menu();


   

    println!("up till here");

    
    match iface_option  {
        
        Some(mut iface) => {

            iface.capture(traffic_filter);
        }

        None =>{

        }        

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