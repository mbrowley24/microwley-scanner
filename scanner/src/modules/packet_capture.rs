use crate::modules::{
    menu::{self, previous_menu, parse_string_to_num_selection_u16, parse_string_to_num_u32},
    filter::{self, Filter},
    interface::{
        self,
        Interface
    },
};
use::pnet::datalink::NetworkInterface;

use std::io::{self, Write};

use super::menu::clear_terminal;



pub fn packet_capture(menu: &mut String){

    //Pakcet capture main menu returns and interface
    let iface: Option<NetworkInterface> = packet_capture_menu(menu);



    let traffic_filter  = filter::filter_menu();

    println!("up till here");

    //menu.clear();
    //menu.push_str("0");


    

    
    
}

pub fn packet_capture_menu(menu : &mut String) -> Option<NetworkInterface>{

    //get Vec of interfaces on the systems
    let interfaces: Vec<NetworkInterface> = interface::get_interfaces();
    

    //index of the interface in the network interfaces vector
    let mut iface_idx: usize = 1;

    

    //user input value
    let mut capture_opt = String::new();
    
    
    //loop through options and user input. This function will provide feedback to the user
    //if there are input issues
    packet_capture_menu_loop(&mut capture_opt, &interfaces, menu, &mut iface_idx);

    //returns the interface
    interface::iface_opt(interfaces, iface_idx)
    
}



//loop through options and user input. This function will provide feedback to the user
//if there are input issues
fn packet_capture_menu_loop(capture_opt: &mut String,
                            interfaces : &Vec<NetworkInterface>,
                            menu: &mut String, 
                            iface_idx : &mut usize){
    
    let interface_opt: Vec<String> = interface::interface_menu_opt(interfaces);    
    let mut invalid_char: bool = false;
        
    loop{

        //check if user wants to return to previouos menu
        previous_menu(&capture_opt, menu); 
        
        interface::interface_menu(&interface_opt, 
                                                capture_opt,
                                               &invalid_char);
        
                
        //validate user input
        //user input must be a digit 
        menu::input_validation_digit(capture_opt, &mut invalid_char);                          
        
        

        if invalid_char == true{
            capture_opt.clear();
            //eprintln!("Please make a valid input");
            clear_terminal();
            continue;
        }

        //convert capture_opt into an u32 iace_idx if there is an error change invalid_char to true
         

        if invalid_char == true{
            capture_opt.clear();
            clear_terminal();
            continue;
        }

        //check if the an interace exsists for the value the user provided
        let iface_valid: bool  = interface::check_iface_idx_valid(&interfaces, &iface_idx); 
        
        if iface_valid == false {
            eprintln!("Invalid index entered");
            invalid_char  = true;
            capture_opt.clear();
            clear_terminal();
            continue;
        
        }else{
            break;
        }
        
    }
}