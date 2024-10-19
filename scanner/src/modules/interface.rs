use crate::modules::{
    filter::Filter as packet_filter,
    export_to_file::ExportToTextFile,
};

use crate::menu::{
  clear_terminal,
  crusor_to_top_left,
  input_validation_digit,
  parse_string_to_num_u32,  
  previous_menu,
  spacer_size,
  time_now,
};
use pnet::{
    datalink::{self, Channel::Ethernet as CEthernet, DataLinkReceiver, DataLinkSender, MacAddr, NetworkInterface
    },
    ipnetwork::IpNetwork, 
    packet::{
        self,
        ethernet::{EtherTypes, EthernetPacket},
        ip::{self, IpNextHeaderProtocols},
        ipv4::{self, Ipv4Packet}, 
        ipv6::{self, Ipv6Packet}, 
        tcp::TcpPacket, 
        udp::UdpPacket, Packet,
    }
};

use std::io::{
        self,
        Write
    };


use regex::Regex;



// use super::filter;

pub struct Interface{
    iface : NetworkInterface,
    rx : Box<dyn DataLinkReceiver>,
    tx: Box<dyn DataLinkSender>,
}


impl Interface{
    
    pub fn new(iface : NetworkInterface) -> Self{

          let (tx,rx) = match datalink::channel(&iface, Default::default()){

            Ok(CEthernet(tx, rx)) => (tx, rx), 
            Ok(_) => panic!("unhandled channel"),
            Err(e) => panic!("failed to create channel: {:?}", e)
        }; 

        

        Self{
             iface,
             rx,
             tx
             }
    }


    pub fn capture(&mut self, packet_filter : &mut packet_filter){


        loop{
            
            match self.rx.next(){
                
                Ok(packet) =>{
                
                    packet_filter.capture_flow(packet);
                    
                }

                Err(e) => eprintln!("Failed to capture packets: {}", e)
            }     

        }
    }
}





//Interface functions
pub fn interface_menu(menu : &mut String,
                      stdin : &mut io::Stdin,
                      stdout : &mut io::Stdout) -> Option<Interface>{

    let interfaces: Vec<NetworkInterface> = get_interfaces();
    
    let interface_opt: Vec<String> = interface_menu_opt(&interfaces);    
    
    let mut is_valid: bool = false;

    let mut option: String = String::new();

    let mut idx : usize = 0;

    loop{

        
        interface_menu_text(&interface_opt, &mut option, &is_valid, stdin, stdout);

        //check if user wants to return to previouos menu
        previous_menu(&option, menu); 
    

        //validate user input
        // must be a digit
        input_validation_digit(&option, &mut is_valid);                          
        
        

        if is_valid == false{
            option.clear();
            //eprintln!("Please make a valid input");
            clear_terminal();
            continue;
        }

        //convert string to usize for interface index
        idx  = parse_string_to_num_u32(&option) as usize;


        //check if the interface exists for the value the user provided
        let iface_valid: bool  = check_iface_idx_valid(&interfaces, &idx); 
        
        if iface_valid == false {
            eprintln!("Invalid index entered");
            is_valid  = false;
            option.clear();
            clear_terminal();
            continue;
        
        }else{
            break;
        }
        
    }
    
    match iface_opt(interfaces, idx){

        Some(net_iface) => Some(Interface::new(net_iface)),

        None => None 
    }

}

pub fn interface_menu_text(interfaces : &Vec<String>,
                                input: &mut String,
                                invalid_char : &bool,
                                stdin : &mut io::Stdin,
                                stdout : &mut io::Stdout){

    let mut propmt: String = String::new();
    propmt.clear();
    propmt.push_str(format!("{}Microwley-scanner: Packet Capture\n",
                                spacer_size(25)).as_str());

    propmt.push_str(format!("{}---------------------------------\n\n",
                            spacer_size(25)).as_str());

    propmt.push_str(format!("Index{}Name{}MAC Addr{}Active{}IPv4{}IPv6 -> Link-Local\n",
        spacer_size(8), spacer_size(15), spacer_size(6),
        spacer_size(5), spacer_size(10)
    ).as_str());

    propmt
        .push_str("----------------------------------------------------------------------------------------------\n");

    for iface in interfaces.iter(){
        propmt.push_str(format!("{}\n", iface).as_str());
        propmt.push_str("----------------------------------------------------------------------------------------------\n\n");
    }
    propmt.push_str("E-> Back to main menu\n\n");


    if *invalid_char{
        propmt.push_str("Please choose a valid Index\n\n");
    }

    propmt.push_str("Enter a Valid Index -> ");

    write!(stdout, "{}", propmt).expect("Failed to write to stdout");

    stdout.flush().unwrap();

    stdin.read_line(input)
    .expect("Error reading input");

    clear_terminal();
    
}


pub fn convert_interface_idx_input(input : &str, idx : &mut usize, is_valid : &mut bool){

    let value = parse_string_to_num_u32(input);

    if value == 0 {
        *is_valid = false;
    
    }else{

        *is_valid = true;
    }

    *idx = value as usize;

}


//Get network interfaces for system
pub fn get_interfaces() -> Vec<NetworkInterface>{

    datalink::interfaces()

}

//interface data to string
pub fn interface_to_string(iface: &NetworkInterface) -> String{
    
    //mac address from interface
    let mac_add = iface.mac.unwrap_or_else(|| MacAddr::zero());
    
    //get interface index
    let index = iface.index;

    //get name for interface if name > 8 shorten name
    let name = get_of_iface_name(&iface.name);    

    //check if name is less than 8. If the name is less than 
    //8 all spaces to the name until it equals 8 spaces //space for name text
    let name_space = get_name_space(&iface.name);


    //status if is up change status to up for false down
    let status = get_interface_status(iface.is_up());

    //ipv4 and ipv6 address
    let ipv6  =  get_ipv6(&iface.ips);
    let ipv4 = get_ipv4(&iface.ips);

    format!("{space_1}{index}{space_2}|{space_3}{name}{name_space}{space_4}|{space_5}{mac}{space_6}|\
    {space_7}{status}{space_8}|{space_9}{ipv4}{space_10}|{space_11}{ipv6}",
            space_1 = spacer_size(3),
            index = index,
            space_2 = spacer_size(3),
            space_3 = spacer_size(5),
            name = name,
            name_space = name_space,
            space_4 = spacer_size(2),
            space_5 = spacer_size(2),
            mac = mac_add,
            space_6 = spacer_size(2),
            space_7 = spacer_size(2),
            status = status,
            space_8 = spacer_size(2),
            space_9 = spacer_size(2),
            ipv4=ipv4,
            space_10=spacer_size(3),
            space_11=spacer_size(3),
            ipv6=ipv6,
            )
}






//convert many interfaces data in to string for menu
pub fn interface_menu_opt(interfaces : &Vec<NetworkInterface>) -> Vec<String> {

    
    interfaces.into_iter().map(|iface|{
        interface_to_string(iface)
    }).collect()
    
}



//converts bool into UP and Down
fn get_interface_status(is_up : bool ) -> String{

    let mut status = String::new();

    if is_up == true{
        
        status = String::from("UP");
    
    }else{

        status = String::from("Down");

    }

    status

}


// Get first IPV4 address in the list of IPS attached to ther interface
fn get_ipv4(ip_networks : &Vec<IpNetwork>) -> String{

    let mut ipv4_network = String::new();

    for ip in  ip_networks{

        if ip.is_ipv6(){
            continue;
        }

        if ip.is_ipv4(){
            ipv4_network = ip.ip().to_string();
        }
    }

    ipv4_network
}

// Get IPv6 network link-local to loop back for an interface
fn get_ipv6(ip_networks : &Vec<IpNetwork>) -> String{

    let mut ipv6_network = String::new();

    for ip in ip_networks{

        if ip.is_ipv4(){
            continue;
        }

        let ipv6 = ip.ip().to_string();

        if ipv6.contains("fe80::"){

            ipv6_network = ipv6;  
            break;

        }else if ipv6.contains("::1"){

            ipv6_network = ipv6;
            break;
        }
    }

    ipv6_network
}

//get space for name if name is less than 8 character
fn get_name_space(name : &str) -> String{
    
    let mut spacer = String::new();

    if name.len() < 8 {

        for _ in name.len()..8{

            spacer.push_str(" ");

        }
    }    

    spacer
}


//check the length of interface name if name is longer than 8
//get a name if less than 8, if grater than 8 shorten name
fn get_of_iface_name(name: &str) -> String{
    
    let length = name.len();
    
    if length > 8{

        return name[..8].to_string();

    }else{

        return name.to_string();

    }

}











//check if the selected interface is valid. if iface_count is == 1 then idx is valid
//iface_count is less than one then there is no interface with the idx provided by the user
//if the iface_count is greater than one then there is an issue with the program
pub fn check_iface_idx_valid(interfaces : &Vec<NetworkInterface>, iface_idx : &usize) -> bool{

    //    
    let iface_count:usize = interfaces
                    .into_iter()
                    .filter(|net_iface| net_iface.index as usize == *iface_idx)
                    .count();    

    if iface_count  < 1 || iface_count > 1 {

        return false;
    }

    true

}

//get option form 
pub fn iface_opt(interfaces: Vec<NetworkInterface>, idx : usize) -> Option<NetworkInterface>{

    let mut iface_vec : Vec<NetworkInterface> = interfaces
                    .into_iter()
                    .filter(|net_iface|  net_iface.index as usize == idx)
                    .collect();

    
    if iface_vec.len() == 1 {

        return Some(iface_vec.remove(0))        
    
    }else{

        return None
    }

}





