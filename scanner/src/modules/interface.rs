use crate::menu::{
  self,
  clear_terminal,
  parse_string_to_num_u32  
};
use pnet::{
    datalink::{self, 
        Channel::Ethernet as CEthernet,
        EtherType,
        MacAddr, 
        NetworkInterface,
        DataLinkReceiver,
        DataLinkSender,
    },
    ipnetwork::IpNetwork, 
    packet::{
        ip, ipv4::{self, Ipv4Packet}, ipv6::{self, Ipv6Packet}
    }
};

use std::{
    io::{self, Write},
    num::ParseIntError
};
use regex::Regex;



use super::filter;

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
            Err(e) => panic!("failed to create channel: {}", e)
        }; 

        

        Self{
             iface,
             rx,
             tx
             }
    }


    pub fn capture(&mut self, filter : filter::Filter){
        
        loop{

            match self.rx.next(){
                
                Ok(packet) =>{

                    if let Some (eth_packet) = filter.layer2_protocol(packet){

                    }

                    
                }

                Err(e) => eprintln!("Failed to capture packets: {}", e),
            }     


        }
    }
}




//Interface functions


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
    let mac_add = match iface.mac{

        Some(mac) => mac,
        None => MacAddr::zero(),
    };  
    
    //get interface index
    let index = iface.index;

    //get name for interface if name if name > 8 shorten name
    let name = get_of_iface_name(&iface.name);    

    //check if name is less than 8. If the name is less than 
    //8 all spaces to the name until it equals 8 spaces //space for name text
    let spacer = get_name_space(&iface.name);


    //status if is up change status to up for false down
    let status = get_interface_status(iface.is_up());

    //ipv4 and ipv6 address
    let ipv6  =  get_ipv6(&iface.ips);
    let ipv4 = get_ipv4(&iface.ips);

    format!("  {index}  |  {name} {spacer} | {mac} |  {status}  |   {ipv4}  |  {ipv6}", name = name, spacer= spacer, status = status, mac = mac_add, ipv4=ipv4, ipv6=ipv6)   
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







pub fn interface_menu(interfaces : &Vec<String>,
                                input: &mut String,
                                invalid_char : &bool){

    println!("                        Microwley-scanner: Packet Capture");
    println!("                        ---------------------------------");
    println!("");
    println!("Index   Name        MAC Addr           Active    IPv4         IPv6 -> Link-Local");
    println!("----------------------------------------------------------------------------------------------");
    for iface in interfaces.iter(){
        println!("{}", iface);
        println!("----------------------------------------------------------------------------------------------")
    }
    println!("");
    println!("E-> Back to main menu");
    println!("");
    if *invalid_char{
        println!("Please choose a valid Index");
        println!("");
    }
    print!("Enter a valid index ->");
    io::stdout().flush().unwrap();
    io::stdin().read_line(input)
    .expect("Error reading input");

    clear_terminal();
    
}




//check if the selected interface is valid. if iface_count is == 1 then idx is valid
//ifcae_count is less than one then there is no interface with the idx provided by the user
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





