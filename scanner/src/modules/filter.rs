use crate::modules::menu::{clear_terminal, parse_string_to_num_selection_u16, user_input};
use pnet::{
    datalink::{self, Channel::Ethernet as CEthernet, DataLinkReceiver, DataLinkSender, EtherType, NetworkInterface
        
    },
    packet::{
        ethernet::{ 
            EtherTypes, 
            EthernetPacket
        }, 
        icmp::IcmpPacket,
        icmpv6::Icmpv6Packet, 
        ipv4::Ipv4Packet, 
        ipv6::Ipv6Packet, 
        tcp::TcpPacket, 
        udp::UdpPacket,
        Packet
    },
};
use regex::Regex;
use std::io::{stdin, stdout, Write};



pub struct Filter{
    source_ipv4 : String,
    destination_ipv4 : String,
    source_ipv6: String,
    destination_ipv6 : String,
    s_port : u16,
    d_port : u16,
    arp : bool,
    icmp : bool,
    icmpv6: bool,
    ipv4 : bool,
    ipv6 : bool,
    layer2 : bool,
    lldp : bool,
    p_bridge : bool,
    ptp : bool,
    q_n_q : bool,
    rarp : bool,
    tcp: bool,
    udp : bool,
    vlan : bool
}


impl Filter{

    //creates struct to gather key data for packet capture capabilities
    pub fn new() -> Self {
        

        Self{
            source_ipv4: String::new(),
            destination_ipv4: String::new(),
            source_ipv6 : String::new(),
            destination_ipv6 : String::new(),
            s_port : 0,
            d_port : 0,
            arp : false,
            icmp : false,
            icmpv6: false,
            ipv4 : false,
            ipv6 : false,
            layer2 : false,
            lldp : false,
            p_bridge : false,
            ptp : false,
            q_n_q : false,
            rarp : false,
            tcp: false,
            udp : false,
            vlan : false
        }
        
     
    }

    //set source port filter
    pub fn source_ip(&mut self, source_ip : String, ipv4 : &bool) {

        if *ipv4 == true{

            self.source_ipv4 = source_ip;
        
        }else{

            self.source_ipv6 = source_ip;

        }

        
                
    }

    //set destination port filter
    pub fn destination_ip(&mut self, destination_ip : String, ipv4 : &bool){

        if *ipv4 == true{

            self.destination_ipv4 = destination_ip;
        
        }else{

            self.destination_ipv6 = destination_ip;
        }        
    }

    //set source port filter
    pub fn s_port(&mut self, s_port : u16){
        
        self.s_port = s_port;
    }

    //set destination port 
    pub fn d_port(&mut self, d_port : u16){

        self.d_port = d_port;
    }

     //create ethernet packet option
    pub fn layer2_protocol<'a>(&'a self, packet : &'a [u8]) -> Option<EthernetPacket>{

        if self.layer2 {

            None

        
        }else{

            EthernetPacket::new(packet)
        }

    }
    

    //check for icmp protocol
    pub fn icmp_protocol<'a>(&'a mut self, packet : &'a [u8]) -> Option<IcmpPacket>{

        if self.icmp {

            None            

        }else{

            IcmpPacket::new(packet)

        }

                 
    }

    //check for layer 3 ipv4 traffic information
    pub fn ip_protocol<'a>(&'a mut self, packet : &'a [u8], is_ipv4 : &bool) -> Option<Ipv4Packet>{

        if self.ipv4{

            None            

        }else{

            Ipv4Packet::new(packet)

        }
        
                
    }


    //check for layer 3 ipv6 traffic
    pub fn ipv6_protocol<'a>(&'a mut self, packet : &'a [u8]) -> Option<Ipv6Packet>{

        if self.icmpv6{
        
            None
            
        
        }else{
        
            Ipv6Packet::new(packet)
        
        }
        
    }

    //check for tcp protocol
    pub fn tcp_protocol<'a>(&'a mut self, packet : &'a [u8]) -> Option<TcpPacket>{

        if self.tcp{
        
            None    
        
        }else{
            
           TcpPacket::new(packet)

        }
    }

    //check for UDP taffice
    pub fn udp_protocol<'a>(&'a mut self, packet : &'a [u8]) -> Option<UdpPacket>{

        if self.udp{

            None
        
        }else{
        
            UdpPacket::new(packet)
        }
    }    

} 
//Filter menu
pub fn filter_menu() -> Filter{

    //check if ip is IPv4 or ipv6
    let mut ipv4 = false;
    //source and destination ip fields can be version 4 or 6
    let source_ip : String;
    let destination_ip : String;

    //ask user to select ipv4 or ipv6
    filter_ip_version(&mut ipv4);

    if ipv4 == true {
        
        source_ip = filter_ip(true, true);
        destination_ip = filter_ip(true, false);
    
    }else{

        source_ip = filter_ip(false, true);
        destination_ip = filter_ip(false, false);

    }

    

     Filter::new()
}


fn filter_ip(ipv4 : bool, is_source : bool) -> String{
    
    let mut input = String::from("");
    let mut is_valid = true;
    
    
    loop{

        //present menu and take user input        
        filter_ip_input(&mut input, &is_valid, &is_source);    

        //if user input is blank capture all traffic
        if input.trim().len() == 0{
            
            break;
        }

        if ipv4 == true {

            //if input is greater than zero check id is valid 
            filter_regex_ipv4(&input, &mut is_valid);
        
        }else{

            filter_regex_ipv6(&input, &mut is_valid);

        }

        

        //if is valid is false then reset input continue loop
        if is_valid == false{
            input = String::new();
            clear_terminal();
            continue;
        
        }else{
            break;
        }           
    }


    if input.ends_with("\n"){
        _ = input.pop()
    }

    input

}

fn filter_ip_version(ipv4 : &mut bool){

    let mut input = String::new();
    let mut is_valid = true;

    
    loop{
        
        println!("Choose IP Version");
        println!("");
        println!("");
        if is_valid == false{
            println!("Choose option 1 or 2");
        }
        println!("1: IPv4");
        println!("2: IPv6");
        user_input(&mut input);
        
        if input == String::from("1") || input == String::from("2"){
 
            clear_terminal();
            break;
 
        }else{

            clear_terminal();
            is_valid = false;
            continue;
        }
    }
    
}

//user input menu and take user input
fn filter_ip_input(input : &mut String, is_valid : &bool, is_source : &bool){
        

        
        println!("Leave blank for all IPs");
        println!("");
        //takes input from the user
        user_input(input);
        if *is_valid == false{
            println!("Enter a valid IPv4 or IPv6 address");
            println!("");
        }
        if *is_source == true{

            print!("Source IP (all)-> ");
        
        }else{
            print!("Destination IP (all)-> ");
        }
        
        clear_terminal();
}

fn filter_port(input : &mut String, is_source : bool) -> u16{

    let mut is_valid = true;
    
    
    let mut port : u16;

    loop{
        println!("Leave blank for all ports");
        println!("");
        if is_valid == false{

            println!("Select valid port 1-65535");
            println!("")
        }
        if is_source{
        
            println!("Source port:")
        
        }else{
        
            println!("Destination port:")
        
        }        

        user_input(input);

        //convert user input to u32:        
        port = parse_string_to_num_selection_u16(input); 

        filter_port_check(&port, &mut is_valid);        
        
        if is_valid == true{
            
            clear_terminal();
            break;
            
        }else{
            
            clear_terminal();

            continue;
        }

    }

    port


}

fn filter_port_check(value : &u16, is_valid_ : &mut bool){

    if *value < 1 || *value > 65535{
  
        *is_valid_ = false;        
  
    }else{

        *is_valid_ = true;

    }


} 


fn filter_regex_ipv4(input : &String, is_valid : &mut bool){
    
    let ip_reg = Regex::new(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:))|(::([0-9a-fA-F]{1,4}:){0,6}([0-9a-fA-F]{1,4}))$").unwrap();
    
    if ip_reg.is_match(input.trim()){

        *is_valid = true;

    }else{

        *is_valid = false;

    }
}

fn filter_regex_ipv6(input : &String, is_valid : &mut bool){

    let ipv6_regex = r"^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){1,7}:)|(([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2})|(([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3})|(([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4})|(([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5})|([0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6}))|(:((:[0-9A-Fa-f]{1,4}){1,7}|:)))(%.+)?$";

    // Compile the regex
    let ip_reg = Regex::new(ipv6_regex).unwrap();

    if ip_reg.is_match(input.trim()){

        *is_valid = true;
    
    }else{

        *is_valid = false;

    }
}