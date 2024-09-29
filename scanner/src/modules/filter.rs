use std::f32::consts::E;

use crate::modules::menu::{
    clear_terminal,
    input_validation_digit,
    input_validation_digit_range,
    parse_string_to_num_u32, 
    parse_string_to_num_selection_u16, 
    user_input,
};
// use pnet::{
//     packet::{
//         ethernet::{ 
//             EtherTypes, 
//             EthernetPacket
//         }, 
//         icmp::IcmpPacket,
//         icmpv6::Icmpv6Packet, 
//         ipv4::Ipv4Packet, 
//         ipv6::Ipv6Packet, 
//         tcp::{ipv4_checksum, TcpPacket}, 
//         udp::UdpPacket,
//         Packet
//     },
// };
use regex::Regex;
// use std::io::{stdin, stdout, Write};



pub struct Filter{
    source_ipv4 : String,
    destination_ipv4 : String,
    source_ipv6: String,
    destination_ipv6 : String,
    s_port : u32,
    s_limit : u32,
    d_port : u32,
    d_limit: u32,
    arp : bool,
    icmp : bool,
    icmpv6: bool,
    pub ipv4 : bool,
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
            s_port : 66000,
            d_port : 66000,
            s_limit: 60000,
            d_limit :60000,
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

    //menus for the filter struct
    
    //Filter IP version
    pub fn filter_ip_version_menu(&mut self){

        let mut input = String::new();
        
        println!("Choose IP Version");
        println!("");
        println!("Press space or enter for both");
        println!("");
        println!("1: IPv4");
        println!("2: IPv6");
        

        user_input(&mut input);
        
        if input == String::from("1"){
            //ipv4 is the interesting traffic
            self.set_ipv4_filter();
        }else if input == String::from("2"){
            //ipv6 is the interesting traffic
            self.set_ipv6_filter();

        }else{

            self.reset_ip_filter();

        }
        
        clear_terminal();
    }


    fn reset_ip_filter(&mut self){

        self.ipv4 = false;
        self.ipv6 = false;
    }

    fn set_ipv4_filter(&mut self){

        self.ipv4 = false;
        self.ipv6 = true;

    }

    fn set_ipv6_filter(&mut self){

        self.ipv4 = true;
        self.ipv6 = false;

    }


    //set source port filter
    fn set_source_ipv4(&mut self, source_ip : String) {

        self.source_ipv4 = source_ip.trim().to_string();        
                
    }

    pub fn source_ip_menu(&mut self){

        if self.ipv4 == false  && self.ipv6 == true{

            self.source_ipv4_menu();
            self.destination_ipv4_menu();

        }else if self.ipv4 == true && self.ipv6 == false{

            self.source_ipv6_menu();
            self.destination_ipv6_menu();

        }else{

            self.source_ipv4_menu();
            self.destination_ipv4_menu();

            self.source_ipv6_menu();
            self.destination_ipv6_menu();
        } 
    }

    pub fn source_ipv4_menu(&mut self){

        let mut input : String= String::new();
        let mut is_valid: bool = true;

        loop{
            println!("Leave blank for all IPs"); 
            println!("");            
            print!("Source IP (all)-> ");
            
            if is_valid == false{

                clear_terminal();
                input.clear();
                println!("Enter a valid source IPv4");
                println!("");
                println!("Or press enter for all traffic");
                print!("");
                print!("Source IP (all)-> ");
            }

            user_input(&mut input);

            filter_regex_ipv4(&input, &mut is_valid);
                        
            clear_terminal();

            if is_valid == true{

                self.set_source_ipv4(input);

                break;
            }
        }

        clear_terminal();

    }

    

    //set source port filter
    pub fn set_source_ipv6(&mut self, input : String) {

        self.source_ipv6 = input.trim().to_string();        
                
    }

    //ip v6 menu for traffic filter
    //blank filter allows all IPs address
    //when a valid IP is entered all other IPs will
    //be filtered out
    pub fn source_ipv6_menu(&mut self){

        let mut input : String = String::new();
        let mut is_valid : bool = true;

        loop{
            println!("Leave Blank for all IPs");
            println!("");
            print!("Destination IPs (All) ->");

            if is_valid == false{

                clear_terminal();
                input.clear();
                
                println!("Entered a valid  destination IPv6");
                println!("");
                println!("or for all IPv6 traffic");
                println!("");
                print!("Destination IPs (All) ->");
            }

            user_input(&mut input);

            //validate
            filter_regex_ipv6(&input, &mut is_valid);

            if is_valid == true{

                self.set_source_ipv6(input);
                
                break;
            }
        }

        clear_terminal();

    }


    //set destination port filter
    pub fn set_destination_ipv4(&mut self, input : String){

        self.source_ipv4 = input.trim().to_string();        
    }

    pub fn destination_ipv4_menu(&mut self){

        let mut input : String= String::new();
        let mut is_valid: bool = true;

        loop{
            println!("Leave blank for all IPs"); 
            println!("");            
            print!("Destination IP (all)-> ");
            
            if is_valid == false{

                clear_terminal();
                input.clear();
                println!("Enter a valid destination IPv4");
                println!("");
                println!("Or press enter for all traffic");
                print!("Destination IP (all)-> ");
            }

            user_input(&mut input);

            filter_regex_ipv4(&input, &mut is_valid);
                        
            clear_terminal();

            if is_valid == true{

                self.set_destination_ipv4(input);

                break;
            }
        }

        clear_terminal();
    }

    //set destination port filter
    pub fn set_destination_ipv6(&mut self, input : String){

        self.source_ipv6 = input.trim().to_string();        
    }

    
    pub fn destination_ipv6_menu(&mut self){
        
        let mut input : String = String::new();
        let mut is_valid : bool = true;

        loop{
            println!("Leave Blank for all IPs");
            println!("");
            print!("Destination IPs (All) ->");

            if is_valid == false{

                clear_terminal();
                input.clear();
                
                println!("Entered a valid destination  IPv6");
                println!("");
                println!("or for all IPv6 traffic");
                println!("");
                print!("Destination IPs (All) ->");
            }

            user_input(&mut input);

            //validate
            filter_regex_ipv6(&input, &mut is_valid);

            if is_valid == true{

                self.set_destination_ipv6(input); 
                
                break;
            }
        }

        clear_terminal();
    }


    fn set_ports(&mut self, port_range : [u32; 2]){

        if self.s_port == 60000 && self.s_limit == 60000{

            self.set_s_port_range(port_range);
        
        }else{

            self.set_d_port_range(port_range);
        }

    }

    //reset port to range outside of normal
    //port range on the high to indicate
    //port unconfigured 
    fn reset_s_ports(&mut self){

        self.s_port = 60000;
        self.s_limit = 60000;
    }
     
    fn set_s_port(&mut self, port : u32){

        self.s_port = port;
        self.s_limit = 0;
    }

    //set source port range. index 0 will always for the
    //s_port and index 1 s_limit
    fn set_s_port_range(&mut self, port_range : [u32; 2]){
        
        self.s_port = port_range[0];
        self.s_limit = port_range[1];
    }


    //port menu for user input if user enters invalid input
    //all port will be counted as interesting traffic
    pub fn s_port_menu(&mut self){

        let mut input : String = String::new();
        let mut is_valid : bool = true;
                

        loop{

            
            
            println!("Enter a port or valid port range");
            println!("");
            println!("hit enter or space bar");
            println!("");
            println!("Enter port or port range (1-65535) ->");
            
            if is_valid == false{
                let mut exit = String::new();
                println!("Currently not filtering for any ports");
                print!("Do you want continue with all ports? (y/n) ");
                user_input(&mut exit);

                if exit == String::from("y"){

                    break 
                }


            }

            user_input(&mut input);

            //
            self.filter_port_range(&input, &mut is_valid);

          
            
            if is_valid == true{


                clear_terminal();
                break;
            }


        }
    }

    //reset destination port to default port
    // status outside of port range on the high end to
    //indicate port needs to be configured
    pub fn reset_d_port(&mut self){

        self.d_port = 60000;
        self.d_limit = 60000;
    }

    pub fn set_d_port(&mut self, port : u32){
        
        self.s_port = port;
        self.d_limit = 0;
    
    }

    //set destination port 
    pub fn set_d_port_range(&mut self, port_range : [u32; 2]){

        self.d_port = port_range[0];
        self.d_limit = port_range[1];
    }


    //port check and validation
    //if a port is not entered or if a port is invalid array of all zeros
    //with an array of zeros port will be set to zero and fillter not filter
    //for any ports 
    fn filter_port_range(&mut self, input : &String, is_valid : &mut bool){
        
        //array of zeros = no ports filtered
        let mut port_range: [u32; 2] = [0, 0]; 

        //check is user left input blank
        //if blank port nums will be set to 0
        if input.trim().len() == 0{
            
           self.set_ports(port_range);
        
        }

        //check if user input a range using the - char
        let ports : Vec<&str> = input.trim().split("-").collect();

        
        //check the length of the string split
        let port_range_length = ports.len();

        
            
        if port_range_length == 1 {
            //single port number enter
            //
            if let Some(port) = ports.get(0){
                
                //returns a 0 for invalid input
                let num_port = parse_string_to_num_u32(port);
                
                //check if port in valid port range
                filter_port_check(&num_port, is_valid);

                if *is_valid == false{
                    //if port invalid set traffic settings to 
                    //include all traffic
                    self.set_ports(port_range);
                    
                }else{
                    //if traffic valid set index 0 
                    //to the num_port and set ports
                    port_range[0] = num_port;

                    self.set_ports(port_range);
                }

                
            };
            
        }else if port_range_length == 2 {
            //user input a port range

            //check index 0 for port string and converts to 
            //u32 
            let port1:u32 = match ports.get(0){

                Some(port) =>{ 
                    parse_string_to_num_u32(port)
                },
                None => 0
            };

            //checks if first port is in a valid range
            filter_port_check(&port1, is_valid);

            //if port is in valid return array of all zeros
            if *is_valid == false{

                self.set_s_port_range(port_range);
            }

            //check for port num string at index 1
            //return a u32 port number
            let port2: u32 = match ports.get(1){

                Some(port) =>{
                    
                    parse_string_to_num_u32(port)
                }

                None => 0
            };

            //if either number is invalid include 
            //all traffic as interesting traffic
            if *is_valid == false{


                self.set_s_port_range(port_range);
               
            
            }else{
                //traffic is valid. set the lower port number 
                //to index 0 and the higher number to index 1
                //set port number

                if port1 > port2{
                
                    port_range[0] = port2;
                    port_range[1] = port1;
                    self.set_s_port_range(port_range);
                
                }else{
                    
                    port_range[0] = port1;
                    port_range[1] = port2;    
                    self.set_d_port_range(port_range);
                
                }    
            }

        }

        return
        
    }


} 






// //user input menu and take user input
// fn filter_ip_input_ipv4(input: &mut String , is_valid : &bool, is_source : bool){
        

        
//         println!("Leave blank for all IPs");
//         println!("");

//         //takes input from the user
        
//         user_input(input);
        
//         if *is_valid == false{
//             println!("Enter a valid IPv4 or IPv6 address");
//             println!("");
//         }
        
//         if is_source == true{

//             print!("Source IP (all)-> ");
        
//         }else{
//             print!("Destination IP (all)-> ");
//         }
        
//         clear_terminal();

// }

// fn filter_port(input : &mut String, is_source : bool) -> u32{

//     let mut is_valid = true;
    
    
//     let mut port : u32;

//     loop{
//         println!("Leave blank for all ports");
//         println!("");
//         if is_valid == false{

//             println!("Select valid port 1-65535");
//             println!("")
//         }
//         if is_source{
        
//             println!("Source port:")
        
//         }else{
        
//             println!("Destination port:")
        
//         }        

//         user_input(input);

//         //convert user input to u32:        
//         port = parse_string_to_num_u32(input); 

//         filter_port_check(&port, &mut is_valid);        
        
//         if is_valid == true{
            
//             clear_terminal();
//             break;
            
//         }else{
            
//             clear_terminal();

//             continue;
//         }

//     }

//     port


// }

fn filter_port_check(value : &u32, is_valid_ : &mut bool){

    if *value < 1 || *value > 65535{
  
        *is_valid_ = false;        
  
    }else{

        *is_valid_ = true;

    }


} 


fn filter_regex_ipv4(input : &str, is_valid : &mut bool){
    
    if input.trim().len() == 0 {
        *is_valid = true;

        return
    } 

    let ip_reg = Regex::new(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$|^(([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4}|:))|(::([0-9a-fA-F]{1,4}:){0,6}([0-9a-fA-F]{1,4}))$").unwrap();
    
    if ip_reg.is_match(input.trim()){

        *is_valid = true;

    }else{

        *is_valid = false;

    }
}

fn filter_regex_ipv6(input : &str, is_valid : &mut bool){

    //if input empty return true
    if input.trim().len() == 0 {
        *is_valid =  true;
        return 
    } 

    let ipv6_regex = r"^((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){1,7}:)|(([0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4})|(([0-9A-Fa-f]{1,4}:){1,5}(:[0-9A-Fa-f]{1,4}){1,2})|(([0-9A-Fa-f]{1,4}:){1,4}(:[0-9A-Fa-f]{1,4}){1,3})|(([0-9A-Fa-f]{1,4}:){1,3}(:[0-9A-Fa-f]{1,4}){1,4})|(([0-9A-Fa-f]{1,4}:){1,2}(:[0-9A-Fa-f]{1,4}){1,5})|([0-9A-Fa-f]{1,4}:((:[0-9A-Fa-f]{1,4}){1,6}))|(:((:[0-9A-Fa-f]{1,4}){1,7}|:)))(%.+)?$";

    // Compile the regex
    let ip_reg = Regex::new(ipv6_regex).unwrap();

    if ip_reg.is_match(input.trim()){

        *is_valid = true;
    

    }else{

        *is_valid = false;

    }
}


