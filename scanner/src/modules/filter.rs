use std::f32::consts::E;
use pnet::packet;
use crate::modules::menu::{
    clear_terminal,
    input_validation_digit,
    input_validation_digit_range,
    parse_string_to_num_u32,
    parse_string_to_num_selection_u16,
    user_input,
    spacer_size,
    time_now

};
use pnet::packet::{ethernet::{
    EtherTypes,
    EthernetPacket
}, icmp::{
    IcmpCode,
    IcmpPacket,
    IcmpTypes,
},
icmpv6::{
    Icmpv6Code,
    Icmpv6Packet,
    Icmpv6Types,
},
   ip::{IpNextHeaderProtocol,
        IpNextHeaderProtocols
   },
   ipv4::Ipv4Packet,
    ipv6::Ipv6Packet,
   tcp::{
    TcpFlags::{
        ACK,
        CWR,
        FIN,
        PSH,
        RST,
        SYN,
        URG
    },
    TcpPacket
}, udp::UdpPacket, FromPacket, Packet};
use pnet::packet::icmpv6::Icmpv6;
use regex::Regex;
// use std::io::{stdin, stdout, Write};



pub struct Filter{
    source_ipv4 : String,
    destination_ipv4 : String,
    source_ipv6: String,
    destination_ipv6 : String,
    details: bool,
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
            details: false,
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


    pub fn capture_flow(&self, packet: &[u8]){
        if let Some(frame) = EthernetPacket::new(packet){

            self.capture_flow_layer2(&frame);

            // match frame.get_ethertype(){
            //
            //     EtherTypes::Ipv4 =>{
            //         if self.ipv4 == true{
            //             println!("in here");
            //             return
            //         }
            //
            //         // self.capture_flow_ipv4(&frame)
            //     },
            //
            //     EtherTypes::Ipv6 =>{
            //         if self.ipv6 == true{
            //             println!("in here");
            //             return
            //         }
            //
            //         self.capture_flow_ipv6(&frame)
            //     },

                // EtherTypes::Arp => capture_flow_arp(),

                // EtherTypes::Vlan => capture_flow_vlan(),

                // EtherTypes::Lldp => capture_flow_lldp(),

                // EtherTypes::QinQ => capture_q_n_q(),

            //     _ => {}
            // }
        }
    }


    //format String for output

    //Layer2 source transmission type into string Unicast, broadcast, etc
    fn layer2_source_transmission(&self, frame : &EthernetPacket) -> String {

        if frame.get_source().is_broadcast() == true{

            String::from("Broadcast")

        }else if frame.get_source().is_multicast(){

            String::from("Multicast")

        }else if frame.get_source().is_unicast() == true{

            String::from("Unicast")

        }else{
            String::from("")
        }


    }

    //Layer2 destination transmission type into string Unicast, broadcast, etc
    fn layer2_source_destination(&self, frame : &EthernetPacket) -> String{

        if frame.get_destination().is_broadcast() == true{

            String::from("Broadcast")

        }else if frame.get_destination().is_multicast(){

            String::from("Multicast")

        }else if frame.get_destination().is_unicast() == true{

            String::from("Unicast")

        }else{
            String::from("")
        }
    }
    //Ethernet type to string
    pub fn ether_type_to_text(&mut self, frame: EthernetPacket) -> String{


        match frame.get_ethertype(){

            EtherTypes::Arp => String::from("ARP"),
            EtherTypes::Ipv4 => String::from("IPv4"),
            EtherTypes::Ipv6 => String::from("IPv6"),
            EtherTypes::Lldp => String::from("LLDP"),
            _ =>  String::from("")
        }   
        
    }

    //ICMP code format
    fn icmp_code_format(&self, packet: &IcmpPacket, message : String) -> String{
        format!("{:?}: {}", packet.get_icmp_code(), message)
    }

    fn icmp6_code_format(&self, packet : &Icmpv6Packet, message : String) -> String{
        format!("{:?}: {}", packet.get_icmpv6_code(), message)
    }

    //ICMP type format
    fn icmp_type_format(&self, packet : &IcmpPacket, message : String) -> String {

        format!("{:?}: {}", packet.get_icmp_type(), message)
    }

    fn icmp6_type_format(&self, packet : &Icmpv6Packet, message : String) -> String {

        format!("{:?}: {}", packet.get_icmpv6_type(), message)
    }

    //Destination unreachable code
    fn icmp_destination_unreachable(&self, packet : &IcmpPacket) -> String{

        match packet.get_icmp_code() {
            IcmpCode(0) => self.icmp_code_format(&packet, String::from("Network Unreachable")),
            IcmpCode(1) => self.icmp_code_format(&packet, String::from("Host Unreachable")),
            IcmpCode(2) => self.icmp_code_format(&packet, String::from("Protocol Unreachable")),
            IcmpCode(3) => self.icmp_code_format(&packet, String::from("Port Unreachable")),

            IcmpCode(4) => {
                self.icmp_code_format(&packet,
                              String::from("Fragmentation needed, fragment flag set to false"))
            },

            IcmpCode(5) => self.icmp_code_format(&packet, String::from("Source Route failed")),

            IcmpCode(6) => {
                self.icmp_code_format(&packet,
                                      String::from("Destination Network Unknown"))
            }

            IcmpCode(7) =>{ self.icmp_code_format(&packet,
                                                 String::from("Destination Host Unknown"))
            }

            IcmpCode(8) => self.icmp_code_format(packet, String::from("Source Host Isolated")),

            IcmpCode(9) => {
                self.icmp_code_format(&packet,
                                      String::from("Network Administratively Prohibited"))
            },

            IcmpCode(10) => {
                self.icmp_code_format(&packet, String::from("Host Administratively Unknown"))
            },

            IcmpCode(11) => {
                self.icmp_code_format(&packet,
                                      String::from("Network Unreachable for Type of Service"))
            },

            IcmpCode(12) => {
                self.icmp_code_format(&packet,
                                      String::from("Host Unreachable for Type of Service"))
            },

            IcmpCode(13) =>{
                self.icmp_code_format(&packet,
                                      String::from("Communication Administratively Prohibited"))
            }

            IcmpCode(14) => self.icmp_code_format(&packet,
                                                  String::from("Host Precedence Violation")),


            IcmpCode(15) => self.icmp_code_format(&packet,
                                                  String::from("Precedence Cutoff in Effect")),
            _ => String::from("")
        }
    }


    fn icmp6_destination_unreachable(&self, packet : &Icmpv6Packet) -> String{

        match packet.get_icmpv6_code(){

            Icmpv6Code(0) => self.icmp6_code_format(&packet, String::from("No route to destination")),

            Icmpv6Code(1) => {
                self.icmp6_code_format(&packet,
                String::from("Communication with the destination is administratively prohibited.")
                )
            },

            Icmpv6Code(2) => {
                self.icmp6_code_format(&packet,String::from("Beyond scope of source address"))
            }

            Icmpv6Code(3) => self.icmp6_code_format(&packet,String::from("Address unreachable")),

            Icmpv6Code(4) => self.icmp6_code_format(&packet,String::from("Port unreachable")),

            Icmpv6Code(5) =>{
                self.icmp6_code_format(&packet,
                                   String::from("Source address failed ingress/egress policy"))
            },

            Icmpv6Code(6) => {
                self.icmp6_code_format(&packet, String::from("Reject route to destination"))
            },

            Icmpv6Code(7) =>{
                self.icmp6_code_format(&packet, String::from("DError in source routing header."))
            }

            _=> self.icmp6_code_format(&packet, String::from("Unknown")),
        }
    }


    fn icmp_node_information_query(&self, packet : &Icmpv6Packet) -> String{


        match packet.get_icmpv6_code(){
            Icmpv6Code(0) => {
                self.icmp6_code_format(&packet, String::from("No route to destination"))
            },
            Icmpv6Code(1) => {
                self.icmp6_code_format(&packet,
               String::from("Data field contains a name that is fully or partially qualified"))
            }
            Icmpv6Code(2) =>{
                self.icmp6_code_format(&packet,
                                       String::from("Data field contains an IPv4 address"))
            }

            _=> self.icmp6_code_format(&packet, String::from("Unknown")),
        }

    }
    fn icmp_node_information_response(&self, packet : &Icmpv6Packet) -> String{

        match packet.get_icmpv6_code(){

            Icmpv6Code(0) => self.icmp6_code_format(packet, String::from("Reply, no error")),
            Icmpv6Code(1) => self.icmp6_code_format(packet, String::from("Reply, name does not exist")),
            Icmpv6Code(2) => self.icmp6_code_format(packet, String::from("Reply, type of data does not exist")),
            _=> String::from("")
        }
    }






    //ICMP parameter problem codes to String
    fn icmp_parameter_problem(&self, packet: &IcmpPacket) -> String{

        match packet.get_icmp_code(){

            IcmpCode(0) => self.icmp_code_format(&packet, String::from("Pointer Indicates the Error")),
            IcmpCode(1) => self.icmp_code_format(&packet, String::from("Missing a Required Option")),
            IcmpCode(2) => self.icmp_code_format(&packet, String::from("Bad Length")),
            _=> String::from("")
        }
    }
    fn icmp6_parameter_problem(&self, packet : &Icmpv6Packet) -> String{

        match packet.get_icmpv6_code(){

            Icmpv6Code(0) =>{
                self.icmp6_code_format(&packet, String::from("Erroneous header field encountered"))
            },

            Icmpv6Code(1) => {
                self.icmp6_code_format(&packet, String::from("Unrecognized next header type encountered"))
            },

            Icmpv6Code(2) =>{
                self.icmp6_code_format(&packet, String::from("Unrecognized IPv6 option encountered"))
            }

            _=> self.icmp6_code_format(&packet, String::from("Unknown")),

        }
    }


    //icmp redirect messages
    fn icmp_redirect(&self, packet : &IcmpPacket) -> String{

        match packet.get_icmp_code() {
            IcmpCode(0) => {
                self.icmp_code_format(&packet, String::from("Redirect Datagram for the Network"))
            }

            IcmpCode(1) =>{
                self.icmp_code_format(&packet, String::from("Redirect Datagram for the Host"))
            }
            IcmpCode(2) =>{
                self.icmp_code_format(&packet,
                          String::from("Redirect Datagram for the Type of Service and Network"))
            }
            IcmpCode(3) =>{
                self.icmp_code_format(&packet,
                          String::from("Redirect Datagram for the Type of Service and Host"))
            }

            _=> String::from("")
        }
    }

    fn icmp_router_renumbering(&self, packet : &Icmpv6Packet) -> String{

        match packet.get_icmpv6_code(){

            Icmpv6Code(0) =>{
                self.icmp6_code_format(&packet, String::from("Command."))
            },

            Icmpv6Code(1) =>{
                self.icmp6_code_format(&packet, String::from("Result"))
            },

            Icmpv6Code(255) => {
                self.icmp6_code_format(&packet, String::from("Error"))
            }

            _=> self.icmp6_code_format(&packet, String::from("Sequence number reset")),
        }
    }

    //Time exceeded ICMP codes
    fn icmp_time_exceeded(&self, packet : &IcmpPacket) -> String{

        match packet.get_icmp_code() {

            IcmpCode(0) => self.icmp_code_format(&packet, String::from("Time Limit Exceeded")),
            IcmpCode(1) => self.icmp_code_format(&packet, String::from("Fragment Reassembly Time Exceeded")),
            _=> String::from("")
        }
    }

    fn icmp6_time_exceeded(&self, packet : &Icmpv6Packet) -> String{

        match packet.get_icmpv6_code(){

            Icmpv6Code(0) =>{
                self.icmp6_code_format(&packet, String::from("Hop limit exceeded in transit"))
            },

            Icmpv6Code(1) =>{
                self.icmp6_code_format(&packet, String::from("Fragment reassembly time exceeded"))
            }

            _=> self.icmp6_code_format(&packet, String::from("Unknown")),
        }
    }

    //returns an array of two strings index 0 is the type and index 1 is the type code
    fn icmp_type_and_code(&self, packet : &IcmpPacket) -> [String; 2]{
        let mut type_code = [String::new(), String::new()];

        match packet.get_icmp_type(){

            IcmpTypes::EchoReply =>{

                type_code[0] = self.icmp_type_format(packet, String::from("(Echo Reply)"));
                type_code[1] = self.icmp_code_format(packet, String::from("(Echo Reply)"));

            },
            IcmpTypes::EchoRequest =>{

                type_code[0] = self.icmp_type_format(packet, String::from("(Echo Request)"));
                type_code[1] = self.icmp_code_format(packet, String::from("(Echo Request)"));

            },
            IcmpTypes::DestinationUnreachable =>{

                type_code[0] = self.icmp_type_format(packet, String::from("(Destination Unreachable)"));
                type_code[1] = self.icmp_destination_unreachable(packet);

            },
            IcmpTypes::RedirectMessage => {

                type_code[0] = self.icmp_type_format(packet, self.icmp_redirect(packet));
                type_code[1] = self.icmp_redirect(packet);

            },
            IcmpTypes::RouterAdvertisement =>{

                type_code[0] = self.icmp_type_format(packet, String::from("(Router Advertisement)"));
                type_code[1] = self.icmp_code_format(packet, String::from("(Router Advertisement)"));

            },
            IcmpTypes::RouterSolicitation =>{

                type_code[0] = self.icmp_type_format(packet, String::from("(Router Solicitation)"));
                type_code[1] = self.icmp_code_format(packet, String::from("(Router Solicitation)"));

            },
            IcmpTypes::TimeExceeded =>{

                type_code[0] = self.icmp_type_format(packet, String::from("(Time Exceeded)"));
                type_code[1] = self.icmp_code_format(packet, self.icmp_time_exceeded(packet));

            },

            IcmpTypes::ParameterProblem => {

                type_code[0] = self.icmp_type_format(packet, String::from("Parameter Problem"));
                type_code[1] = self.icmp_code_format(packet, self.icmp_parameter_problem(packet));

            },
            IcmpTypes::Timestamp =>{
                type_code[0] = self.icmp_type_format(packet, String::from("Timestamp"));
                type_code[1] = self.icmp_code_format(packet, String::from("Timestamp Request"));
            },
            IcmpTypes::TimestampReply =>{
                type_code[0] = self.icmp_type_format(packet, String::from("Timestamp Reply"));
                type_code[1] = self.icmp_code_format(packet, String::from("Timestamp Request"));
            },

            IcmpTypes::AddressMaskRequest => {
                type_code[0] = self.icmp_type_format(packet, String::from("Address Mask Request"));
                type_code[1] = self.icmp_code_format(packet, String::from("Address Mask Request"));

            },
            IcmpTypes::AddressMaskReply =>{
                type_code[0] = self.icmp_type_format(packet, String::from("Address Mask Reply"));
                type_code[1] = self.icmp_code_format(packet, String::from("Address Mask Reply"));
            },
            _=>{
                type_code[0] = self.icmp_type_format(packet, String::from("Unknown"));
                type_code[1] = self.icmp_code_format(packet, String::from("Unknown"));
            }
        }

        type_code
    }


    //To DO finish ICMP 6 type and code
    fn icmp6_type_and_code(&self, packet : &Icmpv6Packet) -> [String; 2]{

        println!("icmp6_type_and_code Marker");
        let mut type_code: [String; 2] = [String::new(), String::new()];
        match packet.get_icmpv6_type(){

            Icmpv6Types::DestinationUnreachable =>{
                type_code[0] = self.icmp6_type_format(packet,
                                                      String::from("Destination Unreachable"));
                type_code[1] = self.icmp6_type_format(packet,
                                                      self.icmp6_destination_unreachable(packet));
            }
            Icmpv6Types::EchoReply =>{

                type_code[0] = self.icmp6_type_format(packet, String::from("(Echo Reply)"));
                type_code[1] = self.icmp6_code_format(packet, String::from("(Echo Reply)"));
            }

            Icmpv6Types::EchoRequest =>{
                type_code[0] = self.icmp6_type_format(packet, String::from("(Echo Request"));
                type_code[1] = self.icmp6_code_format(packet, String::from("(Echo Request"));
            }


            Icmpv6Types::NeighborAdvert =>{
                type_code[0] = self.icmp6_type_format(packet, String::from("(NeighborAdvert)"));
                type_code[1] = self.icmp6_code_format(packet, String::from("(No specific code"));
            }

            Icmpv6Types::NeighborSolicit =>{
                type_code[0] = self.icmp6_type_format(packet, String::from("(Neighbor Solicit"));
                type_code[1] = self.icmp6_code_format(packet, String::from("(No specific code"));
            }

            Icmpv6Types::PacketTooBig =>{
                type_code[0] = self.icmp6_type_format(packet, String::from("(PacketTooBig)"));
                type_code[1] = self.icmp6_code_format(packet, String::from("(No specific code)"));
            }

            Icmpv6Types::Redirect =>{
                type_code[0] = self.icmp6_type_format(packet, String::from("(Redirect)"));
                type_code[1] = self.icmp6_code_format(packet, String::from("(No specific code"));
            }

            Icmpv6Types::RouterAdvert =>{
                type_code[0] = self.icmp6_type_format(packet, String::from("(Router Advert)"));
                type_code[1] = self.icmp6_code_format(packet, String::from("(No specific code)"));
            }

            Icmpv6Types::RouterSolicit =>{
                type_code[0] = self.icmp6_type_format(packet, String::from("(Router Solicit"));
                type_code[1] = self.icmp6_code_format(packet, String::from("(No specific code)"));
            }

            Icmpv6Types::TimeExceeded => {
                type_code[0] = self.icmp6_code_format(packet, String::from("(Time Exceeded)"));
                type_code[1] = self.icmp6_code_format(packet, self.icmp6_time_exceeded(packet));
            }

            _=> println!()

        }

        type_code
    }

    //layer 4 filter output
    fn layer_4_protocol(&self, next_protocol : IpNextHeaderProtocol) -> String{

        match next_protocol{

            IpNextHeaderProtocols::Tcp => String::from("TCP"),
            IpNextHeaderProtocols::Udp => String::from("UDP"),
            IpNextHeaderProtocols::Icmp => String::from("ICMP"),
            IpNextHeaderProtocols::Icmpv6 => String::from("ICMPv6"),
            IpNextHeaderProtocols::Esp => String::from("ESP"),
            IpNextHeaderProtocols::Ah => String::from("AH"),
            _ => String::new()
        }
    }

    //tcp flag String output
    fn tcp_flag(&self, flags: u8) ->String{

        let mut flag = String::new();

        if (flags & ACK) != 0{


            flag.push_str("SYN/ACK");


        }else if (flags & SYN) != 0 && (flags & FIN) != 0{


            flag.push_str("SYN/FIN");


        }else if (flags & FIN) != 0 && (flags & ACK) != 0{


            flag.push_str("FIN/ACK");


        }else if (flags & PSH) != 0 && (flags & ACK) != 0{


            flag.push_str("PSH/ACK");


        }else if(flags & URG) != 0 && (flags & ACK) != 0{


            flag.push_str("URG/ACK");


        }else if (flags & RST) != 0  && (flags & ACK) != 0{


            flag.push_str("RST/ACK");

        }else if (flags & ACK) != 0{


            flag.push_str("ACK");


        }else if (flags & CWR) != 0{

            flag.push_str("CWR");


        }else if (flags & FIN) != 0 {


            flag.push_str("FIN");


        }else if (flags & PSH) != 0{


            flag.push_str("PSH");


        }else if (flags & RST) != 0 {


            flag.push_str("RST");


        }else if(flags & SYN) != 0{

            flag.push_str("SYN");


        }else if (flags & URG) != 0{


            flag.push_str("URG");


        }


        flag
    }


    //Filter Menus
    //IP menu asks user to IP version selection
    pub fn filter_ip_version_menu(&mut self){

        let mut input = String::new();
        
        println!("Choose IP Version");
        println!();
        println!("Press space or enter for both");
        println!();
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
            println!();
            print!("Source IP (all)-> ");

            if is_valid == false{

                clear_terminal();
                input.clear();
                println!("Enter a valid source IPv4");
                println!();
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

    //ip v6 menu for traffic filter
    //blank filter allows all IPs address
    //when a valid IP is entered all other IPs will
    //be filtered out
    pub fn source_ipv6_menu(&mut self){

        let mut input : String = String::new();
        let mut is_valid : bool = true;

        loop{
            println!("Leave Blank for all IPs");
            println!();
            print!("Destination IPs (All) ->");

            if is_valid == false{

                clear_terminal();
                input.clear();

                println!("Entered a valid  destination IPv6");
                println!();
                println!("or for all IPv6 traffic");
                println!();
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

    pub fn destination_ipv4_menu(&mut self){

        let mut input : String= String::new();
        let mut is_valid: bool = true;

        loop{
            println!("Leave blank for all IPs");
            println!();
            print!("Destination IP (all)-> ");

            if is_valid == false{

                clear_terminal();
                input.clear();
                println!("Enter a valid destination IPv4");
                println!();
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

    pub fn destination_ipv6_menu(&mut self){

        let mut input : String = String::new();
        let mut is_valid : bool = true;

        loop{
            println!("Leave Blank for all IPs");
            println!();
            print!("Destination IPs (All) ->");

            if is_valid == false{

                clear_terminal();
                input.clear();

                println!("Entered a valid destination  IPv6");
                println!();
                println!("or for all IPv6 traffic");
                println!();
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

    //port menu for user input if user enters invalid input
    //all port will be counted as interesting traffic
    pub fn s_port_menu(&mut self){

        let mut input : String = String::new();
        let mut is_valid : bool = true;


        loop{



            println!("Enter a port or valid port range");
            println!();
            println!("hit enter or space bar");
            println!();
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

    //reset ip filters
    fn reset_ip_filter(&mut self){

        self.ipv4 = false;
        self.ipv6 = false;
    }

    //set ipv4 only filter
    fn set_ipv4_filter(&mut self){

        self.ipv4 = false;
        self.ipv6 = true;

    }

    //set filter for ipv6 only
    fn set_ipv6_filter(&mut self){

        self.ipv4 = true;
        self.ipv6 = false;

    }


    //set IPV4 source port filter string
    fn set_source_ipv4(&mut self, source_ip : String) {

        self.source_ipv4 = source_ip.trim().to_string();        
                
    }

    //set IPV6 source port filter
    pub fn set_source_ipv6(&mut self, input : String) {

        self.source_ipv6 = input.trim().to_string();        
                
    }


    //set ipv4 destination port filter
    pub fn set_destination_ipv4(&mut self, input : String){

        self.source_ipv4 = input.trim().to_string();        
    }



    //set ipv6 destination port filter
    pub fn set_destination_ipv6(&mut self, input : String){

        self.source_ipv6 = input.trim().to_string();        
    }

    //set port ranges for both source and destination
    fn set_ports(&mut self, port_range : [u32; 2]){

        if self.s_port == 60000 && self.s_limit == 60000{

            self.set_s_port_range(port_range);

        }else{

            self.set_d_port_range(port_range);
        }

    }

    //reset port to range outside of normal
    //port range on the high to indicate
    //port reconfigured
    fn reset_s_ports(&mut self){

        self.s_port = 60000;
        self.s_limit = 60000;
    }

    //set source ports
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




    //reset destination port to default port
    // status outside of port range on the high end to
    //indicate port needs to be configured
    pub fn reset_d_port(&mut self){

        self.d_port = 60000;
        self.d_limit = 60000;
    }

    //set destination port
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



    //IPV4 packet match to details of the packet or for short abbr traffic flow

    fn capture_flow_ipv4(&self, frame: &EthernetPacket){

        if let Some(packet) = Ipv4Packet::new(frame.payload()) {


            match self.details{

                true => self.capture_flow_ipv4_details(&packet),

                false => self.capture_flow_ipv4_abbr(&packet),
            }


        }

    }

    //short abbreviated layer 3 traffic flow
    fn capture_flow_ipv4_abbr(&self, packet : &Ipv4Packet){

        match packet.get_next_level_protocol() {


            IpNextHeaderProtocols::Icmp =>{

                self.capture_flow_icmp_ipv4(packet);
            },
            IpNextHeaderProtocols::Tcp =>{

                self.capture_flow_tcp_ipv4_abbr(packet);
            },
            IpNextHeaderProtocols::Udp =>{

                self.capture_flow_udp_ipv4_abbr(packet);
            }
            _=> println!("Unhandled packet: Here Here")
        }

    }

    //ipv4 capture output with details
    fn capture_flow_ipv4_details(&self, packet : &Ipv4Packet){

        //checks to see if ipv4 is filtered
        //if marked true for filter return out of function
        if self.ipv4 == true{

            return
        }

        match packet.get_next_level_protocol() {

            IpNextHeaderProtocols::Icmp => self.capture_flow_icmp_ipv4(&packet),

            IpNextHeaderProtocols::Tcp => self.capture_flow_tcp_ipv4(&packet),

            IpNextHeaderProtocols::Udp => self.capture_flow_udp_ipv4(&packet),
            _=> println!()

        }

    }

    //ipv4 capture output






    //ipv4 icmp output
    fn capture_flow_icmp_ipv4(&self, packet : &Ipv4Packet ){


        if let Some(icmp) = IcmpPacket::new(packet.payload()){

            let icmp_type_code : [String;2] = self.icmp_type_and_code(&icmp);
            println!("\x1b[91;1mICMP:\x1b[0m");
            println!("Packet Length: {}", icmp.payload().len());
            println!("{} --> {}", packet.get_source(), packet.get_destination());
            println!("{}  {}", icmp_type_code[0], icmp_type_code[1]);
        }
    }

    //tcp ipv4 output
    fn capture_flow_tcp_ipv4(&self, packet : &Ipv4Packet){

        if let Some(segment) = TcpPacket::new(packet.payload()){
            println!("\x1b[91;1mInternet Protocol Version 4:\x1b[0m");
            println!("\x1b[1mVersion\x1b[0m: 4");
            println!("\x1b[1mHeader Length\x1b[0m: {}", packet.get_header_length());
            println!("\x1b[1mTotal Length\x1b[0m: {}", packet.get_total_length());
            println!("\x1b[1mTime to Live\x1b[0m: {}", packet.get_ttl());
            println!("\x1b[1mFragment Offset\x1b[0m: {}", packet.get_fragment_offset());
            println!("\x1b[1mProtocol\x1b[0m: {}", self.layer_4_protocol(packet.get_next_level_protocol()));
            println!("\x1b[1mFlags\x1b[0m: {}", self.tcp_flag(packet.get_flags()));
            println!("\x1b[1mSource Address: {}:{}", packet.get_source(), segment.get_source());
            println!("\x1b[1mDestination Address:\x1b[0m {}:{}", packet.get_destination(), segment.get_destination());
            println!();
        }
    }

    fn capture_flow_tcp_ipv4_abbr(&self, packet : &Ipv4Packet){

        if let Some(segment) = TcpPacket::new(packet.payload()){

            println!("\x1b[91;1mInternet Protocol Version 4:\x1b[0m");
            println!("\x1b[1mTime to Live\x1b[0m: {}", packet.get_ttl());
            println!("\x1b[1mProtocol\x1b[0m: {}", self.layer_4_protocol(packet.get_next_level_protocol()));
            println!("\x1b[1mFlags\x1b[0m: {}", self.tcp_flag(packet.get_flags()));
            println!("{}:{} --> {}:{}",
                     packet.get_source(),
                     segment.get_source(),
                     packet.get_destination(),
                     segment.get_destination());
        }
    }


    //output fpr udp capture
    pub fn capture_flow_udp_ipv4(&self, packet : &Ipv4Packet){

        if let Some(segment) = UdpPacket::new(packet.payload()){

            println!("--------------------------------------------------");
            println!("Timestamp: {}", time_now());
            println!("Source: {}:{}", packet.get_source(), segment.get_source());
            println!("Destination: {}:{}", packet.get_destination(), segment.get_destination());
            println!("Length: {}", packet.get_total_length());
            println!();
               
        }
    }


    fn capture_flow_udp_ipv4_abbr(&self, packet : &Ipv4Packet){

        if let Some(segment) = UdpPacket::new(packet.payload()){

            println!("{}:{} --> {}:{}",
                     packet.get_source(),
                     segment.get_source(),
                     packet.get_destination(),
                     segment.get_destination()
            );
        }
    }


    //ipv6 capture output
    fn capture_flow_ipv6(&self, frame : &EthernetPacket){

        if self.icmpv6 == true {
            return;
        }

        if let Some(packet) = Ipv6Packet::new(frame.payload()){
            match self.details{

                true => self.capture_flow_ipv6_details(&packet),

                false => self.capture_flow_ipv6_abbr(&packet)
            }
        }

    }

    fn capture_flow_ipv6_abbr(&self, packet :&Ipv6Packet){

        match packet.get_next_header(){
            IpNextHeaderProtocols::Icmpv6 => self.capture_flow_icmp_ipv6(packet),
            IpNextHeaderProtocols::Tcp => self.capture_flow_tcp_ipv6_abbr(packet),
            IpNextHeaderProtocols::Udp => self.capture_flow_udp_ipv6_abbr(packet),
            _=> println!()
        }

    }

    fn capture_flow_ipv6_details(&self, packet : &Ipv6Packet){

        match packet.get_next_header() {

            IpNextHeaderProtocols::Icmpv6 => self.capture_flow_icmp_ipv6(packet),
            IpNextHeaderProtocols::Tcp => self.capture_flow_tcp_ipv6_details(packet),
            IpNextHeaderProtocols::Udp => self.capture_flow_udp_ipv6_details(packet),

            _=> println!()
        }

    }

    fn capture_flow_icmp_ipv6(&self, packet : &Ipv6Packet){

        if let Some(icmp) = Icmpv6Packet::new(packet.payload()){

            let icmp_type_code : [String;2] = self.icmp6_type_and_code(&icmp);
            println!("\x1b[91;1mICMP:\x1b[0m");
            println!("Packet Length: {}", icmp.payload().len());
            println!("{} --> {}", packet.get_source(), packet.get_destination());
            println!("{}  {}", icmp_type_code[0], icmp_type_code[1]);
        }

    }

    fn capture_flow_tcp_ipv6_abbr(&self, packet : &Ipv6Packet){

        println!("in tcp abbr");
        if let Some(segment) = TcpPacket::new(packet.payload()){

            println!("\x1b[91;1mInternet Protocol Version 6\x1b[0m");
            println!("\x1b[1m[ {} ]\x1b[0m:{} --> \x1b[1m[ {} ]\x1b[0m:{}",
                     packet.get_source(),
                     segment.get_source(),
                     packet.get_destination(),
                     segment.get_destination()
            );
            println!();

        }
    }

    //ipv6 TCP output
    fn capture_flow_tcp_ipv6_details(&self, packet : &Ipv6Packet){

        if let Some(segment) = TcpPacket::new(packet.payload()){
            
            
            println!("\x1b[91;1mInternet Protocol Version 6\x1b[0m"); 
            println!("\x1b[1mVersion\x1b[0m: 6");
            println!("\x1b[1mTraffic Class\x1b[0m: {}", packet.get_traffic_class());
            println!("\x1b[1mFlow label\x1b[0m: {}", packet.get_flow_label());
            println!("\x1b[1mPayload Length:\x1b[0m: {}", packet.get_payload_length());
            println!("\x1b[1mNext Header\x1b[0m: {}", self.layer_4_protocol(packet.get_next_header()));
            println!("\x1b[1mHop Limit:\x1b[0m {}", packet.get_hop_limit());
            println!("\x1b[1mSource Address:\x1b[0m \x1b[1m[ {} ]\x1b[0m:{}", packet.get_source(), segment.get_source());
            println!("\x1b[1mDestination Address:\x1b[0m \x1b[1m[ {} ]\x1b[0m:{}", packet.get_destination(), segment.get_destination());
            println!();
            
        }
    }


    fn capture_flow_udp_ipv6_abbr(&self,packet : &Ipv6Packet){



        if let Some(segment) = UdpPacket::new(packet.payload()){


            println!("\x1b[91;1mInternet Protocol Version 6\x1b[0m");;
            println!("[0m \x1b[1m[ {} ]\x1b[0m:{} --> \x1b[1m[ {} ]\x1b[0m:{}",
                     packet.get_source(),
                     segment.get_source(),
                     packet.get_destination(),
                     packet.get_destination());
            println!();
        }
    }

    //ipv6 output flow
    fn capture_flow_udp_ipv6_details(&self,packet : &Ipv6Packet){



        if let Some(segment) = UdpPacket::new(packet.payload()){


            println!("\x1b[91;1mInternet Protocol Version 6\x1b[0m"); 
            println!("\x1b[1mTraffic Class\x1b[0m: {}", packet.get_traffic_class());
            println!("\x1b[1mFlow label\x1b[0m: {}", packet.get_flow_label());
            println!("\x1b[1mPayload Length:\x1b[0m: {}", packet.get_payload_length());
            println!("\x1b[1mNext Header\x1b[0m: {}", self.layer_4_protocol(packet.get_next_header()));
            println!("\x1b[1mHop Limit:\x1b[0m {}", packet.get_hop_limit());
            println!("\x1b[1mSource Address:\x1b[0m \x1b[1m[ {} ]\x1b[0m:{}", packet.get_source(), segment.get_source());
            println!("\x1b[1mDestination Address:\x1b[0m \x1b[1m[ {} ]\x1b[0m:{}", packet.get_destination(), segment.get_destination());
            println!();
        }
    }


    //output for capture flow
    fn capture_flow_layer2(&self, frame : &EthernetPacket){

        self.capture_flow_layer2_details(frame);

        match frame.get_ethertype(){

            EtherTypes::Ipv4 =>{

                if self.ipv4 == true{
                    return
                }

                self.capture_flow_ipv4(frame);

            },
            EtherTypes::Ipv6 =>{

                if self.ipv6 == true{
                    return
                }

                self.capture_flow_ipv6(frame);
            }

            _=> println!()
        }

    }

    fn capture_flow_layer2_details(&self, frame : &EthernetPacket){


        println!("\x1b[1m-------------------------------------------------------\x1b[0m");
        println!();
        println!("\x1b[91;1mEthernet II:\x1b[0m");
        println!("Timestamp: {}", time_now());
        println!("{} ({}) --> {} ({})",
                 frame.get_source(),
                 self.layer2_source_transmission(frame),
                 frame.get_destination(),
                 self.layer2_source_destination(frame)
        );
        println!();

    }

}

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


