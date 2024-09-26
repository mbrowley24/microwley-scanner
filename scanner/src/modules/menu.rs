use clap::{Arg, ArgMatches ,Command, Error};
use pnet::datalink::NetworkInterface;
use crate::modules::{
    interface,
    packet_capture::packet_capture,
};

use std::iter;
use std::{
    io::{self, Write, stdin, stdout},
    num::ParseIntError,
    convert::TryFrom,
};
use pnet::{
    datalink::{self, 
        Channel::Ethernet,
        EtherType,
    },
    packet::ethernet::{
        EthernetPacket,
        EtherTypes,
    }
};
use regex::Regex;


pub struct Menu{
    to_blue : String,
    to_bold : String,
    to_green : String,
    to_red : String,
    text : String,
    start : String,
    end : String,
    reset: String,
    underline : String,
    white : String,
    yellow : String,
    
}

//ToDO creating a standard for displaying text. Will work on this 
//once app is functional
impl Menu {

    pub fn new(text : String) -> Self{

        Self{   to_blue : String::from("94"),
                to_bold: String::from("1"),
                to_green : String::from("92"),
                to_red: String::from("91"), 
                text: String::from(text),
                start : String::from("\033["), 
                end : String::from("m"),
                reset : String::from("\033[0m"),
                underline: String::from("4"), 
                white: String::from("97"), 
                yellow: String::from("93") 
            }

    }

    pub fn display(&self){

        println!("{}{}{}", self.white, self.text, self.end)
    } 
}



fn clap_set_up() -> ArgMatches{

    Command::new("Microwley-Scanner")
        .version("1.0")
        .author("Michael Browley")
        .about("A simple packet snifffer")
        .subcommand(Command::new("start")
            .about("Starts the application"))
        .subcommand(Command::new("stop")
            .about("Stops the applications"))
         .subcommand(Command::new("output loc")
          .about("")
          .arg(Arg::new("file")
            .required(false)
            .index(1)))
            .get_matches()
}

pub fn clear_terminal() {
    // Clear the terminal screen using ANSI escape codes
    print!("\x1B[2J\x1B[1;1H");
}

pub fn convert_to_u16(value : u32) -> u16{

    
    
    match u16::try_from(value){

        Ok(new_val) => new_val,
        
        Err(_) => 0
    }

}

fn guided_mode(cmd : &mut String){
   let mut test_string = String::new();
    
    
}

//user validation check for user selecting an interface
pub fn input_validation_digit(input_opt : &String, invalid : &mut bool){
    
    //check for digits only
    let re = Regex::new(r"^\d$").unwrap();    

    //return value: 
    //Returns true if selection is valid
    //Return false if selection is invalid
    
    //check if input is a digit
    if re.is_match(input_opt.trim()){
        *invalid = false;
    
    }else{

        *invalid = true;
    }


}

pub fn master_menu(){
    

    let matches = clap_set_up();

    match matches.subcommand(){
        
        Some(("start", _)) =>{

            println!("start connection....");
            let mut menu_position: String = String::from("0");
            
            loop{
                
                if menu_position.trim() == String::from("0"){


                    menu_set_up(&mut menu_position);
                    clear_terminal();
  
                }else if menu_position.trim() == String::from("1") {


                    packet_capture(&mut menu_position);


                }else {

                    println!("Break statement {}", menu_position);
                    break;
                
                }

            }
        }

        Some(("cmd-start", _)) => {
            println!("stop service....")
        }
        _ => println!("Unkown command. use --hlp to see available options.")
    }


    

}


fn menu_set_up(input : &mut String){
    clear_terminal();
    input.clear();

     println!("Welcome to Microwley-Scanner!!");
     println!("-----------------------------");
     println!("");
     println!("Make a selection: ");
     println!("");
     println!("1: Packet Capture");
     println!("2: Network Scanner");
     println!("3: Exit Program ");
     println!("");
     print!("Make a selection -> ");
    user_input(input);

}




//check if user input is E or e for exit current menu
//return true for previous menu
//return false to continue in current selection
pub fn previous_menu(input_opt: &String, menu : & mut String){

    // if true go back to previous menu
    if input_opt.to_string() ==  String::from("e") || input_opt.to_string() == String::from("E"){         
        
    
            menu.clear();
            menu.push_str("0");
        
    }

}

//parse string to u32
pub fn parse_string_to_num_selection_u16(capture_opt : &str) -> u16{
        
        let selected_opt: Result<u16, ParseIntError> = capture_opt.trim().parse();
        
        match selected_opt{
            
            Ok(value) => value,
            
            Err(e) =>{
                eprintln!("Invalid digit found: {}", e);
                0
            }
        }    
}


pub fn parse_string_to_num_u32(option : &str) -> u32{
    
    let selected_opt: Result<u32, ParseIntError> = option.trim().parse();
        
        match selected_opt{
            
            Ok(value) => value,
            
            Err(e) =>{
                eprintln!("Invalid digit found: {}", e);
                0
            }
        }    
}

pub fn user_input(input :&mut String){

    stdout().flush().unwrap();
        stdin().read_line(input)
        .expect("Error in user input");

    if input.ends_with("\n"){
        input.pop();
    }
}