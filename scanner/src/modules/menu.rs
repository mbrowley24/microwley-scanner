use chrono::{DateTime, Local};
use clap::{Arg, ArgMatches ,Command};
use crate::modules::packet_capture::packet_capture;


use std::{
    io::{Write, stdin, stdout},
    num::ParseIntError,
    convert::TryFrom,
    time::SystemTime,
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
                start : String::from("\x1b["), 
                end : String::from("m"),
                reset : String::from("\x1b[0m"),
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

pub fn crusor_to_top_left(){

    print!("\x1B[2J\x1B[H");
}

fn guided_mode(cmd : &mut String){
   let mut test_string = String::new();
    
    
}

//user validation check for user selecting an interface
pub fn input_validation_digit(input_opt : &str, is_valid : &mut bool){
    
    //check for digits only
    let re = Regex::new(r"^\d$").unwrap();    

    //return value: 
    //Returns true if selection is valid
    //Return false if selection is invalid
    
    //check if input is a digit
    if re.is_match(input_opt.trim()){
        *is_valid = true;
    
    }else{

        *is_valid = false;
    }


}

pub fn input_validation_digit_range(input : &str, is_valid : &mut bool){

    let range  = input.split("-");

    for value in range{
        
        input_validation_digit(value, is_valid);
        
        if *is_valid == false{

            break;
        }
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

pub fn spacer_size(num_spaces : usize) -> String{

    let mut spacer = String::new();

    for i in 0..num_spaces{

        spacer.push_str(" ");
    }

    spacer
    
}

pub fn time_now()  -> String{

    let system_time = SystemTime::now();

    let datetime : DateTime<Local> =  system_time.into();

    datetime.format("%Y-%m-%d %H:%M:%S.%3f").to_string()
}


pub fn user_input(input :&mut String){

    stdout().flush().unwrap();
        stdin().read_line(input)
        .expect("Error in user input");

    if input.ends_with("\n"){
        input.pop();
    }
}
