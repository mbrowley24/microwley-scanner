use std::{
    fs::File,
    io,
    io::Write,
    mem::drop,
    path::Path
};

use crate::modules::menu;
use crate::modules::menu::user_input;

pub struct ExportToTextFile {
    file : Option<File>,
}


impl ExportToTextFile {
    pub fn new() -> Self {

        Self{
            file : None
        }
    }


    pub fn create_new_file(&mut self, stdin : &mut io::Stdin, stdout : &mut io::Stdout) {
        //hoisted variable

        //prompt to provide the user instruction
        let prompt : String = String::from("Save packet capture file\n\nenter a valid file name ->");

        //input from the user
        let mut input : [String; 2] = [String::new(), String::new()];

        // if a file is name exists prompt user to overwrite
        let mut file_count : usize = 1;

        write!(stdout, "{}", prompt).unwrap();
        stdout.flush().unwrap();

        //user provided file name
        stdin.read_line(&mut input[0])
            .expect("Unable to take user input");


        input[0] = input[0].replace("\n","");


        if input[0].ends_with(".txt"){

            input[1] = input[0].clone();

            input[0] = input[0].replace(".txt", "");

        }else{

            input[1] = input[0].clone();

            input[1] = input[1].replace(".txt", "");
        }


        //check if file name has a value if not assign a value of capture
        if input[0].trim().len() == 0 {

            input[0].clear();

            input[0].push_str("capture");
            input[1].push_str("capture.txt");

        }

        //set file path
        let mut  path: &Path = Path::new(input[1].as_str());



        //loop to change name if already exists
        while path.exists() == true {

            input[1].clear();

            input[1] = String::from(format!("{}({}).txt", input[0], file_count));

            path = Path::new(&input[1]);

            file_count += 1;
        }

        //handle path to create file
        match File::create(input[1].as_str()) {

            Ok(file) => self.file = Some(file),
            Err(e) => self.file =  None,

        };

    }

    //Write to and print to screen the amount of bytes saved in file
    pub fn write_to_file(&mut self, text : &str, stdin : &mut io::Stdin, stdout : &mut io::Stdout) {

        if let Some(ref mut file) = self.file {

            match file.write(text.as_bytes()){

                Ok(bytes_save) =>{

                    let saved_message = format!("Successfully wrote {} bytes to file: ", bytes_save);

                    write!(stdout, "{}", saved_message).unwrap();
                    stdout.flush().unwrap();

                },

                Err(e) => eprintln!("Unable to write to file: {}", e),
            }
        }

    }

    pub fn close_file(self) {

        if let Some(file) = self.file {
            drop(file)
        }
    }
}