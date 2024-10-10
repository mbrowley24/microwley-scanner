use std::{
    fs::File,
    io::{self, Error, Write},
    path::Path
};

use crate::modules::menu;
use crate::modules::menu::user_input;

pub struct ExportToTextFile {

    file : Option<File>,
}


impl ExportToTextFile {
    pub fn new() -> Self {
        Self
    }


    pub fn create_new_file(&mut self, stdin : &mut io::Stdin, stdout : &mut io::Stdout) {
        //hoisted variable

        //prompt to provide the user instruction
        let prompt : String = String::from("Enter a valid file name");
        let mut overwrite : bool = false;
        let overwrite_prompt = String::from("Overwrite existing file? (y/n) \n\n");

        //input from the user
        let mut input : String = String::new();

        //number to change file name if duplicate
        let mut file_number : usize = 0;

        //user provided file name
        io::stdin().read_line(&mut input)
            .expect("Unable to take user input");

        //path / file name for new file
        let mut  path: &Path = Path::new(prompt.as_str());

        //check if the path exists
        let name_exists: bool = path.exists();

        // if a file is name exists prompt user to overwrite
        if name_exists == true {

            // input for user option
            let mut overwrite_file = String::new();

            //prompt for asking the user if they want to overwrite string
            write!(stdout, "{}", overwrite_prompt)
                .expect("Unable to write to stdin");

            //display to user
            stdout.flush().expect("Unable to flush stdout");

            //user input y gets the user to overwrite
            io::stdin().read_line(&mut overwrite_file).expect("Unable to take user input");

            //if user selects yes set overwrite to true
            if overwrite_file != String::from("y") {

                overwrite = true;

            }
        }

        //if overwrite is false, get create another unique, ex if file is taken file(1)
        //maybe available if not the number will increment until a unique name is found
        if overwrite == false {

            //check if file currently exists in current work directory
            while path.exists(){

                //increment the number to change file name
                file_number += 1;

                //new file name
                let new_file_name = format!("{}({}).txt", prompt, file_number);

                //reset
                path = Path::new(new_file_name.as_str());
            }
        }


        //turn the path into a string
        let path_string = match path.to_str(){

            Ok(path) => path,

            Err(e) => e

        };

        //create Option for file
        match File::create(path_string){
            Ok(file) => self.file = Some(file),
            Err(e) => self.file =  None,
        };
    }

    pub fn save_file(&mut self)  {
        let mut stdout = io::stdout();

        let mut prompt : String = String::from("Save output to local file\nfile name ->");


        loop {
            writeln!(&mut stdout, "{}", prompt.as_str())
                .expect("Unable to write prompt");

            io::stdin().read_line(&mut prompt)
                .expect("Unable to read prompt");

            self.file_exists()


        }

    }


    pub fn write_to_file(&self){

    }

    pub fn file_exists(&mut self){



    }
}