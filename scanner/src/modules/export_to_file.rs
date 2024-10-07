use std::{
    fs::File,
    io::{self, Error, Write},
    path::Path
};

use crate::modules::menu;
use crate::modules::menu::user_input;

pub struct ExportToTextFile {
    file_name : String,
}


impl ExportToTextFile {
    pub fn new() -> Self {
        Self{
            file_name : String::new(),
        }
    }


    pub fn create_new_file(&mut self)-> Result<File, Error> {


        File::create(self.file_name.as_str())
    }

    pub fn save_file(&mut self)  {
        let mut stdout = io::stdout();

        let mut prompt : String = String::from("Save output to local file\nfile name ->");

        self.file_name.clear();

        loop {
            writeln!(&mut stdout, "{}", prompt.as_str()).expect("Unable to write prompt");

            user_input(&mut self.file_name);

            self.file_exists()


        }

    }


    pub fn write_to_file(&self){

    }

    pub fn file_exists(&mut self){


        let mut file_number : usize = 0;

        let path: &Path = Path::new(self.file_name.as_str());

        while path.exists(){

            file_number += 1;

            // self.file_name.push_str(format!("{}({})", self.file_name, file_number).as_str());

        }
    }
}