use std::{
    fs::File,
    io::{Error, Write},
    path::Path
};

use crate::modules::menu;
use crate::modules::menu::user_input;

pub struct ExportToTextFile {
    file_name : String,
}


impl ExportToTextFile {
    pub fn new() -> Self {
        Self
    }


    pub fn create_new_file(&mut self, file_name : String)-> Result<File, Error> {


        self.file_exists(file_name);

        File::create(self.file_name.as_str())
    }

    pub fn save_file_menu (&mut self)  {

        let mut input : String = String::from("capture");


        loop {

            user_input(&mut input);



        }

    }


    pub fn write_to_file(&self){

    }

    pub fn file_exists(&mut self,  name : String){

        let mut file_name : String = name;
        let mut file_number : usize = 0;

        let path: &Path = Path::new(file_name.as_str());

        while path.exists(){

            file_number += 1;

            file_name.clear();
            file_name.push_str(format!("{}({})", file_name, file_number).as_str());

        }

        self.file_name.clear();
        self.file_name.push_str(file_name.as_str());


    }



    fn file_name_regex(self, ) -> bool {

        let pattern = r"^[a-zA-Z0-9_\-]+\.[a-zA-Z0-9]+$";




    }
}