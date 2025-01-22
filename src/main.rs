use std::ffi::{CStr, CString, OsStr};
use std::os::unix::process::CommandExt;
use std::process;
use std::process::Command;

use pam::Client;
use pam::Conversation;
use rpassword::read_password;
use uzers::get_user_by_name;

mod cli;
mod binary_parser;
mod json_parser;

// A simple struct to implement the trait
struct PamConv {
    username: Option<String>,
}

impl PamConv {
    fn new() -> Self {
        PamConv { username: None }
    }

    fn username_as_osstr(&self) -> &OsStr {
        self.username
            .as_ref()
            .map(OsStr::new)
            .unwrap_or(OsStr::new("")) 
    }
}

impl Conversation for PamConv {
    fn prompt_echo(&mut self, msg: &CStr) -> Result<CString, ()> {
        let msg_str = msg.to_str().unwrap(); 
        println!("{}", msg_str);
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).map_err(|_| ())?;
        input.pop();
        self.username = Some(input.clone());
        Ok(CString::new(input).map_err(|_| ())?)
    }

    fn prompt_blind(&mut self, msg: &CStr) -> Result<CString, ()> {
        let msg_str = msg.to_str().unwrap();
        println!("{}", msg_str);
        let password = read_password().map_err(|_| ())?;
        Ok(CString::new(password).map_err(|_| ())?)
    }

    fn info(&mut self, msg: &CStr) {
        println!("{}", msg.to_str().unwrap());
    }

    fn error(&mut self, msg: &CStr) {
        eprintln!("{}", msg.to_str().unwrap());
    }
    fn prompt_binary(&mut self, msg: &CStr) -> Result<*mut i8, ()> {
        let pam_ext = binary_parser::parse(msg);
        let auth_mechs = json_parser::parse(&pam_ext.json);
        let reply = cli::ui(auth_mechs.unwrap());
        let auth_sel = json_parser::format(reply);
        Ok(binary_parser::format(auth_sel))
    }
}


fn main() {
    let conv = PamConv::new();
    let mut client = Client::with_conversation("system-auth", conv).expect("Failed to init PAM client.");

    // Actually try to authenticate
    match client.authenticate() {
        Ok(()) => println!("Authentication successful!"),
        Err(e) => {
            eprintln!("PAM authentication error: {}", e);
            process::exit(1);
        }
    }
    // Now that we are authenticated, it's possible to open a sesssion
    match client.open_session() {
        Ok(()) => println!("Session opened successfully!"),
        Err(e) => {
            eprintln!("Failed to open a session: {}", e);
            process::exit(1);
        }
    }

    let conv = client.conversation();
    let username_osstr = conv.username_as_osstr();
    let user = get_user_by_name(&username_osstr).unwrap();
    println!("username {:?}, uid {}, gid {}", user.name(), user.uid(), user.primary_group_id());

    // we now try to spawn `/bin/bash` as this user
    // note that setting the uid/gid is likely to fail if this program is not already run as the
    // proper user or as root
    let error = Command::new("/bin/bash")
        .uid(user.uid())
        .gid(user.primary_group_id())
        .exec();
    // if exec() returned, this means there was an error:
    println!("Error spawning bash: {:?}", error);
}
