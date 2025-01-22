use rpassword::read_password;

use crate::json_parser;

fn auth_options(mechs: json_parser::Mechanisms) -> Vec<String> {
    let mut auth_options: Vec<String> = Vec::new();

    if mechs.password.is_some() {
        auth_options.push(mechs.password.clone().unwrap().role);
    }
    if mechs.eidp.is_some() {
        auth_options.push(mechs.eidp.clone().unwrap().role);
    }
    if mechs.smartcard1.is_some() {
        auth_options.push(mechs.smartcard1.clone().unwrap().role);
    }
    if mechs.smartcard2.is_some() {
        auth_options.push(mechs.smartcard2.clone().unwrap().role);
    }
    if mechs.passkey.is_some() {
        auth_options.push(mechs.passkey.clone().unwrap().role);
    }

    println!("Select authentication mechanism:");
    for (index, s) in auth_options.iter().enumerate() {
        println!("{}: {}", index+1, s);
    }

    return auth_options;
}

fn password_ui(data: json_parser::Password) -> json_parser::Reply {
    println!("{} ", data.prompt);
    let password = read_password().map_err(|_| ());

    json_parser::Reply::new(
        String::from("Ok"),
        data.role,
        Some(password.unwrap()),
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

fn eidp_ui(data: json_parser::Oauth2) -> json_parser::Reply {
    println!("{} ", data.link_prompt);
    println!("Uri: {} ", data.uri);
    println!("Code: {} ", data.code);
    println!("Press enter when finished");
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input).map_err(|_| ());

    json_parser::Reply::new(
        String::from("Ok"),
        data.role,
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )
}

fn smartcard_ui(data: json_parser::Smartcard) -> json_parser::Reply {
    println!("{} ", data.init_instruction);
    let mut input = String::new();
    let _ = std::io::stdin().read_line(&mut input).map_err(|_| ());
    println!("{} ", data.pin_prompt);
    let pin = read_password().map_err(|_| ());

    json_parser::Reply::new(
        String::from("Ok"),
        "smartcard:1".to_string(),
        Some(pin.unwrap()),
        Some(data.name),
        Some(data.module_name),
        Some(data.key_id),
        Some(data.label),
        None,
        None,
    )
}

fn passkey_ui(data: json_parser::Passkey) -> json_parser::Reply {
    let mut input = String::new();
    println!("{} ", data.init_instruction);
    let _ = std::io::stdin().read_line(&mut input).map_err(|_| ());
    println!("{} ", data.pin_prompt);
    let pin = read_password().map_err(|_| ());
    println!("{} ", data.touch_instruction);

    json_parser::Reply::new(
        String::from("Ok"),
        data.role,
        Some(pin.unwrap()),
        None,
        None,
        None,
        None,
        Some(data.kerberos),
        Some(data.crypto_challenge),
    )
}

pub fn ui(auth_sel: json_parser::AuthSelection) -> json_parser::Reply {
    let mechs = auth_sel.auth_selection.mechanisms;

    let auth_options = auth_options(mechs.clone());
    
    let mut selection_str = String::new();
    let _ = std::io::stdin().read_line(&mut selection_str).map_err(|_| ());
    selection_str = selection_str.trim().to_string();
    let selection: usize = selection_str.parse::<usize>().unwrap() - 1;

    if auth_options[selection] == "password" {
        password_ui(mechs.password.unwrap())
    } else if auth_options[selection] == "eidp" {
        eidp_ui(mechs.eidp.unwrap())
    } else if auth_options[selection] == "smartcard" {
        smartcard_ui(mechs.smartcard1.unwrap())
    } else {
        passkey_ui(mechs.passkey.unwrap())
    }
}