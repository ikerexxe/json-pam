use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Serialize, Deserialize)]
struct Person {
    name: String,
    age: u8,
    phones: Vec<String>,
}


#[derive(Clone, Serialize, Deserialize)]
pub struct Password {
    pub name: String,
    pub role: String,
    selectable: bool,
    pub prompt: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Oauth2 {
    pub name: String,
    pub role: String,
    selectable: bool,
    pub init_prompt: String,
    pub link_prompt: String,
    pub uri: String,
    pub code: String,
    timeout: i32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Smartcard {
    pub name: String,
    pub role: String,
    selectable: bool,
    pub init_instruction: String,
    cert_instruction: String,
    pub pin_prompt: String,
    pub module_name: String,
    pub key_id: String,
    pub label: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Passkey {
    pub name: String,
    pub role: String,
    selectable: bool,
    pub init_instruction: String,
    pin_request: bool,
    pin_attempts: i32,
    pub pin_prompt: String,
    pub touch_instruction: String,
    pub kerberos: bool,
    pub crypto_challenge: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Mechanisms {
    pub password: Option<Password>,
    pub eidp: Option<Oauth2>,
    #[serde(rename = "smartcard:1")]
    pub smartcard1: Option<Smartcard>,
    #[serde(rename = "smartcard:2")]
    pub smartcard2: Option<Smartcard>,
    pub passkey: Option<Passkey>,
}

#[derive(Serialize, Deserialize)]
pub struct AuthSelectionInner {
    pub mechanisms: Mechanisms,
    pub priority: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct AuthSelection {
    #[serde(rename = "auth-selection")]
    pub auth_selection: AuthSelectionInner,
}

pub struct Reply {
    status: String,
    mechanism: String,
    secret: Option<String>,
    name: Option<String>,
    module_name: Option<String>,
    key_id: Option<String>,
    label: Option<String>,
    kerberos: Option<bool>,
    crypto_challenge: Option<String>,
}

impl Reply {
    pub fn new(status: String, mechanism: String, secret: Option<String>,
               name: Option<String>, module_name: Option<String>,
               key_id: Option<String>, label: Option<String>,
               kerberos: Option<bool>, crypto_challenge: Option<String>) -> Self {
        Self {
            status: status,
            mechanism: mechanism,
            secret: secret,
            name: name,
            module_name: module_name,
            key_id: key_id,
            label: label,
            kerberos: kerberos,
            crypto_challenge: crypto_challenge
        }
    }
}

pub fn parse(json: &str) -> Option<AuthSelection> {
    match serde_json::from_str::<AuthSelection>(&json) {
        Ok(auth_sel) => {
            println!("Success parsing JSON");
            Some(auth_sel)
        }
        Err(e) => {
            println!("Error parsing JSON: {}", e);
            None
        }
    }
}

fn format_password(reply: Reply) -> String {
    json!({
        "auth-selection": {
            "status": reply.status,
            reply.mechanism: {
                "password": reply.secret,
            }
        }
    }).to_string()
}

fn format_smartcard(reply: Reply) -> String {
    json!({
        "auth-selection": {
            "status": reply.status,
            reply.mechanism: {
                "pin": reply.secret,
                "name": reply.name,
                "module_name": reply.module_name,
                "key_id": reply.key_id,
                "label": reply.label,
            }
        }
    }).to_string()
}

fn format_passkey(reply: Reply) -> String {
    json!({
        "auth-selection": {
            "status": reply.status,
            reply.mechanism: {
                "pin": reply.secret,
                "kerberos": reply.kerberos,
                "crypto_challenge": reply.crypto_challenge,
            }
        }
    }).to_string()
}

fn format_eidp(reply: Reply) -> String {
    json!({
        "auth-selection": {
            "status": reply.status,
            reply.mechanism: {}
        }
    }).to_string()
}

pub fn format(reply: Reply) -> String {
    let json = if reply.mechanism == "password" {
        format_password(reply)
    } else if reply.mechanism.contains("smartcard") {
        format_smartcard(reply)
    } else if reply.mechanism == "passkey" {
        format_passkey(reply)
    } else {
        format_eidp(reply)
    };

    println!("json-pam sends: {}", json);

    json
}

#[cfg(test)]
mod tests {
    use super::*;

    // Request
    const AUTH_SELECTION_PASSWORD: &str = r#"
    {
        "auth-selection": {
            "mechanisms": {
                "password": {
                    "name": "Password",
                    "role": "password",
                    "selectable": true,
                    "prompt": "Password"
                }
            },
            "priority": ["password"]
        }
    }"#;
    const AUTH_SELECTION_OAUTH2: &str = r#"
    {
        "auth-selection": {
            "mechanisms": {
                "eidp": {
                    "name": "Web Login",
                    "role": "eidp",
                    "selectable": true,
                    "init_prompt": "Log In",
                    "link_prompt": "Log in online with another device",
                    "uri": "short.url.com/tmp",
                    "code": "1234-5678",
                    "timeout": 300
                }
            },
            "priority": ["eidp"]
        }
    }"#;
    const AUTH_SELECTION_SC1: &str = r#"
    {
        "auth-selection": {
            "mechanisms": {
                "smartcard:1": {
                    "name": "sc1",
                    "role": "smartcard",
                    "selectable": true,
                    "init_instruction": "Insert smartcard",
                    "cert_instruction": "Certificate for PIV Authentication\nCN=sc1,O=GDM.TEST",
                    "pin_prompt": "Smartcard PIN",
                    "module_name": "/usr/lib64/pkcs11/opensc-pkcs11.so",
                    "key_id": "01",
                    "label": "Certificate for PIV Authentication"
                }
            },
            "priority": ["sc1"]
        }
    }"#;
    const AUTH_SELECTION_SC2: &str = r#"
    {
        "auth-selection": {
            "mechanisms": {
                "smartcard:1": {
                    "name": "sc1",
                    "role": "smartcard",
                    "selectable": true,
                    "init_instruction": "Insert smartcard",
                    "cert_instruction": "Certificate for PIV Authentication\nCN=sc1,O=GDM.TEST",
                    "pin_prompt": "Smartcard PIN",
                    "module_name": "/usr/lib64/pkcs11/opensc-pkcs11.so",
                    "key_id": "01",
                    "label": "Certificate for PIV Authentication"
                },
                "smartcard:2": {
                    "name": "sc2",
                    "role": "smartcard",
                    "selectable": true,
                    "init_instruction": "Insert smartcard",
                    "cert_instruction": "Certificate for PIV Authentication\nCN=sc2,O=GDM.TEST",
                    "pin_prompt": "Smartcard PIN",
                    "module_name": "/usr/lib64/pkcs11/opensc-pkcs11.so",
                    "key_id": "02",
                    "label": "Certificate for PIV Authentication"
                }
            },
            "priority": ["smartcard:1", "smartcard:2"]
        }
    }"#;
    const AUTH_SELECTION_PASSKEY: &str = r#"
    {
        "auth-selection": {
            "mechanisms": {
                "passkey": {
                    "name": "passkey",
                    "role": "passkey",
                    "selectable": true,
                    "init_instruction": "Insert security key",
                    "pin_request": true,
                    "pin_attempts": 8,
                    "pin_prompt": "Security key PIN",
                    "touch_instruction": "Touch security key",
                    "kerberos": true,
                    "crypto_challenge": "6uDMvRKj3W5xJV3HaQjZrtXMNmUUAjRGklFG2MIhN5s="
                }
            },
            "priority": ["passkey"]
        }
    }"#;
    const AUTH_SELECTION_ALL: &str = r#"
    {
        "auth-selection": {
            "mechanisms": {
                "password": {
                    "name": "Password",
                    "role": "password",
                    "selectable": true,
                    "prompt": "Password"
                },
                "eidp": {
                    "name": "Web Login",
                    "role": "eidp",
                    "selectable": true,
                    "init_prompt": "Log In",
                    "link_prompt": "Log in online with another device",
                    "uri": "short.url.com/tmp",
                    "code": "1234-5678",
                    "timeout": 300
                },
                "smartcard:1": {
                    "name": "sc1",
                    "role": "smartcard",
                    "selectable": true,
                    "init_instruction": "Insert smartcard",
                    "cert_instruction": "Certificate for PIV Authentication\nCN=sc1,O=GDM.TEST",
                    "pin_prompt": "Smartcard PIN",
                    "module_name": "/usr/lib64/pkcs11/opensc-pkcs11.so",
                    "key_id": "01",
                    "label": "Certificate for PIV Authentication"
                },
                "smartcard:2": {
                    "name": "sc2",
                    "role": "smartcard",
                    "selectable": true,
                    "init_instruction": "Insert smartcard",
                    "cert_instruction": "Certificate for PIV Authentication\nCN=sc2,O=GDM.TEST",
                    "pin_prompt": "Smartcard PIN",
                    "module_name": "/usr/lib64/pkcs11/opensc-pkcs11.so",
                    "key_id": "02",
                    "label": "Certificate for PIV Authentication"
                },
                "passkey": {
                    "name": "passkey",
                    "role": "passkey",
                    "selectable": true,
                    "init_instruction": "Insert security key",
                    "pin_request": true,
                    "pin_attempts": 8,
                    "pin_prompt": "Security key PIN",
                    "touch_instruction": "Touch security key",
                    "kerberos": true,
                    "crypto_challenge": "6uDMvRKj3W5xJV3HaQjZrtXMNmUUAjRGklFG2MIhN5s="
                }
            },
            "priority": ["passkey", "eidp", "smartcard:1", "smartcard:2", "password"]
        }
    }"#;

    // Reply
    const AUTH_REPLY_PASSWORD: &str = r#"{"auth-selection":{"status":"Ok","password":{"password":"ThePassword"}}}"#;
    const AUTH_REPLY_OAUTH2: &str = r#"{"auth-selection":{"status":"Ok","eidp":{}}}"#;
    const AUTH_REPLY_SMARTCARD: &str = r#"{"auth-selection":{"status":"Ok","smartcard:1":{"pin":"ThePIN","name":"sc1","module_name":"/usr/lib64/pkcs11/opensc-pkcs11.so","key_id":"01","label":"Certificate for PIV Authentication"}}}"#;
    const AUTH_REPLY_PASSKEY: &str = r#"{"auth-selection":{"status":"Ok","passkey":{"pin":"ThePIN","kerberos":true,"crypto_challenge":"6uDMvRKj3W5xJV3HaQjZrtXMNmUUAjRGklFG2MIhN5s="}}}"#;

    #[test]
    fn test_parse_password() {
        let auth_sel = parse(AUTH_SELECTION_PASSWORD);
        assert!(auth_sel.is_some());
        let auth_sel = auth_sel.unwrap();

        let password = &auth_sel.auth_selection.mechanisms.password;
        assert!(password.is_some());

        let password = password.as_ref().unwrap();
        assert_eq!(password.name, "Password");
        assert_eq!(password.role, "password");
        assert_eq!(password.selectable, true);
        assert_eq!(password.prompt, "Password");

        let priority = &auth_sel.auth_selection.priority;
        assert_eq!(priority[0], "password");
    }

    #[test]
    fn test_parse_oauth2() {
        let auth_sel = parse(AUTH_SELECTION_OAUTH2);
        assert!(auth_sel.is_some());
        let auth_sel = auth_sel.unwrap();

        let eidp = &auth_sel.auth_selection.mechanisms.eidp;
        assert!(eidp.is_some());

        let eidp = eidp.as_ref().unwrap();
        assert_eq!(eidp.name, "Web Login");
        assert_eq!(eidp.role, "eidp");
        assert_eq!(eidp.selectable, true);
        assert_eq!(eidp.init_prompt, "Log In");
        assert_eq!(eidp.link_prompt, "Log in online with another device");
        assert_eq!(eidp.uri, "short.url.com/tmp");
        assert_eq!(eidp.code, "1234-5678");
        assert_eq!(eidp.timeout, 300);

        let priority = &auth_sel.auth_selection.priority;
        assert_eq!(priority[0], "eidp");
    }

    #[test]
    fn test_parse_sc1() {
        let auth_sel = parse(AUTH_SELECTION_SC1);
        assert!(auth_sel.is_some());
        let auth_sel = auth_sel.unwrap();

        let sc1 = &auth_sel.auth_selection.mechanisms.smartcard1;
        assert!(sc1.is_some());

        let sc1 = sc1.as_ref().unwrap();
        assert_eq!(sc1.name, "sc1");
        assert_eq!(sc1.role, "smartcard");
        assert_eq!(sc1.selectable, true);
        assert_eq!(sc1.init_instruction, "Insert smartcard");
        assert_eq!(sc1.cert_instruction, "Certificate for PIV Authentication\nCN=sc1,O=GDM.TEST");
        assert_eq!(sc1.pin_prompt, "Smartcard PIN");
        assert_eq!(sc1.module_name, "/usr/lib64/pkcs11/opensc-pkcs11.so");
        assert_eq!(sc1.key_id, "01");
        assert_eq!(sc1.label, "Certificate for PIV Authentication");

        let priority = &auth_sel.auth_selection.priority;
        assert_eq!(priority[0], "sc1");
    }

    #[test]
    fn test_parse_sc2() {
        let auth_sel = parse(AUTH_SELECTION_SC2);
        assert!(auth_sel.is_some());
        let auth_sel = auth_sel.unwrap();

        let sc1 = &auth_sel.auth_selection.mechanisms.smartcard1;
        assert!(sc1.is_some());
        let sc2 = &auth_sel.auth_selection.mechanisms.smartcard2;
        assert!(sc2.is_some());

        let sc1 = sc1.as_ref().unwrap();
        assert_eq!(sc1.name, "sc1");
        assert_eq!(sc1.role, "smartcard");
        assert_eq!(sc1.selectable, true);
        assert_eq!(sc1.init_instruction, "Insert smartcard");
        assert_eq!(sc1.cert_instruction, "Certificate for PIV Authentication\nCN=sc1,O=GDM.TEST");
        assert_eq!(sc1.pin_prompt, "Smartcard PIN");
        assert_eq!(sc1.module_name, "/usr/lib64/pkcs11/opensc-pkcs11.so");
        assert_eq!(sc1.key_id, "01");
        assert_eq!(sc1.label, "Certificate for PIV Authentication");

        let sc2 = sc2.as_ref().unwrap();
        assert_eq!(sc2.name, "sc2");
        assert_eq!(sc2.role, "smartcard");
        assert_eq!(sc2.selectable, true);
        assert_eq!(sc2.init_instruction, "Insert smartcard");
        assert_eq!(sc2.cert_instruction, "Certificate for PIV Authentication\nCN=sc2,O=GDM.TEST");
        assert_eq!(sc2.pin_prompt, "Smartcard PIN");
        assert_eq!(sc2.module_name, "/usr/lib64/pkcs11/opensc-pkcs11.so");
        assert_eq!(sc2.key_id, "02");
        assert_eq!(sc2.label, "Certificate for PIV Authentication");

        let priority = &auth_sel.auth_selection.priority;
        assert_eq!(priority[0], "smartcard:1");
        assert_eq!(priority[1], "smartcard:2");
    }

    #[test]
    fn test_parse_passkey() {
        let auth_sel = parse(AUTH_SELECTION_PASSKEY);
        assert!(auth_sel.is_some());
        let auth_sel = auth_sel.unwrap();

        let passkey = &auth_sel.auth_selection.mechanisms.passkey;
        assert!(passkey.is_some());

        let passkey = passkey.as_ref().unwrap();
        assert_eq!(passkey.name, "passkey");
        assert_eq!(passkey.role, "passkey");
        assert_eq!(passkey.selectable, true);
        assert_eq!(passkey.init_instruction, "Insert security key");
        assert_eq!(passkey.pin_request, true);
        assert_eq!(passkey.pin_attempts, 8);
        assert_eq!(passkey.pin_prompt, "Security key PIN");
        assert_eq!(passkey.touch_instruction, "Touch security key");
        assert_eq!(passkey.kerberos, true);
        assert_eq!(passkey.crypto_challenge, "6uDMvRKj3W5xJV3HaQjZrtXMNmUUAjRGklFG2MIhN5s=");

        let priority = &auth_sel.auth_selection.priority;
        assert_eq!(priority[0], "passkey");
    }

    #[test]
    fn test_parse_all() {
        let auth_sel = parse(AUTH_SELECTION_ALL);
        assert!(auth_sel.is_some());
        let auth_sel = auth_sel.unwrap();

        let password = &auth_sel.auth_selection.mechanisms.password;
        assert!(password.is_some());

        let password = password.as_ref().unwrap();
        assert_eq!(password.name, "Password");
        assert_eq!(password.role, "password");
        assert_eq!(password.selectable, true);
        assert_eq!(password.prompt, "Password");

        let eidp = &auth_sel.auth_selection.mechanisms.eidp;
        assert!(eidp.is_some());

        let eidp = eidp.as_ref().unwrap();
        assert_eq!(eidp.name, "Web Login");
        assert_eq!(eidp.role, "eidp");
        assert_eq!(eidp.selectable, true);
        assert_eq!(eidp.init_prompt, "Log In");
        assert_eq!(eidp.link_prompt, "Log in online with another device");
        assert_eq!(eidp.uri, "short.url.com/tmp");
        assert_eq!(eidp.code, "1234-5678");
        assert_eq!(eidp.timeout, 300);

        let sc1 = &auth_sel.auth_selection.mechanisms.smartcard1;
        assert!(sc1.is_some());
        let sc2 = &auth_sel.auth_selection.mechanisms.smartcard2;
        assert!(sc2.is_some());

        let sc1 = sc1.as_ref().unwrap();
        assert_eq!(sc1.name, "sc1");
        assert_eq!(sc1.role, "smartcard");
        assert_eq!(sc1.selectable, true);
        assert_eq!(sc1.init_instruction, "Insert smartcard");
        assert_eq!(sc1.cert_instruction, "Certificate for PIV Authentication\nCN=sc1,O=GDM.TEST");
        assert_eq!(sc1.pin_prompt, "Smartcard PIN");
        assert_eq!(sc1.module_name, "/usr/lib64/pkcs11/opensc-pkcs11.so");
        assert_eq!(sc1.key_id, "01");
        assert_eq!(sc1.label, "Certificate for PIV Authentication");

        let sc2 = sc2.as_ref().unwrap();
        assert_eq!(sc2.name, "sc2");
        assert_eq!(sc2.role, "smartcard");
        assert_eq!(sc2.selectable, true);
        assert_eq!(sc2.init_instruction, "Insert smartcard");
        assert_eq!(sc2.cert_instruction, "Certificate for PIV Authentication\nCN=sc2,O=GDM.TEST");
        assert_eq!(sc2.pin_prompt, "Smartcard PIN");
        assert_eq!(sc2.module_name, "/usr/lib64/pkcs11/opensc-pkcs11.so");
        assert_eq!(sc2.key_id, "02");
        assert_eq!(sc2.label, "Certificate for PIV Authentication");

        let passkey = &auth_sel.auth_selection.mechanisms.passkey;
        assert!(passkey.is_some());

        let passkey = passkey.as_ref().unwrap();
        assert_eq!(passkey.name, "passkey");
        assert_eq!(passkey.role, "passkey");
        assert_eq!(passkey.selectable, true);
        assert_eq!(passkey.init_instruction, "Insert security key");
        assert_eq!(passkey.pin_request, true);
        assert_eq!(passkey.pin_attempts, 8);
        assert_eq!(passkey.pin_prompt, "Security key PIN");
        assert_eq!(passkey.touch_instruction, "Touch security key");
        assert_eq!(passkey.kerberos, true);
        assert_eq!(passkey.crypto_challenge, "6uDMvRKj3W5xJV3HaQjZrtXMNmUUAjRGklFG2MIhN5s=");

        let priority = &auth_sel.auth_selection.priority;
        assert_eq!(priority[0], "passkey");
        assert_eq!(priority[1], "eidp");
        assert_eq!(priority[2], "smartcard:1");
        assert_eq!(priority[3], "smartcard:2");
        assert_eq!(priority[4], "password");
    }

    #[test]
    fn test_format_password() {
        let reply = Reply::new(
            String::from("Ok"),
            "password".to_string(),
            Some("ThePassword".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let reply = format(reply);
        assert_eq!(reply, AUTH_REPLY_PASSWORD);
    }

    #[test]
    fn test_format_oauth2() {
        let reply = Reply::new(
            String::from("Ok"),
            "eidp".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        let reply = format(reply);
        assert_eq!(reply, AUTH_REPLY_OAUTH2);
    }

    #[test]
    fn test_format_sc() {
        let reply = Reply::new(
            String::from("Ok"),
            "smartcard:1".to_string(),
            Some("ThePIN".to_string()),
            Some("sc1".to_string()),
            Some("/usr/lib64/pkcs11/opensc-pkcs11.so".to_string()),
            Some("01".to_string()),
            Some("Certificate for PIV Authentication".to_string()),
            None,
            None,
        );
        let reply = format(reply);
        assert_eq!(reply, AUTH_REPLY_SMARTCARD);
    }

    #[test]
    fn test_format_passkey() {
        let reply = Reply::new(
            String::from("Ok"),
            "passkey".to_string(),
            Some("ThePIN".to_string()),
            None,
            None,
            None,
            None,
            Some(true),
            Some("6uDMvRKj3W5xJV3HaQjZrtXMNmUUAjRGklFG2MIhN5s=".to_string())
        );
        let reply_str = format(reply);
        assert_eq!(reply_str, AUTH_REPLY_PASSKEY);
    }
}