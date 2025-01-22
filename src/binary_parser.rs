use std::ffi::CString;
use std::slice;
use std::ffi::CStr;
use std::ffi::c_char;
use std::convert::TryInto;

use libc::{c_void, memcpy, malloc};

pub struct GdmPamExtensionJSONProtocol {
    pub protocol_name: String,
    pub version: u32,
    pub json: String,
}

impl GdmPamExtensionJSONProtocol {
    pub fn new() -> Self {
        Self {
            protocol_name: String::new(),
            version: 0,
            json: String::new(),
        }
    }
}

pub fn parse(msg: &CStr) -> GdmPamExtensionJSONProtocol {
    let raw_ptr = msg.as_ptr();

    let mut pam_extension = GdmPamExtensionJSONProtocol::new();

    // Length (4 bytes)
    // Type (2 bytes)
    // Data (2 bytes)

    // Protocol_name (64 bytes)
    pam_extension.protocol_name = unsafe {
        let protocol_name_slice = slice::from_raw_parts(raw_ptr.add(8), 64);
        let protocol_name_slice = protocol_name_slice.split(|&c| c == 0).next().unwrap();
        let protocol_name_slice: &[u8] = protocol_name_slice
            .iter()
            .map(|&i| i as u8)
            .collect::<Vec<u8>>()
            .leak();
        std::str::from_utf8(protocol_name_slice)
            .unwrap()
            .to_owned()
    };

    // Version (4 bytes)
    pam_extension.version = unsafe {
        let version_slice = slice::from_raw_parts(raw_ptr.add(72), 4);
        let version_array: [i8; 4] = version_slice.try_into().unwrap();
        let version_array_u8: [u8; 4] = version_array.map(|i| i as u8);
        u32::from_le_bytes(version_array_u8)
    };

    // Padding (4 bytes)

    // Pointer to the JSON msg (8 bytes)
    let ptr_bytes: &[u8; 8] = unsafe {
        let ptr = slice::from_raw_parts(raw_ptr.add(80), 8).as_ptr();
        (ptr as *const [u8; 8])
            .as_ref()
            .unwrap()
    };
    let extracted_ptr = u64::from_ne_bytes(*ptr_bytes);
    let c_string = unsafe { CStr::from_ptr(extracted_ptr as *const c_char) };
    pam_extension.json = match c_string.to_str() {
        Ok(rust_string) => {
            println!("json-pam receives: {}", rust_string);
            rust_string.to_owned()
        }
        Err(e) => {
            eprintln!("Error converting to string: {}", e);
            String::new()
        }
    };

    return pam_extension;
}

pub fn format(msg: String) -> *mut i8 {
    let length: i32 = 88;
    let mut slice = Vec::with_capacity(length.try_into().unwrap());

    // Add the length (4 bytes)
    slice.extend_from_slice(&length.to_be_bytes());

    // Add padding for type and data (4 bytes)
    let padding: u32 = 0;
    slice.extend_from_slice(&padding.to_ne_bytes());

    // Add the protocol_name (64 bytes)
    let name_bytes = "auth-mechanisms".as_bytes();
    let name_len = std::cmp::min(name_bytes.len(), 64);
    slice.extend_from_slice(&name_bytes[..name_len]);
    slice.resize(64+4+4, 0);

    // Add the version (4 bytes)
    let version: u32 = 1;
    slice.extend_from_slice(&version.to_ne_bytes());

    // Add padding (4 bytes)
    slice.extend_from_slice(&padding.to_ne_bytes());

    // Add the pointer to the JSON msg (8 bytes)
    let ptr_length = msg.len();
    let ptr = unsafe { malloc(ptr_length+1) }; // Allocate space for the string + NULL terminator
    unsafe { 
        memcpy(ptr, msg.as_ptr() as *const c_void, ptr_length); 
        let null_terminator_ptr = ptr.add(ptr_length) as *mut u8;
        *null_terminator_ptr = 0;
    }
    slice.extend_from_slice(&(ptr as usize).to_ne_bytes());

    let c_string = unsafe { CString::from_vec_unchecked(slice) };
    c_string.into_raw()
}