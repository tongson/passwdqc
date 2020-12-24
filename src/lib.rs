use std::ffi::CStr;
use std::os::raw::{c_char, c_uint};
use std::panic;

extern crate serde_json;
extern crate zxcvbn;
use serde::Deserialize;
use serde_json::from_slice;
use zxcvbn::zxcvbn;

#[no_mangle]
pub extern "C" fn score(c: *const c_char) -> c_uint {
  panic::set_hook(Box::new(move |_| eprintln!("panic: passwdqc.score()")));
  #[derive(Deserialize)]
  struct Args {
    password: String,
    inputs: Vec<String>,
  }
  let cb = unsafe { CStr::from_ptr(c).to_bytes() };
  let v: Args = match from_slice(cb) {
    Ok(jv) => jv,
    Err(_) => return 5,
  };
  let i: Vec<_> = v.inputs.iter().map(String::as_str).collect();
  let _: () = match zxcvbn(&v.password, &i) {
    Ok(entropy) => return entropy.score().into(),
    Err(_) => return 5,
  };
}
