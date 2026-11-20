//! Skulls & Bones Linux PAM & NSS Authentication Module (`pam_sb.so` / `libnss_sb.so`).
//!
//! Communicates with the local `sb-node-agent` OS Auth Broker over `/run/sb-node/auth.sock`
//! (with fallback to `~/.sb/domain/auth.sock`) — no LDAP/LDAPS or Kerberos required.

use serde::Deserialize;
#[cfg(unix)]
use serde::Serialize;
use std::ffi::{c_char, c_int, c_void, CStr};
#[cfg(unix)]
use std::io::{BufRead, BufReader, Write};

const PAM_SUCCESS: c_int = 0;
const PAM_AUTH_ERR: c_int = 7;
const PAM_USER_UNKNOWN: c_int = 10;

#[cfg(unix)]
#[derive(Serialize)]
struct BrokerReq<'a> {
    username: &'a str,
    password: &'a str,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct BrokerResp {
    allowed: bool,
    #[serde(default)]
    is_local_admin: bool,
}

#[cfg(unix)]
fn query_broker(username: &str, password: &str) -> Result<BrokerResp, ()> {
    use std::os::unix::net::UnixStream;
    let sock = if std::path::Path::new("/run/sb-node/auth.sock").exists() {
        "/run/sb-node/auth.sock".to_string()
    } else {
        return Err(());
    };
    let mut stream = UnixStream::connect(sock).map_err(|_| ())?;
    let line = serde_json::to_string(&BrokerReq { username, password }).map_err(|_| ())?;
    stream
        .write_all(format!("{line}\n").as_bytes())
        .map_err(|_| ())?;
    stream.flush().map_err(|_| ())?;
    let mut reader = BufReader::new(stream);
    let mut resp_line = String::new();
    reader.read_line(&mut resp_line).map_err(|_| ())?;
    serde_json::from_str::<BrokerResp>(resp_line.trim()).map_err(|_| ())
}

#[cfg(not(unix))]
fn query_broker(_username: &str, _password: &str) -> Result<BrokerResp, ()> {
    Err(())
}

#[cfg(target_os = "linux")]
#[link(name = "pam")]
extern "C" {
    fn pam_get_user(pamh: *mut c_void, user: *mut *const c_char, prompt: *const c_char) -> c_int;
    fn pam_get_authtok(
        pamh: *mut c_void,
        item_type: c_int,
        authtok: *mut *const c_char,
        prompt: *const c_char,
    ) -> c_int;
}

#[cfg(target_os = "linux")]
const PAM_AUTHTOK_ITEM: c_int = 6;

#[cfg(target_os = "linux")]
unsafe fn read_pam_credentials(pamh: *mut c_void) -> (Option<String>, Option<String>) {
    let mut user_ptr: *const c_char = std::ptr::null();
    let user = if !pamh.is_null()
        && pam_get_user(pamh, &mut user_ptr, std::ptr::null()) == PAM_SUCCESS
        && !user_ptr.is_null()
    {
        CStr::from_ptr(user_ptr).to_str().ok().map(String::from)
    } else {
        None
    };
    let mut tok_ptr: *const c_char = std::ptr::null();
    let pass = if !pamh.is_null()
        && pam_get_authtok(pamh, PAM_AUTHTOK_ITEM, &mut tok_ptr, std::ptr::null()) == PAM_SUCCESS
        && !tok_ptr.is_null()
    {
        CStr::from_ptr(tok_ptr).to_str().ok().map(String::from)
    } else {
        None
    };
    (user, pass)
}

/// Standard Linux PAM entry point (`pam_sm_authenticate`).
///
/// # Safety
/// Called by `libpam` with valid C pointers (`pamh`, `argv`).
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut c_void,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    #[cfg(target_os = "linux")]
    let (mut user_opt, mut pass_opt) = read_pam_credentials(pamh);
    #[cfg(not(target_os = "linux"))]
    let (mut user_opt, pass_opt) = {
        let _ = pamh;
        (None::<String>, None::<String>)
    };

    if user_opt.is_none() {
        user_opt = std::env::var("PAM_USER").ok();
    }
    #[cfg(target_os = "linux")]
    if pass_opt.is_none() {
        pass_opt = std::env::var("PAM_AUTHTOK").ok();
    }
    #[cfg(not(target_os = "linux"))]
    let pass_opt = pass_opt.or_else(|| std::env::var("PAM_AUTHTOK").ok());

    if !argv.is_null() && argc > 0 {
        for i in 0..(argc as isize) {
            let ptr = *argv.offset(i);
            if !ptr.is_null() {
                if let Ok(s) = CStr::from_ptr(ptr).to_str() {
                    if let Some(u) = s.strip_prefix("user=") {
                        user_opt = Some(u.to_string());
                    }
                }
            }
        }
    }
    let (Some(user), Some(pass)) = (user_opt, pass_opt) else {
        return PAM_USER_UNKNOWN;
    };
    match query_broker(&user, &pass) {
        Ok(resp) if resp.allowed => {
            let _ = resp.is_local_admin;
            PAM_SUCCESS
        }
        _ => PAM_AUTH_ERR,
    }
}

/// Standard Linux PAM credential hook (`pam_sm_setcred`).
#[no_mangle]
pub extern "C" fn pam_sm_setcred(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}

/// Standard Linux PAM account check (`pam_sm_acct_mgmt`).
#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut c_void,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PAM_SUCCESS
}
