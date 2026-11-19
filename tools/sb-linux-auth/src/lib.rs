//! Skulls & Bones Linux PAM & NSS Authentication Module (`pam_sb.so` / `libnss_sb.so`).
//!
//! Communicates with the local `sb-node-agent` OS Auth Broker over `/run/sb-node/auth.sock`
//! (with fallback to `~/.sb/domain/auth.sock`) — no LDAP/LDAPS or Kerberos required.

use serde::{Deserialize, Serialize};
use std::ffi::{c_char, c_int, c_void, CStr};
use std::io::{BufRead, BufReader, Write};

const PAM_SUCCESS: c_int = 0;
const PAM_AUTH_ERR: c_int = 7;
const PAM_USER_UNKNOWN: c_int = 10;

#[derive(Serialize)]
struct BrokerReq<'a> {
    username: &'a str,
    password: &'a str,
}

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

/// Standard Linux PAM entry point (`pam_sm_authenticate`).
///
/// # Safety
/// Called by `libpam` with valid C pointers (`pamh`, `argv`).
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    _pamh: *mut c_void,
    _flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // Expected arguments or PAM conversation: supports `user=<name>` / `SB_AUTH_TEST` or PAM env.
    let mut user_opt: Option<String> = std::env::var("PAM_USER").ok();
    let pass_opt: Option<String> = std::env::var("PAM_AUTHTOK").ok();
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
pub extern "C" fn pam_sm_setcred(_pamh: *mut c_void, _flags: c_int, _argc: c_int, _argv: *const *const c_char) -> c_int {
    PAM_SUCCESS
}

/// Standard Linux PAM account check (`pam_sm_acct_mgmt`).
#[no_mangle]
pub extern "C" fn pam_sm_acct_mgmt(_pamh: *mut c_void, _flags: c_int, _argc: c_int, _argv: *const *const c_char) -> c_int {
    PAM_SUCCESS
}
