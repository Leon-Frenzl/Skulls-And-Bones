//! Skulls & Bones Windows Credential Provider COM DLL (`sb_cred_provider.dll`).
//!
//! Exposes a native Windows LogonUI tile ("Bei Skulls & Bones anmelden") backed by
//! the local `sb-node-agent` OS Auth Broker (`\\.\pipe\sb-node-auth`).

#![cfg(windows)]

use serde::{Deserialize, Serialize};
use std::ffi::c_void;
use std::fs::OpenOptions;
use std::io::{BufRead, BufReader, Write};
use std::sync::{Arc, Mutex};
use windows::core::{implement, w, Error, Interface, GUID, HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    BOOL, CLASS_E_CLASSNOTAVAILABLE, E_INVALIDARG, E_NOTIMPL, E_POINTER, HINSTANCE, NTSTATUS,
    S_FALSE, S_OK,
};
use windows::Win32::Security::Authentication::Identity::{
    LsaConnectUntrusted, LsaDeregisterLogonProcess, LsaLookupAuthenticationPackage, LSA_STRING,
};
use windows::Win32::Security::Credentials::{CredPackAuthenticationBufferW, CRED_PACK_FLAGS};
use windows::Win32::System::Com::{CoTaskMemAlloc, IClassFactory, IClassFactory_Impl};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::Registry::{
    RegCloseKey, RegCreateKeyExW, RegDeleteTreeW, RegSetValueExW, HKEY, HKEY_CLASSES_ROOT,
    HKEY_LOCAL_MACHINE, KEY_WRITE, REG_OPTION_NON_VOLATILE, REG_SZ,
};
use windows::Win32::UI::Shell::{
    ICredentialProvider, ICredentialProviderCredential, ICredentialProviderCredentialEvents,
    ICredentialProviderCredential_Impl, ICredentialProviderEvents, ICredentialProvider_Impl,
    CPFIS_FOCUSED, CPFIS_NONE, CPFS_DISPLAY_IN_BOTH, CPFS_DISPLAY_IN_SELECTED_TILE,
    CPFS_HIDDEN, CPFT_EDIT_TEXT, CPFT_LARGE_TEXT, CPFT_PASSWORD_TEXT, CPFT_SUBMIT_BUTTON,
    CPGSR_NO_CREDENTIAL_NOT_FINISHED, CPGSR_RETURN_CREDENTIAL_FINISHED,
    CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION, CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR,
    CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE, CREDENTIAL_PROVIDER_FIELD_STATE,
    CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE, CREDENTIAL_PROVIDER_STATUS_ICON,
    CREDENTIAL_PROVIDER_USAGE_SCENARIO, CPUS_CREDUI, CPUS_LOGON, CPUS_UNLOCK_WORKSTATION,
};

/// {7B9A5D12-4F8E-4B1D-9A2E-8C1F4D2A6B10}
pub const CLSID_SB_CRED_PROVIDER: GUID = GUID::from_u128(0x7b9a5d12_4f8e_4b1d_9a2e_8c1f4d2a6b10);
const CLSID_STR: PCWSTR = w!("{7B9A5D12-4F8E-4B1D-9A2E-8C1F4D2A6B10}");
const PROVIDER_NAME: PCWSTR = w!("Skulls & Bones Sovereign Login");

static mut MODULE_HANDLE: HINSTANCE = HINSTANCE(std::ptr::null_mut());

#[derive(Serialize)]
struct BrokerAuthReq<'a> {
    username: &'a str,
    password: &'a str,
}

#[derive(Deserialize)]
struct BrokerAuthResp {
    allowed: bool,
    #[serde(default)]
    username: String,
    #[serde(default)]
    error: String,
}

fn query_local_broker(username: &str, password: &str) -> Result<BrokerAuthResp, String> {
    let mut pipe = OpenOptions::new()
        .read(true)
        .write(true)
        .open(r"\\.\pipe\sb-node-auth")
        .map_err(|e| format!("sb-node-agent Auth-Broker nicht erreichbar: {e}"))?;
    let line = serde_json::to_string(&BrokerAuthReq { username, password })
        .map_err(|e| e.to_string())?;
    pipe.write_all(format!("{line}\n").as_bytes())
        .map_err(|e| e.to_string())?;
    pipe.flush().map_err(|e| e.to_string())?;
    let mut reader = BufReader::new(pipe);
    let mut resp_line = String::new();
    reader
        .read_line(&mut resp_line)
        .map_err(|e| e.to_string())?;
    serde_json::from_str::<BrokerAuthResp>(resp_line.trim()).map_err(|e| e.to_string())
}

unsafe fn alloc_co_task_pwstr(s: &str) -> windows::core::Result<PWSTR> {
    let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
    let byte_len = wide.len() * 2;
    let ptr = CoTaskMemAlloc(byte_len) as *mut u16;
    if ptr.is_null() {
        return Err(Error::from(E_POINTER));
    }
    std::ptr::copy_nonoverlapping(wide.as_ptr(), ptr, wide.len());
    Ok(PWSTR(ptr))
}

/// Packs `username` and `password` into a `CoTaskMemAlloc`-allocated
/// `KERB_INTERACTIVE_UNLOCK_LOGON` buffer with relative offsets via `CredPackAuthenticationBufferW`.
unsafe fn pack_interactive_credentials(
    username: &str,
    password: &str,
) -> Result<(*mut u8, u32), String> {
    let mut user_w: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
    let mut pass_w: Vec<u16> = password.encode_utf16().chain(std::iter::once(0)).collect();
    let mut cb: u32 = 0;
    let _ = CredPackAuthenticationBufferW(
        CRED_PACK_FLAGS(0),
        PWSTR(user_w.as_mut_ptr()),
        PWSTR(pass_w.as_mut_ptr()),
        None,
        &mut cb,
    );
    if cb == 0 {
        return Err("CredPackAuthenticationBufferW lieferte Länge 0".into());
    }
    let raw = CoTaskMemAlloc(cb as usize) as *mut u8;
    if raw.is_null() {
        return Err("CoTaskMemAlloc fehlgeschlagen".into());
    }
    std::ptr::write_bytes(raw, 0, cb as usize);
    if CredPackAuthenticationBufferW(
        CRED_PACK_FLAGS(0),
        PWSTR(user_w.as_mut_ptr()),
        PWSTR(pass_w.as_mut_ptr()),
        Some(raw),
        &mut cb,
    )
    .is_err()
    {
        windows::Win32::System::Com::CoTaskMemFree(Some(raw as *const c_void));
        return Err("CredPackAuthenticationBufferW fehlgeschlagen".into());
    }
    Ok((raw, cb))
}

#[derive(Default)]
struct CredFields {
    username: String,
    password: String,
    last_error: String,
}

#[implement(ICredentialProviderCredential)]
struct SBCredential {
    state: Arc<Mutex<CredFields>>,
}

impl ICredentialProviderCredential_Impl for SBCredential_Impl {
    fn Advise(
        &self,
        _pcpce: windows::core::Ref<'_, ICredentialProviderCredentialEvents>,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn UnAdvise(&self) -> windows::core::Result<()> {
        Ok(())
    }

    fn SetSelected(&self) -> windows::core::Result<BOOL> {
        Ok(false.into())
    }

    fn SetDeselected(&self) -> windows::core::Result<()> {
        Ok(())
    }

    fn GetFieldState(
        &self,
        dwfieldid: u32,
        pcpfs: *mut CREDENTIAL_PROVIDER_FIELD_STATE,
        pcpfis: *mut CREDENTIAL_PROVIDER_FIELD_INTERACTIVE_STATE,
    ) -> windows::core::Result<()> {
        if pcpfs.is_null() || pcpfis.is_null() {
            return Err(Error::from(E_POINTER));
        }
        unsafe {
            match dwfieldid {
                0 => {
                    *pcpfs = CPFS_DISPLAY_IN_BOTH;
                    *pcpfis = CPFIS_NONE;
                }
                1 => {
                    *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
                    *pcpfis = CPFIS_FOCUSED;
                }
                2 => {
                    *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
                    *pcpfis = CPFIS_NONE;
                }
                3 => {
                    *pcpfs = CPFS_DISPLAY_IN_SELECTED_TILE;
                    *pcpfis = CPFIS_NONE;
                }
                _ => {
                    *pcpfs = CPFS_HIDDEN;
                    *pcpfis = CPFIS_NONE;
                }
            }
        }
        Ok(())
    }

    fn GetStringValue(&self, dwfieldid: u32) -> windows::core::Result<PWSTR> {
        let guard = self.state.lock().map_err(|_| Error::from(E_FAIL))?;
        let val = match dwfieldid {
            0 => "Bei Skulls & Bones anmelden",
            1 => guard.username.as_str(),
            2 => guard.password.as_str(),
            3 => "Anmelden",
            _ => return Err(Error::from(E_INVALIDARG)),
        };
        unsafe { alloc_co_task_pwstr(val) }
    }

    fn GetBitmapValue(&self, _dwfieldid: u32) -> windows::core::Result<windows::Win32::Graphics::Gdi::HBITMAP> {
        Err(Error::from(E_NOTIMPL))
    }

    fn GetCheckboxValue(
        &self,
        _dwfieldid: u32,
        _pbchecked: *mut BOOL,
        _ppszlabel: *mut PWSTR,
    ) -> windows::core::Result<()> {
        Err(Error::from(E_NOTIMPL))
    }

    fn GetSubmitButtonValue(&self, dwfieldid: u32) -> windows::core::Result<u32> {
        if dwfieldid == 3 {
            Ok(2)
        } else {
            Err(Error::from(E_INVALIDARG))
        }
    }

    fn GetComboBoxValueCount(
        &self,
        _dwfieldid: u32,
        _pcitems: *mut u32,
        _pdwselecteditem: *mut u32,
    ) -> windows::core::Result<()> {
        Err(Error::from(E_NOTIMPL))
    }

    fn GetComboBoxValueAt(&self, _dwfieldid: u32, _dwitem: u32) -> windows::core::Result<PWSTR> {
        Err(Error::from(E_NOTIMPL))
    }

    fn SetStringValue(&self, dwfieldid: u32, psz: &PCWSTR) -> windows::core::Result<()> {
        let text = unsafe { psz.to_string().unwrap_or_default() };
        let mut guard = self.state.lock().map_err(|_| Error::from(E_FAIL))?;
        match dwfieldid {
            1 => guard.username = text,
            2 => guard.password = text,
            _ => return Err(Error::from(E_INVALIDARG)),
        }
        Ok(())
    }

    fn SetCheckboxValue(&self, _dwfieldid: u32, _bchecked: BOOL) -> windows::core::Result<()> {
        Err(Error::from(E_NOTIMPL))
    }

    fn SetComboBoxSelectedValue(&self, _dwfieldid: u32, _dwselecteditem: u32) -> windows::core::Result<()> {
        Err(Error::from(E_NOTIMPL))
    }

    fn CommandLinkClicked(&self, _dwfieldid: u32) -> windows::core::Result<()> {
        Err(Error::from(E_NOTIMPL))
    }

    fn GetSerialization(
        &self,
        pcpgsr: *mut CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE,
        pcpcs: *mut CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
        ppszoptionalstatustext: *mut PWSTR,
        pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> windows::core::Result<()> {
        if pcpgsr.is_null() || pcpcs.is_null() {
            return Err(Error::from(E_POINTER));
        }
        unsafe {
            std::ptr::write_bytes(pcpcs, 0, 1);
            if !ppszoptionalstatustext.is_null() {
                *ppszoptionalstatustext = PWSTR::null();
            }
        }
        let (user, pass) = {
            let guard = self.state.lock().map_err(|_| Error::from(E_FAIL))?;
            (guard.username.clone(), guard.password.clone())
        };

        if user.trim().is_empty() || pass.is_empty() {
            unsafe {
                *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                if !ppszoptionalstatustext.is_null() {
                    *ppszoptionalstatustext =
                        alloc_co_task_pwstr("Bitte Benutzername und Passwort eingeben.")?;
                }
                if !pcpsioptionalstatusicon.is_null() {
                    *pcpsioptionalstatusicon = windows::Win32::UI::Shell::CPSI_WARNING;
                }
            }
            return Ok(());
        }

        let resp = match query_local_broker(&user, &pass) {
            Ok(r) => r,
            Err(e) => {
                unsafe {
                    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                    if !ppszoptionalstatustext.is_null() {
                        *ppszoptionalstatustext = alloc_co_task_pwstr(&e)?;
                    }
                    if !pcpsioptionalstatusicon.is_null() {
                        *pcpsioptionalstatusicon =
                            windows::Win32::UI::Shell::CPSI_ERROR;
                    }
                }
                return Ok(());
            }
        };

        if !resp.allowed {
            let msg = if resp.error.is_empty() {
                "Anmeldung abgelehnt".to_string()
            } else {
                resp.error
            };
            unsafe {
                *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                if !ppszoptionalstatustext.is_null() {
                    *ppszoptionalstatustext = alloc_co_task_pwstr(&msg)?;
                }
                if !pcpsioptionalstatusicon.is_null() {
                    *pcpsioptionalstatusicon = windows::Win32::UI::Shell::CPSI_ERROR;
                }
            }
            return Ok(());
        }

        // Pack KERB_INTERACTIVE_UNLOCK_LOGON using CredPackAuthenticationBufferW so all
        // LSA_UNICODE_STRING.Buffer fields are relative offsets valid across winlogon/lsass.
        unsafe {
            let mut lsa_handle = windows::Win32::Foundation::HANDLE::default();
            if LsaConnectUntrusted(&mut lsa_handle).is_err() {
                *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                return Ok(());
            }
            let pkg_name = b"Negotiate";
            let lsa_str = LSA_STRING {
                Length: pkg_name.len() as u16,
                MaximumLength: pkg_name.len() as u16,
                Buffer: windows::core::PSTR(pkg_name.as_ptr() as *mut u8),
            };
            let mut auth_pkg: u32 = 0;
            let pkg_res = LsaLookupAuthenticationPackage(lsa_handle, &lsa_str, &mut auth_pkg);
            let _ = LsaDeregisterLogonProcess(lsa_handle);
            if pkg_res.is_err() || auth_pkg == 0 {
                *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                if !ppszoptionalstatustext.is_null() {
                    *ppszoptionalstatustext =
                        alloc_co_task_pwstr("Negotiate-Authentifizierungspaket nicht gefunden.")?;
                }
                return Ok(());
            }

            let local_user = format!(".\\{}", resp.username);
            let (raw, total) = match pack_interactive_credentials(&local_user, &pass) {
                Ok(v) => v,
                Err(msg) => {
                    *pcpgsr = CPGSR_NO_CREDENTIAL_NOT_FINISHED;
                    if !ppszoptionalstatustext.is_null() {
                        *ppszoptionalstatustext = alloc_co_task_pwstr(&msg)?;
                    }
                    if !pcpsioptionalstatusicon.is_null() {
                        *pcpsioptionalstatusicon = windows::Win32::UI::Shell::CPSI_ERROR;
                    }
                    return Ok(());
                }
            };

            *pcpcs = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION {
                ulAuthenticationPackage: auth_pkg,
                clsidCredentialProvider: CLSID_SB_CRED_PROVIDER,
                cbSerialization: total,
                rgbSerialization: raw,
            };
            *pcpgsr = CPGSR_RETURN_CREDENTIAL_FINISHED;
        }
        Ok(())
    }

    fn ReportResult(
        &self,
        _ntsstatus: NTSTATUS,
        _ntssubstatus: NTSTATUS,
        _ppszoptionalstatustext: *mut PWSTR,
        _pcpsioptionalstatusicon: *mut CREDENTIAL_PROVIDER_STATUS_ICON,
    ) -> windows::core::Result<()> {
        Ok(())
    }
}

use windows::Win32::Foundation::E_FAIL;

#[implement(ICredentialProvider)]
struct SBCredentialProvider {
    cred: ICredentialProviderCredential,
}

impl SBCredentialProvider {
    fn new() -> Self {
        let cred: ICredentialProviderCredential = SBCredential {
            state: Arc::new(Mutex::new(CredFields::default())),
        }
        .into();
        Self { cred }
    }
}

impl ICredentialProvider_Impl for SBCredentialProvider_Impl {
    fn SetUsageScenario(
        &self,
        cpus: CREDENTIAL_PROVIDER_USAGE_SCENARIO,
        _dwflags: u32,
    ) -> windows::core::Result<()> {
        if cpus == CPUS_LOGON || cpus == CPUS_UNLOCK_WORKSTATION || cpus == CPUS_CREDUI {
            Ok(())
        } else {
            Err(Error::from(E_NOTIMPL))
        }
    }

    fn SetSerialization(
        &self,
        _pcpcs: *const CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn Advise(
        &self,
        _pcpe: windows::core::Ref<'_, ICredentialProviderEvents>,
        _upadvisecontext: usize,
    ) -> windows::core::Result<()> {
        Ok(())
    }

    fn UnAdvise(&self) -> windows::core::Result<()> {
        Ok(())
    }

    fn GetFieldDescriptorCount(&self) -> windows::core::Result<u32> {
        Ok(4)
    }

    fn GetFieldDescriptorAt(
        &self,
        dwindex: u32,
    ) -> windows::core::Result<*mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR> {
        let (ftype, label) = match dwindex {
            0 => (CPFT_LARGE_TEXT, "Bei Skulls & Bones anmelden"),
            1 => (CPFT_EDIT_TEXT, "Benutzername"),
            2 => (CPFT_PASSWORD_TEXT, "Passwort"),
            3 => (CPFT_SUBMIT_BUTTON, "Anmelden"),
            _ => return Err(Error::from(E_INVALIDARG)),
        };
        unsafe {
            let desc = CoTaskMemAlloc(std::mem::size_of::<CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR>())
                as *mut CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR;
            if desc.is_null() {
                return Err(Error::from(E_POINTER));
            }
            *desc = CREDENTIAL_PROVIDER_FIELD_DESCRIPTOR {
                dwFieldID: dwindex,
                cpft: ftype,
                pszLabel: alloc_co_task_pwstr(label)?,
                guidFieldType: GUID::zeroed(),
            };
            Ok(desc)
        }
    }

    fn GetCredentialCount(
        &self,
        pdwcount: *mut u32,
        pdwdefault: *mut u32,
        pbautologonwithdefault: *mut BOOL,
    ) -> windows::core::Result<()> {
        unsafe {
            *pdwcount = 1;
            *pdwdefault = 0;
            *pbautologonwithdefault = false.into();
        }
        Ok(())
    }

    fn GetCredentialAt(&self, dwindex: u32) -> windows::core::Result<ICredentialProviderCredential> {
        if dwindex != 0 {
            return Err(Error::from(E_INVALIDARG));
        }
        Ok(self.cred.clone())
    }
}

#[implement(IClassFactory)]
struct SBClassFactory;

impl IClassFactory_Impl for SBClassFactory_Impl {
    fn CreateInstance(
        &self,
        _punkouter: windows::core::Ref<'_, windows::core::IUnknown>,
        riid: *const GUID,
        ppvobject: *mut *mut c_void,
    ) -> windows::core::Result<()> {
        let provider: ICredentialProvider = SBCredentialProvider::new().into();
        unsafe { provider.query(riid, ppvobject).ok() }
    }

    fn LockServer(&self, _flock: BOOL) -> windows::core::Result<()> {
        Ok(())
    }
}

#[no_mangle]
pub unsafe extern "system" fn DllMain(
    hinst: HINSTANCE,
    reason: u32,
    _reserved: *mut c_void,
) -> bool {
    if reason == 1 {
        MODULE_HANDLE = hinst;
    }
    true
}

#[no_mangle]
pub unsafe extern "system" fn DllGetClassObject(
    rclsid: *const GUID,
    riid: *const GUID,
    ppv: *mut *mut c_void,
) -> HRESULT {
    if rclsid.is_null() || riid.is_null() || ppv.is_null() {
        return E_POINTER;
    }
    if *rclsid != CLSID_SB_CRED_PROVIDER {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    let factory: IClassFactory = SBClassFactory.into();
    factory.query(riid, ppv)
}

#[no_mangle]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    S_FALSE
}

fn reg_write_sz(root: HKEY, subkey: PCWSTR, value_name: Option<PCWSTR>, data: &[u16]) -> HRESULT {
    unsafe {
        let mut hkey = HKEY::default();
        if RegCreateKeyExW(
            root,
            subkey,
            None,
            None,
            REG_OPTION_NON_VOLATILE,
            KEY_WRITE,
            None,
            &mut hkey,
            None,
        )
        .is_err()
        {
            return E_FAIL;
        }
        let bytes = std::slice::from_raw_parts(data.as_ptr() as *const u8, data.len() * 2);
        let res = RegSetValueExW(
            hkey,
            value_name.unwrap_or(PCWSTR::null()),
            None,
            REG_SZ,
            Some(bytes),
        );
        let _ = RegCloseKey(hkey);
        if res.is_ok() {
            S_OK
        } else {
            E_FAIL
        }
    }
}

#[no_mangle]
pub unsafe extern "system" fn DllRegisterServer() -> HRESULT {
    let mut path_buf = [0u16; 512];
    let len = GetModuleFileNameW(Some(MODULE_HANDLE.into()), &mut path_buf) as usize;
    if len == 0 {
        return E_FAIL;
    }
    let dll_path = &path_buf[..=len];
    let name_w: Vec<u16> = "Skulls & Bones Sovereign Login"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let apt_w: Vec<u16> = "Apartment".encode_utf16().chain(std::iter::once(0)).collect();

    let clsid_key: Vec<u16> = format!("CLSID\\{{7B9A5D12-4F8E-4B1D-9A2E-8C1F4D2A6B10}}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let inproc_key: Vec<u16> =
        format!("CLSID\\{{7B9A5D12-4F8E-4B1D-9A2E-8C1F4D2A6B10}}\\InprocServer32")
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
    let cp_key: Vec<u16> = format!(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{{7B9A5D12-4F8E-4B1D-9A2E-8C1F4D2A6B10}}"
    )
    .encode_utf16()
    .chain(std::iter::once(0))
    .collect();

    let _ = reg_write_sz(HKEY_CLASSES_ROOT, PCWSTR(clsid_key.as_ptr()), None, &name_w);
    let _ = reg_write_sz(
        HKEY_CLASSES_ROOT,
        PCWSTR(inproc_key.as_ptr()),
        None,
        dll_path,
    );
    let _ = reg_write_sz(
        HKEY_CLASSES_ROOT,
        PCWSTR(inproc_key.as_ptr()),
        Some(w!("ThreadingModel")),
        &apt_w,
    );
    reg_write_sz(HKEY_LOCAL_MACHINE, PCWSTR(cp_key.as_ptr()), None, &name_w)
}

#[no_mangle]
pub unsafe extern "system" fn DllUnregisterServer() -> HRESULT {
    let clsid_key: Vec<u16> = format!("CLSID\\{{7B9A5D12-4F8E-4B1D-9A2E-8C1F4D2A6B10}}")
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let cp_key: Vec<u16> = format!(
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{{7B9A5D12-4F8E-4B1D-9A2E-8C1F4D2A6B10}}"
    )
    .encode_utf16()
    .chain(std::iter::once(0))
    .collect();
    let _ = RegDeleteTreeW(HKEY_CLASSES_ROOT, PCWSTR(clsid_key.as_ptr()));
    let _ = RegDeleteTreeW(HKEY_LOCAL_MACHINE, PCWSTR(cp_key.as_ptr()));
    let _ = (CLSID_STR, PROVIDER_NAME);
    S_OK
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Security::Authentication::Identity::KERB_INTERACTIVE_UNLOCK_LOGON;

    #[test]
    fn cred_pack_authentication_buffer_uses_relative_offsets() {
        unsafe {
            let (raw, cb) = pack_interactive_credentials(".\\leon.admin", "TestPass!123")
                .expect("CredPackAuthenticationBufferW must succeed");
            assert!(cb as usize > std::mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>());
            let logon = &*(raw as *const KERB_INTERACTIVE_UNLOCK_LOGON);
            let user_offset = logon.Logon.UserName.Buffer.0 as usize;
            let pass_offset = logon.Logon.Password.Buffer.0 as usize;
            assert!(
                user_offset >= std::mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>()
                    && user_offset < cb as usize,
                "UserName.Buffer must be a relative offset inside the packed buffer, got {user_offset}"
            );
            assert!(
                pass_offset >= std::mem::size_of::<KERB_INTERACTIVE_UNLOCK_LOGON>()
                    && pass_offset < cb as usize,
                "Password.Buffer must be a relative offset inside the packed buffer, got {pass_offset}"
            );
            windows::Win32::System::Com::CoTaskMemFree(Some(raw as *const c_void));
        }
    }

    #[test]
    fn com_lifecycle_and_empty_input_guard() {
        unsafe {
            let provider: ICredentialProvider = SBCredentialProvider::new().into();
            provider.SetUsageScenario(CPUS_LOGON, 0).unwrap();
            assert_eq!(provider.GetFieldDescriptorCount().unwrap(), 4);

            for idx in 0..4 {
                let desc = provider.GetFieldDescriptorAt(idx).unwrap();
                assert_eq!((*desc).dwFieldID, idx);
                windows::Win32::System::Com::CoTaskMemFree(Some((*desc).pszLabel.0 as *const c_void));
                windows::Win32::System::Com::CoTaskMemFree(Some(desc as *const c_void));
            }

            let mut count = 0;
            let mut default_idx = 0;
            let mut autologon = BOOL(1);
            provider
                .GetCredentialCount(&mut count, &mut default_idx, &mut autologon)
                .unwrap();
            assert_eq!(count, 1);
            assert!(!autologon.as_bool());

            let cred = provider.GetCredentialAt(0).unwrap();
            let sel_autologon = cred.SetSelected().unwrap();
            assert!(!sel_autologon.as_bool(), "SetSelected must NOT auto-logon");
            assert_eq!(cred.GetSubmitButtonValue(3).unwrap(), 2);

            let mut resp = CREDENTIAL_PROVIDER_GET_SERIALIZATION_RESPONSE::default();
            let mut ser = CREDENTIAL_PROVIDER_CREDENTIAL_SERIALIZATION::default();
            let mut status_text = PWSTR::null();
            let mut status_icon = CREDENTIAL_PROVIDER_STATUS_ICON::default();
            cred.GetSerialization(&mut resp, &mut ser, &mut status_text, &mut status_icon)
                .unwrap();
            assert_eq!(resp, CPGSR_NO_CREDENTIAL_NOT_FINISHED);
            assert!(!status_text.is_null());
            windows::Win32::System::Com::CoTaskMemFree(Some(status_text.0 as *const c_void));
        }
    }
}
