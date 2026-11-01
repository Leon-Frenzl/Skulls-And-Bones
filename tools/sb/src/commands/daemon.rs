use colored::Colorize;
use sb_core::daemon_auth::DaemonAuthToken;
use sb_core::dto::*;
use sb_core::ports::DEFAULT_DAEMON_API_PORT;
use sb_core::rpc::{
    error_codes, RpcRequest, RpcResponse, MAX_RPC_HTTP_HEADER_BYTES, MAX_RPC_HTTP_REQUEST_BYTES,
    RPC_METHOD_APPS_INSTALL, RPC_METHOD_APPS_LAUNCH, RPC_METHOD_APPS_LIST, RPC_METHOD_APPS_PREVIEW,
    RPC_METHOD_APPS_ROLLBACK, RPC_METHOD_APPS_UNINSTALL, RPC_METHOD_AUDIT_LIST,
    RPC_METHOD_AUDIT_RECORDING, RPC_METHOD_DRIVE_GET, RPC_METHOD_DRIVE_LIST, RPC_METHOD_DRIVE_READ,
    RPC_METHOD_DRIVE_WRITE, RPC_METHOD_FLEET_LIST, RPC_METHOD_MESH_NODES,
    RPC_METHOD_MESH_OBJECTS_GET, RPC_METHOD_MESH_OBJECTS_LIST, RPC_METHOD_MESH_OBJECTS_PREVIEW,
    RPC_METHOD_MESH_PING, RPC_METHOD_MESH_SET_AIR_GAP, RPC_METHOD_MESH_STATUS,
    RPC_METHOD_SUITE_CATALOG, RPC_METHOD_SUITE_STATUS, RPC_METHOD_TUNNELS_LIST,
    RPC_METHOD_VAULT_CHANGE_PASSWORD, RPC_METHOD_VAULT_DELETE, RPC_METHOD_VAULT_GET,
    RPC_METHOD_VAULT_GET_ALL, RPC_METHOD_VAULT_INITIALIZE, RPC_METHOD_VAULT_LIST,
    RPC_METHOD_VAULT_LOCK, RPC_METHOD_VAULT_SET, RPC_METHOD_VAULT_STATUS, RPC_METHOD_VAULT_UNLOCK,
};
use sb_core::service::{InventoryProductCatalog, ProductCatalogService, SERVICE_API_VERSION};
use sb_core::vault::{VaultSession, VaultStore};
use sb_drive::PeerFilesystem;
use sb_mesh::runtime_status::MeshRuntimeStatus;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{timeout, Duration};
use zeroize::Zeroize;

const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DAEMON_CONNECTIONS: usize = 64;
const MAX_HTTP_REQUEST_BYTES: usize = MAX_RPC_HTTP_REQUEST_BYTES;
const MAX_HTTP_HEADER_BYTES: usize = MAX_RPC_HTTP_HEADER_BYTES;

const MAX_OBJECT_LIST_ENTRIES: usize = 1000;

// CVE-Threat: Confused deputy; a client could ask the daemon to enumerate objects as another device.
// Analysis: The caller supplies no identity; the daemon evaluates ACLs only for its own mesh key.
// Hardening: Identity comes from the fresh runtime status, results are ACL-filtered and bounded,
// and a missing catalog yields an explicit state instead of an error or an unfiltered listing.
fn mesh_objects_list_value() -> Result<Value, String> {
    let Some(status) = load_mesh_runtime_status()? else {
        return Ok(json!({ "state": "offline", "objects": [] }));
    };
    let catalog_path = sb_drive::stream::default_catalog_path(&status.mesh_name)?;
    let store = sb_mesh::MeshObjectCatalogStore::new(catalog_path);
    let Some(catalog) = store.load_optional()? else {
        return Ok(json!({ "state": "no_catalog", "mesh": status.mesh_name, "objects": [] }));
    };
    if !catalog.mesh_id.eq_ignore_ascii_case(&status.mesh_name) {
        return Err("Object catalog belongs to a different mesh".to_string());
    }
    match catalog.visible_summaries_for_authenticated_device(
        &status.local_public_key,
        MAX_OBJECT_LIST_ENTRIES,
    ) {
        Ok(objects) => Ok(json!({ "state": "ok", "mesh": status.mesh_name, "objects": objects })),
        Err(error) => Ok(json!({
            "state": "denied",
            "mesh": status.mesh_name,
            "reason": error,
            "objects": []
        })),
    }
}

const OBJECT_FETCH_TIMEOUT: Duration = Duration::from_secs(120);

fn app_store() -> Result<sb_app_contract::install::AppStore, String> {
    let home = dirs::home_dir().ok_or_else(|| "Cannot resolve the home directory".to_string())?;
    Ok(sb_app_contract::install::AppStore::new(
        home.join(".sb-node").join("apps"),
    ))
}

fn load_trusted_publishers() -> Result<std::collections::BTreeMap<String, [u8; 32]>, String> {
    let home = dirs::home_dir().ok_or_else(|| "Cannot resolve the home directory".to_string())?;
    match std::fs::read(home.join(".sb-node").join("app-publishers.json")) {
        Ok(bytes) => sb_app_contract::install::parse_trusted_publishers(&bytes)
            .map_err(|error| error.to_string()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Default::default()),
        Err(error) => Err(format!("Cannot read publisher trust file: {error}")),
    }
}

// CVE-Threat: Malicious app distribution / confused consent; a mesh object could masquerade as an
// app, or the installer could be tricked into installing a different manifest than the user saw.
// Analysis: Bundle bytes come from a peer; trust anchors are local user configuration only.
// Hardening: ACL-checked, hash-verified fetch; publisher signature against local trust anchors;
// artifact digest pin; consent bound to the manifest digest and the exact requested capabilities;
// installation is not execution — runtime access still needs per-operation grants.
async fn verified_bundle_from_mesh(
    params: &Value,
) -> Result<
    Result<
        (
            sb_app_contract::VerifiedManifest,
            sb_app_contract::install::AppBundle,
        ),
        Value,
    >,
    String,
> {
    let fetched = match fetch_object_to_cache(params).await? {
        Ok(fetched) => fetched,
        Err(state) => return Ok(Err(state)),
    };
    let limit = (sb_app_contract::install::MAX_ARTIFACT_BYTES
        + sb_app_contract::MAX_MANIFEST_BYTES
        + 4096) as u64;
    let size = std::fs::metadata(&fetched.destination)
        .map_err(|error| format!("Cannot inspect fetched bundle: {error}"))?
        .len();
    if size > limit {
        return Ok(Err(
            json!({ "state": "denied", "reason": "Bundle is too large" }),
        ));
    }
    let bytes = std::fs::read(&fetched.destination)
        .map_err(|error| format!("Cannot read fetched bundle: {error}"))?;
    let bundle = match sb_app_contract::install::parse_bundle(&bytes) {
        Ok(bundle) => bundle,
        Err(error) => {
            return Ok(Err(
                json!({ "state": "invalid", "reason": error.to_string() }),
            ));
        }
    };
    let trusted = load_trusted_publishers()?;
    if trusted.is_empty() {
        return Ok(Err(json!({
            "state": "untrusted",
            "reason": "No trusted publishers configured (~/.sb-node/app-publishers.json)"
        })));
    }
    match sb_app_contract::verify_signed_manifest(&bundle.manifest, &bundle.signature_hex, &trusted)
    {
        Ok(verified) => Ok(Ok((verified, bundle))),
        Err(error) => Ok(Err(
            json!({ "state": "untrusted", "reason": error.to_string() }),
        )),
    }
}

fn apps_list_value() -> Result<Value, String> {
    let apps = app_store()?.list().map_err(|error| error.to_string())?;
    Ok(json!({ "state": "ok", "apps": apps }))
}

async fn apps_preview_value(params: &Value) -> Result<Value, String> {
    Ok(match verified_bundle_from_mesh(params).await? {
        Ok((verified, _)) => {
            let manifest = verified.manifest();
            json!({
                "state": "ok",
                "app_id": manifest.app_id,
                "version": manifest.version,
                "publisher_key_id": verified.publisher_key_id(),
                "manifest_digest": verified.manifest_digest(),
                "capabilities": manifest.requested_capabilities,
            })
        }
        Err(state) => state,
    })
}

async fn apps_install_value(params: &Value) -> Result<Value, String> {
    let consent_digest = params
        .get("manifest_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| "Missing 'manifest_digest'".to_string())?;
    let (verified, bundle) = match verified_bundle_from_mesh(params).await? {
        Ok(pair) => pair,
        Err(state) => return Ok(state),
    };
    let consent = sb_app_contract::install::InstallConsent {
        manifest_digest: consent_digest.to_string(),
        granted: verified.manifest().requested_capabilities.clone(),
    };
    let trusted = load_trusted_publishers()?;
    Ok(
        match app_store()?.install(
            &bundle.manifest,
            &bundle.signature_hex,
            &bundle.artifact,
            &trusted,
            &consent,
        ) {
            Ok(app) => json!({ "state": "ok", "app": app }),
            Err(error) => json!({ "state": "denied", "reason": error.to_string() }),
        },
    )
}

fn apps_change_value(
    params: &Value,
    action: fn(
        &sb_app_contract::install::AppStore,
        &str,
    ) -> Result<(), sb_app_contract::install::InstallError>,
) -> Result<Value, String> {
    let app_id = params
        .get("app_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "Missing 'app_id'".to_string())?;
    Ok(match action(&app_store()?, app_id) {
        Ok(()) => json!({ "state": "ok" }),
        Err(error) => json!({ "state": "denied", "reason": error.to_string() }),
    })
}

// CVE-Threat: Post-install binary replacement (TOCTOU) or unsandboxed execution of a mesh app.
// Analysis: An installed app binary sits in the user's home directory and could be modified after
// installation, or could attempt ambient network/filesystem access when launched.
// Hardening: Re-verify SHA-256 via AppStore::verified_artifact_path immediately before launch,
// and spawn the process inside a zero-capability Windows AppContainer + memory/process-limited Job Object
// with zero inherited handles and a minimal environment block.
fn apps_launch_value(params: &Value) -> Result<Value, String> {
    let app_id = params
        .get("app_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "Missing 'app_id'".to_string())?;
    apps_launch_with_store(&app_store()?, app_id)
}

fn apps_launch_with_store(
    store: &sb_app_contract::install::AppStore,
    app_id: &str,
) -> Result<Value, String> {
    let record = match store.current(app_id) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return Ok(json!({ "state": "denied", "reason": "App is not installed" }));
        }
        Err(error) => {
            return Ok(json!({ "state": "denied", "reason": error.to_string() }));
        }
    };
    let artifact_path = match store.verified_artifact_path(app_id) {
        Ok(path) => path,
        Err(error) => {
            return Ok(json!({ "state": "denied", "reason": error.to_string() }));
        }
    };
    match spawn_sandboxed_app(&artifact_path, &record) {
        Ok(pid) => Ok(json!({
            "state": "ok",
            "app_id": record.app_id,
            "version": record.version,
            "pid": pid,
            "sandbox": "windows-appcontainer",
        })),
        Err(reason) => Ok(json!({ "state": "denied", "reason": reason })),
    }
}

#[cfg(windows)]
fn spawn_sandboxed_app(
    artifact_path: &std::path::Path,
    record: &sb_app_contract::install::InstalledApp,
) -> Result<u32, String> {
    use std::ffi::c_void;
    use std::mem::{size_of, zeroed};
    use std::os::windows::ffi::OsStrExt;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{CloseHandle, GetLastError};
    use windows_sys::Win32::Security::Isolation::{
        CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
    };
    use windows_sys::Win32::Security::{FreeSid, SECURITY_CAPABILITIES};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS, JOB_OBJECT_LIMIT_JOB_MEMORY,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    };
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, DeleteProcThreadAttributeList, InitializeProcThreadAttributeList,
        ResumeThread, TerminateProcess, UpdateProcThreadAttribute, WaitForSingleObject,
        CREATE_NO_WINDOW, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
        EXTENDED_STARTUPINFO_PRESENT, INFINITE, PROCESS_INFORMATION,
        PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTUPINFOEXW,
    };

    const HRESULT_ALREADY_EXISTS: i32 = 0x8007_00b7u32 as i32;
    const APP_MEMORY_LIMIT_BYTES: usize = 512 * 1024 * 1024;

    let wide = |text: &str| -> Vec<u16> { text.encode_utf16().chain(Some(0)).collect() };
    let profile_name = wide("SkullsAndBones.AppRuntime");
    let display_name = wide("Skulls & Bones Sandboxed App");
    let description = wide("Zero-capability AppContainer for SB-MAP installed apps");
    let mut sid = null_mut();
    let hr = unsafe {
        CreateAppContainerProfile(
            profile_name.as_ptr(),
            display_name.as_ptr(),
            description.as_ptr(),
            null(),
            0,
            &mut sid,
        )
    };
    if hr < 0 {
        if !sid.is_null() {
            unsafe { FreeSid(sid) };
            sid = null_mut();
        }
        if hr != HRESULT_ALREADY_EXISTS {
            return Err(format!(
                "AppContainer profile creation failed (0x{:08x})",
                hr as u32
            ));
        }
        let derived =
            unsafe { DeriveAppContainerSidFromAppContainerName(profile_name.as_ptr(), &mut sid) };
        if derived < 0 || sid.is_null() {
            if !sid.is_null() {
                unsafe { FreeSid(sid) };
            }
            return Err(format!(
                "AppContainer SID resolution failed (0x{:08x})",
                derived as u32
            ));
        }
    }

    let capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: sid,
        Capabilities: null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };
    let mut attr_size = 0usize;
    unsafe {
        let _ = InitializeProcThreadAttributeList(null_mut(), 1, 0, &mut attr_size);
    }
    if attr_size == 0 {
        unsafe { FreeSid(sid) };
        return Err("Failed to size AppContainer attribute list".into());
    }
    let mut attr_buf = vec![0usize; attr_size.div_ceil(size_of::<usize>())];
    let attr_list = attr_buf.as_mut_ptr().cast();
    if unsafe { InitializeProcThreadAttributeList(attr_list, 1, 0, &mut attr_size) } == 0 {
        unsafe { FreeSid(sid) };
        return Err("Failed to initialize AppContainer attribute list".into());
    }
    if unsafe {
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            (&capabilities as *const SECURITY_CAPABILITIES).cast::<c_void>(),
            size_of::<SECURITY_CAPABILITIES>(),
            null_mut(),
            null(),
        )
    } == 0
    {
        unsafe {
            DeleteProcThreadAttributeList(attr_list);
            FreeSid(sid);
        }
        return Err("Failed to apply AppContainer security capabilities".into());
    }

    let job = unsafe { CreateJobObjectW(null(), null()) };
    if job.is_null() {
        unsafe {
            DeleteProcThreadAttributeList(attr_list);
            FreeSid(sid);
        }
        return Err("Failed to create Job Object for app".into());
    }
    let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
        | JOB_OBJECT_LIMIT_PROCESS_MEMORY
        | JOB_OBJECT_LIMIT_JOB_MEMORY;
    limits.BasicLimitInformation.ActiveProcessLimit = 1;
    limits.ProcessMemoryLimit = APP_MEMORY_LIMIT_BYTES;
    limits.JobMemoryLimit = APP_MEMORY_LIMIT_BYTES;
    if unsafe {
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        unsafe {
            CloseHandle(job);
            DeleteProcThreadAttributeList(attr_list);
            FreeSid(sid);
        }
        return Err("Failed to configure Job Object limits".into());
    }

    let application_name: Vec<u16> = artifact_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut command_line: Vec<u16> = format!("\"{}\"", artifact_path.display())
        .encode_utf16()
        .chain(Some(0))
        .collect();
    let work_dir: Vec<u16> = artifact_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect();
    let mut env_entries: Vec<(String, String)> = ["SystemRoot", "TEMP", "TMP", "WINDIR"]
        .into_iter()
        .filter_map(|k| std::env::var(k).ok().map(|v| (k.to_string(), v)))
        .collect();
    env_entries.push(("SB_APP_ID".to_string(), record.app_id.clone()));
    env_entries.push(("SB_APP_VERSION".to_string(), record.version.clone()));
    env_entries.sort_by(|(a, _), (b, _)| a.to_ascii_lowercase().cmp(&b.to_ascii_lowercase()));
    let mut env_block = Vec::new();
    for (k, v) in env_entries {
        env_block.extend(k.encode_utf16());
        env_block.push(b'=' as u16);
        env_block.extend(v.encode_utf16());
        env_block.push(0);
    }
    env_block.push(0);

    let mut startup: STARTUPINFOEXW = unsafe { zeroed() };
    startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
    startup.lpAttributeList = attr_list;
    let mut process: PROCESS_INFORMATION = unsafe { zeroed() };
    let created = unsafe {
        CreateProcessW(
            application_name.as_ptr(),
            command_line.as_mut_ptr(),
            null(),
            null(),
            0,
            EXTENDED_STARTUPINFO_PRESENT
                | CREATE_UNICODE_ENVIRONMENT
                | CREATE_SUSPENDED
                | CREATE_NO_WINDOW,
            env_block.as_mut_ptr().cast(),
            work_dir.as_ptr(),
            (&startup as *const STARTUPINFOEXW).cast(),
            &mut process,
        )
    };
    let create_err = (created == 0).then(|| unsafe { GetLastError() });
    unsafe {
        DeleteProcThreadAttributeList(attr_list);
        FreeSid(sid);
    }
    if created == 0 {
        unsafe { CloseHandle(job) };
        return Err(format!(
            "Windows refused to launch sandboxed app (Win32 error {})",
            create_err.unwrap_or_default()
        ));
    }
    if unsafe { AssignProcessToJobObject(job, process.hProcess) } == 0 {
        let err = unsafe { GetLastError() };
        unsafe {
            TerminateProcess(process.hProcess, 1);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            CloseHandle(job);
        }
        return Err(format!(
            "Failed to assign app to Job Object (Win32 error {err})"
        ));
    }
    if unsafe { ResumeThread(process.hThread) } == u32::MAX {
        let err = unsafe { GetLastError() };
        unsafe {
            TerminateProcess(process.hProcess, 1);
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
            CloseHandle(job);
        }
        return Err(format!(
            "Failed to resume sandboxed app (Win32 error {err})"
        ));
    }
    let pid = process.dwProcessId;
    unsafe { CloseHandle(process.hThread) };
    let proc_handle = process.hProcess as usize;
    let job_handle = job as usize;
    std::thread::spawn(move || unsafe {
        WaitForSingleObject(proc_handle as *mut c_void, INFINITE);
        CloseHandle(proc_handle as *mut c_void);
        CloseHandle(job_handle as *mut c_void);
    });
    Ok(pid)
}

#[cfg(not(windows))]
fn spawn_sandboxed_app(
    _artifact_path: &std::path::Path,
    _record: &sb_app_contract::install::InstalledApp,
) -> Result<u32, String> {
    Err("OS-level AppContainer sandboxing is required to launch installed apps".into())
}

// CVE-Threat: Confused deputy / path traversal / stale-version replay; a client could make the
// daemon fetch arbitrary objects, versions or write outside the cache.
// Analysis: Identity comes only from the fresh runtime status, the anchor only from the pinned
// join ticket, and the authoritative provider re-checks membership, version and ACL on the stream.
// Hardening: Strict ID validation, local fail-closed Read-ACL and current-version precheck,
// sb-drive provider check, a hash-derived cache name, a bounded timeout and no path in the reply.
async fn mesh_objects_get_value(params: &Value) -> Result<Value, String> {
    Ok(match fetch_object_to_cache(params).await? {
        Ok(fetched) => fetched.meta,
        Err(state) => state,
    })
}

struct FetchedObject {
    destination: PathBuf,
    meta: Value,
}

async fn fetch_object_to_cache(params: &Value) -> Result<Result<FetchedObject, Value>, String> {
    let object_id = params
        .get("object_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "Missing 'object_id'".to_string())?;
    let version_id = params
        .get("version_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "Missing 'version_id'".to_string())?;
    let object_key = sb_mesh::objects::MeshObjectId::new(object_id.to_string())?;
    let version_key = sb_mesh::objects::ObjectVersionId::new(version_id.to_string())?;
    let Some(status) = load_mesh_runtime_status()? else {
        return Ok(Err(json!({ "state": "offline" })));
    };
    let store = sb_mesh::MeshObjectCatalogStore::new(sb_drive::stream::default_catalog_path(
        &status.mesh_name,
    )?);
    let Some(catalog) = store.load_optional()? else {
        return Ok(Err(json!({ "state": "no_catalog" })));
    };
    if !catalog.mesh_id.eq_ignore_ascii_case(&status.mesh_name) {
        return Err("Object catalog belongs to a different mesh".to_string());
    }
    let required = std::collections::BTreeSet::from([sb_mesh::objects::ObjectPermission::Read]);
    let allowed = catalog
        .check_access_for_authenticated_device_key(&object_key, &status.local_public_key, &required)
        .unwrap_or(false);
    let object = catalog.objects.get(&object_key);
    let version = object.filter(|_| allowed).and_then(|object| {
        (object.current_version.as_ref() == Some(&version_key))
            .then(|| {
                object
                    .versions
                    .iter()
                    .find(|version| version.id == version_key)
            })
            .flatten()
    });
    let Some(version) = version else {
        return Ok(Err(
            json!({ "state": "denied", "reason": "Object is not readable at this version" }),
        ));
    };
    if version.payload.provider != "sb-drive" {
        return Ok(Err(
            json!({ "state": "denied", "reason": "Unsupported payload provider" }),
        ));
    }
    let ticket = sb_mesh::ticket::load_cached_ticket(&status.mesh_name)
        .ok_or_else(|| "No valid cached mesh ticket; join the mesh first".to_string())?;
    let anchor: SocketAddr = ticket
        .server_addr
        .parse()
        .map_err(|error| format!("Invalid anchor address in cached ticket: {error}"))?;
    let identity = Arc::new(sb_mesh::identity::NodeIdentity::load_registered_for_mesh(
        &status.mesh_name,
    )?);
    let client = sb_mesh::client::MeshClient::connect(sb_mesh::client::MeshClientConfig {
        mesh_name: status.mesh_name.clone(),
        swarm_topic: status.swarm_topic.clone(),
        anchor_addr: anchor,
        identity,
        local_bind_port: None,
    })
    .await
    .map_err(|error| format!("Mesh connection failed: {error}"))?;
    let cache_name = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(object_id.as_bytes());
        hasher.update([0]);
        hasher.update(version_id.as_bytes());
        format!("{}.bin", hex::encode(hasher.finalize()))
    };
    let app_grant = match params.get("app_grant") {
        None | Some(Value::Null) => None,
        Some(raw) => Some(
            serde_json::from_value::<sb_app_contract::OperationGrant>(raw.clone())
                .map_err(|error| format!("Invalid 'app_grant': {error}"))?,
        ),
    };
    let destination = sb_drive::GhostCache::default().cache_path(&status.mesh_name, &cache_name);
    match timeout(
        OBJECT_FETCH_TIMEOUT,
        sb_drive::stream::download_from_mesh(
            &client,
            &status.mesh_name,
            object_id,
            version_id,
            &destination,
            None,
            app_grant,
        ),
    )
    .await
    {
        Ok(Ok(_)) => Ok(Ok(FetchedObject {
            destination: destination.clone(),
            meta: json!({
                "state": "ok",
                "object_id": object_id,
                "version_id": version_id,
                "size_bytes": version.size_bytes,
                "sha256": hex::encode(version.content_hash),
                "cache_name": cache_name,
            }),
        })),
        Ok(Err(error)) => Ok(Err(json!({ "state": "denied", "reason": error }))),
        Err(_) => Ok(Err(
            json!({ "state": "denied", "reason": "Mesh download timed out" }),
        )),
    }
}

const MAX_OBJECT_PREVIEW_BYTES: usize = 16 * 1024;
const MAX_CACHED_PREVIEW_FILE_BYTES: u64 = 256 * 1024 * 1024;

// CVE-Threat: Arbitrary host file read or stale/revoked cache disclosure via preview RPC.
// Analysis: A sandboxed desktop client requests a preview of a cached mesh object; if the daemon
// trusted caller paths or skipped fresh ACL/digest checks, revoked or tampered files could leak.
// Hardening: Derive cache filename exclusively from SHA-256(object_id \0 version_id), re-verify
// fresh local Mesh RBAC + Read ACL + current catalog version, re-verify cached file size and full
// SHA-256 against the catalog's content_hash, and return a bounded 16 KiB UTF-8 or hex preview
// without exposing any filesystem path.
fn mesh_objects_preview_value(params: &Value) -> Result<Value, String> {
    let object_id = params
        .get("object_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "Missing 'object_id'".to_string())?;
    let version_id = params
        .get("version_id")
        .and_then(Value::as_str)
        .ok_or_else(|| "Missing 'version_id'".to_string())?;
    let object_key = sb_mesh::objects::MeshObjectId::new(object_id.to_string())?;
    let version_key = sb_mesh::objects::ObjectVersionId::new(version_id.to_string())?;
    let Some(status) = load_mesh_runtime_status()? else {
        return Ok(json!({ "state": "offline" }));
    };
    let store = sb_mesh::MeshObjectCatalogStore::new(sb_drive::stream::default_catalog_path(
        &status.mesh_name,
    )?);
    let Some(catalog) = store.load_optional()? else {
        return Ok(json!({ "state": "no_catalog" }));
    };
    if !catalog.mesh_id.eq_ignore_ascii_case(&status.mesh_name) {
        return Err("Object catalog belongs to a different mesh".to_string());
    }
    let required = std::collections::BTreeSet::from([sb_mesh::objects::ObjectPermission::Read]);
    let allowed = catalog
        .check_access_for_authenticated_device_key(&object_key, &status.local_public_key, &required)
        .unwrap_or(false);
    let object = catalog.objects.get(&object_key);
    let version = object.filter(|_| allowed).and_then(|object| {
        (object.current_version.as_ref() == Some(&version_key))
            .then(|| {
                object
                    .versions
                    .iter()
                    .find(|version| version.id == version_key)
            })
            .flatten()
    });
    let Some(version) = version else {
        return Ok(json!({
            "state": "denied",
            "reason": "Object is not readable at this version"
        }));
    };
    let cache_name = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(object_id.as_bytes());
        hasher.update([0]);
        hasher.update(version_id.as_bytes());
        format!("{}.bin", hex::encode(hasher.finalize()))
    };
    let cached_path = sb_drive::GhostCache::default().cache_path(&status.mesh_name, &cache_name);
    preview_cached_object_at_path(
        &cached_path,
        object_id,
        version_id,
        version.size_bytes,
        &version.content_hash,
    )
}

fn preview_cached_object_at_path(
    cached_path: &std::path::Path,
    object_id: &str,
    version_id: &str,
    expected_size: u64,
    expected_sha256: &[u8; 32],
) -> Result<Value, String> {
    let meta = match std::fs::symlink_metadata(cached_path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({
                "state": "not_cached",
                "reason": "Object is not in the local verified cache; download it first"
            }));
        }
        Err(err) => return Err(format!("Cannot inspect cached object: {err}")),
    };
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Ok(json!({
            "state": "denied",
            "reason": "Cached object entry is not a regular file"
        }));
    }
    if meta.len() != expected_size || meta.len() > MAX_CACHED_PREVIEW_FILE_BYTES {
        return Ok(json!({
            "state": "denied",
            "reason": "Cached object size does not match the catalog version"
        }));
    }
    let bytes = std::fs::read(cached_path)
        .map_err(|err| format!("Cannot read cached object payload: {err}"))?;
    if bytes.len() as u64 != expected_size {
        return Ok(json!({
            "state": "denied",
            "reason": "Cached object length changed during read"
        }));
    }
    let actual_hash: [u8; 32] = {
        use sha2::{Digest, Sha256};
        Sha256::digest(&bytes).into()
    };
    if &actual_hash != expected_sha256 {
        return Ok(json!({
            "state": "denied",
            "reason": "Cached object SHA-256 digest mismatch"
        }));
    }
    let truncated = bytes.len() > MAX_OBJECT_PREVIEW_BYTES;
    let slice = &bytes[..bytes.len().min(MAX_OBJECT_PREVIEW_BYTES)];
    let (preview_kind, preview_text) = match std::str::from_utf8(slice) {
        Ok(text) => (
            "utf8",
            text.chars()
                .filter(|c| *c == '\n' || *c == '\r' || *c == '\t' || !c.is_control())
                .collect::<String>(),
        ),
        Err(_) => ("hex", hex::encode(slice)),
    };
    Ok(json!({
        "state": "ok",
        "object_id": object_id,
        "version_id": version_id,
        "size_bytes": expected_size,
        "sha256": hex::encode(expected_sha256),
        "preview_kind": preview_kind,
        "preview_text": preview_text,
        "truncated": truncated,
    }))
}

fn fleet_list_value() -> Result<Value, String> {
    let path = sb_core::paths::servers_config_path();
    if !path.exists() {
        return Ok(json!({ "servers": [] }));
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read fleet server configuration: {e}"))?;
    let parsed: toml::Value = toml::from_str(&content)
        .map_err(|e| format!("Invalid fleet server configuration TOML: {e}"))?;
    let mut servers = Vec::new();
    if let Some(items) = parsed.get("servers").and_then(toml::Value::as_array) {
        for item in items.iter().take(256) {
            let name = item.get("name").and_then(toml::Value::as_str).unwrap_or("");
            let host = item.get("host").and_then(toml::Value::as_str).unwrap_or("");
            let port = item
                .get("port")
                .and_then(toml::Value::as_integer)
                .unwrap_or(22);
            let user = item.get("user").and_then(toml::Value::as_str).unwrap_or("");
            let tags = item
                .get("tags")
                .and_then(toml::Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(toml::Value::as_str)
                        .take(16)
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            if !name.is_empty() && !host.is_empty() {
                servers.push(json!({
                    "name": name,
                    "host": host,
                    "port": port,
                    "user": user,
                    "tags": tags,
                }));
            }
        }
    }
    Ok(json!({ "servers": servers }))
}

fn tunnels_list_value() -> Result<Value, String> {
    let path = sb_core::paths::tunnels_config_path();
    if !path.exists() {
        return Ok(json!({ "tunnels": [] }));
    }
    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("Cannot read tunnels configuration: {e}"))?;
    let parsed: Value = serde_json::from_str(&content)
        .map_err(|e| format!("Invalid tunnels configuration JSON: {e}"))?;
    let mut tunnels = Vec::new();
    if let Some(items) = parsed.as_array() {
        for item in items.iter().take(256) {
            let id = item.get("id").and_then(Value::as_str).unwrap_or("");
            let name = item
                .get("name")
                .or_else(|| item.get("label"))
                .and_then(Value::as_str)
                .unwrap_or(id);
            let local_port = item.get("local_port").and_then(Value::as_u64).unwrap_or(0);
            let remote_host = item
                .get("remote_host")
                .and_then(Value::as_str)
                .unwrap_or("127.0.0.1");
            let remote_port = item.get("remote_port").and_then(Value::as_u64).unwrap_or(0);
            let server = item
                .get("server")
                .or_else(|| item.get("host"))
                .and_then(Value::as_str)
                .unwrap_or("");
            tunnels.push(json!({
                "id": id,
                "name": name,
                "local_port": local_port,
                "remote_host": remote_host,
                "remote_port": remote_port,
                "server": server,
            }));
        }
    }
    Ok(json!({ "tunnels": tunnels }))
}

fn audit_list_value() -> Result<Value, String> {
    let home = sb_core::paths::sb_home();
    let sessions_path = home.join("audit").join("sessions.jsonl");
    let runs_path = home.join("audit").join("runs.jsonl");
    let recordings_dir = home.join("recordings");

    let mut sessions = Vec::new();
    if sessions_path.is_file() {
        if let Ok(content) = std::fs::read_to_string(&sessions_path) {
            for line in content.lines().rev().take(100) {
                if let Ok(val) = serde_json::from_str::<Value>(line) {
                    sessions.push(val);
                }
            }
        }
    }

    let mut runs = Vec::new();
    if runs_path.is_file() {
        if let Ok(content) = std::fs::read_to_string(&runs_path) {
            for line in content.lines().rev().take(100) {
                if let Ok(val) = serde_json::from_str::<Value>(line) {
                    runs.push(val);
                }
            }
        }
    }

    let mut recordings = Vec::new();
    if recordings_dir.is_dir() {
        if let Ok(entries) = std::fs::read_dir(&recordings_dir) {
            for entry in entries.flatten().take(200) {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("cast") {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        recordings.push(name.to_string());
                    }
                }
            }
        }
    }
    recordings.sort();
    let is_live = !sessions.is_empty() || !runs.is_empty() || !recordings.is_empty();
    Ok(json!({
        "is_live": is_live,
        "ssh_sessions": sessions,
        "pipeline_runs": runs,
        "available_recordings": recordings,
    }))
}

fn audit_recording_value(params: &Value) -> Result<Value, String> {
    let filename = params
        .get("recording")
        .and_then(Value::as_str)
        .ok_or_else(|| "Missing 'recording' parameter".to_string())?;
    if filename.is_empty()
        || filename.len() > 128
        || !filename.ends_with(".cast")
        || filename.contains("..")
        || filename.contains('/')
        || filename.contains('\\')
        || filename.contains(':')
        || filename.contains('\0')
    {
        return Err("Invalid recording filename".to_string());
    }
    let recordings_dir = sb_core::paths::sb_home().join("recordings");
    let path = recordings_dir.join(filename);
    let meta = std::fs::symlink_metadata(&path)
        .map_err(|_| format!("Recording '{filename}' does not exist"))?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > 8 * 1024 * 1024 {
        return Err("Recording file is invalid or exceeds size limit".to_string());
    }
    let content =
        std::fs::read_to_string(&path).map_err(|e| format!("Cannot read recording: {e}"))?;
    let mut lines = content.lines();
    let header_line = lines.next().ok_or_else(|| "Empty .cast file".to_string())?;
    let header: Value =
        serde_json::from_str(header_line).map_err(|e| format!("Invalid .cast header: {e}"))?;
    let width = header.get("width").and_then(Value::as_u64).unwrap_or(80);
    let height = header.get("height").and_then(Value::as_u64).unwrap_or(24);
    let mut frames = Vec::new();
    let mut duration = 0.0_f64;
    for line in lines.take(2_000) {
        if let Ok(arr) = serde_json::from_str::<Vec<Value>>(line) {
            if arr.len() >= 3 {
                let time = arr[0].as_f64().unwrap_or(0.0);
                let event_type = arr[1].as_str().unwrap_or("o");
                let data = arr[2].as_str().unwrap_or("");
                if time > duration {
                    duration = time;
                }
                frames.push(json!({
                    "time": time,
                    "event_type": event_type,
                    "data": data,
                }));
            }
        }
    }
    Ok(json!({
        "recording": filename,
        "width": width,
        "height": height,
        "duration": duration,
        "frames": frames,
    }))
}

fn load_mesh_runtime_status() -> Result<Option<MeshRuntimeStatus>, String> {
    let data_dir = sb_mesh::identity::default_data_dir()?;
    let networks_path = data_dir.join("networks.json");
    let content = match std::fs::read_to_string(&networks_path) {
        Ok(content) => content,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("Mesh network catalog could not be read: {error}")),
    };
    let networks: sb_mesh::network::NetworksFile = serde_json::from_str(&content)
        .map_err(|error| format!("Mesh network catalog is invalid: {error}"))?;
    let paths = sb_mesh::state::MeshStatePaths::for_mesh_at(&data_dir, &networks.active_network)?;
    load_mesh_runtime_status_from(&paths.runtime_status)
}

fn load_mesh_runtime_status_from(
    status_path: &std::path::Path,
) -> Result<Option<MeshRuntimeStatus>, String> {
    match std::fs::metadata(status_path) {
        Ok(_) => MeshRuntimeStatus::load_fresh(status_path).map(Some),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!(
            "Mesh runtime status unavailable at {:?}: {error}",
            status_path
        )),
    }
}

fn mesh_runtime_status_value(
    status: &MeshRuntimeStatus,
    runtime_state: &str,
    runtime_error: Option<&str>,
) -> Result<Value, String> {
    let available_networks = status
        .available_networks
        .iter()
        .map(|network| NetworkSummaryItem {
            name: network.name.clone(),
            description: network.description.clone(),
            subnet: network.subnet.clone(),
            is_active: network.is_active,
        })
        .collect();
    let info = MeshNetworkInfo {
        active_network: status.mesh_name.clone(),
        description: status.description.clone(),
        overlay_subnet: status.overlay_subnet.clone(),
        swarm_topic: status.swarm_topic.clone(),
        local_node_id: status.local_node_id.clone(),
        local_pubkey: status.local_public_key.clone(),
        local_callsign: String::new(),
        listen_port: status.listen_port,
        airgap_killswitch: status.air_gap_killswitch,
        available_networks,
    };
    let mut value = serde_json::to_value(info)
        .map_err(|error| format!("Failed to serialize mesh runtime status: {error}"))?;
    let object = value
        .as_object_mut()
        .ok_or_else(|| "Serialized mesh status is not a JSON object".to_string())?;
    object.insert("runtime_state".into(), json!(runtime_state));
    object.insert("runtime_error".into(), json!(runtime_error));
    object.insert("transport_protocol".into(), json!(status.protocol));
    object.insert("tunnel_active".into(), Value::Null);
    object.insert("tunnel_state".into(), json!("not_probed"));
    Ok(value)
}

fn mesh_runtime_nodes_value(status: &MeshRuntimeStatus) -> Result<Value, String> {
    status
        .peers
        .iter()
        .map(|peer| {
            let state = match peer.status {
                sb_mesh::peer::PeerStatus::Connected => "online",
                sb_mesh::peer::PeerStatus::HandshakeInProgress => "syncing",
                sb_mesh::peer::PeerStatus::Standby => "idle",
                sb_mesh::peer::PeerStatus::Disconnected => "offline",
            };
            serde_json::to_value(MeshNodeInfo {
                node_id: peer.node_id.clone(),
                callsign: peer.callsign.clone(),
                mesh_ip: peer.overlay_ip.clone().unwrap_or_default(),
                role: "unknown".into(),
                privilege: "unknown".into(),
                status: state.into(),
                ping_ms: peer.ping_ms.unwrap_or_default(),
                gpu_info: None,
            })
            .map(|mut value| {
                if let Some(object) = value.as_object_mut() {
                    object.insert("runtime_known".into(), json!(true));
                    object.insert("ping_known".into(), json!(peer.ping_ms.is_some()));
                    object.insert("overlay_ip".into(), json!(peer.overlay_ip));
                }
                value
            })
            .map_err(|error| format!("Failed to serialize mesh peer status: {error}"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(Value::Array)
}

fn empty_mesh_runtime_status() -> MeshRuntimeStatus {
    MeshRuntimeStatus {
        schema_version: 0,
        process_id: 0,
        started_at_unix: 0,
        heartbeat_unix: 0,
        mesh_name: String::new(),
        description: String::new(),
        overlay_subnet: String::new(),
        swarm_topic: String::new(),
        local_node_id: String::new(),
        local_public_key: String::new(),
        listen_port: 0,
        air_gap_killswitch: false,
        protocol: "unknown".into(),
        peers: Vec::new(),
        available_networks: Vec::new(),
    }
}

#[derive(Default)]
struct DaemonVaultState {
    session: Mutex<Option<(PathBuf, VaultSession)>>,
}

pub async fn run_daemon(
    port: Option<u16>,
    api_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let listen_port = port.unwrap_or(DEFAULT_DAEMON_API_PORT);
    let addr: SocketAddr = format!("127.0.0.1:{}", listen_port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    let auth_token = Arc::new(DaemonAuthToken::create_default()?);
    let vault_state = Arc::new(DaemonVaultState::default());
    let connection_limit = Arc::new(tokio::sync::Semaphore::new(MAX_DAEMON_CONNECTIONS));

    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════"
            .bold()
            .black()
    );
    println!(
        "  {} {} {}",
        "S&B SOVEREIGN DAEMON".cyan().bold(),
        "//".black().bold(),
        "HEADLESS SYSTEM API".bold()
    );
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════"
            .bold()
            .black()
    );
    println!(
        "  {} Loopback RPC API active on: {}",
        "●".green().bold(),
        format!("http://{}", addr).yellow().bold()
    );
    println!(
        "  {} Loopback only; RPC clients must authenticate with the local daemon token.",
        "🔒".white()
    );
    println!(
        "  {} JSON-RPC 2.0 endpoints ready for Desktop UI / external clients.",
        "⚡".bright_cyan()
    );
    if api_only {
        println!("  {} Running in API-only headless mode.", "ℹ".blue());
    }
    println!(
        "{}",
        "══════════════════════════════════════════════════════════════════"
            .bold()
            .black()
    );

    loop {
        match listener.accept().await {
            Ok((socket, remote_addr)) => {
                let permit = match Arc::clone(&connection_limit).try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        eprintln!("Rejected daemon connection from {remote_addr}: connection limit reached");
                        continue;
                    }
                };
                let auth_token = Arc::clone(&auth_token);
                let vault_state = Arc::clone(&vault_state);
                tokio::spawn(async move {
                    let _permit = permit;
                    let result = timeout(
                        HTTP_REQUEST_TIMEOUT,
                        handle_connection(socket, remote_addr, auth_token, vault_state),
                    )
                    .await;
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => {
                            eprintln!(
                                "{} Connection error from {}: {}",
                                "✗".red(),
                                remote_addr,
                                error
                            );
                        }
                        Err(_) => {
                            eprintln!("{} Connection from {} timed out", "✗".red(), remote_addr);
                        }
                    }
                });
            }
            Err(e) => {
                eprintln!("{} Accept error: {}", "✗".red(), e);
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    _remote_addr: SocketAddr,
    auth_token: Arc<DaemonAuthToken>,
    vault_state: Arc<DaemonVaultState>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut buffer = [0u8; MAX_HTTP_REQUEST_BYTES];
    let bytes_read = match read_http_request(&mut stream, &mut buffer).await {
        Ok(bytes_read) => bytes_read,
        Err(error) => {
            buffer.zeroize();
            return Err(error.into());
        }
    };
    if bytes_read == 0 {
        return Ok(());
    }

    let mut request_str = String::from_utf8_lossy(&buffer[..bytes_read]).into_owned();
    let request_line = request_str.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("").to_string();
    let uri = parts.next().unwrap_or("").to_string();
    let version = parts.next().unwrap_or("").to_string();
    if method.is_empty() || uri.is_empty() || version != "HTTP/1.1" || parts.next().is_some() {
        request_str.zeroize();
        buffer.zeroize();
        let response = "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    if method == "GET" && (uri == "/" || uri == "/health") {
        let body = serde_json::to_string(&json!({
            "service": "sb-daemon",
            "version": "0.2.1",
            "status": "online",
            "api": "jsonrpc-2.0"
        }))?;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        stream.write_all(response.as_bytes()).await?;
        request_str.zeroize();
        buffer.zeroize();
        return Ok(());
    }

    if method != "POST" || uri != "/" {
        request_str.zeroize();
        buffer.zeroize();
        let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(not_found.as_bytes()).await?;
        return Ok(());
    }

    if !has_valid_bearer_authorization(&request_str, &auth_token) {
        request_str.zeroize();
        buffer.zeroize();
        let response =
            "HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
        return Ok(());
    }
    if has_origin_header(&request_str) {
        request_str.zeroize();
        buffer.zeroize();
        let response = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
        return Ok(());
    }
    if !has_json_content_type(&request_str) {
        request_str.zeroize();
        buffer.zeroize();
        let response =
            "HTTP/1.1 415 Unsupported Media Type\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        stream.write_all(response.as_bytes()).await?;
        return Ok(());
    }

    let parsed = request_str
        .find("\r\n\r\n")
        .map(|idx| idx + 4)
        .ok_or_else(|| "Malformed HTTP request: missing header terminator".to_string())
        .and_then(|body_start| {
            serde_json::from_str::<RpcRequest>(request_str[body_start..].trim())
                .map_err(|e| format!("JSON parse error: {e}"))
        });
    request_str.zeroize();
    buffer.zeroize();

    let mut rpc_res = match parsed {
        Ok(req) => execute_rpc(req, &vault_state).await,
        Err(e) => RpcResponse::error(Value::Null, error_codes::PARSE_ERROR, e, None),
    };

    let mut res_body = serde_json::to_string(&rpc_res)?;
    if res_body.len() > sb_core::rpc::MAX_RPC_RESPONSE_BYTES {
        res_body.zeroize();
        rpc_res = RpcResponse::error(
            rpc_res.id.clone(),
            error_codes::INTERNAL_ERROR,
            "RPC response exceeds the local size limit",
            None,
        );
        res_body = serde_json::to_string(&rpc_res)?;
    }
    let response_header = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        res_body.len()
    );
    let write_result = async {
        stream.write_all(response_header.as_bytes()).await?;
        stream.write_all(res_body.as_bytes()).await
    }
    .await;
    res_body.zeroize();
    zeroize_rpc_result(&mut rpc_res);
    write_result?;
    Ok(())
}

// CVE-Threat: Partial reads, oversized bodies and slow-client exhaustion at the HTTP boundary.
// Analysis: TCP does not preserve HTTP message boundaries and local clients may be faulty.
// Hardening: Enforce a bounded buffer, Content-Length, and a finite read timeout.
async fn read_http_request(
    stream: &mut TcpStream,
    buffer: &mut [u8],
) -> Result<usize, std::io::Error> {
    let mut bytes_read = 0;
    loop {
        let read = timeout(HTTP_READ_TIMEOUT, stream.read(&mut buffer[bytes_read..]))
            .await
            .map_err(|_| {
                std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP request timed out")
            })??;
        if read == 0 {
            return Ok(bytes_read);
        }
        bytes_read += read;

        let Some(header_end) = buffer[..bytes_read]
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|position| position + 4)
        else {
            if bytes_read == buffer.len() || bytes_read >= MAX_HTTP_HEADER_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP headers exceed the local request limit",
                ));
            }
            continue;
        };
        if header_end > MAX_HTTP_HEADER_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP headers exceed the local request limit",
            ));
        }

        let headers = std::str::from_utf8(&buffer[..header_end]).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("HTTP headers are not UTF-8: {error}"),
            )
        })?;
        let is_post = headers
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().next())
            == Some("POST");
        if !is_post {
            return Ok(bytes_read);
        }
        let mut content_length = None;
        for line in headers.lines().skip(1) {
            let Some((name, value)) = line.split_once(':') else {
                continue;
            };
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Transfer-Encoding is not supported by the local RPC endpoint",
                ));
            }
            if name.eq_ignore_ascii_case("content-length") {
                if content_length.is_some() {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "Duplicate Content-Length header",
                    ));
                }
                content_length = Some(value.trim().parse::<usize>().map_err(|error| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Invalid Content-Length: {error}"),
                    )
                })?);
            }
        }
        let content_length = content_length.ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "POST request is missing Content-Length",
            )
        })?;
        if content_length > sb_core::rpc::MAX_RPC_REQUEST_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "RPC request exceeds the local body size limit",
            ));
        }
        let request_end = header_end.checked_add(content_length).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "HTTP body length overflow")
        })?;
        if request_end > buffer.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "HTTP request exceeds the local size limit",
            ));
        }
        if bytes_read >= request_end {
            return Ok(bytes_read);
        }
    }
}

fn zeroize_rpc_result(response: &mut RpcResponse) {
    fn clear_value(value: &mut Value) {
        match value {
            Value::String(value) => value.zeroize(),
            Value::Array(values) => values.iter_mut().for_each(clear_value),
            Value::Object(values) => values.values_mut().for_each(clear_value),
            _ => {}
        }
    }

    if let Some(result) = response.result.as_mut() {
        clear_value(result);
    }
}

// CVE-Threat: Duplicate-header ambiguity or token comparison timing could bypass local RPC authentication.
// Analysis: Any process able to reach loopback can submit arbitrary HTTP headers.
// Hardening: Reject duplicate Authorization headers and verify the sole Bearer token in constant time.
fn has_valid_bearer_authorization(request: &str, token: &DaemonAuthToken) -> bool {
    let Some((headers, _)) = request.split_once("\r\n\r\n") else {
        return false;
    };
    let mut authorization = None;
    for header in headers.lines().skip(1) {
        let Some((name, value)) = header.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("authorization") {
            if authorization.is_some() {
                return false;
            }
            authorization = Some(value.trim());
        }
    }
    authorization
        .and_then(|value| value.strip_prefix("Bearer "))
        .is_some_and(|candidate| token.verify(candidate))
}

// CVE-Threat: Cross-origin browser access or DNS rebinding against the privileged loopback API.
// Analysis: A local address alone does not prevent a web page from reaching a browser-visible endpoint.
// Hardening: Reject browser-supplied Origin headers and expose no CORS permissions.
fn has_origin_header(request: &str) -> bool {
    request
        .split("\r\n\r\n")
        .next()
        .unwrap_or_default()
        .lines()
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .any(|(name, _)| name.trim().eq_ignore_ascii_case("origin"))
}

fn has_json_content_type(request: &str) -> bool {
    let Some(headers) = request.split("\r\n\r\n").next() else {
        return false;
    };
    let mut content_type = None;
    for line in headers.lines().skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-type") {
            if content_type.is_some() {
                return false;
            }
            content_type = Some(value.trim());
        }
    }
    content_type
        .and_then(|value| value.split(';').next())
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

async fn execute_rpc(req: RpcRequest, vault_state: &DaemonVaultState) -> RpcResponse {
    let id = req.id.clone();
    if req.jsonrpc != "2.0" {
        return RpcResponse::error(
            id,
            error_codes::INVALID_REQUEST,
            "Unsupported JSON-RPC version",
            None,
        );
    }
    if req.api_version != SERVICE_API_VERSION {
        return RpcResponse::error(
            id,
            error_codes::UNSUPPORTED_API_VERSION,
            "Unsupported Suite API version",
            Some(json!({
                "requested": req.api_version,
                "supported": SERVICE_API_VERSION
            })),
        );
    }
    if req.method.starts_with("vault.") {
        return execute_vault_rpc(req, vault_state);
    }
    match req.method.as_str() {
        RPC_METHOD_SUITE_STATUS => {
            let mesh_status = load_mesh_runtime_status();
            let (mesh_label, mesh_error) = match &mesh_status {
                Ok(Some(_)) => ("online", None),
                Ok(None) => (
                    "offline",
                    Some("sb-mesh runtime status has not been published"),
                ),
                Err(error) => ("unavailable", Some(error.as_str())),
            };
            let summary = json!({
                "status": if mesh_label == "online" { "healthy" } else { "degraded" },
                "daemon": "active",
                "mesh": mesh_label,
                "mesh_error": mesh_error,
                "drive": "not_probed",
                "telemetry_source": "mesh_runtime_status"
            });
            RpcResponse::success(id, summary)
        }
        RPC_METHOD_SUITE_CATALOG => match InventoryProductCatalog.list_products() {
            Ok(products) => match serde_json::to_value(products) {
                Ok(value) => RpcResponse::success(id, value),
                Err(error) => {
                    RpcResponse::error(id, error_codes::INTERNAL_ERROR, error.to_string(), None)
                }
            },
            Err(error) => error.into_rpc_response(id),
        },
        RPC_METHOD_MESH_STATUS => match load_mesh_runtime_status() {
            Ok(Some(status)) => match mesh_runtime_status_value(&status, "online", None) {
                Ok(value) => RpcResponse::success(id, value),
                Err(error) => RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None),
            },
            Ok(None) => match mesh_runtime_status_value(
                &empty_mesh_runtime_status(),
                "offline",
                Some("sb-mesh runtime status has not been published"),
            ) {
                Ok(value) => RpcResponse::success(id, value),
                Err(error) => RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None),
            },
            Err(error) => RpcResponse::error(
                id,
                error_codes::INTERNAL_ERROR,
                format!("Mesh runtime status unavailable: {error}"),
                None,
            ),
        },

        RPC_METHOD_MESH_NODES => match load_mesh_runtime_status() {
            Ok(Some(status)) => match mesh_runtime_nodes_value(&status) {
                Ok(value) => RpcResponse::success(id, value),
                Err(error) => RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None),
            },
            Ok(None) => RpcResponse::success(id, json!([])),
            Err(error) => RpcResponse::error(
                id,
                error_codes::INTERNAL_ERROR,
                format!("Mesh peer runtime status unavailable: {error}"),
                None,
            ),
        },
        RPC_METHOD_MESH_OBJECTS_LIST => match mesh_objects_list_value() {
            Ok(value) => RpcResponse::success(id, value),
            Err(error) => RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None),
        },
        RPC_METHOD_MESH_OBJECTS_GET => match mesh_objects_get_value(&req.params).await {
            Ok(value) => RpcResponse::success(id, value),
            Err(error) => RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None),
        },
        RPC_METHOD_MESH_OBJECTS_PREVIEW => match mesh_objects_preview_value(&req.params) {
            Ok(value) => RpcResponse::success(id, value),
            Err(error) => RpcResponse::error(id, error_codes::INVALID_PARAMS, error, None),
        },
        RPC_METHOD_FLEET_LIST => match fleet_list_value() {
            Ok(value) => RpcResponse::success(id, value),
            Err(error) => RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None),
        },
        RPC_METHOD_TUNNELS_LIST => match tunnels_list_value() {
            Ok(value) => RpcResponse::success(id, value),
            Err(error) => RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None),
        },
        RPC_METHOD_AUDIT_LIST => match audit_list_value() {
            Ok(value) => RpcResponse::success(id, value),
            Err(error) => RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None),
        },
        RPC_METHOD_AUDIT_RECORDING => match audit_recording_value(&req.params) {
            Ok(value) => RpcResponse::success(id, value),
            Err(error) => RpcResponse::error(id, error_codes::INVALID_PARAMS, error, None),
        },
        RPC_METHOD_APPS_LIST => match apps_list_value() {
            Ok(value) => RpcResponse::success(id, value),
            Err(error) => RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None),
        },
        RPC_METHOD_APPS_PREVIEW => match apps_preview_value(&req.params).await {
            Ok(value) => RpcResponse::success(id, value),
            Err(error) => RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None),
        },
        RPC_METHOD_APPS_INSTALL => match apps_install_value(&req.params).await {
            Ok(value) => RpcResponse::success(id, value),
            Err(error) => RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None),
        },
        RPC_METHOD_APPS_UNINSTALL => {
            match apps_change_value(&req.params, |store, app| store.uninstall(app)) {
                Ok(value) => RpcResponse::success(id, value),
                Err(error) => RpcResponse::error(id, error_codes::INVALID_PARAMS, error, None),
            }
        }
        RPC_METHOD_APPS_ROLLBACK => {
            match apps_change_value(&req.params, |store, app| store.rollback(app).map(|_| ())) {
                Ok(value) => RpcResponse::success(id, value),
                Err(error) => RpcResponse::error(id, error_codes::INVALID_PARAMS, error, None),
            }
        }
        RPC_METHOD_APPS_LAUNCH => match apps_launch_value(&req.params) {
            Ok(value) => RpcResponse::success(id, value),
            Err(error) => RpcResponse::error(id, error_codes::INVALID_PARAMS, error, None),
        },
        RPC_METHOD_MESH_PING => {
            let target = match req.params.get("target").and_then(|v| v.as_str()) {
                Some(t) if !t.trim().is_empty() => t.trim(),
                _ => {
                    return RpcResponse::error(
                        id,
                        error_codes::INVALID_PARAMS,
                        "Missing or empty required string parameter 'target'",
                        None,
                    );
                }
            };
            match sb_mesh::ipc::IpcClient::ping(target).await {
                Ok(ack) => RpcResponse::success(id, json!({ "status": "sent", "ack": ack })),
                Err(err) => RpcResponse::error(id, error_codes::PEER_UNREACHABLE, err, None),
            }
        }
        RPC_METHOD_MESH_SET_AIR_GAP => {
            let enabled = match req.params.get("enabled").and_then(|v| v.as_bool()) {
                Some(val) => val,
                None => {
                    return RpcResponse::error(
                        id,
                        error_codes::INVALID_PARAMS,
                        "Missing or invalid required boolean parameter 'enabled'",
                        None,
                    );
                }
            };
            match sb_mesh::ipc::IpcClient::set_air_gap(enabled).await {
                Ok(ack) => RpcResponse::success(
                    id,
                    json!({
                        "status": "updated",
                        "ack": ack,
                        "air_gap_killswitch": enabled,
                    }),
                ),
                Err(err) => RpcResponse::error(id, error_codes::PEER_UNREACHABLE, err, None),
            }
        }
        RPC_METHOD_DRIVE_LIST => {
            let peer = req
                .params
                .get("peer")
                .and_then(|v| v.as_str())
                .unwrap_or("local")
                .to_string();
            let path = req
                .params
                .get("path")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            match PeerFilesystem::list_directory(peer, path).await {
                Ok(res) => match serde_json::to_value(res) {
                    Ok(val) => RpcResponse::success(id, val),
                    Err(e) => {
                        RpcResponse::error(id, error_codes::INTERNAL_ERROR, e.to_string(), None)
                    }
                },
                Err(e) => RpcResponse::error(id, error_codes::PEER_UNREACHABLE, e, None),
            }
        }
        RPC_METHOD_DRIVE_READ => {
            let peer = req
                .params
                .get("peer")
                .and_then(|v| v.as_str())
                .unwrap_or("local")
                .to_string();
            let path = req
                .params
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();

            match PeerFilesystem::read_file(peer, path).await {
                Ok(res) => match serde_json::to_value(res) {
                    Ok(val) => RpcResponse::success(id, val),
                    Err(e) => {
                        RpcResponse::error(id, error_codes::INTERNAL_ERROR, e.to_string(), None)
                    }
                },
                Err(e) => RpcResponse::error(id, error_codes::PEER_UNREACHABLE, e, None),
            }
        }
        RPC_METHOD_DRIVE_WRITE => {
            let peer = req
                .params
                .get("peer")
                .and_then(|v| v.as_str())
                .unwrap_or("local")
                .to_string();
            let path = req
                .params
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();
            let content = req
                .params
                .get("content")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            match PeerFilesystem::write_file(peer, path, content, None).await {
                Ok(success) => RpcResponse::success(id, json!({ "success": success })),
                Err(e) => RpcResponse::error(id, error_codes::PEER_UNREACHABLE, e, None),
            }
        }
        RPC_METHOD_DRIVE_GET => {
            let peer = req
                .params
                .get("peer")
                .and_then(|v| v.as_str())
                .unwrap_or("local")
                .to_string();
            let path = req
                .params
                .get("path")
                .and_then(|v| v.as_str())
                .unwrap_or("/")
                .to_string();

            match PeerFilesystem::download_to_cache(peer, path).await {
                Ok(cached_path) => RpcResponse::success(id, json!({ "cached_path": cached_path })),
                Err(e) => RpcResponse::error(id, error_codes::PEER_UNREACHABLE, e, None),
            }
        }
        other => RpcResponse::error(
            id,
            error_codes::METHOD_NOT_FOUND,
            format!("Method '{}' not found", other),
            None,
        ),
    }
}

fn execute_vault_rpc(req: RpcRequest, state: &DaemonVaultState) -> RpcResponse {
    let store = match VaultStore::active() {
        Ok(store) => store,
        Err(error) => {
            return RpcResponse::error(req.id, error_codes::INTERNAL_ERROR, error, None);
        }
    };
    execute_vault_rpc_with_store(req, state, store)
}

// CVE-Threat: Unauthorized vault operations could expose plaintext or mutate encrypted state.
// Analysis: These handlers accept passphrases and secret values over the authenticated IPC boundary.
// Hardening: Session verification gates reads/writes; failures clear stale sessions and secret buffers are wiped.
fn execute_vault_rpc_with_store(
    req: RpcRequest,
    state: &DaemonVaultState,
    store: VaultStore,
) -> RpcResponse {
    let id = req.id.clone();
    let method = req.method.as_str();
    let mut params = req.params;
    let environment = request_string(&params, "environment")
        .unwrap_or("dev")
        .to_string();
    match method {
        RPC_METHOD_VAULT_STATUS => {
            let vault = match store.load(&environment) {
                Ok(vault) => vault,
                Err(error) => {
                    return RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None);
                }
            };
            let path = match store.path_for(&environment) {
                Ok(path) => path,
                Err(error) => {
                    return RpcResponse::error(id, error_codes::INVALID_PARAMS, error, None);
                }
            };
            let mut environments =
                vec!["dev".to_string(), "staging".to_string(), "prod".to_string()];
            if store.root().exists() {
                let entries = match std::fs::read_dir(store.root()) {
                    Ok(entries) => entries,
                    Err(error) => {
                        return RpcResponse::error(
                            id,
                            error_codes::INTERNAL_ERROR,
                            format!("Vault-Verzeichnis konnte nicht gelesen werden: {error}"),
                            None,
                        )
                    }
                };
                for entry in entries {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(error) => {
                            return RpcResponse::error(
                                id,
                                error_codes::INTERNAL_ERROR,
                                format!("Vault-Datei konnte nicht gelesen werden: {error}"),
                                None,
                            )
                        }
                    };
                    let entry_path = entry.path();
                    if entry_path.extension().and_then(|ext| ext.to_str()) == Some("vault") {
                        if let Some(name) = entry_path.file_stem().and_then(|name| name.to_str()) {
                            if !environments.iter().any(|existing| existing == name) {
                                environments.push(name.to_string());
                            }
                        }
                    }
                }
            }
            let is_unlocked = match state.session.lock() {
                Ok(mut session) => {
                    let active = session.as_ref().is_some_and(|(root, active_session)| {
                        root == store.root() && active_session.verify_vault(&vault).is_ok()
                    });
                    if !active {
                        *session = None;
                    }
                    active
                }
                Err(_) => {
                    return RpcResponse::error(
                        id,
                        error_codes::INTERNAL_ERROR,
                        "Vault session state is unavailable",
                        None,
                    )
                }
            };
            RpcResponse::success(
                id,
                json!({
                    "environment": environment,
                    "exists": path.exists(),
                    "initialized": vault.verifier.is_some(),
                    "unlocked": is_unlocked,
                    "secret_count": vault.secrets.len(),
                    "environments": environments
                }),
            )
        }
        RPC_METHOD_VAULT_INITIALIZE | RPC_METHOD_VAULT_UNLOCK => {
            match state.session.lock() {
                Ok(mut active) => *active = None,
                Err(_) => {
                    return RpcResponse::error(
                        id,
                        error_codes::INTERNAL_ERROR,
                        "Vault session state is unavailable",
                        None,
                    )
                }
            }
            let password = match take_string(&mut params, "password") {
                Ok(password) if !password.is_empty() => password,
                Ok(_) => {
                    return RpcResponse::error(
                        id,
                        error_codes::INVALID_PARAMS,
                        "Password must not be empty",
                        None,
                    )
                }
                Err(error) => {
                    return RpcResponse::error(id, error_codes::INVALID_PARAMS, error, None)
                }
            };
            let mut vault = match store.load(&environment) {
                Ok(vault) => vault,
                Err(error) => {
                    return RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None);
                }
            };
            let session = VaultSession::from_owned_passphrase(password);
            if method == RPC_METHOD_VAULT_INITIALIZE {
                if !vault.secrets.is_empty() {
                    return RpcResponse::error(
                        id,
                        error_codes::ACCESS_DENIED,
                        "Refusing to initialize a non-empty legacy vault",
                        None,
                    );
                }
                if let Err(error) = session.initialize(&mut vault) {
                    return RpcResponse::error(id, error_codes::ACCESS_DENIED, error, None);
                }
                if let Err(error) = store.save(&environment, &vault) {
                    return RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None);
                }
            } else {
                if let Err(error) = session.verify_vault(&vault) {
                    return RpcResponse::error(id, error_codes::ACCESS_DENIED, error, None);
                }
            }
            let root = store.root().to_path_buf();
            match state.session.lock() {
                Ok(mut active) => *active = Some((root, session)),
                Err(_) => {
                    return RpcResponse::error(
                        id,
                        error_codes::INTERNAL_ERROR,
                        "Vault session state is unavailable",
                        None,
                    )
                }
            }
            RpcResponse::success(
                id,
                json!({
                    "environment": environment,
                    "unlocked": true,
                    "initialized": true
                }),
            )
        }
        RPC_METHOD_VAULT_CHANGE_PASSWORD => {
            let new_password = match take_string(&mut params, "new_password") {
                Ok(password) if !password.is_empty() => password,
                Ok(_) => {
                    return RpcResponse::error(
                        id,
                        error_codes::INVALID_PARAMS,
                        "New password must not be empty",
                        None,
                    )
                }
                Err(error) => {
                    return RpcResponse::error(id, error_codes::INVALID_PARAMS, error, None)
                }
            };
            let new_session = VaultSession::from_owned_passphrase(new_password);
            let mut sessions = match state.session.lock() {
                Ok(sessions) => sessions,
                Err(_) => {
                    return RpcResponse::error(
                        id,
                        error_codes::INTERNAL_ERROR,
                        "Vault session state is unavailable",
                        None,
                    )
                }
            };
            let Some((root, current_session)) = sessions.as_ref() else {
                return RpcResponse::error(id, error_codes::ACCESS_DENIED, "Vault is locked", None);
            };
            if root != store.root() {
                *sessions = None;
                return RpcResponse::error(
                    id,
                    error_codes::ACCESS_DENIED,
                    "Vault profile changed; unlock the active vault",
                    None,
                );
            }

            let mut environments = vec![environment.clone()];
            if store.root().exists() {
                let entries = match std::fs::read_dir(store.root()) {
                    Ok(entries) => entries,
                    Err(error) => {
                        return RpcResponse::error(
                            id,
                            error_codes::INTERNAL_ERROR,
                            format!("Vault-Verzeichnis konnte nicht gelesen werden: {error}"),
                            None,
                        )
                    }
                };
                for entry in entries {
                    let entry = match entry {
                        Ok(entry) => entry,
                        Err(error) => {
                            return RpcResponse::error(
                                id,
                                error_codes::INTERNAL_ERROR,
                                format!("Vault-Datei konnte nicht gelesen werden: {error}"),
                                None,
                            )
                        }
                    };
                    let path = entry.path();
                    if path.extension().and_then(|ext| ext.to_str()) == Some("vault") {
                        if let Some(name) = path.file_stem().and_then(|name| name.to_str()) {
                            if !environments.iter().any(|existing| existing == name) {
                                environments.push(name.to_string());
                            }
                        }
                    }
                }
            }

            let mut changed_vaults = Vec::new();
            let mut active_environment_changed = false;
            for name in environments {
                let mut vault = match store.load(&name) {
                    Ok(vault) => vault,
                    Err(error) => {
                        return RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None)
                    }
                };
                if vault.verifier.is_none() && vault.secrets.is_empty() {
                    continue;
                }
                if let Err(error) = current_session.rekey_vault(&mut vault, &new_session) {
                    return RpcResponse::error(id, error_codes::ACCESS_DENIED, error, None);
                }
                if name == environment {
                    active_environment_changed = true;
                }
                changed_vaults.push((name, vault));
            }
            if !active_environment_changed {
                return RpcResponse::error(
                    id,
                    error_codes::ACCESS_DENIED,
                    "Active vault is not initialized",
                    None,
                );
            }

            if let Err(error) = persist_rekeyed_vaults(&store, &changed_vaults) {
                *sessions = None;
                return RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None);
            }
            *sessions = Some((store.root().to_path_buf(), new_session));
            RpcResponse::success(id, json!({"password_changed": true}))
        }
        RPC_METHOD_VAULT_LOCK => match state.session.lock() {
            Ok(mut session) => {
                *session = None;
                RpcResponse::success(id, json!({"locked": true}))
            }
            Err(_) => RpcResponse::error(
                id,
                error_codes::INTERNAL_ERROR,
                "Vault session state is unavailable",
                None,
            ),
        },
        RPC_METHOD_VAULT_LIST => {
            let vault = match store.load(&environment) {
                Ok(vault) => vault,
                Err(error) => {
                    return RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None);
                }
            };
            RpcResponse::success(
                id,
                json!({
                    "secrets": vault.secrets.iter().map(|(name, entry)| json!({
                        "name": name,
                        "updated_at": entry.updated_at,
                        "updated_by": entry.updated_by,
                        "version": entry.version,
                        "project": entry.project
                    })).collect::<Vec<_>>()
                }),
            )
        }
        RPC_METHOD_VAULT_GET
        | RPC_METHOD_VAULT_GET_ALL
        | RPC_METHOD_VAULT_SET
        | RPC_METHOD_VAULT_DELETE => {
            let mut vault = match store.load(&environment) {
                Ok(vault) => vault,
                Err(error) => {
                    return RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None);
                }
            };
            let mut sessions = match state.session.lock() {
                Ok(sessions) => sessions,
                Err(_) => {
                    return RpcResponse::error(
                        id,
                        error_codes::INTERNAL_ERROR,
                        "Vault session state is unavailable",
                        None,
                    )
                }
            };
            let Some((root, session)) = sessions.as_mut() else {
                return RpcResponse::error(id, error_codes::ACCESS_DENIED, "Vault is locked", None);
            };
            if root != store.root() {
                *sessions = None;
                return RpcResponse::error(
                    id,
                    error_codes::ACCESS_DENIED,
                    "Vault profile changed; unlock the active vault",
                    None,
                );
            }
            if let Err(error) = session.verify_vault(&vault) {
                *sessions = None;
                return RpcResponse::error(id, error_codes::ACCESS_DENIED, error, None);
            }

            match method {
                RPC_METHOD_VAULT_GET => {
                    let Some(name) = request_string(&params, "name") else {
                        return RpcResponse::error(
                            id,
                            error_codes::INVALID_PARAMS,
                            "Missing string parameter 'name'",
                            None,
                        );
                    };
                    let Some(entry) = vault.secrets.get(name) else {
                        return RpcResponse::error(
                            id,
                            error_codes::INVALID_PARAMS,
                            "Secret was not found",
                            None,
                        );
                    };
                    match session.decrypt(entry) {
                        Ok(value) => {
                            let mut result = serde_json::Map::new();
                            result.insert("value".to_string(), Value::String(value));
                            RpcResponse::success(id, Value::Object(result))
                        }
                        Err(error) => {
                            RpcResponse::error(id, error_codes::ACCESS_DENIED, error, None)
                        }
                    }
                }
                RPC_METHOD_VAULT_GET_ALL => {
                    let mut values = serde_json::Map::new();
                    let project_filter = request_string(&params, "project");
                    for (name, entry) in &vault.secrets {
                        if project_filter.is_some_and(|project| {
                            entry.project != project && entry.project != "global"
                        }) {
                            continue;
                        }
                        match session.decrypt(entry) {
                            Ok(value) => {
                                values.insert(name.clone(), Value::String(value));
                            }
                            Err(error) => {
                                for value in values.values_mut() {
                                    if let Value::String(value) = value {
                                        value.zeroize();
                                    }
                                }
                                return RpcResponse::error(
                                    id,
                                    error_codes::ACCESS_DENIED,
                                    error,
                                    None,
                                );
                            }
                        }
                    }
                    RpcResponse::success(id, Value::Object(values))
                }
                RPC_METHOD_VAULT_SET => {
                    let name = match request_string(&params, "name") {
                        Some(name) if !name.is_empty() => name.to_string(),
                        _ => {
                            return RpcResponse::error(
                                id,
                                error_codes::INVALID_PARAMS,
                                "Missing non-empty string parameter 'name'",
                                None,
                            )
                        }
                    };
                    let value = match take_string(&mut params, "value") {
                        Ok(value) => value,
                        Err(error) => {
                            return RpcResponse::error(id, error_codes::INVALID_PARAMS, error, None)
                        }
                    };
                    let project = request_string(&params, "project")
                        .map(str::to_owned)
                        .or_else(|| vault.secrets.get(&name).map(|entry| entry.project.clone()))
                        .unwrap_or_else(|| "global".to_string());
                    let updated_by =
                        request_string(&params, "updated_by").unwrap_or("daemon-client");
                    let encrypted = session.encrypt(&value);
                    let mut value = value;
                    value.zeroize();
                    let (ciphertext, nonce, salt) = match encrypted {
                        Ok(encrypted) => encrypted,
                        Err(error) => {
                            return RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None)
                        }
                    };
                    let version = match vault.secrets.get(&name) {
                        Some(entry) => match entry.version.checked_add(1) {
                            Some(version) => version,
                            None => {
                                return RpcResponse::error(
                                    id,
                                    error_codes::INTERNAL_ERROR,
                                    "Secret version counter is exhausted",
                                    None,
                                )
                            }
                        },
                        None => 1,
                    };
                    vault.secrets.insert(
                        name.clone(),
                        sb_core::vault::VaultSecretEntry {
                            ciphertext,
                            nonce,
                            salt,
                            updated_at: chrono::Utc::now().to_rfc3339(),
                            updated_by: updated_by.to_string(),
                            version,
                            project,
                        },
                    );
                    match store.save(&environment, &vault) {
                        Ok(()) => {
                            RpcResponse::success(id, json!({"name": name, "version": version}))
                        }
                        Err(error) => {
                            RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None)
                        }
                    }
                }
                RPC_METHOD_VAULT_DELETE => {
                    let Some(name) = request_string(&params, "name") else {
                        return RpcResponse::error(
                            id,
                            error_codes::INVALID_PARAMS,
                            "Missing string parameter 'name'",
                            None,
                        );
                    };
                    if vault.secrets.remove(name).is_none() {
                        return RpcResponse::error(
                            id,
                            error_codes::INVALID_PARAMS,
                            "Secret was not found",
                            None,
                        );
                    }
                    match store.save(&environment, &vault) {
                        Ok(()) => RpcResponse::success(id, json!({"deleted": true})),
                        Err(error) => {
                            RpcResponse::error(id, error_codes::INTERNAL_ERROR, error, None)
                        }
                    }
                }
                _ => unreachable!(),
            }
        }
        _ => RpcResponse::error(
            id,
            error_codes::METHOD_NOT_FOUND,
            format!("Method '{}' not found", method),
            None,
        ),
    }
}

fn request_string<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(Value::as_str)
}

fn take_string(params: &mut Value, key: &str) -> Result<String, String> {
    match params.as_object_mut().and_then(|object| object.remove(key)) {
        Some(Value::String(value)) => Ok(value),
        _ => Err(format!("Missing string parameter '{key}'")),
    }
}

// CVE-Threat: A partial multi-file password rotation could strand environments under mixed passwords.
// Analysis: Each environment is stored in a separate file and a later write can fail after earlier writes.
// Hardening: Stage all encrypted replacements, rename originals to recoverable backups, and roll back failures.
fn persist_rekeyed_vaults(
    store: &VaultStore,
    vaults: &[(String, sb_core::vault::VaultFile)],
) -> Result<(), String> {
    if vaults.is_empty() {
        return Ok(());
    }
    std::fs::create_dir_all(store.root())
        .map_err(|error| format!("Vault-Verzeichnis konnte nicht erstellt werden: {error}"))?;
    let staging_root = store.root().join(format!(
        ".vault-rekey-{}-{}",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::create_dir(&staging_root).map_err(|error| {
        format!("Rekey-Staging-Verzeichnis konnte nicht angelegt werden: {error}")
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(error) =
            std::fs::set_permissions(&staging_root, std::fs::Permissions::from_mode(0o700))
        {
            let cleanup_error = std::fs::remove_dir_all(&staging_root).err();
            return Err(match cleanup_error {
                Some(cleanup_error) => format!(
                    "Rekey-Staging-Verzeichnis konnte nicht geschützt werden ({error}); '{}' konnte nicht entfernt werden: {cleanup_error}",
                    staging_root.display()
                ),
                None => format!("Rekey-Staging-Verzeichnis konnte nicht geschützt werden: {error}"),
            });
        }
    }
    let staging_store = VaultStore::new(&staging_root);
    for (environment, vault) in vaults {
        if let Err(error) = staging_store.save(environment, vault) {
            let cleanup_error = std::fs::remove_dir_all(&staging_root).err();
            return Err(match cleanup_error {
                Some(cleanup_error) => format!(
                    "{error}; Staging-Verzeichnis '{}' konnte nicht entfernt werden: {cleanup_error}",
                    staging_root.display()
                ),
                None => error,
            });
        }
    }

    let mut committed: Vec<(std::path::PathBuf, std::path::PathBuf)> = Vec::new();
    for (environment, _) in vaults {
        let target = match store.path_for(environment) {
            Ok(path) => path,
            Err(error) => return rollback_rekey_failure(&staging_root, &committed, None, error),
        };
        let staged = match staging_store.path_for(environment) {
            Ok(path) => path,
            Err(error) => return rollback_rekey_failure(&staging_root, &committed, None, error),
        };
        let backup = staging_root.join(format!("{environment}.backup"));
        if let Err(error) = std::fs::rename(&target, &backup) {
            return rollback_rekey_failure(
                &staging_root,
                &committed,
                None,
                format!(
                    "Vault '{}' konnte für Passwortwechsel nicht gesichert werden: {error}",
                    target.display()
                ),
            );
        }
        if let Err(error) = std::fs::rename(&staged, &target) {
            let current_restore = std::fs::rename(&backup, &target).err();
            let cause = current_restore
                .as_ref()
                .map(|restore_error| format!(
                    "Neue Vault-Datei konnte nicht installiert werden ({error}); die aktuelle Datei konnte nicht wiederhergestellt werden ({restore_error})"
                ))
                .unwrap_or_else(|| format!("Neue Vault-Datei konnte nicht installiert werden: {error}"));
            return rollback_rekey_failure(&staging_root, &committed, current_restore, cause);
        }
        committed.push((target, backup));
    }

    if let Err(error) = std::fs::remove_dir_all(&staging_root) {
        eprintln!(
            "Rekey abgeschlossen, aber Staging-Verzeichnis '{}' konnte nicht entfernt werden: {error}",
            staging_root.display()
        );
    }
    Ok(())
}

fn rollback_rekey_failure(
    staging_root: &std::path::Path,
    committed: &[(std::path::PathBuf, std::path::PathBuf)],
    current_restore_error: Option<std::io::Error>,
    cause: String,
) -> Result<(), String> {
    let mut rollback_errors = current_restore_error
        .map(|error| {
            vec![format!(
                "Aktuelles Vault konnte nicht wiederhergestellt werden: {error}"
            )]
        })
        .unwrap_or_default();
    for (target, backup) in committed.iter().rev() {
        if let Err(error) = std::fs::remove_file(target) {
            rollback_errors.push(format!(
                "Neue Datei '{}' konnte beim Rollback nicht entfernt werden: {error}",
                target.display()
            ));
            continue;
        }
        if let Err(error) = std::fs::rename(backup, target) {
            rollback_errors.push(format!(
                "Backup '{}' konnte nicht wiederhergestellt werden: {error}",
                backup.display()
            ));
        }
    }
    if rollback_errors.is_empty() {
        if let Err(error) = std::fs::remove_dir_all(staging_root) {
            rollback_errors.push(format!(
                "Staging-Verzeichnis '{}' konnte nicht entfernt werden: {error}",
                staging_root.display()
            ));
        }
    }
    if rollback_errors.is_empty() {
        Err(cause)
    } else {
        Err(format!(
            "{cause}; Rollback unvollständig: {}. Dateien liegen zur Wiederherstellung in '{}'",
            rollback_errors.join("; "),
            staging_root.display()
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_runtime_status() -> MeshRuntimeStatus {
        let now = MeshRuntimeStatus::now_unix().unwrap();
        let mut status = empty_mesh_runtime_status();
        status.schema_version = sb_mesh::runtime_status::RUNTIME_STATUS_SCHEMA_VERSION;
        status.process_id = std::process::id();
        status.started_at_unix = now;
        status.heartbeat_unix = now;
        status.mesh_name = "engineering".into();
        status.description = "Engineering mesh".into();
        status.overlay_subnet = "10.42.0.0/16".into();
        status.swarm_topic = "engineering-topic".into();
        status.local_node_id = "node-local".into();
        status.local_public_key = "public-key".into();
        status.listen_port = 58888;
        status.protocol = "sb-mesh-experimental-v2".into();
        status
    }

    #[test]
    fn mesh_runtime_loader_distinguishes_missing_and_stale_status() {
        let path = std::env::temp_dir().join(format!(
            "sb-daemon-mesh-status-{}-{}.json",
            std::process::id(),
            rand::random::<u64>()
        ));
        assert!(load_mesh_runtime_status_from(&path).unwrap().is_none());

        let mut stale = test_runtime_status();
        stale.heartbeat_unix = 1;
        std::fs::write(&path, serde_json::to_vec(&stale).unwrap()).unwrap();
        assert!(load_mesh_runtime_status_from(&path)
            .unwrap_err()
            .contains("stale"));
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn mesh_runtime_rpc_values_never_claim_tunnel_or_ping_without_evidence() {
        let mut status = test_runtime_status();
        status.peers.push(sb_mesh::runtime_status::MeshRuntimePeer {
            node_id: "node-peer".into(),
            callsign: "@peer".into(),
            overlay_ip: None,
            status: sb_mesh::peer::PeerStatus::Connected,
            ping_ms: None,
            last_handshake_unix: None,
        });

        let mesh_value = mesh_runtime_status_value(&status, "online", None).unwrap();
        assert_eq!(mesh_value["runtime_state"], "online");
        assert_eq!(mesh_value["transport_protocol"], "sb-mesh-experimental-v2");
        assert!(mesh_value["tunnel_active"].is_null());
        assert_eq!(mesh_value["tunnel_state"], "not_probed");
        assert_eq!(mesh_value["local_callsign"], "");

        let nodes = mesh_runtime_nodes_value(&status).unwrap();
        assert_eq!(nodes[0]["node_id"], "node-peer");
        assert_eq!(nodes[0]["status"], "online");
        assert_eq!(nodes[0]["ping_ms"], 0);
        assert_eq!(nodes[0]["ping_known"], false);
        assert_eq!(nodes[0]["role"], "unknown");
        assert_eq!(nodes[0]["privilege"], "unknown");
    }

    #[tokio::test]
    async fn http_reader_handles_fragmented_post_requests() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let receiver = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; 65536];
            read_http_request(&mut stream, &mut buffer).await.unwrap()
        });

        let body = serde_json::to_vec(&RpcRequest::new(1, "vault.status", json!({}))).unwrap();
        let headers = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", body.len());
        let mut stream = TcpStream::connect(endpoint).await.unwrap();
        stream
            .write_all(&headers.as_bytes()[..headers.len() / 2])
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        stream
            .write_all(&headers.as_bytes()[headers.len() / 2..])
            .await
            .unwrap();
        stream.write_all(&body).await.unwrap();
        assert_eq!(receiver.await.unwrap(), headers.len() + body.len());
    }

    #[tokio::test]
    async fn http_reader_accepts_rpc_body_with_near_limit_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let receiver = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; MAX_HTTP_REQUEST_BYTES];
            read_http_request(&mut stream, &mut buffer).await.unwrap()
        });

        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "api_version": SERVICE_API_VERSION,
            "id": 1,
            "method": "suite.catalog",
            "params": { "padding": "x".repeat(58 * 1024) }
        }))
        .unwrap();
        let headers = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\nX-Fill: {}\r\n\r\n",
            body.len(),
            "x".repeat(7 * 1024)
        );
        let request_len = headers.len() + body.len();
        assert!(body.len() <= sb_core::rpc::MAX_RPC_REQUEST_BYTES);
        assert!(headers.len() <= MAX_HTTP_HEADER_BYTES);
        assert!(request_len > 64 * 1024);
        assert!(request_len <= MAX_HTTP_REQUEST_BYTES);

        let mut stream = TcpStream::connect(endpoint).await.unwrap();
        stream.write_all(headers.as_bytes()).await.unwrap();
        stream.write_all(&body).await.unwrap();
        assert_eq!(receiver.await.unwrap(), request_len);
    }

    #[tokio::test]
    async fn http_reader_rejects_ambiguous_framing_headers() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let receiver = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = [0u8; MAX_HTTP_REQUEST_BYTES];
            read_http_request(&mut stream, &mut buffer).await
        });
        let mut stream = TcpStream::connect(endpoint).await.unwrap();
        stream
            .write_all(b"POST / HTTP/1.1\r\nContent-Length: 2\r\nContent-Length: 2\r\n\r\n{}")
            .await
            .unwrap();
        assert!(receiver
            .await
            .unwrap()
            .unwrap_err()
            .to_string()
            .contains("Duplicate Content-Length"));
    }

    /// Threat Modeling Audit:
    /// - Dynamic Threat Vector: Daemon serving outdated or spoofed product catalog over authenticated RPC.
    /// - CVE / CWE Mapping: CWE-345 (Insufficient Verification of Data Authenticity), CWE-306 (Missing Authentication for Critical Function)
    /// - Likelihood & Exploitability: Low (2/10); requires valid daemon authentication token and local socket access.
    /// - Applied Mitigation: Enforce token-authenticated IPC and assert all returned products reflect ProductMaturity::Releasevalidated.
    /// - Standards Compliance: JSON-RPC 2.0 / RFC 8259
    #[tokio::test]
    async fn suite_catalog_runs_over_authenticated_versioned_ipc() {
        let token_path = std::env::temp_dir().join(format!(
            "sb-daemon-catalog-{}-{}.token",
            std::process::id(),
            rand::random::<u64>()
        ));
        let auth_token = Arc::new(DaemonAuthToken::create_at(&token_path).unwrap());
        let token_value = std::fs::read_to_string(&token_path).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server_token = Arc::clone(&auth_token);
        let server = tokio::spawn(async move {
            let (socket, remote_addr) = listener.accept().await.unwrap();
            handle_connection(
                socket,
                remote_addr,
                server_token,
                Arc::new(DaemonVaultState::default()),
            )
            .await
            .unwrap();
        });

        let client = sb_core::daemon_client::DaemonClient::with_token(endpoint, token_value);
        let response =
            tokio::task::spawn_blocking(move || client.call(RPC_METHOD_SUITE_CATALOG, json!({})))
                .await
                .unwrap()
                .unwrap();
        let products: Vec<sb_core::SuiteProduct> = serde_json::from_value(response).unwrap();
        assert_eq!(products.len(), sb_core::catalog::products().unwrap().len());
        assert!(products.iter().any(|product| product.id == "mesh"));
        assert_eq!(
            products
                .iter()
                .filter(|product| product.maturity == sb_core::ProductMaturity::Releasevalidated)
                .count(),
            15
        );
        let ca_product = products.iter().find(|product| product.id == "ca").expect("ca product");
        assert_eq!(ca_product.maturity, sb_core::ProductMaturity::Releasevalidated);

        server.await.unwrap();
        drop(auth_token);
        assert!(!token_path.exists());
    }

    #[tokio::test]
    async fn daemon_rejects_browser_origins_and_non_json_rpc_bodies() {
        let token_path = std::env::temp_dir().join(format!(
            "sb-daemon-http-policy-{}-{}.token",
            std::process::id(),
            rand::random::<u64>()
        ));
        let auth_token = Arc::new(DaemonAuthToken::create_at(&token_path).unwrap());
        let token_value = std::fs::read_to_string(&token_path).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = listener.local_addr().unwrap();
        let server_token = Arc::clone(&auth_token);
        let server = tokio::spawn(async move {
            for _ in 0..3 {
                let (socket, remote_addr) = listener.accept().await.unwrap();
                handle_connection(
                    socket,
                    remote_addr,
                    Arc::clone(&server_token),
                    Arc::new(DaemonVaultState::default()),
                )
                .await
                .unwrap();
            }
        });

        for (request_target, headers, expected_status) in [
            (
                "/",
                "Origin: https://example.invalid\r\nContent-Type: application/json\r\n",
                "403 Forbidden",
            ),
            (
                "/",
                "Content-Type: text/plain\r\n",
                "415 Unsupported Media Type",
            ),
            (
                "/unknown",
                "Content-Type: application/json\r\n",
                "404 Not Found",
            ),
        ] {
            let request = format!(
                "POST {request_target} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\n{}Content-Length: 2\r\nConnection: close\r\n\r\n{{}}",
                token_value, headers
            );
            let mut stream = TcpStream::connect(endpoint).await.unwrap();
            stream.write_all(request.as_bytes()).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert!(String::from_utf8_lossy(&response)
                .starts_with(&format!("HTTP/1.1 {expected_status}")));
        }

        server.await.unwrap();
        drop(auth_token);
        assert!(!token_path.exists());
    }

    #[tokio::test]
    async fn daemon_rejects_unsupported_service_api_versions() {
        let mut request = RpcRequest::new(9, RPC_METHOD_SUITE_CATALOG, json!({}));
        request.api_version = SERVICE_API_VERSION + 1;
        let response = execute_rpc(request, &DaemonVaultState::default()).await;

        assert_eq!(
            response.error.as_ref().map(|error| error.code),
            Some(error_codes::UNSUPPORTED_API_VERSION)
        );
        assert_eq!(
            response
                .error
                .as_ref()
                .and_then(|error| error.data.as_ref())
                .and_then(|data| data["supported"].as_u64()),
            Some(u64::from(SERVICE_API_VERSION))
        );
    }

    #[test]
    fn daemon_rpc_requires_single_valid_bearer_token() {
        let path = std::env::temp_dir().join(format!(
            "sb-daemon-rpc-auth-{}-{}.token",
            std::process::id(),
            rand::random::<u64>()
        ));
        let token = DaemonAuthToken::create_at(&path).unwrap();
        let value = std::fs::read_to_string(&path).unwrap();

        let authenticated = format!(
            "POST / HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\n\r\n{{}}",
            value
        );
        assert!(has_valid_bearer_authorization(&authenticated, &token));

        let missing = "POST / HTTP/1.1\r\nHost: localhost\r\n\r\n{}";
        assert!(!has_valid_bearer_authorization(missing, &token));

        let duplicate = format!(
            "POST / HTTP/1.1\r\nAuthorization: Bearer {}\r\nAuthorization: Bearer {}\r\n\r\n{{}}",
            value, value
        );
        assert!(!has_valid_bearer_authorization(&duplicate, &token));

        let wrong_scheme = format!(
            "POST / HTTP/1.1\r\nAuthorization: Basic {}\r\n\r\n{{}}",
            value
        );
        assert!(!has_valid_bearer_authorization(&wrong_scheme, &token));
    }

    #[test]
    fn daemon_rpc_requires_json_content_type_and_rejects_browser_origins() {
        let native_request =
            "POST / HTTP/1.1\r\nContent-Type: application/json; charset=utf-8\r\n\r\n{}";
        assert!(has_json_content_type(native_request));
        assert!(!has_origin_header(native_request));

        let browser_request = "POST / HTTP/1.1\r\nContent-Type: application/json\r\nOrigin: https://example.invalid\r\n\r\n{}";
        assert!(has_origin_header(browser_request));

        let duplicate_content_type = "POST / HTTP/1.1\r\nContent-Type: application/json\r\nContent-Type: text/plain\r\n\r\n{}";
        assert!(!has_json_content_type(duplicate_content_type));

        let missing_content_type = "POST / HTTP/1.1\r\nAuthorization: Bearer token\r\n\r\n{}";
        assert!(!has_json_content_type(missing_content_type));
    }

    #[test]
    fn vault_rpc_initializes_verifies_and_gates_secret_access() {
        let root = std::env::temp_dir().join(format!(
            "sb-daemon-vault-rpc-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let store = VaultStore::new(&root);
        let state = DaemonVaultState::default();
        let initialize = |state: &DaemonVaultState, password: &str| {
            execute_vault_rpc_with_store(
                RpcRequest::new(
                    1,
                    RPC_METHOD_VAULT_INITIALIZE,
                    json!({"environment": "dev", "password": password}),
                ),
                state,
                store.clone(),
            )
        };

        let initialized = initialize(&state, "correct horse");
        assert!(initialized.error.is_none());
        assert_eq!(store.load("dev").unwrap().secrets.len(), 0);
        let initialized_staging = execute_vault_rpc_with_store(
            RpcRequest::new(
                8,
                RPC_METHOD_VAULT_INITIALIZE,
                json!({"environment": "staging", "password": "correct horse"}),
            ),
            &state,
            store.clone(),
        );
        assert!(initialized_staging.error.is_none());
        let unlock_dev = execute_vault_rpc_with_store(
            RpcRequest::new(
                9,
                RPC_METHOD_VAULT_UNLOCK,
                json!({"environment": "dev", "password": "correct horse"}),
            ),
            &state,
            store.clone(),
        );
        assert!(unlock_dev.error.is_none());

        let listed = execute_vault_rpc_with_store(
            RpcRequest::new(2, RPC_METHOD_VAULT_LIST, json!({"environment": "dev"})),
            &state,
            store.clone(),
        );
        assert_eq!(
            listed.result.unwrap()["secrets"].as_array().unwrap().len(),
            0
        );

        let set = execute_vault_rpc_with_store(
            RpcRequest::new(
                3,
                RPC_METHOD_VAULT_SET,
                json!({
                    "environment": "dev",
                    "name": "API_TOKEN",
                    "value": "secret-value",
                    "project": "test"
                }),
            ),
            &state,
            store.clone(),
        );
        assert!(set.error.is_none());

        let get = execute_vault_rpc_with_store(
            RpcRequest::new(
                4,
                RPC_METHOD_VAULT_GET,
                json!({"environment": "dev", "name": "API_TOKEN"}),
            ),
            &state,
            store.clone(),
        );
        assert_eq!(get.result.unwrap()["value"], "secret-value");

        let wrong_unlock = execute_vault_rpc_with_store(
            RpcRequest::new(
                5,
                RPC_METHOD_VAULT_UNLOCK,
                json!({"environment": "dev", "password": "wrong password"}),
            ),
            &state,
            store.clone(),
        );
        assert!(wrong_unlock.error.is_some());
        let denied_after_wrong_unlock = execute_vault_rpc_with_store(
            RpcRequest::new(
                6,
                RPC_METHOD_VAULT_GET,
                json!({"environment": "dev", "name": "API_TOKEN"}),
            ),
            &state,
            store.clone(),
        );
        assert_eq!(
            denied_after_wrong_unlock.error.unwrap().code,
            error_codes::ACCESS_DENIED
        );

        let unlock = execute_vault_rpc_with_store(
            RpcRequest::new(
                7,
                RPC_METHOD_VAULT_UNLOCK,
                json!({"environment": "dev", "password": "correct horse"}),
            ),
            &state,
            store.clone(),
        );
        assert!(unlock.error.is_none());

        let changed = execute_vault_rpc_with_store(
            RpcRequest::new(
                10,
                RPC_METHOD_VAULT_CHANGE_PASSWORD,
                json!({"environment": "dev", "new_password": "new horse"}),
            ),
            &state,
            store.clone(),
        );
        assert!(changed.error.is_none());
        assert!(VaultSession::new("new horse")
            .verify_vault(&store.load("dev").unwrap())
            .is_ok());
        assert!(VaultSession::new("new horse")
            .verify_vault(&store.load("staging").unwrap())
            .is_ok());
        assert!(VaultSession::new("correct horse")
            .verify_vault(&store.load("dev").unwrap())
            .is_err());
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn password_rotation_rolls_back_files_when_a_later_environment_is_missing() {
        let root = std::env::temp_dir().join(format!(
            "sb-daemon-rekey-rollback-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let store = VaultStore::new(&root);
        let old_session = VaultSession::new("old password");
        let new_session = VaultSession::new("new password");
        let mut original = sb_core::vault::VaultFile::default();
        old_session.initialize(&mut original).unwrap();
        store.save("dev", &original).unwrap();

        let mut rekeyed = original;
        old_session.rekey_vault(&mut rekeyed, &new_session).unwrap();
        let staged_vaults = vec![
            ("dev".to_string(), rekeyed),
            ("missing".to_string(), sb_core::vault::VaultFile::default()),
        ];
        assert!(persist_rekeyed_vaults(&store, &staged_vaults).is_err());

        let persisted = store.load("dev").unwrap();
        assert!(old_session.verify_vault(&persisted).is_ok());
        assert!(new_session.verify_vault(&persisted).is_err());
        assert_eq!(
            std::fs::read_dir(&root).unwrap().count(),
            1,
            "rollback should remove its temporary staging directory"
        );
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn daemon_rpc_validates_mesh_ping_and_airgap_params() {
        let state = DaemonVaultState::default();

        // mesh.ping without target
        let req_ping_invalid = RpcRequest::new(1, RPC_METHOD_MESH_PING, json!({}));
        let resp = execute_rpc(req_ping_invalid, &state).await;
        assert_eq!(
            resp.error.as_ref().map(|e| e.code),
            Some(error_codes::INVALID_PARAMS)
        );

        // mesh.set_air_gap without enabled
        let req_airgap_invalid = RpcRequest::new(2, RPC_METHOD_MESH_SET_AIR_GAP, json!({}));
        let resp = execute_rpc(req_airgap_invalid, &state).await;
        assert_eq!(
            resp.error.as_ref().map(|e| e.code),
            Some(error_codes::INVALID_PARAMS)
        );

        // mesh.ping to offline peer returns PEER_UNREACHABLE
        let req_ping_valid = RpcRequest::new(
            3,
            RPC_METHOD_MESH_PING,
            json!({ "target": "nonexistent-peer" }),
        );
        let resp = execute_rpc(req_ping_valid, &state).await;
        assert_eq!(
            resp.error.as_ref().map(|e| e.code),
            Some(error_codes::PEER_UNREACHABLE)
        );
    }

    #[test]
    fn apps_launch_rejects_uninstalled_or_tampered_artifact() {
        use ed25519_dalek::SigningKey;
        let dir = std::env::temp_dir().join(format!(
            "sb_app_launch_{}_{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let store = sb_app_contract::install::AppStore::new(&dir);

        let missing = apps_launch_with_store(&store, "org.skullsandbones.viewer").unwrap();
        assert_eq!(missing["state"], "denied");

        let key = SigningKey::from_bytes(&[7u8; 32]);
        let trusted = std::collections::BTreeMap::from([(
            "org.skullsandbones.publisher".to_string(),
            key.verifying_key().to_bytes(),
        )]);
        let manifest = json!({
            "schema_version": 1,
            "app_id": "org.skullsandbones.viewer",
            "version": "0.1.0",
            "publisher_key_id": "org.skullsandbones.publisher",
            "client": {"target": "windows-x86_64", "artifact": format!("sha256:{}", "0".repeat(64))},
            "services": [{"service_id": "org.skullsandbones.drive.api", "api_version": 1,
                "contract_digest": format!("sha256:{}", "b".repeat(64))}],
            "requested_capabilities": [],
            "sandbox_profile": "native-client-default"
        });
        let packed = sb_app_contract::install::pack_signed_bundle(
            manifest.to_string().as_bytes(),
            b"not-a-valid-pe-binary",
            &key,
        )
        .unwrap();
        let bundle = sb_app_contract::install::parse_bundle(&packed).unwrap();
        let verified = sb_app_contract::verify_signed_manifest(
            &bundle.manifest,
            &bundle.signature_hex,
            &trusted,
        )
        .unwrap();
        store
            .install(
                &bundle.manifest,
                &bundle.signature_hex,
                &bundle.artifact,
                &trusted,
                &sb_app_contract::install::InstallConsent {
                    manifest_digest: verified.manifest_digest().to_string(),
                    granted: Vec::new(),
                },
            )
            .unwrap();

        let artifact_path = store
            .verified_artifact_path("org.skullsandbones.viewer")
            .unwrap();
        std::fs::write(&artifact_path, b"tampered-on-disk").unwrap();
        let tampered = apps_launch_with_store(&store, "org.skullsandbones.viewer").unwrap();
        assert_eq!(tampered["state"], "denied");
        assert!(tampered["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("Artifact digest does not match"));

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn preview_cached_object_verifies_digest_and_formats_utf8() {
        use sha2::{Digest, Sha256};
        let dir = std::env::temp_dir().join(format!("sb-preview-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cache_path = dir.join("obj.bin");
        let payload = b"Zero-Trust Mesh Document\nLine 2";
        std::fs::write(&cache_path, payload).unwrap();
        let digest: [u8; 32] = Sha256::digest(payload).into();

        let ok = preview_cached_object_at_path(
            &cache_path,
            "sb-drive:w1:readme.md",
            "v1",
            payload.len() as u64,
            &digest,
        )
        .unwrap();
        assert_eq!(ok["state"], "ok");
        assert_eq!(ok["preview_kind"], "utf8");
        assert_eq!(ok["truncated"], false);
        assert!(ok["preview_text"]
            .as_str()
            .unwrap_or_default()
            .contains("Zero-Trust Mesh Document"));

        let bad = preview_cached_object_at_path(
            &cache_path,
            "sb-drive:w1:readme.md",
            "v1",
            payload.len() as u64,
            &[0u8; 32],
        )
        .unwrap();
        assert_eq!(bad["state"], "denied");
        assert!(bad["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("SHA-256 digest mismatch"));

        let missing = preview_cached_object_at_path(
            &dir.join("missing.bin"),
            "sb-drive:w1:readme.md",
            "v1",
            payload.len() as u64,
            &digest,
        )
        .unwrap();
        assert_eq!(missing["state"], "not_cached");

        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn audit_recording_rejects_traversal_and_non_cast_names() {
        let traversal = audit_recording_value(&json!({ "recording": "../secret.cast" }));
        assert!(traversal.is_err());
        let non_cast = audit_recording_value(&json!({ "recording": "session.txt" }));
        assert!(non_cast.is_err());
    }
}
