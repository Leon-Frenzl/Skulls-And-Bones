use crate::vcs::VcsEngine;
use sb_mesh::client::{MeshClient, MeshClientConfig};
use sb_mesh::identity::NodeIdentity;
use std::collections::HashMap;
use std::io::{self, Read};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;

pub const WEB_PORT: u16 = 58835;
const MAX_REQUEST_BYTES: usize = 16 * 1024;
const MAX_JSON_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_BLOB_BYTES: u64 = 512 * 1024;
const MAX_DIFF_LINES: usize = 1200;
const MAX_DIFF_CELLS: usize = 1_000_000;
const MAX_TREE_PAGE_SIZE: usize = 300;
const MAX_ACTION_BODY_BYTES: usize = 4096;
const MAX_CONCURRENT_CONNECTIONS: usize = 64;
const UI: &str = include_str!("web/index.html");

struct HttpResponse {
    status: u16,
    reason: &'static str,
    content_type: &'static str,
    body: Vec<u8>,
}

impl HttpResponse {
    fn new(status: u16, reason: &'static str, content_type: &'static str, body: Vec<u8>) -> Self {
        Self {
            status,
            reason,
            content_type,
            body,
        }
    }

    fn json(value: serde_json::Value) -> Result<Self, String> {
        let body = serde_json::to_vec(&value)
            .map_err(|error| format!("Could not serialize web response: {error}"))?;
        if body.len() > MAX_JSON_RESPONSE_BYTES {
            return Err("Response exceeds the maximum JSON response size".into());
        }
        Ok(Self::new(
            200,
            "OK",
            "application/json; charset=utf-8",
            body,
        ))
    }

    fn error(status: u16, reason: &'static str, message: &str) -> Self {
        let mut body = b"{\"error\":\"".to_vec();
        for character in message.chars() {
            match character {
                '"' => body.extend_from_slice(b"\\\""),
                '\\' => body.extend_from_slice(b"\\\\"),
                '\n' => body.extend_from_slice(b"\\n"),
                '\r' => body.extend_from_slice(b"\\r"),
                '\t' => body.extend_from_slice(b"\\t"),
                character if character.is_control() => {
                    body.extend_from_slice(format!("\\u{:04x}", character as u32).as_bytes());
                }
                character => {
                    let mut encoded = [0; 4];
                    body.extend_from_slice(character.encode_utf8(&mut encoded).as_bytes());
                }
            }
        }
        body.extend_from_slice(b"\"}");
        Self::new(status, reason, "application/json; charset=utf-8", body)
    }
}

#[derive(Debug, PartialEq, Eq)]
struct HttpRequest {
    method: String,
    target: String,
    content_type: Option<String>,
    body: Vec<u8>,
    raw: Vec<u8>,
}

/// CVE-Threat: Request smuggling, DNS rebinding, and oversized header allocation.
/// Analysis: The viewer is a browser-facing loopback service reachable through an authenticated mesh tunnel.
/// Hardening: One bounded GET request per connection; reject bodies and non-loopback Host values.
fn parse_request(bytes: &[u8]) -> Result<HttpRequest, String> {
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err("HTTP request headers exceed the size limit".into());
    }
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| "Incomplete HTTP request headers".to_string())?;
    let headers = std::str::from_utf8(&bytes[..header_end])
        .map_err(|_| "HTTP headers are not valid UTF-8".to_string())?;
    let mut lines = headers.split("\r\n");
    let request_line = lines
        .next()
        .ok_or_else(|| "Missing HTTP request line".to_string())?;
    let mut parts = request_line.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| "Missing HTTP method".to_string())?;
    let target = parts
        .next()
        .ok_or_else(|| "Missing HTTP request target".to_string())?;
    let version = parts
        .next()
        .ok_or_else(|| "Missing HTTP version".to_string())?;
    if parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err("Malformed HTTP request line".into());
    }
    if !matches!(method, "GET" | "POST") {
        return Err("Only GET and POST requests are allowed".into());
    }
    if !target.starts_with('/') || target.starts_with("//") || target.contains('#') {
        return Err("Invalid request target".into());
    }

    let mut host_seen = false;
    let mut host = None;
    let mut origin = None;
    let mut content_type = None;
    let mut content_length = None;
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "Malformed HTTP header".to_string())?;
        let name = name.trim();
        let value = value.trim();
        if name.eq_ignore_ascii_case("host") {
            if host_seen || !is_loopback_host(value) {
                return Err("Only localhost Host headers are accepted".into());
            }
            host_seen = true;
            host = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err("Duplicate Content-Length headers are not supported".into());
            }
            content_length = Some(
                value
                    .parse::<usize>()
                    .map_err(|_| "Invalid Content-Length header".to_string())?,
            );
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err("Transfer-encoded requests are not supported".into());
        } else if name.eq_ignore_ascii_case("origin") {
            if origin.replace(value.to_string()).is_some() {
                return Err("Duplicate Origin headers are not supported".into());
            }
        } else if name.eq_ignore_ascii_case("content-type") {
            content_type = Some(value.to_string());
        }
    }
    if !host_seen {
        return Err("A localhost Host header is required".into());
    }
    let content_length = content_length.unwrap_or(0);
    if content_length > MAX_ACTION_BODY_BYTES {
        return Err("Request body exceeds the size limit".into());
    }
    if method == "GET" && content_length != 0 {
        return Err("GET request bodies are not supported".into());
    }
    if method == "POST" {
        let expected_origin = format!(
            "http://{}",
            host.as_deref()
                .ok_or_else(|| "A localhost Host header is required".to_string())?
        );
        if origin.as_deref() != Some(expected_origin.as_str()) {
            return Err("POST requests require a same-origin loopback Origin header".into());
        }
    }
    let body_start = header_end + 4;
    let body_end = body_start
        .checked_add(content_length)
        .ok_or_else(|| "Request length overflow".to_string())?;
    if body_end != bytes.len() {
        return Err("Incomplete request body or pipelined requests are not supported".into());
    }

    Ok(HttpRequest {
        method: method.to_string(),
        target: target.to_string(),
        content_type,
        body: bytes[body_start..body_end].to_vec(),
        raw: bytes.to_vec(),
    })
}

fn is_loopback_host(host: &str) -> bool {
    let hostname = if let Some(rest) = host.strip_prefix('[') {
        rest.split_once(']')
            .map(|(address, suffix)| {
                if suffix.is_empty()
                    || suffix
                        .strip_prefix(':')
                        .is_some_and(|port| port.parse::<u16>().is_ok())
                {
                    Some(address)
                } else {
                    None
                }
            })
            .flatten()
    } else if let Some((name, port)) = host.rsplit_once(':') {
        if port.parse::<u16>().is_ok() && !name.contains(':') {
            Some(name)
        } else {
            None
        }
    } else {
        Some(host)
    };
    matches!(hostname, Some("localhost" | "127.0.0.1" | "::1"))
}

fn parse_target(target: &str) -> Result<(&str, HashMap<String, String>), String> {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut params = HashMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(key)?;
        let value = percent_decode(value)?;
        if params.insert(key.clone(), value).is_some() {
            return Err(format!("Duplicate query parameter '{key}'"));
        }
    }
    Ok((path, params))
}

fn percent_decode(value: &str) -> Result<String, String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' => {
                if index + 2 >= bytes.len() {
                    return Err("Malformed percent encoding".into());
                }
                let high = hex_value(bytes[index + 1])
                    .ok_or_else(|| "Malformed percent encoding".to_string())?;
                let low = hex_value(bytes[index + 2])
                    .ok_or_else(|| "Malformed percent encoding".to_string())?;
                decoded.push((high << 4) | low);
                index += 3;
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(decoded).map_err(|_| "Query parameter is not valid UTF-8".into())
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn declared_content_length(bytes: &[u8]) -> Result<usize, String> {
    let headers =
        std::str::from_utf8(bytes).map_err(|_| "HTTP headers are not valid UTF-8".to_string())?;
    let mut content_length = None;
    for line in headers.split("\r\n").skip(1) {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| "Malformed HTTP header".to_string())?;
        if name.trim().eq_ignore_ascii_case("transfer-encoding") {
            return Err("Transfer-encoded requests are not supported".into());
        }
        if name.trim().eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err("Duplicate Content-Length headers are not supported".into());
            }
            let parsed = value
                .trim()
                .parse::<usize>()
                .map_err(|_| "Invalid Content-Length header".to_string())?;
            if parsed > MAX_ACTION_BODY_BYTES {
                return Err("Request body exceeds the size limit".into());
            }
            content_length = Some(parsed);
        }
    }
    Ok(content_length.unwrap_or(0))
}

async fn read_http_request(socket: &mut TcpStream) -> io::Result<Result<HttpRequest, String>> {
    let mut bytes = Vec::with_capacity(2048);
    let mut chunk = [0u8; 2048];
    let mut expected_length = None;
    loop {
        let limit = MAX_REQUEST_BYTES + MAX_ACTION_BODY_BYTES;
        if bytes.len() >= limit {
            return Ok(Err("HTTP request exceeds the size limit".into()));
        }
        let read = tokio::time::timeout(Duration::from_secs(10), socket.read(&mut chunk))
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "request read timed out"))??;
        if read == 0 {
            return Ok(Err(
                "Client closed before completing HTTP request headers".into()
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
        if expected_length.is_none() {
            if let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
                if header_end + 4 > MAX_REQUEST_BYTES {
                    return Ok(Err("HTTP request headers exceed the size limit".into()));
                }
                let body_length = match declared_content_length(&bytes[..header_end]) {
                    Ok(length) => length,
                    Err(error) => return Ok(Err(error)),
                };
                expected_length = Some(header_end + 4 + body_length);
            }
        }
        if let Some(expected_length) = expected_length {
            if bytes.len() > expected_length {
                return Ok(Err(
                    "Pipelined or trailing HTTP request bytes are not supported".into(),
                ));
            }
            if bytes.len() == expected_length {
                return Ok(parse_request(&bytes));
            }
        }
    }
}

async fn write_http_response(socket: &mut TcpStream, response: HttpResponse) -> io::Result<()> {
    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nContent-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'none'\r\n\r\n",
        response.status,
        response.reason,
        response.content_type,
        response.body.len()
    );
    socket.write_all(header.as_bytes()).await?;
    socket.write_all(&response.body).await?;
    socket.shutdown().await
}

fn query_value<'a>(
    params: &'a HashMap<String, String>,
    name: &str,
) -> Result<&'a str, HttpResponse> {
    params
        .get(name)
        .map(String::as_str)
        .ok_or_else(|| HttpResponse::error(400, "Bad Request", &format!("Missing '{name}'")))
}

fn handle_api(engine: &VcsEngine, target: &str) -> HttpResponse {
    match handle_api_inner(engine, target) {
        Ok(response) => response,
        Err(response) => response,
    }
}

fn handle_api_inner(engine: &VcsEngine, target: &str) -> Result<HttpResponse, HttpResponse> {
    let (path, params) =
        parse_target(target).map_err(|error| HttpResponse::error(400, "Bad Request", &error))?;

    let value = match path {
        "/api/branches" => {
            let heads = engine.branch_head_ids().map_err(internal_error)?;
            serde_json::json!({
                "branches": heads.into_iter().map(|(name, head)| {
                    serde_json::json!({ "name": name, "head": head })
                }).collect::<Vec<_>>(),
                "current": engine.current_branch().map_err(internal_error)?,
                "repository": engine.project_name(),
            })
        }
        "/api/history" => {
            let branch = query_value(&params, "branch")?;
            if !engine
                .branch_list()
                .map_err(internal_error)?
                .iter()
                .any(|candidate| candidate == branch)
            {
                return Err(HttpResponse::error(404, "Not Found", "Branch not found"));
            }
            let limit = bounded_usize(&params, "limit", 100, 1, 200)?;
            let ids = engine
                .branch_ancestry_ids(branch, limit)
                .map_err(internal_error)?;
            let commits = ids
                .iter()
                .map(|id| {
                    let commit = engine.get_commit(id).map_err(internal_error)?;
                    Ok(serde_json::json!({
                        "commit_id": commit.commit_id,
                        "parent_ids": commit.parent_ids,
                        "tree_hash": commit.tree_hash,
                        "author_callsign": commit.author_callsign,
                        "timestamp": commit.timestamp,
                        "message": commit.message,
                    }))
                })
                .collect::<Result<Vec<_>, _>>()?;
            serde_json::json!({ "branch": branch, "commits": commits })
        }
        "/api/commit" => {
            let id = query_value(&params, "id")?;
            let commit = engine
                .get_commit(id)
                .map_err(|error| HttpResponse::error(404, "Not Found", &error))?;
            serde_json::json!({
                "commit": {
                    "commit_id": commit.commit_id,
                    "parent_ids": commit.parent_ids,
                    "tree_hash": commit.tree_hash,
                    "author_callsign": commit.author_callsign,
                    "timestamp": commit.timestamp,
                    "message": commit.message,
                    "signature_ed25519": commit.signature_ed25519,
                    "ast_parser_version": commit.ast_parser_version,
                }
            })
        }
        "/api/changes" => {
            let commit_id = query_value(&params, "commit")?;
            let commit = engine
                .get_commit(commit_id)
                .map_err(|error| HttpResponse::error(404, "Not Found", &error))?;
            let new_tree = engine.get_tree(&commit.tree_hash).map_err(internal_error)?;
            let old_tree = match commit.parent_ids.first() {
                Some(parent_id) => {
                    let parent = engine.get_commit(parent_id).map_err(internal_error)?;
                    engine.get_tree(&parent.tree_hash).map_err(internal_error)?
                }
                None => crate::vcs::VcsTree::default(),
            };
            let limit = bounded_usize(&params, "limit", 100, 1, MAX_TREE_PAGE_SIZE)?;
            let offset = bounded_usize(&params, "offset", 0, 0, 100_000)?;
            let mut paths = old_tree
                .entries
                .keys()
                .map(String::as_str)
                .chain(new_tree.entries.keys().map(String::as_str))
                .collect::<Vec<_>>();
            paths.sort_unstable();
            paths.dedup();
            let mut total = 0;
            let mut added_count = 0;
            let mut modified_count = 0;
            let mut deleted_count = 0;
            let mut page = Vec::with_capacity(limit);
            for path in paths {
                let old = old_tree.entries.get(path).filter(|entry| !entry.is_dir);
                let new = new_tree.entries.get(path).filter(|entry| !entry.is_dir);
                if old.map(|entry| &entry.blake3_hash) == new.map(|entry| &entry.blake3_hash) {
                    continue;
                }
                let status = if old.is_none() {
                    added_count += 1;
                    "added"
                } else if new.is_none() {
                    deleted_count += 1;
                    "deleted"
                } else {
                    modified_count += 1;
                    "modified"
                };
                if total >= offset && page.len() < limit {
                    page.push(serde_json::json!({
                        "path": path,
                        "status": status,
                        "old_hash": old.map(|entry| entry.blake3_hash.as_str()),
                        "new_hash": new.map(|entry| entry.blake3_hash.as_str()),
                        "size_bytes": new.map(|entry| entry.size_bytes).unwrap_or(0),
                    }));
                }
                total += 1;
            }
            serde_json::json!({
                "commit": commit_id,
                "parent": commit.parent_ids.first(),
                "change_count": total,
                "added_count": added_count,
                "modified_count": modified_count,
                "deleted_count": deleted_count,
                "offset": offset,
                "limit": limit,
                "changes": page,
            })
        }
        "/api/diff" => {
            let commit_id = query_value(&params, "commit")?;
            let path = query_value(&params, "path")?;
            if path.len() > 4096 || path.contains('\0') {
                return Err(HttpResponse::error(
                    400,
                    "Bad Request",
                    "Invalid repository path",
                ));
            }
            let commit = engine
                .get_commit(commit_id)
                .map_err(|error| HttpResponse::error(404, "Not Found", &error))?;
            let new_tree = engine.get_tree(&commit.tree_hash).map_err(internal_error)?;
            let old_tree = match commit.parent_ids.first() {
                Some(parent_id) => {
                    let parent = engine.get_commit(parent_id).map_err(internal_error)?;
                    engine.get_tree(&parent.tree_hash).map_err(internal_error)?
                }
                None => crate::vcs::VcsTree::default(),
            };
            let old = old_tree.entries.get(path).filter(|entry| !entry.is_dir);
            let new = new_tree.entries.get(path).filter(|entry| !entry.is_dir);
            if old.is_none() && new.is_none() {
                return Err(HttpResponse::error(
                    404,
                    "Not Found",
                    "Path is not present in this commit or its parent",
                ));
            }
            let old_text = match old {
                Some(entry) => {
                    let bytes = engine
                        .get_blob_limited(&entry.blake3_hash, MAX_BLOB_BYTES)
                        .map_err(internal_error)?;
                    String::from_utf8(bytes).map_err(|_| {
                        HttpResponse::error(415, "Unsupported Media Type", "File is not UTF-8 text")
                    })?
                }
                None => String::new(),
            };
            let new_text = match new {
                Some(entry) => {
                    let bytes = engine
                        .get_blob_limited(&entry.blake3_hash, MAX_BLOB_BYTES)
                        .map_err(internal_error)?;
                    String::from_utf8(bytes).map_err(|_| {
                        HttpResponse::error(415, "Unsupported Media Type", "File is not UTF-8 text")
                    })?
                }
                None => String::new(),
            };
            let old_line_count = old_text.lines().count();
            let new_line_count = new_text.lines().count();
            if old_line_count > MAX_DIFF_LINES
                || new_line_count > MAX_DIFF_LINES
                || old_line_count.saturating_mul(new_line_count) > MAX_DIFF_CELLS
            {
                return Err(HttpResponse::error(
                    413,
                    "Payload Too Large",
                    "Diff is too large for the bounded line-diff algorithm; open the file instead",
                ));
            }
            let lines = crate::vcs::compute_unified_diff(&old_text, &new_text);
            serde_json::json!({
                "commit": commit_id,
                "path": path,
                "status": if old.is_none() { "added" } else if new.is_none() { "deleted" } else { "modified" },
                "old_hash": old.map(|entry| entry.blake3_hash.as_str()),
                "new_hash": new.map(|entry| entry.blake3_hash.as_str()),
                "old_line_count": old_line_count,
                "new_line_count": new_line_count,
                "lines": lines,
            })
        }
        "/api/worktree" => {
            let status = engine.status().map_err(internal_error)?;
            serde_json::json!({
                "branch": status.current_branch,
                "clean": status.is_clean,
                "modified_count": status.modified_count,
                "added_count": status.added_count,
                "deleted_count": status.deleted_count,
                "changes": status.changes,
            })
        }
        "/api/worktree-diff" => {
            let path = query_value(&params, "path")?;
            if path.len() > 4096 || path.contains('\0') {
                return Err(HttpResponse::error(
                    400,
                    "Bad Request",
                    "Invalid repository path",
                ));
            }
            let status = engine.status().map_err(internal_error)?;
            if !status.changes.iter().any(|change| change.rel_path == path) {
                return Err(HttpResponse::error(
                    404,
                    "Not Found",
                    "Path has no working-tree changes",
                ));
            }
            let diff = engine.diff_file(path).map_err(internal_error)?;
            serde_json::to_value(diff).map_err(|error| {
                HttpResponse::error(500, "Internal Server Error", &error.to_string())
            })?
        }
        "/api/tree" => {
            let commit_id = query_value(&params, "commit")?;
            let commit = engine
                .get_commit(commit_id)
                .map_err(|error| HttpResponse::error(404, "Not Found", &error))?;
            let tree = engine.get_tree(&commit.tree_hash).map_err(internal_error)?;
            let prefix = params.get("prefix").map(String::as_str).unwrap_or("");
            if prefix.len() > 1024 || prefix.contains('\0') {
                return Err(HttpResponse::error(
                    400,
                    "Bad Request",
                    "Invalid tree prefix",
                ));
            }
            let limit = bounded_usize(&params, "limit", 100, 1, MAX_TREE_PAGE_SIZE)?;
            let offset = bounded_usize(&params, "offset", 0, 0, 100_000)?;
            let mut entries = tree
                .entries
                .iter()
                .filter(|(path, _)| path.starts_with(prefix))
                .collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            let total = entries.len();
            let page = entries
                .into_iter()
                .skip(offset)
                .take(limit)
                .map(|(path, entry)| {
                    serde_json::json!({
                        "path": path,
                        "entry": entry,
                    })
                })
                .collect::<Vec<_>>();
            serde_json::json!({
                "commit": commit_id,
                "prefix": prefix,
                "offset": offset,
                "limit": limit,
                "total": total,
                "entries": page,
            })
        }
        "/api/blob" => {
            let id = query_value(&params, "id")?;
            let bytes = engine
                .get_blob_limited(id, MAX_BLOB_BYTES)
                .map_err(|error| {
                    let (status, reason) = if error.contains("maximum readable size") {
                        (413, "Payload Too Large")
                    } else {
                        (404, "Not Found")
                    };
                    HttpResponse::error(status, reason, &error)
                })?;
            let text = String::from_utf8(bytes).map_err(|_| {
                HttpResponse::error(415, "Unsupported Media Type", "Blob is not UTF-8 text")
            })?;
            return Ok(HttpResponse::new(
                200,
                "OK",
                "text/plain; charset=utf-8",
                text.into_bytes(),
            ));
        }
        _ => {
            return Err(HttpResponse::error(
                404,
                "Not Found",
                "Unknown API endpoint",
            ))
        }
    };

    HttpResponse::json(value).map_err(|error| HttpResponse::error(413, "Payload Too Large", &error))
}

fn internal_error(error: String) -> HttpResponse {
    HttpResponse::error(500, "Internal Server Error", &error)
}

fn bounded_usize(
    params: &HashMap<String, String>,
    name: &str,
    default: usize,
    min: usize,
    max: usize,
) -> Result<usize, HttpResponse> {
    let Some(value) = params.get(name) else {
        return Ok(default);
    };
    let parsed = value
        .parse::<usize>()
        .map_err(|_| HttpResponse::error(400, "Bad Request", &format!("Invalid '{name}' value")))?;
    if !(min..=max).contains(&parsed) {
        return Err(HttpResponse::error(
            400,
            "Bad Request",
            &format!("'{name}' must be between {min} and {max}"),
        ));
    }
    Ok(parsed)
}

pub async fn serve(workspace: PathBuf, bind: SocketAddr) -> Result<(), String> {
    if bind.ip() != std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST) {
        return Err("The code viewer must bind to 127.0.0.1 for the sb-node route".into());
    }
    let engine = Arc::new(VcsEngine::open(&workspace)?);
    let listener = TcpListener::bind(bind)
        .await
        .map_err(|error| format!("Could not bind viewer to {bind}: {error}"))?;
    println!(
        "Read-only sb-code viewer for {} listening at http://{}",
        workspace.display(),
        listener
            .local_addr()
            .map_err(|error| format!("Could not inspect viewer listener: {error}"))?
    );
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));

    loop {
        let (mut socket, peer) = listener
            .accept()
            .await
            .map_err(|error| format!("Viewer accept failed: {error}"))?;
        let permit = match permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                eprintln!("sb-code viewer at capacity; rejecting connection from {peer}");
                if let Err(error) = socket
                    .write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await
                {
                    eprintln!("Could not send viewer overload response to {peer}: {error}");
                }
                continue;
            }
        };
        let engine = engine.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(error) =
                tokio::time::timeout(Duration::from_secs(15), serve_connection(socket, engine))
                    .await
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::TimedOut, "viewer request timed out")
                    })
                    .and_then(|result| result)
            {
                eprintln!("sb-code viewer request from {peer} failed: {error}");
            }
        });
    }
}

async fn serve_connection(mut socket: TcpStream, engine: Arc<VcsEngine>) -> io::Result<()> {
    let parsed = read_http_request(&mut socket).await?;
    let response = match parsed {
        Ok(request) if request.method != "GET" => HttpResponse::error(
            405,
            "Method Not Allowed",
            "The repository viewer is read-only",
        ),
        Ok(request) if request.target == "/" => HttpResponse::new(
            200,
            "OK",
            "text/html; charset=utf-8",
            UI.as_bytes().to_vec(),
        ),
        Ok(request) if request.target == "/__client" => {
            match local_read_only_client_info(&engine) {
                Ok(value) => HttpResponse::json(value).unwrap_or_else(|error| {
                    HttpResponse::error(500, "Internal Server Error", &error)
                }),
                Err(error) => HttpResponse::error(500, "Internal Server Error", &error),
            }
        }
        Ok(request) if request.target.starts_with("/api/") => {
            let engine = engine.clone();
            let target = request.target;
            tokio::task::spawn_blocking(move || handle_api(&engine, &target))
                .await
                .map_err(|error| io::Error::other(format!("viewer handler task failed: {error}")))?
        }
        Ok(_) => HttpResponse::error(404, "Not Found", "Unknown viewer path"),
        Err(error) => HttpResponse::error(400, "Bad Request", &error),
    };
    write_http_response(&mut socket, response).await
}

fn local_read_only_client_info(engine: &VcsEngine) -> Result<serde_json::Value, String> {
    let status = engine.status()?;
    Ok(serde_json::json!({
        "available": false,
        "readOnly": true,
        "reason": "Read-only viewer — commit, push and pull require an active mesh proxy.",
        "branch": status.current_branch,
        "clean": status.is_clean,
        "modified_count": status.modified_count,
        "added_count": status.added_count,
        "deleted_count": status.deleted_count,
        "branches": engine.branch_list()?,
        "changes": status.changes,
    }))
}

#[derive(Clone)]
struct WebProxyConfig {
    source_mesh: String,
    target_mesh: String,
    anchor_addr: SocketAddr,
    workspace: Option<PathBuf>,
    capability_token: Option<PathBuf>,
    service_port: u16,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WebSyncAction {
    branch: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct WebCommitAction {
    message: String,
}

fn local_client_info(workspace: Option<&PathBuf>) -> Result<serde_json::Value, String> {
    let Some(workspace) = workspace else {
        return Ok(serde_json::json!({
            "available": false,
            "reason": "Start web-proxy with --workspace to enable local push and pull.",
        }));
    };
    let engine = VcsEngine::open(workspace)?;
    let status = engine.status()?;
    let branches = engine.branch_list()?;
    Ok(serde_json::json!({
        "available": true,
        "branch": status.current_branch,
        "clean": status.is_clean,
        "modified_count": status.modified_count,
        "added_count": status.added_count,
        "deleted_count": status.deleted_count,
        "branches": branches,
        "changes": status.changes,
    }))
}

fn local_worktree_diff(
    workspace: Option<&PathBuf>,
    path: &str,
) -> Result<serde_json::Value, HttpResponse> {
    let workspace = workspace.ok_or_else(|| {
        HttpResponse::error(
            409,
            "Conflict",
            "Start web-proxy with --workspace to inspect local changes",
        )
    })?;
    let engine = VcsEngine::open(workspace).map_err(internal_error)?;
    let status = engine.status().map_err(internal_error)?;
    let change = status
        .changes
        .iter()
        .find(|change| change.rel_path == path)
        .ok_or_else(|| HttpResponse::error(404, "Not Found", "Path has no local changes"))?;
    if change.size_bytes > MAX_BLOB_BYTES {
        return Err(HttpResponse::error(
            413,
            "Payload Too Large",
            "Working-tree file exceeds the 512 KiB diff limit",
        ));
    }
    let current_text = if change.status == "deleted" {
        String::new()
    } else {
        let root = engine.workspace_root().canonicalize().map_err(|error| {
            internal_error(format!("Could not resolve repository root: {error}"))
        })?;
        let full_path = root.join(path);
        let resolved_path = full_path
            .canonicalize()
            .map_err(|error| internal_error(format!("Could not resolve changed file: {error}")))?;
        if !resolved_path.starts_with(&root) {
            return Err(HttpResponse::error(
                400,
                "Bad Request",
                "Changed file resolves outside the repository",
            ));
        }
        let mut bytes = Vec::with_capacity(MAX_BLOB_BYTES as usize + 1);
        std::fs::File::open(&resolved_path)
            .and_then(|file| {
                file.take(MAX_BLOB_BYTES + 1)
                    .read_to_end(&mut bytes)
                    .map(|_| ())
            })
            .map_err(|error| internal_error(format!("Could not read changed file: {error}")))?;
        if bytes.len() as u64 > MAX_BLOB_BYTES {
            return Err(HttpResponse::error(
                413,
                "Payload Too Large",
                "Working-tree file exceeds the 512 KiB diff limit",
            ));
        }
        String::from_utf8(bytes).map_err(|_| {
            HttpResponse::error(
                415,
                "Unsupported Media Type",
                "Working-tree file is not UTF-8 text",
            )
        })?
    };
    let old_text = match (&status.head_commit, &change.old_hash) {
        (Some(head), Some(_)) => {
            let tree = engine.get_tree(&head.tree_hash).map_err(internal_error)?;
            match tree.entries.get(path).filter(|entry| !entry.is_dir) {
                Some(entry) => {
                    let bytes = engine
                        .get_blob_limited(&entry.blake3_hash, MAX_BLOB_BYTES)
                        .map_err(internal_error)?;
                    String::from_utf8(bytes).map_err(|_| {
                        HttpResponse::error(
                            415,
                            "Unsupported Media Type",
                            "HEAD file is not UTF-8 text",
                        )
                    })?
                }
                None => String::new(),
            }
        }
        _ => String::new(),
    };
    let old_line_count = old_text.lines().count();
    let new_line_count = current_text.lines().count();
    if old_line_count > MAX_DIFF_LINES
        || new_line_count > MAX_DIFF_LINES
        || old_line_count.saturating_mul(new_line_count) > MAX_DIFF_CELLS
    {
        return Err(HttpResponse::error(
            413,
            "Payload Too Large",
            "Diff is too large for the bounded line-diff algorithm; open the file instead",
        ));
    }
    Ok(serde_json::json!({
        "path": path,
        "status": change.status,
        "old_hash": change.old_hash,
        "new_hash": change.new_hash,
        "old_line_count": old_line_count,
        "new_line_count": new_line_count,
        "lines": crate::vcs::compute_unified_diff(&old_text, &current_text),
    }))
}

async fn handle_proxy_action(path: &str, body: &[u8], config: &WebProxyConfig) -> HttpResponse {
    let Some(workspace) = config.workspace.as_ref() else {
        return HttpResponse::error(
            409,
            "Conflict",
            "Local repository actions require starting web-proxy with --workspace",
        );
    };
    if path == "/__actions/commit" {
        let action: WebCommitAction = match serde_json::from_slice(body) {
            Ok(action) => action,
            Err(error) => {
                return HttpResponse::error(
                    400,
                    "Bad Request",
                    &format!("Invalid commit action: {error}"),
                )
            }
        };
        let message = action.message.trim();
        if message.is_empty() || message.len() > 2000 {
            return HttpResponse::error(
                400,
                "Bad Request",
                "Commit message must contain 1 to 2000 bytes",
            );
        }
        let mut engine = match VcsEngine::open(workspace) {
            Ok(engine) => engine,
            Err(error) => return HttpResponse::error(500, "Internal Server Error", &error),
        };
        match engine.status() {
            Ok(status) if status.is_clean => {
                return HttpResponse::error(409, "Conflict", "There are no local changes to commit")
            }
            Ok(_) => {}
            Err(error) => return HttpResponse::error(500, "Internal Server Error", &error),
        }
        return match engine.commit(message, &crate::session::get_active_callsign()) {
            Ok(commit) => match engine.current_branch() {
                Ok(branch) => HttpResponse::json(serde_json::json!({
                    "success": true,
                    "commit": {
                        "commit_id": commit.commit_id,
                        "branch": branch,
                        "message": commit.message,
                    },
                }))
                .unwrap_or_else(|error| HttpResponse::error(500, "Internal Server Error", &error)),
                Err(error) => HttpResponse::error(500, "Internal Server Error", &error),
            },
            Err(error) => HttpResponse::error(409, "Conflict", &error),
        };
    }
    let action: WebSyncAction = match serde_json::from_slice(body) {
        Ok(action) => action,
        Err(error) => {
            return HttpResponse::error(
                400,
                "Bad Request",
                &format!("Invalid sync action: {error}"),
            )
        }
    };
    if action.branch.is_empty()
        || action.branch.len() > 128
        || !action
            .branch
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return HttpResponse::error(400, "Bad Request", "Invalid branch name");
    }
    let engine = match VcsEngine::open(workspace) {
        Ok(engine) => engine,
        Err(error) => return HttpResponse::error(500, "Internal Server Error", &error),
    };
    let local_branches = match engine.branch_list() {
        Ok(branches) => branches,
        Err(error) => return HttpResponse::error(500, "Internal Server Error", &error),
    };
    if path == "/__actions/push" && !local_branches.iter().any(|b| b == &action.branch) {
        return HttpResponse::error(
            400,
            "Bad Request",
            "The selected branch does not exist in the local repository",
        );
    }
    let token = match crate::mesh_sync::read_capability_token(config.capability_token.as_deref()) {
        Ok(token) => token,
        Err(error) => return HttpResponse::error(400, "Bad Request", &error),
    };
    let report = match path {
        "/__actions/push" => {
            crate::mesh_sync::push_on_port(
                &engine,
                &config.source_mesh,
                &config.target_mesh,
                config.anchor_addr,
                config.service_port,
                &action.branch,
                token,
            )
            .await
        }
        "/__actions/pull" => {
            let mut engine = engine;
            crate::mesh_sync::pull_on_port(
                &mut engine,
                &config.source_mesh,
                &config.target_mesh,
                config.anchor_addr,
                config.service_port,
                &action.branch,
                token,
            )
            .await
        }
        _ => return HttpResponse::error(404, "Not Found", "Unknown local action"),
    };
    match report {
        Ok(report) => HttpResponse::json(serde_json::json!({
            "success": true,
            "report": report,
        }))
        .unwrap_or_else(|error| HttpResponse::error(500, "Internal Server Error", &error)),
        Err(error) => HttpResponse::error(502, "Bad Gateway", &error),
    }
}

/// Exposes only a loopback listener; every accepted connection gets its own authorized mesh stream.
pub async fn run_mesh_proxy(
    source_mesh: &str,
    target_mesh: &str,
    anchor_addr: SocketAddr,
    listen: SocketAddr,
    workspace: Option<PathBuf>,
    capability_token: Option<PathBuf>,
    service_port: u16,
) -> Result<(), String> {
    if source_mesh.trim().is_empty() || target_mesh.trim().is_empty() {
        return Err("Source and target mesh names must not be empty".into());
    }
    if !listen.ip().is_loopback() {
        return Err("The local viewer proxy must bind to a loopback address".into());
    }
    if let Some(workspace) = &workspace {
        VcsEngine::open(workspace).map_err(|error| {
            format!(
                "Could not open local repository {} for web actions: {error}",
                workspace.display()
            )
        })?;
    }
    crate::mesh_sync::read_capability_token(capability_token.as_deref())?;
    let proxy_config = Arc::new(WebProxyConfig {
        source_mesh: source_mesh.to_string(),
        target_mesh: target_mesh.to_string(),
        anchor_addr,
        workspace,
        capability_token,
        service_port,
    });
    let identity = Arc::new(
        NodeIdentity::load_or_generate_for_mesh(source_mesh)
            .map_err(|error| format!("Could not load mesh identity: {error}"))?,
    );
    if sb_mesh::ticket::load_cached_ticket(source_mesh).is_none() {
        sb_mesh::ticket::request_ticket(
            &anchor_addr.to_string(),
            &identity,
            source_mesh,
            Duration::from_millis(1500),
        )
        .await
        .map_err(|error| format!("Could not obtain a mesh ticket: {error}"))?;
    }
    let client = Arc::new(
        MeshClient::connect(MeshClientConfig {
            mesh_name: source_mesh.to_string(),
            swarm_topic: format!("sbm-swarm-{source_mesh}"),
            anchor_addr,
            identity,
            local_bind_port: None,
        })
        .await
        .map_err(|error| format!("Could not connect to sb-node mesh anchor: {error}"))?,
    );
    let listener = TcpListener::bind(listen)
        .await
        .map_err(|error| format!("Could not bind local proxy to {listen}: {error}"))?;
    println!(
        "Mesh viewer tunnel listening at http://{} -> {}:{}:{}",
        listener
            .local_addr()
            .map_err(|error| format!("Could not inspect proxy listener: {error}"))?,
        target_mesh,
        WEB_PORT,
        anchor_addr
    );
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_CONNECTIONS));
    let action_lock = Arc::new(tokio::sync::Mutex::new(()));

    loop {
        let (mut local, peer) = listener
            .accept()
            .await
            .map_err(|error| format!("Proxy accept failed: {error}"))?;
        let permit = match permits.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                eprintln!("sb-code web proxy at capacity; rejecting connection from {peer}");
                if let Err(error) = local
                    .write_all(
                        b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                    )
                    .await
                {
                    eprintln!("Could not send proxy overload response to {peer}: {error}");
                }
                continue;
            }
        };
        let client = client.clone();
        let config = proxy_config.clone();
        let action_lock = action_lock.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let result = proxy_connection(&mut local, client, config, action_lock).await;
            if let Err(error) = result {
                eprintln!("sb-code web proxy connection from {peer} failed: {error}");
            }
        });
    }
}

async fn proxy_connection(
    local: &mut TcpStream,
    client: Arc<MeshClient>,
    config: Arc<WebProxyConfig>,
    action_lock: Arc<tokio::sync::Mutex<()>>,
) -> Result<(), String> {
    let request = match read_http_request(local)
        .await
        .map_err(|error| format!("Could not read browser request: {error}"))?
    {
        Ok(request) => request,
        Err(error) => {
            write_http_response(local, HttpResponse::error(400, "Bad Request", &error))
                .await
                .map_err(|error| format!("Could not send bad-request response: {error}"))?;
            return Ok(());
        }
    };

    if request.method == "GET" && request.target == "/__client" {
        let workspace = config.workspace.clone();
        let response = tokio::task::spawn_blocking(move || {
            local_client_info(workspace.as_ref())
                .and_then(HttpResponse::json)
                .unwrap_or_else(|error| HttpResponse::error(500, "Internal Server Error", &error))
        })
        .await
        .map_err(|error| format!("Local repository status task failed: {error}"))?;
        write_http_response(local, response)
            .await
            .map_err(|error| format!("Could not send local repository status: {error}"))?;
        return Ok(());
    }

    if request.method == "GET" && request.target.starts_with("/__client/diff?") {
        let response = match parse_target(&request.target).and_then(|(path, params)| {
            if path != "/__client/diff" {
                return Err("Invalid local diff endpoint".to_string());
            }
            params
                .get("path")
                .cloned()
                .ok_or_else(|| "Missing 'path'".to_string())
        }) {
            Ok(path) => {
                let workspace = config.workspace.clone();
                match tokio::task::spawn_blocking(move || {
                    local_worktree_diff(workspace.as_ref(), &path)
                })
                .await
                {
                    Ok(Ok(data)) => HttpResponse::json(data).unwrap_or_else(|error| {
                        HttpResponse::error(500, "Internal Server Error", &error)
                    }),
                    Ok(Err(response)) => response,
                    Err(error) => HttpResponse::error(
                        500,
                        "Internal Server Error",
                        &format!("Local diff task failed: {error}"),
                    ),
                }
            }
            Err(error) => HttpResponse::error(400, "Bad Request", &error),
        };
        write_http_response(local, response)
            .await
            .map_err(|error| format!("Could not send local diff response: {error}"))?;
        return Ok(());
    }

    if request.method == "POST" {
        if request.content_type.as_deref() != Some("application/json") {
            write_http_response(
                local,
                HttpResponse::error(415, "Unsupported Media Type", "Expected application/json"),
            )
            .await
            .map_err(|error| format!("Could not send content-type error: {error}"))?;
            return Ok(());
        }
        if !matches!(
            request.target.as_str(),
            "/__actions/commit" | "/__actions/push" | "/__actions/pull"
        ) {
            write_http_response(
                local,
                HttpResponse::error(404, "Not Found", "Unknown local action"),
            )
            .await
            .map_err(|error| format!("Could not send unknown-action response: {error}"))?;
            return Ok(());
        }
        let _action_guard = action_lock.lock().await;
        let response = tokio::time::timeout(
            Duration::from_secs(600),
            handle_proxy_action(&request.target, &request.body, &config),
        )
        .await
        .unwrap_or_else(|_| {
            HttpResponse::error(
                504,
                "Gateway Timeout",
                "Mesh synchronization exceeded 10 minutes",
            )
        });
        write_http_response(local, response)
            .await
            .map_err(|error| format!("Could not send sync result: {error}"))?;
        return Ok(());
    }

    if request.method != "GET" {
        write_http_response(
            local,
            HttpResponse::error(
                405,
                "Method Not Allowed",
                "Only GET and local sync POST are allowed",
            ),
        )
        .await
        .map_err(|error| format!("Could not send method error: {error}"))?;
        return Ok(());
    }

    let mut stream = client
        .open_cross_mesh_stream(&config.target_mesh, WEB_PORT, None)
        .await
        .map_err(|error| format!("Mesh stream rejected: {error}"))?;
    stream
        .write_all(&request.raw)
        .await
        .map_err(|error| format!("Could not forward browser request to viewer: {error}"))?;
    tokio::time::timeout(
        Duration::from_secs(120),
        tokio::io::copy_bidirectional(local, &mut stream),
    )
    .await
    .map_err(|_| "Browser tunnel exceeded the 120-second connection limit".to_string())?
    .map_err(|error| format!("Browser tunnel failed: {error}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_get_only_loopback_requests() {
        let request =
            parse_request(b"GET /api/branches HTTP/1.1\r\nHost: 127.0.0.1:58836\r\n\r\n").unwrap();
        assert_eq!(
            request,
            HttpRequest {
                method: "GET".into(),
                target: "/api/branches".into(),
                content_type: None,
                body: Vec::new(),
                raw: b"GET /api/branches HTTP/1.1\r\nHost: 127.0.0.1:58836\r\n\r\n".to_vec(),
            }
        );
        assert!(parse_request(
            b"POST /api/branches HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n"
        )
        .is_err());
        assert!(parse_request(b"GET / HTTP/1.1\r\nHost: attacker.example\r\n\r\n").is_err());
        assert!(parse_request(
            b"GET / HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n"
        )
        .is_err());
    }

    #[test]
    fn parses_bounded_same_origin_action_posts() {
        let body = br#"{"message":"test"}"#;
        let mut request = format!(
            "POST /__actions/commit HTTP/1.1\r\nHost: localhost:58836\r\nOrigin: http://localhost:58836\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        let parsed = parse_request(&request).unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.content_type.as_deref(), Some("application/json"));
        assert_eq!(parsed.body, body);

        let wrong_origin = String::from_utf8(request.clone()).unwrap().replacen(
            "Origin: http://localhost:58836",
            "Origin: http://attacker.invalid",
            1,
        );
        assert!(parse_request(wrong_origin.as_bytes()).is_err());
        assert!(
            parse_request(b"GET / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\nx")
                .is_err()
        );
        assert!(parse_request(
            b"POST /__actions/commit HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n"
        )
        .is_err());
    }

    #[test]
    fn decodes_query_parameters_and_rejects_duplicates() {
        let (path, params) = parse_target("/api/tree?prefix=src%2Fmain.rs&limit=4").unwrap();
        assert_eq!(path, "/api/tree");
        assert_eq!(params["prefix"], "src/main.rs");
        assert_eq!(params["limit"], "4");
        assert!(parse_target("/api/tree?limit=1&limit=2").is_err());
        assert!(parse_target("/api/tree?prefix=%xx").is_err());
    }

    #[test]
    fn viewer_api_lists_commits_and_caps_blob_reads() {
        let root = std::env::temp_dir().join(format!("sb-code-web-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let result = (|| {
            let mut engine = VcsEngine::init(&root).unwrap();
            std::fs::write(root.join("small.txt"), "hello viewer\n").unwrap();
            std::fs::write(
                root.join("large.txt"),
                vec![b'x'; MAX_BLOB_BYTES as usize + 1],
            )
            .unwrap();
            let commit = engine.commit("viewer test", "test").unwrap();

            let branches = handle_api(&engine, "/api/branches");
            assert_eq!(branches.status, 200);
            let branches: serde_json::Value = serde_json::from_slice(&branches.body).unwrap();
            assert_eq!(branches["current"], "main");

            let history = handle_api(&engine, "/api/history?branch=main&limit=10");
            assert_eq!(history.status, 200);
            let history: serde_json::Value = serde_json::from_slice(&history.body).unwrap();
            assert_eq!(history["commits"][0]["commit_id"], commit.commit_id);

            let tree = handle_api(
                &engine,
                &format!("/api/tree?commit={}&limit=10", commit.commit_id),
            );
            assert_eq!(tree.status, 200);
            let tree: serde_json::Value = serde_json::from_slice(&tree.body).unwrap();
            let files = tree["entries"].as_array().unwrap();
            let small = files
                .iter()
                .find(|entry| entry["path"] == "small.txt")
                .unwrap();
            let small_blob = small["entry"]["blake3_hash"].as_str().unwrap();
            let blob = handle_api(&engine, &format!("/api/blob?id={small_blob}"));
            assert_eq!(blob.status, 200);
            assert_eq!(blob.body, b"hello viewer\n");

            let large = files
                .iter()
                .find(|entry| entry["path"] == "large.txt")
                .unwrap();
            let large_blob = large["entry"]["blake3_hash"].as_str().unwrap();
            let blob = handle_api(&engine, &format!("/api/blob?id={large_blob}"));
            assert_eq!(blob.status, 413);
            Ok::<(), String>(())
        })();
        let cleanup = std::fs::remove_dir_all(&root);
        assert!(
            cleanup.is_ok(),
            "test workspace cleanup failed: {cleanup:?}"
        );
        result.unwrap();
    }

    #[test]
    fn commit_change_pages_and_diff_report_file_edits() {
        let root = std::env::temp_dir().join(format!("sb-code-web-diff-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let result = (|| {
            let mut engine = VcsEngine::init(&root).unwrap();
            std::fs::write(root.join("existing.txt"), "before\n").unwrap();
            engine.commit("initial", "test")?;
            std::fs::write(root.join("existing.txt"), "after\n").unwrap();
            std::fs::write(root.join("new.txt"), "new file\n").unwrap();
            let commit = engine.commit("update files", "test")?;

            let first_page = handle_api(
                &engine,
                &format!("/api/changes?commit={}&limit=1", commit.commit_id),
            );
            assert_eq!(first_page.status, 200);
            let first_page: serde_json::Value = serde_json::from_slice(&first_page.body).unwrap();
            assert_eq!(first_page["change_count"], 2);
            assert_eq!(first_page["added_count"], 1);
            assert_eq!(first_page["modified_count"], 1);
            assert_eq!(first_page["changes"].as_array().unwrap().len(), 1);
            let second_page = handle_api(
                &engine,
                &format!("/api/changes?commit={}&limit=1&offset=1", commit.commit_id),
            );
            let second_page: serde_json::Value = serde_json::from_slice(&second_page.body).unwrap();
            assert_eq!(second_page["changes"].as_array().unwrap().len(), 1);

            let diff = handle_api(
                &engine,
                &format!("/api/diff?commit={}&path=existing.txt", commit.commit_id),
            );
            assert_eq!(diff.status, 200);
            let diff: serde_json::Value = serde_json::from_slice(&diff.body).unwrap();
            let lines = diff["lines"].as_array().unwrap();
            assert!(lines.iter().any(|line| line["change_type"] == "-"));
            assert!(lines.iter().any(|line| line["change_type"] == "+"));
            Ok::<(), String>(())
        })();
        let cleanup = std::fs::remove_dir_all(&root);
        assert!(
            cleanup.is_ok(),
            "test workspace cleanup failed: {cleanup:?}"
        );
        result.unwrap();
    }

    #[test]
    fn local_worktree_diff_returns_only_tracked_repository_changes() {
        let root =
            std::env::temp_dir().join(format!("sb-code-web-worktree-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let result = (|| {
            let mut engine = VcsEngine::init(&root)?;
            std::fs::write(root.join("file.txt"), "before\n").map_err(|error| error.to_string())?;
            engine.commit("initial", "test")?;
            std::fs::write(root.join("file.txt"), "after\n").map_err(|error| error.to_string())?;
            let diff = local_worktree_diff(Some(&root), "file.txt")
                .unwrap_or_else(|response| panic!("unexpected diff response: {}", response.status));
            let lines = diff["lines"].as_array().unwrap();
            assert!(lines.iter().any(|line| line["change_type"] == "-"));
            assert!(lines.iter().any(|line| line["change_type"] == "+"));
            assert_eq!(
                local_worktree_diff(Some(&root), "../outside.txt")
                    .unwrap_err()
                    .status,
                404
            );
            Ok::<(), String>(())
        })();
        let cleanup = std::fs::remove_dir_all(&root);
        assert!(
            cleanup.is_ok(),
            "test workspace cleanup failed: {cleanup:?}"
        );
        result.unwrap();
    }

    #[test]
    fn standalone_viewer_reports_local_status_without_enabling_actions() {
        let root =
            std::env::temp_dir().join(format!("sb-code-web-readonly-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let result = (|| {
            let mut engine = VcsEngine::init(&root)?;
            std::fs::write(root.join("file.txt"), "before\n").map_err(|error| error.to_string())?;
            engine.commit("initial", "test")?;
            std::fs::write(root.join("file.txt"), "after\n").map_err(|error| error.to_string())?;

            let client = local_read_only_client_info(&engine)?;
            assert_eq!(client["available"], false);
            assert_eq!(client["readOnly"], true);
            assert_eq!(client["branch"], "main");
            assert_eq!(client["changes"].as_array().unwrap().len(), 1);
            Ok::<(), String>(())
        })();
        let cleanup = std::fs::remove_dir_all(&root);
        assert!(
            cleanup.is_ok(),
            "test workspace cleanup failed: {cleanup:?}"
        );
        result.unwrap();
    }

    #[tokio::test]
    async fn local_proxy_commit_action_creates_a_commit_without_mesh_access() {
        let root =
            std::env::temp_dir().join(format!("sb-code-web-action-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&root).unwrap();
        let result = async {
            let mut engine = VcsEngine::init(&root)?;
            std::fs::write(root.join("file.txt"), "first\n").map_err(|error| error.to_string())?;
            engine.commit("initial", "test")?;
            std::fs::write(root.join("file.txt"), "changed\n")
                .map_err(|error| error.to_string())?;

            let config = WebProxyConfig {
                source_mesh: "source".into(),
                target_mesh: "target".into(),
                anchor_addr: "127.0.0.1:58888".parse().unwrap(),
                workspace: Some(root.clone()),
                capability_token: None,
                service_port: crate::mesh_sync::CODE_SYNC_PORT,
            };
            let response = handle_proxy_action(
                "/__actions/commit",
                br#"{"message":"web action commit"}"#,
                &config,
            )
            .await;
            assert_eq!(response.status, 200);
            let body: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
            assert_eq!(body["commit"]["message"], "web action commit");
            assert!(VcsEngine::open(&root)?.status()?.is_clean);

            let invalid = handle_proxy_action("/__actions/commit", b"{}", &config).await;
            assert_eq!(invalid.status, 400);
            Ok::<(), String>(())
        }
        .await;
        let cleanup = std::fs::remove_dir_all(&root);
        assert!(
            cleanup.is_ok(),
            "test workspace cleanup failed: {cleanup:?}"
        );
        result.unwrap();
    }
}
