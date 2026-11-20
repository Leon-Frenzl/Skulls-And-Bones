use std::io;
use std::path::{Path, PathBuf};
use tokio::fs::File;
use tokio::io::{AsyncWrite, AsyncWriteExt};

pub async fn serve<S>(
    client: &mut S,
    root: &Path,
    method: &str,
    request_target: &str,
) -> Result<u16, Box<dyn std::error::Error + Send + Sync>>
where
    S: AsyncWrite + Unpin,
{
    if method != "GET" && method != "HEAD" {
        write_response(
            client,
            405,
            "Method Not Allowed",
            "text/plain; charset=utf-8",
            b"Only GET and HEAD are supported.\n",
            "Allow: GET, HEAD\r\n",
        )
        .await?;
        return Ok(405);
    }

    let file_path = match resolve_file(root, request_target) {
        Ok(path) => path,
        Err(ResolveError::BadRequest) => {
            write_response(
                client,
                400,
                "Bad Request",
                "text/plain; charset=utf-8",
                b"Invalid request path.\n",
                "",
            )
            .await?;
            return Ok(400);
        }
        Err(ResolveError::NotFound) => {
            write_response(
                client,
                404,
                "Not Found",
                "text/plain; charset=utf-8",
                b"Not found.\n",
                "",
            )
            .await?;
            return Ok(404);
        }
        Err(ResolveError::Forbidden) => {
            write_response(
                client,
                403,
                "Forbidden",
                "text/plain; charset=utf-8",
                b"Forbidden.\n",
                "",
            )
            .await?;
            return Ok(403);
        }
    };

    let mut file = File::open(&file_path).await?;
    let size = file.metadata().await?.len();
    let content_type = content_type(&file_path);
    let cache_control = if is_release_metadata(&file_path) {
        "no-cache"
    } else {
        "public, max-age=300"
    };
    let response_head = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {size}\r\nCache-Control: {cache_control}\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n"
    );
    client.write_all(response_head.as_bytes()).await?;
    if method == "GET" {
        tokio::io::copy(&mut file, client).await?;
    }
    Ok(200)
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum ResolveError {
    BadRequest,
    NotFound,
    Forbidden,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(crate) struct StaticFileOptions {
    pub spa_fallback: bool,
}

pub(crate) fn resolve_file(root: &Path, request_target: &str) -> Result<PathBuf, ResolveError> {
    resolve_file_with_options(root, request_target, StaticFileOptions::default())
}

pub(crate) fn resolve_file_with_options(
    root: &Path,
    request_target: &str,
    options: StaticFileOptions,
) -> Result<PathBuf, ResolveError> {
    // CVE-Threat: URL traversal and symlinks could expose files outside the published directory.
    // Analysis: Decoding before component checks catches encoded separators and dot segments.
    // Hardening: Reject hidden/traversal paths and require the canonical file to remain under root.
    let root = std::fs::canonicalize(root).map_err(|_| ResolveError::NotFound)?;
    if !root.is_dir() {
        return Err(ResolveError::NotFound);
    }
    let uri_path = request_target
        .split_once('?')
        .map_or(request_target, |(path, _)| path);
    if !uri_path.starts_with('/') || uri_path.contains('#') {
        return Err(ResolveError::BadRequest);
    }

    let decoded = percent_decode(uri_path).ok_or(ResolveError::BadRequest)?;
    if decoded.contains('\\') || decoded.contains('\0') {
        return Err(ResolveError::BadRequest);
    }

    let mut candidate = root.clone();
    for segment in decoded.split('/').skip(1) {
        if segment.is_empty() {
            continue;
        }
        if segment == "." || segment == ".." || segment.starts_with('.') || segment.contains(':') {
            return Err(ResolveError::Forbidden);
        }
        candidate.push(segment);
    }

    let canonical_res = std::fs::canonicalize(&candidate);
    let candidate = match canonical_res {
        Ok(c) => c,
        Err(error) => {
            if error.kind() == io::ErrorKind::NotFound {
                if options.spa_fallback {
                    let index = std::fs::canonicalize(root.join("index.html"))
                        .map_err(|_| ResolveError::NotFound)?;
                    if index.starts_with(&root) && index.is_file() {
                        return Ok(index);
                    }
                }
                return Err(ResolveError::NotFound);
            } else {
                return Err(ResolveError::Forbidden);
            }
        }
    };

    if !candidate.starts_with(&root) {
        return Err(ResolveError::Forbidden);
    }
    if candidate.is_dir() {
        let index = std::fs::canonicalize(candidate.join("index.html"))
            .map_err(|_| ResolveError::NotFound)?;
        if !index.starts_with(&root) {
            return Err(ResolveError::Forbidden);
        }
        if !index.is_file() {
            if options.spa_fallback {
                let root_index = std::fs::canonicalize(root.join("index.html"))
                    .map_err(|_| ResolveError::NotFound)?;
                if root_index.starts_with(&root) && root_index.is_file() {
                    return Ok(root_index);
                }
            }
            return Err(ResolveError::NotFound);
        }
        return Ok(index);
    }
    if !candidate.is_file() {
        if options.spa_fallback {
            let index = std::fs::canonicalize(root.join("index.html"))
                .map_err(|_| ResolveError::NotFound)?;
            if index.starts_with(&root) && index.is_file() {
                return Ok(index);
            }
        }
        return Err(ResolveError::NotFound);
    }
    Ok(candidate)
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = *bytes.get(index + 1)?;
            let low = *bytes.get(index + 2)?;
            decoded.push((hex_value(high)? << 4) | hex_value(low)?);
            index += 3;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(decoded).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn content_type(path: &Path) -> String {
    let mime = mime_guess::from_path(path)
        .first_or_octet_stream()
        .essence_str()
        .to_owned();
    if mime.starts_with("text/") && mime != "text/event-stream" {
        format!("{mime}; charset=utf-8")
    } else {
        mime
    }
}

fn is_release_metadata(path: &Path) -> bool {
    matches!(
        path.file_name().and_then(|name| name.to_str()),
        Some("release-manifest.json" | "release-manifest.json.ed25519")
    )
}

async fn write_response<S>(
    client: &mut S,
    status: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
    extra_headers: &str,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let response_head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\n{extra_headers}Connection: close\r\n\r\n",
        body.len()
    );
    client.write_all(response_head.as_bytes()).await?;
    client.write_all(body).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "sb-static-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }

    #[test]
    fn static_path_resolution_serves_index_and_files_without_escape() {
        let root = test_root();
        fs::create_dir_all(root.join("nested")).unwrap();
        fs::write(root.join("index.html"), b"homepage").unwrap();
        fs::write(root.join("nested").join("app.js"), b"app").unwrap();
        let outside = root.with_extension("secret");
        fs::write(&outside, b"secret").unwrap();

        assert_eq!(
            resolve_file(&root, "/"),
            Ok(root.canonicalize().unwrap().join("index.html"))
        );
        assert_eq!(
            resolve_file(&root, "/nested/app.js?v=1"),
            Ok(root.canonicalize().unwrap().join("nested").join("app.js"))
        );
        assert_eq!(resolve_file(&root, "/missing"), Err(ResolveError::NotFound));
        assert_eq!(
            resolve_file(&root, "/%2e%2e/secret"),
            Err(ResolveError::Forbidden)
        );
        assert_eq!(resolve_file(&root, "/.env"), Err(ResolveError::Forbidden));
        assert_eq!(resolve_file(&root, "/%ZZ"), Err(ResolveError::BadRequest));

        // Test SPA fallback
        let spa_options = StaticFileOptions { spa_fallback: true };
        assert_eq!(
            resolve_file_with_options(&root, "/missing-route", spa_options),
            Ok(root.canonicalize().unwrap().join("index.html"))
        );
        // Hidden files/traversal still forbidden even with SPA fallback
        assert_eq!(
            resolve_file_with_options(&root, "/.env", spa_options),
            Err(ResolveError::Forbidden)
        );

        fs::remove_dir_all(&root).unwrap();
        fs::remove_file(outside).unwrap();
    }

    #[tokio::test]
    async fn static_server_handles_get_head_and_rejects_other_methods() {
        let root = test_root();
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("index.html"), b"homepage").unwrap();

        for (method, expected_status, body) in [
            ("GET", 200, b"homepage".as_slice()),
            ("HEAD", 200, b"".as_slice()),
            (
                "POST",
                405,
                b"Only GET and HEAD are supported.\n".as_slice(),
            ),
        ] {
            let (mut server, mut client) = tokio::io::duplex(1024);
            assert_eq!(
                serve(&mut server, &root, method, "/").await.unwrap(),
                expected_status
            );
            server.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            let response = String::from_utf8(response).unwrap();
            assert!(response.starts_with(&format!("HTTP/1.1 {expected_status}")));
            assert!(response.ends_with(std::str::from_utf8(body).unwrap()));
        }

        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn static_path_resolution_rejects_symlinks_outside_root() {
        use std::os::unix::fs::symlink;

        let root = test_root();
        fs::create_dir_all(&root).unwrap();
        let outside = root.with_extension("secret");
        fs::write(&outside, b"secret").unwrap();
        symlink(&outside, root.join("escape")).unwrap();

        assert_eq!(resolve_file(&root, "/escape"), Err(ResolveError::Forbidden));

        fs::remove_dir_all(root).unwrap();
        fs::remove_file(outside).unwrap();
    }
}
