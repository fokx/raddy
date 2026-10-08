use async_trait::async_trait;
use bytes::Bytes;
use http::{HeaderValue, StatusCode};
use raddy_core::context::Context;
use raddy_core::error::Result;
use raddy_core::handler::Handler;
use std::path::{Path, PathBuf};

/// Static file server handler implementing Caddy's `file_server` directive.
#[derive(Debug, Clone)]
pub struct FileServerHandler {
    pub root: Option<String>,
    pub browse: bool,
    pub hide: Vec<String>,
}

impl FileServerHandler {
    pub fn new(root: Option<String>, browse: bool, hide: Vec<String>) -> Self {
        Self { root, browse, hide }
    }
}

#[async_trait]
impl Handler for FileServerHandler {
    async fn handle(&self, ctx: &mut Context) -> Result<()> {
        let root_str = self
            .root
            .as_deref()
            .or_else(|| ctx.get_var("root"))
            .unwrap_or(".");

        let root_path = PathBuf::from(root_str);
        let req_path = ctx.uri.path().to_string();

        // Check hidden files/directories
        for seg in req_path.split('/') {
            if !seg.is_empty() && self.hide.iter().any(|h| h == seg) {
                ctx.set_response(StatusCode::NOT_FOUND, "404 Not Found\n");
                return Ok(());
            }
        }

        // Strip leading slash to join relative to root
        let clean_path = req_path.trim_start_matches('/');
        let target_path = root_path.join(clean_path);

        // Security check: ensure path does not escape root (directory traversal)
        let canonical_root = match root_path.canonicalize() {
            Ok(p) => p,
            Err(_) => {
                ctx.set_response(
                    StatusCode::NOT_FOUND,
                    "404 Not Found: Root directory not accessible\n",
                );
                return Ok(());
            }
        };

        let canonical_target = match target_path.canonicalize() {
            Ok(p) => p,
            Err(_) => {
                ctx.set_response(StatusCode::NOT_FOUND, "404 Not Found\n");
                return Ok(());
            }
        };

        if !canonical_target.starts_with(&canonical_root) {
            ctx.set_response(StatusCode::FORBIDDEN, "403 Forbidden: Access denied\n");
            return Ok(());
        }

        // If directory, check for index.html or directory browse
        if canonical_target.is_dir() {
            // Enforce trailing slash on directory URLs so relative links in directory listings resolve correctly
            let orig_path = ctx.orig_uri.path();
            if !orig_path.ends_with('/') {
                let query = ctx
                    .orig_uri
                    .query()
                    .map(|q| format!("?{}", q))
                    .unwrap_or_default();
                let redirect_to = format!("{}/{}", orig_path, query);
                if let Ok(loc) = HeaderValue::try_from(redirect_to) {
                    ctx.response_headers.insert(http::header::LOCATION, loc);
                }
                ctx.status = Some(StatusCode::PERMANENT_REDIRECT);
                ctx.response_written = true;
                return Ok(());
            }

            let index_file = canonical_target.join("index.html");
            if index_file.is_file() {
                return serve_file(&index_file, ctx).await;
            }

            if self.browse {
                return render_directory_listing(&canonical_target, &req_path, &self.hide, ctx)
                    .await;
            } else {
                ctx.set_response(
                    StatusCode::NOT_FOUND,
                    "404 Not Found: Directory index forbidden\n",
                );
                return Ok(());
            }
        }

        if canonical_target.is_file() {
            return serve_file(&canonical_target, ctx).await;
        }

        ctx.set_response(StatusCode::NOT_FOUND, "404 Not Found\n");
        Ok(())
    }
}

const STREAM_THRESHOLD: u64 = 64 * 1024; // 64 KB
const CHUNK_SIZE: usize = 64 * 1024; // 64 KB read buffer

#[derive(Debug, PartialEq, Eq)]
enum FileRange {
    Full,
    Partial(u64, u64),
    NotSatisfiable,
}

fn parse_range(range_header: &str, file_len: u64) -> FileRange {
    if file_len == 0 {
        return FileRange::NotSatisfiable;
    }
    let range_header = range_header.trim();
    if !range_header.starts_with("bytes=") {
        return FileRange::Full;
    }
    let spec = &range_header["bytes=".len()..].trim();
    let first_range = spec.split(',').next().unwrap_or("").trim();
    let parts: Vec<&str> = first_range.split('-').collect();
    if parts.len() != 2 {
        return FileRange::Full;
    }
    let (start_str, end_str) = (parts[0].trim(), parts[1].trim());
    if start_str.is_empty() {
        if let Ok(suffix) = end_str.parse::<u64>() {
            if suffix == 0 {
                return FileRange::NotSatisfiable;
            }
            let start = if suffix >= file_len {
                0
            } else {
                file_len - suffix
            };
            let end = file_len - 1;
            FileRange::Partial(start, end)
        } else {
            FileRange::Full
        }
    } else if end_str.is_empty() {
        if let Ok(start) = start_str.parse::<u64>() {
            if start >= file_len {
                FileRange::NotSatisfiable
            } else {
                FileRange::Partial(start, file_len - 1)
            }
        } else {
            FileRange::Full
        }
    } else if let (Ok(start), Ok(end)) = (start_str.parse::<u64>(), end_str.parse::<u64>()) {
        if start > end || start >= file_len {
            FileRange::NotSatisfiable
        } else {
            let end = std::cmp::min(end, file_len - 1);
            FileRange::Partial(start, end)
        }
    } else {
        FileRange::Full
    }
}

async fn serve_file(file_path: &Path, ctx: &mut Context) -> Result<()> {
    let mut file = match tokio::fs::File::open(file_path).await {
        Ok(f) => f,
        Err(_) => {
            ctx.set_response(StatusCode::NOT_FOUND, "404 Not Found\n");
            return Ok(());
        }
    };

    let metadata = match file.metadata().await {
        Ok(m) => m,
        Err(_) => {
            ctx.set_response(StatusCode::NOT_FOUND, "404 Not Found\n");
            return Ok(());
        }
    };

    let file_len = metadata.len();
    let modified = metadata
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // ETag format: W/"<len>-<mtime>"
    let etag = format!("W/\"{}-{}\"", file_len, modified);

    // Check If-None-Match for 304 Not Modified
    if let Some(inm) = ctx.headers.get(http::header::IF_NONE_MATCH) {
        if let Ok(inm_str) = inm.to_str() {
            if inm_str == etag || inm_str == "*" {
                ctx.status = Some(StatusCode::NOT_MODIFIED);
                ctx.response_written = true;
                if let Ok(val) = HeaderValue::try_from(&etag) {
                    ctx.response_headers.insert(http::header::ETAG, val);
                }
                return Ok(());
            }
        }
    }

    // Check If-Modified-Since for 304 Not Modified
    if let Some(ims) = ctx.headers.get(http::header::IF_MODIFIED_SINCE) {
        if let Ok(ims_str) = ims.to_str() {
            if let Ok(ims_time) = httpdate::parse_http_date(ims_str) {
                if let Ok(mtime) = metadata.modified() {
                    let mtime_secs = mtime
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    let ims_secs = ims_time
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs();
                    if mtime_secs <= ims_secs {
                        ctx.status = Some(StatusCode::NOT_MODIFIED);
                        ctx.response_written = true;
                        if let Ok(val) = HeaderValue::try_from(&etag) {
                            ctx.response_headers.insert(http::header::ETAG, val);
                        }
                        return Ok(());
                    }
                }
            }
        }
    }

    let mime_type = mime_guess::from_path(file_path).first_or_octet_stream();

    if let Ok(val) = HeaderValue::try_from(mime_type.as_ref()) {
        ctx.response_headers.insert(http::header::CONTENT_TYPE, val);
    }
    if let Ok(val) = HeaderValue::try_from(&etag) {
        ctx.response_headers.insert(http::header::ETAG, val);
    }
    if let Ok(mtime) = metadata.modified() {
        if let Ok(val) = HeaderValue::try_from(httpdate::fmt_http_date(mtime)) {
            ctx.response_headers
                .insert(http::header::LAST_MODIFIED, val);
        }
    }
    ctx.response_headers.insert(
        http::header::ACCEPT_RANGES,
        HeaderValue::from_static("bytes"),
    );

    let range = ctx
        .headers
        .get(http::header::RANGE)
        .and_then(|r| r.to_str().ok())
        .map(|r| parse_range(r, file_len));

    let (status, start, length) = match range {
        Some(FileRange::Partial(start, end)) => {
            let length = end - start + 1;
            if let Ok(val) = HeaderValue::try_from(format!("bytes {}-{}/{}", start, end, file_len))
            {
                ctx.response_headers
                    .insert(http::header::CONTENT_RANGE, val);
            }
            if let Ok(val) = HeaderValue::try_from(length.to_string()) {
                ctx.response_headers
                    .insert(http::header::CONTENT_LENGTH, val);
            }
            (StatusCode::PARTIAL_CONTENT, start, length)
        }
        Some(FileRange::NotSatisfiable) => {
            if let Ok(val) = HeaderValue::try_from(format!("bytes */{}", file_len)) {
                ctx.response_headers
                    .insert(http::header::CONTENT_RANGE, val);
            }
            ctx.set_response(StatusCode::RANGE_NOT_SATISFIABLE, Bytes::new());
            return Ok(());
        }
        _ => {
            if let Ok(val) = HeaderValue::try_from(file_len.to_string()) {
                ctx.response_headers
                    .insert(http::header::CONTENT_LENGTH, val);
            }
            (StatusCode::OK, 0, file_len)
        }
    };

    // If HEAD request, set headers and return empty body
    if ctx.method == http::Method::HEAD {
        ctx.status = Some(status);
        ctx.response_body = Some(Bytes::new());
        ctx.response_written = true;
        return Ok(());
    }

    if length == 0 {
        ctx.set_response(status, Bytes::new());
        return Ok(());
    }

    use tokio::io::{AsyncReadExt, AsyncSeekExt};

    // For small payloads (<= STREAM_THRESHOLD), read into memory to avoid stream overhead and support middleware/tests
    if length <= STREAM_THRESHOLD {
        if start > 0 {
            if let Err(e) = file.seek(std::io::SeekFrom::Start(start)).await {
                ctx.set_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("500 Seek error: {}\n", e),
                );
                return Ok(());
            }
        }
        let mut buf = vec![0u8; length as usize];
        if let Err(e) = file.read_exact(&mut buf).await {
            ctx.set_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("500 Read error: {}\n", e),
            );
            return Ok(());
        }
        ctx.set_response(status, buf);
        return Ok(());
    }

    // For large files (> 64KB, several GBs), STREAM chunks without loading the whole file into RAM!
    if start > 0 {
        if let Err(e) = file.seek(std::io::SeekFrom::Start(start)).await {
            ctx.set_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("500 Seek error: {}\n", e),
            );
            return Ok(());
        }
    }

    let limited = file.take(length);
    let stream = tokio_util::io::ReaderStream::with_capacity(limited, CHUNK_SIZE);
    ctx.set_response_stream(status, stream);
    Ok(())
}

async fn render_directory_listing(
    dir_path: &Path,
    req_path: &str,
    hide: &[String],
    ctx: &mut Context,
) -> Result<()> {
    let mut entries = match tokio::fs::read_dir(dir_path).await {
        Ok(rd) => rd,
        Err(_) => {
            ctx.set_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "500 Could not read directory\n",
            );
            return Ok(());
        }
    };

    let clean_req = req_path.trim_matches('/');
    let mut items = Vec::new();

    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if hide.iter().any(|h| h == &name) {
            continue;
        }
        let is_dir = entry
            .file_type()
            .await
            .map(|ft| ft.is_dir())
            .unwrap_or(false);
        items.push((name, is_dir));
    }

    items.sort_by(|a, b| {
        if a.1 != b.1 {
            b.1.cmp(&a.1) // directories first
        } else {
            a.0.cmp(&b.0)
        }
    });

    let display_path = ctx.orig_uri.path();
    let mut html = format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Index of {}</title>\
        <style>body{{font-family:sans-serif;margin:2em;}}ul{{list-style:none;padding:0;}}li{{padding:0.3em 0;}}a{{text-decoration:none;}}a:hover{{text-decoration:underline;}}</style>\
        </head><body><h1>Index of {}</h1><hr><ul>",
        display_path, display_path
    );

    if !clean_req.is_empty() {
        html.push_str("<li><a href=\"..\">&larr; Parent Directory</a></li>");
    }

    for (name, is_dir) in items {
        let slash = if is_dir { "/" } else { "" };
        let link = format!("./{}{}", name, slash);
        html.push_str(&format!(
            "<li><a href=\"{}\">{}{}</a></li>",
            link, name, slash
        ));
    }

    html.push_str("</ul><hr><p><small>Powered by Raddy</small></p></body></html>");

    ctx.response_headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    ctx.set_response(StatusCode::OK, html);
    Ok(())
}
