use std::path::{Path, PathBuf};
use async_trait::async_trait;
use http::{HeaderValue, StatusCode};
use raddy_core::context::Context;
use raddy_core::error::Result;
use raddy_core::handler::Handler;

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
                ctx.set_response(StatusCode::NOT_FOUND, "404 Not Found: Root directory not accessible\n");
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
            let index_file = canonical_target.join("index.html");
            if index_file.is_file() {
                return serve_file(&index_file, ctx).await;
            }

            if self.browse {
                return render_directory_listing(&canonical_target, &req_path, &self.hide, ctx).await;
            } else {
                ctx.set_response(StatusCode::NOT_FOUND, "404 Not Found: Directory index forbidden\n");
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

async fn serve_file(file_path: &Path, ctx: &mut Context) -> Result<()> {
    let metadata = match tokio::fs::metadata(file_path).await {
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

    let contents = match tokio::fs::read(file_path).await {
        Ok(c) => c,
        Err(e) => {
            ctx.set_response(StatusCode::INTERNAL_SERVER_ERROR, format!("500 Error reading file: {}\n", e));
            return Ok(());
        }
    };

    let mime_type = mime_guess::from_path(file_path).first_or_octet_stream();

    if let Ok(val) = HeaderValue::try_from(mime_type.as_ref()) {
        ctx.response_headers.insert(http::header::CONTENT_TYPE, val);
    }
    if let Ok(val) = HeaderValue::try_from(file_len.to_string()) {
        ctx.response_headers.insert(http::header::CONTENT_LENGTH, val);
    }
    if let Ok(val) = HeaderValue::try_from(&etag) {
        ctx.response_headers.insert(http::header::ETAG, val);
    }

    ctx.set_response(StatusCode::OK, contents);
    Ok(())
}

async fn render_directory_listing(dir_path: &Path, req_path: &str, hide: &[String], ctx: &mut Context) -> Result<()> {
    let mut entries = match tokio::fs::read_dir(dir_path).await {
        Ok(rd) => rd,
        Err(_) => {
            ctx.set_response(StatusCode::INTERNAL_SERVER_ERROR, "500 Could not read directory\n");
            return Ok(());
        }
    };

    let clean_req = req_path.trim_end_matches('/');
    let mut items = Vec::new();

    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if hide.iter().any(|h| h == &name) {
            continue;
        }
        let is_dir = entry.file_type().await.map(|ft| ft.is_dir()).unwrap_or(false);
        items.push((name, is_dir));
    }

    items.sort_by(|a, b| {
        if a.1 != b.1 {
            b.1.cmp(&a.1) // directories first
        } else {
            a.0.cmp(&b.0)
        }
    });

    let mut html = format!(
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>Index of {}</title>\
        <style>body{{font-family:sans-serif;margin:2em;}}ul{{list-style:none;padding:0;}}li{{padding:0.3em 0;}}a{{text-decoration:none;}}a:hover{{text-decoration:underline;}}</style>\
        </head><body><h1>Index of {}</h1><hr><ul>",
        req_path, req_path
    );

    if clean_req != "" && clean_req != "/" {
        html.push_str("<li><a href=\"..\">&larr; Parent Directory</a></li>");
    }

    for (name, is_dir) in items {
        let slash = if is_dir { "/" } else { "" };
        let link = format!("{}/{}{}", clean_req, name, slash);
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
