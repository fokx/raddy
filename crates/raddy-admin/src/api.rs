use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use bytes::Bytes;
use raddy_caddyfile::Adapter;
use raddy_caddyfile::parse_caddyfile;
use raddy_core::config::Config;
use std::sync::Arc;

use crate::error::{AdminError, Result};
use crate::path_ops::{delete_path, get_path, patch_path, set_path};
use crate::state::AppState;

pub fn build_admin_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/", get(get_status))
        .route("/load", post(post_load))
        .route("/adapt", post(post_adapt))
        .route("/stop", post(post_stop))
        .route("/config/", get(get_config))
        .route("/config", get(get_config))
        .route(
            "/config/{*path}",
            get(get_config_path)
                .post(post_config_path)
                .put(post_config_path)
                .patch(patch_config_path)
                .delete(delete_config_path),
        )
        .route("/reverse_proxy/upstreams", get(get_upstreams))
        .route("/pki/ca/local", get(get_local_ca))
        .with_state(state)
}

async fn get_status() -> impl IntoResponse {
    Json(serde_json::json!({
        "status": "ok",
        "app": "raddy",
        "version": env!("CARGO_PKG_VERSION")
    }))
}

async fn get_config(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse> {
    let current_config = state.config.load();
    let json_val = serde_json::to_value(&**current_config)?;
    Ok(Json(json_val))
}

async fn get_config_path(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
) -> Result<impl IntoResponse> {
    let current_config = state.config.load();
    let root = serde_json::to_value(&**current_config)?;

    match get_path(&root, &path) {
        Some(val) => Ok(Json(val.clone())),
        None => Err(AdminError::NotFound(format!(
            "Path '/config/{}' not found",
            path
        ))),
    }
}

async fn post_config_path(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Result<impl IntoResponse> {
    let current_config = state.config.load();
    let mut root = serde_json::to_value(&**current_config)?;

    set_path(&mut root, &path, payload).map_err(AdminError::BadRequest)?;

    let new_config: Config = serde_json::from_value(root)?;
    state.reload(new_config).await?;

    Ok(StatusCode::OK)
}

async fn patch_config_path(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
    Json(payload): Json<serde_json::Value>,
) -> Result<impl IntoResponse> {
    let current_config = state.config.load();
    let mut root = serde_json::to_value(&**current_config)?;

    patch_path(&mut root, &path, payload).map_err(AdminError::BadRequest)?;

    let new_config: Config = serde_json::from_value(root)?;
    state.reload(new_config).await?;

    Ok(StatusCode::OK)
}

async fn delete_config_path(
    State(state): State<Arc<AppState>>,
    Path(path): Path<String>,
) -> Result<impl IntoResponse> {
    let current_config = state.config.load();
    let mut root = serde_json::to_value(&**current_config)?;

    delete_path(&mut root, &path).map_err(AdminError::BadRequest)?;

    let new_config: Config = serde_json::from_value(root)?;
    state.reload(new_config).await?;

    Ok(StatusCode::OK)
}

async fn post_load(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response> {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let new_config = if content_type.contains("caddyfile") || content_type.contains("text/plain") {
        let text = std::str::from_utf8(&body)
            .map_err(|e| AdminError::BadRequest(format!("Invalid UTF-8 in Caddyfile: {}", e)))?;
        let ast = parse_caddyfile(text)
            .map_err(|e| AdminError::BadRequest(format!("Failed to parse Caddyfile: {}", e)))?;
        let mut adapter = Adapter::new();
        adapter
            .adapt(&ast)
            .map_err(|e| AdminError::BadRequest(format!("Failed to adapt Caddyfile: {}", e)))?
    } else {
        match serde_json::from_slice::<Config>(&body) {
            Ok(cfg) => cfg,
            Err(e) => {
                // Fallback attempt: if body is a Caddyfile text
                if let Ok(text) = std::str::from_utf8(&body) {
                    if let Ok(ast) = parse_caddyfile(text) {
                        let mut adapter = Adapter::new();
                        if let Ok(adapted) = adapter.adapt(&ast) {
                            adapted
                        } else {
                            return Err(AdminError::Json(e));
                        }
                    } else {
                        return Err(AdminError::Json(e));
                    }
                } else {
                    return Err(AdminError::Json(e));
                }
            }
        }
    };

    state.reload(new_config).await?;
    Ok((
        StatusCode::OK,
        Json(serde_json::json!({ "status": "success" })),
    )
        .into_response())
}

async fn post_stop(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    tokio::spawn(async move {
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        state.stop_all();
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({ "status": "stopping" })),
    )
}

async fn get_local_ca(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse> {
    if let Some(ref _tls) = state.tls_manager {
        // TlsManager has local CA cert
        Ok((
            StatusCode::OK,
            [("content-type", "application/x-pem-file")],
            "-----BEGIN CERTIFICATE-----\n[Raddy Local Authority CA]\n-----END CERTIFICATE-----\n",
        )
            .into_response())
    } else {
        Err(AdminError::NotFound(
            "TLS Manager or Local CA not active".into(),
        ))
    }
}

async fn post_adapt(_headers: HeaderMap, body: Bytes) -> Result<Response> {
    let text = std::str::from_utf8(&body)
        .map_err(|e| AdminError::BadRequest(format!("Invalid UTF-8: {}", e)))?;
    let ast = parse_caddyfile(text)
        .map_err(|e| AdminError::BadRequest(format!("Failed to parse Caddyfile: {}", e)))?;
    let mut adapter = Adapter::new();
    let adapted = adapter
        .adapt(&ast)
        .map_err(|e| AdminError::BadRequest(format!("Failed to adapt Caddyfile: {}", e)))?;
    let json_val = serde_json::to_value(&adapted)?;
    Ok(Json(json_val).into_response())
}

async fn get_upstreams(State(state): State<Arc<AppState>>) -> Result<impl IntoResponse> {
    let current_config = state.config.load();
    let mut upstreams = Vec::new();
    if let Some(http) = current_config.http_app() {
        for server in http.servers.values() {
            for route in &server.routes {
                for handler in &route.handle {
                    if handler.handler == "reverse_proxy" {
                        if let Some(arr) =
                            handler.details.get("upstreams").and_then(|v| v.as_array())
                        {
                            for u in arr {
                                upstreams.push(u.clone());
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(Json(upstreams))
}
