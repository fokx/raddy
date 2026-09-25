use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AdminError {
    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Bad request: {0}")]
    BadRequest(String),

    #[error("Internal server error: {0}")]
    Internal(String),

    #[error("Core error: {0}")]
    Core(#[from] raddy_core::CoreError),

    #[error("HTTP server error: {0}")]
    HttpServer(#[from] raddy_http::HttpServerError),

    #[error("Serialization error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, AdminError>;

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        let (status, msg) = match &self {
            AdminError::NotFound(m) => (StatusCode::NOT_FOUND, m.clone()),
            AdminError::BadRequest(m) => (StatusCode::BAD_REQUEST, m.clone()),
            AdminError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m.clone()),
            AdminError::Core(e) => (StatusCode::BAD_REQUEST, format!("Configuration error: {}", e)),
            AdminError::HttpServer(e) => (StatusCode::BAD_REQUEST, format!("Server configuration error: {}", e)),
            AdminError::Json(e) => (StatusCode::BAD_REQUEST, format!("Invalid JSON: {}", e)),
        };

        let body = serde_json::json!({
            "error": msg,
        });

        (status, axum::Json(body)).into_response()
    }
}
