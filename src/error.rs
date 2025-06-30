use axum::{http::StatusCode, response::Json};
use serde_json::{json, Value};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    
    #[error("Solana error: {0}")]
    SolanaError(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Internal server error: {0}")]
    InternalError(String),
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            AppError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::CryptoError(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::SolanaError(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::SerializationError(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };

        let body = Json(json!({
            "success": false,
            "error": error_message
        }));

        (status, body).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;

pub fn success_response<T>(data: T) -> Json<Value>
where
    T: serde::Serialize,
{
    Json(json!({
        "success": true,
        "data": data
    }))
}
