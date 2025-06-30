//! Error handling types and utilities
//!
//! This module defines the application's error types and provides consistent
//! error handling across all endpoints. All errors are converted to appropriate
//! HTTP responses with proper status codes and JSON formatting.

use axum::{http::StatusCode, response::Json};
use serde_json::{json, Value};
use thiserror::Error;

/// Application-specific error types
///
/// All business logic errors are represented by this enum and automatically
/// converted to appropriate HTTP responses via the [`axum::response::IntoResponse`]
/// implementation.
#[derive(Error, Debug)]
pub enum AppError {
    /// Input validation errors (e.g., invalid public keys, zero amounts)
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Cryptographic operation errors (e.g., invalid signatures, key format issues)
    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    /// Solana SDK related errors (e.g., instruction creation failures)
    #[error("Solana error: {0}")]
    SolanaError(String),
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        let (status, error_message) = match self {
            AppError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::CryptoError(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::SolanaError(msg) => (StatusCode::BAD_REQUEST, msg),
        };

        let body = Json(json!({
            "success": false,
            "error": error_message
        }));

        (status, body).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;

/// Creates a successful JSON response
pub fn success_response<T>(data: T) -> Json<Value>
where
    T: serde::Serialize,
{
    Json(json!({
        "success": true,
        "data": data
    }))
}
