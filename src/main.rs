//! Solana HTTP Server
//!
//! A high-performance, production-ready HTTP server built in Rust for Solana blockchain operations.
//! This server provides secure endpoints for keypair generation, SPL token operations, message
//! signing/verification, and transaction instruction creation.
//!
//! ## Features
//!
//! - **Keypair Generation**: Generate secure Ed25519 keypairs for Solana
//! - **SPL Token Operations**: Create tokens and mint instructions  
//! - **Message Signing**: Sign and verify messages using Ed25519 cryptography
//! - **Transaction Instructions**: Create SOL and SPL token transfer instructions
//! - **Production Ready**: Comprehensive error handling, logging, and input validation
//! - **High Performance**: Built with Axum framework for maximum throughput

use axum::{
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

mod error;
mod extractors;
mod handlers;
mod models;
mod services;
mod utils;

use handlers::*;
use services::SolanaService;

/// Application state shared across all handlers
#[derive(Debug, Clone)]
pub struct AppState {
    solana_service: Arc<SolanaService>,
}

impl AppState {
    /// Creates a new application state instance
    pub fn new() -> Self {
        Self {
            solana_service: Arc::new(SolanaService::new()),
        }
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new()
    }
}

/// Health check endpoint for monitoring and load balancer health checks
async fn health_check() -> Result<Json<serde_json::Value>, StatusCode> {
    Ok(Json(serde_json::json!({
        "status": "healthy",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION"),
        "service": "solana-http-server"
    })))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize structured logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "solana_http_server=info,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let state = AppState::new();

    // Build the application with all routes and middleware
    let app = Router::new()
        // Health check endpoint
        .route("/health", get(health_check))
        // Keypair operations
        .route("/keypair", post(generate_keypair))
        // SPL Token operations
        .route("/token/create", post(create_token))
        .route("/token/mint", post(mint_token))
        // Message cryptography
        .route("/message/sign", post(sign_message))
        .route("/message/verify", post(verify_message))
        // Transfer instructions
        .route("/send/sol", post(send_sol))
        .route("/send/token", post(send_token))
        // Middleware layers
        .layer(
            CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers(tower_http::cors::Any),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    // Server configuration
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse::<u16>()
        .unwrap_or(3000);

    let bind_address = format!("0.0.0.0:{}", port);
    let listener = tokio::net::TcpListener::bind(&bind_address).await?;

    tracing::info!(
        "🚀 Solana HTTP Server v{} listening on {}",
        env!("CARGO_PKG_VERSION"),
        listener.local_addr()?
    );
    tracing::info!("📚 API Documentation: See README.md for endpoint specifications");

    // Start the server
    axum::serve(listener, app).await?;

    Ok(())
}
