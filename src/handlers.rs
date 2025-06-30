use axum::{extract::State, response::Json};
use serde_json::Value;

use crate::{
    error::{success_response, AppResult},
    extractors::JsonExtractor,
    models::*,
    AppState,
};

// ===== Keypair Generation =====

/// Generates a new Solana keypair using secure randomness
///
/// # Returns
/// - `200 OK`: New keypair with public and secret keys
/// - `500 Internal Server Error`: If cryptographic operations fail
pub async fn generate_keypair(State(state): State<AppState>) -> AppResult<Json<Value>> {
    let keypair = state.solana_service.generate_keypair()?;
    Ok(success_response(keypair))
}

// ===== SPL Token Operations =====

/// Creates a new SPL token mint initialization instruction
///
/// # Request Body
/// - `mintAuthority`: Base58-encoded public key for mint authority
/// - `mint`: Base58-encoded public key for the mint account
/// - `decimals`: Number of decimal places (0-9)
///
/// # Returns
/// - `200 OK`: Instruction data for initializing the mint
/// - `400 Bad Request`: Invalid input parameters
pub async fn create_token(
    State(state): State<AppState>,
    JsonExtractor(request): JsonExtractor<CreateTokenRequest>,
) -> AppResult<Json<Value>> {
    let instruction = state.solana_service.create_token_instruction(request)?;
    Ok(success_response(instruction))
}

/// Creates a mint-to instruction for SPL tokens
///
/// # Request Body
/// - `mint`: Mint address
/// - `destination`: Destination user address
/// - `authority`: Authority address for minting
/// - `amount`: Amount to mint (must be > 0)
///
/// # Returns
/// - `200 OK`: Instruction data for minting tokens
/// - `400 Bad Request`: Invalid input parameters
pub async fn mint_token(
    State(state): State<AppState>,
    JsonExtractor(request): JsonExtractor<MintTokenRequest>,
) -> AppResult<Json<Value>> {
    let instruction = state.solana_service.mint_token_instruction(request)?;
    Ok(success_response(instruction))
}

// ===== Message Cryptography =====

/// Signs a message using Ed25519 cryptography
///
/// # Request Body
/// - `message`: Message to sign (max 1KB)
/// - `secret`: Base58-encoded secret key
///
/// # Returns
/// - `200 OK`: Signature, public key, and original message
/// - `400 Bad Request`: Invalid input parameters or cryptographic errors
pub async fn sign_message(
    State(state): State<AppState>,
    JsonExtractor(request): JsonExtractor<SignMessageRequest>,
) -> AppResult<Json<Value>> {
    let signature = state.solana_service.sign_message(request)?;
    Ok(success_response(signature))
}

/// Verifies a signed message using Ed25519 cryptography
///
/// # Request Body
/// - `message`: Original message that was signed
/// - `signature`: Base64-encoded signature
/// - `pubkey`: Base58-encoded public key
///
/// # Returns
/// - `200 OK`: Verification result with validity status
/// - `400 Bad Request`: Invalid input parameters
pub async fn verify_message(
    State(state): State<AppState>,
    JsonExtractor(request): JsonExtractor<VerifyMessageRequest>,
) -> AppResult<Json<Value>> {
    let result = state.solana_service.verify_message(request)?;
    Ok(success_response(result))
}

// ===== Transfer Instructions =====

/// Creates a SOL transfer instruction
///
/// # Request Body
/// - `from`: Sender address (base58-encoded)
/// - `to`: Recipient address (base58-encoded, must be different from sender)
/// - `lamports`: Amount in lamports (must be > 0)
///
/// # Returns
/// - `200 OK`: Transfer instruction data
/// - `400 Bad Request`: Invalid input parameters
pub async fn send_sol(
    State(state): State<AppState>,
    JsonExtractor(request): JsonExtractor<SendSolRequest>,
) -> AppResult<Json<Value>> {
    let instruction = state.solana_service.send_sol_instruction(request)?;
    Ok(success_response(instruction))
}

/// Creates an SPL token transfer instruction
///
/// # Request Body
/// - `destination`: Destination user address
/// - `mint`: Mint address
/// - `owner`: Owner address (must be different from destination)
/// - `amount`: Amount to transfer (must be > 0)
///
/// # Returns
/// - `200 OK`: Transfer instruction data
/// - `400 Bad Request`: Invalid input parameters
pub async fn send_token(
    State(state): State<AppState>,
    JsonExtractor(request): JsonExtractor<SendTokenRequest>,
) -> AppResult<Json<Value>> {
    let instruction = state.solana_service.send_token_instruction(request)?;
    Ok(success_response(instruction))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Method, Request, StatusCode},
        routing::post,
        Router,
    };
    use serde_json::{json, Value};
    use tower::util::ServiceExt;

    async fn create_test_app() -> Router {
        let state = AppState::new();
        Router::new()
            .route("/keypair", post(generate_keypair))
            .route("/token/create", post(create_token))
            .route("/token/mint", post(mint_token))
            .route("/message/sign", post(sign_message))
            .route("/message/verify", post(verify_message))
            .route("/send/sol", post(send_sol))
            .route("/send/token", post(send_token))
            .with_state(state)
    }

    #[tokio::test]
    async fn test_generate_keypair() {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/keypair")
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], true);
        assert!(json["data"]["pubkey"].is_string());
        assert!(json["data"]["secret"].is_string());
    }

    #[tokio::test]
    async fn test_sign_and_verify_message() {
        let app = create_test_app().await;

        // First generate a keypair
        let keypair_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/keypair")
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let keypair_body = axum::body::to_bytes(keypair_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let keypair_json: Value = serde_json::from_slice(&keypair_body).unwrap();

        let pubkey = keypair_json["data"]["pubkey"].as_str().unwrap();
        let secret = keypair_json["data"]["secret"].as_str().unwrap();

        // Sign a message
        let sign_request = json!({
            "message": "Hello, Solana!",
            "secret": secret
        });

        let sign_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/message/sign")
                    .header("content-type", "application/json")
                    .body(Body::from(sign_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(sign_response.status(), StatusCode::OK);

        let sign_body = axum::body::to_bytes(sign_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let sign_json: Value = serde_json::from_slice(&sign_body).unwrap();

        assert_eq!(sign_json["success"], true);
        let signature = sign_json["data"]["signature"].as_str().unwrap();

        // Verify the message
        let verify_request = json!({
            "message": "Hello, Solana!",
            "signature": signature,
            "pubkey": pubkey
        });

        let verify_response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/message/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(verify_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(verify_response.status(), StatusCode::OK);

        let verify_body = axum::body::to_bytes(verify_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let verify_json: Value = serde_json::from_slice(&verify_body).unwrap();

        assert_eq!(verify_json["success"], true);
        assert_eq!(verify_json["data"]["valid"], true);
    }

    #[tokio::test]
    async fn test_create_token_instruction() {
        let app = create_test_app().await;

        let request = json!({
            "mintAuthority": "11111111111111111111111111111112",
            "mint": "11111111111111111111111111111113",
            "decimals": 6
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/token/create")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], true);
        assert!(json["data"]["program_id"].is_string());
        assert!(json["data"]["accounts"].is_array());
        assert!(json["data"]["instruction_data"].is_string());
    }

    #[tokio::test]
    async fn test_invalid_input_error() {
        let app = create_test_app().await;

        let request = json!({
            "mintAuthority": "invalid-pubkey",
            "mint": "11111111111111111111111111111113",
            "decimals": 6
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/token/create")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], false);
        assert!(json["error"].is_string());
    }

    #[tokio::test]
    async fn test_send_sol_instruction() {
        let app = create_test_app().await;

        let request = json!({
            "from": "11111111111111111111111111111112",
            "to": "11111111111111111111111111111113",
            "lamports": 1000000
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/send/sol")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], true);
        assert!(json["data"]["program_id"].is_string());
        assert!(json["data"]["accounts"].is_array());
        assert_eq!(json["data"]["accounts"].as_array().unwrap().len(), 2);
        assert!(json["data"]["instruction_data"].is_string());
    }

    #[tokio::test]
    async fn test_mint_token_instruction() {
        let app = create_test_app().await;

        let request = json!({
            "mint": "11111111111111111111111111111112",
            "destination": "11111111111111111111111111111113",
            "authority": "11111111111111111111111111111114",
            "amount": 1000000
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/token/mint")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], true);
        assert!(json["data"]["program_id"].is_string());
        assert!(json["data"]["accounts"].is_array());
        assert!(json["data"]["instruction_data"].is_string());
    }

    #[tokio::test]
    async fn test_send_token_instruction() {
        let app = create_test_app().await;

        let request = json!({
            "destination": "11111111111111111111111111111112",
            "mint": "11111111111111111111111111111113",
            "owner": "11111111111111111111111111111114",
            "amount": 1000000
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/send/token")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], true);
        assert!(json["data"]["program_id"].is_string());
        assert!(json["data"]["accounts"].is_array());
        assert!(json["data"]["instruction_data"].is_string());
    }

    // Edge case tests
    #[tokio::test]
    async fn test_send_sol_zero_lamports() {
        let app = create_test_app().await;

        let request = json!({
            "from": "11111111111111111111111111111112",
            "to": "11111111111111111111111111111113",
            "lamports": 0
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/send/sol")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], false);
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("Amount must be greater than 0"));
    }

    #[tokio::test]
    async fn test_send_token_zero_amount() {
        let app = create_test_app().await;

        let request = json!({
            "destination": "11111111111111111111111111111112",
            "mint": "11111111111111111111111111111113",
            "owner": "11111111111111111111111111111114",
            "amount": 0
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/send/token")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], false);
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("Amount must be greater than 0"));
    }

    #[tokio::test]
    async fn test_mint_token_zero_amount() {
        let app = create_test_app().await;

        let request = json!({
            "mint": "11111111111111111111111111111112",
            "destination": "11111111111111111111111111111113",
            "authority": "11111111111111111111111111111114",
            "amount": 0
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/token/mint")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], false);
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("Amount must be greater than 0"));
    }

    #[tokio::test]
    async fn test_create_token_invalid_decimals() {
        let app = create_test_app().await;

        let request = json!({
            "mintAuthority": "11111111111111111111111111111112",
            "mint": "11111111111111111111111111111113",
            "decimals": 20
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/token/create")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], false);
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("Decimals must be between 0 and 9"));
    }

    #[tokio::test]
    async fn test_sign_message_invalid_secret() {
        let app = create_test_app().await;

        let request = json!({
            "message": "Hello, Solana!",
            "secret": "invalid-secret-key"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/message/sign")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], false);
        assert!(json["error"].is_string());
    }

    #[tokio::test]
    async fn test_verify_message_invalid_signature() {
        let app = create_test_app().await;

        let request = json!({
            "message": "Hello, Solana!",
            "signature": "invalid-signature",
            "pubkey": "11111111111111111111111111111112"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/message/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], false);
        assert!(json["error"].is_string());
    }

    #[tokio::test]
    async fn test_verify_message_invalid_pubkey() {
        let app = create_test_app().await;

        let request = json!({
            "message": "Hello, Solana!",
            "signature": "5VERv8NMvzbUjkUcMrC3UwY4mQqMAYJCYrmwLqzKmBFfLmHFKAPYeVFDGeDrnJdcbAKe3oLhVRTKCvZJw2AfgvZW",
            "pubkey": "invalid-pubkey"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/message/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], false);
        assert!(json["error"].is_string());
    }

    #[tokio::test]
    async fn test_send_sol_same_from_to() {
        let app = create_test_app().await;

        let request = json!({
            "from": "11111111111111111111111111111112",
            "to": "11111111111111111111111111111112",
            "lamports": 1000000
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/send/sol")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], false);
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("From and to addresses cannot be the same"));
    }

    #[tokio::test]
    async fn test_send_token_same_from_to() {
        let app = create_test_app().await;

        let request = json!({
            "destination": "11111111111111111111111111111112",
            "mint": "11111111111111111111111111111113",
            "owner": "11111111111111111111111111111112",
            "amount": 1000000
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/send/token")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], false);
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("From and to addresses cannot be the same"));
    }

    #[tokio::test]
    async fn test_malformed_json() {
        let app = create_test_app().await;

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/send/sol")
                    .header("content-type", "application/json")
                    .body(Body::from("{invalid json"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_missing_required_fields() {
        let app = create_test_app().await;

        let request = json!({
            "from": "11111111111111111111111111111112",
            // missing "to" and "lamports"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/send/sol")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_message_verify_wrong_signature() {
        let app = create_test_app().await;

        // Generate a keypair and sign a message
        let keypair_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/keypair")
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let keypair_body = axum::body::to_bytes(keypair_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let keypair_json: Value = serde_json::from_slice(&keypair_body).unwrap();
        let pubkey = keypair_json["data"]["pubkey"].as_str().unwrap();
        let secret = keypair_json["data"]["secret"].as_str().unwrap();

        // Sign message "Hello"
        let sign_request = json!({
            "message": "Hello",
            "secret": secret
        });

        let sign_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/message/sign")
                    .header("content-type", "application/json")
                    .body(Body::from(sign_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        let sign_body = axum::body::to_bytes(sign_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let sign_json: Value = serde_json::from_slice(&sign_body).unwrap();
        let signature = sign_json["data"]["signature"].as_str().unwrap();

        // Try to verify with different message "World"
        let verify_request = json!({
            "message": "World",
            "signature": signature,
            "pubkey": pubkey
        });

        let verify_response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/message/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(verify_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(verify_response.status(), StatusCode::OK);

        let verify_body = axum::body::to_bytes(verify_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let verify_json: Value = serde_json::from_slice(&verify_body).unwrap();

        assert_eq!(verify_json["success"], true);
        assert_eq!(verify_json["data"]["valid"], false);
    }

    #[tokio::test]
    async fn test_large_amounts() {
        let app = create_test_app().await;

        let request = json!({
            "from": "11111111111111111111111111111112",
            "to": "11111111111111111111111111111113",
            "lamports": 1000000000000u64
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/send/sol")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], true);
    }

    #[tokio::test]
    async fn test_empty_message() {
        let app = create_test_app().await;

        // Generate a keypair first
        let keypair_response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/keypair")
                    .header("content-type", "application/json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let keypair_body = axum::body::to_bytes(keypair_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let keypair_json: Value = serde_json::from_slice(&keypair_body).unwrap();
        let secret = keypair_json["data"]["secret"].as_str().unwrap();

        // Try to sign empty message
        let sign_request = json!({
            "message": "",
            "secret": secret
        });

        let sign_response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/message/sign")
                    .header("content-type", "application/json")
                    .body(Body::from(sign_request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(sign_response.status(), StatusCode::BAD_REQUEST);

        let sign_body = axum::body::to_bytes(sign_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let sign_json: Value = serde_json::from_slice(&sign_body).unwrap();

        assert_eq!(sign_json["success"], false);
        assert!(sign_json["error"]
            .as_str()
            .unwrap()
            .contains("Message cannot be empty"));
    }

    #[tokio::test]
    async fn test_create_token_valid_decimals_boundary() {
        let app = create_test_app().await;

        // Test with decimals = 9 (valid upper bound)
        let request = json!({
            "mintAuthority": "11111111111111111111111111111112",
            "mint": "11111111111111111111111111111113",
            "decimals": 9
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/token/create")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], true);
    }

    #[tokio::test]
    async fn test_create_token_zero_decimals() {
        let app = create_test_app().await;

        // Test with decimals = 0 (valid lower bound)
        let request = json!({
            "mintAuthority": "11111111111111111111111111111112",
            "mint": "11111111111111111111111111111113",
            "decimals": 0
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/token/create")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], true);
    }

    #[tokio::test]
    async fn test_create_token_same_mint_and_authority() {
        let app = create_test_app().await;

        let request = json!({
            "mintAuthority": "11111111111111111111111111111112",
            "mint": "11111111111111111111111111111112",
            "decimals": 6
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/token/create")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], false);
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("Mint authority and mint address should be different"));
    }

    #[tokio::test]
    async fn test_verify_message_invalid_signature_length() {
        let app = create_test_app().await;

        let request = json!({
            "message": "Hello, Solana!",
            "signature": "aGVsbG8=", // Too short base64 signature
            "pubkey": "11111111111111111111111111111112"
        });

        let response = app
            .oneshot(
                Request::builder()
                    .method(Method::POST)
                    .uri("/message/verify")
                    .header("content-type", "application/json")
                    .body(Body::from(request.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(json["success"], false);
        assert!(json["error"]
            .as_str()
            .unwrap()
            .contains("Invalid signature length"));
    }
}
