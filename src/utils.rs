//! Input validation utilities
//!
//! This module provides comprehensive validation functions for all types of
//! input data including public keys, amounts, messages, and signatures.
//! All validation functions follow a consistent pattern and provide detailed
//! error messages for debugging.

use base64::Engine;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

use crate::error::{AppError, AppResult};

// ===== Constants =====

/// Maximum allowed public key string length for safety
const MAX_PUBKEY_STRING_LENGTH: usize = 100;

/// Expected length of a decoded secret key in bytes (32 secret + 32 public)
const SECRET_KEY_BYTES_LENGTH: usize = 64;

/// Expected length of an Ed25519 signature in bytes
const SIGNATURE_BYTES_LENGTH: usize = 64;

/// Maximum allowed message length for signing operations (1KB)
const MAX_MESSAGE_LENGTH: usize = 1024;

/// Maximum allowed message size for verification operations (10KB)
const MAX_MESSAGE_SIZE: usize = 10_000;

/// Maximum allowed token decimals per SPL token standard
const MAX_TOKEN_DECIMALS: u8 = 9;

// ===== Public Key Validation =====

/// Validates that a string is a valid base58-encoded Solana public key
pub fn validate_pubkey(pubkey_str: &str) -> AppResult<Pubkey> {
    Pubkey::from_str(pubkey_str)
        .map_err(|e| AppError::InvalidInput(format!("Invalid public key '{}': {}", pubkey_str, e)))
}

/// Validates that a public key string is not empty and has reasonable length
pub fn validate_pubkey_string(pubkey_str: &str) -> AppResult<()> {
    if pubkey_str.trim().is_empty() {
        return Err(AppError::InvalidInput(
            "Public key cannot be empty".to_string(),
        ));
    }

    if pubkey_str.len() > MAX_PUBKEY_STRING_LENGTH {
        return Err(AppError::InvalidInput(
            "Public key string too long".to_string(),
        ));
    }

    Ok(())
}

// ===== Secret Key Validation =====

/// Validates that a string is a valid base58-encoded secret key (64 bytes when decoded)
pub fn validate_secret_key(secret_str: &str) -> AppResult<Vec<u8>> {
    if secret_str.trim().is_empty() {
        return Err(AppError::InvalidInput(
            "Secret key cannot be empty".to_string(),
        ));
    }

    let decoded = bs58::decode(secret_str)
        .into_vec()
        .map_err(|e| AppError::InvalidInput(format!("Invalid base58 secret key: {}", e)))?;

    if decoded.len() != SECRET_KEY_BYTES_LENGTH {
        return Err(AppError::InvalidInput(format!(
            "Secret key must be {} bytes when decoded",
            SECRET_KEY_BYTES_LENGTH
        )));
    }

    Ok(decoded)
}

// ===== Amount Validation =====

/// Validates that an amount is positive and within reasonable bounds
pub fn validate_amount(amount: u64) -> AppResult<u64> {
    if amount == 0 {
        return Err(AppError::InvalidInput(
            "Amount must be greater than 0".to_string(),
        ));
    }

    // Prevent overflow issues - max reasonable amount
    if amount > u64::MAX / 2 {
        return Err(AppError::InvalidInput("Amount too large".to_string()));
    }

    Ok(amount)
}

// ===== Token Decimals Validation =====

/// Validates that decimals are within valid range for SPL tokens (0-9)
pub fn validate_decimals(decimals: u8) -> AppResult<u8> {
    if decimals > MAX_TOKEN_DECIMALS {
        return Err(AppError::InvalidInput(format!(
            "Decimals must be between 0 and {}",
            MAX_TOKEN_DECIMALS
        )));
    }
    Ok(decimals)
}

// ===== Message Validation =====

/// Validates that a message is not empty and within reasonable length
pub fn validate_message(message: &str) -> AppResult<&str> {
    if message.trim().is_empty() {
        return Err(AppError::InvalidInput(
            "Message cannot be empty".to_string(),
        ));
    }

    if message.len() > MAX_MESSAGE_LENGTH {
        return Err(AppError::InvalidInput(format!(
            "Message too long (max {} characters)",
            MAX_MESSAGE_LENGTH
        )));
    }

    Ok(message)
}

/// Validates that a message is within a reasonable size for signing
pub fn validate_message_size(message: &str) -> AppResult<()> {
    // For production, limit message size for performance
    if message.len() > MAX_MESSAGE_SIZE {
        return Err(AppError::InvalidInput(format!(
            "Message too large for signing (max {}KB)",
            MAX_MESSAGE_SIZE / 1000
        )));
    }
    Ok(())
}

// ===== Signature Validation =====

/// Validates base64 encoded signature with proper length checking
pub fn validate_signature(signature_str: &str) -> AppResult<Vec<u8>> {
    if signature_str.trim().is_empty() {
        return Err(AppError::InvalidInput(
            "Signature cannot be empty".to_string(),
        ));
    }

    let decoded = base64::engine::general_purpose::STANDARD
        .decode(signature_str)
        .map_err(|e| AppError::InvalidInput(format!("Invalid base64 signature: {}", e)))?;

    // Ed25519 signatures are always 64 bytes
    if decoded.len() != SIGNATURE_BYTES_LENGTH {
        return Err(AppError::InvalidInput(format!(
            "Invalid signature length: expected {} bytes, got {}",
            SIGNATURE_BYTES_LENGTH,
            decoded.len()
        )));
    }

    Ok(decoded)
}
