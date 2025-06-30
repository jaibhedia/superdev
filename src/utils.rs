use base64::Engine;
use solana_sdk::pubkey::Pubkey;
use std::str::FromStr;

use crate::error::{AppError, AppResult};

/// Validates that a string is a valid base58-encoded Solana public key
pub fn validate_pubkey(pubkey_str: &str) -> AppResult<Pubkey> {
    Pubkey::from_str(pubkey_str).map_err(|e| {
        AppError::InvalidInput(format!("Invalid public key '{}': {}", pubkey_str, e))
    })
}

/// Validates that a string is a valid base58-encoded secret key (should be 64 bytes when decoded)
pub fn validate_secret_key(secret_str: &str) -> AppResult<Vec<u8>> {
    let decoded = bs58::decode(secret_str)
        .into_vec()
        .map_err(|e| AppError::InvalidInput(format!("Invalid base58 secret key: {}", e)))?;

    if decoded.len() != 64 {
        return Err(AppError::InvalidInput(
            "Secret key must be 64 bytes when decoded".to_string(),
        ));
    }

    Ok(decoded)
}

/// Validates that an amount is positive and within reasonable bounds
pub fn validate_amount(amount: u64) -> AppResult<u64> {
    if amount == 0 {
        return Err(AppError::InvalidInput("Amount must be greater than 0".to_string()));
    }
    
    // Prevent overflow issues - max reasonable amount
    if amount > u64::MAX / 2 {
        return Err(AppError::InvalidInput("Amount too large".to_string()));
    }
    
    Ok(amount)
}

/// Validates that decimals are within valid range for SPL tokens
pub fn validate_decimals(decimals: u8) -> AppResult<u8> {
    if decimals > 9 {
        return Err(AppError::InvalidInput(
            "Decimals must be between 0 and 9".to_string(),
        ));
    }
    Ok(decimals)
}

/// Validates that a message is not empty and within reasonable length
pub fn validate_message(message: &str) -> AppResult<&str> {
    if message.is_empty() {
        return Err(AppError::InvalidInput("Message cannot be empty".to_string()));
    }
    
    if message.len() > 1024 {
        return Err(AppError::InvalidInput(
            "Message too long (max 1024 characters)".to_string(),
        ));
    }
    
    Ok(message)
}

/// Validates base64 encoded signature
pub fn validate_signature(signature_str: &str) -> AppResult<Vec<u8>> {
    base64::engine::general_purpose::STANDARD.decode(signature_str).map_err(|e| {
        AppError::InvalidInput(format!("Invalid base64 signature: {}", e))
    })
}
