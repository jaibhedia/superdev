//! Data models for API requests and responses
//!
//! This module contains all the data structures used for serializing and
//! deserializing JSON requests and responses. All models are designed to
//! match the exact API specification.

use serde::{Deserialize, Serialize};

// ===== Keypair Models =====

/// Response for keypair generation endpoint
#[derive(Debug, Serialize, Deserialize)]
pub struct KeypairResponse {
    /// Base58-encoded public key
    pub pubkey: String,
    /// Base58-encoded secret key (64 bytes total - 32 byte secret + 32 byte public)
    pub secret: String,
}

// ===== Token Creation Models =====
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    pub mint_authority: String,
    pub mint: String,
    pub decimals: u8,
}

// ===== Token Minting Models =====
#[derive(Debug, Serialize, Deserialize)]
pub struct MintTokenRequest {
    pub mint: String,
    pub destination: String,
    pub authority: String,
    pub amount: u64,
}

// ===== Message Signing Models =====
#[derive(Debug, Serialize, Deserialize)]
pub struct SignMessageRequest {
    pub message: String,
    pub secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignMessageResponse {
    pub signature: String,
    pub public_key: String,
    pub message: String,
}

// ===== Message Verification Models =====
#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyMessageRequest {
    pub message: String,
    pub signature: String,
    pub pubkey: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyMessageResponse {
    pub valid: bool,
    pub message: String,
    pub pubkey: String,
}

// ===== SOL Transfer Models =====
#[derive(Debug, Serialize, Deserialize)]
pub struct SendSolRequest {
    pub from: String,
    pub to: String,
    pub lamports: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendSolResponse {
    pub program_id: String,
    pub accounts: Vec<String>,
    pub instruction_data: String,
}

// ===== Token Transfer Models =====
#[derive(Debug, Serialize, Deserialize)]
pub struct SendTokenRequest {
    pub destination: String,
    pub mint: String,
    pub owner: String,
    pub amount: u64,
}

// ===== Instruction Response Models =====
#[derive(Debug, Serialize, Deserialize)]
pub struct AccountMeta {
    pub pubkey: String,
    pub is_signer: bool,
    pub is_writable: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstructionResponse {
    pub program_id: String,
    pub accounts: Vec<AccountMeta>,
    pub instruction_data: String,
}

// Token transfer uses different account format per spec
#[derive(Debug, Serialize, Deserialize)]
pub struct TokenTransferAccountMeta {
    pub pubkey: String,
    #[serde(rename = "isSigner")]
    pub is_signer: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenTransferResponse {
    pub program_id: String,
    pub accounts: Vec<TokenTransferAccountMeta>,
    pub instruction_data: String,
}
