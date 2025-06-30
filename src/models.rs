use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct KeypairResponse {
    pub pubkey: String,
    pub secret: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CreateTokenRequest {
    #[serde(rename = "mintAuthority")]
    pub mint_authority: String,
    pub mint: String,
    pub decimals: u8,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MintTokenRequest {
    pub mint: String,
    pub to: String,
    pub authority: String,
    pub amount: u64,
}

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

#[derive(Debug, Serialize, Deserialize)]
pub struct SendSolRequest {
    pub from: String,
    pub to: String,
    pub lamports: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendTokenRequest {
    pub from: String,
    pub to: String,
    pub authority: String,
    pub amount: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InstructionResponse {
    pub program_id: String,
    pub accounts: Vec<AccountMeta>,
    pub instruction_data: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AccountMeta {
    pub pubkey: String,
    #[serde(rename = "is_signer")]
    pub is_signer: bool,
    #[serde(rename = "is_writable")]
    pub is_writable: bool,
}

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

#[derive(Debug, Serialize, Deserialize)]
pub struct SolTransferResponse {
    pub program_id: String,
    pub accounts: Vec<String>,
    pub instruction_data: String,
}
