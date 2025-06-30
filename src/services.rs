//! Core business logic for Solana operations
//!
//! This module contains the [`SolanaService`] which handles all Solana-related
//! operations including keypair generation, token operations, message signing,
//! and transaction instruction creation.

use base64::Engine;
use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand_core::OsRng;
use solana_sdk::{instruction::Instruction, system_instruction};
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction as token_instruction;

use crate::{
    error::{AppError, AppResult},
    models::*,
    utils::*,
};

/// Core service for handling Solana-related operations
///
/// This service provides a clean, stateless interface for all Solana blockchain
/// operations. It handles input validation, cryptographic operations, and
/// instruction generation while maintaining security best practices.
#[derive(Debug, Clone)]
pub struct SolanaService;

impl SolanaService {
    /// Creates a new instance of the SolanaService
    pub const fn new() -> Self {
        Self
    }

    /// Generates a new Ed25519 keypair for Solana
    /// Returns both the public key and secret key in base58 format
    pub fn generate_keypair(&self) -> AppResult<KeypairResponse> {
        let mut csprng = OsRng;
        let keypair = Keypair::generate(&mut csprng);

        let public_key_bytes = keypair.public.to_bytes();
        let secret_key_bytes = keypair.secret.to_bytes();

        // Combine secret and public key for Solana format (64 bytes total)
        let mut solana_secret = [0u8; 64];
        solana_secret[..32].copy_from_slice(&secret_key_bytes);
        solana_secret[32..].copy_from_slice(&public_key_bytes);

        Ok(KeypairResponse {
            pubkey: bs58::encode(public_key_bytes).into_string(),
            secret: bs58::encode(solana_secret).into_string(),
        })
    }

    /// Creates a new SPL token mint initialization instruction
    /// Validates all inputs and returns the instruction data
    pub fn create_token_instruction(
        &self,
        request: CreateTokenRequest,
    ) -> AppResult<InstructionResponse> {
        // Comprehensive input validation
        self.validate_create_token_request(&request)?;

        let mint_authority = validate_pubkey(&request.mint_authority)?;
        let mint = validate_pubkey(&request.mint)?;
        let decimals = validate_decimals(request.decimals)?;

        // Business logic validation
        if mint_authority == mint {
            return Err(AppError::InvalidInput(
                "Mint authority and mint address should be different".to_string(),
            ));
        }

        // Create the initialize mint instruction
        let instruction = token_instruction::initialize_mint(
            &spl_token::id(),
            &mint,
            &mint_authority,
            Some(&mint_authority), // freeze authority same as mint authority
            decimals,
        )
        .map_err(|e| AppError::SolanaError(format!("Failed to create mint instruction: {}", e)))?;

        Ok(self.instruction_to_response(instruction))
    }

    /// Creates a mint-to instruction for SPL tokens
    /// Validates all inputs and creates proper mint instruction
    pub fn mint_token_instruction(
        &self,
        request: MintTokenRequest,
    ) -> AppResult<InstructionResponse> {
        // Comprehensive input validation
        self.validate_mint_token_request(&request)?;

        let mint = validate_pubkey(&request.mint)?;
        let destination = validate_pubkey(&request.destination)?;
        let authority = validate_pubkey(&request.authority)?;
        let amount = validate_amount(request.amount)?;

        // Create mint to instruction
        let instruction = token_instruction::mint_to(
            &spl_token::id(),
            &mint,
            &destination,
            &authority,
            &[],
            amount,
        )
        .map_err(|e| AppError::SolanaError(format!("Failed to create mint instruction: {}", e)))?;

        Ok(self.instruction_to_response(instruction))
    }

    /// Signs a message using Ed25519 cryptography
    /// Returns signature, public key, and original message
    pub fn sign_message(&self, request: SignMessageRequest) -> AppResult<SignMessageResponse> {
        // Comprehensive input validation
        self.validate_sign_message_request(&request)?;

        let message = validate_message(&request.message)?;
        validate_message_size(message)?;
        let secret_bytes = validate_secret_key(&request.secret)?;

        // Extract the actual secret key (first 32 bytes) from Solana format
        let secret_key_bytes = &secret_bytes[..32];
        let secret_key = SecretKey::from_bytes(secret_key_bytes)
            .map_err(|e| AppError::CryptoError(format!("Invalid secret key: {}", e)))?;

        // Extract public key (last 32 bytes) from Solana format
        let public_key_bytes = &secret_bytes[32..];
        let public_key = PublicKey::from_bytes(public_key_bytes)
            .map_err(|e| AppError::CryptoError(format!("Invalid public key: {}", e)))?;

        // Create keypair and sign
        let keypair = Keypair {
            secret: secret_key,
            public: public_key,
        };

        let signature = keypair.sign(message.as_bytes());

        Ok(SignMessageResponse {
            signature: base64::engine::general_purpose::STANDARD.encode(signature.to_bytes()),
            public_key: bs58::encode(public_key_bytes).into_string(),
            message: message.to_string(),
        })
    }

    /// Verifies a signed message using Ed25519 cryptography
    /// Returns whether the signature is valid along with message details
    pub fn verify_message(
        &self,
        request: VerifyMessageRequest,
    ) -> AppResult<VerifyMessageResponse> {
        // Comprehensive input validation
        self.validate_verify_message_request(&request)?;

        let message = validate_message(&request.message)?;
        validate_message_size(message)?;
        validate_pubkey_string(&request.pubkey)?;
        let pubkey = validate_pubkey(&request.pubkey)?;
        let signature_bytes = validate_signature(&request.signature)?;

        // Convert pubkey to Ed25519 format
        let public_key_bytes = pubkey.to_bytes();
        let public_key = PublicKey::from_bytes(&public_key_bytes)
            .map_err(|e| AppError::CryptoError(format!("Invalid public key: {}", e)))?;

        // Parse signature
        let signature = Signature::try_from(&signature_bytes[..])
            .map_err(|e| AppError::CryptoError(format!("Invalid signature format: {}", e)))?;

        // Verify signature
        let is_valid = public_key.verify(message.as_bytes(), &signature).is_ok();

        Ok(VerifyMessageResponse {
            valid: is_valid,
            message: message.to_string(),
            pubkey: request.pubkey,
        })
    }

    /// Creates a SOL transfer instruction
    /// Validates inputs and ensures proper transfer setup
    pub fn send_sol_instruction(&self, request: SendSolRequest) -> AppResult<SendSolResponse> {
        // Comprehensive input validation
        self.validate_send_sol_request(&request)?;

        let from = validate_pubkey(&request.from)?;
        let to = validate_pubkey(&request.to)?;
        let lamports = validate_amount(request.lamports)?;

        // Business logic validation
        if from == to {
            return Err(AppError::InvalidInput(
                "From and to addresses cannot be the same".to_string(),
            ));
        }

        // Create transfer instruction
        let instruction = system_instruction::transfer(&from, &to, lamports);

        Ok(SendSolResponse {
            program_id: instruction.program_id.to_string(),
            accounts: instruction
                .accounts
                .iter()
                .map(|acc| acc.pubkey.to_string())
                .collect(),
            instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
        })
    }

    /// Creates an SPL token transfer instruction
    /// Validates inputs and creates proper token transfer
    pub fn send_token_instruction(
        &self,
        request: SendTokenRequest,
    ) -> AppResult<TokenTransferResponse> {
        // Comprehensive input validation
        self.validate_send_token_request(&request)?;

        let destination = validate_pubkey(&request.destination)?;
        let mint = validate_pubkey(&request.mint)?;
        let owner = validate_pubkey(&request.owner)?;
        let amount = validate_amount(request.amount)?;

        // Business logic validation
        if destination == owner {
            return Err(AppError::InvalidInput(
                "From and to addresses cannot be the same".to_string(),
            ));
        }

        // Get associated token accounts
        let source_ata = get_associated_token_address(&owner, &mint);
        let dest_ata = get_associated_token_address(&destination, &mint);

        // Create transfer instruction
        let instruction = token_instruction::transfer(
            &spl_token::id(),
            &source_ata,
            &dest_ata,
            &owner,
            &[],
            amount,
        )
        .map_err(|e| {
            AppError::SolanaError(format!("Failed to create transfer instruction: {}", e))
        })?;

        Ok(TokenTransferResponse {
            program_id: instruction.program_id.to_string(),
            accounts: instruction
                .accounts
                .iter()
                .map(|acc| TokenTransferAccountMeta {
                    pubkey: acc.pubkey.to_string(),
                    is_signer: acc.is_signer,
                })
                .collect(),
            instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
        })
    }

    // ===== Private Validation Methods =====

    /// Validates create token request
    fn validate_create_token_request(&self, request: &CreateTokenRequest) -> AppResult<()> {
        if request.mint_authority.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "mintAuthority is required".to_string(),
            ));
        }
        if request.mint.trim().is_empty() {
            return Err(AppError::InvalidInput("mint is required".to_string()));
        }
        validate_pubkey_string(&request.mint_authority)?;
        validate_pubkey_string(&request.mint)?;
        Ok(())
    }

    /// Validates mint token request
    fn validate_mint_token_request(&self, request: &MintTokenRequest) -> AppResult<()> {
        if request.mint.trim().is_empty() {
            return Err(AppError::InvalidInput("mint is required".to_string()));
        }
        if request.destination.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "destination is required".to_string(),
            ));
        }
        if request.authority.trim().is_empty() {
            return Err(AppError::InvalidInput("authority is required".to_string()));
        }
        Ok(())
    }

    /// Validates sign message request
    fn validate_sign_message_request(&self, request: &SignMessageRequest) -> AppResult<()> {
        if request.secret.trim().is_empty() {
            return Err(AppError::InvalidInput("secret is required".to_string()));
        }
        Ok(())
    }

    /// Validates verify message request
    fn validate_verify_message_request(&self, request: &VerifyMessageRequest) -> AppResult<()> {
        if request.message.trim().is_empty() {
            return Err(AppError::InvalidInput("message is required".to_string()));
        }
        if request.signature.trim().is_empty() {
            return Err(AppError::InvalidInput("signature is required".to_string()));
        }
        if request.pubkey.trim().is_empty() {
            return Err(AppError::InvalidInput("pubkey is required".to_string()));
        }
        Ok(())
    }

    /// Validates send SOL request
    fn validate_send_sol_request(&self, request: &SendSolRequest) -> AppResult<()> {
        if request.from.trim().is_empty() {
            return Err(AppError::InvalidInput("from is required".to_string()));
        }
        if request.to.trim().is_empty() {
            return Err(AppError::InvalidInput("to is required".to_string()));
        }
        Ok(())
    }

    /// Validates send token request
    fn validate_send_token_request(&self, request: &SendTokenRequest) -> AppResult<()> {
        if request.destination.trim().is_empty() {
            return Err(AppError::InvalidInput(
                "destination is required".to_string(),
            ));
        }
        if request.mint.trim().is_empty() {
            return Err(AppError::InvalidInput("mint is required".to_string()));
        }
        if request.owner.trim().is_empty() {
            return Err(AppError::InvalidInput("owner is required".to_string()));
        }
        Ok(())
    }

    /// Helper to convert Instruction to InstructionResponse
    fn instruction_to_response(&self, instruction: Instruction) -> InstructionResponse {
        InstructionResponse {
            program_id: instruction.program_id.to_string(),
            accounts: instruction
                .accounts
                .into_iter()
                .map(|acc| AccountMeta {
                    pubkey: acc.pubkey.to_string(),
                    is_signer: acc.is_signer,
                    is_writable: acc.is_writable,
                })
                .collect(),
            instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
        }
    }
}

impl Default for SolanaService {
    fn default() -> Self {
        Self::new()
    }
}
