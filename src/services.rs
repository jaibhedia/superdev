use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};
use rand_core::OsRng;
use solana_sdk::{
    instruction::Instruction,
    system_instruction,
};
use spl_associated_token_account::get_associated_token_address;
use spl_token::instruction as token_instruction;
use base64::Engine;

use crate::{
    error::{AppError, AppResult},
    models::*,
    utils::*,
};

pub struct SolanaService;

impl SolanaService {
    pub fn new() -> Self {
        Self
    }

    /// Generate a new Ed25519 keypair for Solana
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

    /// Create a new SPL token mint instruction
    pub fn create_token_instruction(&self, request: CreateTokenRequest) -> AppResult<InstructionResponse> {
        // Validate inputs
        let mint_authority = validate_pubkey(&request.mint_authority)?;
        let mint = validate_pubkey(&request.mint)?;
        let decimals = validate_decimals(request.decimals)?;

        // Create initialize mint instruction
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

    /// Create a mint tokens instruction
    pub fn mint_token_instruction(&self, request: MintTokenRequest) -> AppResult<InstructionResponse> {
        // Validate inputs
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

    /// Sign a message using Ed25519
    pub fn sign_message(&self, request: SignMessageRequest) -> AppResult<SignMessageResponse> {
        // Validate inputs
        let message = validate_message(&request.message)?;
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

    /// Verify a signed message
    pub fn verify_message(&self, request: VerifyMessageRequest) -> AppResult<VerifyMessageResponse> {
        // Validate inputs
        let message = validate_message(&request.message)?;
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

    /// Create SOL transfer instruction
    pub fn send_sol_instruction(&self, request: SendSolRequest) -> AppResult<SolTransferResponse> {
        // Validate inputs
        let from = validate_pubkey(&request.from)?;
        let to = validate_pubkey(&request.to)?;
        let lamports = validate_amount(request.lamports)?;

        // Create transfer instruction
        let instruction = system_instruction::transfer(&from, &to, lamports);

        Ok(SolTransferResponse {
            program_id: instruction.program_id.to_string(),
            accounts: instruction
                .accounts
                .iter()
                .map(|acc| acc.pubkey.to_string())
                .collect(),
            instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
        })
    }

    /// Create SPL token transfer instruction
    pub fn send_token_instruction(&self, request: SendTokenRequest) -> AppResult<TokenTransferResponse> {
        // Validate inputs
        let destination = validate_pubkey(&request.destination)?;
        let mint = validate_pubkey(&request.mint)?;
        let owner = validate_pubkey(&request.owner)?;
        let amount = validate_amount(request.amount)?;

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
        .map_err(|e| AppError::SolanaError(format!("Failed to create transfer instruction: {}", e)))?;

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

    /// Helper to convert Instruction to InstructionResponse
    fn instruction_to_response(&self, instruction: Instruction) -> InstructionResponse {
        InstructionResponse {
            program_id: instruction.program_id.to_string(),
            accounts: instruction
                .accounts
                .into_iter()
                .map(|acc| crate::models::AccountMeta {
                    pubkey: acc.pubkey.to_string(),
                    is_signer: acc.is_signer,
                    is_writable: acc.is_writable,
                })
                .collect(),
            instruction_data: base64::engine::general_purpose::STANDARD.encode(&instruction.data),
        }
    }
}
