# Solana HTTP Server

A high-performance, production-ready HTTP server built in Rust for Solana blockchain operations. This server provides secure endpoints for keypair generation, SPL token operations, message signing/verification, and transaction instruction creation.

## Features

- **Keypair Generation**: Generate secure Ed25519 keypairs for Solana
- **SPL Token Operations**: Create tokens and mint instructions
- **Message Signing**: Sign and verify messages using Ed25519 cryptography
- **Transaction Instructions**: Create SOL and SPL token transfer instructions
- **Production Ready**: Comprehensive error handling, logging, and input validation
- **High Performance**: Built with Axum framework for maximum throughput

## 🛠️ Installation

### Prerequisites

- Rust 1.70+ (install via [rustup](https://rustup.rs/))
- Cargo (included with Rust)

### Setup

```bash
# Clone the repository
git clone https://www.github.com/jaibhedia/superdev 

# Install dependencies and build
cargo build --release

# Run the server
cargo run --release
```

The server should start on `http://localhost:3000`

## 📚 API Documentation

### Response Format

All endpoints return JSON responses with a consistent format:

**Success Response (200 OK):**
```json
{
  "success": true,
  "data": { /* endpoint-specific result */ }
}
```

**Error Response (400 Bad Request):**
```json
{
  "success": false,
  "error": "Description of error"
}
```

### Common Error Types

- **Invalid Input**: Invalid public keys, amounts, decimals, etc.
- **Cryptographic Error**: Invalid signatures, key format issues
- **Validation Error**: Empty messages, same from/to addresses
- **JSON Error**: Malformed JSON or missing required fields

Example error responses:
```json
// Invalid public key
{
  "success": false,
  "error": "Invalid public key 'invalid': Invalid Base58 string"
}

// Zero amount
{
  "success": false,
  "error": "Amount must be greater than 0"
}

// Same addresses
{
  "success": false,
  "error": "From and to addresses cannot be the same"
}
```

### Endpoints

#### 1. Generate Keypair
- **POST** `/keypair`
- Generates a new Solana keypair using secure randomness

**Response:**
```json
{
  "success": true,
  "data": {
    "pubkey": "base58-encoded-public-key",
    "secret": "base58-encoded-secret-key"
  }
}
```

#### 2. Create Token
- **POST** `/token/create`
- Creates an SPL token mint initialization instruction

**Request:**
```json
{
  "mintAuthority": "base58-encoded-public-key",
  "mint": "base58-encoded-public-key",
  "decimals": 6
}
```

#### 3. Mint Token
- **POST** `/token/mint`
- Creates a mint-to instruction for SPL tokens

**Request:**
```json
{
  "mint": "mint-address",
  "destination": "destination-address",
  "authority": "authority-address",
  "amount": 1000000
}
```

#### 4. Sign Message
- **POST** `/message/sign`
- Signs a message using Ed25519 cryptography

**Request:**
```json
{
  "message": "Hello, Solana!",
  "secret": "base58-encoded-secret-key"
}
```

#### 5. Verify Message
- **POST** `/message/verify`
- Verifies a signed message

**Request:**
```json
{
  "message": "Hello, Solana!",
  "signature": "base64-encoded-signature",
  "pubkey": "base58-encoded-public-key"
}
```

#### 6. Send SOL
- **POST** `/send/sol`
- Creates a SOL transfer instruction

**Request:**
```json
{
  "from": "sender-address",
  "to": "recipient-address",
  "lamports": 100000
}
```

#### 7. Send Token
- **POST** `/send/token`
- Creates an SPL token transfer instruction

**Request:**
```json
{
  "destination": "destination-address",
  "mint": "mint-address",
  "owner": "owner-address",
  "amount": 100000
}
```

## 🔧 Development

### Running in Development Mode

```bash
# Run with hot-reload (install cargo-watch first)
cargo install cargo-watch
cargo watch -x run

# Run tests
cargo test

# Check code formatting
cargo fmt --check

# Run clippy for linting
cargo clippy -- -D warnings
```

### Project Structure

```
src/
├── main.rs          # Application entry point and server setup
├── handlers.rs      # HTTP request handlers
├── services.rs      # Business logic and Solana operations
├── models.rs        # Data structures and serialization
├── error.rs         # Error handling and response formatting
└── utils.rs         # Input validation utilities
```

## 🔒 Security Features

- **No Key Storage**: Private keys are never stored on the server
- **Comprehensive Input Validation**: All inputs are validated including:
  - Public key format and length validation
  - Secret key format and 64-byte length validation
  - Message length limits (1KB for signing, 10KB for verification)
  - Amount validation (must be > 0, within reasonable bounds)
  - Decimals validation (0-9 for SPL tokens)
  - Signature format and length validation (64 bytes for Ed25519)
  - Prevention of identical from/to addresses in transfers
  - Prevention of identical mint and mint authority addresses
- **Standard Cryptography**: Uses industry-standard Ed25519 implementation
- **Secure Error Handling**: Error messages don't leak sensitive information
- **JSON Validation**: Proper handling of malformed JSON and missing fields
- **CORS Support**: Configurable CORS headers for web integration

## 🧪 Test Coverage

The server includes **25 comprehensive tests** covering:

### Functionality Tests
- Keypair generation and validation
- Token creation and minting instructions
- Message signing and verification
- SOL and token transfer instructions

### Edge Case Tests
- Zero amounts (rejected)
- Maximum decimal values (0-9 accepted)
- Same from/to addresses (rejected)
- Same mint/authority addresses (rejected)
- Empty messages (rejected)
- Large amounts (accepted within bounds)

### Error Handling Tests
- Invalid public keys and signatures
- Malformed JSON requests
- Missing required fields
- Invalid signature lengths
- Wrong signature verification

Run tests with:
```bash
cargo test
```

## Deployment

- Done with Railway

## Performance

- Built with Axum for maximum performance
- Async/await throughout for non-blocking operations
- Optimized release builds with LTO
- Minimal memory allocations
- Connection pooling and request batching ready
