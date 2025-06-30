# Solana HTTP Server

A high-performance, production-ready HTTP server built in Rust for Solana blockchain operations. This server provides secure endpoints for keypair generation, SPL token operations, message signing/verification, and transaction instruction creation.

## 🚀 Features

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
git clone <your-repo-url>
cd solana-http-server

# Install dependencies and build
cargo build --release

# Run the server
cargo run --release
```

The server will start on `http://localhost:3000`

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
- **Input Validation**: Comprehensive validation of all inputs
- **Standard Cryptography**: Uses industry-standard Ed25519 implementation
- **Error Handling**: Secure error messages that don't leak sensitive information
- **CORS Support**: Configurable CORS headers for web integration

## 🚀 Deployment

### Docker Deployment

```dockerfile
# Dockerfile
FROM rust:1.70 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/solana-http-server /usr/local/bin/
EXPOSE 3000
CMD ["solana-http-server"]
```

### Environment Variables

- `RUST_LOG`: Set logging level (default: `info`)
- `PORT`: Server port (default: `3000`)

## 📈 Performance

- Built with Axum for maximum performance
- Async/await throughout for non-blocking operations
- Optimized release builds with LTO
- Minimal memory allocations
- Connection pooling and request batching ready

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
