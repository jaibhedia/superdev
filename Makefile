# Development Scripts
dev:
	cargo watch -x run

# Build for production
build:
	cargo build --release

# Run tests
test:
	cargo test

# Format code
fmt:
	cargo fmt

# Lint code
lint:
	cargo clippy -- -D warnings

# Check for security vulnerabilities
audit:
	cargo audit

# Run with custom port
run-port:
	PORT=8080 cargo run

# Docker commands
docker-build:
	docker build -t solana-http-server .

docker-run:
	docker run -p 3000:3000 solana-http-server

# Docker compose
up:
	docker-compose up -d

down:
	docker-compose down

# Development with monitoring
up-dev:
	docker-compose --profile monitoring up -d

# Clean build artifacts
clean:
	cargo clean
	docker system prune -f

# Full test suite including integration tests
test-all:
	cargo test --all-features
	./examples/test_api.sh

# Install development dependencies
install-dev:
	cargo install cargo-watch cargo-audit

.PHONY: dev build test fmt lint audit run-port docker-build docker-run up down up-dev clean test-all install-dev
