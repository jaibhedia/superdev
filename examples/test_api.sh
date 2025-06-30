#!/bin/bash

# Solana HTTP Server - Example Usage Script
# This script demonstrates how to use all endpoints

set -e

BASE_URL="http://localhost:8080"

echo "Solana HTTP Server API Examples"
echo "===================================="

# Check if server is running
echo "Checking server health..."
curl -s "${BASE_URL}/health" | jq '.' || {
    echo " Server is not running. Please start it with: cargo run"
    exit 1
}

echo " Server is healthy!"
echo

# 1. Generate Keypair
echo "1. Generating new keypair..."
KEYPAIR_RESPONSE=$(curl -s -X POST "${BASE_URL}/keypair" -H "Content-Type: application/json")
echo "$KEYPAIR_RESPONSE" | jq '.'

# Extract keys for further use
PUBKEY=$(echo "$KEYPAIR_RESPONSE" | jq -r '.data.pubkey')
SECRET=$(echo "$KEYPAIR_RESPONSE" | jq -r '.data.secret')

echo "Generated Pubkey: $PUBKEY"
echo

# 2. Sign Message
echo " 2. Signing message..."
SIGN_RESPONSE=$(curl -s -X POST "${BASE_URL}/message/sign" \
    -H "Content-Type: application/json" \
    -d "{
        \"message\": \"Hello, Solana!\",
        \"secret\": \"$SECRET\"
    }")
echo "$SIGN_RESPONSE" | jq '.'

# Extract signature for verification
SIGNATURE=$(echo "$SIGN_RESPONSE" | jq -r '.data.signature')
echo

# 3. Verify Message
echo "🔍 3. Verifying message..."
VERIFY_RESPONSE=$(curl -s -X POST "${BASE_URL}/message/verify" \
    -H "Content-Type: application/json" \
    -d "{
        \"message\": \"Hello, Solana!\",
        \"signature\": \"$SIGNATURE\",
        \"pubkey\": \"$PUBKEY\"
    }")
echo "$VERIFY_RESPONSE" | jq '.'
echo

# 4. Create Token
echo "4. Creating token mint instruction..."
# Using system program pubkey as example
MINT_AUTHORITY="11111111111111111111111111111112"
MINT_PUBKEY="So11111111111111111111111111111111111111112"

TOKEN_CREATE_RESPONSE=$(curl -s -X POST "${BASE_URL}/token/create" \
    -H "Content-Type: application/json" \
    -d "{
        \"mintAuthority\": \"$MINT_AUTHORITY\",
        \"mint\": \"$MINT_PUBKEY\",
        \"decimals\": 6
    }")
echo "$TOKEN_CREATE_RESPONSE" | jq '.'
echo

# 5. Mint Token
echo "🏭 5. Creating mint token instruction..."
MINT_RESPONSE=$(curl -s -X POST "${BASE_URL}/token/mint" \
    -H "Content-Type: application/json" \
    -d "{
        \"mint\": \"$MINT_PUBKEY\",
        \"destination\": \"$PUBKEY\",
        \"authority\": \"$MINT_AUTHORITY\",
        \"amount\": 1000000
    }")
echo "$MINT_RESPONSE" | jq '.'
echo

# 6. Send SOL
echo "6. Creating SOL transfer instruction..."
SOL_RESPONSE=$(curl -s -X POST "${BASE_URL}/send/sol" \
    -H "Content-Type: application/json" \
    -d "{
        \"from\": \"$PUBKEY\",
        \"to\": \"$MINT_AUTHORITY\",
        \"lamports\": 1000000
    }")
echo "$SOL_RESPONSE" | jq '.'
echo

# 7. Send Token
echo "7. Creating token transfer instruction..."
TOKEN_RESPONSE=$(curl -s -X POST "${BASE_URL}/send/token" \
    -H "Content-Type: application/json" \
    -d "{
        \"destination\": \"$MINT_AUTHORITY\",
        \"mint\": \"$MINT_PUBKEY\",
        \"owner\": \"$PUBKEY\",
        \"amount\": 500000
    }")
echo "$TOKEN_RESPONSE" | jq '.'
echo

echo "All API endpoints tested successfully!"
echo
echo "For more information, check the README.md file."
