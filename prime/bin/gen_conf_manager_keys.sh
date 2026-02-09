#!/bin/bash

# Output filenames
PRIVATE_KEY="private_key.pem"
PUBLIC_KEY="public_key.pem"

# Generate a 2048-bit private key
openssl genpkey -algorithm RSA -out "$PRIVATE_KEY" -pkeyopt rsa_keygen_bits:2048

# Extract the public key from the private key
openssl pkey -in "$PRIVATE_KEY" -pubout -out "$PUBLIC_KEY"

echo "Generated:"
echo "  Private key: $PRIVATE_KEY"
echo "  Public key:  $PUBLIC_KEY"
