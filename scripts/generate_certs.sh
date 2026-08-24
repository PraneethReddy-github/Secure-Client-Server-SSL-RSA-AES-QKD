#!/bin/bash

# Script to generate local self-signed SSL/TLS certificates for testing

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
BASE_DIR="$(dirname "$SCRIPT_DIR")"
CERTS_DIR="$BASE_DIR/certs"
CONFIG_FILE="$BASE_DIR/config/openssl.cnf"

mkdir -p "$CERTS_DIR"

echo "Generating self-signed SSL certificate..."
openssl req -x509 -newkey rsa:2048 \
  -keyout "$CERTS_DIR/server.key" \
  -out "$CERTS_DIR/server.crt" \
  -days 365 \
  -nodes \
  -config "$CONFIG_FILE"

echo "Certificate generation complete!"
echo "  Private Key: $CERTS_DIR/server.key"
echo "  Public Cert: $CERTS_DIR/server.crt"
