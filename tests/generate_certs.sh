#!/bin/bash

# Script to generate test certificates for TLS testing
# This creates a Certificate Authority (CA) and a server certificate signed by that CA

set -e

# Navigate to the tests directory
cd "$(dirname "$0")"

echo "Generating test certificates..."

# 1. Generate CA private key
echo "1. Generating CA private key..."
openssl genrsa -out ca.key 2048

# 2. Generate CA certificate (self-signed)
echo "2. Generating CA certificate..."
openssl req -new -x509 -days 365 -key ca.key -out ca.pem \
    -subj "//CN=Test-CA"

# 3. Generate server private key
echo "3. Generating server private key..."
openssl genrsa -out server.key 2048

# 4. Generate server certificate signing request (CSR)
echo "4. Generating server CSR..."
openssl req -new -key server.key -out server.csr \
    -subj "//CN=localhost"

# 5. Create SAN extension file for server certificate
echo "5. Creating SAN extension configuration..."
cat > server_san.cnf <<EOF
subjectAltName = DNS:localhost,IP:127.0.0.1
EOF

# 6. Sign server certificate with CA and SAN
echo "6. Signing server certificate with CA..."
openssl x509 -req -days 365 -in server.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out server.pem -extfile server_san.cnf

# 7. Generate client private key
echo "7. Generating client private key..."

# 6. Generate client private key
echo "6. Generating client private key..."
openssl genrsa -out client.key 2048

# 7. Generate client certificate signing request (CSR)
echo "7. Generating client CSR..."
openssl req -new -key client.key -out client.csr \
    -subj "//CN=Test-Client"

# 8. Sign client certificate with CA
echo "8. Signing client certificate with CA..."
openssl x509 -req -days 365 -in client.csr -CA ca.pem -CAkey ca.key \
    -CAcreateserial -out client.pem

# 9. Clean up CSR and serial files
echo "9. Cleaning up temporary files..."
rm -f server.csr client.csr ca.srl server_san.cnf

echo ""
echo "Certificate generation complete!"
echo "Generated files:"
echo "  - ca.key        : CA private key"
echo "  - ca.pem        : CA certificate (self-signed)"
echo "  - server.key    : Server private key"
echo "  - server.pem    : Server certificate (signed by CA)"
echo "  - client.key    : Client private key"
echo "  - client.pem    : Client certificate (signed by CA)"
echo ""
echo "To verify the certificates:"
echo "  openssl x509 -in ca.pem -text -noout"
echo "  openssl x509 -in server.pem -text -noout"
echo "  openssl x509 -in client.pem -text -noout"
echo "  openssl verify -CAfile ca.pem server.pem"
