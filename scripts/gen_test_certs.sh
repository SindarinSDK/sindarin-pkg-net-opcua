#!/bin/bash
# Generate deterministic test PKI for OPC UA tests.
# Produces under tests/pki/:
#   ca/cert.pem, ca/key.pem
#   server/cert.pem, server/key.pem, server/cert.der
#   client/cert.pem, client/key.pem, client/cert.der
#   trusted/certs/ca.der            (for client-side trust list)
#   trusted/crl/                    (empty)
#   issuers/certs/, issuers/crl/    (empty)
#
# Skips generation if CA key/cert already exist and are unexpired.

set -e

PKI_DIR="$(pwd)/tests/pki"
DAYS=3650  # 10 years — long enough that tests don't break on date math

mkdir -p "$PKI_DIR"/{ca,server,client,trusted/certs,trusted/crl,issuers/certs,issuers/crl}

if [ -f "$PKI_DIR/ca/cert.pem" ] && openssl x509 -in "$PKI_DIR/ca/cert.pem" -checkend 86400 -noout >/dev/null 2>&1; then
    echo "Test PKI already present at $PKI_DIR — skipping generation."
    exit 0
fi

command -v openssl >/dev/null 2>&1 || { echo "openssl not found in PATH" >&2; exit 1; }

echo "Generating test PKI under $PKI_DIR..."

# ------------------------------------------------------------------
# Test CA
# ------------------------------------------------------------------
cat > "$PKI_DIR/ca/openssl.cnf" <<'EOF'
[req]
distinguished_name = req_dn
x509_extensions    = v3_ca
prompt             = no

[req_dn]
CN = Sindarin OPC UA Test CA
O  = Sindarin
C  = GB

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage         = critical, digitalSignature, keyCertSign, cRLSign
EOF

openssl genrsa -out "$PKI_DIR/ca/key.pem" 2048 2>/dev/null
openssl req -x509 -new -nodes \
    -key "$PKI_DIR/ca/key.pem" \
    -config "$PKI_DIR/ca/openssl.cnf" \
    -sha256 -days $DAYS \
    -out "$PKI_DIR/ca/cert.pem" 2>/dev/null

# ------------------------------------------------------------------
# Server cert (SAN covers localhost + loopback addresses + URI)
# ------------------------------------------------------------------
cat > "$PKI_DIR/server/openssl.cnf" <<'EOF'
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no

[req_dn]
CN = Sindarin OPC UA Test Server
O  = Sindarin
C  = GB

[v3_req]
basicConstraints     = CA:FALSE
keyUsage             = digitalSignature, keyEncipherment, dataEncipherment, keyCertSign, nonRepudiation
extendedKeyUsage     = serverAuth, clientAuth
subjectAltName       = @san

[san]
DNS.1 = localhost
IP.1  = 127.0.0.1
IP.2  = ::1
URI.1 = urn:sindarin:opcua-test-server
EOF

openssl genrsa -out "$PKI_DIR/server/key.pem" 2048 2>/dev/null
openssl req -new \
    -key "$PKI_DIR/server/key.pem" \
    -config "$PKI_DIR/server/openssl.cnf" \
    -out "$PKI_DIR/server/csr.pem" 2>/dev/null
openssl x509 -req \
    -in "$PKI_DIR/server/csr.pem" \
    -CA "$PKI_DIR/ca/cert.pem" -CAkey "$PKI_DIR/ca/key.pem" -CAcreateserial \
    -out "$PKI_DIR/server/cert.pem" \
    -days $DAYS -sha256 \
    -extensions v3_req -extfile "$PKI_DIR/server/openssl.cnf" 2>/dev/null
openssl x509 -in "$PKI_DIR/server/cert.pem" -outform DER -out "$PKI_DIR/server/cert.der"
rm -f "$PKI_DIR/server/csr.pem"

# ------------------------------------------------------------------
# Client cert
# ------------------------------------------------------------------
cat > "$PKI_DIR/client/openssl.cnf" <<'EOF'
[req]
distinguished_name = req_dn
req_extensions     = v3_req
prompt             = no

[req_dn]
CN = Sindarin OPC UA Test Client
O  = Sindarin
C  = GB

[v3_req]
basicConstraints     = CA:FALSE
keyUsage             = digitalSignature, keyEncipherment, dataEncipherment, keyCertSign, nonRepudiation
extendedKeyUsage     = clientAuth
subjectAltName       = @san

[san]
DNS.1 = localhost
URI.1 = urn:sindarin:opcua-test-client
EOF

openssl genrsa -out "$PKI_DIR/client/key.pem" 2048 2>/dev/null
openssl req -new \
    -key "$PKI_DIR/client/key.pem" \
    -config "$PKI_DIR/client/openssl.cnf" \
    -out "$PKI_DIR/client/csr.pem" 2>/dev/null
openssl x509 -req \
    -in "$PKI_DIR/client/csr.pem" \
    -CA "$PKI_DIR/ca/cert.pem" -CAkey "$PKI_DIR/ca/key.pem" -CAcreateserial \
    -out "$PKI_DIR/client/cert.pem" \
    -days $DAYS -sha256 \
    -extensions v3_req -extfile "$PKI_DIR/client/openssl.cnf" 2>/dev/null
openssl x509 -in "$PKI_DIR/client/cert.pem" -outform DER -out "$PKI_DIR/client/cert.der"
rm -f "$PKI_DIR/client/csr.pem"

# ------------------------------------------------------------------
# Publish CA into trusted/ for the client trust list
# ------------------------------------------------------------------
openssl x509 -in "$PKI_DIR/ca/cert.pem" -outform DER -out "$PKI_DIR/trusted/certs/ca.der"

# ------------------------------------------------------------------
# Generate an expired cert for negative tests
# ------------------------------------------------------------------
mkdir -p "$PKI_DIR/expired"
openssl genrsa -out "$PKI_DIR/expired/key.pem" 2048 2>/dev/null
openssl req -new \
    -key "$PKI_DIR/expired/key.pem" \
    -subj "/CN=Sindarin OPC UA Expired Test/O=Sindarin/C=GB" \
    -out "$PKI_DIR/expired/csr.pem" 2>/dev/null
# -days -1 produces an already-expired cert
openssl x509 -req \
    -in "$PKI_DIR/expired/csr.pem" \
    -CA "$PKI_DIR/ca/cert.pem" -CAkey "$PKI_DIR/ca/key.pem" -CAcreateserial \
    -out "$PKI_DIR/expired/cert.pem" \
    -days -1 -sha256 2>/dev/null
openssl x509 -in "$PKI_DIR/expired/cert.pem" -outform DER -out "$PKI_DIR/expired/cert.der"
rm -f "$PKI_DIR/expired/csr.pem"

# ------------------------------------------------------------------
# Generate a cert signed by an UNTRUSTED CA for negative tests
# ------------------------------------------------------------------
mkdir -p "$PKI_DIR/untrusted_ca" "$PKI_DIR/untrusted_server"
openssl genrsa -out "$PKI_DIR/untrusted_ca/key.pem" 2048 2>/dev/null
openssl req -x509 -new -nodes \
    -key "$PKI_DIR/untrusted_ca/key.pem" \
    -sha256 -days $DAYS \
    -subj "/CN=Sindarin OPC UA Untrusted CA/O=Evil/C=XX" \
    -out "$PKI_DIR/untrusted_ca/cert.pem" 2>/dev/null
openssl genrsa -out "$PKI_DIR/untrusted_server/key.pem" 2048 2>/dev/null
openssl req -new \
    -key "$PKI_DIR/untrusted_server/key.pem" \
    -config "$PKI_DIR/server/openssl.cnf" \
    -out "$PKI_DIR/untrusted_server/csr.pem" 2>/dev/null
openssl x509 -req \
    -in "$PKI_DIR/untrusted_server/csr.pem" \
    -CA "$PKI_DIR/untrusted_ca/cert.pem" -CAkey "$PKI_DIR/untrusted_ca/key.pem" -CAcreateserial \
    -out "$PKI_DIR/untrusted_server/cert.pem" \
    -days $DAYS -sha256 \
    -extensions v3_req -extfile "$PKI_DIR/server/openssl.cnf" 2>/dev/null
openssl x509 -in "$PKI_DIR/untrusted_server/cert.pem" -outform DER -out "$PKI_DIR/untrusted_server/cert.der"
rm -f "$PKI_DIR/untrusted_server/csr.pem"

echo "Test PKI generated successfully."
