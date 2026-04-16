# Generate deterministic test PKI for OPC UA tests (Windows).
# Delegates to openssl on PATH. Ships the same directory layout as gen_test_certs.sh.
#
# OpenSSL writes diagnostic messages (e.g. "Certificate request self-signature ok")
# to stderr even on success. Under $ErrorActionPreference = "Stop" and PowerShell
# 7.3+, any stderr output from a native command is treated as a terminating
# NativeCommandError. We therefore use "Continue" mode and verify success via
# $LASTEXITCODE after each openssl call.

$ErrorActionPreference = "Continue"
if (Get-Variable -Name PSNativeCommandUseErrorActionPreference -Scope Global -ErrorAction SilentlyContinue) {
    $Global:PSNativeCommandUseErrorActionPreference = $false
}

$PkiDir = Join-Path (Get-Location) "tests\pki"
$Days   = 3650

function Resolve-OpenSSL {
    $cmd = Get-Command openssl -ErrorAction SilentlyContinue
    if (-not $cmd) {
        Write-Host "openssl not found in PATH. Install OpenSSL (e.g. via Git for Windows, vcpkg, or Chocolatey)." -ForegroundColor Red
        exit 1
    }
    return $cmd.Source
}

$openssl = Resolve-OpenSSL

function Run-OpenSSL {
    & $openssl @args 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "openssl failed (exit $LASTEXITCODE): $($args -join ' ')" -ForegroundColor Red
        exit 1
    }
}

# Skip if valid CA already exists.
$caCert = Join-Path $PkiDir "ca\cert.pem"
if (Test-Path $caCert) {
    & $openssl x509 -in $caCert -checkend 86400 -noout 2>&1 | Out-Null
    if ($LASTEXITCODE -eq 0) {
        Write-Host "Test PKI already present at $PkiDir - skipping generation."
        return
    }
}

Write-Host "Generating test PKI under $PkiDir..."

$subDirs = @(
    "ca", "server", "client",
    "trusted\certs", "trusted\crl",
    "issuers\certs", "issuers\crl",
    "expired", "untrusted_ca", "untrusted_server"
)
foreach ($sub in $subDirs) {
    $path = Join-Path $PkiDir $sub
    if (-not (Test-Path $path)) { New-Item -ItemType Directory -Path $path -Force | Out-Null }
}

# --- CA ---
$caCfg = @"
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
"@
$caCfgPath = Join-Path $PkiDir "ca\openssl.cnf"
Set-Content -Path $caCfgPath -Value $caCfg -Encoding ASCII

Run-OpenSSL genrsa -out (Join-Path $PkiDir "ca\key.pem") 2048
Run-OpenSSL req -x509 -new -nodes `
    -key (Join-Path $PkiDir "ca\key.pem") `
    -config $caCfgPath `
    -sha256 -days $Days `
    -out (Join-Path $PkiDir "ca\cert.pem")

# --- Server ---
$serverCfg = @"
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
"@
$serverCfgPath = Join-Path $PkiDir "server\openssl.cnf"
Set-Content -Path $serverCfgPath -Value $serverCfg -Encoding ASCII

Run-OpenSSL genrsa -out (Join-Path $PkiDir "server\key.pem") 2048
Run-OpenSSL req -new `
    -key    (Join-Path $PkiDir "server\key.pem") `
    -config $serverCfgPath `
    -out    (Join-Path $PkiDir "server\csr.pem")
Run-OpenSSL x509 -req `
    -in     (Join-Path $PkiDir "server\csr.pem") `
    -CA     (Join-Path $PkiDir "ca\cert.pem") -CAkey (Join-Path $PkiDir "ca\key.pem") -CAcreateserial `
    -out    (Join-Path $PkiDir "server\cert.pem") `
    -days   $Days -sha256 `
    -extensions v3_req -extfile $serverCfgPath
Run-OpenSSL x509 -in  (Join-Path $PkiDir "server\cert.pem") -outform DER -out (Join-Path $PkiDir "server\cert.der")
Remove-Item (Join-Path $PkiDir "server\csr.pem") -ErrorAction SilentlyContinue

# --- Client ---
$clientCfg = @"
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
"@
$clientCfgPath = Join-Path $PkiDir "client\openssl.cnf"
Set-Content -Path $clientCfgPath -Value $clientCfg -Encoding ASCII

Run-OpenSSL genrsa -out (Join-Path $PkiDir "client\key.pem") 2048
Run-OpenSSL req -new `
    -key    (Join-Path $PkiDir "client\key.pem") `
    -config $clientCfgPath `
    -out    (Join-Path $PkiDir "client\csr.pem")
Run-OpenSSL x509 -req `
    -in     (Join-Path $PkiDir "client\csr.pem") `
    -CA     (Join-Path $PkiDir "ca\cert.pem") -CAkey (Join-Path $PkiDir "ca\key.pem") -CAcreateserial `
    -out    (Join-Path $PkiDir "client\cert.pem") `
    -days   $Days -sha256 `
    -extensions v3_req -extfile $clientCfgPath
Run-OpenSSL x509 -in  (Join-Path $PkiDir "client\cert.pem") -outform DER -out (Join-Path $PkiDir "client\cert.der")
Remove-Item (Join-Path $PkiDir "client\csr.pem") -ErrorAction SilentlyContinue

# --- Publish CA into trusted/ ---
Run-OpenSSL x509 -in (Join-Path $PkiDir "ca\cert.pem") -outform DER -out (Join-Path $PkiDir "trusted\certs\ca.der")

# --- Expired cert for negative tests ---
Run-OpenSSL genrsa -out (Join-Path $PkiDir "expired\key.pem") 2048
Run-OpenSSL req -new `
    -key    (Join-Path $PkiDir "expired\key.pem") `
    -subj "/CN=Sindarin OPC UA Expired Test/O=Sindarin/C=GB" `
    -out    (Join-Path $PkiDir "expired\csr.pem")
Run-OpenSSL x509 -req `
    -in     (Join-Path $PkiDir "expired\csr.pem") `
    -CA     (Join-Path $PkiDir "ca\cert.pem") -CAkey (Join-Path $PkiDir "ca\key.pem") -CAcreateserial `
    -out    (Join-Path $PkiDir "expired\cert.pem") `
    -days   -1 -sha256
Run-OpenSSL x509 -in  (Join-Path $PkiDir "expired\cert.pem") -outform DER -out (Join-Path $PkiDir "expired\cert.der")
Remove-Item (Join-Path $PkiDir "expired\csr.pem") -ErrorAction SilentlyContinue

# --- Untrusted CA + server cert signed by it ---
Run-OpenSSL genrsa -out (Join-Path $PkiDir "untrusted_ca\key.pem") 2048
Run-OpenSSL req -x509 -new -nodes `
    -key    (Join-Path $PkiDir "untrusted_ca\key.pem") `
    -sha256 -days $Days `
    -subj "/CN=Sindarin OPC UA Untrusted CA/O=Evil/C=XX" `
    -out    (Join-Path $PkiDir "untrusted_ca\cert.pem")
Run-OpenSSL genrsa -out (Join-Path $PkiDir "untrusted_server\key.pem") 2048
Run-OpenSSL req -new `
    -key    (Join-Path $PkiDir "untrusted_server\key.pem") `
    -config $serverCfgPath `
    -out    (Join-Path $PkiDir "untrusted_server\csr.pem")
Run-OpenSSL x509 -req `
    -in     (Join-Path $PkiDir "untrusted_server\csr.pem") `
    -CA     (Join-Path $PkiDir "untrusted_ca\cert.pem") -CAkey (Join-Path $PkiDir "untrusted_ca\key.pem") -CAcreateserial `
    -out    (Join-Path $PkiDir "untrusted_server\cert.pem") `
    -days   $Days -sha256 `
    -extensions v3_req -extfile $serverCfgPath
Run-OpenSSL x509 -in  (Join-Path $PkiDir "untrusted_server\cert.pem") -outform DER -out (Join-Path $PkiDir "untrusted_server\cert.der")
Remove-Item (Join-Path $PkiDir "untrusted_server\csr.pem") -ErrorAction SilentlyContinue

Write-Host "Test PKI generated successfully."
