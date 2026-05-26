#!/bin/sh
# Generate a self-signed certificate for the auto-bughunter sidecar mesh.
#
# Output (written once, then reused on subsequent boots):
#   /certs/server.crt   - PEM cert; backend trusts this as its CA bundle
#                         (SIDECAR_CA_BUNDLE), sidecars serve it as their
#                         server cert.
#   /certs/server.key   - matching PEM private key, served by every sidecar.
#
# The cert is self-signed (so it acts as its own CA) and lists every sidecar
# service hostname in SubjectAltName so the backend can verify any of them
# without per-service certs:
#
#   ml-service, agents, security-knowledge, nuclei-service, zap-service
#
# `localhost` and `127.0.0.1` are included so each sidecar's own HTTPS
# healthcheck (`https://localhost:PORT/health`) verifies cleanly too.

set -eu

CERT=/certs/server.crt
KEY=/certs/server.key

if [ -s "${CERT}" ] && [ -s "${KEY}" ]; then
    echo "tls-init: ${CERT} already present, reusing existing keypair"
    exit 0
fi

mkdir -p /certs

CONF=$(mktemp)
cat >"${CONF}" <<'EOF'
[req]
distinguished_name = req_dn
prompt             = no
x509_extensions    = v3_ext

[req_dn]
CN = auto-bughunter sidecar mesh
O  = auto-bughunter

[v3_ext]
basicConstraints     = critical, CA:TRUE
keyUsage             = critical, digitalSignature, keyEncipherment, keyCertSign
extendedKeyUsage     = serverAuth, clientAuth
subjectAltName       = @alt_names

[alt_names]
DNS.1 = ml-service
DNS.2 = agents
DNS.3 = security-knowledge
DNS.4 = nuclei-service
DNS.5 = zap-service
DNS.6 = localhost
IP.1  = 127.0.0.1
EOF

echo "tls-init: generating self-signed cert (valid 10 years)"
openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -days 3650 \
    -keyout "${KEY}" \
    -out "${CERT}" \
    -config "${CONF}"

rm -f "${CONF}"

# Make readable by non-root users inside the sidecar containers (the
# python:3.12-slim and zap images run uvicorn as non-root).
chmod 0644 "${CERT}" "${KEY}"

echo "tls-init: wrote ${CERT}"
openssl x509 -in "${CERT}" -noout -subject -issuer -dates -ext subjectAltName 2>/dev/null || true
