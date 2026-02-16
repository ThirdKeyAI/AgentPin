# Deployment Guide

This guide covers how to deploy AgentPin discovery and revocation endpoints in production.

---

## Architecture Overview

```
Internet                          Your Infrastructure
─────────                         ──────────────────

Verifiers ──HTTPS──> Reverse Proxy ──> agentpin-server
                     (nginx/Apache)    (port 8080)
                          │
                          ├── /.well-known/agent-identity.json
                          └── /.well-known/agent-identity-revocations.json
```

AgentPin endpoints are static JSON documents served over HTTPS. You can either:

1. **Use `agentpin-server`** — The built-in Axum HTTP server
2. **Serve static files** — Place JSON documents in your web server's document root
3. **Use a CDN** — Serve from S3/CloudFront or similar

---

## Option 1: Using agentpin-server

### Build

```bash
cargo install --path crates/agentpin-server
```

### Run

```bash
agentpin-server \
  --discovery ./agent-identity.json \
  --revocation ./revocations.json \
  --port 8080
```

### Endpoints

| Path | Cache-Control | Description |
|------|---------------|-------------|
| `GET /.well-known/agent-identity.json` | `max-age=3600` | Discovery document |
| `GET /.well-known/agent-identity-revocations.json` | `max-age=300` | Revocation document |
| `GET /health` | — | Health check (`200 OK`) |

### Systemd Service

```ini
# /etc/systemd/system/agentpin.service
[Unit]
Description=AgentPin Discovery Server
After=network.target

[Service]
Type=simple
User=agentpin
Group=agentpin
WorkingDirectory=/opt/agentpin
ExecStart=/usr/local/bin/agentpin-server \
  --discovery /opt/agentpin/agent-identity.json \
  --revocation /opt/agentpin/revocations.json \
  --port 8080
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl enable --now agentpin
```

---

## Option 2: Static Files

Place discovery and revocation documents directly in your web server's `.well-known` directory:

```
/var/www/example.com/.well-known/
├── agent-identity.json
└── agent-identity-revocations.json
```

### Nginx Configuration

```nginx
server {
    listen 443 ssl http2;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    # AgentPin discovery document
    location = /.well-known/agent-identity.json {
        root /var/www/example.com;
        default_type application/json;
        add_header Cache-Control "public, max-age=3600";
        add_header Access-Control-Allow-Origin "*";
        add_header X-Content-Type-Options "nosniff";
    }

    # AgentPin revocation document
    location = /.well-known/agent-identity-revocations.json {
        root /var/www/example.com;
        default_type application/json;
        add_header Cache-Control "public, max-age=300";
        add_header Access-Control-Allow-Origin "*";
        add_header X-Content-Type-Options "nosniff";
    }
}
```

### Apache Configuration

```apache
<VirtualHost *:443>
    ServerName example.com
    DocumentRoot /var/www/example.com

    SSLEngine on
    SSLCertificateFile /etc/ssl/certs/example.com.pem
    SSLCertificateKeyFile /etc/ssl/private/example.com.key

    # AgentPin discovery
    <Location "/.well-known/agent-identity.json">
        Header set Cache-Control "public, max-age=3600"
        Header set Content-Type "application/json"
        Header set Access-Control-Allow-Origin "*"
        Header set X-Content-Type-Options "nosniff"
    </Location>

    # AgentPin revocations
    <Location "/.well-known/agent-identity-revocations.json">
        Header set Cache-Control "public, max-age=300"
        Header set Content-Type "application/json"
        Header set Access-Control-Allow-Origin "*"
        Header set X-Content-Type-Options "nosniff"
    </Location>
</VirtualHost>
```

---

## Creating the Discovery Document

### Step 1: Generate Keys

```bash
agentpin keygen --domain example.com --kid example-2026-01 --output-dir ./keys
```

### Step 2: Build the Document

Create `agent-identity.json`:

```json
{
  "agentpin_version": "0.1",
  "entity": "example.com",
  "entity_type": "maker",
  "public_keys": [
    {
      "kid": "example-2026-01",
      "kty": "EC",
      "crv": "P-256",
      "x": "<from example-2026-01.public.jwk.json>",
      "y": "<from example-2026-01.public.jwk.json>",
      "use": "sig",
      "key_ops": ["verify"],
      "exp": "2027-02-15T00:00:00Z"
    }
  ],
  "agents": [
    {
      "agent_id": "urn:agentpin:example.com:my-agent",
      "name": "My Agent",
      "description": "Production AI agent for data analysis",
      "version": "1.0.0",
      "capabilities": ["read:data", "write:reports", "execute:analysis"],
      "credential_ttl_max": 3600,
      "status": "active"
    }
  ],
  "revocation_endpoint": "https://example.com/.well-known/agent-identity-revocations.json",
  "policy_url": "https://example.com/agent-policy",
  "max_delegation_depth": 2,
  "updated_at": "2026-02-15T00:00:00Z"
}
```

Or use the SDK:

```python
from agentpin import build_discovery_document, pem_to_jwk, generate_key_pair, generate_key_id
import json

private_key_pem, public_key_pem = generate_key_pair()
kid = generate_key_id(public_key_pem)
jwk = pem_to_jwk(public_key_pem, kid)

discovery = build_discovery_document(
    "example.com", "maker", [jwk],
    [{
        "agent_id": "urn:agentpin:example.com:my-agent",
        "name": "My Agent",
        "capabilities": ["read:data", "write:reports"],
        "status": "active",
    }],
    2,
)

with open("agent-identity.json", "w") as f:
    json.dump(discovery, f, indent=2)
```

### Step 3: Create Revocation Document

Create an empty revocation document:

```json
{
  "agentpin_version": "0.1",
  "entity": "example.com",
  "revoked_credentials": [],
  "revoked_agents": [],
  "revoked_keys": [],
  "updated_at": "2026-02-15T00:00:00Z"
}
```

### Step 4: Deploy

```bash
# Copy to web server
sudo cp agent-identity.json /var/www/example.com/.well-known/
sudo cp revocations.json /var/www/example.com/.well-known/agent-identity-revocations.json

# Verify it's accessible
curl -s https://example.com/.well-known/agent-identity.json | jq .
```

---

## Cache Headers

AgentPin specifies recommended cache durations:

| Document | Cache-Control | Rationale |
|----------|---------------|-----------|
| Discovery | `max-age=3600` (1 hour) | Keys don't change often |
| Discovery (during rotation) | `max-age=300` (5 min) | Faster propagation during key rotation |
| Revocation | `max-age=300` (5 min) | Revocations need faster propagation |

Verifiers MUST re-fetch the discovery document when encountering an unknown `kid` in a credential.

---

## HTTPS Requirements

- Discovery documents MUST be served over HTTPS with a valid TLS certificate
- HTTP redirects MUST NOT be followed (to prevent redirect-based attacks)
- The `entity` field in the discovery document MUST match the domain serving it

---

## Docker Deployment

```dockerfile
FROM rust:1.75-slim AS builder
WORKDIR /app
COPY . .
RUN cargo build --release -p agentpin-server

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/agentpin-server /usr/local/bin/
COPY agent-identity.json /data/
COPY revocations.json /data/

EXPOSE 8080
CMD ["agentpin-server", "--discovery", "/data/agent-identity.json", "--revocation", "/data/revocations.json", "--port", "8080"]
```

```bash
docker build -t agentpin-server .
docker run -p 8080:8080 agentpin-server
```

---

## Monitoring

### Health Check

```bash
curl -f http://localhost:8080/health
```

### Validation Script

```bash
#!/bin/bash
# validate-endpoints.sh — Verify AgentPin endpoints are serving correctly

DOMAIN="${1:-example.com}"

echo "Checking discovery document..."
DISCOVERY=$(curl -sf "https://$DOMAIN/.well-known/agent-identity.json")
if [ $? -ne 0 ]; then
    echo "FAIL: Cannot fetch discovery document"
    exit 1
fi

# Validate entity matches domain
ENTITY=$(echo "$DISCOVERY" | jq -r '.entity')
if [ "$ENTITY" != "$DOMAIN" ]; then
    echo "FAIL: entity '$ENTITY' doesn't match domain '$DOMAIN'"
    exit 1
fi

# Validate at least one public key
KEY_COUNT=$(echo "$DISCOVERY" | jq '.public_keys | length')
if [ "$KEY_COUNT" -lt 1 ]; then
    echo "FAIL: No public keys in discovery document"
    exit 1
fi

echo "OK: Discovery document valid ($KEY_COUNT keys, $(echo "$DISCOVERY" | jq '.agents | length') agents)"

echo "Checking revocation document..."
curl -sf "https://$DOMAIN/.well-known/agent-identity-revocations.json" > /dev/null
if [ $? -ne 0 ]; then
    echo "WARN: No revocation document (recommended but optional)"
else
    echo "OK: Revocation document accessible"
fi
```

---

## Key Rotation

When rotating keys:

1. Generate a new key pair
2. Add the new key to the discovery document's `public_keys` array (keep the old key)
3. Reduce cache TTL to 5 minutes during transition
4. Start issuing credentials with the new key
5. After the transition period, add the old key to the revocation document
6. Remove the old key from the discovery document
7. Restore normal cache TTL

```bash
# 1. Generate new key
agentpin keygen --domain example.com --kid example-2026-02 --output-dir ./keys

# 2. Update discovery document (add new key, keep old)
# Edit agent-identity.json

# 3-6. Issue new credentials, revoke old key, clean up
# ...

# 7. Verify rotation completed
curl -s https://example.com/.well-known/agent-identity.json | jq '.public_keys[].kid'
```
