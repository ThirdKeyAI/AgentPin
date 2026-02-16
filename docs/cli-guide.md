# AgentPin CLI Guide

The AgentPin CLI (`agentpin`) provides commands for key generation, credential issuance, credential verification, and serving discovery endpoints.

---

## Installation

Build from the Rust workspace:

```bash
# Install the CLI binary
cargo install --path crates/agentpin-cli

# Or build the full workspace
cargo build --workspace --release
```

The binary is at `target/release/agentpin`.

---

## Commands

### `agentpin keygen` — Generate Key Pair

Generate an ECDSA P-256 key pair for signing agent credentials.

```bash
agentpin keygen \
  --domain example.com \
  --kid example-2026-01 \
  --output-dir ./keys
```

**Options:**

| Flag | Required | Description |
|------|----------|-------------|
| `--domain` | Yes | Domain this key is associated with |
| `--kid` | Yes | Key identifier (used in JWT headers and discovery documents) |
| `--output-dir` | Yes | Directory to write key files |

**Output files:**

```
keys/
├── example-2026-01.private.pem      # ECDSA P-256 private key (keep secret!)
├── example-2026-01.public.pem       # Public key in PEM format
└── example-2026-01.public.jwk.json  # Public key in JWK format
```

The JWK file is ready to embed in your discovery document's `public_keys` array.

**Example JWK output:**

```json
{
  "kid": "example-2026-01",
  "kty": "EC",
  "crv": "P-256",
  "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
  "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
  "use": "sig",
  "key_ops": ["verify"]
}
```

---

### `agentpin issue` — Issue a Credential

Issue a signed JWT credential for an agent.

```bash
agentpin issue \
  --private-key ./keys/example-2026-01.private.pem \
  --kid example-2026-01 \
  --issuer example.com \
  --agent-id "urn:agentpin:example.com:scout" \
  --capabilities "read:data,write:reports" \
  --ttl 3600
```

**Options:**

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--private-key` | Yes | — | Path to PEM-encoded private key |
| `--kid` | Yes | — | Key identifier (must match a key in the discovery document) |
| `--issuer` | Yes | — | Issuer domain (e.g., `example.com`) |
| `--agent-id` | Yes | — | Agent identifier URN (e.g., `urn:agentpin:example.com:scout`) |
| `--capabilities` | Yes | — | Comma-separated capability list |
| `--audience` | No | — | Target audience domain |
| `--ttl` | No | `3600` | Credential lifetime in seconds |
| `--constraints` | No | — | JSON object of constraints |

**Output:**

The signed JWT is printed to stdout:

```
eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImV4YW1wbGUtMjAyNi0wMSJ9.eyJpc3M...
```

**Usage in scripts:**

```bash
# Store credential in a variable
CREDENTIAL=$(agentpin issue \
  --private-key ./keys/example-2026-01.private.pem \
  --kid example-2026-01 \
  --issuer example.com \
  --agent-id "urn:agentpin:example.com:scout" \
  --capabilities "read:data" \
  --ttl 3600)

# Pass to another agent via HTTP header
curl -H "Authorization: Bearer $CREDENTIAL" https://api.verifier.com/endpoint

# Or verify it immediately
agentpin verify --credential "$CREDENTIAL" --discovery ./agent-identity.json
```

---

### `agentpin verify` — Verify a Credential

Verify a signed JWT credential against a discovery document.

**Offline verification (recommended):**

```bash
agentpin verify \
  --credential <jwt> \
  --discovery ./agent-identity.json \
  --pin-store ./pins.json
```

**Online verification (fetches discovery from issuer domain):**

```bash
agentpin verify --credential <jwt>
```

**Options:**

| Flag | Required | Description |
|------|----------|-------------|
| `--credential` | Yes | The JWT credential to verify |
| `--discovery` | No | Path to local discovery document (offline mode) |
| `--revocation` | No | Path to local revocation document |
| `--pin-store` | No | Path to TOFU pin store file (created if missing) |
| `--audience` | No | Expected audience domain |
| `--bundle` | No | Path to trust bundle file |

**Output (JSON):**

```json
{
  "valid": true,
  "agent_id": "urn:agentpin:example.com:scout",
  "issuer": "example.com",
  "capabilities": ["read:data", "write:reports"],
  "key_pinning": "first_use",
  "delegation_chain_valid": true,
  "expires_at": "2026-02-15T13:00:00Z"
}
```

**Failure output:**

```json
{
  "valid": false,
  "error_code": "expired",
  "error_message": "Credential expired at 2026-02-15T12:00:00Z"
}
```

**Using with trust bundles:**

```bash
agentpin verify \
  --credential <jwt> \
  --bundle ./trust-bundle.json \
  --pin-store ./pins.json
```

---

### `agentpin-server` — Serve Discovery Endpoints

The `agentpin-server` binary serves `.well-known` discovery and revocation endpoints over HTTP.

```bash
agentpin-server \
  --discovery ./agent-identity.json \
  --revocation ./revocations.json \
  --port 8080
```

**Options:**

| Flag | Required | Default | Description |
|------|----------|---------|-------------|
| `--discovery` | Yes | — | Path to discovery document JSON |
| `--revocation` | No | — | Path to revocation document JSON |
| `--port` | No | `8080` | HTTP listening port |
| `--host` | No | `0.0.0.0` | Bind address |

**Endpoints served:**

| Path | Cache-Control | Description |
|------|---------------|-------------|
| `GET /.well-known/agent-identity.json` | `max-age=3600` | Discovery document |
| `GET /.well-known/agent-identity-revocations.json` | `max-age=300` | Revocation document |
| `GET /health` | — | Health check (returns `200 OK`) |

**Production deployment behind a reverse proxy:**

```nginx
# nginx configuration
server {
    listen 443 ssl;
    server_name example.com;

    location /.well-known/agent-identity.json {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        add_header Cache-Control "public, max-age=3600";
        add_header Content-Type "application/json";
    }

    location /.well-known/agent-identity-revocations.json {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        add_header Cache-Control "public, max-age=300";
        add_header Content-Type "application/json";
    }
}
```

---

## Common Workflows

### Generate Keys, Issue, and Verify

```bash
# 1. Generate keys
agentpin keygen --domain example.com --kid key-01 --output-dir ./keys

# 2. Issue a credential
JWT=$(agentpin issue \
  --private-key ./keys/key-01.private.pem \
  --kid key-01 \
  --issuer example.com \
  --agent-id "urn:agentpin:example.com:agent" \
  --capabilities "read:data" \
  --ttl 3600)

# 3. Verify offline with a discovery document
agentpin verify \
  --credential "$JWT" \
  --discovery ./agent-identity.json \
  --pin-store ./pins.json
```

### Rotate Keys

```bash
# 1. Generate new key
agentpin keygen --domain example.com --kid key-02 --output-dir ./keys

# 2. Add new key to discovery document (keep old key temporarily)
# Edit agent-identity.json to add key-02 to public_keys array

# 3. Issue new credentials with the new key
agentpin issue --private-key ./keys/key-02.private.pem --kid key-02 ...

# 4. After transition period, revoke old key
# Add key-01 to revocation document

# 5. Remove old key from discovery document
```

### Batch Verification

```bash
# Verify multiple credentials from a file
while IFS= read -r jwt; do
    result=$(agentpin verify --credential "$jwt" --discovery ./discovery.json --pin-store ./pins.json)
    echo "$jwt: $(echo "$result" | jq -r '.valid')"
done < credentials.txt
```
