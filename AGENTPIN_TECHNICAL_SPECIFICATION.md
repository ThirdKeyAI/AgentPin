# AgentPin Technical Specification

**Protocol Version:** 0.3.0
**Status:** Stable
**Author:** Jascha Wanger / [ThirdKey.ai](https://thirdkey.ai)
**Date:** 2026-05-14
**License:** MIT

> **What's new in 0.3.0 (additive, wire-compatible with 0.2):**
> §4.8.3 DNS TXT cross-verification at `_agentpin.{domain}` is now
> normative (not "Reserved"). §4.9 adds the optional `a2a_endpoint`
> field on `DiscoveryDocument`. New §4.10 specifies the **A2A AgentCard
> extension** (signed AgentCards published at
> `.well-known/agent-card.json`, AgentPin extension payload, sorted-key
> canonical signing input). New §4.11 specifies the `AllowedDomains`
> typed wrapper (empty-list = unrestricted; intersection semantics for
> cross-protocol scoping with SchemaPin v1.4
> `A2aVerificationContext`). §4.8 gains two new resolver entries
> (LocalAgentCardStore, A2aAgentCardResolver). The wire protocol
> version (`agentpin_version` field on documents) stays at `"0.1"` —
> all v0.3 additions are purely additive fields that v0.2 callers
> ignore.

---

## Table of Contents

- [1. Introduction](#1-introduction)
  - [1.1 Problem Statement](#11-problem-statement)
  - [1.2 Goals](#12-goals)
  - [1.3 Non-Goals](#13-non-goals)
  - [1.4 Relationship to SchemaPin and Symbiont](#14-relationship-to-schemapin-and-symbiont)
- [2. Terminology](#2-terminology)
- [3. Protocol Overview](#3-protocol-overview)
  - [3.1 Trust Model](#31-trust-model)
  - [3.2 Entity Roles](#32-entity-roles)
  - [3.3 Delegation Chain](#33-delegation-chain)
  - [3.4 Protocol Flow Summary](#34-protocol-flow-summary)
- [4. Discovery Document](#4-discovery-document)
  - [4.1 Endpoint](#41-endpoint)
  - [4.2 Schema Definition](#42-schema-definition)
  - [4.3 Field Specifications](#43-field-specifications)
  - [4.4 Public Key Format](#44-public-key-format)
  - [4.5 Agent Declaration Format](#45-agent-declaration-format)
  - [4.6 Caching and Freshness](#46-caching-and-freshness)
  - [4.7 Example Discovery Document](#47-example-discovery-document)
  - [4.8 Alternative Discovery Mechanisms](#48-alternative-discovery-mechanisms)
  - [4.9 Cross-Protocol Endpoint Fields (v0.3)](#49-cross-protocol-endpoint-fields-v03)
  - [4.10 A2A AgentCard Extension (v0.3)](#410-a2a-agentcard-extension-v03)
  - [4.11 AllowedDomains Typed Wrapper (v0.3)](#411-alloweddomains-typed-wrapper-v03)
- [5. Agent Credentials](#5-agent-credentials)
  - [5.1 Credential Format](#51-credential-format)
  - [5.2 JWT Header](#52-jwt-header)
  - [5.3 JWT Payload](#53-jwt-payload)
  - [5.4 Capability Claims](#54-capability-claims)
  - [5.5 Constraint Claims](#55-constraint-claims)
  - [5.6 Delegation Chain Claims](#56-delegation-chain-claims)
  - [5.7 Credential Lifetime](#57-credential-lifetime)
  - [5.8 Example Credential](#58-example-credential)
- [6. Verification Protocol](#6-verification-protocol)
  - [6.1 Verification Flow](#61-verification-flow)
  - [6.2 Discovery Document Retrieval](#62-discovery-document-retrieval)
  - [6.3 Signature Verification](#63-signature-verification)
  - [6.4 Delegation Chain Verification](#64-delegation-chain-verification)
  - [6.5 Capability Validation](#65-capability-validation)
  - [6.6 Constraint Enforcement](#66-constraint-enforcement)
  - [6.7 Verification Result](#67-verification-result)
- [7. Key Management](#7-key-management)
  - [7.1 Key Generation](#71-key-generation)
  - [7.2 Key Rotation](#72-key-rotation)
  - [7.3 Key Pinning (TOFU)](#73-key-pinning-tofu)
  - [7.4 Key Pinning Storage](#74-key-pinning-storage)
- [8. Revocation](#8-revocation)
  - [8.1 Revocation Endpoint](#81-revocation-endpoint)
  - [8.2 Revocation Document Schema](#82-revocation-document-schema)
  - [8.3 Revocation Checking](#83-revocation-checking)
  - [8.4 Emergency Revocation](#84-emergency-revocation)
- [9. Mutual Verification](#9-mutual-verification)
  - [9.1 Challenge-Response Protocol](#91-challenge-response-protocol)
  - [9.2 Nonce Requirements](#92-nonce-requirements)
  - [9.3 Mutual Verification Flow](#93-mutual-verification-flow)
- [10. Capability Taxonomy](#10-capability-taxonomy)
  - [10.1 Core Capabilities](#101-core-capabilities)
  - [10.2 Capability Scoping](#102-capability-scoping)
  - [10.3 Capability Inheritance](#103-capability-inheritance)
  - [10.4 Custom Capabilities](#104-custom-capabilities)
- [11. Integration with SchemaPin](#11-integration-with-schemapin)
  - [11.1 Shared Cryptographic Infrastructure](#111-shared-cryptographic-infrastructure)
  - [11.2 Unified Discovery](#112-unified-discovery)
  - [11.3 Bidirectional Trust Model](#113-bidirectional-trust-model)
  - [11.4 Combined Verification Flow](#114-combined-verification-flow)
- [12. Integration with Symbiont](#12-integration-with-symbiont)
  - [12.1 Policy Engine Integration](#121-policy-engine-integration)
  - [12.2 Audit Trail Integration](#122-audit-trail-integration)
  - [12.3 Runtime Enforcement](#123-runtime-enforcement)
- [13. Transport and Binding](#13-transport-and-binding)
  - [13.1 HTTP Header Binding](#131-http-header-binding)
  - [13.2 MCP Transport Binding](#132-mcp-transport-binding)
  - [13.3 WebSocket Binding](#133-websocket-binding)
  - [13.4 gRPC Binding](#134-grpc-binding)
- [14. Security Considerations](#14-security-considerations)
  - [14.1 Threat Model](#141-threat-model)
  - [14.2 Domain Compromise](#142-domain-compromise)
  - [14.3 Replay Attacks](#143-replay-attacks)
  - [14.4 Capability Confusion](#144-capability-confusion)
  - [14.5 Prompt Injection and Behavioral Integrity](#145-prompt-injection-and-behavioral-integrity)
  - [14.6 Denial of Service](#146-denial-of-service)
  - [14.7 Cryptographic Agility](#147-cryptographic-agility)
- [15. Privacy Considerations](#15-privacy-considerations)
- [16. IANA Considerations](#16-iana-considerations)
- [17. Conformance Requirements](#17-conformance-requirements)
- [18. Future Work](#18-future-work)
- [Appendix A: JSON Schema Definitions](#appendix-a-json-schema-definitions)
- [Appendix B: Example Implementations](#appendix-b-example-implementations)
- [Appendix C: Relationship to Existing Standards](#appendix-c-relationship-to-existing-standards)

---

## 1. Introduction

### 1.1 Problem Statement

As autonomous AI agents proliferate and begin interacting with each other, with services, and with humans on behalf of their operators, there exists no standardized mechanism for an agent to cryptographically prove its identity. Current agent interactions rely on self-asserted identity — an agent claims to be "Scout v2 from Tarnover LLC" with no way for the receiving party to verify that claim.

This creates several critical attack vectors:

- **Agent Impersonation:** A malicious agent claims to be a trusted agent to gain access to sensitive tools or data.
- **Unauthorized Delegation:** An agent claims authorization from an operator who never granted it.
- **Phantom Agents:** Agents operate with no verifiable provenance, making incident response and forensics impossible.
- **Capability Inflation:** An agent claims capabilities or permissions beyond what its maker or deployer authorized.

These problems are analogous to the pre-TLS web, where any server could claim to be any domain. AgentPin solves this the same way TLS/PKI solved it for the web: by anchoring trust to domain ownership via cryptographic verification, using established infrastructure (DNS, HTTPS, `.well-known` URIs) rather than introducing new centralized registries or blockchain dependencies.

### 1.2 Goals

1. **Domain-anchored agent identity.** Any entity controlling a domain can publish verifiable agent identities, using existing DNS and HTTPS infrastructure as the trust anchor.

2. **Maker-Deployer delegation.** Support a two-layer trust model where agent software makers and agent instance deployers are independently verifiable, enabling delegation chains.

3. **Capability-scoped credentials.** Agent credentials declare specific capabilities, allowing verifiers to enforce least-privilege access.

4. **Interoperability with SchemaPin.** Share cryptographic primitives, discovery patterns, and key management with the SchemaPin protocol to provide a unified trust stack for agentic AI.

5. **Runtime enforcement via Symbiont.** Provide the identity layer that Symbiont's zero-trust policy engine can consume for cryptographically-backed access control.

6. **Practical adoption path.** Minimize barriers to adoption by using existing standards (JWT, RFC 8615, JWK) and avoiding dependencies on novel infrastructure.

### 1.3 Non-Goals

1. **Behavioral verification.** AgentPin verifies *who* an agent is and *what it's authorized to do*, not *how it behaves*. A verified agent may still be manipulated via prompt injection; behavioral integrity is orthogonal to identity.

2. **Centralized registry.** AgentPin intentionally avoids requiring a central authority or registry. Trust is anchored to domain ownership.

3. **Blockchain or DID dependency.** While the protocol can coexist with W3C DIDs, it does not require them. Domain-based discovery is the primary mechanism.

4. **Human identity.** AgentPin identifies agents and their organizational affiliations, not individual human users.

5. **Encryption or confidentiality.** AgentPin provides authentication and integrity. Transport-layer encryption (TLS) is assumed but out of scope.

### 1.4 Relationship to SchemaPin and Symbiont

AgentPin is the second layer in the ThirdKey trust stack:

| Layer | Protocol | Question Answered |
|-------|----------|-------------------|
| Tool Integrity | **SchemaPin** | "Are the tools this agent uses legitimate and untampered?" |
| Agent Identity | **AgentPin** | "Is this agent legitimate and authorized to act?" |
| Runtime Enforcement | **Symbiont** | "Does policy allow this verified agent to perform this action?" |

SchemaPin verifies *what* (tools); AgentPin verifies *who* (agents); Symbiont enforces *whether* (policy). Together they form a complete, cryptographic chain of trust for autonomous AI agent operations.

---

## 2. Terminology

| Term | Definition |
|------|------------|
| **Agent** | An autonomous AI software system that acts on behalf of an entity, interacting with other agents, tools, services, or humans. |
| **Maker** | The organization or individual that develops and publishes agent software. Identified by a domain (e.g., `anthropic.com`). |
| **Deployer** | The organization or individual that operates a specific agent instance, authorizing it to act on their behalf. Identified by a domain (e.g., `tarnover.com`). |
| **Verifier** | Any party that receives an agent credential and validates it. May be another agent, a tool/service, or a gateway. |
| **Agent Credential** | A signed JWT asserting an agent's identity, capabilities, and delegation chain. |
| **Discovery Document** | A JSON document hosted at `/.well-known/agent-identity.json` containing an entity's public keys and agent declarations. |
| **Delegation Chain** | An ordered list of cryptographic attestations linking a Deployer's agent instance back to the Maker's agent software. |
| **Capability** | A scoped permission declared in an agent credential, describing what the agent is authorized to do. |
| **Constraint** | A restriction on an agent credential, limiting where, when, or how the agent may operate. |
| **TOFU** | Trust On First Use. A key pinning strategy where the first observed key for a domain is pinned and subsequent key changes require explicit approval. |
| **Trust Anchor** | The root of a verification chain. In AgentPin, the trust anchor is domain ownership verified via HTTPS. |

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119).

---

## 3. Protocol Overview

### 3.1 Trust Model

AgentPin uses a **domain-anchored trust model**. Trust is rooted in domain ownership, verified through the existing HTTPS/PKI infrastructure:

1. An entity controls a domain (e.g., `tarnover.com`).
2. The entity publishes a discovery document at `https://tarnover.com/.well-known/agent-identity.json`.
3. The discovery document contains public keys and agent declarations.
4. Agent credentials are signed with the corresponding private keys.
5. Verifiers fetch the discovery document over HTTPS and validate signatures.

This model inherits the security properties of the web PKI: domain control is verified by certificate authorities, and HTTPS ensures the discovery document is authentic and untampered during transit.

### 3.2 Entity Roles

AgentPin recognizes two entity roles that participate in credential issuance:

**Maker** — The creator of agent software. A Maker's discovery document declares agent *types* (software definitions) and the public keys used to sign attestations about those agent types. A Maker MAY also be a Deployer of their own agents.

**Deployer** — The operator of agent instances. A Deployer's discovery document declares specific agent *instances* authorized to act on the Deployer's behalf, references the Maker's agent type, and includes the Deployer's own public keys.

```
Maker (anthropic.com)                  Deployer (tarnover.com)
┌──────────────────────┐              ┌───────────────────────────┐
│ Discovery Document   │              │ Discovery Document        │
│                      │              │                           │
│ agent_type:          │  referenced  │ agent_instance:           │
│   "claude-agent"     │◄─────────── │   type: "claude-agent"    │
│                      │   by         │   maker: "anthropic.com"  │
│ public_key:          │              │   deployer: "tarnover.com"│
│   maker-key-01       │              │                           │
│                      │              │ public_key:               │
│                      │              │   deployer-key-01         │
└──────────────────────┘              └───────────────────────────┘
```

### 3.3 Delegation Chain

A delegation chain links an agent instance back to its origins through cryptographic signatures:

1. **Maker attestation:** The Maker signs a statement: "Agent type X exists and has these baseline capabilities."
2. **Deployer attestation:** The Deployer signs a statement: "I authorize instance Y of agent type X with these specific capabilities (which MUST be a subset of the Maker's baseline)."

A verifier can walk the chain to confirm both the software provenance (Maker) and the operational authorization (Deployer).

**Maximum delegation depth:** The protocol supports a maximum delegation depth of 3 (Maker → Deployer → Sub-deployer). Each entity in the chain MUST declare `max_delegation_depth` in their discovery document. An entity MUST NOT issue credentials with a delegation depth exceeding the minimum `max_delegation_depth` declared by any entity in its chain.

### 3.4 Protocol Flow Summary

```
┌──────────┐                           ┌──────────┐
│ Agent A  │                           │ Agent B  │
│(Prover)  │                           │(Verifier)│
└────┬─────┘                           └────┬─────┘
     │                                      │
     │  1. Present Credential (JWT)         │
     │─────────────────────────────────────>│
     │                                      │
     │                    2. Extract `iss` claim (domain)
     │                                      │
     │                    3. Fetch /.well-known/agent-identity.json
     │                       from issuer domain over HTTPS
     │                                      │
     │                    4. Resolve `kid` → public key
     │                                      │
     │                    5. Verify JWT signature
     │                                      │
     │                    6. Check revocation endpoint
     │                                      │
     │                    7. Validate capabilities against
     │                       discovery document declarations
     │                                      │
     │                    8. (Optional) Walk delegation chain:
     │                       fetch each domain's discovery doc,
     │                       verify each attestation signature
     │                                      │
     │                    9. Apply TOFU key pinning
     │                                      │
     │                   10. Return verification result
     │                                      │
     │  11. (If mutual) Challenge-Response  │
     │<────────────────────────────────────>│
     │                                      │
```

---

## 4. Discovery Document

### 4.1 Endpoint

The discovery document MUST be served at:

```
https://{domain}/.well-known/agent-identity.json
```

This follows [RFC 8615](https://www.rfc-editor.org/rfc/rfc8615) (Well-Known URIs). The document MUST be served over HTTPS with a valid TLS certificate. HTTP redirects MUST NOT be followed (to prevent redirect-based attacks).

### 4.2 Schema Definition

The discovery document is a JSON object with the following top-level structure:

```json
{
  "agentpin_version": "0.1",
  "entity": "<domain>",
  "entity_type": "<maker|deployer|both>",
  "public_keys": [ ... ],
  "agents": [ ... ],
  "revocation_endpoint": "<URL>",
  "policy_url": "<URL>",
  "schemapin_endpoint": "<URL>",
  "a2a_endpoint": "<URL>",
  "max_delegation_depth": <integer>,
  "updated_at": "<ISO 8601 datetime>"
}
```

> The `a2a_endpoint` field is new in v0.3 and OPTIONAL — see §4.9. Documents
> emitted by v0.2 implementations omit it; v0.3 verifiers MUST NOT require it.

### 4.3 Field Specifications

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agentpin_version` | string | REQUIRED | Protocol version. MUST be `"0.1"` for this specification. |
| `entity` | string | REQUIRED | The domain serving this document. MUST match the domain in the URL. |
| `entity_type` | string | REQUIRED | One of `"maker"`, `"deployer"`, or `"both"`. Indicates the entity's role(s). |
| `public_keys` | array | REQUIRED | Array of JWK objects (see §4.4). MUST contain at least one key. |
| `agents` | array | REQUIRED | Array of agent declarations (see §4.5). MAY be empty. |
| `revocation_endpoint` | string | RECOMMENDED | URL of the revocation document (see §8). |
| `policy_url` | string | OPTIONAL | URL of a human-readable policy document describing the entity's agent governance. |
| `schemapin_endpoint` | string | OPTIONAL | URL of the entity's SchemaPin discovery document, if any. Enables cross-protocol discovery. |
| `a2a_endpoint` | string | OPTIONAL | (v0.3) URL of the entity's A2A AgentCard endpoint (typically `https://{domain}/.well-known/agent-card.json`). Enables cross-protocol discovery from AgentPin into A2A. See §4.9, §4.10. |
| `max_delegation_depth` | integer | REQUIRED | Maximum delegation depth this entity permits. MUST be between 0 and 3 inclusive. |
| `updated_at` | string | REQUIRED | ISO 8601 datetime of the last update to this document. |

### 4.4 Public Key Format

Public keys are represented as JWK (JSON Web Key) objects per [RFC 7517](https://www.rfc-editor.org/rfc/rfc7517):

```json
{
  "kid": "<unique key identifier>",
  "kty": "EC",
  "crv": "P-256",
  "x": "<base64url-encoded x coordinate>",
  "y": "<base64url-encoded y coordinate>",
  "use": "sig",
  "key_ops": ["verify"],
  "exp": "<ISO 8601 expiration datetime>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `kid` | string | REQUIRED | Unique key identifier. SHOULD be formatted as `{domain}-{YYYY}-{sequence}` (e.g., `tarnover-2026-01`). |
| `kty` | string | REQUIRED | Key type. MUST be `"EC"` for this version. |
| `crv` | string | REQUIRED | Curve. MUST be `"P-256"` for this version. |
| `x` | string | REQUIRED | Base64url-encoded x-coordinate of the EC public key. |
| `y` | string | REQUIRED | Base64url-encoded y-coordinate of the EC public key. |
| `use` | string | REQUIRED | Key usage. MUST be `"sig"`. |
| `key_ops` | array | RECOMMENDED | Permitted operations. SHOULD be `["verify"]`. |
| `exp` | string | RECOMMENDED | Key expiration datetime in ISO 8601 format. |

**Cryptographic algorithm choice:** AgentPin v0.1 mandates ECDSA with P-256 (secp256r1), matching SchemaPin's cryptographic choices for interoperability. Future versions MAY support Ed25519 (EdDSA) as an additional option (see §14.7).

### 4.5 Agent Declaration Format

Each entry in the `agents` array declares an agent type (for Makers) or agent instance (for Deployers):

```json
{
  "agent_id": "urn:agentpin:{domain}:{agent-name}",
  "agent_type": "urn:agentpin:{maker-domain}:{agent-type-name}",
  "name": "<human-readable name>",
  "description": "<human-readable description>",
  "version": "<semver>",
  "capabilities": [ ... ],
  "constraints": { ... },
  "maker_attestation": "<base64url-encoded signature>",
  "credential_ttl_max": <integer>,
  "status": "<active|suspended|deprecated>",
  "directory_listing": <boolean>
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agent_id` | string | REQUIRED | Unique agent identifier as a URN. Format: `urn:agentpin:{domain}:{name}`. |
| `agent_type` | string | Deployer REQUIRED | For Deployers: references the Maker's agent type URN. For Makers: omitted (the `agent_id` itself defines the type). |
| `name` | string | REQUIRED | Human-readable agent name. Max 128 characters. |
| `description` | string | RECOMMENDED | Human-readable description. Max 1024 characters. |
| `version` | string | RECOMMENDED | Semantic version of the agent. |
| `capabilities` | array | REQUIRED | Array of capability strings (see §10). |
| `constraints` | object | OPTIONAL | Default constraints for credentials issued for this agent (see §5.5). |
| `maker_attestation` | string | Deployer REQUIRED | For Deployers: a base64url-encoded signature from the Maker over the canonical form of this agent declaration, proving the Maker authorized this deployment. For Makers: omitted. |
| `credential_ttl_max` | integer | RECOMMENDED | Maximum allowed credential lifetime in seconds. Default: 86400 (24 hours). |
| `status` | string | REQUIRED | One of `"active"`, `"suspended"`, `"deprecated"`. Verifiers MUST reject credentials for non-active agents. |
| `directory_listing` | boolean | OPTIONAL | When `false`, signals that this agent SHOULD NOT be included in public agent directories or registries. Analogous to `noindex` for search engines. Defaults to `true` if omitted. See §15. |

### 4.6 Caching and Freshness

Discovery documents SHOULD be served with appropriate HTTP cache headers:

- `Cache-Control: max-age=3600` (1 hour) is RECOMMENDED for normal operation.
- `Cache-Control: max-age=300` (5 minutes) is RECOMMENDED during key rotation.
- The `updated_at` field provides application-layer freshness indication.
- Verifiers SHOULD re-fetch the discovery document if their cached copy is older than `max-age`.
- Verifiers MUST re-fetch the discovery document when encountering an unknown `kid` in a credential.
- Verifiers MUST always check the revocation endpoint regardless of discovery document cache state.

### 4.7 Example Discovery Document

**Maker example (anthropic.com):**

```json
{
  "agentpin_version": "0.1",
  "entity": "anthropic.com",
  "entity_type": "maker",
  "public_keys": [
    {
      "kid": "anthropic-2026-01",
      "kty": "EC",
      "crv": "P-256",
      "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
      "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
      "use": "sig",
      "key_ops": ["verify"],
      "exp": "2027-01-01T00:00:00Z"
    }
  ],
  "agents": [
    {
      "agent_id": "urn:agentpin:anthropic.com:claude-agent-v4",
      "name": "Claude Agent Runtime v4",
      "description": "Claude-based autonomous agent runtime",
      "version": "4.0.0",
      "capabilities": [
        "read:*",
        "write:text",
        "execute:code",
        "delegate:agent"
      ],
      "credential_ttl_max": 86400,
      "status": "active"
    }
  ],
  "revocation_endpoint": "https://anthropic.com/.well-known/agent-identity-revocations.json",
  "policy_url": "https://anthropic.com/agent-policy",
  "schemapin_endpoint": "https://anthropic.com/.well-known/schemapin.json",
  "max_delegation_depth": 2,
  "updated_at": "2026-01-15T00:00:00Z"
}
```

**Deployer example (tarnover.com):**

```json
{
  "agentpin_version": "0.1",
  "entity": "tarnover.com",
  "entity_type": "deployer",
  "public_keys": [
    {
      "kid": "tarnover-2026-01",
      "kty": "EC",
      "crv": "P-256",
      "x": "a1b2c3d4e5f6...",
      "y": "g7h8i9j0k1l2...",
      "use": "sig",
      "key_ops": ["verify"],
      "exp": "2027-06-01T00:00:00Z"
    }
  ],
  "agents": [
    {
      "agent_id": "urn:agentpin:tarnover.com:scout-v2",
      "agent_type": "urn:agentpin:anthropic.com:claude-agent-v4",
      "name": "Scout Security Analyzer",
      "description": "Automated security assessment agent operated by Tarnover LLC",
      "version": "2.1.0",
      "capabilities": [
        "read:public-api",
        "read:codebase",
        "write:report"
      ],
      "constraints": {
        "allowed_domains": ["*.client-corp.com", "tarnover.com"],
        "rate_limit": "100/hour",
        "data_classification_max": "confidential"
      },
      "maker_attestation": "MEUCIQD7y2F8...<base64url signature>...",
      "credential_ttl_max": 3600,
      "status": "active",
      "directory_listing": false
    }
  ],
  "revocation_endpoint": "https://tarnover.com/.well-known/agent-identity-revocations.json",
  "policy_url": "https://tarnover.com/agent-policy",
  "schemapin_endpoint": "https://tarnover.com/.well-known/schemapin.json",
  "max_delegation_depth": 1,
  "updated_at": "2026-01-30T12:00:00Z"
}
```

### 4.8 Alternative Discovery Mechanisms

The standard `.well-known` HTTPS endpoint (§4.1) is the REQUIRED baseline discovery mechanism. Implementations MAY support additional discovery mechanisms for environments where `.well-known` is unavailable or impractical. When using alternative mechanisms, the discovery document format (§4.2–4.5), credential format (§5), and verification flow (§6) remain identical — only the document retrieval step changes.

#### 4.8.1 Local File Discovery

Discovery documents are read from a local filesystem directory, with files named `{domain}.json`. Revocation documents, when present, are named `{domain}.revocations.json` in the same directory or a separate revocation directory.

**Use cases:** Air-gapped networks, CI/CD pipelines, development environments, embedded deployments.

**Requirements:**
- File contents MUST conform to the discovery document schema (§4.2).
- Verifiers MUST validate the document identically to a `.well-known`-fetched document.
- File permissions SHOULD restrict read access to authorized processes.

#### 4.8.2 Pre-Shared Trust Bundle

A trust bundle is a JSON file containing a collection of discovery and revocation documents, distributed out-of-band. The bundle format is:

```json
{
  "agentpin_bundle_version": "0.1",
  "created_at": "2026-02-10T00:00:00Z",
  "documents": [
    { /* DiscoveryDocument */ },
    { /* DiscoveryDocument */ }
  ],
  "revocations": [
    { /* RevocationDocument */ },
    { /* RevocationDocument */ }
  ]
}
```

**Use cases:** Enterprise-internal agents, pre-provisioned trust relationships, air-gapped environments, runtime identity bootstrapping.

**Requirements:**
- Each document within the bundle MUST independently conform to its respective schema.
- Bundles SHOULD be signed or distributed over authenticated channels.
- Verifiers MUST validate documents from bundles identically to `.well-known`-fetched documents.
- The `created_at` timestamp indicates bundle generation time; verifiers MAY use it to enforce freshness policies.

#### 4.8.3 DNS TXT Cross-Verification (v0.3)

A publisher MAY publish a TXT record at `_agentpin.{domain}` containing a fingerprint of one of the public keys advertised in their `.well-known` discovery document. Verifiers MAY consult this record as a *second-channel* trust signal — DNS is administered through a separate credential chain (registrar account, DNS provider, optionally DNSSEC) from the HTTPS hosting account, so compromising one channel does not automatically compromise the other.

**Wire format.** The TXT record value is a `;`-separated list of `key=value` pairs:

```text
_agentpin.example.com.  3600  IN  TXT  "v=agentpin1; kid=example-2026-05; fp=sha256:bae50bde68f47eba0e5d61ecd59db073ffe742eec94aeac0d2d26f27c155036a"
```

Fields:

| Field | Required | Description |
|-------|----------|-------------|
| `v`   | REQUIRED | Wire-format version. MUST be `"agentpin1"` for this specification. |
| `fp`  | REQUIRED | Lowercase fingerprint, formatted as `sha256:<hex>`. The hex value is the RFC 7638 JWK thumbprint of one of the discovery document's `public_keys` entries. |
| `kid` | OPTIONAL | Key identifier of the discovery key the `fp` is computed over. When present, the matching key MUST also carry this `kid`. |

Parsers MUST:

- Tolerate whitespace around `;` and `=`.
- Treat field order as unsignificant.
- Lowercase the `fp` value before comparison (the prefix `sha256:` is also case-insensitive on input).
- Ignore unknown fields for forward compatibility.

Parsers MUST reject the record when:

- The `v` or `fp` field is missing.
- `v` is any value other than `"agentpin1"` (in particular: SchemaPin's `_schemapin.{domain}` records, which use `v=schemapin1`, MUST NOT be accepted by the AgentPin parser).
- `fp` does not begin with `sha256:`.
- A field has no `=` separator.

**Verifier semantics.** A verifier that observes a TXT record at `_agentpin.{domain}` MUST:

1. Parse the record per the rules above.
2. Compute the RFC 7638 thumbprint of each key in the discovery document's `public_keys` and compare against the TXT `fp` (case-insensitive). When the TXT carries a `kid`, only the discovery key with the matching `kid` is eligible.
3. Treat the discovery document as trustworthy on this channel only if *at least one* discovery key matches.

The semantics MUST be:

- **Absent record** — no effect; DNS TXT is purely additive. Verifiers MUST NOT fail verification merely because no `_agentpin` TXT record exists.
- **Present and matching** — second-channel confirmation succeeded.
- **Present and mismatching** — **hard failure** (`DISCOVERY_INVALID`). A publisher who intentionally published a TXT record has signaled that DNS is part of their trust chain; divergence between DNS and `.well-known` indicates one channel is compromised, and the verifier cannot tell which is authentic.
- **Present and malformed** — hard failure (`DISCOVERY_INVALID`).

**Multi-key match.** AgentPin discovery documents MAY carry several keys for rotation (see §7.2). A published TXT record need only match *one* of them; verifiers MUST iterate the full `public_keys` list before declaring a mismatch.

**Threat coverage.** DNS TXT defends against:

- A compromised hosting account / expired domain not removed from a CDN.
- ACME ownership-validation bypass that mints a TLS cert for the attacker.
- TLS certificate mis-issuance by a CA the attacker controls.

It does NOT defend against attackers who control the DNS chain itself (registrar account, DNS provider, or a downstream resolver). Publishers concerned about DNS-level compromise SHOULD pair this mechanism with DNSSEC.

**Interaction with the rest of verification.** DNS TXT cross-verification is independent of the 12-step credential verification flow (§6.1). Verifiers MAY perform DNS TXT verification opportunistically at discovery-document-retrieval time (§6.2), or skip it entirely. When performed, a TXT mismatch MUST short-circuit the rest of the flow with `DISCOVERY_INVALID`.

#### 4.8.4 LocalAgentCardStore (v0.3)

In-memory store of pre-registered A2A AgentCards keyed by their AgentPin discovery domain. For agents that do not serve HTTP themselves (CLI tools, daemon processes, externally-registered agents pushed into a coordinator at registration time), a coordinator can keep their AgentCards in memory and resolve them via the standard `DiscoveryResolver` interface without making any network calls.

**Use cases:** Symbiont's push-based external-agent registration flow, where a coordinator receives the AgentCard JSON inline; ephemeral runtime agents that exist only for the lifetime of an orchestration plan.

**Requirements:**

- The store MUST verify the AgentPin extension signature on each card at registration time (see §4.10).
- The store MUST derive a `DiscoveryDocument` from the registered card so the rest of the AgentPin verification stack (TOFU pinning, capability validation) runs unchanged.
- Re-registering an existing domain MUST replace the prior entry (supports key rotation on long-lived coordinators).

#### 4.8.5 A2aAgentCardResolver (v0.3)

HTTPS resolver that fetches `https://{domain}/.well-known/agent-card.json`, verifies the AgentPin extension on the returned card, cross-checks that the embedded `agentpin_endpoint` host matches the fetched domain, and derives a `DiscoveryDocument` from the card. See §4.10 for the AgentCard extension format.

**Requirements:**

- The resolver MUST follow HTTPS only; redirects MUST be rejected (same rule as the standard `.well-known` resolver in §6.2).
- The resolver MUST verify the AgentPin extension before trusting any field on the card.
- The resolver MUST reject a card whose `agentpin_endpoint` URL host does not equal the fetched domain — this defends against a card that legitimately exists at one domain being served from another.

#### 4.8.6 Internal CA / Trust Delegation (Future)

*Reserved for future specification.* An internal certificate authority model where a root organization signs discovery documents for subsidiary entities, enabling hierarchical trust without requiring each entity to serve its own `.well-known` endpoint.

#### 4.8.7 Resolver Chain

A resolver chain tries multiple discovery mechanisms in priority order until one succeeds. The recommended enterprise pattern is:

1. **Trust bundle** — Check pre-loaded bundle first (fastest, no I/O).
2. **Local file** — Check filesystem directory (fast, no network).
3. **LocalAgentCardStore** — (v0.3) Check the in-memory store of push-registered AgentCards (§4.8.4).
4. **A2aAgentCardResolver** — (v0.3) Try `https://{domain}/.well-known/agent-card.json` (§4.8.5).
5. **`.well-known` HTTPS** — Fall back to standard `agent-identity.json` discovery.

The chain stops at the first resolver that successfully returns a document. If all resolvers fail, verification fails with `DISCOVERY_FETCH_FAILED`.

**Requirements:**
- Chain order MUST be deterministic and configurable.
- A document returned by any resolver in the chain MUST be validated identically.
- Revocation documents SHOULD be resolved from the same source as the discovery document when possible.

### 4.9 Cross-Protocol Endpoint Fields (v0.3)

Two OPTIONAL fields on `DiscoveryDocument` advertise neighbouring trust-stack endpoints, enabling cross-protocol resolution from AgentPin into the other layers:

| Field | Type | Purpose |
|-------|------|---------|
| `schemapin_endpoint` | URL | The entity's SchemaPin discovery document (`/.well-known/schemapin-discovery.json`). A verifier processing an AgentPin credential MAY follow this link to fetch the tool-integrity catalogue for the same domain. |
| `a2a_endpoint`       | URL | The entity's A2A AgentCard (typically `/.well-known/agent-card.json`). A verifier that already trusts the AgentPin discovery document MAY use this link to fetch the corresponding signed A2A AgentCard for the same entity (§4.10). |

Both fields are advisory. A verifier MAY decline to follow them, and a producer MAY omit them. Implementations MUST treat absence as "no advertised endpoint" and MUST NOT synthesize default URLs.

When `a2a_endpoint` is present, verifiers SHOULD cross-check that its host equals the discovery document's `entity` field (modulo trailing-dot normalisation); a mismatch indicates a misconfigured publisher and MAY be treated as `DISCOVERY_INVALID`.

### 4.10 A2A AgentCard Extension (v0.3)

AgentPin extends the [Google A2A](https://github.com/google-a2a/A2A) AgentCard format with a cryptographic-identity payload, allowing an AgentCard discovered through the A2A protocol to be verified against the AgentPin trust chain (TOFU pinning, revocation, capability narrowing) without an additional round-trip to the publisher's `.well-known/agent-identity.json`.

#### 4.10.1 AgentCard Subset

AgentPin defines a *minimal subset* of the upstream A2A AgentCard shape that it populates and consumes. The full upstream AgentCard MAY carry additional fields; AgentPin implementations MUST preserve any unknown fields verbatim through serialize/deserialize round-trips so that subsequent A2A consumers see the full card.

The AgentPin-relevant fields are:

```json
{
  "name": "<human-readable agent name>",
  "description": "<optional description>",
  "version": "<optional semver>",
  "url": "<public URL where the agent receives A2A traffic>",
  "capabilities": {
    "streaming": <boolean>,
    "pushNotifications": <boolean>,
    "allowed_domains": [ "<domain>", ... ]
  },
  "skills": [
    { "id": "<capability string>", "name": "<display name>", "description": "<optional>" },
    ...
  ],
  "agentpin": {
    "agentpin_endpoint": "<URL of the entity's AgentPin discovery document>",
    "public_key_jwk": { /* RFC 7517 JWK, identical shape to §4.4 */ },
    "signature": "<base64-encoded DER ECDSA P-256 signature>"
  }
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | REQUIRED | Display name for the agent. Mapped from `AgentDeclaration.name` (§4.5). |
| `description` | string | OPTIONAL | Description for the agent. Mapped from `AgentDeclaration.description`. |
| `version` | string | OPTIONAL | Agent semver. Mapped from `AgentDeclaration.version`. |
| `url` | string | REQUIRED | Public URL at which the agent receives A2A traffic. This is the *A2A endpoint*, not the AgentPin discovery endpoint. |
| `capabilities.streaming` | boolean | REQUIRED | Whether the agent supports streaming responses. |
| `capabilities.pushNotifications` | boolean | REQUIRED | Whether the agent emits push notifications. Note: camelCase per upstream A2A convention. |
| `capabilities.allowed_domains` | array | OPTIONAL | (AgentPin extension) Domains this agent is permitted to interact with. Omitted when unrestricted (see §4.11). |
| `skills` | array | REQUIRED | A2A skills, one per `AgentDeclaration.capabilities` entry. The skill `id` MUST be the AgentPin capability verb-resource string (e.g., `"read:customers/*"`). |
| `agentpin` | object | OPTIONAL (REQUIRED for AgentPin-verifiable cards) | The AgentPin extension payload. A card without this field is a vanilla A2A AgentCard with no AgentPin trust binding. |

#### 4.10.2 AgentPin Extension Payload

The `agentpin` field carries three sub-fields:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `agentpin_endpoint` | string | REQUIRED | URL of the entity's AgentPin discovery document (typically `https://{domain}/.well-known/agent-identity.json`). |
| `public_key_jwk` | object | REQUIRED | The public key used to sign this AgentCard, in JWK form (§4.4). The verifier uses this key to verify `signature`. |
| `signature` | string | REQUIRED | Detached ECDSA P-256 signature over the canonical bytes of the AgentCard with the `agentpin` field cleared. Standard-base64-encoded DER bytes (matches the JWT signature encoding used elsewhere in AgentPin). |

#### 4.10.3 Canonical Signing Input

The signature in `agentpin.signature` is computed over the canonical JSON serialization of the AgentCard with the `agentpin` field set to `null`/absent. The canonicalisation rules are:

1. Take the AgentCard you intend to publish.
2. Remove (or set to `null`) its `agentpin` field.
3. Recursively serialize as JSON with:
   - Object keys sorted alphabetically at every depth.
   - Compact separators (no whitespace between tokens).
   - Fields whose value is `null`/`undefined` dropped from objects.
   - UTF-8 string encoding (no `\uXXXX` escapes for non-ASCII).
4. Sign the resulting byte sequence with ECDSA P-256 using SHA-256 as the message hash. Encode the DER signature with standard base64.

This canonicalisation pattern is intentionally identical in spirit to SchemaPin's schema canonicalisation, so implementations can share the same `canonicalize()` helper.

**Implementation note.** All four AgentPin SDKs (Rust, JavaScript, Python, Go) MUST produce byte-identical canonical bytes for the same input AgentCard. Conformance is verified end-to-end: a card signed in any SDK MUST verify in the other three.

#### 4.10.4 Verification

A verifier presented with an AgentCard `card` performs:

1. Reject if `card.agentpin` is absent.
2. Recompute the canonical signing input by canonicalising `card` with the `agentpin` field cleared (§4.10.3).
3. Decode `card.agentpin.public_key_jwk` into a P-256 public key.
4. Verify `card.agentpin.signature` against the canonical bytes using that key. A failure MUST surface as `DISCOVERY_INVALID`.

Verification of the AgentCard signature alone proves only that the card has not been tampered with relative to the key inside its own extension. To chain the card back to a *trusted* AgentPin identity, the verifier MUST then:

5. Verify that `card.agentpin.public_key_jwk` is also present in the entity's AgentPin discovery document at `card.agentpin.agentpin_endpoint`, by JWK thumbprint (§4.4). This step is what binds an A2A AgentCard to the rest of the AgentPin trust chain.

Implementations MAY skip step 5 when the card was supplied through a channel that already establishes its provenance (e.g., a `LocalAgentCardStore` that was populated from an out-of-band, authenticated source — §4.8.4). When skipping step 5, implementations MUST document the substitute provenance check.

#### 4.10.5 Capability Mapping

The `skills` array on the AgentCard is derived from `AgentDeclaration.capabilities` (§4.5):

- Each capability string `"<verb>:<resource>"` becomes a skill with `id == "<verb>:<resource>"`.
- The default `skills[i].name` is the same verb-resource string. Builders MAY override with a human-readable name.
- The capability *taxonomy* (§10) is unchanged — A2A AgentCards do not introduce new capability semantics; they merely re-express the existing capability list in the A2A skill shape so A2A-native consumers can read it.

#### 4.10.6 Example Signed AgentCard

```json
{
  "name": "Tarnover Field Analyst",
  "description": "Reads customer reports, writes invoices",
  "version": "1.0.0",
  "url": "https://tarnover.com/agent",
  "capabilities": {
    "streaming": true,
    "pushNotifications": false,
    "allowed_domains": ["partner-corp.com"]
  },
  "skills": [
    { "id": "read:customers/*", "name": "read:customers/*" },
    { "id": "write:invoices/*", "name": "write:invoices/*" }
  ],
  "agentpin": {
    "agentpin_endpoint": "https://tarnover.com/.well-known/agent-identity.json",
    "public_key_jwk": {
      "kid": "tarnover-2026-05",
      "kty": "EC",
      "crv": "P-256",
      "x": "...",
      "y": "...",
      "use": "sig"
    },
    "signature": "MEUCIQD..."
  }
}
```

### 4.11 AllowedDomains Typed Wrapper (v0.3)

`AllowedDomains` is a typed view over the `allowed_domains` field on `Constraints` (§5.5) and on the A2A AgentCard `capabilities.allowed_domains` field (§4.10.1), used for cross-protocol allow-list composition.

#### 4.11.1 Semantics

An `AllowedDomains` value is an ordered list of strings, each of which is either a literal domain or a pattern using the wildcard rules from §5.5 (e.g., `"*.client-corp.com"`).

The list has a single *convention* that v0.3 implementations MUST honour:

> **An empty `AllowedDomains` list means *unrestricted* (all domains trusted).**

This is the opposite of the naïve set-theoretic interpretation (where an empty set allows nothing), but it matches the existing v0.2 behaviour where an *omitted* `allowed_domains` field allowed all domains. The convention lets `AllowedDomains` be the unified type at API boundaries regardless of whether the upstream constraint was absent or explicitly empty.

#### 4.11.2 Operations

Implementations MUST expose the following operations:

| Operation | Semantics |
|-----------|-----------|
| `unrestricted()`               | Returns an empty allow-list, i.e. "no restriction". |
| `from_domains(list)`           | Constructs from any iterable of strings. |
| `is_unrestricted(list)`        | Returns true iff the list is empty. |
| `allows(list, domain)`         | Returns true iff `is_unrestricted(list)` OR `domain` is in `list` (pattern match per §5.5). |
| `intersect(lhs, rhs)`          | Returns the intersection following these rules: `unrestricted ∩ X = X`; `X ∩ unrestricted = X`; otherwise the set intersection of `lhs` and `rhs`. |
| `from_constraints(constraints)` | Returns `unrestricted()` when `constraints == null` or `constraints.allowed_domains` is absent; otherwise returns the literal list. |

#### 4.11.3 Cross-Protocol Use

SchemaPin v1.4 introduced `A2aVerificationContext`, which scopes tool-integrity verification to the intersection of *caller* and *provider* allow-lists. AgentPin v0.3 exposes `AllowedDomains` and its `intersect` operation so SchemaPin can compose the two allow-lists directly:

```text
caller_allowed  = AllowedDomains.from_constraints(caller_credential.constraints)
provider_allowed = AllowedDomains.from_constraints(provider_agent.constraints)
effective_scope  = AllowedDomains.intersect(caller_allowed, provider_allowed)
```

If `is_unrestricted(effective_scope)` is true at this point, the cross-protocol context places no domain restriction; otherwise the resulting set is the maximal domain allow-list the bridged interaction may operate on.

#### 4.11.4 Edge Case: Intersection That Becomes Empty

Two non-empty allow-lists with no overlap intersect to the empty list. Under the v0.3 convention this is *re-interpreted as "unrestricted"*, which is the same outcome as having no allow-list at all. This is documented behaviour — callers that need to distinguish "intentionally restricted to nothing" from "no restriction" MUST track that distinction outside the `AllowedDomains` value (e.g., with an out-of-band sentinel). The AgentPin SDKs deliberately do not encode this distinction in `AllowedDomains` because the existing v0.2 deployment surface does not encode it either.

---

## 5. Agent Credentials

### 5.1 Credential Format

Agent credentials are encoded as JSON Web Tokens (JWT) per [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519), signed using ECDSA with P-256 (ES256) per [RFC 7518](https://www.rfc-editor.org/rfc/rfc7518).

A credential is a compact-serialization JWT consisting of three Base64url-encoded parts:

```
<header>.<payload>.<signature>
```

### 5.2 JWT Header

```json
{
  "alg": "ES256",
  "typ": "agentpin-credential+jwt",
  "kid": "<key identifier matching discovery document>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `alg` | string | REQUIRED | Signature algorithm. MUST be `"ES256"` for this version. |
| `typ` | string | REQUIRED | Token type. MUST be `"agentpin-credential+jwt"`. |
| `kid` | string | REQUIRED | Key identifier. MUST match a `kid` in the issuer's discovery document. |

**Critical validation:** Verifiers MUST reject any credential where `alg` is not `"ES256"`. This prevents algorithm confusion attacks (e.g., `alg: "none"`). The `alg` header MUST NOT be used to select the verification algorithm; verifiers MUST use the algorithm specified by the key in the discovery document.

### 5.3 JWT Payload

```json
{
  "iss": "<issuer domain>",
  "sub": "<agent URN>",
  "aud": "<intended verifier domain or wildcard>",
  "iat": <issued-at timestamp>,
  "exp": <expiration timestamp>,
  "nbf": <not-before timestamp>,
  "jti": "<unique credential identifier>",
  "agentpin_version": "0.1",
  "capabilities": [ ... ],
  "constraints": { ... },
  "delegation_chain": [ ... ],
  "nonce": "<optional challenge nonce>"
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `iss` | string | REQUIRED | Issuer domain. MUST match the `entity` in the discovery document. |
| `sub` | string | REQUIRED | Agent URN. MUST match an `agent_id` in the issuer's discovery document. |
| `aud` | string | RECOMMENDED | Intended audience. Domain of the verifier, or `"*"` for bearer credentials. |
| `iat` | integer | REQUIRED | Issued-at time as Unix timestamp. |
| `exp` | integer | REQUIRED | Expiration time as Unix timestamp. MUST be ≤ `iat + credential_ttl_max`. |
| `nbf` | integer | OPTIONAL | Not-before time as Unix timestamp. Credential is invalid before this time. |
| `jti` | string | REQUIRED | Unique credential identifier. MUST be a UUID v4 or equivalent unique string. |
| `agentpin_version` | string | REQUIRED | Protocol version. MUST be `"0.1"`. |
| `capabilities` | array | REQUIRED | Array of capability strings (see §5.4). |
| `constraints` | object | OPTIONAL | Operational constraints (see §5.5). |
| `delegation_chain` | array | OPTIONAL | Delegation attestations (see §5.6). |
| `nonce` | string | OPTIONAL | Challenge nonce for mutual verification (see §9). |

### 5.4 Capability Claims

Capabilities in the credential payload MUST be a subset of the capabilities declared in the discovery document for the corresponding agent. Verifiers MUST reject credentials where any capability is not present in the discovery document.

Capability format: `<action>:<resource>`

```json
{
  "capabilities": [
    "read:public-api",
    "read:codebase",
    "write:report"
  ]
}
```

See §10 for the full capability taxonomy.

### 5.5 Constraint Claims

Constraints limit the operational scope of a credential. Constraints in a credential MUST be equal to or more restrictive than the constraints in the discovery document.

```json
{
  "constraints": {
    "allowed_domains": ["api.client-corp.com"],
    "denied_domains": ["internal.client-corp.com"],
    "rate_limit": "50/hour",
    "data_classification_max": "internal",
    "ip_allowlist": ["203.0.113.0/24"],
    "valid_hours": {
      "start": "09:00",
      "end": "17:00",
      "timezone": "America/New_York"
    }
  }
}
```

| Constraint | Type | Description |
|------------|------|-------------|
| `allowed_domains` | array of strings | Domains/patterns the agent may interact with. Supports `*` wildcard for subdomains. |
| `denied_domains` | array of strings | Domains/patterns the agent MUST NOT interact with. Takes precedence over allowed. |
| `rate_limit` | string | Maximum request rate. Format: `<count>/<period>` where period is `second`, `minute`, or `hour`. |
| `data_classification_max` | string | Maximum data sensitivity level: `public`, `internal`, `confidential`, `restricted`. |
| `ip_allowlist` | array of strings | CIDR ranges the agent is expected to operate from. |
| `valid_hours` | object | Time-of-day restrictions with timezone. |

### 5.6 Delegation Chain Claims

The delegation chain provides cryptographic linkage from the credential back through Deployer to Maker:

```json
{
  "delegation_chain": [
    {
      "domain": "anthropic.com",
      "role": "maker",
      "agent_id": "urn:agentpin:anthropic.com:claude-agent-v4",
      "kid": "anthropic-2026-01",
      "attestation": "<base64url signature>"
    }
  ]
}
```

Each entry in the delegation chain contains:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `domain` | string | REQUIRED | Domain of the attesting entity. |
| `role` | string | REQUIRED | Role of the attesting entity: `"maker"` or `"deployer"`. |
| `agent_id` | string | REQUIRED | The agent URN as known to the attesting entity. |
| `kid` | string | REQUIRED | Key identifier used for the attestation. |
| `attestation` | string | REQUIRED | Base64url-encoded ECDSA signature over the canonical form of: `{domain}|{role}|{agent_id}|{delegatee_domain}|{delegatee_agent_id}|{capabilities_hash}` |

The `capabilities_hash` is the SHA-256 hash of the sorted, JSON-serialized capabilities array, ensuring the Maker attested to a specific set of capabilities.

### 5.7 Credential Lifetime

- Credentials MUST have an `exp` (expiration) claim.
- The lifetime (`exp - iat`) MUST NOT exceed the `credential_ttl_max` declared in the discovery document for the corresponding agent.
- Short-lived credentials (≤ 1 hour) are RECOMMENDED for automated agent-to-agent interactions.
- Longer-lived credentials (≤ 24 hours) MAY be used for human-supervised agents where frequent renewal is impractical.
- Verifiers SHOULD reject credentials with lifetimes exceeding 24 hours regardless of the declared `credential_ttl_max`.
- Clock skew tolerance: Verifiers SHOULD allow up to 60 seconds of clock skew when checking `iat`, `exp`, and `nbf`.

### 5.8 Example Credential

**Header:**
```json
{
  "alg": "ES256",
  "typ": "agentpin-credential+jwt",
  "kid": "tarnover-2026-01"
}
```

**Payload:**
```json
{
  "iss": "tarnover.com",
  "sub": "urn:agentpin:tarnover.com:scout-v2",
  "aud": "api.client-corp.com",
  "iat": 1738300800,
  "exp": 1738304400,
  "jti": "550e8400-e29b-41d4-a716-446655440000",
  "agentpin_version": "0.1",
  "capabilities": [
    "read:public-api",
    "read:codebase"
  ],
  "constraints": {
    "allowed_domains": ["api.client-corp.com"],
    "rate_limit": "50/hour",
    "data_classification_max": "internal"
  },
  "delegation_chain": [
    {
      "domain": "anthropic.com",
      "role": "maker",
      "agent_id": "urn:agentpin:anthropic.com:claude-agent-v4",
      "kid": "anthropic-2026-01",
      "attestation": "MEUCIQD7y2F8..."
    }
  ]
}
```

---

## 6. Verification Protocol

### 6.1 Verification Flow

Verification is a multi-step process. Each step MUST succeed for the credential to be considered valid. If any step fails, the verifier MUST reject the credential.

```
┌─────────────────────────────────────────────────────┐
│                 Verification Flow                    │
│                                                     │
│  1. Parse JWT                                       │
│     ├─ Decode header and payload (no signature      │
│     │  verification yet)                            │
│     ├─ Validate `typ` == "agentpin-credential+jwt"  │
│     └─ Validate `alg` == "ES256"                    │
│                                                     │
│  2. Check temporal validity                         │
│     ├─ `iat` ≤ now + skew                           │
│     ├─ `exp` > now - skew                           │
│     └─ `nbf` ≤ now + skew (if present)              │
│                                                     │
│  3. Fetch discovery document                        │
│     ├─ GET https://{iss}/.well-known/               │
│     │       agent-identity.json                     │
│     ├─ Validate `entity` == `iss`                   │
│     └─ Validate HTTPS, no redirects                 │
│                                                     │
│  4. Resolve public key                              │
│     ├─ Find key where `kid` matches header `kid`    │
│     ├─ Validate key not expired                     │
│     └─ If `kid` not found, re-fetch (cache bust)    │
│                                                     │
│  5. Verify signature                                │
│     └─ ECDSA-P256-SHA256 verify JWT signature       │
│                                                     │
│  6. Check revocation                                │
│     ├─ Fetch revocation endpoint                    │
│     ├─ Check `jti` not in revoked credentials       │
│     ├─ Check `sub` not in revoked agents            │
│     └─ Check `kid` not in revoked keys              │
│                                                     │
│  7. Validate agent status                           │
│     ├─ Find agent in discovery `agents` array       │
│     │  where `agent_id` == `sub`                    │
│     └─ Validate `status` == "active"                │
│                                                     │
│  8. Validate capabilities                           │
│     └─ Every capability in credential MUST exist    │
│        in discovery document agent declaration      │
│                                                     │
│  9. Validate constraints                            │
│     └─ Credential constraints MUST be equal to      │
│        or more restrictive than discovery defaults   │
│                                                     │
│ 10. Validate delegation chain (if present)          │
│     ├─ For each entry in chain:                     │
│     │  ├─ Fetch that domain's discovery document    │
│     │  ├─ Resolve kid → public key                  │
│     │  ├─ Verify attestation signature              │
│     │  └─ Validate capabilities_hash                │
│     └─ Verify chain depth ≤ min(max_delegation_     │
│        depth) across all entities                   │
│                                                     │
│ 11. Apply TOFU key pinning                          │
│     ├─ If domain not previously seen: pin key       │
│     ├─ If domain seen and key matches: proceed      │
│     └─ If domain seen and key changed: WARN/REJECT  │
│                                                     │
│ 12. (Optional) Check audience                       │
│     └─ If `aud` present, verify it matches          │
│        verifier's domain                            │
│                                                     │
│ Result: VALID or REJECTED with reason code          │
└─────────────────────────────────────────────────────┘
```

### 6.2 Discovery Document Retrieval

When fetching a discovery document, the verifier:

1. MUST use HTTPS. HTTP MUST be rejected.
2. MUST NOT follow redirects (3xx responses). The document MUST be served at the canonical `.well-known` URL.
3. MUST validate the TLS certificate per standard web PKI.
4. MUST verify the `entity` field matches the requested domain.
5. SHOULD cache the document according to `Cache-Control` headers.
6. MUST re-fetch if encountering an unknown `kid`.

### 6.3 Signature Verification

1. Extract the `kid` from the JWT header.
2. Find the corresponding public key in the discovery document.
3. Verify the JWT signature using ECDSA-P256-SHA256.
4. The verification MUST use the key from the discovery document, NOT the `alg` from the JWT header (to prevent algorithm substitution attacks).

### 6.4 Delegation Chain Verification

For each entry in the `delegation_chain` array, ordered from outermost (Maker) to innermost:

1. Fetch the discovery document from the entry's `domain`.
2. Resolve the `kid` to a public key.
3. Reconstruct the canonical attestation input: `{domain}|{role}|{agent_id}|{delegatee_domain}|{delegatee_agent_id}|{capabilities_hash}`
4. Verify the `attestation` signature over the canonical input using the resolved public key.
5. Verify the `capabilities_hash` matches the SHA-256 of the sorted, JSON-serialized capabilities in the credential.
6. Verify the chain depth does not exceed any entity's `max_delegation_depth`.

### 6.5 Capability Validation

For each capability in the credential's `capabilities` array:

1. The capability MUST be present in the agent declaration's `capabilities` array in the discovery document.
2. Wildcard capabilities in the discovery document (e.g., `read:*`) match any specific capability with the same action (e.g., `read:codebase`).
3. A credential MUST NOT contain wildcard capabilities unless the discovery document also declares that exact wildcard.

### 6.6 Constraint Enforcement

Verifiers SHOULD enforce constraints declared in the credential:

1. **Domain constraints:** Reject requests to domains not in `allowed_domains` or in `denied_domains`.
2. **Rate limits:** Track and enforce the declared rate limit.
3. **Data classification:** Reject access to resources above the declared classification level.
4. **IP allowlist:** Reject requests originating from IPs outside the allowlist.
5. **Time restrictions:** Reject requests outside valid hours.

Constraint enforcement is RECOMMENDED but ultimately at the verifier's discretion. A verifier MAY apply stricter constraints than those in the credential.

### 6.7 Verification Result

Verification produces a structured result:

```json
{
  "valid": true,
  "agent_id": "urn:agentpin:tarnover.com:scout-v2",
  "issuer": "tarnover.com",
  "capabilities": ["read:public-api", "read:codebase"],
  "constraints": { ... },
  "delegation_verified": true,
  "delegation_chain": [
    { "domain": "anthropic.com", "role": "maker", "verified": true }
  ],
  "key_pinning": {
    "status": "pinned",
    "first_seen": "2026-01-15T00:00:00Z"
  },
  "warnings": []
}
```

On failure:

```json
{
  "valid": false,
  "error_code": "SIGNATURE_INVALID",
  "error_message": "JWT signature verification failed for kid 'tarnover-2026-01'",
  "warnings": ["Key for tarnover.com has changed since last pinned"]
}
```

**Error codes:**

| Code | Description |
|------|-------------|
| `SIGNATURE_INVALID` | JWT signature does not verify against the public key. |
| `KEY_NOT_FOUND` | No key matching `kid` found in discovery document. |
| `KEY_EXPIRED` | The matching key has passed its `exp` date. |
| `KEY_REVOKED` | The key has been revoked (found in revocation document). |
| `CREDENTIAL_EXPIRED` | The credential's `exp` has passed. |
| `CREDENTIAL_REVOKED` | The credential's `jti` is in the revocation list. |
| `AGENT_NOT_FOUND` | No agent matching `sub` found in discovery document. |
| `AGENT_INACTIVE` | Agent status is not `"active"`. |
| `CAPABILITY_EXCEEDED` | Credential claims capabilities not in discovery document. |
| `CONSTRAINT_VIOLATION` | Credential constraints are less restrictive than discovery defaults. |
| `DELEGATION_INVALID` | Delegation chain attestation failed verification. |
| `DELEGATION_DEPTH_EXCEEDED` | Chain depth exceeds `max_delegation_depth`. |
| `DISCOVERY_FETCH_FAILED` | Could not retrieve discovery document. |
| `DISCOVERY_INVALID` | Discovery document failed schema validation. |
| `DOMAIN_MISMATCH` | `iss` does not match discovery document `entity`. |
| `AUDIENCE_MISMATCH` | `aud` does not match verifier's domain. |
| `ALGORITHM_REJECTED` | JWT `alg` is not `ES256`. |
| `KEY_PIN_MISMATCH` | Key for domain changed since TOFU pin. |

---

## 7. Key Management

### 7.1 Key Generation

Keys MUST be generated using a cryptographically secure random number generator (CSPRNG).

**ECDSA P-256 key generation:**

1. Generate a random 256-bit private key `d` in the range [1, n-1] where `n` is the order of the P-256 curve.
2. Compute the public key point `Q = d * G` where `G` is the P-256 generator point.
3. Export the public key as a JWK with `x` and `y` coordinates.
4. Store the private key securely (hardware security module recommended for production).

Reference implementations SHOULD provide key generation utilities consistent with the SchemaPin `KeyManager` interface.

### 7.2 Key Rotation

Key rotation is the process of transitioning from one keypair to another:

1. Generate a new keypair.
2. Add the new public key to the discovery document's `public_keys` array.
3. Begin issuing new credentials with the new key's `kid`.
4. After all outstanding credentials signed with the old key have expired, remove the old key from the discovery document.
5. Optionally add the old key to the revocation document.

During rotation, the discovery document SHOULD contain both old and new keys. The overlap period SHOULD be at least `credential_ttl_max` to ensure all outstanding credentials remain verifiable.

Discovery documents SHOULD reduce their `Cache-Control: max-age` during rotation periods.

### 7.3 Key Pinning (TOFU)

AgentPin uses Trust-On-First-Use (TOFU) key pinning, consistent with SchemaPin's pinning model:

1. **First encounter:** When a verifier first sees a credential from a domain, it fetches the discovery document and pins the public key(s) associated with that domain.
2. **Subsequent encounters:** The verifier checks that the key used to sign the credential matches a pinned key for that domain.
3. **Key change detected:** If the key has changed, the verifier MUST flag this as a warning. In interactive contexts, the verifier SHOULD prompt the user. In automated contexts, the verifier SHOULD reject the credential unless explicit key rotation policy allows it.

### 7.4 Key Pinning Storage

Pinned keys are stored as:

```json
{
  "domain": "tarnover.com",
  "pinned_keys": [
    {
      "kid": "tarnover-2026-01",
      "public_key_hash": "<SHA-256 hash of canonical JWK>",
      "first_seen": "2026-01-15T00:00:00Z",
      "last_seen": "2026-01-30T12:00:00Z",
      "trust_level": "tofu"
    }
  ]
}
```

The `public_key_hash` is the SHA-256 hash of the canonical JSON serialization of the JWK (keys sorted alphabetically, no whitespace), providing a compact fingerprint for comparison.

**Trust levels:**

| Level | Description |
|-------|-------------|
| `tofu` | Key accepted on first use. Default. |
| `verified` | Key verified through an out-of-band mechanism (e.g., manual confirmation). |
| `pinned` | Key explicitly pinned by administrator policy. Highest trust. |

---

## 8. Revocation

### 8.1 Revocation Endpoint

The revocation document MUST be served at the URL specified in the discovery document's `revocation_endpoint` field. If not specified, verifiers SHOULD assume `https://{domain}/.well-known/agent-identity-revocations.json`.

### 8.2 Revocation Document Schema

```json
{
  "agentpin_version": "0.1",
  "entity": "<domain>",
  "updated_at": "<ISO 8601 datetime>",
  "revoked_credentials": [
    {
      "jti": "<credential identifier>",
      "revoked_at": "<ISO 8601 datetime>",
      "reason": "<reason code>"
    }
  ],
  "revoked_agents": [
    {
      "agent_id": "<agent URN>",
      "revoked_at": "<ISO 8601 datetime>",
      "reason": "<reason code>"
    }
  ],
  "revoked_keys": [
    {
      "kid": "<key identifier>",
      "revoked_at": "<ISO 8601 datetime>",
      "reason": "<reason code>"
    }
  ]
}
```

**Reason codes:**

| Code | Description |
|------|-------------|
| `key_compromise` | Private key material has been compromised. |
| `affiliation_changed` | The agent's organizational affiliation has changed. |
| `superseded` | The credential/agent/key has been replaced by a newer version. |
| `cessation_of_operation` | The agent is no longer in operation. |
| `privilege_withdrawn` | The authorization for this agent has been withdrawn. |
| `policy_violation` | The agent violated operational policy. |

### 8.3 Revocation Checking

Verifiers MUST check revocation status as part of credential verification:

1. Fetch the revocation document.
2. Check if the credential's `jti` appears in `revoked_credentials`.
3. Check if the credential's `sub` (agent URN) appears in `revoked_agents`.
4. Check if the credential's `kid` appears in `revoked_keys`.
5. If any match is found, reject the credential.

Revocation documents SHOULD be served with short cache lifetimes (`Cache-Control: max-age=300` or less).

### 8.4 Emergency Revocation

For emergency revocation (e.g., key compromise), an entity SHOULD:

1. Immediately update the revocation document.
2. Remove the compromised key from the discovery document.
3. Set `Cache-Control: no-cache` on both documents temporarily.
4. Issue new credentials with a new key.

Verifiers SHOULD support a "revocation check bypass timeout": if the revocation endpoint is unreachable, the verifier SHOULD reject credentials rather than assume they are valid (fail-closed).

---

## 9. Mutual Verification

### 9.1 Challenge-Response Protocol

For agent-to-agent interactions where both parties need to verify each other, AgentPin supports a mutual verification protocol using challenge-response:

1. Agent A sends its credential to Agent B.
2. Agent B verifies Agent A's credential (per §6).
3. Agent B generates a random nonce and includes it in a challenge.
4. Agent A creates a new credential (or signs the nonce) with its private key and returns it.
5. Agent B verifies the response, confirming Agent A possesses the private key corresponding to its claimed identity.
6. The process repeats in reverse for Agent B to prove its identity to Agent A.

### 9.2 Nonce Requirements

- Nonces MUST be at least 128 bits of cryptographically random data, encoded as base64url.
- Nonces MUST be single-use. Verifiers MUST reject previously seen nonces.
- Nonces MUST expire within 60 seconds.

### 9.3 Mutual Verification Flow

```
Agent A                                Agent B
   │                                      │
   │── Credential A ─────────────────────>│
   │                                      │── Verify A
   │                                      │
   │<─ Credential B + challenge_nonce ────│
   │                                      │
   │── Verify B                           │
   │── Sign(nonce) with A's key           │
   │                                      │
   │── nonce_response ───────────────────>│
   │                                      │── Verify nonce sig
   │                                      │
   │<─ nonce_response (B's nonce) ────────│
   │── Verify nonce sig                   │
   │                                      │
   │       Mutual verification complete   │
   │                                      │
```

The challenge and response are encoded as:

```json
{
  "type": "agentpin-challenge",
  "nonce": "<base64url-encoded random bytes>",
  "timestamp": "<ISO 8601 datetime>",
  "verifier_credential": "<Agent B's JWT>"
}
```

```json
{
  "type": "agentpin-response",
  "nonce": "<echoed nonce>",
  "signature": "<base64url ECDSA signature over nonce>",
  "kid": "<key used to sign>"
}
```

---

## 10. Capability Taxonomy

### 10.1 Core Capabilities

AgentPin defines a minimal core capability vocabulary. The format is `<action>:<resource>`.

**Core actions:**

| Action | Description |
|--------|-------------|
| `read` | Read/retrieve data from a resource. |
| `write` | Create or modify data in a resource. |
| `delete` | Remove data from a resource. |
| `execute` | Execute code, commands, or workflows. |
| `delegate` | Delegate authority to another agent. |
| `admin` | Administrative operations (key management, policy changes). |

**Core resource types:**

| Resource | Description |
|----------|-------------|
| `*` | Wildcard. All resources of any type. |
| `public-api` | Public API endpoints. |
| `private-api` | Private/internal API endpoints. |
| `codebase` | Source code repositories. |
| `database` | Database access. |
| `filesystem` | File system access. |
| `network` | Network resources. |
| `agent` | Other agents (for delegation). |
| `tool` | MCP or other tool invocations. |
| `report` | Generated reports and analysis outputs. |
| `text` | Text content (documents, messages). |
| `code` | Code execution environments. |
| `secret` | Secrets and credentials. |

### 10.2 Capability Scoping

Capabilities can be further scoped using dot-notation on the resource:

```
read:codebase.github.com/org/repo
write:database.production.users
execute:tool.mcp.file-manager
```

Scoped capabilities are more restrictive than their unscoped equivalents. `read:codebase` grants broader access than `read:codebase.github.com/org/repo`.

### 10.3 Capability Inheritance

- A Deployer's agent capabilities MUST be a subset of the Maker's declared capabilities for that agent type.
- A credential's capabilities MUST be a subset of the Deployer's declared capabilities for that agent instance.
- Wildcard capabilities in a parent scope authorize any specific capability in child scopes: `read:*` authorizes `read:codebase`, `read:database`, etc.
- The `admin` action MUST NOT be granted via wildcard; it must be explicitly declared at each level.

### 10.4 Custom Capabilities

Organizations MAY define custom capabilities using reverse-domain notation for the resource:

```
read:com.client-corp.internal-api
execute:com.tarnover.security-scan
```

Custom capabilities MUST NOT collide with core capability names. Verifiers that do not recognize a custom capability SHOULD treat it as an opaque string and validate it against the discovery document as normal.

---

## 11. Integration with SchemaPin

### 11.1 Shared Cryptographic Infrastructure

AgentPin and SchemaPin share:

- **Algorithm:** ECDSA with P-256 (secp256r1), SHA-256 hashing.
- **Key format:** JWK per RFC 7517 (AgentPin) / PEM (SchemaPin). Implementations SHOULD support both formats for interoperability.
- **TOFU pinning:** Identical trust model and storage format. A shared `KeyPinning` module can service both protocols with a `protocol` discriminator.
- **Discovery pattern:** Both use `/.well-known/` endpoints per RFC 8615.

A reference library (`thirdkey-crypto`) SHOULD provide shared implementations of:
- Key generation and serialization (JWK ↔ PEM)
- ECDSA signing and verification
- SHA-256 hashing and canonicalization
- TOFU key pinning with multi-protocol support
- `.well-known` endpoint fetching with TLS validation

### 11.2 Unified Discovery

While AgentPin and SchemaPin use separate `.well-known` endpoints for modularity (allowing independent adoption), the discovery documents cross-reference each other:

- AgentPin discovery documents include `schemapin_endpoint` pointing to the entity's SchemaPin document.
- SchemaPin discovery documents MAY include an `agentpin_endpoint` field (to be proposed as a SchemaPin extension).

This enables a verifier to discover both protocols from either entry point.

### 11.3 Bidirectional Trust Model

SchemaPin and AgentPin together create a bidirectional trust model for agent-tool interactions:

```
┌─────────────┐                    ┌──────────────┐
│   Agent     │                    │  Tool/Service │
│             │                    │              │
│ "I am Scout │  AgentPin cred    │ "Verify the  │
│  from       │───────────────────>│  agent is    │
│  Tarnover"  │                    │  legit"      │
│             │                    │              │
│ "Verify the │  SchemaPin sig    │ "My schemas  │
│  tool is    │<───────────────────│  are signed  │
│  legit"     │                    │  by me"      │
└─────────────┘                    └──────────────┘

  Agent verifies tool (SchemaPin) ←→ Tool verifies agent (AgentPin)
```

### 11.4 Combined Verification Flow

When an agent invokes a tool, the full trust verification involves both protocols:

1. **Agent → Tool:** Agent presents AgentPin credential. Tool verifies agent identity, capabilities, and delegation chain.
2. **Tool → Agent:** Tool presents its schema with SchemaPin signature. Agent verifies schema integrity and authenticity.
3. **Policy check:** The runtime (e.g., Symbiont) evaluates whether the verified agent's capabilities authorize it to use the verified tool.
4. **Audit log:** Both verifications and the policy decision are recorded in the cryptographic audit trail.

---

## 12. Integration with Symbiont

### 12.1 Policy Engine Integration

Symbiont's DSL policy engine can consume AgentPin verification results to make access control decisions:

```
policy agent_access {
    // Only allow verified agents
    allow: invoke(tool) if caller.agentpin.valid == true

    // Require specific maker provenance
    allow: invoke(tool) if caller.agentpin.delegation_chain
        contains { role: "maker", domain: "anthropic.com" }

    // Enforce capability requirements
    allow: read(resource) if caller.agentpin.capabilities
        includes "read:" + resource.type

    // Deny suspended agents
    deny: invoke(tool) if caller.agentpin.agent_status != "active"

    // Rate limit based on credential constraints
    throttle: invoke(tool) at caller.agentpin.constraints.rate_limit

    // Audit all agent interactions
    audit: all_agent_interactions with {
        agent_id: caller.agentpin.agent_id,
        issuer: caller.agentpin.issuer,
        delegation_chain: caller.agentpin.delegation_chain,
        capabilities_used: caller.agentpin.capabilities
    }
}
```

### 12.2 Audit Trail Integration

Symbiont's cryptographic audit trails are enhanced by AgentPin:

**Without AgentPin:**
```json
{
  "timestamp": "2026-01-30T15:00:00Z",
  "actor": "self-asserted:scout-v2",
  "action": "invoke_tool",
  "tool": "code-analyzer",
  "result": "success",
  "audit_hash": "sha256:abc..."
}
```

**With AgentPin:**
```json
{
  "timestamp": "2026-01-30T15:00:00Z",
  "actor": {
    "agent_id": "urn:agentpin:tarnover.com:scout-v2",
    "issuer": "tarnover.com",
    "credential_jti": "550e8400-e29b-41d4-a716-446655440000",
    "verification": "valid",
    "delegation": [
      {"domain": "anthropic.com", "role": "maker", "verified": true}
    ]
  },
  "action": "invoke_tool",
  "tool": {
    "id": "code-analyzer",
    "schemapin_verified": true,
    "schema_hash": "sha256:def..."
  },
  "policy_decision": "allow",
  "policy_rule": "agent_access:line_3",
  "capabilities_exercised": ["read:codebase"],
  "result": "success",
  "audit_hash": "sha256:abc...",
  "previous_hash": "sha256:xyz..."
}
```

This provides cryptographically verifiable, tamper-evident logs with full provenance — critical for SOC2, HIPAA, and financial regulatory compliance.

### 12.3 Runtime Enforcement

Symbiont's zero-trust runtime integrates AgentPin at the agent communication boundary:

1. **Inbound:** When Symbiont receives a request from an external agent, it extracts the AgentPin credential, verifies it, and makes the verification result available to the policy engine.
2. **Outbound:** When Symbiont's agents make requests to external services, Symbiont attaches the appropriate AgentPin credential to the request.
3. **Internal:** For agent-to-agent communication within a Symbiont runtime, lightweight credential verification (signature check only, skip discovery fetch) MAY be used for performance.

---

## 13. Transport and Binding

AgentPin credentials must be transmitted between agents. This section defines bindings for common transport protocols.

### 13.1 HTTP Header Binding

For HTTP-based interactions, the credential is transmitted in the `Authorization` header:

```
Authorization: AgentPin <JWT>
```

Example:
```http
GET /api/v1/codebase/analysis HTTP/1.1
Host: api.client-corp.com
Authorization: AgentPin eyJhbGciOiJFUzI1NiIsInR5cCI6ImFnZW50cGluLWNyZWRlbnRpYWwrand0IiwiImtpZCI6InRhcm5vdmVyLTIwMjYtMDEifQ...
```

Services MUST NOT accept AgentPin credentials via query parameters or request bodies for security reasons (to prevent credential leakage in logs and referrer headers).

### 13.2 MCP Transport Binding

For Model Context Protocol interactions, the credential is included in the MCP request metadata:

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "code-analyzer",
    "arguments": { ... },
    "_meta": {
      "agentpin_credential": "<JWT>"
    }
  }
}
```

MCP servers that support AgentPin SHOULD declare this in their capabilities:

```json
{
  "capabilities": {
    "agentpin": {
      "version": "0.1",
      "required": false
    }
  }
}
```

### 13.3 WebSocket Binding

For WebSocket connections, the credential is sent in the initial connection handshake as a subprotocol or in the first message:

```json
{
  "type": "agentpin-auth",
  "credential": "<JWT>"
}
```

For long-lived WebSocket connections, credentials SHOULD be refreshed before expiration by sending an updated authentication message.

### 13.4 gRPC Binding

For gRPC, the credential is transmitted as metadata:

```
agentpin-credential: <JWT>
```

---

## 14. Security Considerations

### 14.1 Threat Model

AgentPin is designed to defend against the following threat actors:

| Threat Actor | Capability | Mitigated By |
|-------------|-----------|--------------|
| **Impersonating Agent** | Can send arbitrary messages claiming any identity | Signature verification, discovery document validation |
| **Compromised Deployer** | Has access to a Deployer's infrastructure but not Maker keys | Delegation chain verification, Maker attestation |
| **Compromised Domain** | Controls DNS and web server for a domain | TOFU key pinning, transparency logging (future) |
| **Network Attacker (MITM)** | Can intercept and modify network traffic | HTTPS requirement, no-redirect policy |
| **Replay Attacker** | Can capture and re-send valid credentials | Short TTLs, nonces for challenge-response, `jti` uniqueness |

### 14.2 Domain Compromise

If an attacker gains control of a domain, they can publish arbitrary discovery documents and issue fraudulent credentials. Mitigations:

1. **TOFU key pinning:** Verifiers that have previously interacted with the domain will detect the key change.
2. **Delegation chain:** Even with domain compromise, the attacker cannot forge Maker attestations without the Maker's private key. Verifiers that validate the full delegation chain will detect the break.
3. **Transparency logging (future work):** A Certificate Transparency-style log for agent identity documents would provide a public, auditable record of all published discovery documents, making unauthorized changes detectable.
4. **DNS security:** DNSSEC and CAA records provide additional protection against domain hijacking.

### 14.3 Replay Attacks

Captured credentials could be replayed by an attacker. Mitigations:

1. **Short credential lifetimes:** Default TTLs of 1 hour or less limit the window for replay.
2. **Audience restriction:** Credentials with an `aud` claim are only valid for the specified verifier.
3. **Challenge-response nonces:** For high-security interactions, mutual verification with nonces prevents replay entirely.
4. **JTI tracking:** Verifiers MAY track seen `jti` values to detect replays within a credential's lifetime.

### 14.4 Capability Confusion

A verifier might misinterpret capability claims, granting inappropriate access. Mitigations:

1. **Strict capability schema:** Well-defined taxonomy with explicit action:resource format.
2. **Deny by default:** Verifiers SHOULD reject any capability they do not explicitly recognize.
3. **Discovery document validation:** Capabilities in a credential MUST match those in the discovery document.
4. **Subset enforcement:** Deployer capabilities MUST be a subset of Maker capabilities.

### 14.5 Prompt Injection and Behavioral Integrity

AgentPin verifies identity, not behavior. A verified agent may still be manipulated via prompt injection to act outside its intended behavior. AgentPin's position on this boundary:

- **What AgentPin provides:** Cryptographic assurance of *who* is acting and *what they're authorized to do*.
- **What AgentPin does NOT provide:** Assurance that the agent *is doing what it should*.
- **Complementary defense:** Symbiont's policy engine, sandboxing, and audit trails address behavioral integrity at the runtime layer.

### 14.6 Denial of Service

Attackers could target the verification flow:

1. **Discovery document unavailability:** Verifiers SHOULD cache discovery documents and use the cached version if the endpoint is temporarily unavailable, with a time limit.
2. **Revocation endpoint unavailability:** Verifiers SHOULD fail closed (reject credentials) if the revocation endpoint is unreachable, not fail open.
3. **Expensive verification:** Delegation chain verification requires multiple HTTP fetches. Implementations SHOULD parallelize chain verification and enforce timeouts.

### 14.7 Cryptographic Agility

AgentPin v0.1 mandates ECDSA P-256. Future versions MAY add support for:

- **Ed25519 (EdDSA):** Faster, simpler, no randomness-dependent signing. Candidate for v0.2.
- **P-384 / P-521:** For organizations requiring higher security margins.
- **Post-quantum algorithms:** As NIST PQC standards mature (ML-DSA, SLH-DSA), AgentPin will need to support hybrid or pure post-quantum signatures.

The `alg` field in JWT headers and the `crv` field in JWK keys provide the extension points for cryptographic agility. Version negotiation through `agentpin_version` ensures backward compatibility.

---

## 15. Privacy Considerations

- **Agent identity disclosure:** Presenting a credential reveals the agent's identity, issuer, capabilities, and delegation chain to the verifier. Agents operating in privacy-sensitive contexts SHOULD use minimal capability sets and audience-restricted credentials.
- **Discovery document probing:** An adversary can probe `/.well-known/agent-identity.json` to enumerate an organization's agents. Organizations MAY choose to serve discovery documents only for agent IDs that are already known to the requester (authenticated discovery), at the cost of breaking TOFU.
- **Directory listing opt-out:** The `directory_listing` field (§4.5) allows agents to signal that they SHOULD NOT be indexed or listed in public agent directories or registries. This is analogous to the `noindex` directive for search engines: it is a cooperative signal, not an enforcement mechanism. Directory operators SHOULD respect `"directory_listing": false` and exclude such agents from public listings. Note that setting `directory_listing` to `false` does not prevent the agent from being discoverable via the `.well-known` endpoint — it only signals to directory aggregators that the agent prefers not to be publicly catalogued.
- **Correlation:** Verifiers that track `jti` values can correlate agent activity across time. Short credential lifetimes and frequent `jti` rotation mitigate this.
- **Revocation disclosure:** Revocation documents reveal which agents/credentials have been revoked, potentially disclosing security incidents. Organizations SHOULD use generic reason codes where appropriate.

---

## 16. IANA Considerations

This specification would register the following if submitted as an RFC:

- **Well-Known URI:** `agent-identity.json` in the Well-Known URIs registry per RFC 8615.
- **Well-Known URI:** `agent-identity-revocations.json` in the Well-Known URIs registry.
- **JWT Type:** `agentpin-credential+jwt` in the JSON Web Token Types registry.
- **HTTP Authentication Scheme:** `AgentPin` in the HTTP Authentication Scheme registry.

---

## 17. Conformance Requirements

### Credential Issuers MUST:
- Serve a valid discovery document at `/.well-known/agent-identity.json` over HTTPS.
- Sign credentials using ES256 with a key listed in the discovery document.
- Include all REQUIRED JWT claims (§5.3).
- Ensure credential capabilities are a subset of discovery document capabilities.
- Maintain a revocation endpoint and promptly revoke compromised credentials.

### Verifiers MUST:
- Implement `.well-known` HTTPS discovery as the baseline mechanism.
- Fetch discovery documents over HTTPS without following redirects (when using `.well-known`).
- Verify JWT signatures using the key from the discovery document (not the JWT `alg` header).
- Reject credentials with `alg` other than `ES256`.
- Check credential expiration with ≤ 60 seconds clock skew tolerance.
- Check revocation status before accepting a credential.
- Validate that credential capabilities match the discovery document.
- Implement TOFU key pinning.

### Verifiers MAY:
- Implement alternative discovery mechanisms (§4.8) including local file discovery, pre-shared trust bundles, the `LocalAgentCardStore` (§4.8.4), the `A2aAgentCardResolver` (§4.8.5), and resolver chains (§4.8.7).
- When using alternative mechanisms, all verification steps except document retrieval MUST remain identical to the standard flow (§6).
- (v0.3) Perform DNS TXT cross-verification at `_agentpin.{domain}` (§4.8.3) as a second-channel trust signal. When implemented, the verifier MUST treat a mismatching record as a hard `DISCOVERY_INVALID` failure and an absent record as a no-op.
- (v0.3) Accept A2A AgentCards (§4.10) as discovery input, provided they have been verified per §4.10.4 (extension-signature verification AND key thumbprint matched against the AgentPin discovery document, unless an out-of-band provenance check is documented).

### Verifiers SHOULD:
- Validate the full delegation chain when present.
- Enforce credential constraints (domain, rate limit, data classification).
- Cache discovery documents per HTTP cache headers.
- Fail closed when revocation endpoints are unreachable.
- (v0.3) When a discovery document's `a2a_endpoint` host disagrees with its `entity` field, fail with `DISCOVERY_INVALID`.
- (v0.3) When composing `AllowedDomains` with a cross-protocol context (e.g., SchemaPin v1.4 `A2aVerificationContext`), use the intersection helper documented in §4.11.2 rather than reimplementing set logic — the empty-list-equals-unrestricted convention is part of the protocol.

---

## 18. Future Work

1. **Transparency logging.** A CT-log style system for agent identity documents, allowing public auditability of all published discovery documents.

2. **Federated trust.** Support for trust federations where organizations explicitly vouch for each other's agents without requiring direct domain-based verification.

3. **Capability negotiation.** A protocol for agents to dynamically negotiate capabilities with verifiers before interaction.

4. **Post-quantum migration.** Hybrid signature schemes combining classical ECDSA with ML-DSA for quantum-safe credentials.

5. **W3C DID bridging.** Optional support for resolving agent identities via W3C Decentralized Identifiers for organizations preferring DID-based infrastructure.

6. **OAuth 2.0 integration.** Mapping AgentPin credentials to OAuth 2.0 scopes and flows for integration with existing API gateway infrastructure.

7. **Agent reputation.** A system for verifiers to share agent behavior assessments, complementing identity verification with behavioral track records.

8. **SchemaPin cross-signing.** Allow a SchemaPin signature to embed an expected `agent_id`, and an AgentPin credential to embed expected `schema_hash` values, creating a bidirectional cryptographic binding between agents and their tools.

9. **Internal CA / Trust Delegation.** An internal certificate authority model where a root organization signs discovery documents for subsidiary entities, enabling hierarchical trust without per-entity `.well-known` endpoints (§4.8.6).

10. **Symbiont-native identity provisioning.** Runtime-managed agent identity where Symbiont provisions and rotates agent credentials automatically, integrating discovery document management into the orchestration lifecycle.

11. **Mutual-auth as A2A handshake (v0.4 target).** Adapt the §9 challenge-response mutual authentication as a normative A2A handshake message, so two A2A endpoints can perform AgentPin mutual auth as part of their session setup.

---

## Appendix A: JSON Schema Definitions

### Discovery Document JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "https://agentpin.org/schemas/discovery-document-v0.1.json",
  "title": "AgentPin Discovery Document",
  "type": "object",
  "required": [
    "agentpin_version",
    "entity",
    "entity_type",
    "public_keys",
    "agents",
    "max_delegation_depth",
    "updated_at"
  ],
  "properties": {
    "agentpin_version": {
      "type": "string",
      "const": "0.1"
    },
    "entity": {
      "type": "string",
      "format": "hostname"
    },
    "entity_type": {
      "type": "string",
      "enum": ["maker", "deployer", "both"]
    },
    "public_keys": {
      "type": "array",
      "minItems": 1,
      "items": {
        "type": "object",
        "required": ["kid", "kty", "crv", "x", "y", "use"],
        "properties": {
          "kid": { "type": "string", "maxLength": 128 },
          "kty": { "type": "string", "const": "EC" },
          "crv": { "type": "string", "const": "P-256" },
          "x": { "type": "string" },
          "y": { "type": "string" },
          "use": { "type": "string", "const": "sig" },
          "key_ops": {
            "type": "array",
            "items": { "type": "string" }
          },
          "exp": { "type": "string", "format": "date-time" }
        }
      }
    },
    "agents": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["agent_id", "name", "capabilities", "status"],
        "properties": {
          "agent_id": { "type": "string", "pattern": "^urn:agentpin:.+:.+$" },
          "agent_type": { "type": "string", "pattern": "^urn:agentpin:.+:.+$" },
          "name": { "type": "string", "maxLength": 128 },
          "description": { "type": "string", "maxLength": 1024 },
          "version": { "type": "string" },
          "capabilities": {
            "type": "array",
            "items": {
              "type": "string",
              "pattern": "^[a-z]+:[a-z0-9.*-]+$"
            }
          },
          "constraints": { "type": "object" },
          "maker_attestation": { "type": "string" },
          "credential_ttl_max": {
            "type": "integer",
            "minimum": 60,
            "maximum": 86400
          },
          "status": {
            "type": "string",
            "enum": ["active", "suspended", "deprecated"]
          },
          "directory_listing": {
            "type": "boolean",
            "default": true,
            "description": "When false, signals the agent should not be listed in public directories"
          }
        }
      }
    },
    "revocation_endpoint": { "type": "string", "format": "uri" },
    "policy_url": { "type": "string", "format": "uri" },
    "schemapin_endpoint": { "type": "string", "format": "uri" },
    "a2a_endpoint": {
      "type": "string",
      "format": "uri",
      "description": "(v0.3) Optional URL of the entity's A2A AgentCard endpoint."
    },
    "max_delegation_depth": {
      "type": "integer",
      "minimum": 0,
      "maximum": 3
    },
    "updated_at": { "type": "string", "format": "date-time" }
  }
}
```

---

## Appendix B: Example Implementations

Reference implementations are planned for the following languages, consistent with SchemaPin's multi-language approach:

| Language | Package | Status |
|----------|---------|--------|
| Python | `agentpin` (PyPI) | Planned |
| JavaScript | `agentpin` (npm) | Planned |
| Rust | `agentpin` (crates.io) | Planned |
| Go | `github.com/ThirdKeyAI/agentpin/go` | Planned |

Each implementation MUST provide:

1. **Discovery document generation and serving.**
2. **Credential issuance (signing).**
3. **Credential verification (full flow per §6).**
4. **TOFU key pinning storage.**
5. **Revocation document generation and checking.**
6. **CLI tools:** `agentpin-keygen`, `agentpin-issue`, `agentpin-verify`.

The Rust implementation is the primary integration target for Symbiont.

### Shared Library: `thirdkey-crypto`

A shared cryptographic library providing common primitives for both SchemaPin and AgentPin:

```
thirdkey-crypto/
├── src/
│   ├── keys.rs          # Key generation, JWK/PEM serialization
│   ├── signing.rs       # ECDSA sign/verify
│   ├── hashing.rs       # SHA-256, canonical hashing
│   ├── pinning.rs       # Multi-protocol TOFU key pinning
│   ├── discovery.rs     # .well-known endpoint fetching
│   └── lib.rs
├── Cargo.toml
└── README.md
```

---

## Appendix C: Relationship to Existing Standards

| Standard | Relationship to AgentPin |
|----------|--------------------------|
| **RFC 8615** (Well-Known URIs) | AgentPin uses `.well-known` for discovery, same as SchemaPin. |
| **RFC 7519** (JWT) | Agent credentials are JWTs with a custom type and claim set. |
| **RFC 7517** (JWK) | Public keys in discovery documents use JWK format. |
| **RFC 7518** (JWA) | ES256 algorithm for signing. |
| **W3C DIDs** | AgentPin's domain-based identity is complementary to DIDs. A DID method (`did:agentpin:{domain}:{agent-id}`) could bridge the two. |
| **W3C Verifiable Credentials** | AgentPin credentials could be expressed as VCs. The JWT compact serialization is already VC-compatible. |
| **OAuth 2.0** | AgentPin credentials can be mapped to OAuth scopes. AgentPin could serve as a client authentication mechanism in OAuth flows. |
| **OpenID Connect** | The discovery document pattern is analogous to `.well-known/openid-configuration`. |
| **MCP (Model Context Protocol)** | AgentPin defines a transport binding for MCP (§13.2). |
| **SchemaPin** | Sister protocol. Shared crypto, discovery pattern, and TOFU model. Cross-referenced via `schemapin_endpoint`. |
| **DKIM/DMARC** | Analogous trust model: domain-based identity with DNS-anchored public keys. AgentPin extends this pattern to AI agents. |
| **Certificate Transparency** | Future work: CT-style logging for agent identity documents. |

---

*AgentPin: Domain-anchored cryptographic identity for AI agents. Part of the ThirdKey trust stack alongside SchemaPin (tool integrity) and Symbiont (runtime enforcement).*

**Repository:** https://github.com/ThirdKeyAI/AgentPin  
**SchemaPin:** https://github.com/ThirdKeyAI/SchemaPin  
**Symbiont:** https://github.com/ThirdKeyAI/Symbiont  
**Contact:** jascha@thirdkey.ai
