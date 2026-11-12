# Web Bot Auth

Web Bot Auth (WBA) is the IETF protocol for identifying automated HTTP
clients with [RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421).
An agent signs each request with an Ed25519 or RSA key and names the HTTPS key
directory that publishes that key. Origins and edge providers that support
WBA verify the signature and recognize the agent by that directory URL.

AgentPin supports WBA in three ways:

- **Signing and verification.** RFC 9421 signatures with Ed25519 or
  RSASSA-PSS SHA-512 in the WBA profile (`agentpin::wba`, built on
  `agentpin::httpsig`).
- **Key publication.** A signed `/.well-known/http-message-signatures-directory`,
  served by `agentpin-server` or generated with the CLI.
- **Identity binding.** An optional link from a WBA signature to an AgentPin
  credential, so a request recognized at the edge can also be attributed to
  a specific agent with its capabilities and constraints.

WBA uses its own keys. Your ES256 credential keys and credentials
are unchanged.

The normative rules are in §18 of the
[technical specification](../AGENTPIN_TECHNICAL_SPECIFICATION.md#18-web-bot-auth-binding-v04).
The implementation follows draft-ietf-webbotauth-httpsig-protocol-01 and
reproduces that draft's Ed25519 test vectors byte for byte and verifies its
RSA-PSS vectors. The Rust crate and the JavaScript, Python and Go SDKs all
run the same vectors from `testdata/web_bot_auth/vectors.json`.

## 1. Create a key and publish it

```bash
agentpin wba keygen --name crawler-2026-11 --output-dir ./keys
# prints the keyid, e.g. zVNvvSRgA8AfRNkV0kROlFxvl8ICcm-w3GrE3lpJEWI
```

This writes `keys/crawler-2026-11.ed25519.pem` (mode 0600) and prints the
key's `keyid`: its JWK thumbprint.

Serve the key directory. `agentpin-server` signs the directory response with
each key, as the draft recommends:

```bash
agentpin-server \
  --discovery agent-identity.json \
  --wba-key keys/crawler-2026-11.ed25519.pem
```

The directory is answered only for the discovery entity's host, plus any
host added with `--wba-authority`. The response's possession proof covers
the request authority, so signing for any `Host` a client sends would let
others mint proofs for domains that are not yours.

`agentpin wba keygen` makes Ed25519 keys, which the draft's examples and
most deployments use. To sign with RSA instead (`rsa-pss-sha512`), bring a
2048 to 4096-bit key in PKCS#8 or PKCS#1 PEM and use it anywhere a key is
accepted:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 -out keys/crawler-rsa.pem
```

Keys with the RSASSA-PSS algorithm identifier (`openssl genpkey -algorithm
RSA-PSS`) are not accepted; use a plain RSA key.

To host the directory elsewhere, print it and serve it with media type
`application/http-message-signatures-directory+json`:

```bash
agentpin wba directory --key keys/crawler-2026-11.ed25519.pem
```

To rotate, add the new key alongside the old one (repeat `--wba-key`), switch
signing to it, then remove the old key.

## 2. Sign requests

```rust
use agentpin::httpsig::HttpRequest;
use agentpin::wba::{self, SignOptions};

let key = wba::load_signing_key(&std::fs::read_to_string("keys/crawler-2026-11.ed25519.pem")?)?;
let mut req = HttpRequest::new("GET", "https://shop.example/products")?;
wba::sign_request(
    &req,
    &key,
    "https://example.com/.well-known/http-message-signatures-directory",
    &SignOptions::default(),
)?
.apply(&mut req);

// Send req.headers with your HTTP client.
```

By default the signature covers `@authority`, the `Signature-Agent` member,
`@method` and `@path`. It is valid for 5 minutes and carries a random nonce.
Add components with `SignOptions::components`. To cover individual query
parameters, add `Component::query_param("q")`, or pass `--query-param q` to
the CLI. This survives intermediaries reordering the query string, which
`@target-uri` and `@query` do not.

From the shell:

```bash
agentpin wba sign \
  --key keys/crawler-2026-11.ed25519.pem \
  --signature-agent https://example.com/.well-known/http-message-signatures-directory \
  --url https://shop.example/products
```

### Legacy `Signature-Agent`

The draft requires `Signature-Agent` as a Dictionary
(`sig1="https://…"`). Verifiers built against earlier drafts expect a bare
String (`"https://…"`). Set `SignOptions::legacy_signature_agent`, or pass
`--legacy-signature-agent`, for those. For example, Cloudflare's public
demo at `http-message-signatures-example.research.cloudflare.com` accepted
only the legacy form when tested on 2026-11-04, while Cloudflare's current
reference code accepts both.

## 3. Verify requests

```rust
use agentpin::wba::{VerifyOptions, WbaOutcome};
use agentpin::resolver_wba::{verify_request_async, CachingDirectoryResolver};

let directories = CachingDirectoryResolver::default();   // `fetch` feature
match verify_request_async(&req, &directories, &VerifyOptions::default()).await {
    WbaOutcome::Verified(agent) => { /* agent.signature_agent, agent.keyid */ }
    WbaOutcome::Invalid(reason) => { /* reject */ }
    WbaOutcome::Unverified(reason) => { /* no signature, or directory unavailable */ }
}
```

The three outcomes follow the draft's guidance. *Invalid* means a check
failed. *Unverified* means there was no signature, or there was not enough
information to decide, for example because the directory could not be
fetched. Treat *unverified* as its own signal, not as a failure.

Notes on `CachingDirectoryResolver`:

- It looks keys up by the (directory URL, keyid) pair.
- Directory fetches use `https` only and never follow redirects.
- It refuses hosts that resolve to private or loopback addresses.
- Response size, key count and fetch time are capped.
- A directory is cached according to its `Cache-Control: max-age`.
- If a refetch fails, the cached copy is kept.
- Set `require_proof` to accept only keys that carry a valid directory
  signature.

For offline or pre-provisioned keys, use `DirectoryKeyStore` with the
synchronous `verify_request`.

For replay protection, set a nonce store. Each verified signature's
`(keyid, nonce)` pair is recorded until the signature expires. A repeat, or
a signature without a nonce, is *invalid*. Nonces are recorded only after
the signature verifies, so forged requests cannot fill the store.

```rust
use std::sync::Arc;
use agentpin::nonce::InMemoryNonceStore;

let opts = VerifyOptions {
    nonce_store: Some(Arc::new(InMemoryNonceStore::new())),
    ..Default::default()
};
```

Use a shared store implementing `agentpin::nonce::NonceStore` when several
verifier instances sit behind one origin.

## 4. Bind WBA to an AgentPin identity

A WBA signature tells an origin which key directory a request came from.
Binding it to an AgentPin credential adds which agent sent it, under which
domain, with which capabilities.

**Issuer.** Put the WBA `keyid` in the credential's `cnf.jkt`:

```bash
agentpin issue --private-key es256.pem --kid example-2026-01 \
  --issuer example.com --agent-id urn:agentpin:example.com:crawler \
  --capabilities read:pages \
  --wba-jkt zVNvvSRgA8AfRNkV0kROlFxvl8ICcm-w3GrE3lpJEWI
```

In Rust, use `credential::issue_bound_credential`.

If the key directory is not at the issuer's own well-known URL, list it in
the discovery document:

```json
"web_bot_auth": {
  "signature_agents": ["https://bots.provider.example/keys/example-com"]
}
```

**Agent.** Send the credential as `Authorization: AgentPin <jwt>`, and cover
`authorization` in the signature:

```rust
let mut req = HttpRequest::new("GET", url)?
    .header("Authorization", &agentpin::transport::http::format_authorization_header(&jwt));
let mut opts = SignOptions::default();
opts.components.push(agentpin::httpsig::Component::new("authorization"));
wba::sign_request(&req, &key, directory_url, &opts)?.apply(&mut req);
```

**Verifier.** `wba::verify_bound_request` verifies the WBA signature and the
credential, then checks the binding. Async code can verify each part itself
and call `wba::check_binding`. A request is bound only when all of the
following hold:

- the WBA signature verifies;
- the credential verifies;
- the signature covers `authorization`;
- `cnf.jkt` equals the signature's `keyid`;
- the issuer's discovery document vouches for the `Signature-Agent` URL.

Any other result is a `BindingFailure` that says which part failed.

## JavaScript, Python and Go

Every SDK implements the same protocol and passes the same vectors. The
names follow each language's conventions:

| | JavaScript (`agentpin/wba`) | Python (`agentpin`) | Go (`pkg/wba`) |
|---|---|---|---|
| Load a key | `loadSigningKey(pem)` | `load_signing_key(pem)` | `wba.LoadSigningKey(pem)` |
| Sign | `signRequest(req, key, url, opts)` | `sign_request(req, key, url, opts)` | `wba.SignRequest(req, key, url, opts)` |
| Verify | `await verifyRequest(req, keys, opts)` | `verify_request(req, keys, opts)` | `wba.VerifyRequest(req, keys, opts)` |
| Fetch directories | `CachingDirectoryResolver` | `CachingDirectoryResolver` | `wba.NewCachingDirectoryResolver` |
| Replay protection | `opts.nonceStore` | `VerifyOptions.nonce_store` | `VerifyOptions.NonceStore` |
| Binding | `verifyBoundRequest` | `verify_bound_request` | `wba.VerifyBoundRequest` |
| Bound credential | `issueBoundCredential` | `issue_bound_credential` | `credential.IssueBoundCredential` |

Only Rust and JavaScript need an async key lookup. Python and Go fetch
directories synchronously, so their resolver plugs straight into the normal
verify call. The Go CLI has the same `agentpin wba` commands and
`issue --wba-jkt` as the Rust CLI. See each SDK's README for a full example.

## Scope

- HTTP signature algorithms are `ed25519` and `rsa-pss-sha512`. Shared-key
  HMAC is excluded by the draft, and ECDSA is not used by WBA deployments.
- Supported components are `@method`, `@target-uri`, `@authority`,
  `@scheme`, `@request-target`, `@path`, `@query`, `@query-param`,
  `@status` and HTTP fields, with the `key`, `req` and `name` parameters.
  Signatures using the `sf`, `bs` or `tr` parameters are rejected.
