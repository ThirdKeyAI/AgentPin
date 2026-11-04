//! Web Bot Auth key directory resolution over HTTPS (`fetch` feature).
//!
//! The `Signature-Agent` URL comes from the client, so every fetch is
//! hardened against SSRF (draft §6.7): https only, no redirects, non-public
//! addresses refused, bounded time, bytes and key count. A resolved
//! directory replaces the cached copy; a failed fetch never evicts it, so a
//! directory outage does not revoke an agent's keys (§6.10).

#![cfg(feature = "fetch")]

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use chrono::Utc;
use ed25519_dalek::VerifyingKey;

use crate::error::Error;
use crate::httpsig::HttpRequest;
use crate::net::{fetch_bounded, FetchOptions};
use crate::wba::{
    self, candidates, find_key, finish, normalize_signature_agent, worse, Directory, VerifyOptions,
    WbaOutcome,
};

/// Options for directory fetching.
#[derive(Debug, Clone)]
pub struct DirectoryFetchOptions {
    /// Timeout and byte cap (default 10 s, 64 KiB).
    pub fetch: FetchOptions,
    /// Refuse hosts that are or resolve to non-public addresses (default
    /// true). Only disable for tests against local servers.
    pub public_only: bool,
    /// Require `https` URLs (default true). Only disable for tests.
    pub require_https: bool,
    /// Keep only keys with a valid directory response signature
    /// (Appendix B.1). Default false: a directory the verifier resolved
    /// itself is usable without proof (§B.1).
    pub require_proof: bool,
    /// Cache lifetime when the response has no usable `max-age`.
    pub default_ttl: Duration,
    /// Bounds applied to `max-age`.
    pub min_ttl: Duration,
    pub max_ttl: Duration,
}

impl Default for DirectoryFetchOptions {
    fn default() -> Self {
        Self {
            fetch: FetchOptions {
                max_bytes: 64 * 1024,
                ..FetchOptions::default()
            },
            public_only: true,
            require_https: true,
            require_proof: false,
            default_ttl: Duration::from_secs(3600),
            min_ttl: Duration::from_secs(60),
            max_ttl: Duration::from_secs(86_400),
        }
    }
}

fn max_age(headers: &[(String, String)]) -> Option<u64> {
    let cc = crate::httpsig::combined_field(headers, "cache-control")?;
    cc.split(',').find_map(|d| {
        let (k, v) = d.trim().split_once('=')?;
        if k.trim().eq_ignore_ascii_case("max-age") {
            v.trim().parse().ok()
        } else {
            None
        }
    })
}

/// Fetch and parse the key directory at `url`. Returns the directory and
/// how long it may be cached.
pub async fn fetch_directory(
    url: &str,
    opts: &DirectoryFetchOptions,
) -> Result<(Directory, Duration), Error> {
    let parsed =
        url::Url::parse(url).map_err(|_| Error::Transport("invalid directory URL".into()))?;
    if opts.require_https && parsed.scheme() != "https" {
        return Err(Error::Transport(format!("Directory {} is not https", url)));
    }
    let resp = fetch_bounded(
        url,
        &format!(
            "{}, application/jwk-set+json, application/json",
            wba::DIRECTORY_MEDIA_TYPE
        ),
        &opts.fetch,
        opts.public_only,
    )
    .await?;
    if resp.status != 200 {
        return Err(Error::Transport(format!(
            "HTTP {} fetching {}",
            resp.status, url
        )));
    }
    let directory = if opts.require_proof {
        let authority = match parsed.port() {
            Some(p) => format!("{}:{}", parsed.host_str().unwrap_or_default(), p),
            None => parsed.host_str().unwrap_or_default().to_string(),
        };
        wba::verify_directory_response(
            &resp.body,
            &resp.headers,
            &authority,
            Utc::now().timestamp(),
            60,
        )?
    } else {
        Directory::parse(&resp.body)?
    };
    let ttl = max_age(&resp.headers)
        .map(Duration::from_secs)
        .unwrap_or(opts.default_ttl)
        .clamp(opts.min_ttl, opts.max_ttl);
    Ok((directory, ttl))
}

/// Async equivalent of [`wba::KeyLookup`].
#[allow(clippy::double_must_use)]
#[async_trait::async_trait]
pub trait AsyncKeyLookup: Send + Sync {
    async fn lookup(
        &self,
        signature_agent: &str,
        keyid: &str,
    ) -> Result<Option<VerifyingKey>, Error>;
}

struct Cached {
    directory: Directory,
    fresh_until: Instant,
}

/// Fetches directories on demand and caches them per URL.
pub struct CachingDirectoryResolver {
    opts: DirectoryFetchOptions,
    cache: Mutex<HashMap<String, Cached>>,
}

impl CachingDirectoryResolver {
    pub fn new(opts: DirectoryFetchOptions) -> Self {
        Self {
            opts,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cached(&self, url: &str, fresh_only: bool) -> Option<Directory> {
        let cache = self.cache.lock().ok()?;
        let c = cache.get(url)?;
        (!fresh_only || c.fresh_until > Instant::now()).then(|| c.directory.clone())
    }
}

impl Default for CachingDirectoryResolver {
    fn default() -> Self {
        Self::new(DirectoryFetchOptions::default())
    }
}

#[async_trait::async_trait]
impl AsyncKeyLookup for CachingDirectoryResolver {
    async fn lookup(
        &self,
        signature_agent: &str,
        keyid: &str,
    ) -> Result<Option<VerifyingKey>, Error> {
        // Verified requests always pass a normalized https URL; plain URLs
        // are only reachable with `require_https` off (tests).
        let url = if self.opts.require_https {
            normalize_signature_agent(signature_agent)?
        } else {
            signature_agent.to_string()
        };
        let now = Utc::now().timestamp();
        if let Some(dir) = self.cached(&url, true) {
            if let Some(k) = find_key(&dir, keyid, now, 60) {
                return Ok(Some(k));
            }
        }
        match fetch_directory(&url, &self.opts).await {
            Ok((directory, ttl)) => {
                let key = find_key(&directory, keyid, now, 60);
                if let Ok(mut cache) = self.cache.lock() {
                    cache.insert(
                        url,
                        Cached {
                            directory,
                            fresh_until: Instant::now() + ttl,
                        },
                    );
                }
                Ok(key)
            }
            // A failed fetch is not evidence: fall back to the last
            // resolved copy (§6.10).
            Err(e) => match self.cached(&url, false) {
                Some(dir) => Ok(find_key(&dir, keyid, now, 60)),
                None => Err(e),
            },
        }
    }
}

/// Async equivalent of [`wba::verify_request`].
pub async fn verify_request_async(
    req: &HttpRequest,
    keys: &dyn AsyncKeyLookup,
    opts: &VerifyOptions,
) -> WbaOutcome {
    let now = opts.now.unwrap_or_else(|| Utc::now().timestamp());
    let (candidates, invalid) = match candidates(req, opts, now) {
        Ok(v) => v,
        Err(outcome) => return outcome,
    };
    let mut result = invalid.map(WbaOutcome::Invalid);
    for c in candidates {
        let key = keys.lookup(c.signature_agent(), c.keyid()).await;
        match finish(req, c, key) {
            v @ WbaOutcome::Verified(_) => return v,
            failure => result = worse(result, failure),
        }
    }
    result.unwrap_or_else(|| WbaOutcome::Unverified("no usable signature".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wba::{generate_signing_key, sign_directory_response, sign_request, SignOptions};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// HTTP/1.1 server; `respond` builds the canned response from the
    /// directory URL. Counts connections.
    fn serve_with(respond: impl FnOnce(&str) -> Vec<u8>) -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!(
            "http://{}{}",
            listener.local_addr().unwrap(),
            wba::DIRECTORY_PATH
        );
        let response = respond(&url);
        let hits = Arc::new(AtomicUsize::new(0));
        let h = hits.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                h.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(&response);
            }
        });
        (url, hits)
    }

    fn serve(response: Vec<u8>) -> (String, Arc<AtomicUsize>) {
        serve_with(|_| response)
    }

    fn http(status: &str, headers: &[(String, String)], body: &[u8]) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {}\r\n", status).into_bytes();
        for (k, v) in headers {
            out.extend_from_slice(format!("{}: {}\r\n", k, v).as_bytes());
        }
        out.extend_from_slice(
            format!(
                "Content-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .as_bytes(),
        );
        out.extend_from_slice(body);
        out
    }

    fn local_opts() -> DirectoryFetchOptions {
        DirectoryFetchOptions {
            public_only: false,
            require_https: false,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn fetches_signed_directory_and_caches_it() {
        let key = generate_signing_key();
        let body = Directory::from_keys([&key.verifying_key()])
            .to_json()
            .unwrap();
        let (url, hits) = serve_with(|url| {
            let u = url::Url::parse(url).unwrap();
            let authority = format!("{}:{}", u.host_str().unwrap(), u.port().unwrap());
            let mut headers = sign_directory_response(
                &body,
                &authority,
                std::slice::from_ref(&key),
                Utc::now().timestamp(),
                3600,
            )
            .unwrap();
            headers.push(("Content-Type".into(), wba::DIRECTORY_MEDIA_TYPE.into()));
            headers.push(("Cache-Control".into(), "max-age=600".into()));
            http("200 OK", &headers, &body)
        });

        let opts = DirectoryFetchOptions {
            require_proof: true,
            ..local_opts()
        };
        let (dir, ttl) = fetch_directory(&url, &opts).await.unwrap();
        assert_eq!(dir.keys.len(), 1);
        assert_eq!(ttl, Duration::from_secs(600));

        let resolver = CachingDirectoryResolver::new(local_opts());
        let tp = wba::thumbprint(&key.verifying_key());
        hits.store(0, Ordering::SeqCst);
        assert_eq!(
            resolver.lookup(&url, &tp).await.unwrap(),
            Some(key.verifying_key())
        );
        assert_eq!(
            resolver.lookup(&url, &tp).await.unwrap(),
            Some(key.verifying_key())
        );
        assert_eq!(hits.load(Ordering::SeqCst), 1, "second lookup is cached");
        // A key the directory does not publish: resolved, not found.
        let other = wba::thumbprint(&generate_signing_key().verifying_key());
        assert_eq!(resolver.lookup(&url, &other).await.unwrap(), None);
    }

    /// A failed refetch keeps the cached directory instead of evicting it.
    #[tokio::test]
    async fn failed_fetch_keeps_cached_directory() {
        let key = generate_signing_key();
        let tp = wba::thumbprint(&key.verifying_key());
        let resolver = CachingDirectoryResolver::new(local_opts());
        let url = "http://127.0.0.1:9/.well-known/http-message-signatures-directory";
        resolver.cache.lock().unwrap().insert(
            url.to_string(),
            Cached {
                directory: Directory::from_keys([&key.verifying_key()]),
                fresh_until: Instant::now(),
            },
        );
        assert_eq!(
            resolver.lookup(url, &tp).await.unwrap(),
            Some(key.verifying_key())
        );
        let empty = CachingDirectoryResolver::new(local_opts());
        assert!(empty.lookup(url, &tp).await.is_err());
    }

    #[tokio::test]
    async fn refuses_unsafe_directories() {
        let body = b"{\"keys\":[]}".to_vec();
        let (url, _) = serve(http(
            "302 Found",
            &[("Location".into(), "http://127.0.0.1:9/".into())],
            &body,
        ));
        assert!(fetch_directory(&url, &local_opts()).await.is_err());

        let (url, _) = serve(http("404 Not Found", &[], &body));
        assert!(fetch_directory(&url, &local_opts()).await.is_err());

        // Default options: http and loopback are refused before connecting.
        let (url, hits) = serve(http("200 OK", &[], &body));
        assert!(fetch_directory(&url, &DirectoryFetchOptions::default())
            .await
            .is_err());
        let https_opts = DirectoryFetchOptions {
            require_https: false,
            ..Default::default()
        };
        assert!(fetch_directory(&url, &https_opts).await.is_err());
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        // require_proof drops unsigned keys.
        let key = generate_signing_key();
        let body = Directory::from_keys([&key.verifying_key()])
            .to_json()
            .unwrap();
        let (url, _) = serve(http(
            "200 OK",
            &[(
                "Content-Digest".into(),
                crate::httpsig::content_digest(&body),
            )],
            &body,
        ));
        let opts = DirectoryFetchOptions {
            require_proof: true,
            ..local_opts()
        };
        assert!(fetch_directory(&url, &opts)
            .await
            .unwrap()
            .0
            .keys
            .is_empty());
    }

    struct Fixed(Option<VerifyingKey>);

    #[async_trait::async_trait]
    impl AsyncKeyLookup for Fixed {
        async fn lookup(&self, _: &str, _: &str) -> Result<Option<VerifyingKey>, Error> {
            Ok(self.0)
        }
    }

    #[tokio::test]
    async fn async_verify_matches_sync_outcomes() {
        let key = generate_signing_key();
        let mut req = HttpRequest::new("GET", "https://origin.example/").unwrap();
        sign_request(
            &req,
            &key,
            "https://agent.example/.well-known/http-message-signatures-directory",
            &SignOptions::default(),
        )
        .unwrap()
        .apply(&mut req);
        let opts = VerifyOptions::default();
        assert!(matches!(
            verify_request_async(&req, &Fixed(Some(key.verifying_key())), &opts).await,
            WbaOutcome::Verified(_)
        ));
        assert!(matches!(
            verify_request_async(&req, &Fixed(None), &opts).await,
            WbaOutcome::Unverified(_)
        ));
        assert!(matches!(
            verify_request_async(
                &req,
                &Fixed(Some(generate_signing_key().verifying_key())),
                &opts
            )
            .await,
            WbaOutcome::Invalid(_)
        ));
    }

    #[test]
    fn parses_max_age() {
        let h = vec![(
            "Cache-Control".to_string(),
            "public, max-age=120".to_string(),
        )];
        assert_eq!(max_age(&h), Some(120));
        assert_eq!(max_age(&[]), None);
    }
}
