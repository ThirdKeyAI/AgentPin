//! Hardened HTTP fetching shared by every network resolver (`fetch` feature).
//!
//! Every outbound request made by this crate goes through
//! [`fetch_json_bounded`], which enforces the network defaults the spec and
//! the security review require (AP-7, AP-12, AP-13):
//!
//! - redirects are never followed (a 3xx is a hard failure);
//! - a request timeout (default 10 s) bounds slowloris-style stalls;
//! - the response body is read with a hard byte cap (default 1 MiB), both
//!   from `Content-Length` and while streaming, so a hostile issuer cannot
//!   exhaust memory;
//! - the response must carry a JSON `Content-Type`;
//! - error strings are generic: they name the URL (derived from a normalized
//!   domain) and the failure class, never the transport error text.

#![cfg(feature = "fetch")]

use std::time::Duration;

use crate::error::Error;

/// Default request timeout.
pub const DEFAULT_TIMEOUT_SECS: u64 = 10;
/// Default maximum accepted response body size (1 MiB).
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1 << 20;

/// Options for [`fetch_json_bounded`].
#[derive(Debug, Clone)]
pub struct FetchOptions {
    /// Total request timeout.
    pub timeout: Duration,
    /// Maximum accepted response body size in bytes.
    pub max_bytes: usize,
}

impl Default for FetchOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(DEFAULT_TIMEOUT_SECS),
            max_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        }
    }
}

/// Build the shared client: no redirects, bounded timeout.
pub(crate) fn build_client(timeout: Duration) -> Result<reqwest::Client, Error> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .build()
        .map_err(|_| Error::Transport("HTTP client initialization failed".to_string()))
}

fn is_json_content_type(value: Option<&reqwest::header::HeaderValue>) -> bool {
    let Some(v) = value.and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let media = v
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    media == "application/json" || media.ends_with("+json")
}

/// GET `url` and return its body bytes, or `Ok(None)` on HTTP 404.
///
/// Rejects redirects, non-success statuses, non-JSON content types and
/// bodies larger than `opts.max_bytes`.
pub async fn fetch_json_bounded(url: &str, opts: &FetchOptions) -> Result<Option<Vec<u8>>, Error> {
    let client = build_client(opts.timeout)?;
    let resp = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/json")
        .send()
        .await
        .map_err(|_| Error::Transport(format!("Failed to fetch {}", url)))?;

    let status = resp.status();
    if status.is_redirection() {
        return Err(Error::Transport(format!(
            "Redirect rejected fetching {} (status {})",
            url,
            status.as_u16()
        )));
    }
    if status == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    if !status.is_success() {
        return Err(Error::Transport(format!(
            "HTTP {} fetching {}",
            status.as_u16(),
            url
        )));
    }
    if !is_json_content_type(resp.headers().get(reqwest::header::CONTENT_TYPE)) {
        return Err(Error::Transport(format!(
            "Response from {} is not application/json",
            url
        )));
    }
    if let Some(len) = resp.content_length() {
        if len > opts.max_bytes as u64 {
            return Err(Error::Transport(format!(
                "Response from {} exceeds {} bytes",
                url, opts.max_bytes
            )));
        }
    }

    let mut resp = resp;
    let mut body: Vec<u8> = Vec::new();
    loop {
        let chunk = resp
            .chunk()
            .await
            .map_err(|_| Error::Transport(format!("Failed to read response from {}", url)))?;
        let Some(chunk) = chunk else { break };
        if body.len() + chunk.len() > opts.max_bytes {
            return Err(Error::Transport(format!(
                "Response from {} exceeds {} bytes",
                url, opts.max_bytes
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

/// A response read by [`fetch_bounded`].
#[derive(Debug, Clone)]
pub struct FetchedResponse {
    pub status: u16,
    /// Header fields, lowercase names.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// `true` for addresses a server-side fetch driven by a client-supplied
/// URL must never reach: loopback, private, link-local, CGNAT, multicast,
/// documentation, unspecified and reserved ranges.
pub fn is_non_public(ip: std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                || (o[0] == 100 && (o[1] & 0xc0) == 64)
                || (o[0] == 192 && o[1] == 0 && o[2] == 0)
                || (o[0] == 198 && (o[1] & 0xfe) == 18)
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_non_public(IpAddr::V4(v4));
            }
            let s = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x0064 && s[1] == 0xff9b)
        }
    }
}

/// DNS resolver that drops non-public addresses (SSRF guard).
struct PublicOnlyResolver;

impl reqwest::dns::Resolve for PublicOnlyResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        Box::pin(async move {
            let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((name.as_str(), 0))
                .await?
                .filter(|a| !is_non_public(a.ip()))
                .collect();
            if addrs.is_empty() {
                return Err("host resolves only to non-public addresses".into());
            }
            Ok(Box::new(addrs.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

/// GET `url` with the same limits as [`fetch_json_bounded`] (no
/// redirects, timeout, byte cap) and return status, headers and body for
/// any non-redirect status. With `public_only`, hosts that are or resolve
/// to non-public addresses are refused.
pub async fn fetch_bounded(
    url: &str,
    accept: &str,
    opts: &FetchOptions,
    public_only: bool,
) -> Result<FetchedResponse, Error> {
    let parsed =
        url::Url::parse(url).map_err(|_| Error::Transport(format!("Invalid URL {}", url)))?;
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(opts.timeout);
    if public_only {
        let literal = match parsed.host() {
            Some(url::Host::Ipv4(ip)) => Some(std::net::IpAddr::V4(ip)),
            Some(url::Host::Ipv6(ip)) => Some(std::net::IpAddr::V6(ip)),
            _ => None,
        };
        if literal.is_some_and(is_non_public) {
            return Err(Error::Transport(format!(
                "Refusing to fetch non-public address {}",
                url
            )));
        }
        builder = builder.dns_resolver(std::sync::Arc::new(PublicOnlyResolver));
    }
    let client = builder
        .build()
        .map_err(|_| Error::Transport("HTTP client initialization failed".to_string()))?;
    let mut resp = client
        .get(url)
        .header(reqwest::header::ACCEPT, accept)
        .send()
        .await
        .map_err(|_| Error::Transport(format!("Failed to fetch {}", url)))?;

    let status = resp.status();
    if status.is_redirection() {
        return Err(Error::Transport(format!(
            "Redirect rejected fetching {} (status {})",
            url,
            status.as_u16()
        )));
    }
    if resp
        .content_length()
        .is_some_and(|l| l > opts.max_bytes as u64)
    {
        return Err(Error::Transport(format!(
            "Response from {} exceeds {} bytes",
            url, opts.max_bytes
        )));
    }
    let headers = resp
        .headers()
        .iter()
        .filter_map(|(k, v)| Some((k.as_str().to_string(), v.to_str().ok()?.to_string())))
        .collect();
    let mut body: Vec<u8> = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|_| Error::Transport(format!("Failed to read response from {}", url)))?
    {
        if body.len() + chunk.len() > opts.max_bytes {
            return Err(Error::Transport(format!(
                "Response from {} exceeds {} bytes",
                url, opts.max_bytes
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(FetchedResponse {
        status: status.as_u16(),
        headers,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;

    /// Minimal one-shot HTTP/1.1 server returning a canned response.
    fn serve_once(response: Vec<u8>) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut buf = [0u8; 4096];
                let _ = stream.read(&mut buf);
                let _ = stream.write_all(&response);
                let _ = stream.flush();
            }
        });
        format!("http://{}/doc.json", addr)
    }

    fn response(status: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
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

    #[tokio::test]
    async fn fetches_small_json_body() {
        let url = serve_once(response(
            "200 OK",
            &[("Content-Type", "application/json; charset=utf-8")],
            b"{\"a\":1}",
        ));
        let body = fetch_json_bounded(&url, &FetchOptions::default())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(body, b"{\"a\":1}");
    }

    /// AP-7 / AP-12: redirects are rejected, never followed.
    #[tokio::test]
    async fn rejects_redirect() {
        let url = serve_once(response(
            "302 Found",
            &[
                ("Location", "http://127.0.0.1:9/other"),
                ("Content-Type", "application/json"),
            ],
            b"{}",
        ));
        let err = fetch_json_bounded(&url, &FetchOptions::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("Redirect rejected"), "{}", err);
    }

    /// AP-13: oversized bodies are rejected by Content-Length ...
    #[tokio::test]
    async fn rejects_oversized_by_content_length() {
        let big = vec![b' '; 2048];
        let url = serve_once(response(
            "200 OK",
            &[("Content-Type", "application/json")],
            &big,
        ));
        let opts = FetchOptions {
            max_bytes: 1024,
            ..Default::default()
        };
        let err = fetch_json_bounded(&url, &opts)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("exceeds"), "{}", err);
    }

    /// ... and while streaming when no Content-Length is sent.
    #[tokio::test]
    async fn rejects_oversized_streamed_body() {
        let mut out = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n".to_vec();
        for _ in 0..4 {
            out.extend_from_slice(b"400\r\n");
            out.extend_from_slice(&vec![b'x'; 0x400]);
            out.extend_from_slice(b"\r\n");
        }
        out.extend_from_slice(b"0\r\n\r\n");
        let url = serve_once(out);
        let opts = FetchOptions {
            max_bytes: 1024,
            ..Default::default()
        };
        let err = fetch_json_bounded(&url, &opts)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("exceeds"), "{}", err);
    }

    /// AP-13: a non-JSON content type is rejected.
    #[tokio::test]
    async fn rejects_non_json_content_type() {
        let url = serve_once(response("200 OK", &[("Content-Type", "text/html")], b"{}"));
        let err = fetch_json_bounded(&url, &FetchOptions::default())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("not application/json"), "{}", err);
    }

    /// AP-13: the request times out instead of hanging forever.
    #[tokio::test]
    async fn times_out_on_stalled_server() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        std::thread::spawn(move || {
            if let Ok((_stream, _)) = listener.accept() {
                std::thread::sleep(Duration::from_secs(3));
            }
        });
        let url = format!("http://{}/doc.json", addr);
        let opts = FetchOptions {
            timeout: Duration::from_millis(300),
            ..Default::default()
        };
        let start = std::time::Instant::now();
        assert!(fetch_json_bounded(&url, &opts).await.is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn classifies_non_public_addresses() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "224.0.0.1",
            "240.0.0.1",
            "198.18.0.1",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
        ] {
            assert!(is_non_public(ip.parse().unwrap()), "{}", ip);
        }
        for ip in ["93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(!is_non_public(ip.parse().unwrap()), "{}", ip);
        }
    }

    #[tokio::test]
    async fn public_only_refuses_loopback() {
        let url = serve_once(response(
            "200 OK",
            &[("Content-Type", "application/json")],
            b"{}",
        ));
        let err = fetch_bounded(&url, "application/json", &FetchOptions::default(), true)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("non-public"), "{}", err);
        let ok = fetch_bounded(&url, "application/json", &FetchOptions::default(), false)
            .await
            .unwrap();
        assert_eq!(ok.status, 200);
        assert_eq!(ok.body, b"{}");
    }

    #[tokio::test]
    async fn not_found_is_none() {
        let url = serve_once(response(
            "404 Not Found",
            &[("Content-Type", "application/json")],
            b"{}",
        ));
        assert!(fetch_json_bounded(&url, &FetchOptions::default())
            .await
            .unwrap()
            .is_none());
    }

    /// Error strings never carry transport-level detail.
    #[tokio::test]
    async fn connection_errors_are_generic() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let url = format!("http://{}/doc.json", addr);
        let err = fetch_json_bounded(&url, &FetchOptions::default())
            .await
            .unwrap_err()
            .to_string();
        assert_eq!(err, format!("Transport error: Failed to fetch {}", url));
    }
}
