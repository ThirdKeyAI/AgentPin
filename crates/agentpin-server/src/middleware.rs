use axum::http::{header::HeaderName, HeaderValue};
use tower_http::set_header::SetResponseHeaderLayer;

/// Create security header layers for the server.
///
/// HSTS is only added when `hsts` is set: the listener itself is plaintext,
/// so the header is meaningful only behind a TLS-terminating proxy (AP-23).
pub fn security_headers(hsts: bool) -> Vec<SetResponseHeaderLayer<HeaderValue>> {
    let mut layers = vec![
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'none'"),
        ),
    ];
    if hsts {
        layers.push(SetResponseHeaderLayer::overriding(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ));
    }
    layers
}
