use axum::http::{header::HeaderName, HeaderValue};
use tower_http::set_header::SetResponseHeaderLayer;

/// Create security header layers for the server.
pub fn security_headers() -> Vec<SetResponseHeaderLayer<HeaderValue>> {
    vec![
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-content-type-options"),
            HeaderValue::from_static("nosniff"),
        ),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("x-frame-options"),
            HeaderValue::from_static("DENY"),
        ),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("strict-transport-security"),
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ),
        SetResponseHeaderLayer::overriding(
            HeaderName::from_static("content-security-policy"),
            HeaderValue::from_static("default-src 'none'"),
        ),
    ]
}
