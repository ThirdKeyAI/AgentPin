use clap::Parser;

#[derive(Parser)]
#[command(name = "agentpin-server", about = "AgentPin discovery endpoint server")]
pub struct ServerConfig {
    /// Path to discovery document JSON file
    #[arg(long)]
    pub discovery: String,

    /// Path to revocation document JSON file (optional)
    #[arg(long)]
    pub revocation: Option<String>,

    /// Bind address
    #[arg(long, default_value = "0.0.0.0")]
    pub bind: String,

    /// Port
    #[arg(long, default_value = "8080")]
    pub port: u16,

    /// Emit a Strict-Transport-Security header. This listener speaks
    /// plaintext HTTP; only enable HSTS when a TLS-terminating reverse proxy
    /// serves these endpoints under https (AP-23).
    #[arg(long)]
    pub hsts: bool,

    /// Ed25519 PKCS#8 PEM key to publish and sign with at
    /// /.well-known/http-message-signatures-directory (Web Bot Auth).
    /// Repeat for key rotation.
    #[arg(long = "wba-key")]
    pub wba_keys: Vec<String>,

    /// Extra host the key directory may be served under. The discovery
    /// entity is always allowed; requests for any other Host get 404, so the
    /// directory's possession proof cannot be minted for a foreign domain.
    #[arg(long = "wba-authority")]
    pub wba_authorities: Vec<String>,
}

impl ServerConfig {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
