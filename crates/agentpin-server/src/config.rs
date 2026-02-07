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
}

impl ServerConfig {
    pub fn parse_args() -> Self {
        Self::parse()
    }
}
