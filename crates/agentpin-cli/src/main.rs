mod bundle;
mod issue;
mod keygen;
mod verify;
mod wba;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "agentpin", about = "AgentPin credential management CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new ECDSA P-256 keypair
    Keygen(keygen::KeygenArgs),
    /// Issue an agent credential (JWT)
    Issue(issue::IssueArgs),
    /// Verify an agent credential
    Verify(verify::VerifyArgs),
    /// Create a trust bundle from discovery and revocation documents
    Bundle(bundle::BundleArgs),
    /// Web Bot Auth: Ed25519 keys, key directories, request signing
    Wba(wba::WbaArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen(args) => keygen::run(args)?,
        Commands::Issue(args) => issue::run(args)?,
        Commands::Verify(args) => verify::run(args).await?,
        Commands::Bundle(args) => bundle::run(args)?,
        Commands::Wba(args) => wba::run(args)?,
    }
    Ok(())
}
