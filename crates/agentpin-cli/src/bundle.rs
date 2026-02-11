use std::fs;

use chrono::Utc;
use clap::Args;

use agentpin::types::bundle::TrustBundle;
use agentpin::types::discovery::DiscoveryDocument;
use agentpin::types::revocation::RevocationDocument;

#[derive(Args)]
pub struct BundleArgs {
    /// Paths to discovery document JSON files to include
    #[arg(long = "discovery", num_args = 1..)]
    pub discovery_files: Vec<String>,

    /// Paths to revocation document JSON files to include
    #[arg(long = "revocation", num_args = 1..)]
    pub revocation_files: Vec<String>,

    /// Output path (default: stdout)
    #[arg(short, long)]
    pub output: Option<String>,
}

pub fn run(args: BundleArgs) -> anyhow::Result<()> {
    if args.discovery_files.is_empty() {
        anyhow::bail!("At least one --discovery file is required");
    }

    let mut bundle = TrustBundle::new(&Utc::now().to_rfc3339());

    for path in &args.discovery_files {
        let json = fs::read_to_string(path)?;
        let doc: DiscoveryDocument = serde_json::from_str(&json)
            .map_err(|e| anyhow::anyhow!("Invalid discovery document {}: {}", path, e))?;
        bundle.documents.push(doc);
    }

    for path in &args.revocation_files {
        let json = fs::read_to_string(path)?;
        let doc: RevocationDocument = serde_json::from_str(&json)
            .map_err(|e| anyhow::anyhow!("Invalid revocation document {}: {}", path, e))?;
        bundle.revocations.push(doc);
    }

    let output = serde_json::to_string_pretty(&bundle)?;

    match args.output {
        Some(path) => {
            fs::write(&path, &output)?;
            eprintln!("Trust bundle written to {}", path);
        }
        None => {
            println!("{}", output);
        }
    }

    Ok(())
}
