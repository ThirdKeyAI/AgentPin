use std::fs;

use clap::Args;

use agentpin::credential::issue_credential;
use agentpin::crypto;
use agentpin::types::capability::Capability;
use agentpin::types::constraint::Constraints;
use agentpin::types::credential::DelegationAttestation;

#[derive(Args)]
pub struct IssueArgs {
    /// Path to private key PEM file
    #[arg(long)]
    pub private_key: String,

    /// Key identifier
    #[arg(long)]
    pub kid: String,

    /// Issuer domain
    #[arg(long)]
    pub issuer: String,

    /// Agent URN (e.g., "urn:agentpin:example.com:my-agent")
    #[arg(long)]
    pub agent_id: String,

    /// Audience domain (optional)
    #[arg(long)]
    pub audience: Option<String>,

    /// Comma-separated capabilities (e.g., "read:data,write:reports")
    #[arg(long)]
    pub capabilities: String,

    /// Credential TTL in seconds
    #[arg(long, default_value = "3600")]
    pub ttl: u64,

    /// JSON file with delegation chain entries
    #[arg(long)]
    pub delegation_chain: Option<String>,

    /// JSON string with constraint overrides (literal; use --constraints-file for a file)
    #[arg(long, conflicts_with = "constraints_file")]
    pub constraints: Option<String>,

    /// Path to a JSON file with constraint overrides
    #[arg(long, conflicts_with = "constraints")]
    pub constraints_file: Option<String>,
}

pub fn run(args: IssueArgs) -> anyhow::Result<()> {
    let pem = fs::read_to_string(&args.private_key)?;
    let signing_key = crypto::load_signing_key(&pem)?;

    let capabilities: Vec<Capability> = args
        .capabilities
        .split(',')
        .map(|s| Capability::from(s.trim()))
        .collect();

    // --constraints is always literal JSON and --constraints-file always a
    // path (AP-23).
    let constraints: Option<Constraints> = match (&args.constraints, &args.constraints_file) {
        (Some(json), None) => Some(serde_json::from_str(json)?),
        (None, Some(path)) => Some(serde_json::from_str(&fs::read_to_string(path)?)?),
        (None, None) => None,
        _ => anyhow::bail!("use only one of --constraints or --constraints-file"),
    };

    let delegation_chain: Option<Vec<DelegationAttestation>> = match &args.delegation_chain {
        Some(path) => {
            let json = fs::read_to_string(path)?;
            Some(serde_json::from_str(&json)?)
        }
        None => None,
    };

    let jwt = issue_credential(
        &signing_key,
        &args.kid,
        &args.issuer,
        &args.agent_id,
        args.audience.as_deref(),
        capabilities,
        constraints,
        delegation_chain,
        args.ttl,
    )?;

    println!("{}", jwt);
    Ok(())
}
