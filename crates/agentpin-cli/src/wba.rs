//! `agentpin wba`: Web Bot Auth keys, key directories and request signing.

use std::fs;
use std::path::Path;

use clap::{Args, Subcommand};

use agentpin::httpsig::{Component, HttpRequest};
use agentpin::wba::{self, Directory, SignOptions};

use crate::keygen::{validate_kid, write_new_file};

#[derive(Args)]
pub struct WbaArgs {
    #[command(subcommand)]
    pub command: WbaCommand,
}

#[derive(Subcommand)]
pub enum WbaCommand {
    /// Generate an Ed25519 signing key; prints its keyid (JWK thumbprint)
    Keygen(KeygenArgs),
    /// Print the key directory (JWK Set) for one or more keys
    Directory(DirectoryArgs),
    /// Sign a request and print the Signature-Agent, Signature-Input and
    /// Signature headers
    Sign(SignArgs),
}

#[derive(Args)]
pub struct KeygenArgs {
    /// File name stem for the key (letters, digits, '.', '_' and '-')
    #[arg(long)]
    pub name: String,

    /// Output directory
    #[arg(long, default_value = ".")]
    pub output_dir: String,

    /// Overwrite an existing key file
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct DirectoryArgs {
    /// Ed25519 private key PEM (repeat for rotation)
    #[arg(long = "key", required = true)]
    pub keys: Vec<String>,
}

#[derive(Args)]
pub struct SignArgs {
    /// Ed25519 private key PEM
    #[arg(long)]
    pub key: String,

    /// HTTPS URL of the key directory publishing this key
    #[arg(long)]
    pub signature_agent: String,

    /// Request URL
    #[arg(long)]
    pub url: String,

    /// Request method
    #[arg(long, default_value = "GET")]
    pub method: String,

    /// Header to send and cover, as "Name: value" (repeatable)
    #[arg(long = "header")]
    pub headers: Vec<String>,

    /// Signature lifetime in seconds (max 86400)
    #[arg(long, default_value = "300")]
    pub validity: i64,

    /// Send the legacy bare-String Signature-Agent, for verifiers that
    /// predate the Dictionary form
    #[arg(long)]
    pub legacy_signature_agent: bool,
}

fn load_key(path: &str) -> anyhow::Result<ed25519_dalek::SigningKey> {
    let pem = zeroize::Zeroizing::new(fs::read_to_string(path)?);
    wba::load_signing_key(&pem).map_err(|e| anyhow::anyhow!("{}: {}", path, e))
}

pub fn run(args: WbaArgs) -> anyhow::Result<()> {
    match args.command {
        WbaCommand::Keygen(a) => {
            validate_kid(&a.name)?;
            let key = wba::generate_signing_key();
            let out_dir = Path::new(&a.output_dir);
            fs::create_dir_all(out_dir)?;
            let path = out_dir.join(format!("{}.ed25519.pem", a.name));
            write_new_file(
                &path,
                wba::signing_key_to_pem(&key)?.as_bytes(),
                0o600,
                a.force,
            )?;
            eprintln!(
                "Generated Ed25519 Web Bot Auth key: {} (mode 0600)",
                path.display()
            );
            println!("{}", wba::thumbprint(&key.verifying_key()));
        }
        WbaCommand::Directory(a) => {
            let keys = a
                .keys
                .iter()
                .map(|p| load_key(p))
                .collect::<anyhow::Result<Vec<_>>>()?;
            let dir = Directory::from_keys(keys.iter().map(|k| k.as_ref()));
            println!("{}", serde_json::to_string_pretty(&dir)?);
        }
        WbaCommand::Sign(a) => {
            let key = load_key(&a.key)?;
            let mut req = HttpRequest::new(&a.method, &a.url)?;
            let mut opts = SignOptions {
                validity_secs: a.validity,
                legacy_signature_agent: a.legacy_signature_agent,
                ..Default::default()
            };
            for h in &a.headers {
                let (name, value) = h
                    .split_once(':')
                    .ok_or_else(|| anyhow::anyhow!("--header must be \"Name: value\""))?;
                let name = name.trim();
                req = req.header(name, value.trim());
                let c = Component::new(&name.to_ascii_lowercase());
                if !opts.components.contains(&c) {
                    opts.components.push(c);
                }
            }
            for (name, value) in wba::sign_request(&req, &key, &a.signature_agent, &opts)?.to_vec()
            {
                println!("{}: {}", name, value);
            }
        }
    }
    Ok(())
}
