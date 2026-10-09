use std::fs;

use clap::Args;

use agentpin::pinning::KeyPinStore;
use agentpin::resolver::{
    ChainResolver, DiscoveryResolver, LocalFileResolver, TrustBundleResolver,
};
use agentpin::types::bundle::TrustBundle;
use agentpin::types::discovery::DiscoveryDocument;
use agentpin::types::revocation::RevocationDocument;
use agentpin::verification::{
    verify_credential, verify_credential_offline, verify_credential_with_resolver, VerifierConfig,
};

#[derive(Args)]
pub struct VerifyArgs {
    /// JWT credential string or path to file containing it
    #[arg(long)]
    pub credential: String,

    /// Path to discovery document JSON file (for offline verification)
    #[arg(long)]
    pub discovery: Option<String>,

    /// Path to revocation document JSON file (for offline verification)
    #[arg(long)]
    pub revocation: Option<String>,

    /// Path to pin store JSON file
    #[arg(long)]
    pub pin_store: Option<String>,

    /// Verifier's audience domain
    #[arg(long)]
    pub audience: Option<String>,

    /// Use offline-only verification (no HTTP fetches)
    #[arg(long)]
    pub offline: bool,

    /// Path to a trust bundle JSON file for verification
    #[arg(long)]
    pub trust_bundle: Option<String>,

    /// Path to a directory containing discovery document files ({domain}.json)
    #[arg(long)]
    pub discovery_dir: Option<String>,
}

pub async fn run(args: VerifyArgs) -> anyhow::Result<()> {
    // Load credential — could be a JWT string or a file path
    let credential = if std::path::Path::new(&args.credential).exists() {
        fs::read_to_string(&args.credential)?.trim().to_string()
    } else {
        args.credential.clone()
    };

    // Load or create pin store
    let mut pin_store = match &args.pin_store {
        Some(path) if std::path::Path::new(path).exists() => {
            let json = fs::read_to_string(path)?;
            KeyPinStore::from_json(&json)?
        }
        _ => KeyPinStore::new(),
    };

    let config = VerifierConfig::default();

    let result = if args.trust_bundle.is_some() || args.discovery_dir.is_some() {
        // Resolver-based verification
        let resolver = build_resolver(&args)?;
        verify_credential_with_resolver(
            &credential,
            resolver.as_ref(),
            &mut pin_store,
            args.audience.as_deref(),
            &config,
        )
    } else if args.offline || args.discovery.is_some() {
        // Offline verification
        let discovery_path = args
            .discovery
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--discovery is required for offline verification"))?;
        let discovery_json = fs::read_to_string(discovery_path)?;
        let discovery: DiscoveryDocument = serde_json::from_str(&discovery_json)?;

        let revocation: Option<RevocationDocument> = match &args.revocation {
            Some(path) => {
                let json = fs::read_to_string(path)?;
                Some(serde_json::from_str(&json)?)
            }
            None => None,
        };

        verify_credential_offline(
            &credential,
            &discovery,
            revocation.as_ref(),
            &mut pin_store,
            args.audience.as_deref(),
            &config,
        )
    } else {
        // Online verification — fetch discovery/revocation from issuer domain
        verify_credential(
            &credential,
            &mut pin_store,
            args.audience.as_deref(),
            &config,
        )
        .await
    };

    let output = serde_json::to_string_pretty(&result)?;
    println!("{}", output);

    // Persist pin store if path was provided: write to a sibling temp file
    // with restrictive permissions and rename into place, so a crash can
    // never leave a truncated store and the file is not world-readable
    // (AP-16).
    if let Some(path) = &args.pin_store {
        let json = pin_store.to_json()?;
        write_atomic(std::path::Path::new(path), json.as_bytes(), 0o600)?;
    }

    if !result.valid {
        std::process::exit(1);
    }

    Ok(())
}

/// Write `contents` to `path` atomically (temp file + rename) with `mode`.
fn write_atomic(path: &std::path::Path, contents: &[u8], mode: u32) -> anyhow::Result<()> {
    use std::io::Write;
    let dir = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(std::path::Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow::anyhow!("invalid pin store path {}", path.display()))?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    let mut opts = fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    let result = (|| -> anyhow::Result<()> {
        let mut f = opts.open(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Build a sync resolver from the CLI flags.
fn build_resolver(args: &VerifyArgs) -> anyhow::Result<Box<dyn DiscoveryResolver>> {
    let mut resolvers: Vec<Box<dyn DiscoveryResolver>> = Vec::new();

    if let Some(ref path) = args.trust_bundle {
        let json = fs::read_to_string(path)?;
        let bundle: TrustBundle = serde_json::from_str(&json)?;
        resolvers.push(Box::new(TrustBundleResolver::new(&bundle)));
    }

    if let Some(ref dir) = args.discovery_dir {
        resolvers.push(Box::new(LocalFileResolver::new(
            std::path::Path::new(dir),
            None,
        )));
    }

    match resolvers.len() {
        0 => Err(anyhow::anyhow!(
            "At least --trust-bundle or --discovery-dir must be provided"
        )),
        1 => Ok(resolvers.remove(0)),
        _ => Ok(Box::new(ChainResolver::new(resolvers))),
    }
}
