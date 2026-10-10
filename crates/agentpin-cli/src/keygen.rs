use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use clap::Args;

use agentpin::crypto;
use agentpin::jwk::pem_to_jwk;

#[derive(Args)]
pub struct KeygenArgs {
    /// Domain this key is associated with
    #[arg(long)]
    pub domain: String,

    /// Key identifier (e.g., "example-2026-01"); letters, digits, '.', '_'
    /// and '-' only
    #[arg(long)]
    pub kid: String,

    /// Output directory for key files
    #[arg(long, default_value = ".")]
    pub output_dir: String,

    /// Output format
    #[arg(long, default_value = "both", value_parser = ["jwk", "pem", "both"])]
    pub format: String,

    /// Overwrite existing key files (by default an existing file is an error)
    #[arg(long)]
    pub force: bool,
}

/// A key id is used as a file name component; it must never be able to
/// escape --output-dir or collide with path syntax (AP-16).
pub fn validate_kid(kid: &str) -> anyhow::Result<()> {
    let ok = !kid.is_empty()
        && kid.len() <= 128
        && kid != "."
        && kid != ".."
        && !kid.contains("..")
        && kid
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-')
        && kid
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphanumeric());
    if !ok {
        anyhow::bail!(
            "invalid --kid '{}': use letters, digits, '.', '_' and '-' only (no path separators)",
            kid
        );
    }
    Ok(())
}

/// Create `path` with `mode`, refusing to overwrite unless `force`. The mode
/// is applied at creation (so a 0600 private key is never world-readable
/// even for an instant) and re-applied after an overwrite.
fn write_new_file(path: &Path, contents: &[u8], mode: u32, force: bool) -> anyhow::Result<()> {
    let mut opts = fs::OpenOptions::new();
    opts.write(true);
    if force {
        opts.create(true).truncate(true);
    } else {
        opts.create_new(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(mode);
    }
    let mut file = opts.open(path).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            anyhow::anyhow!(
                "{} already exists; pass --force to overwrite",
                path.display()
            )
        } else {
            anyhow::anyhow!("cannot create {}: {}", path.display(), e)
        }
    })?;
    file.write_all(contents)?;
    file.sync_all()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))?;
    }
    #[cfg(not(unix))]
    {
        let _ = mode;
    }
    Ok(())
}

pub fn run(args: KeygenArgs) -> anyhow::Result<()> {
    validate_kid(&args.kid)?;
    let kp = crypto::generate_key_pair()?;

    let out_dir = Path::new(&args.output_dir);
    fs::create_dir_all(out_dir)?;

    let priv_path = out_dir.join(format!("{}.private.pem", args.kid));
    write_new_file(&priv_path, kp.private_key_pem.as_bytes(), 0o600, args.force)?;
    let wrote_private_pem: Option<PathBuf> = Some(priv_path);

    let mut wrote_public_pem: Option<PathBuf> = None;
    let mut wrote_public_jwk: Option<PathBuf> = None;

    if args.format == "pem" || args.format == "both" {
        let pub_path = out_dir.join(format!("{}.public.pem", args.kid));
        write_new_file(&pub_path, kp.public_key_pem.as_bytes(), 0o644, args.force)?;
        wrote_public_pem = Some(pub_path);
    }
    if args.format == "jwk" || args.format == "both" {
        let jwk = pem_to_jwk(&kp.public_key_pem, &args.kid)?;
        let jwk_json = serde_json::to_string_pretty(&jwk)?;
        let jwk_path = out_dir.join(format!("{}.public.jwk.json", args.kid));
        write_new_file(&jwk_path, jwk_json.as_bytes(), 0o644, args.force)?;
        wrote_public_jwk = Some(jwk_path);
    }

    eprintln!(
        "Generated ECDSA P-256 keypair for domain '{}' (kid: '{}')",
        args.domain, args.kid
    );
    if let Some(p) = wrote_private_pem {
        eprintln!("  Private key: {} (mode 0600)", p.display());
    }
    if let Some(p) = wrote_public_pem {
        eprintln!("  Public key (PEM): {}", p.display());
    }
    if let Some(p) = wrote_public_jwk {
        eprintln!("  Public key (JWK): {}", p.display());
    }

    Ok(())
}
