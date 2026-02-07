use std::fs;
use std::path::Path;

use clap::Args;

use agentpin::crypto;
use agentpin::jwk::pem_to_jwk;

#[derive(Args)]
pub struct KeygenArgs {
    /// Domain this key is associated with
    #[arg(long)]
    pub domain: String,

    /// Key identifier (e.g., "example-2026-01")
    #[arg(long)]
    pub kid: String,

    /// Output directory for key files
    #[arg(long, default_value = ".")]
    pub output_dir: String,

    /// Output format
    #[arg(long, default_value = "both", value_parser = ["jwk", "pem", "both"])]
    pub format: String,
}

pub fn run(args: KeygenArgs) -> anyhow::Result<()> {
    let kp = crypto::generate_key_pair()?;

    let out_dir = Path::new(&args.output_dir);
    fs::create_dir_all(out_dir)?;

    let wrote_private_pem;
    let wrote_public_pem;
    let wrote_public_jwk;

    match args.format.as_str() {
        "pem" => {
            let priv_path = out_dir.join(format!("{}.private.pem", args.kid));
            fs::write(&priv_path, &kp.private_key_pem)?;
            wrote_private_pem = Some(priv_path);

            let pub_path = out_dir.join(format!("{}.public.pem", args.kid));
            fs::write(&pub_path, &kp.public_key_pem)?;
            wrote_public_pem = Some(pub_path);
            wrote_public_jwk = None;
        }
        "jwk" => {
            let priv_path = out_dir.join(format!("{}.private.pem", args.kid));
            fs::write(&priv_path, &kp.private_key_pem)?;
            wrote_private_pem = Some(priv_path);

            let jwk = pem_to_jwk(&kp.public_key_pem, &args.kid)?;
            let jwk_json = serde_json::to_string_pretty(&jwk)?;
            let jwk_path = out_dir.join(format!("{}.public.jwk.json", args.kid));
            fs::write(&jwk_path, &jwk_json)?;
            wrote_public_jwk = Some(jwk_path);
            wrote_public_pem = None;
        }
        _ => {
            let priv_path = out_dir.join(format!("{}.private.pem", args.kid));
            fs::write(&priv_path, &kp.private_key_pem)?;
            wrote_private_pem = Some(priv_path);

            let pub_path = out_dir.join(format!("{}.public.pem", args.kid));
            fs::write(&pub_path, &kp.public_key_pem)?;
            wrote_public_pem = Some(pub_path);

            let jwk = pem_to_jwk(&kp.public_key_pem, &args.kid)?;
            let jwk_json = serde_json::to_string_pretty(&jwk)?;
            let jwk_path = out_dir.join(format!("{}.public.jwk.json", args.kid));
            fs::write(&jwk_path, &jwk_json)?;
            wrote_public_jwk = Some(jwk_path);
        }
    }

    eprintln!(
        "Generated ECDSA P-256 keypair for domain '{}' (kid: '{}')",
        args.domain, args.kid
    );
    if let Some(p) = wrote_private_pem {
        eprintln!("  Private key: {}", p.display());
    }
    if let Some(p) = wrote_public_pem {
        eprintln!("  Public key (PEM): {}", p.display());
    }
    if let Some(p) = wrote_public_jwk {
        eprintln!("  Public key (JWK): {}", p.display());
    }

    Ok(())
}
