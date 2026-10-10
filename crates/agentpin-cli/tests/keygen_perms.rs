//! AP-16: `agentpin keygen` must create the private key with mode 0600,
//! refuse to overwrite an existing key unless --force, and reject key ids
//! that could escape --output-dir.

use std::process::Command;

fn keygen(dir: &std::path::Path, extra: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agentpin"))
        .arg("keygen")
        .arg("--domain")
        .arg("example.com")
        .arg("--output-dir")
        .arg(dir)
        .args(extra)
        .output()
        .expect("run agentpin keygen")
}

#[test]
#[cfg(unix)]
fn private_key_is_created_0600() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let out = keygen(dir.path(), &["--kid", "k1"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mode = std::fs::metadata(dir.path().join("k1.private.pem"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "private key mode {:o}", mode);
    assert!(dir.path().join("k1.public.pem").exists());
    assert!(dir.path().join("k1.public.jwk.json").exists());
}

#[test]
fn refuses_to_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    assert!(keygen(dir.path(), &["--kid", "k1"]).status.success());
    let first = std::fs::read(dir.path().join("k1.private.pem")).unwrap();
    let second = keygen(dir.path(), &["--kid", "k1"]);
    assert!(!second.status.success());
    assert!(String::from_utf8_lossy(&second.stderr).contains("--force"));
    assert_eq!(
        std::fs::read(dir.path().join("k1.private.pem")).unwrap(),
        first
    );
    let forced = keygen(dir.path(), &["--kid", "k1", "--force"]);
    assert!(forced.status.success());
    assert_ne!(
        std::fs::read(dir.path().join("k1.private.pem")).unwrap(),
        first
    );
}

#[test]
fn rejects_path_like_kid() {
    let dir = tempfile::tempdir().unwrap();
    for bad in ["../../x", "/tmp/x", "a/b", "..", ".", "a..b", "-x", ""] {
        let out = keygen(dir.path(), &["--kid", bad]);
        assert!(!out.status.success(), "kid {:?} accepted", bad);
    }
    assert!(std::fs::read_dir(dir.path()).unwrap().next().is_none());
}
