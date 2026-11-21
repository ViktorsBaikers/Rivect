//! The local credential document is the default store: owner-only bytes,
//! create-only enrollment, replacement, lifecycle removal and typed refusals.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code keeps unwrap/expect/panic conveniences; src/ stays strict (standards §14)"
)]

use rivect::providers::{CredentialStore, ProviderError, SecretRef, StoreKind, native_store};
use std::fs;
use std::path::Path;

const NAMESPACE: &str = "rivect-test";

fn scoped(tail: &str) -> SecretRef {
    SecretRef::parse(&format!("file:{NAMESPACE}/{tail}")).expect("scoped file ref")
}

#[test]
fn file_store_holds_owner_only_scoped_bytes() -> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::TempDir::with_prefix("rivect-file-store-")?;
    let store = native_store(StoreKind::File, NAMESPACE, root.path())?;
    let credential = scoped("deepseek");
    let path = root.path().join("runtime/credentials.json");

    assert!(!store.occupied(&credential)?);
    store.login(&credential, b"sk-first")?;
    assert!(store.occupied(&credential)?);
    assert_eq!(store.resolve(&credential)?, b"sk-first");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path)?.permissions().mode() & 0o777,
            0o600,
            "the credential document is owner-only"
        );
    }

    let document: serde_json::Value = serde_json::from_slice(&fs::read(&path)?)?;
    assert_eq!(document["version"], 1);
    assert_eq!(
        document["entries"]["rivect-test/deepseek"],
        serde_json::json!([115, 107, 45, 102, 105, 114, 115, 116])
    );

    match store.login(&credential, b"sk-second") {
        Err(ProviderError::CredentialOccupied { scope }) => {
            assert_eq!(scope, "rivect-test/deepseek")
        }
        other => panic!("enrollment must stay create-only: {other:?}"),
    }
    assert_eq!(
        store.resolve(&credential)?,
        b"sk-first",
        "a refused duplicate leaves the prior bytes"
    );

    store.refresh(&credential, b"sk-second")?;
    assert_eq!(store.resolve(&credential)?, b"sk-second");
    assert_eq!(
        store.entry_accounts(NAMESPACE)?,
        vec!["rivect-test/deepseek"]
    );

    store.logout(&credential)?;
    assert!(!store.occupied(&credential)?);
    assert!(matches!(
        store.resolve(&credential),
        Err(ProviderError::CredentialAbsent { .. })
    ));
    assert!(matches!(
        store.revoke(&credential),
        Err(ProviderError::CredentialAbsent { .. })
    ));
    Ok(())
}

#[test]
fn file_store_refuses_foreign_scopes_and_tampered_documents()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::TempDir::with_prefix("rivect-file-store-")?;
    let store = native_store(StoreKind::File, NAMESPACE, root.path())?;
    let foreign = SecretRef::parse("file:another-vendor/deepseek")?;
    assert!(matches!(
        store.login(&foreign, b"sk-foreign"),
        Err(ProviderError::CredentialOutsideNamespace { .. })
    ));

    let path = root.path().join("runtime/credentials.json");
    fs::create_dir_all(path.parent().ok_or("no parent")?)?;
    fs::write(
        &path,
        br#"{"version":1,"entries":{"rivect-test/x":"plain"}}"#,
    )?;
    match store.resolve(&scoped("x")) {
        Err(ProviderError::StoreUnavailable { store, reason }) => {
            assert_eq!(store, StoreKind::File);
            assert!(!reason.contains("plain"), "the document is never echoed");
        }
        other => panic!("a mistyped document must refuse: {other:?}"),
    }

    fs::write(&path, br#"{"version":2,"entries":{}}"#)?;
    assert!(matches!(
        store.resolve(&scoped("x")),
        Err(ProviderError::StoreUnavailable { .. })
    ));
    Ok(())
}

#[test]
fn the_default_file_reference_lands_beside_the_runtime_database()
-> Result<(), Box<dyn std::error::Error>> {
    let root = tempfile::TempDir::with_prefix("rivect-file-store-")?;
    let store = native_store(StoreKind::File, NAMESPACE, root.path())?;
    let credential = scoped("profile");
    store.login(&credential, b"token")?;
    assert!(Path::new(&root.path().join("runtime/credentials.json")).is_file());
    assert!(
        !credential.raw().contains("token"),
        "the reference names the location, never the material"
    );
    Ok(())
}
