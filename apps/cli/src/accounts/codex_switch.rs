//! Explicit local Codex switching. Credentials stay in the host process; only status crosses HTTP.
use super::{AccountError, Credential, Document, sources::CodexNativeReference, vault::Vault};
use crate::cli::Provider;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SwitchStatus {
    pub current_account_ids: Vec<String>,
    pub available_account_ids: Vec<String>,
}

pub(crate) fn directory() -> Result<PathBuf, AccountError> {
    std::env::var_os("HOME")
        .map(|home| PathBuf::from(home).join(".codex"))
        .ok_or(AccountError::Storage)
}

fn check_path(path: &Path) -> Result<(), AccountError> {
    for ancestor in path.ancestors() {
        match fs::symlink_metadata(ancestor) {
            Ok(meta) if meta.file_type().is_symlink() => return Err(AccountError::Input),
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err(AccountError::Storage),
        }
    }
    Ok(())
}

fn read(path: &Path) -> Result<Vec<u8>, AccountError> {
    check_path(path)?;
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(|_| AccountError::Storage)?;
    let meta = file.metadata().map_err(|_| AccountError::Storage)?;
    if !meta.is_file() || meta.len() > 1024 * 1024 {
        return Err(AccountError::Input);
    }
    let mut data = Vec::new();
    file.take(1024 * 1024 + 1)
        .read_to_end(&mut data)
        .map_err(|_| AccountError::Storage)?;
    if data.len() > 1024 * 1024 {
        return Err(AccountError::Input);
    }
    Ok(data)
}

fn write(path: &Path, data: &[u8]) -> Result<(), AccountError> {
    check_path(path)?;
    let parent = path.parent().ok_or(AccountError::Input)?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(parent).map_err(|_| AccountError::Storage)?;
    let temporary = parent.join(format!(".quotio-{}.tmp", super::random_string()?));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
        }
        let mut file = options
            .open(&temporary)
            .map_err(|_| AccountError::Storage)?;
        file.write_all(data).map_err(|_| AccountError::Storage)?;
        file.sync_all().map_err(|_| AccountError::Storage)?;
        check_path(path)?;
        fs::rename(&temporary, path).map_err(|_| AccountError::Storage)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn parse(data: &[u8]) -> Result<Value, AccountError> {
    let value: Value = serde_json::from_slice(data).map_err(|_| AccountError::Input)?;
    for field in ["access_token", "refresh_token", "account_id"] {
        if value["tokens"][field]
            .as_str()
            .is_none_or(|s| s.is_empty() || s.len() > 16384 || s.chars().any(char::is_control))
        {
            return Err(AccountError::Input);
        }
    }
    if value["tokens"]["id_token"]
        .as_str()
        .is_some_and(|s| s.len() > 16384 || s.chars().any(char::is_control))
    {
        return Err(AccountError::Input);
    }
    Ok(value)
}

fn borrowed(
    directory: Option<&Path>,
    disabled: &[String],
) -> Result<Vec<(String, Value)>, AccountError> {
    let sources = directory
        .map(|path| super::proxy::codex_switch_sources(path, disabled))
        .transpose()?
        .unwrap_or_default();
    Ok(sources
        .into_iter()
        .filter(|(_, value)| {
            serde_json::to_vec(value)
                .ok()
                .is_some_and(|b| parse(&b).is_ok())
        })
        .collect())
}

fn material(credential: &Credential) -> Result<Value, AccountError> {
    match credential {
        Credential::CodexOAuth {
            access_token,
            refresh_token,
            id_token,
            account_id,
            ..
        } => {
            if access_token.is_empty() || refresh_token.is_empty() || account_id.is_empty() {
                return Err(AccountError::Input);
            }
            Ok(
                json!({"auth_mode":"chatgpt", "OPENAI_API_KEY":null, "tokens":{
                    "access_token":access_token, "refresh_token":refresh_token, "id_token":id_token, "account_id":account_id
                }}),
            )
        }
        Credential::CodexNative { source } => parse(&read(&source.path)?),
        _ => Err(AccountError::Unsupported),
    }
}

fn state(document: &Document, directory: &Path) -> SwitchStatus {
    let current = read(&directory.join("auth.json"))
        .ok()
        .and_then(|data| parse(&data).ok());
    let mut result = SwitchStatus::default();
    let Some(registry) = &document.resolved else {
        return result;
    };
    for account in &document.accounts {
        if account.provider != Provider::Codex || !account.enabled() {
            continue;
        }
        let Some(id) = registry.account_id_for_source(&account.id) else {
            continue;
        };
        let Ok(auth) = material(&account.credential) else {
            continue;
        };
        if !result.available_account_ids.iter().any(|value| value == id) {
            result.available_account_ids.push(id.into());
        }
        if current
            .as_ref()
            .is_some_and(|current| current["tokens"]["account_id"] == auth["tokens"]["account_id"])
            && !result.current_account_ids.iter().any(|value| value == id)
        {
            result.current_account_ids.push(id.into());
        }
    }
    result
}

pub async fn status(
    vault: Vault,
    proxy_directory: Option<PathBuf>,
    disabled: Vec<String>,
) -> Result<SwitchStatus, AccountError> {
    tokio::task::spawn_blocking(move || {
        let mut tx = vault.begin()?;
        tx.document.enable_resolved_accounts()?;
        let directory = directory()?;
        let mut status = state(&tx.document, &directory);
        let current = read(&directory.join("auth.json"))
            .ok()
            .and_then(|b| parse(&b).ok());
        for (id, auth) in borrowed(proxy_directory.as_deref(), &disabled)? {
            status.available_account_ids.push(id.clone());
            if current
                .as_ref()
                .is_some_and(|v| v["tokens"]["account_id"] == auth["tokens"]["account_id"])
            {
                status.current_account_ids.push(id);
            }
        }
        Ok(status)
    })
    .await
    .map_err(|_| AccountError::Storage)?
}

pub async fn activate(
    vault: Vault,
    id: String,
    proxy_directory: Option<PathBuf>,
    disabled: Vec<String>,
) -> Result<(), AccountError> {
    let directory = directory()?;
    tokio::task::spawn_blocking(move || {
        activate_with(
            vault,
            &id,
            &directory,
            proxy_directory.as_deref(),
            &disabled,
        )
    })
    .await
    .map_err(|_| AccountError::Storage)?
}

#[cfg(test)]
fn activate_at(vault: Vault, id: &str, directory: &Path) -> Result<(), AccountError> {
    activate_with(vault, id, directory, None, &[])
}

fn activate_with(
    vault: Vault,
    id: &str,
    directory: &Path,
    proxy_directory: Option<&Path>,
    disabled: &[String],
) -> Result<(), AccountError> {
    let auth_path = directory.join("auth.json");
    check_path(&auth_path)?;
    let mut tx = vault.begin()?;
    tx.document.enable_resolved_accounts()?;
    let ids = tx
        .document
        .resolved
        .as_ref()
        .ok_or(AccountError::Corrupt)?
        .source_ids(id)
        .or_else(|error| {
            if id.starts_with("external-") {
                Ok(Vec::new())
            } else {
                Err(error)
            }
        })?;
    let selected = tx
        .document
        .accounts
        .iter()
        .filter(|a| ids.contains(&a.id) && a.provider == Provider::Codex && a.enabled())
        .filter_map(|a| material(&a.credential).ok().map(|value| (a.clone(), value)))
        .min_by_key(|(a, _)| {
            if matches!(a.credential, Credential::CodexOAuth { .. }) {
                0
            } else {
                1
            }
        })
        .map(|(a, value)| (Some(a), value))
        .or_else(|| {
            borrowed(proxy_directory, disabled)
                .ok()?
                .into_iter()
                .find(|(source_id, _)| source_id == id)
                .map(|(_, v)| (None, v))
        })
        .ok_or(AccountError::Unsupported)?;
    let (account, mut target) = selected;
    let existing = if auth_path.exists() {
        Some(read(&auth_path)?)
    } else {
        None
    };
    if let Some(data) = &existing {
        if parse(data)
            .ok()
            .is_some_and(|value| value["tokens"]["account_id"] == target["tokens"]["account_id"])
        {
            return Ok(());
        }
        let backup = directory.join(format!("auth.json.backup.{}", super::random_string()?));
        write(&backup, data)?;
        let marker = read(&directory.join("quotio-active-source"))
            .ok()
            .and_then(|v| String::from_utf8(v).ok());
        let mut preserved = false;
        for source_account in &mut tx.document.accounts {
            let matches_outgoing = material(&source_account.credential)
                .ok()
                .zip(parse(data).ok())
                .is_some_and(|(source, current)| {
                    source["tokens"]["account_id"] == current["tokens"]["account_id"]
                });
            if let Credential::CodexNative { source } = &mut source_account.credential
                && (source.path == auth_path
                    || (marker.as_deref() == Some(&source_account.id) && matches_outgoing))
            {
                source.path = backup.clone();
                source_account.identity = source.identity()?;
                preserved = true;
            }
            adopt_newer_native(&mut source_account.credential, data);
        }
        if !preserved && let Ok(value) = parse(data) {
            let source = CodexNativeReference { path: backup };
            let identity = source.identity()?;
            let account_id = value["tokens"]["account_id"]
                .as_str()
                .ok_or(AccountError::Input)?;
            let already_owned = tx.document.accounts.iter().any(|a| matches!(&a.credential, Credential::CodexOAuth { account_id: owned, .. } if owned == account_id));
            if !already_owned {
                let label = format!("Codex {}", &super::random_string()?[..8]);
                tx.document.add(
                    Provider::Codex,
                    &label,
                    identity,
                    Credential::CodexNative { source },
                )?;
            }
        }
    }
    target["auth_mode"] = json!("chatgpt");
    target["OPENAI_API_KEY"] = Value::Null;
    let bytes = serde_json::to_vec_pretty(&target).map_err(|_| AccountError::Input)?;
    // Preserve the outgoing account before replacing the credential used by Codex.
    tx.document.enable_resolved_accounts()?;
    tx.commit()?;
    let guard = vault.begin()?;
    if let Some(account) = &account {
        if !guard
            .document
            .accounts
            .iter()
            .any(|a| a.id == account.id && a.enabled() && a.credential == account.credential)
        {
            return Err(AccountError::Busy);
        }
    } else if !borrowed(proxy_directory, disabled)?
        .iter()
        .any(|(source_id, value)| source_id == id && value == &target)
    {
        return Err(AccountError::Busy);
    }
    let latest = if auth_path.exists() {
        Some(read(&auth_path)?)
    } else {
        None
    };
    if latest != existing {
        return Err(AccountError::Busy);
    }
    write(
        &directory.join("quotio-active-source"),
        account.as_ref().map_or(id, |a| a.id.as_str()).as_bytes(),
    )?;
    write(&auth_path, &bytes)?;
    Ok(())
}

fn adopt_newer_native(credential: &mut Credential, data: &[u8]) {
    use base64::Engine;
    let Ok(value) = parse(data) else { return };
    let tokens = &value["tokens"];
    let Credential::CodexOAuth {
        account_id,
        access_token,
        refresh_token,
        id_token,
        expires_at,
        ..
    } = credential
    else {
        return;
    };
    if tokens["account_id"].as_str() != Some(account_id.as_str()) {
        return;
    }
    let Some(access) = tokens["access_token"].as_str() else {
        return;
    };
    let expiry = access
        .split('.')
        .nth(1)
        .and_then(|part| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(part)
                .ok()
        })
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|v| v["exp"].as_i64())
        .unwrap_or(0);
    if expiry <= *expires_at {
        return;
    }
    let Some(refresh) = tokens["refresh_token"].as_str().filter(|s| !s.is_empty()) else {
        return;
    };
    *access_token = access.into();
    *refresh_token = refresh.into();
    *expires_at = expiry;
    if let Some(id) = tokens["id_token"].as_str() {
        *id_token = id.into();
    }
}

/// Reconcile credentials rotated by Codex itself before attempting managed refresh.
pub(crate) fn adopt_active(source_id: &str, credential: &mut Credential) {
    let Ok(directory) = directory() else { return };
    if read(&directory.join("quotio-active-source"))
        .ok()
        .as_deref()
        != Some(source_id.as_bytes())
    {
        return;
    }
    if let Ok(data) = read(&directory.join("auth.json")) {
        adopt_newer_native(credential, &data);
    }
}

/// A late refresh must never replace another account selected in the meantime.
pub(crate) fn persist_active(
    source_id: &str,
    previous: &Credential,
    updated: &Credential,
) -> Result<(), AccountError> {
    persist_active_at(&directory()?, source_id, previous, updated)
}

fn persist_active_at(
    directory: &Path,
    source_id: &str,
    previous: &Credential,
    updated: &Credential,
) -> Result<(), AccountError> {
    if read(&directory.join("quotio-active-source"))
        .ok()
        .as_deref()
        != Some(source_id.as_bytes())
    {
        return Ok(());
    }
    let path = directory.join("auth.json");
    let mut current = parse(&read(&path)?)?;
    let prior = material(previous)?;
    if current["tokens"]["refresh_token"] != prior["tokens"]["refresh_token"]
        || current["tokens"]["account_id"] != prior["tokens"]["account_id"]
    {
        return Ok(());
    }
    current["tokens"] = material(updated)?["tokens"].clone();
    write(
        &path,
        &serde_json::to_vec_pretty(&current).map_err(|_| AccountError::Input)?,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    #[derive(Default)]
    struct Memory(Mutex<Option<Vec<u8>>>);
    impl super::super::vault::Backend for Memory {
        fn read(&self) -> Result<Option<Vec<u8>>, AccountError> {
            Ok(self.0.lock().unwrap().clone())
        }
        fn write(&self, data: &[u8]) -> Result<(), AccountError> {
            *self.0.lock().unwrap() = Some(data.into());
            Ok(())
        }
    }
    struct Fixture {
        dir: PathBuf,
        vault: Vault,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "quotio-switch-{}",
                super::super::random_string().unwrap()
            ));
            fs::create_dir(&dir).unwrap();
            Self {
                vault: Vault::new(Arc::new(Memory::default()), dir.join("vault.lock")),
                dir,
            }
        }
        fn add(&self, credential: Credential, label: &str) -> (String, String) {
            let mut tx = self.vault.begin().unwrap();
            let source = tx
                .document
                .add(Provider::Codex, label, label.into(), credential)
                .unwrap();
            tx.document.enable_resolved_accounts().unwrap();
            tx.document
                .resolved
                .as_mut()
                .unwrap()
                .synchronize(&tx.document.accounts)
                .unwrap();
            let id = tx
                .document
                .resolved
                .as_ref()
                .unwrap()
                .account_id_for_source(&source)
                .unwrap()
                .to_owned();
            tx.commit().unwrap();
            (id, source)
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }
    fn credential(id: &str) -> Credential {
        Credential::CodexOAuth {
            access_token: format!("fake-access-{id}"),
            refresh_token: format!("fake-refresh-{id}"),
            id_token: "fake-id".into(),
            account_id: id.into(),
            email: "fixture@example.invalid".into(),
            expires_at: 0,
        }
    }
    fn bytes(id: &str) -> Vec<u8> {
        serde_json::to_vec(&material(&credential(id)).unwrap()).unwrap()
    }

    #[test]
    fn switching_preserves_config_and_outgoing_native_account() {
        let f = Fixture::new();
        let auth = f.dir.join("auth.json");
        write(&auth, &bytes("original")).unwrap();
        fs::write(f.dir.join("config.toml"), "user config").unwrap();
        let (old, _) = f.add(
            Credential::CodexNative {
                source: CodexNativeReference { path: auth.clone() },
            },
            "old",
        );
        let (new, _) = f.add(credential("new"), "new");
        activate_at(f.vault.clone(), &new, &f.dir).unwrap();
        assert_eq!(
            parse(&read(&auth).unwrap()).unwrap()["tokens"]["account_id"],
            "new"
        );
        assert_eq!(
            fs::read_to_string(f.dir.join("config.toml")).unwrap(),
            "user config"
        );
        let tx = f.vault.begin().unwrap();
        let status = state(&tx.document, &f.dir);
        assert_eq!(status.current_account_ids, vec![new]);
        assert!(status.available_account_ids.contains(&old));
        let public = serde_json::to_string(&status).unwrap();
        assert!(!public.contains("fake-refresh") && !public.contains("fake-access"));
        drop(tx);
        activate_at(f.vault.clone(), &old, &f.dir).unwrap();
        assert_eq!(
            read(&auth).unwrap(),
            serde_json::to_vec_pretty(&material(&credential("original")).unwrap()).unwrap()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&auth).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        assert_eq!(
            fs::read_dir(&f.dir)
                .unwrap()
                .flatten()
                .filter(|v| v
                    .file_name()
                    .to_string_lossy()
                    .starts_with("auth.json.backup."))
                .count(),
            2
        );
    }

    #[test]
    fn unknown_or_disabled_account_leaves_files_intact() {
        let f = Fixture::new();
        write(&f.dir.join("auth.json"), &bytes("old")).unwrap();
        let (id, _) = f.add(credential("new"), "new");
        let mut tx = f.vault.begin().unwrap();
        tx.document.accounts[0].enabled = false;
        tx.commit().unwrap();
        assert!(activate_at(f.vault.clone(), &id, &f.dir).is_err());
        assert!(activate_at(f.vault.clone(), "missing", &f.dir).is_err());
        assert_eq!(read(&f.dir.join("auth.json")).unwrap(), bytes("old"));
    }

    #[test]
    fn outgoing_unregistered_account_remains_available() {
        let f = Fixture::new();
        write(&f.dir.join("auth.json"), &bytes("old")).unwrap();
        let (id, _) = f.add(credential("new"), "new");
        activate_at(f.vault.clone(), &id, &f.dir).unwrap();
        let tx = f.vault.begin().unwrap();
        assert_eq!(state(&tx.document, &f.dir).available_account_ids.len(), 2);
    }

    #[test]
    fn repeated_switch_is_noop() {
        let f = Fixture::new();
        let (id, _) = f.add(credential("new"), "new");
        activate_at(f.vault.clone(), &id, &f.dir).unwrap();
        let count = fs::read_dir(&f.dir).unwrap().count();
        activate_at(f.vault.clone(), &id, &f.dir).unwrap();
        assert_eq!(count, fs::read_dir(&f.dir).unwrap().count());
        assert!(!f.dir.join("config.toml").exists());
    }

    #[test]
    fn refresh_updates_only_matching_active_credential() {
        let f = Fixture::new();
        let (id, source) = f.add(credential("a"), "a");
        activate_at(f.vault.clone(), &id, &f.dir).unwrap();
        let mut updated = credential("a");
        if let Credential::CodexOAuth { refresh_token, .. } = &mut updated {
            *refresh_token = "rotated".into();
        }
        persist_active_at(&f.dir, &source, &credential("a"), &updated).unwrap();
        assert_eq!(
            parse(&read(&f.dir.join("auth.json")).unwrap()).unwrap()["tokens"]["refresh_token"],
            "rotated"
        );
        persist_active_at(&f.dir, &source, &credential("a"), &credential("a")).unwrap();
        assert_eq!(
            parse(&read(&f.dir.join("auth.json")).unwrap()).unwrap()["tokens"]["refresh_token"],
            "rotated"
        );
        write(&f.dir.join("auth.json"), &bytes("b")).unwrap();
        persist_active_at(&f.dir, &source, &credential("a"), &updated).unwrap();
        assert_eq!(read(&f.dir.join("auth.json")).unwrap(), bytes("b"));
    }

    #[test]
    fn adopts_cli_rotated_token_only_for_same_account() {
        use base64::Engine;
        let mut value = material(&credential("a")).unwrap();
        let payload =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"exp":2000000000}"#);
        value["tokens"]["access_token"] = json!(format!("e30.{payload}.sig"));
        value["tokens"]["refresh_token"] = json!("rotated-by-cli");
        let data = serde_json::to_vec(&value).unwrap();
        let mut a = credential("a");
        adopt_newer_native(&mut a, &data);
        assert!(
            matches!(a, Credential::CodexOAuth { expires_at: 2000000000, ref refresh_token, .. } if refresh_token == "rotated-by-cli")
        );
        let mut b = credential("b");
        adopt_newer_native(&mut b, &data);
        assert!(b == credential("b"));
    }

    #[test]
    fn stale_marker_does_not_replace_a_saved_native_account() {
        let f = Fixture::new();
        let saved = f.dir.join("saved.json");
        write(&saved, &bytes("saved")).unwrap();
        let (saved_id, source_id) = f.add(
            Credential::CodexNative {
                source: CodexNativeReference {
                    path: saved.clone(),
                },
            },
            "saved",
        );
        write(&f.dir.join("quotio-active-source"), source_id.as_bytes()).unwrap();
        write(&f.dir.join("auth.json"), &bytes("manual-login")).unwrap();
        let (target, _) = f.add(credential("target"), "target");
        activate_at(f.vault.clone(), &target, &f.dir).unwrap();
        activate_at(f.vault.clone(), &saved_id, &f.dir).unwrap();
        assert_eq!(
            parse(&read(&f.dir.join("auth.json")).unwrap()).unwrap()["tokens"]["account_id"],
            "saved"
        );
        assert_eq!(read(&saved).unwrap(), bytes("saved"));
    }

    #[test]
    fn proxy_account_switch_preserves_source_and_respects_disabled_files() {
        let f = Fixture::new();
        let proxy = f.dir.join("proxy");
        fs::create_dir(&proxy).unwrap();
        let file = proxy.join("codex-test.json");
        let value = json!({"type":"codex", "email":"test@example.invalid", "access_token":"fake-access-proxy", "refresh_token":"fake-refresh-proxy", "id_token":"fake-id", "account_id":"proxy-account"});
        let original = serde_json::to_vec(&value).unwrap();
        write(&file, &original).unwrap();
        let sources = borrowed(Some(&proxy), &[]).unwrap();
        assert_eq!(sources.len(), 1);
        let id = &sources[0].0;
        assert!(
            activate_with(
                f.vault.clone(),
                id,
                &f.dir,
                Some(&proxy),
                &["codex-test.json".into()]
            )
            .is_err()
        );
        assert!(!f.dir.join("auth.json").exists());
        activate_with(f.vault.clone(), id, &f.dir, Some(&proxy), &[]).unwrap();
        assert_eq!(
            parse(&read(&f.dir.join("auth.json")).unwrap()).unwrap()["tokens"]["account_id"],
            "proxy-account"
        );
        assert_eq!(read(&file).unwrap(), original);
        write(
            &file,
            &serde_json::to_vec(&json!({"disabled":true, "type":"codex"})).unwrap(),
        )
        .unwrap();
        assert!(borrowed(Some(&proxy), &[]).unwrap().is_empty());
    }

    #[test]
    fn malformed_native_credentials_are_not_offered() {
        let f = Fixture::new();
        let path = f.dir.join("invalid.json");
        write(
            &path,
            br#"{"tokens":{"access_token":"fake", "account_id":"id"}}"#,
        )
        .unwrap();
        let (id, _) = f.add(
            Credential::CodexNative {
                source: CodexNativeReference { path },
            },
            "invalid",
        );
        assert!(activate_at(f.vault.clone(), &id, &f.dir).is_err());
        assert!(
            state(&f.vault.begin().unwrap().document, &f.dir)
                .available_account_ids
                .is_empty()
        );
        assert!(!f.dir.join("auth.json").exists());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_auth_or_directory() {
        let f = Fixture::new();
        let original = f.dir.join("original");
        write(&original, &bytes("a")).unwrap();
        std::os::unix::fs::symlink(&original, f.dir.join("auth.json")).unwrap();
        let (id, _) = f.add(credential("b"), "b");
        assert!(activate_at(f.vault.clone(), &id, &f.dir).is_err());
        assert_eq!(read(&original).unwrap(), bytes("a"));
        let linked = f.dir.join("linked");
        std::os::unix::fs::symlink(&f.dir, &linked).unwrap();
        assert!(activate_at(f.vault.clone(), &id, &linked).is_err());
    }
}
