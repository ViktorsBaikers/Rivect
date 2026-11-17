use super::{
    AdmittedEffect, EffectRequest, Executor, ExecutorError, FileIdentity, WorkerError,
    WriteIdentity, helper_confined_write,
};
use crate::config::hex;
use rivect_sandbox_helper as native;
use sha2::Digest as _;
use std::fs::{File, Permissions};
use std::io::{self, Read as _};
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Component, Path};
use std::sync::atomic::{AtomicBool, Ordering};

pub struct ProjectEdit {
    pub identity: WriteIdentity,
    pub original_digest: String,
}

impl Executor<'_> {
    pub(crate) fn execute_project_edit(
        &mut self,
        admitted: &AdmittedEffect,
        edit: &ProjectEdit,
        cancel: &AtomicBool,
    ) -> Result<String, ExecutorError> {
        let EffectRequest::Write { path, bytes, .. } = &admitted.request else {
            return Err(ExecutorError::PolicyDenied);
        };
        if admitted.expected_identity != Some(edit.identity) {
            self.store
                .attempt_rejected(&admitted.attempt_id, "write target changed")?;
            return Err(changed(path).into());
        }
        self.execute_gates(admitted)?;
        if let Err(error) = replace_project_file(&admitted.scope_root, path, edit, bytes, cancel) {
            self.commit_worker_error(&admitted.attempt_id, error, false)?;
        }
        let detail = format!(
            "write-performed sha256={}",
            hex(&sha2::Sha256::digest(bytes))
        );
        self.store
            .set_attempt_state(&admitted.attempt_id, "confirmed", Some(&detail))?;
        Ok(detail)
    }
}

fn replace_project_file(
    root: &Path,
    target: &Path,
    edit: &ProjectEdit,
    bytes: &[u8],
    cancel: &AtomicBool,
) -> Result<(), WorkerError> {
    if bytes.len() > super::macos::WRITE_MAX_BYTES {
        return Err(WorkerError::WriteTooLarge);
    }
    let relative = target
        .strip_prefix(root)
        .map_err(|_prefix| changed(target))?;
    if relative
        .components()
        .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err(changed(target));
    }
    let parent = target
        .parent()
        .filter(|parent| parent.starts_with(root))
        .ok_or_else(|| changed(target))?;
    let leaf = target
        .file_name()
        .ok_or_else(|| changed(target))?
        .as_encoded_bytes();
    let dir = open_parent(parent).map_err(write_failure)?;
    let original = open_leaf(&dir, leaf).map_err(write_failure)?;
    verify_original(&original, target, edit)?;
    #[cfg(target_os = "macos")]
    let (platform, profile) = {
        super::macos::probe_write_conformance(Path::new(super::macos::SANDBOX_EXEC), root)?;
        ("macos", super::macos::write_profile(root)?)
    };
    #[cfg(target_os = "linux")]
    let (platform, profile) = {
        use super::linux::{SandboxLauncher, probe_write_conformance};
        probe_write_conformance(&SandboxLauncher::default(), root)?;
        ("linux", String::new())
    };
    let name = format!(".rivect-edit-{}", crate::contracts::CommandId::generate().0);
    let staged = native::create_edit_stage(&dir, name.as_bytes()).map_err(write_failure)?;
    let result = (|| {
        // A worker's partial write affects only the private staging inode.
        let fd = staged.try_clone().map_err(write_failure)?;
        helper_confined_write(platform, &profile, fd, bytes)
            .map_err(|error| write_failure(io::Error::other(error)))?;
        let mode = original
            .metadata()
            .map_err(write_failure)?
            .permissions()
            .mode();
        staged
            .set_permissions(Permissions::from_mode(mode & 0o777))
            .map_err(write_failure)?;
        staged.sync_all().map_err(write_failure)?;
        let live_dir = open_parent(parent).map_err(write_failure)?;
        if !live_dir.identity.same_directory_inode(&dir.identity) {
            return Err(changed(target));
        }
        verify_original(&open_leaf(&dir, leaf).map_err(write_failure)?, target, edit)?;
        confirm_stage(&dir, name.as_bytes(), &staged).map_err(write_failure)?;
        if cancel.load(Ordering::Acquire) {
            return Err(write_failure(io::Error::from(io::ErrorKind::Interrupted)));
        }
        native::exchange_edit_leaves(&dir, name.as_bytes(), leaf).map_err(write_failure)?;
        let moved = open_leaf(&dir, name.as_bytes())
            .map_err(write_failure)
            .and_then(|backup| verify_original(&backup, target, edit));
        confirm_stage(&dir, leaf, &staged).map_err(|source| unproven(parent, &name, source))?;
        if moved.is_err() {
            native::exchange_edit_leaves(&dir, name.as_bytes(), leaf)
                .map_err(|source| unproven(parent, &name, source))?;
            return Err(changed(target));
        }
        Ok(())
    })();
    if matches!(result, Err(WorkerError::WriteMutationFailed { .. })) {
        return result;
    }
    if result.is_err() {
        confirm_stage(&dir, name.as_bytes(), &staged).map_err(write_failure)?;
    }
    native::remove_edit_stage(&dir, name.as_bytes()).map_err(|source| {
        if result.is_ok() {
            unproven(parent, &name, source)
        } else {
            write_failure(source)
        }
    })?;
    result
}

fn open_parent(path: &Path) -> io::Result<native::AnchoredDir> {
    let mut current = native::open_filesystem_root().map_err(io::Error::other)?;
    for component in path.components().skip(1) {
        current = native::openat_directory(&current, component.as_os_str().as_encoded_bytes())
            .map_err(io::Error::other)?;
    }
    Ok(current)
}

fn open_leaf(dir: &native::AnchoredDir, leaf: &[u8]) -> io::Result<File> {
    native::openat_leaf(dir, leaf, super::macos::WRITE_MAX_BYTES as u64)
        .map(|opened| opened.file)
        .map_err(io::Error::other)
}

fn confirm_stage(dir: &native::AnchoredDir, name: &[u8], expected: &File) -> io::Result<()> {
    let live = open_leaf(dir, name)?.metadata()?;
    if !super::same_regular_file(&live, &expected.metadata()?) {
        return Err(io::Error::other("staged file identity changed"));
    }
    Ok(())
}

fn verify_original(mut file: &File, target: &Path, edit: &ProjectEdit) -> Result<(), WorkerError> {
    let metadata = file.metadata().map_err(write_failure)?;
    let reuse = native::reuse_token(file)
        .map_err(|source| WorkerError::WriteIdentityUnavailable { source })?;
    let mut contents = Vec::new();
    file.by_ref()
        .take(super::macos::WRITE_MAX_BYTES as u64 + 1)
        .read_to_end(&mut contents)
        .map_err(write_failure)?;
    if edit.identity != WriteIdentity::new(FileIdentity::from_metadata(&metadata), Ok(reuse))
        || hex(&sha2::Sha256::digest(&contents)) != edit.original_digest
    {
        return Err(changed(target));
    }
    Ok(())
}

fn changed(target: &Path) -> WorkerError {
    WorkerError::TargetChanged {
        target: target.to_path_buf(),
    }
}

fn write_failure(source: io::Error) -> WorkerError {
    WorkerError::WriteFailed { source }
}

fn unproven(parent: &Path, staged_name: &str, source: io::Error) -> WorkerError {
    WorkerError::WriteMutationFailed {
        source: io::Error::other(format!(
            "edit outcome unconfirmed; retained staging name {staged_name} in {}: {source}",
            parent.display()
        )),
    }
}
