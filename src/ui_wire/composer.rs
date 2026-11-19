use super::{Refusal, machine, string};
use rivect::commands::Runtime;
use rivect::contracts::{ErrorCode, IMAGE_MAX_BYTES, SessionId, TaskId};
use rivect::executor::{FileIdentity, FileReadPin, ImageReadPin};
use rivect::model::ImageMedia;
use rivect_sandbox_helper::{
    AnchoredDir, AnchoredLeaf, FdOpenError, open_filesystem_root, openat_directory, openat_leaf,
};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use std::io::Read;
use std::path::{Component, Path};

fn file_error(error: FdOpenError) -> Refusal {
    Refusal::Core(match error {
        FdOpenError::Missing => ErrorCode::NotFound,
        FdOpenError::UnsupportedCapability { .. } => ErrorCode::CapabilityUnavailable,
        FdOpenError::Io { source } => return Refusal::FileRead(source),
        FdOpenError::Oversize => ErrorCode::OutputLimit,
        _ => ErrorCode::Denied,
    })
}

pub(super) fn has_read_hook(rt: &Runtime) -> bool {
    rt.effective().parsed.as_ref().is_some_and(|config| {
        config
            .hooks
            .for_event(rivect::config::HOOK_EVENT_EFFECT_REQUEST)
            .is_some()
    })
}

pub(super) fn visible(rt: &Runtime, target: &Path) -> bool {
    let root = &rt.scope_root;
    let Ok(relative) = target.strip_prefix(root) else {
        return false;
    };
    let Ok(data) = rt.data_root.canonicalize() else {
        return false;
    };
    if let Some(alias) = target.ancestors().find(|ancestor| {
        ancestor
            .as_os_str()
            .as_encoded_bytes()
            .eq_ignore_ascii_case(data.as_os_str().as_encoded_bytes())
    }) {
        if alias != root {
            return false;
        }
        let Ok(inside) = target.strip_prefix(alias) else {
            return false;
        };
        // The data root may itself be the workspace. Its ordinary files remain project files.
        if inside.components().next().is_some_and(|part| {
            let name = part.as_os_str().as_encoded_bytes();
            name.eq_ignore_ascii_case(b"runtime")
                || name.eq_ignore_ascii_case(b"config.toml")
                || rivect::mcp::is_evidence_directory(part.as_os_str())
        }) {
            return false;
        }
    }
    let Ok(grant) = rt
        .policy()
        .admit(&rt.scoped_grant, rivect::contracts::EffectClass::Read)
    else {
        return false;
    };
    grant.scope_root == *root && root.is_absolute()
        && relative.components().all(|part| matches!(part, Component::Normal(name)
            if !name.as_encoded_bytes().starts_with(b".") && !name.as_encoded_bytes().iter().any(u8::is_ascii_control)))
        && !target.starts_with(rt.owner().runtime_dir())
        && !rt.policy().covers(target)
}

pub(super) fn directory(path: &Path) -> Result<AnchoredDir, Refusal> {
    if !path.is_absolute() {
        return Err(Refusal::Denied);
    }
    let mut dir = open_filesystem_root().map_err(file_error)?;
    for part in path.components().skip(1) {
        let Component::Normal(name) = part else {
            return Err(Refusal::Denied);
        };
        dir = openat_directory(&dir, name.as_encoded_bytes()).map_err(file_error)?;
    }
    Ok(dir)
}

pub(super) struct Preview {
    pub(super) receipt: Value,
    pub(super) pin: ImageReadPin,
    // Hold the inodes across the witness so unlink/reuse cannot manufacture the old identity.
    _root: AnchoredDir,
    _leaf: AnchoredLeaf,
}

fn target(rt: &Runtime, path: &str) -> Result<std::path::PathBuf, Refusal> {
    let root = &rt.scope_root;
    let supplied = Path::new(path);
    let relative = if supplied.is_absolute() {
        supplied
            .strip_prefix(root)
            .map_err(|_outside| Refusal::Denied)?
    } else {
        supplied
    };
    if path.len() > 4096 || path.chars().any(char::is_control) || !root.is_absolute() {
        return Err(Refusal::Invalid);
    }
    let target = root.join(relative);
    if !visible(rt, &target) {
        return Err(Refusal::Denied);
    }
    Ok(target)
}

fn open_pin(
    rt: &Runtime,
    target: std::path::PathBuf,
    max_bytes: u64,
) -> Result<(FileReadPin, AnchoredDir, AnchoredLeaf), Refusal> {
    let relative = target
        .strip_prefix(&rt.scope_root)
        .map_err(|_outside| Refusal::Denied)?;
    let name = relative
        .file_name()
        .ok_or(Refusal::Invalid)?
        .as_encoded_bytes();
    let parent = relative.parent().ok_or(Refusal::Invalid)?;
    let root_dir = directory(&rt.scope_root)?;
    let mut parent_dir = None;
    for component in parent.components() {
        let Component::Normal(name) = component else {
            return Err(Refusal::Denied);
        };
        parent_dir = Some(
            openat_directory(
                parent_dir.as_ref().unwrap_or(&root_dir),
                name.as_encoded_bytes(),
            )
            .map_err(file_error)?,
        );
    }
    let leaf = openat_leaf(parent_dir.as_ref().unwrap_or(&root_dir), name, max_bytes)
        .map_err(file_error)?;
    let pin = FileReadPin {
        target,
        scope: FileIdentity::new(root_dir.identity.dev, root_dir.identity.ino),
        file: FileIdentity::new(leaf.identity.dev, leaf.identity.ino),
    };
    Ok((pin, root_dir, leaf))
}

pub(super) fn image(rt: &mut Runtime, path: &str, witness: bool) -> Result<Preview, Refusal> {
    let target = target(rt, path)?;
    if has_read_hook(rt) && !witness {
        return Err(Refusal::Denied);
    }
    rt.executor()
        .preview_image_hook(&target)
        .map_err(|err| Refusal::Core(err.error_code()))?;
    if !visible(rt, &target) {
        return Err(Refusal::Denied);
    }
    let max_bytes = u64::try_from(IMAGE_MAX_BYTES).map_err(|_overflow| Refusal::Invalid)?;
    let (location, root_dir, mut leaf) = open_pin(rt, target, max_bytes)?;
    let mut header = [0; 12];
    let count =
        usize::try_from(leaf.identity.size.min(12)).map_err(|_overflow| Refusal::Invalid)?;
    leaf.file
        .read_exact(&mut header[..count])
        .map_err(Refusal::FileRead)?;
    let media = ImageMedia::sniff(&header[..count])
        .ok_or(Refusal::Invalid)?
        .label();
    let mut hash = Sha256::new();
    hash.update(&header[..count]);
    let copied = std::io::copy(
        &mut (&leaf.file).take(max_bytes + 1 - count as u64),
        &mut hash,
    )
    .map_err(Refusal::FileRead)?;
    if copied + count as u64 != leaf.identity.size || !visible(rt, &location.target) {
        return Err(Refusal::Denied);
    }
    let name = location
        .target
        .file_name()
        .ok_or(Refusal::Invalid)?
        .as_encoded_bytes();
    let current_parent = directory(location.target.parent().ok_or(Refusal::Invalid)?)?;
    let current = openat_leaf(&current_parent, name, max_bytes).map_err(file_error)?;
    if current.identity != leaf.identity
        || !root_dir
            .identity
            .same_directory_inode(&directory(&rt.scope_root)?.identity)
    {
        return Err(Refusal::Denied);
    }
    let sha256 = rivect::model::hex(&hash.finalize());
    let receipt = json!({"path":path,"media_type":media,"bytes":leaf.identity.size,"sha256":sha256,
        "identity":format!("{}:{}:{}:{}", location.scope.dev(), location.scope.ino(), location.file.dev(), location.file.ino())});
    let pin = ImageReadPin { location, sha256 };
    Ok(Preview {
        receipt,
        pin,
        _root: root_dir,
        _leaf: leaf,
    })
}

pub(super) fn command(
    runtime: &mut Runtime,
    params: &Value,
    witness: bool,
) -> Result<Value, Refusal> {
    let kind = string(params, "kind")?;
    if kind == "image" {
        let preview = image(runtime, string(params, "path")?, witness)?;
        let media = string(&preview.receipt, "media_type")?;
        return Ok(
            json!({"lines":[format!("image {media} {} bytes", preview.receipt["bytes"])],"image":preview.receipt}),
        );
    }
    let session = SessionId(string(params, "session_id")?.to_owned());
    let task = TaskId(string(params, "task_id")?.to_owned());
    runtime.store().task_page_anchor(&session, &task)?;
    if kind == "read" {
        if !witness {
            return Err(Refusal::Denied);
        }
        let path = target(runtime, string(params, "path")?)?;
        let cap = u64::try_from(rivect::executor::macos::READ_MAX_BYTES)
            .map_err(|_overflow| Refusal::Invalid)?;
        let (pin, _scope, _leaf) = open_pin(runtime, path, cap)?;
        let answer = runtime
            .read_terminal_file(&task, &pin)
            .map_err(|err| Refusal::Core(err.error_code()))?;
        if answer["class"] != "read" {
            return Err(Refusal::Denied);
        }
        let mut stream = rivect::resources::OutputStream::new();
        if let Some(text) = answer["text"].as_str() {
            stream.push_chunk(text.as_bytes());
        }
        stream.settle(rivect::resources::OutputSettlement::Complete);
        let mut lines = vec![stream.status_line(false)];
        if answer["truncated"] == true {
            lines.push("first 8 KiB retained".to_owned());
        }
        if answer["text"].is_null() {
            lines.push("binary file; text unavailable".to_owned());
        } else {
            lines.push(stream.text().to_owned());
        }
        return Ok(json!({"lines":lines}));
    }
    if kind == "compact" {
        let report = runtime.store_writer().force_compaction(&session, &task)?;
        return Ok(
            json!({"lines":[format!("Context compacted: {} → {} bytes, {} records folded.",
            report.before_bytes, report.after_bytes, report.folded_records)]}),
        );
    }
    if kind != "rewind" {
        return Err(Refusal::Invalid);
    }
    let cmd = json!({"kind":"checkpoint.preview","task_id":task});
    let raw = json!({"jsonrpc":"2.0", "id":1, "method":"command.execute", "params":{
        "schema_version":1, "session_id":session, "command":cmd, "task_id":task
    }});
    let answer = machine(runtime, &raw.to_string())?;
    let count = |key: &str| answer[key].as_u64().ok_or(Refusal::Unknown);
    let checkpoint = answer.get("checkpoint").ok_or(Refusal::Unknown)?;
    let detail = if checkpoint.is_null() {
        "Checkpoint: none recorded".to_owned()
    } else {
        format!(
            "Checkpoint: {} folded {} records; apply is a separate action",
            string(checkpoint, "checkpoint_id")?,
            checkpoint["folded_records"]
                .as_u64()
                .ok_or(Refusal::Unknown)?
        )
    };
    Ok(
        json!({"lines":[format!("Rewind preview: task {}, {} assembled bytes; no rollback applied", task.0, count("assembled_bytes")?), detail]}),
    )
}
