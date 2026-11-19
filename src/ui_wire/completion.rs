use super::{Refusal, composer, string};
use rivect::commands::Runtime;
use rivect::contracts::ErrorCode;
use rustix::fs::{Dir, FileType};
use rustix::io::Errno;
use serde_json::{Value, json};

const MAX_CHOICES: usize = 20;
const MAX_ENTRIES: usize = 2048;

fn directory_error(error: Errno) -> Refusal {
    Refusal::Core(match error {
        Errno::LOOP | Errno::NOTDIR | Errno::ACCESS | Errno::PERM => ErrorCode::Denied,
        Errno::NOENT => ErrorCode::NotFound,
        _ => ErrorCode::StorageUnavailable,
    })
}

fn paths(rt: &Runtime, prefix: &str) -> Result<Vec<String>, Refusal> {
    // Completion must not run user programs, including a policy hook for each directory entry.
    if composer::has_read_hook(rt)
        || prefix.starts_with('/')
        || prefix.split('/').any(|part| part.starts_with('.'))
    {
        return Err(Refusal::Denied);
    }
    let (parent, start) = prefix
        .rsplit_once('/')
        .map_or(("", prefix), |(p, s)| (p, s));
    let parent = rt.scope_root.join(parent);
    if !composer::visible(rt, &parent) {
        return Err(Refusal::Denied);
    }
    let dir = composer::directory(&parent)?;
    let mut names = Vec::new();
    for entry in Dir::read_from(&dir.fd)
        .map_err(directory_error)?
        .take(MAX_ENTRIES)
    {
        let entry = entry.map_err(directory_error)?;
        let suffix = match entry.file_type() {
            FileType::RegularFile => "",
            FileType::Directory => "/",
            _ => continue,
        };
        let Ok(name) = entry.file_name().to_str() else {
            continue;
        };
        if !name.starts_with(start)
            || name.starts_with('.')
            || !composer::visible(rt, &parent.join(name))
        {
            continue;
        }
        let tail = &name[start.len()..];
        names.push(format!("@{prefix}{tail}{suffix}"));
        if names.len() == MAX_CHOICES {
            break;
        }
    }
    if !dir
        .identity
        .same_directory_inode(&composer::directory(&parent)?.identity)
    {
        return Err(Refusal::Denied);
    }
    names.sort_unstable();
    Ok(names)
}

pub(super) fn candidates(params: &Value, rt: Option<&Runtime>) -> Result<Value, Refusal> {
    let token = string(params, "token")?;
    if token.len() > 1024 || token.chars().any(char::is_control) {
        return Err(Refusal::Invalid);
    }
    let names = if let Some(path) = token.strip_prefix('@') {
        paths(rt.ok_or(Refusal::Core(ErrorCode::Conflict))?, path)?
    } else if token.starts_with('/') {
        // Only composer verbs: model tool aliases are not terminal commands.
        [
            "/accounting",
            "/cancel",
            "/clear",
            "/compact",
            "/config",
            "/decision",
            "/decisions",
            "/exit",
            "/harness",
            "/help",
            "/image",
            "/login",
            "/new",
            "/permissions",
            "/read",
            "/resume",
            "/rewind",
            "/settings",
            "/task",
            "/tui",
            "/usage",
            "/workflow",
        ]
        .into_iter()
        .filter(|word| word.starts_with(token))
        .map(str::to_owned)
        .collect()
    } else {
        return Err(Refusal::Invalid);
    };
    Ok(json!({"candidates": names}))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enrolled_names_and_revoked_grants_do_not_disclose_image_metadata()
    -> Result<(), Box<dyn std::error::Error>> {
        let private = tempfile::tempdir()?;
        let project = tempfile::tempdir()?;
        let root = project.path().canonicalize()?;
        std::fs::create_dir(root.join("records"))?;
        for name in ["public.png", "private.png", "records/chart.png"] {
            std::fs::write(root.join(name), b"\x89PNG\r\n\x1a\nfixture")?;
        }
        let mut rt = Runtime::open(
            private.path(),
            Box::new(rivect::providers::LoopbackProvider::new()),
        )?;
        let grant = rt.bind_read_scope(root.clone());
        rt.policy_writer().enroll_deny(root.join("records"))?;
        rt.policy_writer().enroll_deny(root.join("private.png"))?;
        assert_eq!(paths(&rt, "")?, ["@public.png"]);
        assert!(matches!(paths(&rt, "records/"), Err(Refusal::Denied)));
        for path in ["private.png", "records/chart.png"] {
            assert!(matches!(
                composer::image(&mut rt, path, false),
                Err(Refusal::Denied)
            ));
        }
        rt.policy_writer().revoke(&grant);
        assert!(matches!(paths(&rt, ""), Err(Refusal::Denied)));
        assert!(matches!(
            composer::image(&mut rt, "public.png", false),
            Err(Refusal::Denied)
        ));
        Ok(())
    }
}
