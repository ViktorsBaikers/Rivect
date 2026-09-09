//! Minimal read-only tool surface (DXV-1 initial prefix): the typed
//! `read_file` tool routed through executor admission, plus the local
//! command kinds known to the catalog. Known-but-unbuilt capabilities are
//! reported unavailable, never as fake success.

use crate::commands::Runtime;
use crate::contracts::{CommandDescriptor, Page, TaskId};
use crate::executor::{EffectOutcome, EffectRequest, ExecutorError};
use std::path::PathBuf;

pub enum LocalKind {
    PlannedUnimplemented,
    Unknown,
}

const PLANNED_LOCAL_KINDS: &[&str] = &[
    "session.new",
    "session.list",
    "session.search",
    "session.resume",
    "session.fork",
    "session.export",
    "session.recap",
    "session.exit",
    "settings.open",
    "context.compact",
    "context.view",
    "usage.view",
    "checkpoint.preview",
    "checkpoint.apply",
    "permissions.view",
    "model.view",
    "effort.view",
    "workflow.control",
    "harness.control",
    "decisions.control",
    "docs.status",
    "view.clear",
    "config.list",
    "config.search",
    "config.get",
    "config.explain",
    "config.set",
    "config.unset",
    "config.validate",
    "config.export",
    "project.init",
    "doctor",
    "ui.render",
];

pub fn local_command_kind(kind: &str) -> LocalKind {
    if PLANNED_LOCAL_KINDS.contains(&kind) {
        LocalKind::PlannedUnimplemented
    } else {
        LocalKind::Unknown
    }
}

fn descriptor(
    canonical_id: &str,
    aliases: &[&str],
    description: &str,
    available: bool,
) -> CommandDescriptor {
    CommandDescriptor {
        canonical_id: canonical_id.to_string(),
        aliases: aliases.iter().map(|a| a.to_string()).collect(),
        description: description.to_string(),
        busy_policy: if available { "READ" } else { "UNAVAILABLE" }.to_string(),
        available,
        unavailability_reason: if available {
            None
        } else {
            Some("known command without a handler in this build".to_string())
        },
    }
}

/// The initial available prefix plus the planned-but-unbuilt local kinds the
/// catalog already knows about.
pub fn describe() -> Page<CommandDescriptor> {
    let mut items = vec![descriptor(
        "read_file",
        &["read"],
        "Одно разрешённое чтение файла в действующей области.",
        true,
    )];
    for kind in PLANNED_LOCAL_KINDS {
        items.push(descriptor(
            kind,
            &[],
            "Запланированная команда этого каталога.",
            false,
        ));
    }
    Page::new(items, 0)
}

/// Typed tool invoke: everything routes through executor admission; there is
/// no direct filesystem access from the tool layer.
pub fn invoke_read(
    rt: &mut Runtime,
    task_id: &TaskId,
    grant_id: &str,
    path: PathBuf,
) -> Result<EffectOutcome, ExecutorError> {
    let request = EffectRequest::Read {
        grant_id: grant_id.to_string(),
        path,
    };
    let mut executor = Executor::new(&mut rt.policy, &mut rt.owner.store, rt.read_worker.as_mut());
    let admitted = executor.admit(task_id, request)?;
    executor.execute(&admitted)
}

use crate::executor::Executor;
