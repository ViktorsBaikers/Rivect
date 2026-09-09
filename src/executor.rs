//! Effect executor: admission, mutable re-check immediately before the
//! effect, and the read-only macOS backend. Write/exec/egress effects fail
//! closed in this slice; there is no ambient fallback shell.

pub mod macos;

use crate::contracts::{EffectClass, TaskId};
use crate::policy::{Policy, PolicyError};
use crate::state::{StoreError, TaskStore};
use std::path::PathBuf;

pub use macos::{ReadObservation, ReadWorker, WorkerError};

#[derive(Debug, Clone, PartialEq)]
pub enum EffectRequest {
    Read {
        grant_id: String,
        path: PathBuf,
    },
    Write {
        grant_id: String,
        path: PathBuf,
        bytes: Vec<u8>,
    },
    Exec {
        grant_id: String,
        program: PathBuf,
    },
    Egress {
        grant_id: String,
        url: String,
    },
}

impl EffectRequest {
    pub fn class(&self) -> EffectClass {
        match self {
            Self::Read { .. } => EffectClass::Read,
            Self::Write { .. } => EffectClass::Write,
            Self::Exec { .. } => EffectClass::Exec,
            Self::Egress { .. } => EffectClass::Egress,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Self::Read { path, .. } => format!("read {}", path.display()),
            Self::Write { path, .. } => format!("write {}", path.display()),
            Self::Exec { program, .. } => format!("exec {}", program.display()),
            Self::Egress { url, .. } => format!("egress {url}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct AdmittedEffect {
    pub task_id: TaskId,
    pub attempt_id: String,
    pub request: EffectRequest,
    pub scope_root: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
pub enum EffectOutcome {
    Read { bytes: Vec<u8>, digest: String },
    Denied { reason: String },
}

#[derive(Debug, thiserror::Error)]
pub enum ExecutorError {
    #[error("effect denied: {0}")]
    Policy(#[from] PolicyError),
    #[error("effect denied: {0}")]
    Worker(#[from] WorkerError),
    #[error("effect denied: {TASK_CANCELLED}")]
    Cancelled,
    #[error("effect denied: {}", readonly_rejection(*class))]
    Readonly { class: EffectClass },
    #[error("effect store: {0}")]
    Store(#[from] StoreError),
}

pub const TASK_CANCELLED: &str = "task cancelled";

fn readonly_rejection(class: EffectClass) -> String {
    format!(
        "read-only worker rejects {} effects; no ambient fallback",
        match class {
            EffectClass::Write => "write",
            EffectClass::Exec => "exec",
            EffectClass::Egress => "direct egress",
            _ => "this",
        }
    )
}

pub struct Executor<'a> {
    pub policy: &'a mut Policy,
    pub store: &'a mut TaskStore,
    pub worker: &'a mut dyn ReadWorker,
}

impl<'a> Executor<'a> {
    pub fn new(
        policy: &'a mut Policy,
        store: &'a mut TaskStore,
        worker: &'a mut dyn ReadWorker,
    ) -> Self {
        Self {
            policy,
            store,
            worker,
        }
    }

    /// Durable planned intent, then admission. The attempt is visible in the
    /// ledger before any effect can happen.
    pub fn admit(
        &mut self,
        task_id: &TaskId,
        request: EffectRequest,
    ) -> Result<AdmittedEffect, ExecutorError> {
        let grant_id = match &request {
            EffectRequest::Read { grant_id, .. }
            | EffectRequest::Write { grant_id, .. }
            | EffectRequest::Exec { grant_id, .. }
            | EffectRequest::Egress { grant_id, .. } => grant_id.clone(),
        };
        let grant = self.policy.admit(&grant_id, request.class())?;
        let attempt_id = self
            .store
            .plan_attempt(task_id, request.class(), &request.describe())?;
        Ok(AdmittedEffect {
            task_id: task_id.clone(),
            attempt_id,
            request,
            scope_root: grant.scope_root.clone(),
        })
    }

    /// Mutable admission: non-read effects are rejected unconditionally by
    /// the read-only backend before any policy or byte is touched; reads
    /// re-check revocation and cancellation immediately before the effect.
    pub fn execute(&mut self, admitted: &AdmittedEffect) -> Result<EffectOutcome, ExecutorError> {
        if admitted.request.class() != EffectClass::Read {
            let reason = readonly_rejection(admitted.request.class());
            self.store.attempt_rejected(&admitted.attempt_id, &reason)?;
            return Ok(EffectOutcome::Denied { reason });
        }
        let grant_id = match &admitted.request {
            EffectRequest::Read { grant_id, .. } => grant_id.clone(),
            _ => unreachable!("read class checked above"),
        };
        self.policy.admit(&grant_id, EffectClass::Read)?;
        if self.store.task_cancelled(&admitted.task_id)? {
            self.store
                .attempt_rejected(&admitted.attempt_id, TASK_CANCELLED)?;
            return Ok(EffectOutcome::Denied {
                reason: TASK_CANCELLED.to_string(),
            });
        }
        let EffectRequest::Read { path, .. } = &admitted.request else {
            unreachable!("read class checked above")
        };
        self.store.attempt_running(&admitted.attempt_id)?;
        let observation = self
            .worker
            .read_once(&admitted.scope_root, path)
            .map_err(ExecutorError::from)?;
        self.store.set_attempt_state(
            &admitted.attempt_id,
            "confirmed",
            Some(&format!("read-performed sha256={}", observation.digest)),
        )?;
        Ok(EffectOutcome::Read {
            bytes: observation.bytes,
            digest: observation.digest,
        })
    }

    /// Performs the admitted read effect and deliberately loses the
    /// confirmation: the durable record ends `unknown`, modeling a process
    /// death after the effect committed but before the receipt landed. The
    /// real worker read happens exactly once and is marked in the ledger.
    pub fn execute_unconfirmed(
        &mut self,
        admitted: &AdmittedEffect,
    ) -> Result<ReadObservation, ExecutorError> {
        if admitted.request.class() != EffectClass::Read {
            return Err(ExecutorError::Readonly {
                class: admitted.request.class(),
            });
        }
        let grant_id = match &admitted.request {
            EffectRequest::Read { grant_id, .. } => grant_id.clone(),
            _ => unreachable!("read class checked above"),
        };
        self.policy.admit(&grant_id, EffectClass::Read)?;
        if self.store.task_cancelled(&admitted.task_id)? {
            self.store
                .attempt_rejected(&admitted.attempt_id, TASK_CANCELLED)?;
            return Err(ExecutorError::Cancelled);
        }
        let EffectRequest::Read { path, .. } = &admitted.request else {
            unreachable!("read class checked above")
        };
        self.store.attempt_running(&admitted.attempt_id)?;
        let observation = self
            .worker
            .read_once(&admitted.scope_root, path)
            .map_err(ExecutorError::from)?;
        self.store.set_attempt_state(
            &admitted.attempt_id,
            "unknown",
            Some(&format!(
                "read-performed sha256={}; receipt lost after dispatch",
                observation.digest
            )),
        )?;
        Ok(observation)
    }
}

pub fn backend() -> &'static str {
    macos::BACKEND
}
