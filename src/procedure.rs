//! Saved parameterised procedure segments (AC-053, REQ-043, master §12.9):
//! what a segment derived from an executed plan names, how one run binds its
//! parameters, and the one stop decision the control path applies between
//! steps.
//!
//! A segment is never authored by hand: [`SegmentTemplate::derive`] reads the
//! plan revision the plan owner recorded and the rows its handlers closed, so
//! the steps, their tools and their expected outputs are what actually ran.
//! This module holds the types and the pure decisions only; every statement
//! lives in [`crate::state`] (P-002) and every effect goes through
//! [`crate::executor`] (INV-002).

use crate::contracts::{ErrorCode, QuestionId, TaskId};
use crate::executor::EffectRequest;
use crate::state::{PlanObligationRecord, PlanRevisionRecord, StoreError};
use std::collections::BTreeMap;

/// The version of the segment record this build writes and runs. A segment
/// saved under another schema is refused before its first effect instead of
/// being replayed as if its shape had not moved.
pub const PROCEDURE_SCHEMA_VERSION: u64 = 1;

/// The conditions a segment stops its remainder on (AC-053, EDGE-003,
/// EDGE-004). Every run honours all three, and the saved template names them so
/// a reader sees what it will not run past.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopTrigger {
    /// The step's attempt settled `unknown`: the effect may have landed.
    UnknownEffect,
    /// A right the snapshot held is revoked, refused by the effect-time
    /// re-check.
    RevokedRight,
    /// The task waits on a fork the segment's snapshot never held.
    NewMaterialChoice,
}

/// Every trigger a run honours, in the order a run reaches them: the fork is
/// re-checked before the step, the right is re-checked at the effect and the
/// effect's own settlement follows it.
pub const STOP_CONDITIONS: [StopTrigger; 3] = [
    StopTrigger::NewMaterialChoice,
    StopTrigger::RevokedRight,
    StopTrigger::UnknownEffect,
];

impl StopTrigger {
    /// The stored spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::UnknownEffect => "unknown_effect",
            Self::RevokedRight => "revoked_right",
            Self::NewMaterialChoice => "new_material_choice",
        }
    }

    /// The trigger a stored spelling names.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        STOP_CONDITIONS
            .into_iter()
            .find(|trigger| trigger.as_str() == raw)
    }
}

/// One step of an executed plan: the typed tool it called and the output the
/// plan row kept for it, both read back from the store rather than authored.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SegmentStep {
    /// 1-based position in the executed plan's own order.
    pub position: u64,
    /// The capability that performed the step: the tool the plan called.
    pub tool: String,
    /// The output the executed step recorded; a later run's expected output.
    pub expected_output: String,
}

/// A saved segment: one executed plan revision of one selection, ready to run
/// again under new parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SegmentTemplate {
    pub procedure_id: String,
    pub version: u64,
    pub task_id: String,
    pub selection_revision: u64,
    pub plan_revision: u64,
    /// The segment schema this record was written under.
    pub schema_version: u64,
    /// The effect tool the saved steps ran through (another sandbox is not
    /// masked by a past success, master §12.9).
    pub tool_version: String,
    pub stop_conditions: Vec<StopTrigger>,
    pub steps: Vec<SegmentStep>,
}

impl SegmentTemplate {
    /// The identity a task's executed plan derives: stable for the plan
    /// revision it names, so re-deriving the same plan returns the segment
    /// that was saved instead of minting a second one.
    #[must_use]
    pub fn procedure_id_for(task_id: &TaskId, plan_revision: u64) -> String {
        format!("procedure:{}:{plan_revision}", task_id.0)
    }

    /// Derives the segment from the plan that already ran: the revision the
    /// plan owner recorded and the rows its handlers closed, in selection order.
    /// A plan revision of an earlier selection, or a plan whose rows closed
    /// nothing, is refused typed — a segment with no executed step behind it
    /// would be authored by hand.
    ///
    /// # Errors
    /// Returns [`ProcedureError::PlanSuperseded`] when the revision belongs to
    /// an earlier selection and [`ProcedureError::NoExecutedSteps`] when no row
    /// closed with an output.
    pub fn derive(
        task_id: &TaskId,
        selection_revision: u64,
        plan: &PlanRevisionRecord,
        rows: &[PlanObligationRecord],
        tool_version: &str,
    ) -> Result<Self, ProcedureError> {
        if plan.selection_revision != selection_revision {
            return Err(ProcedureError::PlanSuperseded {
                recorded: plan.selection_revision,
                current: selection_revision,
            });
        }
        let mut steps: Vec<SegmentStep> = Vec::new();
        let mut position = 0_u64;
        for row in rows {
            if row.execution != crate::contracts::ObligationExecution::Satisfied {
                continue;
            }
            let Some(expected_output) = row.outcome_json.as_ref() else {
                continue;
            };
            position += 1;
            steps.push(SegmentStep {
                position,
                tool: row.capability.clone(),
                expected_output: expected_output.clone(),
            });
        }
        if steps.is_empty() {
            return Err(ProcedureError::NoExecutedSteps {
                task_id: task_id.0.clone(),
            });
        }
        Ok(Self {
            procedure_id: Self::procedure_id_for(task_id, plan.revision),
            version: 1,
            task_id: task_id.0.clone(),
            selection_revision,
            plan_revision: plan.revision,
            schema_version: PROCEDURE_SCHEMA_VERSION,
            tool_version: tool_version.to_string(),
            stop_conditions: STOP_CONDITIONS.to_vec(),
            steps,
        })
    }

    /// The step at `position`, when the template has one.
    #[must_use]
    pub fn step(&self, position: u64) -> Option<&SegmentStep> {
        self.steps.iter().find(|step| step.position == position)
    }

    /// The steps still ahead of a run that settled `cursor` steps. A one-step
    /// segment has no remainder: stopping and completing coincide (spec edge
    /// cases).
    #[must_use]
    pub fn remainder_after(&self, cursor: u64) -> Vec<SegmentStep> {
        self.steps
            .iter()
            .filter(|step| step.position > cursor)
            .cloned()
            .collect()
    }

    /// Re-validates the saved template against the snapshot a run starts from
    /// (master §12.9: every value of a new run is checked again). A different
    /// tool, schema, selection or plan revision is refused before any effect
    /// rather than replayed against state it was not saved for.
    ///
    /// # Errors
    /// Returns [`ProcedureError::SchemaChanged`], [`ProcedureError::ToolChanged`]
    /// or [`ProcedureError::PlanSuperseded`] with both sides named.
    pub fn prepare(&self, snapshot: &SegmentSnapshot) -> Result<(), ProcedureError> {
        if self.schema_version != PROCEDURE_SCHEMA_VERSION {
            return Err(ProcedureError::SchemaChanged {
                recorded: self.schema_version,
                current: PROCEDURE_SCHEMA_VERSION,
            });
        }
        if self.tool_version != snapshot.tool_version {
            return Err(ProcedureError::ToolChanged {
                recorded: self.tool_version.clone(),
                current: snapshot.tool_version.clone(),
            });
        }
        if snapshot.selection_revision != self.selection_revision
            || snapshot.plan_revision != self.plan_revision
        {
            return Err(ProcedureError::PlanSuperseded {
                recorded: self.selection_revision,
                current: snapshot.selection_revision,
            });
        }
        Ok(())
    }
}

/// The fork a task was waiting on, and the revision it waits under.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PendingFork {
    pub question_id: QuestionId,
    pub revision: u64,
}

/// The state one run starts from, and the state every step re-checks: the
/// selection and plan revision the segment was derived under, the effect tool
/// this build runs, and the fork the task held (AC-053's "new snapshot").
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SegmentSnapshot {
    pub selection_revision: u64,
    pub plan_revision: u64,
    pub tool_version: String,
    pub pending: Option<PendingFork>,
}

/// What a step's durable settlement left for the segment to decide.
#[derive(Debug, Clone, PartialEq)]
pub enum StepOutcome {
    /// The effect settled; the result is the attempt's durable detail.
    Settled { attempt_id: String, result: String },
    /// The effect must not continue the remainder (EDGE-003/EDGE-004).
    Stopped(StopCause),
}

/// What the attempt a prepared step names proves about its effect (PROH-003).
///
/// Only the attempt ledger answers this: the prepared row records the attempt
/// that was about to perform the step, and that attempt's own state says
/// whether anything could have reached the worker. No caller re-derives the
/// answer from how the interrupted call happened to return.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepStanding {
    /// The attempt never reached its effect — it was never stamped, had not
    /// finished admitting, or was refused before the worker. Nothing landed,
    /// so the step may be issued again.
    NotStarted,
    /// The effect landed and its settlement is durable: the step is settled
    /// from the ledger instead of being issued again.
    Landed,
    /// The effect may have landed and the ledger holds no answer yet: the
    /// prepared row is the run's safety record and the remainder stops.
    Unresolved,
}

impl StepStanding {
    /// The standing an attempt state names. An absent attempt — a row never
    /// stamped, or one whose attempt is gone — never started.
    #[must_use]
    pub fn parse(state: Option<&str>) -> Option<Self> {
        match state {
            None | Some("planned" | "rejected") => Some(Self::NotStarted),
            Some("confirmed") => Some(Self::Landed),
            Some("running" | "unknown") => Some(Self::Unresolved),
            Some(_) => None,
        }
    }
}

/// One step a run prepared and did not settle, with what its own attempt
/// proves about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedStep {
    pub position: u64,
    pub tool: String,
    /// The attempt that was about to perform the step.
    pub attempt_id: String,
    pub standing: StepStanding,
    /// The result the attempt's own settlement recorded, when it landed.
    pub result: Option<String>,
}

impl PreparedStep {
    /// The settlement the step's own attempt already earned: the ledger's
    /// result against the attempt that produced it, so a settlement lost after
    /// the effect is completed instead of the effect being issued again.
    #[must_use]
    pub fn settlement(&self) -> SettledStep {
        SettledStep {
            position: self.position,
            tool: self.tool.clone(),
            attempt_id: self.attempt_id.clone(),
            result: settled_result(&self.tool, self.result.as_deref()),
        }
    }
}

/// The result a settled step reports: the durable detail the attempt's own
/// settlement wrote, or the step's tool when it recorded none.
#[must_use]
pub fn settled_result(tool: &str, detail: Option<&str>) -> String {
    detail.map_or_else(|| format!("{tool} settled"), str::to_string)
}

/// What the re-check or the settlement observed that ends the remainder.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StopCause {
    /// The attempt's durable state is unresolved: its effect may already have
    /// landed and nothing has answered whether it did.
    UnknownEffect { attempt_id: String },
    /// The step was prepared and the attempt that owns it is still unresolved:
    /// the run cannot tell whether the effect landed, so it neither runs the
    /// step again nor drops the row. The row stays the run's safety record until the
    /// attempt's own outcome is resolved: a confirmed attempt becomes
    /// [`StepStanding::Landed`] and settles from the ledger instead of running
    /// again (PROH-003), a rejected or never-started one releases the row for a
    /// new attempt, and an `unknown` one is answered only when the
    /// reconciliation path's `reconcile_unknown` finds the `read-performed sha256=`
    /// marker it requires.
    ///
    /// A `running` attempt and a write that ended `unknown` reach none of
    /// those: no owner path answers them, so a run stopped here keeps the row
    /// and stops on this same cause at every later start. That dead end is a
    /// known gap of the reconciliation path, not a recovery this stop performs.
    PreparedStep { position: u64, attempt_id: String },
    /// The effect-time re-check refused the step for a revoked right.
    RevokedRight { grant_id: String },
    /// The task's fork state moved away from the snapshot the run started
    /// under; the carried value is the live state (absent when the fork the
    /// snapshot held was decided).
    NewMaterialChoice { pending: Option<PendingFork> },
}

/// The stop a segment reaches: the condition that fired and the detail it
/// names. The blocker control returns through is the store's own projection for
/// the task's lifecycle, so a stop records no second identity of its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StopDecision {
    pub trigger: StopTrigger,
    pub detail: String,
}

/// The one stop decision (AC-053): an unresolved effect, a revoked right or a
/// fork outside the snapshot ends the remainder. The caller continues only on a
/// [`StepOutcome::Settled`] with the fork state the run started under.
#[must_use]
pub fn stop_decision(cause: &StopCause) -> StopDecision {
    let (trigger, detail) = match cause {
        StopCause::UnknownEffect { attempt_id } => (
            StopTrigger::UnknownEffect,
            format!("attempt {attempt_id} has no settled outcome; the remainder is not run"),
        ),
        StopCause::PreparedStep { position, .. } => (
            StopTrigger::UnknownEffect,
            format!("step {position} was prepared and never settled; the remainder is not run"),
        ),
        StopCause::RevokedRight { grant_id } => (
            StopTrigger::RevokedRight,
            format!("right {grant_id} is revoked; the remainder is not run"),
        ),
        StopCause::NewMaterialChoice {
            pending: Some(fork),
        } => (
            StopTrigger::NewMaterialChoice,
            format!(
                "fork {} revision {} is not the snapshot the segment started under; the remainder is not run",
                fork.question_id.0, fork.revision
            ),
        ),
        StopCause::NewMaterialChoice { pending: None } => (
            StopTrigger::NewMaterialChoice,
            "the fork the segment started under was decided; the remainder needs the new choice"
                .to_string(),
        ),
    };
    StopDecision { trigger, detail }
}

/// Whether a start may open a new run of a segment that already completed one
/// (AC-053). A completed segment's steps are effects that already ran, so a
/// second pass is an explicit request, never what a resume falls through to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunStart {
    /// Continue the newest unfinished run, and refuse when the segment already
    /// completed a run.
    Resume,
    /// Permit a new run once nothing is left to resume: an unfinished run is
    /// still continued, because its settled steps are effects that already
    /// landed.
    Fresh,
}

/// The parameters one run binds into a saved segment: the typed request each
/// step performs. Every bound request is admitted again at its own step, so a
/// revoked or narrowed right refuses it exactly as a first-time request would
/// (INV-001, INV-002).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SegmentBinding {
    requests: BTreeMap<u64, EffectRequest>,
}

impl SegmentBinding {
    /// An empty binding; every step of a run must be bound before it runs.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds the request one step performs.
    #[must_use]
    pub fn bind(mut self, position: u64, request: EffectRequest) -> Self {
        self.requests.insert(position, request);
        self
    }

    /// The request bound to `position`, when the run names one.
    #[must_use]
    pub fn request(&self, position: u64) -> Option<&EffectRequest> {
        self.requests.get(&position)
    }
}

/// Where one persisted run stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunState {
    /// The run has steps left and is not blocked by a stop.
    Running,
    /// Every step settled.
    Completed,
    /// The remainder did not run; the stop names why.
    Stopped,
}

impl RunState {
    /// The stored spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Completed => "completed",
            Self::Stopped => "stopped",
        }
    }

    /// The state a stored spelling names.
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        [Self::Running, Self::Completed, Self::Stopped]
            .into_iter()
            .find(|state| state.as_str() == raw)
    }
}

/// One persisted run of a saved segment: the snapshot it started from, how many
/// steps settled, and — when its remainder stopped — the decision that stopped
/// it.
#[derive(Debug, Clone, PartialEq)]
pub struct ProcedureRun {
    pub run_id: String,
    pub procedure_id: String,
    pub procedure_version: u64,
    pub task_id: String,
    pub snapshot: SegmentSnapshot,
    /// The number of steps that settled; the next step is `cursor + 1`.
    pub cursor: u64,
    pub state: RunState,
    pub stop: Option<StopDecision>,
}

impl ProcedureRun {
    /// The steps this run still has ahead of it.
    #[must_use]
    pub fn remainder(&self, segment: &SegmentTemplate) -> Vec<SegmentStep> {
        segment.remainder_after(self.cursor)
    }
}

/// One settled step and the result the store kept for it: the executed step
/// count and every result stay readable after a stop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettledStep {
    pub position: u64,
    pub tool: String,
    pub attempt_id: String,
    pub result: String,
}

/// A procedure refusal, owner-local (P-001): the segment domain's typed answer
/// for a plan that never ran, a snapshot that moved, or a step a binding does
/// not cover. Store failures keep their own source rather than degrading into
/// one.
#[derive(Debug, thiserror::Error)]
pub enum ProcedureError {
    #[error("no executed plan revision for task {task_id}")]
    PlanMissing { task_id: String },
    #[error("plan revision of selection {recorded} is not the current selection {current}")]
    PlanSuperseded { recorded: u64, current: u64 },
    #[error("the executed plan of task {task_id} closed no step")]
    NoExecutedSteps { task_id: String },
    #[error("segment schema {recorded} is not the {current} this build runs")]
    SchemaChanged { recorded: u64, current: u64 },
    #[error("segment tool {recorded} is not the {current} this build runs")]
    ToolChanged { recorded: String, current: String },
    #[error("step {position} has no bound parameter")]
    UnboundParameter { position: u64 },
    #[error("run cursor {cursor} is past the {steps} steps of {procedure_id}")]
    CursorPastSteps {
        procedure_id: String,
        cursor: u64,
        steps: u64,
    },
    #[error("procedure segment {procedure_id} is not recorded")]
    SegmentMissing { procedure_id: String },
    #[error("procedure run {run_id} is not recorded")]
    RunMissing { run_id: String },
    #[error("run {run_id} settled {cursor} steps; step {position} is not next")]
    StepOutOfOrder {
        run_id: String,
        position: u64,
        cursor: u64,
    },
    #[error("run {run_id} is {state} and takes no transition")]
    RunNotOpen { run_id: String, state: String },
    #[error("procedure segment {procedure_id} already completed run {run_id}")]
    AlreadyCompleted {
        procedure_id: String,
        run_id: String,
    },
    #[error("procedure store: {0}")]
    Store(#[from] StoreError),
}

impl ProcedureError {
    /// The wire code this refusal carries.
    #[must_use]
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::PlanMissing { .. }
            | Self::NoExecutedSteps { .. }
            | Self::UnboundParameter { .. }
            | Self::CursorPastSteps { .. } => ErrorCode::InvalidInput,
            Self::PlanSuperseded { .. } => ErrorCode::StaleIntent,
            Self::SchemaChanged { .. } | Self::ToolChanged { .. } => ErrorCode::UnsupportedVersion,
            Self::SegmentMissing { .. } | Self::RunMissing { .. } => ErrorCode::NotFound,
            Self::StepOutOfOrder { .. }
            | Self::RunNotOpen { .. }
            | Self::AlreadyCompleted { .. } => ErrorCode::Conflict,
            Self::Store(error) => error.code(),
        }
    }
}
