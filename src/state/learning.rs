//! The learning store (AC-051, REQ-041): the one writer of candidate deltas,
//! their corpus verdicts, the activation/rollback state machine and the
//! schema generation the ledger reports.
//!
//! Every statement is named in [`super::sql`] (P-002); the types and the pure
//! evaluation live in [`crate::learning`]. The state transitions are
//! conditional statements, not read-then-write (EDGE-002): a transition that
//! matches no row is refused typed and the caller re-reads the surviving row.

use super::sql;
use super::{
    Connection, LEARNING_CORPUS_RETENTION, LEARNING_DELTA_RETENTION, Result, StoreError, TaskId,
    TaskStore, TransactionBehavior, corrupt_column, storage, stored_u64,
};
use crate::config::{
    BaseCutover, BaseDocument, BaseError, BaseInstall, BaseServed, Config, ReceiptAsset,
    SHIPPED_BASE_VERSION, SemanticInputs, UPDATE_ASSETS, UpdateAsset, UpdatePage, UpdatePhase,
    UpdatePolicy, UpdateReceipt, UpdateState, UpdateStatus,
};
use crate::contracts::{ErrorCode, WireError};
use crate::identity::{
    IdentityError, IdentityKind, IdentityMigration, IdentityRebind, IdentityRules, MigrationRule,
    NamedSubject, Placement, ReboundSubject,
};
use crate::learning::{
    ConditionFact, CorpusCandidate, CorpusCase, CorpusVerdict, DEFINITION_MAX_BYTES,
    DeltaCandidate, DeltaChange, DeltaError, DeltaPayload, DeltaRecord, DeltaScope, DeltaState,
    LearningDefinition, LearningDelta, LearningDeltaView, LearningStatus, PredicateEffect,
    corpus_verdict,
};
use crate::model::LARGEST_INSTRUCTION_BASE;
use crate::procedure::{
    PreparedStep, ProcedureError, ProcedureRun, RunStart, RunState, SegmentSnapshot, SegmentStep,
    SegmentTemplate, SettledStep, StepStanding, StopDecision, StopTrigger,
};
use rusqlite::{OptionalExtension, Transaction, params};

/// The schema generation this build writes and reads (DEC-008). A store that
/// reports a newer generation was written by a newer build and is refused
/// typed instead of being read as this build's own generation; `0` and `1` are
/// the generations the store shipped before this ledger existed.
pub const KNOWN_SCHEMA_GENERATION: u64 = 2;

/// The store's schema generation.
///
/// # Errors
/// Returns [`StoreError::Closed`] when the store is not open and
/// [`StoreError::Storage`] when the ledger cannot be read.
pub(super) fn schema_generation_on(conn: &Connection) -> Result<u64> {
    let raw: i64 = conn
        .query_row(sql::SCHEMA_GENERATION, [], |row| row.get(0))
        .map_err(storage)?;
    u64::try_from(raw).map_err(|_negative| corrupt_column("schema generation", &raw.to_string()))
}

/// The three parts of one published generation, read back as one value: the
/// schema the ledger reports, the base that serves and the digest of the
/// effective configuration that base was activated with. An attempt that cannot
/// say which whole tuple it left behind compares these three together; a mixed
/// answer is what the attempt refuses to call its outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenerationTuple {
    pub schema: u64,
    pub base: Option<u64>,
    pub policy: Option<String>,
}

fn delta_missing(delta_id: &str) -> StoreError {
    StoreError::NotFound(super::Missing::Delta(delta_id.to_string()))
}

fn delta_change(
    scope: &str,
    instruction: Option<String>,
    capability: Option<String>,
    effect: Option<String>,
    condition_json: Option<String>,
) -> Result<DeltaChange> {
    let scope = DeltaScope::parse(scope).ok_or_else(|| corrupt_column("delta scope", scope))?;
    let when = match condition_json.as_deref() {
        None => None,
        Some(raw) => Some(
            serde_json::from_str::<ConditionFact>(raw)
                .map_err(|_not_typed| corrupt_column("delta condition", raw))?,
        ),
    };
    let payload = match scope {
        DeltaScope::Instruction => match instruction {
            Some(text) => DeltaPayload::Instruction { text },
            // A row without its instruction is not a shape this producer
            // writes: the scope and the payload move together.
            None => return Err(corrupt_column("delta instruction", "absent")),
        },
        DeltaScope::Applicability => {
            let capability =
                capability.ok_or_else(|| corrupt_column("delta capability", "absent"))?;
            let effect = effect.ok_or_else(|| corrupt_column("delta effect", "absent"))?;
            let effect = PredicateEffect::parse(&effect)
                .ok_or_else(|| corrupt_column("delta effect", &effect))?;
            DeltaPayload::Applicability { capability, effect }
        }
    };
    Ok(DeltaChange { payload, when })
}

fn delta_state(raw: &str) -> Result<DeltaState> {
    DeltaState::parse(raw).ok_or_else(|| corrupt_column("delta state", raw))
}

fn delta_record_on(conn: &Connection, delta_id: &str) -> Result<Option<DeltaRecord>> {
    conn.query_row(sql::LEARNING_DELTA_ROW, params![delta_id], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, Option<String>>(4)?,
            row.get::<_, Option<String>>(5)?,
            row.get::<_, String>(6)?,
            row.get::<_, String>(7)?,
            row.get::<_, i64>(8)?,
        ))
    })
    .optional()
    .map_err(storage)?
    .map(
        |(
            base_version,
            scope,
            instruction,
            capability,
            effect,
            condition,
            evidence,
            state,
            version,
        )| {
            Ok(DeltaRecord {
                delta_id: delta_id.to_string(),
                base_version: u64::try_from(base_version).map_err(|_negative| {
                    corrupt_column("delta base version", &base_version.to_string())
                })?,
                change: delta_change(&scope, instruction, capability, effect, condition)?,
                evidence,
                state: delta_state(&state)?,
                version: u64::try_from(version)
                    .map_err(|_negative| corrupt_column("delta version", &version.to_string()))?,
            })
        },
    )
    .transpose()
}

fn corpus_on(conn: &Connection, delta_id: &str) -> Result<Vec<CorpusVerdict>> {
    let mut statement = conn.prepare(sql::LEARNING_CORPUS_ROWS).map_err(storage)?;
    let rows = statement
        .query_map(params![delta_id], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        })
        .map_err(storage)?;
    let mut verdicts = Vec::new();
    for row in rows {
        let (version, kind, expected, observed, verdict) = row.map_err(storage)?;
        let kind = crate::learning::CorpusCaseKind::parse(&kind)
            .ok_or_else(|| corrupt_column("corpus case kind", &kind))?;
        verdicts.push(CorpusVerdict {
            delta_id: delta_id.to_string(),
            delta_version: u64::try_from(version)
                .map_err(|_negative| corrupt_column("corpus version", &version.to_string()))?,
            kind,
            expected,
            observed,
            passed: match verdict.as_str() {
                "passed" => true,
                "failed" => false,
                other => return Err(corrupt_column("corpus verdict", other)),
            },
        });
    }
    Ok(verdicts)
}

/// The activation gate (I3): every case kind carries a passed verdict for the
/// version the transition is pinned to — the version whose change the corpus
/// judged. A missing row activates nothing, a failed row is refused with the
/// case that failed, and a stale pin is left for the conditional statement to
/// refuse rather than being misreported as an unjudged candidate.
fn require_corpus(delta_id: &str, version: u64, verdicts: &[CorpusVerdict]) -> Result<()> {
    let judged: Vec<&CorpusVerdict> = verdicts
        .iter()
        .filter(|verdict| verdict.delta_version == version)
        .collect();
    for kind in [
        crate::learning::CorpusCaseKind::Transfer,
        crate::learning::CorpusCaseKind::Composition,
        crate::learning::CorpusCaseKind::NegativeControl,
    ] {
        let Some(verdict) = judged.iter().find(|verdict| verdict.kind == kind) else {
            return Err(StoreError::Delta(DeltaError::CorpusMissing {
                delta_id: delta_id.to_string(),
                kind: kind.as_str(),
                version,
            }));
        };
        if !verdict.passed {
            return Err(StoreError::Delta(DeltaError::CorpusRejected {
                delta_id: delta_id.to_string(),
                kind: kind.as_str(),
                expected: verdict.expected.clone(),
                observed: verdict.observed.clone(),
            }));
        }
    }
    Ok(())
}

/// The effective definition: every active delta in record order. Both seams
/// compose from this one read, so the instruction part a request carries and
/// the applicability the selection weighs never disagree. Reading it on a
/// transaction is what lets activation measure the definition the transition
/// just composed before the write commits.
fn definition_on(conn: &Connection) -> Result<LearningDefinition> {
    let mut statement = conn.prepare(sql::ACTIVE_LEARNING_DELTAS).map_err(storage)?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, Option<String>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<String>>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })
        .map_err(storage)?;
    let mut deltas = Vec::new();
    for row in rows {
        let (delta_id, version, instruction, capability, effect, condition) =
            row.map_err(storage)?;
        let scope = if instruction.is_some() {
            DeltaScope::Instruction
        } else {
            DeltaScope::Applicability
        };
        deltas.push(LearningDelta {
            delta_id,
            version: u64::try_from(version)
                .map_err(|_negative| corrupt_column("delta version", &version.to_string()))?,
            change: delta_change(scope.as_str(), instruction, capability, effect, condition)?,
        });
    }
    Ok(LearningDefinition::new(deltas))
}

/// The size the definition on `conn` reaches beside the longest instruction
/// base an assembly site composes onto: the one measurement every
/// definition-changing path refuses at, so an activation and a rebinding
/// certify the same request part (AC-051).
fn definition_size_on(conn: &Connection) -> Result<usize> {
    Ok(definition_on(conn)?.max_instruction_bytes(LARGEST_INSTRUCTION_BASE))
}

impl TaskStore {
    /// The schema generation the store reports.
    ///
    /// # Errors
    /// Returns [`StoreError::Closed`] when the store is not open and
    /// [`StoreError::Storage`] when the ledger cannot be read.
    pub fn schema_generation(&self) -> Result<u64> {
        schema_generation_on(self.conn()?)
    }

    /// The whole generation tuple the primary holds: the schema the ledger
    /// reports, the base that serves and the policy digest that base was
    /// activated with. A store no update installed answers the shipped generation
    /// with no base and no policy, so the caller compares whole tuples rather
    /// than inferring a half.
    ///
    /// # Errors
    /// Returns [`StoreError::Closed`] when the store is not open,
    /// [`StoreError::Storage`] when the ledger cannot be read, and the store's
    /// own storage refusal when a row holds a value no producer writes — a mixed
    /// tuple is unreadable on purpose, never reported as a whole one.
    pub fn generation_tuple(&self) -> Result<GenerationTuple> {
        let schema = schema_generation_on(self.conn()?)?;
        let status = self.update_status().map_err(base_refusal)?;
        Ok(GenerationTuple {
            schema,
            base: status.base_version,
            policy: status.policy_generation,
        })
    }

    /// Whether this connection holds no open transaction. The one probe a caller
    /// runs after a COMMIT whose result did not arrive: an open transaction means
    /// the engine is still inside the attempt, so the tuple cannot be read yet.
    ///
    /// # Errors
    /// Returns [`StoreError::Closed`] when the store is not open.
    pub fn in_autocommit(&self) -> Result<bool> {
        Ok(self.conn()?.is_autocommit())
    }

    /// Ends this store's connection slot without SQL, after a step whose outcome
    /// could not be established: every later call refuses typed until a
    /// compatible reopen reads the whole tuple back. The slot is what
    /// [`TaskStore::conn`] checks first, so no statement runs against a
    /// connection whose transaction state is unknown.
    pub(crate) fn quarantine(&mut self) {
        self.conn = None;
    }

    /// Records one candidate delta `inactive`: validation runs before any
    /// write, so a refused body leaves no row behind.
    ///
    /// # Errors
    /// Returns [`StoreError::Delta`] with the exact violation, and
    /// [`StoreError::Storage`] when the row cannot be written.
    pub fn record_learning_delta(&mut self, candidate: &DeltaCandidate) -> Result<DeltaRecord> {
        candidate.validate()?;
        let condition = candidate
            .change
            .when
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| storage(std::io::Error::other(error)))?;
        let (instruction, capability, effect) = match &candidate.change.payload {
            DeltaPayload::Instruction { text } => (Some(text.clone()), None, None),
            DeltaPayload::Applicability {
                capability,
                effect: decided,
            } => (None, Some(capability.clone()), Some(decided.as_str())),
        };
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        tx.execute(
            sql::INSERT_LEARNING_DELTA,
            params![
                candidate.delta_id,
                stored_u64(candidate.base_version)?,
                candidate.change.scope().as_str(),
                instruction,
                capability,
                effect,
                condition,
                candidate.evidence
            ],
        )
        .map_err(storage)?;
        if tx.changes() == 0 {
            return Err(StoreError::Delta(DeltaError::AlreadyRecorded {
                delta_id: candidate.delta_id.clone(),
            }));
        }
        tx.execute_batch(&sql::prune_learning_candidates(LEARNING_DELTA_RETENTION))
            .map_err(storage)?;
        tx.commit().map_err(storage)?;
        self.learning_delta(&candidate.delta_id)
    }

    /// Runs the bounded corpus over one candidate and records one verdict per
    /// case kind. A failing case is recorded rather than dropped: activation
    /// reads the rows, so the named reason survives a restart and no model is
    /// asked to re-judge it.
    ///
    /// # Errors
    /// Returns [`StoreError::Delta`] when the case set is malformed or a
    /// control delta is unknown, [`StoreError::NotFound`] when the candidate
    /// is not recorded, and [`StoreError::Storage`] when a row cannot be
    /// written.
    pub fn record_learning_corpus(
        &mut self,
        delta_id: &str,
        cases: &[CorpusCase],
    ) -> Result<Vec<CorpusVerdict>> {
        let record = self.learning_delta(delta_id)?;
        if cases.len() > LEARNING_CORPUS_RETENTION {
            return Err(StoreError::Delta(DeltaError::TooManyCases {
                delta_id: delta_id.to_string(),
                count: cases.len(),
                limit: LEARNING_CORPUS_RETENTION,
            }));
        }
        let mut seen = std::collections::BTreeSet::new();
        for case in cases {
            if !seen.insert(case.kind().as_str()) {
                return Err(StoreError::Delta(DeltaError::DuplicateCase {
                    delta_id: delta_id.to_string(),
                    kind: case.kind().as_str(),
                }));
            }
        }

        // I9: the case that proves an overbroad trigger is refused must name a
        // different, already recorded delta as its control, so the case rests
        // on an experience the store actually holds. A recorded payload never
        // changes — only its state and version move — so reading the control
        // before the write transaction cannot judge a different change.
        let mut controls: Vec<Option<LearningDelta>> = Vec::with_capacity(cases.len());
        for case in cases {
            let CorpusCase::NegativeControl { control, .. } = case else {
                controls.push(None);
                continue;
            };
            if control == delta_id {
                return Err(StoreError::Delta(DeltaError::SelfControl {
                    delta_id: delta_id.to_string(),
                }));
            }
            let held = self.learning_delta(control).map_err(|error| match error {
                StoreError::NotFound(_) => StoreError::Delta(DeltaError::UnknownControl {
                    delta_id: delta_id.to_string(),
                    control: control.clone(),
                }),
                other => other,
            })?;
            controls.push(Some(LearningDelta {
                delta_id: held.delta_id,
                version: held.version,
                change: held.change,
            }));
        }
        let active = self.learning_definition()?;
        let candidate = CorpusCandidate {
            delta_id,
            version: record.version,
            change: &record.change,
        };
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        for (case, control) in cases.iter().zip(controls.iter()) {
            let verdict = corpus_verdict(
                &candidate,
                &active,
                control.as_ref(),
                case,
                LARGEST_INSTRUCTION_BASE,
            );
            tx.execute(
                sql::INSERT_LEARNING_CORPUS,
                params![
                    delta_id,
                    stored_u64(verdict.delta_version)?,
                    verdict.kind.as_str(),
                    verdict.expected,
                    verdict.observed,
                    if verdict.passed { "passed" } else { "failed" }
                ],
            )
            .map_err(storage)?;
        }
        tx.commit().map_err(storage)?;
        self.learning_corpus(delta_id)
    }

    /// Activates one candidate (EDGE-002): the corpus must have passed for the
    /// version this transition is pinned to, the state change is one
    /// conditional statement whose `WHERE` carries both the current state and
    /// the caller's version, and the definition the transition composed is
    /// measured before it commits. A second actor's activation matches no row,
    /// is refused typed, and leaves the winner untouched.
    ///
    /// # Errors
    /// Returns [`StoreError::Delta`] with the refusal — a definition that would
    /// compose past [`DEFINITION_MAX_BYTES`] is refused and leaves no row —
    /// [`StoreError::NotFound`] when the candidate is not recorded, and
    /// [`StoreError::Storage`] when the write fails. The definition the store
    /// now composes is returned on success so the caller installs the exact
    /// bytes it activated.
    pub fn activate_learning_delta(
        &mut self,
        delta_id: &str,
        expected_version: u64,
    ) -> Result<LearningDefinition> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let record = delta_record_on(&tx, delta_id)?.ok_or_else(|| delta_missing(delta_id))?;
        let verdicts = corpus_on(&tx, delta_id)?;
        require_corpus(delta_id, expected_version, &verdicts)?;
        let activated: Option<i64> = tx
            .query_row(
                sql::ACTIVATE_LEARNING_DELTA,
                params![delta_id, stored_u64(expected_version)?],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        // The conditional statement is the only transition (EDGE-002): a row
        // that is no longer the inactive version the caller pinned matches
        // nothing, and the row read above only names the state the winner
        // left behind.
        if activated.is_none() {
            return Err(StoreError::Delta(DeltaError::ActivationRefused {
                delta_id: delta_id.to_string(),
                state: record.state,
                version: record.version,
                expected: expected_version,
            }));
        }
        // The composition verdict is a corpus-time snapshot of the active set;
        // the definition a request would carry is not (AC-051). Re-check the
        // bound against the definition this transition just joined — the live
        // active set inside this transaction — beside the longest instruction
        // base an assembly site composes onto, so the size certified here is
        // the size the request that ships carries.
        let size = definition_size_on(&tx)?;
        if size > DEFINITION_MAX_BYTES {
            return Err(StoreError::Delta(DeltaError::CompositionExceeded {
                delta_id: delta_id.to_string(),
                size,
                limit: DEFINITION_MAX_BYTES,
            }));
        }
        tx.commit().map_err(storage)?;
        self.learning_definition()
    }

    /// Withdraws one active delta. Every other active delta stays, and the row
    /// keeps its history as a `rolled_back` tombstone.
    ///
    /// # Errors
    /// Returns [`StoreError::Delta`] with the refusal, [`StoreError::NotFound`]
    /// when the delta is not recorded, and [`StoreError::Storage`] when the
    /// write fails.
    pub fn roll_back_learning_delta(
        &mut self,
        delta_id: &str,
        expected_version: u64,
    ) -> Result<LearningDefinition> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let record = delta_record_on(&tx, delta_id)?.ok_or_else(|| delta_missing(delta_id))?;
        let rolled_back: Option<i64> = tx
            .query_row(
                sql::ROLL_BACK_LEARNING_DELTA,
                params![delta_id, stored_u64(expected_version)?],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        // The same conditional control the activation uses: a delta that is
        // not the active version the caller pinned is left untouched.
        if rolled_back.is_none() {
            return Err(StoreError::Delta(DeltaError::RollbackRefused {
                delta_id: delta_id.to_string(),
                state: record.state,
                version: record.version,
                expected: expected_version,
            }));
        }
        tx.commit().map_err(storage)?;
        self.learning_definition()
    }

    /// One recorded delta with its state and provenance.
    ///
    /// # Errors
    /// Returns [`StoreError::NotFound`] when no such delta is recorded and
    /// [`StoreError::Storage`] when a column cannot be decoded.
    pub fn learning_delta(&self, delta_id: &str) -> Result<DeltaRecord> {
        delta_record_on(self.conn()?, delta_id)?.ok_or_else(|| delta_missing(delta_id))
    }

    /// The corpus verdicts recorded for one delta.
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when a column cannot be decoded.
    pub fn learning_corpus(&self, delta_id: &str) -> Result<Vec<CorpusVerdict>> {
        corpus_on(self.conn()?, delta_id)
    }

    /// The effective definition: every active delta in record order. Both
    /// seams compose from this one read, so the instruction part a request
    /// carries and the applicability the selection weighs never disagree.
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when a row cannot be decoded.
    pub fn learning_definition(&self) -> Result<LearningDefinition> {
        definition_on(self.conn()?)
    }

    /// Activation, rollback and generation visibility for the status payload
    /// (DEC-011): the deltas composing the definition now, the ones withdrawn,
    /// and the schema generation the store reports.
    ///
    /// # Errors
    /// Returns [`StoreError::Storage`] when a row cannot be decoded.
    pub fn learning_status(&self) -> Result<LearningStatus> {
        let conn = self.conn()?;
        let generation = schema_generation_on(conn)?;
        let mut statement = conn.prepare(sql::LEARNING_STATUS_ROWS).map_err(storage)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, i64>(3)?,
                ))
            })
            .map_err(storage)?;
        let mut active = Vec::new();
        let mut rolled_back = Vec::new();
        for row in rows {
            let (delta_id, state, scope, version) = row.map_err(storage)?;
            let view = LearningDeltaView {
                delta_id,
                scope,
                version: u64::try_from(version)
                    .map_err(|_negative| corrupt_column("delta version", &version.to_string()))?,
            };
            match delta_state(&state)? {
                DeltaState::Active => active.push(view),
                DeltaState::RolledBack => rolled_back.push(view),
                DeltaState::Inactive => {}
            }
        }
        Ok(LearningStatus {
            generation,
            active,
            rolled_back,
        })
    }
}

// ----- the product base ledger and its update receipt (AC-054) -----

/// Retention (INV-010) for the retired bases: `base_state` is primary evidence
/// for the base that serves and for the checkpoint a cutover stages, so only a
/// retired base beyond the newest window leaves — with its receipt rows and the
/// identity rules it was released with.
pub const BASE_VERSION_RETENTION: usize = 4;

fn base_document(raw_version: i64, digest: String) -> Result<BaseDocument> {
    Ok(BaseDocument {
        version: u64::try_from(raw_version)
            .map_err(|_negative| corrupt_column("base version", &raw_version.to_string()))?,
        digest,
    })
}

fn update_state(raw: &str) -> Result<UpdateState> {
    UpdateState::parse(raw).ok_or_else(|| corrupt_column("base state", raw))
}

/// The guard the recorded version carries: an offer of the recorded version is
/// a resume only when its bytes are the ones the ledger holds. Other bytes under
/// an unchanged version are a document change the version had to name, so the
/// offer is refused instead of answering the receipt of a document this open did
/// not compose.
pub(super) fn recorded_document_matches(
    recorded: &BaseDocument,
    install: &BaseInstall,
) -> std::result::Result<(), BaseError> {
    if recorded.digest == install.digest {
        Ok(())
    } else {
        Err(BaseError::DocumentChanged {
            version: install.version,
        })
    }
}

/// The add-only expansion of the base ledger (INV-010a): every metadata column
/// this build reads is added when the store does not already have it, through
/// `PRAGMA table_info` introspection and `ALTER TABLE ... ADD COLUMN`. A column
/// already present is left exactly as it is, so a reopen adds nothing twice and no
/// existing column, row or index is rewritten.
///
/// # Errors
/// Returns the store's typed storage error when the column list cannot be read or
/// a column cannot be added.
pub(super) fn expand_base_state(conn: &Connection) -> Result<()> {
    let present = {
        let mut statement = conn.prepare(sql::BASE_STATE_COLUMNS).map_err(storage)?;
        statement
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(storage)?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(storage)?
    };
    for (column, statement) in [
        ("phase", sql::ADD_BASE_STATE_PHASE),
        ("blocker_count", sql::ADD_BASE_STATE_BLOCKER_COUNT),
        ("schema_generation", sql::ADD_BASE_STATE_SCHEMA_GENERATION),
        ("policy_generation", sql::ADD_BASE_STATE_POLICY_GENERATION),
        ("set_epoch", sql::ADD_BASE_STATE_SET_EPOCH),
    ] {
        if !present.iter().any(|name| name == column) {
            conn.execute_batch(statement).map_err(storage)?;
        }
    }
    Ok(())
}

/// Proves the serving row of a store an earlier build wrote still answers a shape
/// this build accepts, and writes nothing.
///
/// A pre-column row has no `phase`, generation or epoch to report, and the shape
/// check accepts exactly that NULL row. Inventing an `activated` milestone, a
/// schema generation or today's resolved policy digest would claim the base was
/// validated under a view that never ran, so this pass leaves the row alone. The
/// epoch an activation needs is backfilled by [`TaskStore::stage_base_on`], which
/// only ever touches a row that already records a set.
///
/// # Errors
/// Returns the store's typed storage error when the serving row cannot be read, and
/// the shape refusal when the row answers metadata this build does not write.
pub(super) fn legacy_base_row_on(tx: &Transaction<'_>) -> Result<()> {
    let Some(active) = base_document_on(tx, UpdateState::Active).map_err(base_refusal)? else {
        return Ok(());
    };
    base_row_metadata(tx, active.version, UpdateState::Active).map_err(base_refusal)?;
    Ok(())
}

/// A base-ledger refusal as the store's own error: the two owners speak the same
/// storage class, and the caller here is the startup transaction, not a base
/// caller.
pub(super) fn base_refusal(error: BaseError) -> StoreError {
    match error {
        BaseError::Store(source) => source,
        other => StoreError::Storage(Box::new(other)),
    }
}

/// One base row's metadata as the store holds it, validated against the shape
/// its state must have. The set's rows are read by the named page statement, so
/// this validation walks them without keeping them.
struct BaseRowMetadata {
    phase: Option<UpdatePhase>,
    blocker_count: Option<u64>,
    schema_generation: Option<u64>,
    policy_generation: Option<String>,
}

/// The one epoch a blocker set is issued, from the never-deleted sequence inside
/// the caller's transaction. A discarded set keeps its epoch consumed, so a page
/// cursor minted for it can never alias the set that replaced it.
fn allocate_set_epoch(tx: &Transaction<'_>) -> std::result::Result<u64, BaseError> {
    let raw: i64 = tx
        .query_row(sql::ALLOCATE_SET_EPOCH, [], |row| row.get(0))
        .map_err(|error| BaseError::Store(storage(error)))?;
    u64::try_from(raw)
        .map_err(|_negative| BaseError::Store(corrupt_column("set epoch", &raw.to_string())))
}

/// The generation a base is activated under, read inside the activating
/// transaction: it names the ledger this same transaction just wrote, so the
/// row and the DDL cannot name different generations.
fn generation_column(tx: &Transaction<'_>) -> std::result::Result<i64, BaseError> {
    let generation = schema_generation_on(tx).map_err(BaseError::Store)?;
    i64::try_from(generation).map_err(|_overflow| {
        BaseError::Store(corrupt_column("schema generation", &generation.to_string()))
    })
}

/// Whether one value is the 64-lowercase-hex digest of an effective
/// configuration: the only shape an activation may record.
fn policy_generation_shape(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Whether one stored address is a canonical blocker pointer: exactly the
/// `learning` or `config` owner, then two JSON-Pointer-escaped tokens. A token
/// decodes in one pass only — every `~` inside it introduces `0` or `1` — so the
/// same record and field can never be addressed by two spellings.
fn canonical_blocker_address(address: &str) -> bool {
    let mut parts = address.split('/');
    let (Some(owner), Some(record), Some(field), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return false;
    };
    matches!(owner, "learning" | "config")
        && canonical_pointer_token(record)
        && canonical_pointer_token(field)
}

/// One canonical JSON-Pointer token: non-empty, and a `~` is always followed by
/// `0` or `1`.
fn canonical_pointer_token(token: &str) -> bool {
    let mut chars = token.chars();
    let mut at_least_one = false;
    while let Some(character) = chars.next() {
        at_least_one = true;
        if character == '~' && !matches!(chars.next(), Some('0' | '1')) {
            return false;
        }
    }
    at_least_one
}

/// The five metadata columns of one base row plus its blocker rows, validated
/// against the shape the row's state must have. `blocker_count IS NULL` is the
/// only legacy discriminator: such a row predates the columns, holds NULL in all
/// five and answers no set. A row this build stages carries the count and the
/// epoch; an activated one also carries the phase and both generations.
fn base_row_metadata(
    conn: &Connection,
    version: u64,
    state: UpdateState,
) -> std::result::Result<BaseRowMetadata, BaseError> {
    let row = conn
        .query_row(sql::BASE_METADATA, params![stored_u64(version)?], |row| {
            Ok((
                row.get::<_, Option<String>>(0)?,
                row.get::<_, Option<i64>>(1)?,
                row.get::<_, Option<i64>>(2)?,
                row.get::<_, Option<String>>(3)?,
                row.get::<_, Option<i64>>(4)?,
            ))
        })
        .optional()
        .map_err(|error| BaseError::Store(storage(error)))?;
    let Some((phase, blocker_count, schema_generation, policy_generation, set_epoch)) = row else {
        return Err(BaseError::ReceiptMissing { version });
    };
    let unsigned = |column: &'static str, raw: i64| {
        u64::try_from(raw)
            .map_err(|_negative| BaseError::Store(corrupt_column(column, &raw.to_string())))
    };
    let blocker_count = blocker_count
        .map(|raw| unsigned("blocker count", raw))
        .transpose()?;
    let schema_generation = schema_generation
        .map(|raw| unsigned("schema generation", raw))
        .transpose()?;
    let set_epoch = set_epoch
        .map(|raw| unsigned("set epoch", raw))
        .transpose()?;
    let phase = phase
        .as_deref()
        .map(|raw| {
            UpdatePhase::parse(raw)
                .ok_or_else(|| BaseError::Store(corrupt_column("base phase", raw)))
        })
        .transpose()?;
    if let Some(policy) = policy_generation.as_deref()
        && !policy_generation_shape(policy)
    {
        return Err(BaseError::Store(corrupt_column(
            "policy generation",
            policy,
        )));
    }

    // The three legal shapes, and nothing in between. A legacy row is the only
    // one allowed to answer NULL everywhere; every row this build wrote carries
    // the count and an epoch, and only an activated one carries a phase.
    if blocker_count.is_none() {
        if phase.is_some()
            || schema_generation.is_some()
            || policy_generation.is_some()
            || set_epoch.is_some()
        {
            return Err(BaseError::Store(corrupt_column(
                "base metadata",
                "a legacy row carries no metadata",
            )));
        }
        return Ok(BaseRowMetadata {
            phase,
            blocker_count,
            schema_generation,
            policy_generation,
        });
    }
    if set_epoch.is_none() {
        return Err(BaseError::Store(corrupt_column(
            "set epoch",
            "a recorded blocker set carries its epoch",
        )));
    }
    match state {
        UpdateState::Staged => {
            if phase.is_some() || schema_generation.is_some() || policy_generation.is_some() {
                return Err(BaseError::Store(corrupt_column(
                    "base metadata",
                    "a staged base carries no activation metadata",
                )));
            }
        }
        UpdateState::Active | UpdateState::Retired => {
            if phase != Some(UpdatePhase::Activated)
                || schema_generation.is_none()
                || policy_generation.is_none()
            {
                return Err(BaseError::Store(corrupt_column(
                    "base metadata",
                    "an activated base carries its phase and both generations",
                )));
            }
        }
    }

    if conn
        .query_row(sql::BASE_BLOCKER_ORPHANS, [], |row| row.get::<_, i64>(0))
        .map_err(|error| BaseError::Store(storage(error)))?
        != 0
    {
        return Err(BaseError::Store(corrupt_column(
            "base blockers",
            "a blocker row names a base the ledger does not hold",
        )));
    }
    let blockers = {
        let mut statement = conn
            .prepare(sql::BASE_BLOCKER_ADDRESSES)
            .map_err(|error| BaseError::Store(storage(error)))?;
        statement
            .query_map(params![stored_u64(version)?], |row| row.get::<_, String>(0))
            .map_err(|error| BaseError::Store(storage(error)))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| BaseError::Store(storage(error)))?
    };
    for address in &blockers {
        if !canonical_blocker_address(address) {
            return Err(BaseError::Store(corrupt_column("blocker address", address)));
        }
    }
    if let Some(count) = blocker_count
        && count != blockers.len() as u64
    {
        return Err(BaseError::Store(corrupt_column(
            "blocker count",
            &format!("{count} rows name {}", blockers.len()),
        )));
    }
    Ok(BaseRowMetadata {
        phase,
        blocker_count,
        schema_generation,
        policy_generation,
    })
}

/// The base one cutover state holds, if any: at most one row per state, so the
/// staged checkpoint and the base still serving are read by name rather than by
/// walking the ledger.
pub(super) fn base_document_on(
    conn: &Connection,
    state: UpdateState,
) -> std::result::Result<Option<BaseDocument>, BaseError> {
    let row = conn
        .query_row(sql::BASE_BY_STATE, params![state.as_str()], |row| {
            Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
        })
        .optional()
        .map_err(|error| BaseError::Store(storage(error)))?;
    let Some((version, digest)) = row else {
        return Ok(None);
    };
    Ok(Some(base_document(version, digest)?))
}

/// The classified assets of one receipt, in the order the classification wrote
/// them. A base row without them has no receipt, so the read refuses instead of
/// answering an empty classification.
fn receipt_assets_on(
    conn: &Connection,
    version: u64,
) -> std::result::Result<Vec<ReceiptAsset>, BaseError> {
    let mut statement = conn
        .prepare(sql::RECEIPT_ASSETS)
        .map_err(|error| BaseError::Store(storage(error)))?;
    let rows = statement
        .query_map(params![stored_u64(version)?], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .map_err(|error| BaseError::Store(storage(error)))?;
    let mut assets = Vec::new();
    for row in rows {
        let (asset, location, policy) = row.map_err(|error| BaseError::Store(storage(error)))?;
        assets.push(ReceiptAsset {
            asset: UpdateAsset::parse(&asset)
                .ok_or_else(|| corrupt_column("receipt asset", &asset))?,
            location,
            policy: UpdatePolicy::parse(&policy)
                .ok_or_else(|| corrupt_column("receipt policy", &policy))?,
        });
    }
    Ok(assets)
}

/// The abandon half of one cutover inside a caller's transaction: the staged
/// row, its receipt and the identity rules its release recorded leave together,
/// and only a staged row is reachable, so abandoning a checkpoint can never
/// retire the base that serves. Its blocker set leaves through the foreign key.
///
/// # Errors
/// Returns [`BaseError::NotStaged`] when the version is not the staged one —
/// nothing is removed then — and the store's typed storage error on a failed read
/// or write.
pub(super) fn abandon_base_on(
    tx: &Transaction<'_>,
    version: u64,
) -> std::result::Result<BaseDocument, BaseError> {
    let staged = base_document_on(tx, UpdateState::Staged)?;
    let Some(staged) = staged.filter(|staged| staged.version == version) else {
        return Err(BaseError::NotStaged { version });
    };
    let removed = tx
        .execute(sql::DELETE_STAGED_BASE, params![stored_u64(version)?])
        .map_err(storage)?;
    if removed == 0 {
        // The row is still staged only if another writer moved it between this
        // read and the delete. Nothing has left the store: the receipt and rule
        // rows are untouched and the transaction rolls back.
        return Err(BaseError::NotStaged { version });
    }
    tx.execute(sql::DELETE_BASE_RECEIPT, params![stored_u64(version)?])
        .map_err(storage)?;
    tx.execute(
        sql::DELETE_BASE_IDENTITY_MIGRATIONS,
        params![stored_u64(version)?],
    )
    .map_err(storage)?;
    Ok(staged)
}

/// The page-scoped refusal a status read carries inside its own answer: the
/// requested base version and the recovery that clears it, never the RPC error
/// envelope — the other collections of the same read must survive.
///
/// `base` is absent from the ledger, so re-requesting it re-enters this same arm
/// forever. The only recovery is a base the ledger does hold: the one serving now,
/// named, or the request with no `base` key at all.
fn page_restart(base: u64, serving: Option<u64>, refusal: Option<&BaseError>) -> WireError {
    let message = match refusal {
        Some(refusal) => refusal.to_string(),
        None => match serving {
            Some(serving) => format!(
                "base {base} is not in the ledger; request the serving base {serving} or omit the base key"
            ),
            None => format!(
                "base {base} is not in the ledger; omit the base key to read the first page"
            ),
        },
    };
    let mut wire = WireError::new(ErrorCode::Conflict, message);
    // The closed `upd.*` namespace holds this refusal too: the page decision is an
    // update boundary, and a caller matching on the token must be able to say so.
    wire.boundary_id = Some(crate::update::UpdateBoundary::BasePage.token().to_string());
    wire
}

/// What one base's row holds for a page read: the ledger lost the base, the row
/// records no set at all, or the row's set at the requested page. The first two
/// are different answers — a legacy row is a legal shape, not a vanished set — so
/// the status must not turn "this row records no set" into "restart from the first
/// page" when no page ever existed.
enum HeldSet {
    /// The ledger holds no row for this base at all.
    NoBase,
    /// The row predates the set columns: it holds NULL in all five, so no page
    /// exists for it and a request for one is the page-scoped refusal.
    NoSet,
    /// The row records a set, read at the caller's page.
    Page(crate::contracts::Page<String>),
}

/// The page of one base's set as the status serves it.
fn blocker_page_for(
    conn: &Connection,
    version: u64,
    limit: u32,
    cursor: Option<(u64, u64)>,
) -> std::result::Result<HeldSet, BaseError> {
    let held = conn
        .query_row(
            sql::BASE_BLOCKER_SET,
            params![stored_u64(version)?],
            |row| row.get::<_, Option<i64>>(1),
        )
        .optional()
        .map_err(|error| BaseError::Store(storage(error)))?;
    match held {
        None => Ok(HeldSet::NoBase),
        // A legacy row recorded no set: its page is absent, and only a cursor
        // that expects rows there is the page-scoped refusal.
        Some(None) => match cursor {
            None => Ok(HeldSet::NoSet),
            Some((requested, _)) => Err(BaseError::BlockerSetGone { version, requested }),
        },
        Some(Some(_)) => {
            let page = blocker_page_on(conn, version, limit, cursor)?;
            Ok(HeldSet::Page(blocker_page(page, version)))
        }
    }
}

/// One page size a store-level page reader accepts: `1..=PAGE_MAX`. A size of zero
/// would ask the read for one probe row, answer `more` and serve an empty page whose
/// next cursor names the same offset, so a caller looping on `next_cursor` would never
/// advance; a size above the ceiling would issue an unbounded `LIMIT`. The wire surface
/// keeps its own caller-side rule — it clamps `page.page_size` before the store sees it —
/// so the two remain told apart.
fn checked_page_size(page_size: u32) -> std::result::Result<u32, BaseError> {
    if (1..=crate::contracts::PAGE_MAX).contains(&page_size) {
        Ok(page_size)
    } else {
        Err(BaseError::InvalidPage {
            detail: "the page size is outside the range this store serves",
        })
    }
}

/// One page of a base's blocker set plus the epoch that identifies the set.
struct BlockerPage {
    addresses: Vec<String>,
    epoch: u64,
    /// The offset this page was read at. The next cursor resumes after the rows
    /// this page served, never after its own length: those differ on every page
    /// whose offset is not zero.
    offset: u64,
    /// One row past the requested page, so a next page is known without a
    /// second count.
    more: bool,
}

/// One bounded page of a base's blocker set, read inside the caller's read
/// transaction so the base row, its set identity and its rows are one
/// generation's answer. `cursor` is the epoch and offset the caller resumed
/// from: an epoch the row no longer holds is the page-scoped conflict, because
/// serving the replacement's rows under it would skip or repeat the set.
fn blocker_page_on(
    conn: &Connection,
    version: u64,
    limit: u32,
    cursor: Option<(u64, u64)>,
) -> std::result::Result<BlockerPage, BaseError> {
    let stored = conn
        .query_row(
            sql::BASE_BLOCKER_SET,
            params![stored_u64(version)?],
            |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()
        .map_err(|error| BaseError::Store(storage(error)))?;
    let (epoch, count) = match stored {
        Some((Some(epoch), Some(count))) => (
            u64::try_from(epoch).map_err(|_negative| {
                BaseError::Store(corrupt_column("set epoch", &epoch.to_string()))
            })?,
            u64::try_from(count).map_err(|_negative| {
                BaseError::Store(corrupt_column("blocker count", &count.to_string()))
            })?,
        ),
        // A row that predates the metadata, a base the ledger does not hold, or
        // a row whose set was never recorded: none of them addresses a set, so a
        // cursor into it restarts.
        _ => {
            return Err(
                cursor.map_or(BaseError::ReceiptMissing { version }, |(requested, _)| {
                    BaseError::BlockerSetGone { version, requested }
                }),
            );
        }
    };
    let offset = match cursor {
        None => 0,
        Some((requested, offset)) => {
            if requested != epoch {
                return Err(BaseError::BlockerSetMoved {
                    version,
                    requested,
                    stored: epoch,
                });
            }
            offset
        }
    };
    let rows = {
        let mut statement = conn
            .prepare(sql::BASE_BLOCKER_PAGE)
            .map_err(|error| BaseError::Store(storage(error)))?;
        statement
            .query_map(
                params![
                    stored_u64(version)?,
                    i64::from(limit) + 1,
                    stored_u64(offset)?
                ],
                |row| row.get::<_, String>(0),
            )
            .map_err(|error| BaseError::Store(storage(error)))?
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|error| BaseError::Store(storage(error)))?
    };
    let more = rows.len() > usize::try_from(limit).unwrap_or(usize::MAX);
    let mut addresses = rows;
    if more {
        // The extra row only answered "is there a next page"; it is not part of
        // this page.
        drop(addresses.pop());
    }
    let served = u64::try_from(addresses.len()).unwrap_or(u64::MAX);
    // A cursor whose offset lands past the set is the caller's refusal, not a
    // corrupt store: the rows this read enumerated are exactly the rows the set
    // holds, so nothing the store wrote contradicts itself. It rides the
    // page-scoped conflict the status still serves, so the rest of the read
    // survives; it never escalates to `storage_unavailable`.
    if offset > count || offset.checked_add(served).is_none_or(|named| named > count) {
        return Err(BaseError::InvalidPage {
            detail: "the cursor offset is past the rows this set holds; restart from the first page",
        });
    }
    Ok(BlockerPage {
        addresses,
        epoch,
        offset,
        more,
    })
}

/// The page a caller resumes at, as the cursor grammar names it:
/// `blk:<base_version>:<set_epoch>:offset:<n>`. The version the cursor carries
/// must be the one the caller asked for — a cursor from another base is not an
/// offset into this set — and every integer must parse inside its domain.
fn parse_blocker_cursor(cursor: &str) -> std::result::Result<(u64, u64, u64), BaseError> {
    let malformed = |detail: &'static str| BaseError::InvalidPage { detail };
    let rest = cursor
        .strip_prefix("blk:")
        .ok_or_else(|| malformed("a cursor must start with blk:"))?;
    let mut parts = rest.split(':');
    let (Some(version), Some(epoch), Some(offset_tag), Some(offset), None) = (
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
        parts.next(),
    ) else {
        return Err(malformed(
            "a cursor is blk:<base_version>:<set_epoch>:offset:<offset>",
        ));
    };
    if offset_tag != "offset" {
        return Err(malformed(
            "a cursor is blk:<base_version>:<set_epoch>:offset:<offset>",
        ));
    }
    let version = version
        .parse::<u64>()
        .map_err(|_overflow| malformed("the cursor base version is not a decimal integer"))?;
    let epoch = epoch
        .parse::<u64>()
        .map_err(|_overflow| malformed("the cursor set epoch is not a decimal integer"))?;
    let offset = offset
        .parse::<u64>()
        .map_err(|_overflow| malformed("the cursor offset is not a decimal integer"))?;
    if offset > i64::MAX as u64 {
        return Err(malformed("the cursor offset is past the storable range"));
    }
    Ok((version, epoch, offset))
}

/// The cursor a caller's page resumes at, checked against the base the request
/// names: a cursor minted for another base is not an offset into this set.
pub(super) fn blocker_cursor_for(
    cursor: &str,
    requested_base: u64,
) -> std::result::Result<(u64, u64), BaseError> {
    let (version, epoch, offset) = parse_blocker_cursor(cursor)?;
    if version != requested_base {
        return Err(BaseError::InvalidPage {
            detail: "the cursor names another base version than the request does; request the base the cursor names, or restart from the first page",
        });
    }
    Ok((epoch, offset))
}

/// The one page of a set a receipt or a status serves, plus the set identity
/// that page belongs to. A terminal page carries no cursor; a page with more
/// rows names the epoch it was read under, so the next read can tell a moved set
/// from a moved newest base.
fn blocker_page(page: BlockerPage, version: u64) -> crate::contracts::Page<String> {
    let mut answer = crate::contracts::Page::new(page.addresses, version);
    if page.more {
        // The next page resumes after the rows this one served. `offset + len`
        // was proved inside the set's count when this page was read, so the sum
        // is exact; the check keeps an arithmetic impossibility from minting a
        // cursor that names nothing.
        let served = u64::try_from(answer.items.len()).unwrap_or(u64::MAX);
        answer.next_cursor = page
            .offset
            .checked_add(served)
            .map(|next| format!("blk:{version}:{}:offset:{next}", page.epoch));
    }
    answer
}

/// One base's receipt: the base's own row supplies the version, the digest and
/// the cutover state, the receipt table the classification, and the identity map
/// the rules the release carries (AC-056) — the one half of the pass a receipt
/// read back from the store answers.
pub(super) fn receipt_on(
    conn: &Connection,
    version: u64,
) -> std::result::Result<Option<UpdateReceipt>, BaseError> {
    Ok(
        receipt_page_on(conn, version, crate::contracts::PAGE_DEFAULT, None)?
            .map(|(receipt, _)| receipt),
    )
}

/// [`receipt_on`] at a caller's page: the receipt's own base is the one the page
/// ranges over, so `cursor` is either absent or an offset into this receipt's
/// set. The set identity the page was read under comes back beside it, so the
/// status can name the epoch a later read resumes from.
pub(super) fn receipt_page_on(
    conn: &Connection,
    version: u64,
    limit: u32,
    cursor: Option<(u64, u64)>,
) -> std::result::Result<Option<(UpdateReceipt, u64)>, BaseError> {
    let row = conn
        .query_row(sql::BASE_BY_VERSION, params![stored_u64(version)?], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
            ))
        })
        .optional()
        .map_err(|error| BaseError::Store(storage(error)))?;
    let Some((raw_version, digest, state)) = row else {
        return Ok(None);
    };
    let base = base_document(raw_version, digest)?;
    let state = update_state(&state)?;
    let metadata = base_row_metadata(conn, base.version, state)?;
    let assets = receipt_assets_on(conn, base.version)?;
    if assets.is_empty() {
        return Err(BaseError::ReceiptMissing {
            version: base.version,
        });
    }
    // A legacy row records no set, so its receipt answers no page; every row this
    // build wrote answers one, empty included.
    let (blockers, epoch) = match metadata.blocker_count {
        None => (None, 0),
        Some(_) => {
            let page = blocker_page_on(conn, base.version, limit, cursor)?;
            let epoch = page.epoch;
            (Some(blocker_page(page, base.version)), epoch)
        }
    };
    Ok(Some((
        UpdateReceipt {
            base_version: base.version,
            digest: base.digest,
            state,
            assets,
            identity: IdentityRebind {
                base_version: base.version,
                migrations: identity_migrations_on(conn, base.version)?,
                rebound: Vec::new(),
                unassigned: Vec::new(),
            },
            phase: metadata.phase,
            blockers,
            schema_generation: metadata.schema_generation,
            policy_generation: metadata.policy_generation,
        },
        epoch,
    )))
}

/// The location each persistent asset exists at in this installation (REQ-044):
/// the caller supplies the two it owns, the store knows the database it was
/// bound to. Only assets [`UPDATE_ASSETS`] names are classified.
pub(super) fn classified_assets(
    store: &TaskStore,
    install: &BaseInstall,
) -> Vec<(UpdateAsset, String)> {
    let store_path = store.bound_db.display().to_string();
    UPDATE_ASSETS
        .iter()
        .map(|asset| {
            let location = match asset {
                UpdateAsset::ConfigFile => install.config_path.display().to_string(),
                UpdateAsset::SqliteRows | UpdateAsset::IndexRows => store_path.clone(),
                UpdateAsset::WorkspaceDirectories => install.workspace_root.display().to_string(),
            };
            (*asset, location)
        })
        .collect()
}

/// Writes one receipt's asset rows. Idempotent by primary key, so a resumed run
/// re-classifies the same checkpoint without widening it.
pub(super) fn write_receipt(
    tx: &Transaction<'_>,
    version: u64,
    assets: &[(UpdateAsset, String)],
) -> Result<()> {
    for (asset, location) in assets {
        tx.execute(
            sql::INSERT_RECEIPT_ASSET,
            params![
                stored_u64(version)?,
                asset.as_str(),
                location,
                asset.policy().as_str()
            ],
        )
        .map_err(storage)?;
    }
    Ok(())
}

/// Fills one base's sealed conflict set from the generation it installs: every
/// user-owned keyed field no rule of the release places, and every stored delta the
/// generation declares no purpose for. The set is written inside the transaction
/// that stages the base, so the row, its count and its rows are one answer, and a
/// re-run over the same document replaces that set rather than widening it
/// (REQ-004).
///
/// A generation that was never resolved against a user layer carries no semantic
/// inputs: nothing is judged, and the set is the empty one every row this build
/// stages carries.
fn seal_blockers_on(
    tx: &Transaction<'_>,
    version: u64,
    semantics: Option<&SemanticInputs>,
) -> std::result::Result<(), BaseError> {
    // A re-seal over a *serving* row that records no set — both columns NULL — is the
    // legal legacy shape, and it leaves that row exactly as it found it. Writing this
    // generation's rows onto it would need a count, an epoch and, on a serving row, the
    // activation milestone together: a count without the epoch is a shape every reader
    // refuses, and inventing the milestone would claim a validation this base never ran
    // under. A staged row is different: it is the checkpoint this build is staging now, so
    // the set lands with the row and `BACKFILL_BASE_SET_EPOCH` gives the surviving
    // pre-column row its epoch.
    let recorded = tx
        .query_row(
            sql::BASE_BLOCKER_SET,
            params![stored_u64(version)?],
            |row| Ok((row.get::<_, Option<i64>>(0)?, row.get::<_, Option<i64>>(1)?)),
        )
        .optional()
        .map_err(|error| BaseError::Store(storage(error)))?;
    let staging_here =
        base_document_on(tx, UpdateState::Staged)?.is_some_and(|row| row.version == version);
    if let Some((None, None)) = recorded
        && !staging_here
    {
        return Ok(());
    }
    let mut addresses = blockless_addresses(tx, version, semantics)?;
    // One spelling per record field: the composite key already forbids a repeat,
    // and the sort is what every page of the set ranges over.
    addresses.sort_unstable();
    // A seal that replaces a different set rotates the epoch in this same
    // transaction as the rows it renames, from the never-deleted sequence: a cursor
    // minted for the discarded set answers `BlockerSetMoved` with both epochs
    // instead of resuming into the replacement. An identical re-seal leaves the
    // epoch alone, so a replay of the same release is not a move. The rule is the
    // recorded set, not the path the seal came from: a staging transaction that
    // re-offers a staged row keeps it through `INSERT OR IGNORE`, and replacing its
    // members under the old epoch would serve a cursor the set it was never minted
    // for.
    let held = recorded.and_then(|(epoch, _)| epoch);
    if held.is_some() {
        let stored = {
            let mut statement = tx
                .prepare(sql::BASE_BLOCKER_ADDRESSES)
                .map_err(|error| BaseError::Store(storage(error)))?;
            statement
                .query_map(params![stored_u64(version)?], |row| row.get::<_, String>(0))
                .map_err(|error| BaseError::Store(storage(error)))?
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|error| BaseError::Store(storage(error)))?
        };
        if stored != addresses {
            let rotated = allocate_set_epoch(tx)?;
            tx.execute(
                sql::SET_BASE_SET_EPOCH,
                params![
                    stored_u64(version)?,
                    i64::try_from(rotated)
                        .map_err(|_overflow| corrupt_column("set epoch", &rotated.to_string()))?
                ],
            )
            .map_err(storage)?;
        }
    }
    tx.execute(sql::DELETE_BASE_BLOCKERS, params![stored_u64(version)?])
        .map_err(storage)?;
    for address in &addresses {
        tx.execute(
            sql::INSERT_BASE_BLOCKER,
            params![stored_u64(version)?, address],
        )
        .map_err(storage)?;
    }
    tx.execute(
        sql::SET_BASE_BLOCKER_COUNT,
        params![
            stored_u64(version)?,
            i64::try_from(addresses.len())
                .map_err(|_overflow| BaseError::Store(corrupt_column("blocker count", "count")))?
        ],
    )
    .map_err(storage)?;
    Ok(())
}

/// The addresses one generation cannot place. A keyed record the base already
/// declares is mapped by the generation itself, and a record some rule of the
/// release places is mapped by that rule; every other stated field of a user
/// record is the scoped conflict.
fn blockless_addresses(
    tx: &Transaction<'_>,
    version: u64,
    semantics: Option<&SemanticInputs>,
) -> std::result::Result<Vec<String>, BaseError> {
    let Some(semantics) = semantics else {
        return Ok(Vec::new());
    };
    let placed: Vec<(IdentityKind, String, String)> = identity_migrations_on(tx, version)
        .map_err(|error| BaseError::Store(StoreError::Storage(Box::new(error))))?
        .into_iter()
        .map(|rule| (rule.kind, rule.old_id, rule.new_id))
        .collect();
    let mut addresses = Vec::new();
    for (key, fields) in &semantics.user_records {
        let declared = semantics.base_purposes.contains(key)
            || placed
                .iter()
                .any(|(kind, from, to)| *kind == IdentityKind::Role && (from == key || to == key));
        if declared {
            continue;
        }
        let record = crate::config::purpose_record_pointer(key);
        for field in fields {
            addresses.push(crate::config::blocker_address(
                "config",
                &record,
                &format!("/{field}"),
            ));
        }
    }
    addresses.extend(unplaced_bindings(tx, semantics)?);
    Ok(addresses)
}

/// The stored bindings the generation leaves unplaced: a delta whose recorded
/// purpose the base does not declare and no role rule names keeps its own id and
/// content — never reminted, never rewritten — and is reported at its exact
/// native address instead. Only the field the record really carries is named.
fn unplaced_bindings(
    tx: &Transaction<'_>,
    semantics: &SemanticInputs,
) -> std::result::Result<Vec<String>, BaseError> {
    let mut statement = tx
        .prepare(sql::LEARNING_DELTA_BINDINGS)
        .map_err(|error| BaseError::Store(storage(error)))?;
    let rows = statement
        .query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, Option<String>>(4)?,
            ))
        })
        .map_err(|error| BaseError::Store(storage(error)))?;
    let mut addresses = Vec::new();
    for row in rows {
        let (delta_id, scope, condition) = row.map_err(|error| BaseError::Store(storage(error)))?;
        if DeltaScope::parse(&scope) != Some(DeltaScope::Instruction) {
            continue;
        }
        let Some(raw) = condition else {
            continue;
        };
        let Ok(ConditionFact::Purpose(purpose)) = serde_json::from_str::<ConditionFact>(&raw)
        else {
            continue;
        };
        if semantics.base_purposes.contains(&purpose) {
            continue;
        }
        addresses.push(crate::config::blocker_address(
            "learning",
            &delta_id,
            "condition_json",
        ));
    }
    Ok(addresses)
}

impl TaskStore {
    /// Whether one base's sealed set names this exact record field. The answer is
    /// a named lookup, so a scoped conflict is enforced by address rather than by
    /// a non-empty set or a page that happens to have been read.
    ///
    /// # Errors
    /// Returns [`BaseError::Store`] when the row cannot be read.
    pub fn base_blocker(
        &self,
        version: u64,
        address: &str,
    ) -> std::result::Result<bool, BaseError> {
        let held: i64 = self
            .conn()?
            .query_row(
                sql::BASE_BLOCKER_AT,
                params![stored_u64(version)?, address],
                |row| row.get(0),
            )
            .map_err(|error| BaseError::Store(storage(error)))?;
        Ok(held != 0)
    }

    /// The base the ledger serves now, if a base was ever installed.
    ///
    /// # Errors
    /// Returns [`BaseError::Store`] when the ledger cannot be read or a column
    /// holds a value this build does not write.
    pub fn active_base(&self) -> std::result::Result<Option<BaseDocument>, BaseError> {
        base_document_on(self.conn()?, UpdateState::Active)
    }

    /// The base a stopped cutover staged and did not commit (EDGE-006): the
    /// checkpoint a re-run resumes from.
    ///
    /// # Errors
    /// Returns [`BaseError::Store`] when the ledger cannot be read.
    pub fn staged_base(&self) -> std::result::Result<Option<BaseDocument>, BaseError> {
        base_document_on(self.conn()?, UpdateState::Staged)
    }

    /// The receipt of one base version, staged or serving or retired.
    ///
    /// # Errors
    /// Returns [`BaseError::ReceiptMissing`] when the ledger holds no such base
    /// and [`BaseError::Store`] when a row cannot be read.
    pub fn update_receipt(&self, version: u64) -> std::result::Result<UpdateReceipt, BaseError> {
        receipt_on(self.conn()?, version)?.ok_or(BaseError::ReceiptMissing { version })
    }

    /// The receipt of one base at a caller's blocker page: the first page by
    /// default, so a caller that asks for nothing reads what
    /// [`TaskStore::update_receipt`] answers.
    ///
    /// # Errors
    /// The refusals [`TaskStore::update_receipt`] reports, plus
    /// [`BaseError::InvalidPage`] for a malformed cursor or a cursor of another
    /// base.
    pub fn update_receipt_page(
        &self,
        version: u64,
        page: &UpdatePage,
    ) -> std::result::Result<UpdateReceipt, BaseError> {
        let page_size = checked_page_size(page.page_size)?;
        let cursor = match page.cursor.as_deref() {
            None => None,
            Some(cursor) => Some(blocker_cursor_for(cursor, version)?),
        };
        receipt_page_on(self.conn()?, version, page_size, cursor)?
            .map(|(receipt, _)| receipt)
            .ok_or(BaseError::ReceiptMissing { version })
    }

    /// The served projection of the base ledger (DEC-011): the base serving now
    /// and the receipt of the newest base the ledger holds. A staged base is
    /// newer than the one still serving, so a waiting cutover is visible here
    /// and its receipt's own state names it.
    ///
    /// # Errors
    /// Returns [`BaseError::Store`] when the ledger cannot be read.
    pub fn update_status(&self) -> std::result::Result<UpdateStatus, BaseError> {
        self.update_status_page(&UpdatePage::default())
    }

    /// The served projection at a caller's blocker page. `requested` names the
    /// base whose set the page ranges over (default: the one serving) and the
    /// cursor the caller resumes at; the receipt keeps its own newest-base
    /// meaning, so the two pages coincide exactly when the request names that
    /// receipt's base with no cursor.
    ///
    /// A page whose set is gone or was re-created cannot be served at the
    /// requested offset. That refusal is page-scoped: it rides
    /// `page_conflict` inside the status the caller still reads, so the other
    /// collections of the same `runtime.status` survive rather than the whole
    /// read failing.
    ///
    /// # Errors
    /// Returns [`BaseError::InvalidPage`] for a malformed cursor, a cursor of
    /// another base or a page size outside its range, and [`BaseError::Store`]
    /// when the ledger cannot be read.
    pub fn update_status_page(
        &self,
        requested: &UpdatePage,
    ) -> std::result::Result<UpdateStatus, BaseError> {
        let page_size = checked_page_size(requested.page_size)?;
        let conn = self.conn()?;
        let serving = base_document_on(conn, UpdateState::Active)?.map(|base| base.version);
        let newest = conn
            .query_row(sql::NEWEST_BASE_VERSION, [], |row| row.get::<_, i64>(0))
            .optional()
            .map_err(|error| BaseError::Store(storage(error)))?;
        let receipt = match newest {
            None => None,
            Some(raw) => {
                let version = u64::try_from(raw)
                    .map_err(|_negative| corrupt_column("base version", &raw.to_string()))?;
                receipt_on(conn, version)?
            }
        };
        // The page the request names: its own base (default: the serving one)
        // and the cursor's offset into that set. The receipt above keeps its
        // newest-base meaning, so the two pages agree exactly when the request
        // names that receipt's base from the first page.
        // The metadata fields keep the receipt's own meaning — the newest
        // attempt's row — while `blockers` ranges over the *requested* base, so a
        // page read never depends on which base happens to be the newest.
        let (phase, schema_generation, policy_generation) = match receipt.as_ref() {
            Some(receipt) => (
                receipt.phase,
                receipt.schema_generation,
                receipt.policy_generation.clone(),
            ),
            None => (None, None, None),
        };
        let mut blockers = None;
        let mut page_conflict = None;
        if let Some(base) = requested.base.or(serving) {
            let cursor = match requested.cursor.as_deref() {
                None => None,
                Some(cursor) => Some(blocker_cursor_for(cursor, base)?),
            };
            match blocker_page_for(conn, base, page_size, cursor) {
                Ok(HeldSet::Page(page)) => blockers = Some(page),
                // A legacy row records no set: the legal shape has no page to
                // serve, so the status answers no page and no conflict — the
                // cursor refusal belongs to a caller holding one into a set that is
                // gone, not to a base that never had one.
                Ok(HeldSet::NoSet) => {}
                // A base the ledger no longer holds: the refusal names the base
                // that answers instead, and the rest of this status still does.
                Ok(HeldSet::NoBase) => {
                    page_conflict = Some(page_restart(base, serving, None));
                }
                Err(
                    refusal @ (BaseError::BlockerSetMoved { .. }
                    | BaseError::BlockerSetGone { .. }
                    | BaseError::InvalidPage { .. }),
                ) => {
                    page_conflict = Some(page_restart(base, serving, Some(&refusal)));
                }
                Err(other) => return Err(other),
            }
        }
        Ok(UpdateStatus {
            base_version: serving,
            receipt,
            phase,
            blockers,
            schema_generation,
            policy_generation,
            // The retained cause and its record pointer live in the attempt
            // record under the data root, which this owner does not know: the
            // status surface projects them (`src/commands.rs`).
            failure: None,
            evidence: None,
            page_conflict,
            evidence_truncated: None,
        })
    }

    /// Stages one base as the next one to serve, with the receipt of every
    /// asset this build writes. The base serving now is untouched: only a
    /// committed successor replaces it (PROH-004), so an interruption between
    /// this stage and [`TaskStore::commit_base`] leaves the previous base
    /// serving and the new one staged.
    ///
    /// The recorded base decides which step this is: the same document under the
    /// recorded version answers the receipt it already has, the same version with
    /// other bytes is refused ([`BaseError::DocumentChanged`]), a version one
    /// step ahead stages, an older one is refused ([`BaseError::NewerRecorded`])
    /// and a version that skips a step is refused
    /// ([`BaseError::SkippedVersion`], EDGE-005).
    ///
    /// # Errors
    /// The refusals above, [`BaseError::AlreadyStaged`] when another document is
    /// already staged, [`BaseError::DocumentChanged`] when the recorded version
    /// arrived with other bytes, and [`BaseError::Store`] when a read or write
    /// fails.
    pub fn stage_base(
        &mut self,
        install: &BaseInstall,
    ) -> std::result::Result<UpdateReceipt, BaseError> {
        let assets = classified_assets(self, install);
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| BaseError::Store(storage(error)))?;
        if let Err(refusal) = Self::stage_base_on(&tx, install, &assets) {
            let rolled = tx.rollback().map_err(|_failed| ());
            return Err(self.classify_rollback(install.version, refusal, rolled));
        }
        tx.commit().map_err(storage)?;
        // The pin the caller validated this document against lives in memory
        // until the activation that records it: the staged row itself carries no
        // activation metadata, and a crash before the commit leaves a checkpoint
        // the next run re-stages with a freshly resolved object.
        self.staged_policy = Some(install.policy_generation.clone());
        self.update_receipt(install.version)
    }

    /// [`TaskStore::stage_base`]'s body inside a caller's transaction: the
    /// startup path stages and activates a base in the one generation
    /// transaction, so this seam never opens a second one. A staged row carries
    /// the metadata every row this build writes carries — the count of its
    /// (empty here) blocker set and the epoch the sequence issued for it — while
    /// the three activation-only columns stay NULL.
    ///
    /// # Errors
    /// The refusals [`TaskStore::stage_base`] documents.
    pub(crate) fn stage_base_on(
        tx: &Transaction<'_>,
        install: &BaseInstall,
        assets: &[(UpdateAsset, String)],
    ) -> std::result::Result<(), BaseError> {
        if let Some(active) = base_document_on(tx, UpdateState::Active)? {
            if install.version < active.version {
                return Err(BaseError::NewerRecorded {
                    offered: install.version,
                    recorded: active.version,
                });
            }
            if install.version == active.version {
                recorded_document_matches(&active, install)?;
                // The recorded document is already installed: its row and set
                // answer as written, and a re-run reuses the epoch a discarded
                // set already consumed instead of minting another.
                return Ok(());
            }
            if install.version != active.version + 1 {
                return Err(BaseError::SkippedVersion {
                    offered: install.version,
                    recorded: active.version,
                });
            }
        }
        if let Some(staged) = base_document_on(tx, UpdateState::Staged)?
            && (staged.version != install.version || staged.digest != install.digest)
        {
            return Err(BaseError::AlreadyStaged {
                version: staged.version,
            });
        }
        let epoch = allocate_set_epoch(tx)?;
        tx.execute(
            sql::INSERT_BASE,
            params![
                stored_u64(install.version)?,
                install.digest,
                UpdateState::Staged.as_str(),
                i64::try_from(epoch)
                    .map_err(|_overflow| corrupt_column("set epoch", &epoch.to_string()))?
            ],
        )
        .map_err(storage)?;
        write_receipt(tx, install.version, assets)?;
        // The set is sealed with the row that names it: the validated generation,
        // the rules its release already recorded and the conflicts it cannot
        // resolve become one tuple, so a page read can never see a count without
        // its rows.
        seal_blockers_on(tx, install.version, install.semantics.as_ref())?;
        // A row an earlier build staged under these exact bytes survived the
        // `OR IGNORE` above, so it does not carry the epoch just allocated. This
        // build is about to activate it, and every reader refuses a row whose set
        // has no epoch, so the row is given one before that can happen.
        tx.execute(
            sql::BACKFILL_BASE_SET_EPOCH,
            params![
                stored_u64(install.version)?,
                i64::try_from(epoch)
                    .map_err(|_overflow| corrupt_column("set epoch", &epoch.to_string()))?
            ],
        )
        .map_err(storage)?;
        Ok(())
    }

    /// The stage half of one cutover inside a caller's transaction (EDGE-006):
    /// the offered document is staged and a checkpoint it may replace is
    /// returned, so the caller commits both in the same transaction it is
    /// already in. A refusal that must win never touches a checkpoint.
    ///
    /// # Errors
    /// The [`TaskStore::stage_base`] refusals; a checkpoint of another document
    /// under this version is the one recoverable refusal and is discarded here.
    pub(crate) fn stage_for_cutover_on(
        tx: &Transaction<'_>,
        install: &BaseInstall,
        assets: &[(UpdateAsset, String)],
    ) -> std::result::Result<Option<BaseDocument>, BaseError> {
        match Self::stage_base_on(tx, install, assets) {
            Ok(()) => Ok(None),
            // The only recoverable refusal: a checkpoint that never served,
            // holding a version this build is at or past. A newer checkpoint
            // propagates, and the guards have already passed, so the re-stage
            // below can only fail on a store fault.
            Err(BaseError::AlreadyStaged { version }) if version <= install.version => {
                let abandoned = abandon_base_on(tx, version)?;
                Self::stage_base_on(tx, install, assets)?;
                Ok(Some(abandoned))
            }
            Err(refusal) => Err(refusal),
        }
    }

    /// Commits the staged base: the base serving now stops serving, the staged
    /// one takes over and the rules that base was released with place every
    /// stored binding — in one transaction (AC-056), so no caller can activate a
    /// base whose pins, deltas and disables stay bound to the retired ids. A
    /// version the ledger never staged matches no row, so nothing moves and the
    /// previous base keeps serving; a rule set the pass refuses rolls the
    /// activation back with it.
    ///
    /// # Errors
    /// Returns [`BaseError::NotStaged`] when the version is not staged, the
    /// identity refusals [`IdentityError`] reports through [`BaseError::Identity`],
    /// and [`BaseError::Store`] when the write fails or the validated policy this
    /// process staged is no longer known.
    ///
    /// A refusal inside the transaction is undone by an explicit `ROLLBACK`
    /// whose own result decides the outcome: a rollback that reports an error
    /// leaves the connection in a state this call cannot vouch for, so the store
    /// is quarantined and [`BaseError::RollbackFailed`] names it. A `COMMIT` that
    /// answers with an error is read back — an ended transaction plus one whole
    /// tuple is the answer, anything else quarantines as
    /// [`BaseError::OutcomeUnread`]. Neither path retries blind, and neither
    /// treats a dropped handle as a success.
    pub fn commit_base(&mut self, version: u64) -> std::result::Result<UpdateReceipt, BaseError> {
        let pin = self.staged_policy.clone();
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| BaseError::Store(storage(error)))?;
        let identity = match Self::prepare_activation(&tx, version, pin.as_deref()) {
            Ok(identity) => identity,
            Err(refusal) => {
                // The rollback result is the evidence: the transaction is consumed
                // by it, so the store can no longer be observed through it.
                let rolled = match Self::fault_step("rollback") {
                    // The injected rollback that never runs: the transaction is
                    // left open, which is exactly the state the classification
                    // must refuse instead of calling it undone.
                    true => {
                        let mut tx = tx;
                        tx.set_drop_behavior(rusqlite::DropBehavior::Ignore);
                        drop(tx);
                        Err(())
                    }
                    false => tx.rollback().map_err(|_failed| ()),
                };
                return Err(self.classify_rollback(version, refusal, rolled));
            }
        };
        let committed = match Self::fault_step("commit") {
            // The injected ambiguity: the `COMMIT` result never arrives and the
            // transaction is still open, which is what an interrupted commit
            // leaves behind.
            true => {
                let mut tx = tx;
                tx.set_drop_behavior(rusqlite::DropBehavior::Ignore);
                drop(tx);
                Err(rusqlite::Error::SqliteFailure(
                    rusqlite::ffi::Error::new(rusqlite::ffi::SQLITE_BUSY),
                    Some("the activation commit did not answer".to_string()),
                ))
            }
            false => tx.commit(),
        };
        if let Err(source) = committed {
            return self.read_back_after_refused_commit(version, source);
        }
        self.staged_policy = None;
        let mut receipt = self.update_receipt(version)?;
        receipt.identity = identity;
        Ok(receipt)
    }

    /// The steps of one activation that run before its `COMMIT`: the staged
    /// check, the pin the caller validated this document against, and the
    /// activation itself. A refusal here is the caller's to undo explicitly.
    fn prepare_activation(
        tx: &Transaction<'_>,
        version: u64,
        pin: Option<&str>,
    ) -> std::result::Result<IdentityRebind, BaseError> {
        let staged =
            base_document_on(tx, UpdateState::Staged)?.is_some_and(|row| row.version == version);
        if !staged {
            // Refused before the pin is examined: a version nothing staged is
            // the caller's mistake, not a missing policy.
            return Err(BaseError::NotStaged { version });
        }
        let Some(pin) = pin else {
            return Err(BaseError::Store(corrupt_column(
                "policy generation",
                "no validated policy was pinned for this activation",
            )));
        };
        Self::commit_base_on(tx, version, pin)
    }

    /// Classifies one refused activation from the primary itself, after its
    /// transaction ended or failed to end: an ended connection that still holds
    /// another serving base answered the old tuple, so the original refusal stands;
    /// an open transaction or an unreadable tuple quarantines the store as
    /// [`BaseError::RollbackFailed`] until a compatible reopen reads the tuple
    /// back. A destructor never counts as the rollback.
    fn classify_rollback(
        &mut self,
        version: u64,
        refusal: BaseError,
        rolled: std::result::Result<(), ()>,
    ) -> BaseError {
        if rolled.is_ok() {
            return refusal;
        }
        match self.in_autocommit() {
            Ok(true) => match self.generation_tuple() {
                Ok(tuple) if tuple.base != Some(version) => refusal,
                _ => {
                    self.quarantine();
                    BaseError::RollbackFailed { version }
                }
            },
            // An unreadable state is not a rollback: refuse to claim one.
            Ok(false) | Err(_) => {
                self.quarantine();
                BaseError::RollbackFailed { version }
            }
        }
    }

    /// The one test-armed fault of this seam, outside the `upd.*` namespace: it
    /// names the step whose failure the proof injects, so a real rollback failure
    /// and a real ambiguous commit are exercised rather than simulated by dropping
    /// a handle.
    ///
    /// Contained by build, not by a runtime check: the environment probe exists only
    /// in a build with debug assertions on. A release binary carries the constant
    /// `false` below, so no environment string can make it drop a transaction and
    /// quarantine a store. The effect stays on the activation's own transaction, so
    /// even an armed debug build cannot corrupt state outside the store it refuses.
    #[cfg(debug_assertions)]
    fn fault_step(step: &str) -> bool {
        std::env::var_os("RIVECT_UPDATE_FAULT_STEP").is_some_and(|value| value == step)
    }

    /// The release build's answer: no environment names a step, so no transaction is
    /// dropped for one.
    #[cfg(not(debug_assertions))]
    fn fault_step(_step: &str) -> bool {
        false
    }

    /// Establishes which tuple a `COMMIT` that answered with an error left
    /// behind, from the primary itself: an ended transaction that now serves the
    /// offered base answered a commit that landed, one that still serves another
    /// base answered a rollback the engine already performed, and anything else —
    /// an open transaction, an unreadable tuple — quarantines the store instead of
    /// retrying blind.
    fn read_back_after_refused_commit(
        &mut self,
        version: u64,
        source: rusqlite::Error,
    ) -> std::result::Result<UpdateReceipt, BaseError> {
        if !self.in_autocommit().unwrap_or(false) {
            self.quarantine();
            return Err(BaseError::OutcomeUnread { version });
        }
        match self.generation_tuple() {
            Ok(tuple) if tuple.base == Some(version) => {
                // The activation landed: the row serves, so the receipt is read
                // from the tuple rather than fabricated from the failed call.
                self.staged_policy = None;
                self.update_receipt(version)
            }
            Ok(_old) => Err(BaseError::Store(storage(source))),
            Err(_unreadable) => {
                self.quarantine();
                Err(BaseError::OutcomeUnread { version })
            }
        }
    }

    /// [`TaskStore::commit_base`]'s body inside a caller's transaction: the
    /// activation, the rule pass and retention land together, and the startup
    /// transaction calls this seam so no nested `BEGIN` can deadlock the one
    /// generation commit. `policy_generation` is the digest of the effective
    /// configuration the cutover was validated against and is recorded as given —
    /// it is never recomputed after validation.
    ///
    /// # Errors
    /// The refusals [`TaskStore::commit_base`] documents.
    #[expect(
        clippy::needless_borrow,
        reason = "the rebinding seam is called once, from this function, with this exact argument"
    )]
    pub(crate) fn commit_base_on(
        tx: &Transaction<'_>,
        version: u64,
        policy_generation: &str,
    ) -> std::result::Result<IdentityRebind, BaseError> {
        if !policy_generation_shape(policy_generation) {
            return Err(BaseError::Store(corrupt_column(
                "policy generation",
                policy_generation,
            )));
        }
        let generation = generation_column(tx)?;
        // A staged row whose set carries no epoch is metadata no reader accepts,
        // so activating it would publish exactly the unreadable state this guard
        // exists to prevent. Only a row that recorded a set is refused here: a
        // legacy row records none and is staged by nothing.
        let epochless = tx
            .query_row(sql::BASE_METADATA, params![stored_u64(version)?], |row| {
                Ok(row.get::<_, Option<i64>>(1)?.is_some()
                    && row.get::<_, Option<i64>>(4)?.is_none())
            })
            .optional()
            .map_err(storage)?;
        if epochless == Some(true) {
            return Err(BaseError::Store(corrupt_column(
                "set epoch",
                "a recorded blocker set carries its epoch",
            )));
        }
        tx.execute(sql::RETIRE_ACTIVE_BASE, params![stored_u64(version)?])
            .map_err(storage)?;
        let activated = tx
            .execute(
                sql::ACTIVATE_BASE,
                params![stored_u64(version)?, generation, policy_generation],
            )
            .map_err(storage)?;
        if activated == 0 {
            // The transaction drops without committing: the retirement above
            // is rolled back with it, so a refused cutover leaves the previous
            // base serving instead of a store without one.
            return Err(BaseError::NotStaged { version });
        }
        // The rules bind to the base that now serves, so the pass reads the set
        // this very base was released with; a refusal here is the same drop of
        // the transaction, with the previous base still serving.
        let identity = rebind_learning_identities_on(&tx)?;
        tx.execute_batch(&sql::prune_base_versions(BASE_VERSION_RETENTION))
            .map_err(storage)?;
        Ok(identity)
    }

    /// Applies the base this build serves in one call — the write surface an
    /// open or an update run uses: the first base is recorded, the same document
    /// under the recorded version answers the receipt it already has, and an
    /// older recorded base is staged then committed. The two writes stay separate
    /// transactions, so a run that dies between them leaves the resumable state
    /// [`TaskStore::stage_base`] describes.
    ///
    /// A checkpoint is the one state this surface repairs instead of refusing
    /// (EDGE-006): a stopped cutover's staged document is not rewritten in place,
    /// so a checkpoint this build cannot resume — one left by a corrected build,
    /// or a first install that never committed — would otherwise answer
    /// [`BaseError::AlreadyStaged`] on every later open with no surface able to
    /// clear it. Which refusal wins, by the state the ledger is in:
    ///
    /// - **recorded version, other bytes** — [`BaseError::DocumentChanged`]
    ///   wins and every row stays: this version is recorded with a document this
    ///   build does not have, which no cutover may rewrite, and the checkpoint
    ///   remains the resumable one for a build that can step from it.
    /// - **checkpoint of a version beyond this build's** —
    ///   [`BaseError::AlreadyStaged`] wins and nothing is removed: an older build
    ///   never discards a newer one's document.
    /// - **checkpoint of this build's version, other bytes** (a corrected build's
    ///   document) or **an older checkpoint under no serving base** — it never
    ///   served and installs nothing, so it is abandoned and the offered document
    ///   staged in its place; the outcome names what left
    ///   ([`BaseServed::abandoned`]).
    /// - **a step this build may not take** — EDGE-005's
    ///   [`BaseError::SkippedVersion`] and I-6's [`BaseError::NewerRecorded`] win
    ///   before any checkpoint is examined, so a refusal never leaves the ledger
    ///   without the checkpoint a stepping build needs.
    ///
    /// # Errors
    /// The [`TaskStore::stage_base`] and [`TaskStore::commit_base`] refusals —
    /// EDGE-005's skipped version and the changed document under a recorded
    /// version included.
    pub fn serve_base(
        &mut self,
        install: &BaseInstall,
    ) -> std::result::Result<BaseServed, BaseError> {
        self.cut_over_serving(install, &[])
    }

    /// The one entry a release cuts a base over through (AC-054, AC-056): the
    /// base is installed, the identity rules it was released with place every
    /// stored binding in the transaction that activates it, and the user
    /// document's purpose rows follow the role rules once that transaction
    /// committed. The moves the document will make are proven against a copy
    /// first, so a document that cannot carry its pins refuses the cutover
    /// before the ledger moves; a rule set the pass refuses rolls the activation
    /// back, leaving the previous base serving with nothing rebound, and a
    /// second run over an already-installed base answers the receipt it has and
    /// moves nothing.
    ///
    /// # Errors
    /// Returns [`TaskStore::serve_base`]'s refusals, the identity refusals
    /// [`TaskStore::commit_base`] reports, and [`BaseError::Document`] when the
    /// user document cannot carry a move the rules name.
    pub fn cut_over_base(
        &mut self,
        install: &BaseInstall,
        rules: &[IdentityMigration],
        config: &mut Config,
    ) -> std::result::Result<BaseCutover, BaseError> {
        let moves = config.planned_purpose_moves(rules)?;
        let served = self.cut_over_serving(install, rules)?;
        Ok(BaseCutover {
            served,
            edit: config.move_purpose_bindings(&moves)?,
        })
    }

    /// The store side of one cutover: the rules are recorded under the base being
    /// installed — the release ships them with it, so they wait beside the
    /// checkpoint instead of naming a base the ledger does not hold — and the
    /// commit places them. A base that already serves answers its receipt, so a
    /// re-run applies nothing; the rules still record, because a resumed run
    /// replays them.
    fn cut_over_serving(
        &mut self,
        install: &BaseInstall,
        rules: &[IdentityMigration],
    ) -> std::result::Result<BaseServed, BaseError> {
        let abandoned = match self.active_base()? {
            Some(active) if active.version == install.version => {
                recorded_document_matches(&active, install)?;
                self.record_release_rules(install, rules)?;
                return Ok(BaseServed {
                    receipt: self.update_receipt(install.version)?,
                    abandoned: None,
                });
            }
            _ => self.stage_for_cutover(install)?,
        };
        self.record_release_rules(install, rules)?;
        Ok(BaseServed {
            receipt: self.commit_base(install.version)?,
            abandoned,
        })
    }

    /// Records the rules a base's release carries under that base, one
    /// transaction for the set: a rule the map cannot hold leaves the ledger
    /// exactly as it was, and a replayed rule re-reads the row it already has.
    /// The scoped set is re-sealed in the same transaction, because a subject a
    /// rule places is no longer a conflict — the set and the rules it was judged
    /// against land together.
    fn record_release_rules(
        &mut self,
        install: &BaseInstall,
        rules: &[IdentityMigration],
    ) -> std::result::Result<(), BaseError> {
        if rules.is_empty() {
            return Ok(());
        }
        let version = install.version;
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| BaseError::Store(storage(error)))?;
        for rule in rules {
            record_migration_on(&tx, rule, version)?;
        }
        seal_blockers_on(&tx, version, install.semantics.as_ref())?;
        tx.commit().map_err(storage)?;
        Ok(())
    }

    /// The stage half of a cutover (EDGE-006): the offered document is staged
    /// and the checkpoint it may replace is reported. The guards a step this
    /// build may not take are decided by [`TaskStore::stage_base`], so a refusal
    /// that must win never touches a checkpoint.
    fn stage_for_cutover(
        &mut self,
        install: &BaseInstall,
    ) -> std::result::Result<Option<BaseDocument>, BaseError> {
        let assets = classified_assets(self, install);
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| BaseError::Store(storage(error)))?;
        let abandoned = Self::stage_for_cutover_on(&tx, install, &assets)?;
        tx.commit().map_err(storage)?;
        self.staged_policy = Some(install.policy_generation.clone());
        Ok(abandoned)
    }

    /// Abandons the checkpoint a stopped cutover staged (EDGE-006): the staged
    /// row, its receipt and the identity rules its release recorded under that
    /// version leave in one transaction, so a run that will never commit those
    /// bytes unblocks the next step instead of leaving a checkpoint nothing can
    /// replace. The base serving now is untouched — abandoning a checkpoint
    /// installs nothing and retires nothing.
    ///
    /// The rules leave with the checkpoint because they name it: a rule that
    /// outlived its base would place stored bindings by a document no cutover
    /// committed, and once that version's base did commit, the discarded rule
    /// would answer as its set with no surface able to clear it.
    ///
    /// [`TaskStore::serve_base`] calls it for a checkpoint this build cannot
    /// resume, and that is what keeps such a checkpoint from wedging every later
    /// open; a caller staging a different document under the same version clears
    /// the checkpoint here first.
    ///
    /// # Errors
    /// Returns [`BaseError::NotStaged`] when the version is not the staged one —
    /// nothing is removed then — and [`BaseError::Store`] when a read or write
    /// fails.
    pub fn abandon_base(&mut self, version: u64) -> std::result::Result<BaseDocument, BaseError> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(|error| BaseError::Store(storage(error)))?;
        let staged = abandon_base_on(&tx, version)?;
        tx.commit().map_err(storage)?;
        Ok(staged)
    }
}

// ----- semantic identity (AC-056, REQ-046) -----

fn identity_kind(raw: &str) -> std::result::Result<IdentityKind, IdentityError> {
    IdentityKind::parse(raw)
        .ok_or_else(|| IdentityError::Store(corrupt_column("identity kind", raw)))
}

fn migration_rule(raw: &str) -> std::result::Result<MigrationRule, IdentityError> {
    MigrationRule::parse(raw)
        .ok_or_else(|| IdentityError::Store(corrupt_column("identity rule", raw)))
}

/// The base ledger's serving version: a store that never installed
/// a base serves the shipped one, so a rule set is always bound to the base this
/// build actually composes.
fn served_base_version_on(conn: &Connection) -> std::result::Result<u64, IdentityError> {
    let serving = base_document_on(conn, UpdateState::Active).map_err(identity_store)?;
    Ok(serving.map_or(SHIPPED_BASE_VERSION, |base| base.version))
}

/// A ledger refusal as the identity owner reports it: the map is bound to the
/// base the ledger records, so a ledger that cannot be read is the pass's own
/// storage refusal.
fn identity_store(error: BaseError) -> IdentityError {
    match error {
        BaseError::Store(source) => IdentityError::Store(source),
        other => IdentityError::Store(StoreError::Storage(Box::new(other))),
    }
}

fn identity_migrations_on(
    conn: &Connection,
    base_version: u64,
) -> std::result::Result<Vec<IdentityMigration>, IdentityError> {
    let mut statement = conn
        .prepare(sql::IDENTITY_MIGRATIONS_FOR_BASE)
        .map_err(|error| IdentityError::Store(storage(error)))?;
    let rows = statement
        .query_map(params![stored_u64(base_version)?], |row| {
            Ok((
                row.get::<_, i64>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, Option<String>>(5)?,
            ))
        })
        .map_err(|error| IdentityError::Store(storage(error)))?;
    let mut migrations = Vec::new();
    for row in rows {
        let (raw_base, old_id, new_id, kind, rule, subject) =
            row.map_err(|error| IdentityError::Store(storage(error)))?;
        migrations.push(IdentityMigration {
            base_version: u64::try_from(raw_base).map_err(|_negative| {
                IdentityError::Store(corrupt_column(
                    "identity base version",
                    &raw_base.to_string(),
                ))
            })?,
            kind: identity_kind(&kind)?,
            old_id,
            new_id,
            rule: migration_rule(&rule)?,
            subject,
        });
    }
    Ok(migrations)
}

/// One stored binding as a rebinding pass reads it: the delta it belongs to,
/// the id it is bound to, the effect it decides and the condition bytes the row
/// held. The bytes are what the move's `WHERE` matches, so a transition is
/// pinned to the payload it read instead of to a re-rendering of it.
struct StoredBinding {
    delta_id: String,
    kind: IdentityKind,
    subject: String,
    /// The state the row held. A pass places every binding whatever its state,
    /// but only an active delta is in the definition, so only an active
    /// conclusion is judged (AC-056).
    state: DeltaState,
    condition: Option<String>,
    /// The fact an applicability conclusion is read under, `None` for an
    /// instruction binding. Two conclusions that can both hold for one request
    /// disagree when the rules leave them on one capability (AC-056).
    applies_when: Option<ConditionFact>,
    /// What an applicability binding decides about its capability, `None` for
    /// an instruction binding.
    decision: Option<PredicateEffect>,
}

/// One conclusion a pass would leave in the definition: the effect it decides,
/// whether the pass moves it, and the fact that must hold for it to be read.
struct Conclusion {
    effect: PredicateEffect,
    moved: bool,
    when: Option<ConditionFact>,
}

/// Whether two conclusions can both be read for one request. Two conclusions
/// naming different request kinds never meet — one selection request carries
/// exactly one kind — while every other pair does: a surface condition holds
/// beside any kind and a surface scan is a set, so two surfaces can both be
/// decided. A pair a request cannot hold at once is not a disagreement.
fn can_both_apply(first: Option<&ConditionFact>, second: Option<&ConditionFact>) -> bool {
    match (first, second) {
        (Some(ConditionFact::Kind(first)), Some(ConditionFact::Kind(second))) => first == second,
        _ => true,
    }
}

/// The binding a stored delta carries. An instruction delta binds the purpose
/// its condition names — a delta with no condition applies everywhere, so it is
/// bound to nothing and moves for nobody — and an applicability delta binds the
/// capability it overrides, which is the action's own identity.
fn stored_binding_on(
    delta_id: String,
    scope: &str,
    capability: Option<String>,
    effect: Option<String>,
    condition_json: Option<String>,
    state: &str,
) -> std::result::Result<Option<StoredBinding>, IdentityError> {
    let scope = DeltaScope::parse(scope)
        .ok_or_else(|| IdentityError::Store(corrupt_column("delta scope", scope)))?;
    let state = delta_state(state).map_err(IdentityError::Store)?;
    let condition = match condition_json.as_deref() {
        None => None,
        Some(raw) => {
            let fact = serde_json::from_str::<ConditionFact>(raw).map_err(|_not_typed| {
                IdentityError::Store(corrupt_column("delta condition", raw))
            })?;
            Some((fact, raw))
        }
    };
    let binding = match (scope, capability, condition) {
        (DeltaScope::Instruction, _, Some((ConditionFact::Purpose(purpose), raw))) => {
            Some(StoredBinding {
                delta_id,
                kind: IdentityKind::Role,
                subject: purpose,
                state,
                condition: Some(raw.to_string()),
                applies_when: None,
                decision: None,
            })
        }
        (DeltaScope::Instruction, _, _) => None,
        (DeltaScope::Applicability, Some(capability), condition) => {
            let decision = effect
                .as_deref()
                .and_then(PredicateEffect::parse)
                .ok_or_else(|| {
                    IdentityError::Store(corrupt_column(
                        "delta effect",
                        effect.as_deref().unwrap_or("absent"),
                    ))
                })?;
            Some(StoredBinding {
                delta_id,
                kind: IdentityKind::Action,
                subject: capability,
                state,
                condition: None,
                applies_when: condition.map(|(fact, _not_bytes)| fact),
                decision: Some(decision),
            })
        }
        (DeltaScope::Applicability, None, _) => {
            return Err(IdentityError::Store(corrupt_column(
                "delta capability",
                "absent",
            )));
        }
    };
    Ok(binding)
}

/// Records one rule under the base version the caller names — the serving base
/// for [`TaskStore::record_identity_migration`], the base a cutover is
/// installing for [`TaskStore::cut_over_base`] — once the whole set it joins
/// validates. A rule this build cannot serve, or one that would route a subject
/// into two parts, never reaches a row.
///
/// # Errors
/// Returns [`IdentityError::UnknownBase`] for a rule of another base, the
/// refusals [`IdentityMigration::validate`] and [`IdentityRules::new`] report,
/// [`IdentityError::Conflicting`] when the same source and target are recorded
/// with another meaning, and [`IdentityError::Store`] when the write fails.
fn record_migration_on(
    tx: &Transaction<'_>,
    migration: &IdentityMigration,
    version: u64,
) -> std::result::Result<IdentityMigration, IdentityError> {
    if migration.base_version != version {
        return Err(IdentityError::UnknownBase {
            offered: migration.base_version,
            recorded: version,
        });
    }
    let mut migrations = identity_migrations_on(tx, version)?;
    migrations.push(migration.clone());
    // The set is the gate: a rule that would route one subject into two
    // parts, or name an id this build cannot serve, never reaches a row.
    IdentityRules::new(version, migrations)?;
    tx.execute(
        sql::INSERT_IDENTITY_MIGRATION,
        params![
            stored_u64(migration.base_version)?,
            migration.old_id,
            migration.new_id,
            migration.kind.as_str(),
            migration.rule.as_str(),
            migration.subject
        ],
    )
    .map_err(storage)?;
    // The row this key holds is what the map answers from now on; a rule
    // that arrived under an already recorded key with another meaning is
    // refused here, and the transaction's rollback leaves the stored set
    // exactly as it was.
    let stored = identity_migrations_on(tx, version)?
        .into_iter()
        .find(|row| {
            row.kind == migration.kind
                && row.old_id == migration.old_id
                && row.new_id == migration.new_id
        })
        .ok_or_else(|| IdentityError::Store(corrupt_column("identity rule", &migration.old_id)))?;
    if stored != *migration {
        return Err(IdentityError::Conflicting {
            old_id: migration.old_id.clone(),
            new_id: migration.new_id.clone(),
            rule: migration.rule,
        });
    }
    Ok(stored)
}

impl TaskStore {
    /// The rule set the base this store serves was released with (AC-056).
    ///
    /// # Errors
    /// Returns the rule set's own refusals — a set that claims the user's
    /// namespace, names an unknown action or routes one subject into two parts
    /// — and [`IdentityError::Store`] when a row cannot be read.
    pub fn identity_rules(&self) -> std::result::Result<IdentityRules, IdentityError> {
        let conn = self.conn()?;
        let base_version = served_base_version_on(conn)?;
        IdentityRules::new(base_version, identity_migrations_on(conn, base_version)?)
    }

    /// Records one identity rule of the base this store serves (AC-056). The
    /// serving base is read from the base ledger, so a mapping released with
    /// another base is refused instead of applied by guess, and the rule set is
    /// validated as a whole before the write, so a refused rule records nothing.
    ///
    /// # Errors
    /// Returns [`IdentityError::UnknownBase`] for a rule of another base, the
    /// refusals [`IdentityMigration::validate`] and [`IdentityRules::new`]
    /// report, [`IdentityError::Conflicting`] when the same source and target
    /// are recorded with another meaning, and [`IdentityError::Store`] when the
    /// write fails.
    pub fn record_identity_migration(
        &mut self,
        migration: &IdentityMigration,
    ) -> std::result::Result<IdentityMigration, IdentityError> {
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        // The serving base and the recorded set are read inside the write
        // transaction (INV-004): a rule validated against a set another writer
        // moved between the read and the row would be the second truth the
        // conditional statements of this store exist to avoid.
        let recorded = served_base_version_on(&tx)?;
        let stored = record_migration_on(&tx, migration, recorded)?;
        tx.commit().map_err(storage)?;
        Ok(stored)
    }
}

/// Rebinds every stored binding the serving base's rules place (AC-056):
/// a rename and a merge move the whole binding, a split moves it only into
/// the part that inherits its subject, and a subject no rule names keeps its
/// id and is reported for reconciliation (EDGE-007) — never mapped to a free
/// id. A pass never writes a row's state, so a withdrawn experience stays
/// withdrawn and an unknown id's content is never activated; every moved
/// row's version advances, so an activation pinned to the payload it judged
/// conflicts instead of activating a body the corpus did not see (EDGE-002).
///
/// The pass owns no transaction: the transition that activates a base runs it
/// inside its own ([`TaskStore::commit_base`]), so the rules a release carries
/// and the rows they place land together or not at all.
///
/// Two refusals guard this pass. The pair a move would land on one
/// capability is judged: two active conclusions that disagree about the
/// same request, at least one of them moved by this pass, are refused before
/// any row moves, because the definition decides a capability by record
/// order and a merge that put a `require` and a `decline` there would
/// silently stop answering one of them
/// ([`IdentityError::ConflictingBindings`]). Only what the definition
/// composes is in the pair, and only what the move lands is judged: two
/// conclusions one request can never hold at once — each names another
/// request kind — answer their own requests, while a pair the pass leaves
/// exactly where it found it keeps serving untouched. A refusal is resolved
/// by withdrawing one of the two and re-running the transition
/// ([`TaskStore::roll_back_learning_delta`]), which leaves one conclusion and
/// commits. The definition the moves then compose is measured inside the
/// same transaction, at the bound every other definition-changing path
/// refuses at, so a merge that lands two deltas on one purpose cannot commit
/// a part past [`DEFINITION_MAX_BYTES`]
/// ([`IdentityError::CompositionExceeded`]).
///
/// # Errors
/// Returns the rule set's own refusals, the two above, and
/// [`IdentityError::Store`] when a read or write fails; a refused pass
/// writes nothing.
fn rebind_learning_identities_on(
    tx: &Transaction<'_>,
) -> std::result::Result<IdentityRebind, IdentityError> {
    let base_version = served_base_version_on(tx)?;
    let rules = IdentityRules::new(base_version, identity_migrations_on(tx, base_version)?)?;
    let bindings = {
        let mut statement = tx.prepare(sql::LEARNING_DELTA_BINDINGS).map_err(storage)?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Option<String>>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                    row.get::<_, String>(5)?,
                ))
            })
            .map_err(storage)?;
        let mut bindings = Vec::new();
        for row in rows {
            let (delta_id, scope, capability, effect, condition, state) = row.map_err(storage)?;
            if let Some(binding) =
                stored_binding_on(delta_id, &scope, capability, effect, condition, &state)?
            {
                bindings.push(binding);
            }
        }
        bindings
    };
    // Placement is decided for every binding before any row moves, so the
    // refusals below read the set the pass would leave behind and the
    // transaction drops with every row exactly as it was.
    let mut placed: Vec<(StoredBinding, Option<String>)> = Vec::with_capacity(bindings.len());
    let mut unassigned: Vec<NamedSubject> = Vec::new();
    for binding in bindings {
        let to = match rules.place(binding.kind, &binding.subject) {
            Placement::Rebound(to) if to != binding.subject => Some(to),
            Placement::Rebound(_) => None,
            Placement::Unassigned => {
                if !unassigned
                    .iter()
                    .any(|named| named.kind == binding.kind && named.subject == binding.subject)
                {
                    unassigned.push(NamedSubject {
                        kind: binding.kind,
                        subject: binding.subject.clone(),
                    });
                }
                None
            }
        };
        placed.push((binding, to));
    }
    // Two independently verified conclusions are not a merge: a capability
    // the definition decides by record order answers only the last of them,
    // so a rule set that would leave one capability holding two disagreeing
    // conclusions that can both hold for one request is refused rather than
    // quietly dropping one. Only what the definition composes is judged: a
    // delta that is not active is not in it, so withdrawing one of the two
    // and re-running the pass resolves the disagreement, and two conclusions
    // one request can never hold at once — each names another request kind —
    // answer their own requests and are not a disagreement. A pass that
    // moves neither of two conclusions writes nothing and refuses nothing,
    // so a store that already held such a pair keeps running; once a rule set
    // moves one of them, the disagreement is named instead of moving with it.
    let mut decided: std::collections::BTreeMap<(IdentityKind, String), Vec<Conclusion>> =
        std::collections::BTreeMap::new();
    for (binding, to) in &placed {
        let Some(decision) = binding.decision else {
            continue;
        };
        if binding.state != DeltaState::Active {
            continue;
        }
        let subject = to.clone().unwrap_or_else(|| binding.subject.clone());
        decided
            .entry((binding.kind, subject))
            .or_default()
            .push(Conclusion {
                effect: decision,
                moved: to.is_some(),
                when: binding.applies_when.clone(),
            });
    }
    for ((kind, subject), conclusions) in decided {
        for (index, first) in conclusions.iter().enumerate() {
            for second in &conclusions[index + 1..] {
                if first.effect != second.effect
                    && (first.moved || second.moved)
                    && can_both_apply(first.when.as_ref(), second.when.as_ref())
                {
                    return Err(IdentityError::ConflictingBindings {
                        kind,
                        subject,
                        first: first.effect.as_str(),
                        second: second.effect.as_str(),
                    });
                }
            }
        }
    }
    let mut rebound = Vec::new();
    for (binding, to) in placed {
        let Some(to) = to else {
            continue;
        };
        let changed = match (binding.kind, &binding.condition) {
            (IdentityKind::Role, Some(stored)) => {
                let moved = serde_json::to_string(&ConditionFact::Purpose(to.clone()))
                    .map_err(|error| storage(std::io::Error::other(error)))?;
                tx.execute(
                    sql::REBIND_DELTA_PURPOSE,
                    params![binding.delta_id, moved, stored],
                )
                .map_err(storage)?
            }
            (IdentityKind::Role, None) => continue,
            (IdentityKind::Action, _) => tx
                .execute(
                    sql::REBIND_DELTA_CAPABILITY,
                    params![binding.delta_id, to, binding.subject],
                )
                .map_err(storage)?,
        };
        if changed == 0 {
            // The row the pass read is the row it moves: a binding that
            // matched nothing is reported instead of claimed as moved.
            return Err(IdentityError::Store(StoreError::Storage(Box::new(
                std::io::Error::other(format!(
                    "stored binding {} moved between its read and its rebinding",
                    binding.delta_id
                )),
            ))));
        }
        rebound.push(ReboundSubject {
            delta_id: binding.delta_id,
            kind: binding.kind,
            from: binding.subject,
            to,
        });
    }
    // The definition these moves compose is measured inside the same
    // transaction, at the bound every other definition-changing path refuses
    // at: a merge lands two deltas on one purpose, and the composed part the
    // assembly sites carry is what the bound protects (AC-051). A pass that
    // moved nothing cannot have grown it, so a store already sitting past
    // the bound stays readable instead of refusing every later pass.
    if !rebound.is_empty() {
        let size = definition_size_on(tx)?;
        if size > DEFINITION_MAX_BYTES {
            return Err(IdentityError::CompositionExceeded {
                base_version,
                size,
                limit: DEFINITION_MAX_BYTES,
            });
        }
    }
    // The transaction that activated the base commits these moves with the
    // activation; the bound was measured above, inside it.
    Ok(IdentityRebind {
        base_version,
        migrations: rules.migrations().to_vec(),
        rebound,
        unassigned,
    })
}

/// Retention (INV-010) for the saved segments: a derived record of an executed
/// plan, so beyond the newest window a segment leaves with its runs.
pub const PROCEDURE_SEGMENT_RETENTION: usize = 32;

/// Retention (INV-010) for the runs: terminal runs are derived records and
/// leave beyond the named window; a run still running is never pruned. Inside
/// the window a terminal run keeps its cursor, its stop and its step rows, so a
/// resume neither re-issues a settled effect nor takes a stop for a fresh start.
/// Beyond it every terminal run leaves, a stopped one included: losing the
/// completed row leaves nothing to refuse, and losing a stopped run drops the
/// cursor its resume continued from. Neither row is remembered outside the
/// window, so with no completed row left to refuse the segment, a plain
/// [`RunStart::Resume`] opens a new run at the first step and issues the effects
/// that already ran again.
pub const PROCEDURE_RUN_RETENTION: usize = 16;

fn procedure_serialization(error: serde_json::Error) -> StoreError {
    storage(std::io::Error::other(error))
}

fn stop_conditions_stored(triggers: &[StopTrigger]) -> String {
    triggers
        .iter()
        .map(|trigger| trigger.as_str())
        .collect::<Vec<_>>()
        .join(",")
}

fn stop_conditions_read(raw: &str) -> Result<Vec<StopTrigger>> {
    raw.split(',')
        .map(|name| StopTrigger::parse(name).ok_or_else(|| corrupt_column("stop condition", name)))
        .collect()
}

fn run_state(raw: &str) -> Result<RunState> {
    RunState::parse(raw).ok_or_else(|| corrupt_column("run state", raw))
}

fn segment_missing(procedure_id: &str) -> ProcedureError {
    ProcedureError::SegmentMissing {
        procedure_id: procedure_id.to_string(),
    }
}

fn run_missing(run_id: &str) -> ProcedureError {
    ProcedureError::RunMissing {
        run_id: run_id.to_string(),
    }
}

fn procedure_steps_read(raw: &str) -> Result<Vec<SegmentStep>> {
    serde_json::from_str(raw).map_err(|_not_typed| corrupt_column("segment steps", raw))
}

/// The stop a stored run carries, when its `stop_condition` column is set.
fn stop_read(condition: &str, detail: &str) -> Result<StopDecision> {
    let trigger =
        StopTrigger::parse(condition).ok_or_else(|| corrupt_column("stop condition", condition))?;
    Ok(StopDecision {
        trigger,
        detail: detail.to_string(),
    })
}

/// One stored run row, decoded into the typed run: the snapshot it started
/// from, the cursor it reached and the stop that ended its remainder.
struct StoredRun {
    run_id: String,
    procedure_id: String,
    procedure_version: i64,
    task_id: String,
    snapshot_json: String,
    cursor: i64,
    state: String,
    stop_condition: Option<String>,
    stop_detail: Option<String>,
}

impl StoredRun {
    fn decode(self) -> Result<ProcedureRun> {
        let snapshot: SegmentSnapshot = serde_json::from_str(&self.snapshot_json)
            .map_err(|_not_typed| corrupt_column("run snapshot", &self.snapshot_json))?;
        let stop = match (self.stop_condition, self.stop_detail) {
            (None, _) => None,
            (Some(condition), Some(detail)) => Some(stop_read(&condition, &detail)?),
            (Some(condition), None) => return Err(corrupt_column("stop conditions", &condition)),
        };
        Ok(ProcedureRun {
            run_id: self.run_id,
            procedure_id: self.procedure_id,
            procedure_version: u64::try_from(self.procedure_version).map_err(|_negative| {
                corrupt_column("procedure version", &self.procedure_version.to_string())
            })?,
            task_id: self.task_id,
            snapshot,
            cursor: u64::try_from(self.cursor)
                .map_err(|_negative| corrupt_column("run cursor", &self.cursor.to_string()))?,
            state: run_state(&self.state)?,
            stop,
        })
    }
}

impl TaskStore {
    /// Derives the task's segment from the plan that already ran and saves it
    /// (AC-053): the current selection, the plan revision recorded under it and
    /// the rows its handlers closed. Re-deriving the same plan revision returns
    /// the saved segment, so a run that is already following it keeps its steps.
    ///
    /// # Errors
    /// Returns [`ProcedureError::PlanMissing`] when the task has no plan
    /// revision, [`ProcedureError::PlanSuperseded`] when it belongs to an
    /// earlier selection, [`ProcedureError::NoExecutedSteps`] when no row
    /// closed, and [`ProcedureError::Store`] when a read or write fails.
    pub fn record_procedure_segment(
        &mut self,
        task_id: &TaskId,
    ) -> std::result::Result<SegmentTemplate, ProcedureError> {
        let selection =
            self.plan_selection(task_id)?
                .ok_or_else(|| ProcedureError::PlanMissing {
                    task_id: task_id.0.clone(),
                })?;
        let plan =
            self.plan_revisions(task_id)?
                .pop()
                .ok_or_else(|| ProcedureError::PlanMissing {
                    task_id: task_id.0.clone(),
                })?;
        let rows = self.plan_obligations(task_id)?;
        let template = SegmentTemplate::derive(
            task_id,
            selection.revision,
            &plan,
            &rows,
            crate::executor::backend(),
        )?;
        let steps = serde_json::to_string(&template.steps).map_err(procedure_serialization)?;
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        tx.execute(
            sql::INSERT_PROCEDURE_SEGMENT,
            params![
                template.procedure_id,
                stored_u64(template.version)?,
                template.task_id,
                stored_u64(template.selection_revision)?,
                stored_u64(template.plan_revision)?,
                stored_u64(template.schema_version)?,
                template.tool_version,
                stop_conditions_stored(&template.stop_conditions),
                steps
            ],
        )
        .map_err(storage)?;
        tx.execute_batch(&sql::prune_procedure_segments(PROCEDURE_SEGMENT_RETENTION))
            .map_err(storage)?;
        tx.commit().map_err(storage)?;
        self.procedure_segment(&template.procedure_id)
    }

    /// One saved segment with the steps it will run.
    ///
    /// # Errors
    /// Returns [`ProcedureError::SegmentMissing`] when no such segment is
    /// recorded, and a store refusal when a column cannot be decoded.
    pub fn procedure_segment(
        &self,
        procedure_id: &str,
    ) -> std::result::Result<SegmentTemplate, ProcedureError> {
        let row = self
            .conn()?
            .query_row(sql::PROCEDURE_SEGMENT_ROW, params![procedure_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, String>(6)?,
                    row.get::<_, String>(7)?,
                ))
            })
            .optional()
            .map_err(storage)?;
        let Some((
            version,
            task_id,
            selection_revision,
            plan_revision,
            schema_version,
            tool_version,
            stop_conditions,
            steps,
        )) = row
        else {
            return Err(segment_missing(procedure_id));
        };
        Ok(SegmentTemplate {
            procedure_id: procedure_id.to_string(),
            version: u64::try_from(version)
                .map_err(|_negative| corrupt_column("procedure version", &version.to_string()))?,
            task_id,
            selection_revision: u64::try_from(selection_revision).map_err(|_negative| {
                corrupt_column("selection revision", &selection_revision.to_string())
            })?,
            plan_revision: u64::try_from(plan_revision)
                .map_err(|_negative| corrupt_column("plan revision", &plan_revision.to_string()))?,
            schema_version: u64::try_from(schema_version).map_err(|_negative| {
                corrupt_column("segment schema", &schema_version.to_string())
            })?,
            tool_version,
            stop_conditions: stop_conditions_read(&stop_conditions)?,
            steps: procedure_steps_read(&steps)?,
        })
    }

    /// Starts the segment's run under `snapshot`, or resumes the newest run of
    /// this procedure version that has not completed. The template is validated
    /// against the snapshot first, so a moved plan, schema or tool refuses
    /// before the run's first effect (master §12.9). A resume continues from the
    /// cursor it reached, so a settled effect is never re-issued (PROH-003).
    ///
    /// [`RunStart::Resume`] refuses a segment that already completed a run
    /// ([`ProcedureError::AlreadyCompleted`]): every step of a completed run is
    /// an effect that already landed, so starting it again is an explicit
    /// [`RunStart::Fresh`] request rather than what a resume falls through to.
    /// Retention bounds the refusal — see `PROCEDURE_RUN_RETENTION`: beyond the
    /// window the completed row is evicted and nothing remembers the segment
    /// finished.
    ///
    /// # Errors
    /// The [`SegmentTemplate::prepare`] refusals, [`ProcedureError::AlreadyCompleted`]
    /// for a completed segment asked to resume, and [`ProcedureError::Store`]
    /// when a read or write fails.
    pub fn start_procedure_run(
        &mut self,
        segment: &SegmentTemplate,
        snapshot: &SegmentSnapshot,
        open: RunStart,
    ) -> std::result::Result<ProcedureRun, ProcedureError> {
        segment.prepare(snapshot)?;
        if let Some(run) = self.resumable_procedure_run(&segment.procedure_id, segment.version)? {
            return self.reopen_procedure_run(run);
        }
        if open == RunStart::Resume
            && let Some(run_id) =
                self.completed_procedure_run(&segment.procedure_id, segment.version)?
        {
            return Err(ProcedureError::AlreadyCompleted {
                procedure_id: segment.procedure_id.clone(),
                run_id,
            });
        }
        let run_id = uuid::Uuid::new_v4().to_string();
        let snapshot_json = serde_json::to_string(snapshot).map_err(procedure_serialization)?;
        let step_count = u64::try_from(segment.steps.len())
            .map_err(|_overflow| corrupt_column("segment steps", &segment.procedure_id))?;
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        tx.execute(
            sql::INSERT_PROCEDURE_RUN,
            params![
                run_id,
                segment.procedure_id,
                stored_u64(segment.version)?,
                segment.task_id,
                snapshot_json,
                stored_u64(step_count)?
            ],
        )
        .map_err(storage)?;
        tx.execute_batch(&sql::prune_procedure_runs(PROCEDURE_RUN_RETENTION))
            .map_err(storage)?;
        tx.commit().map_err(storage)?;
        self.procedure_run(&run_id)
    }

    /// Prepares the run's next step before its effect, bound to the attempt
    /// that will perform it: the row is written ahead of the effect, so an
    /// interrupted step is readable as one whose own attempt says whether the
    /// effect could have landed (PROH-003). A row already prepared for this
    /// position keeps the first attempt's binding, so a repeated prepare cannot
    /// move the step onto an attempt that never owned it.
    ///
    /// # Errors
    /// Returns [`ProcedureError::StepOutOfOrder`] when the run is not running or
    /// the position is not the next one, and [`ProcedureError::Store`] when the
    /// write fails.
    pub fn prepare_procedure_step(
        &mut self,
        run: &ProcedureRun,
        position: u64,
        tool: &str,
        attempt_id: &str,
    ) -> std::result::Result<(), ProcedureError> {
        if run.state != RunState::Running || position != run.cursor + 1 {
            return Err(ProcedureError::StepOutOfOrder {
                run_id: run.run_id.clone(),
                position,
                cursor: run.cursor,
            });
        }
        let prepared = self
            .conn_write()?
            .execute(
                sql::PREPARE_PROCEDURE_STEP,
                params![run.run_id, stored_u64(position)?, tool, attempt_id],
            )
            .map_err(storage)?;
        if prepared == 0 {
            return Err(ProcedureError::StepOutOfOrder {
                run_id: run.run_id.clone(),
                position,
                cursor: run.cursor,
            });
        }
        Ok(())
    }

    /// Releases a prepared step whose own attempt provably never reached its
    /// effect: nothing landed, so the row must not hold the step's next attempt.
    /// A step whose attempt ran — or may have — keeps its row: that row is the
    /// run's safety record until the attempt's outcome is resolved, and it is
    /// never resolved by deleting what proves it (PROH-003).
    ///
    /// Returns whether a row was released.
    ///
    /// # Errors
    /// Returns [`ProcedureError::Store`] when the read or write fails.
    pub fn release_unstarted_procedure_step(
        &mut self,
        run_id: &str,
        position: u64,
    ) -> std::result::Result<bool, ProcedureError> {
        let Some(prepared) = self.prepared_procedure_step(run_id)? else {
            return Ok(false);
        };
        // The attempt moves under this same writer, so no other actor can settle
        // it between the standing this reads and the row it deletes.
        if prepared.position != position || prepared.standing != StepStanding::NotStarted {
            return Ok(false);
        }
        let released = self
            .conn_write()?
            .execute(
                sql::RELEASE_PROCEDURE_STEP,
                params![run_id, stored_u64(position)?],
            )
            .map_err(storage)?;
        Ok(released > 0)
    }

    /// The step the run prepared and never settled, with the standing its own
    /// attempt proves: the one record that answers whether the step's effect
    /// could have landed.
    ///
    /// # Errors
    /// Returns [`ProcedureError::Store`] when the read fails, and a store
    /// refusal when a column holds a value this build does not write.
    pub fn prepared_procedure_step(
        &self,
        run_id: &str,
    ) -> std::result::Result<Option<PreparedStep>, ProcedureError> {
        let row = self
            .conn()?
            .query_row(sql::PREPARED_PROCEDURE_STEP, params![run_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<String>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })
            .optional()
            .map_err(storage)?;
        let Some((position, tool, attempt_id, state, result)) = row else {
            return Ok(None);
        };
        let standing = StepStanding::parse(state.as_deref())
            .ok_or_else(|| corrupt_column("attempt state", state.as_deref().unwrap_or_default()))?;
        Ok(Some(PreparedStep {
            position: u64::try_from(position)
                .map_err(|_negative| corrupt_column("step position", &position.to_string()))?,
            tool,
            attempt_id,
            standing,
            result,
        }))
    }

    /// Settles one prepared step and moves the run's cursor in the same
    /// transaction. The cursor is pinned to the value the caller settled, so a
    /// step that would skip ahead — or a second settle of the same position —
    /// matches no row and writes nothing.
    ///
    /// # Errors
    /// Returns [`ProcedureError::StepOutOfOrder`] when the run's cursor moved
    /// past the step or the step was never prepared, and
    /// [`ProcedureError::Store`] when a read or write fails.
    pub fn settle_procedure_step(
        &mut self,
        run_id: &str,
        step: &SettledStep,
    ) -> std::result::Result<ProcedureRun, ProcedureError> {
        let run = self.procedure_run(run_id)?;
        let tx = self
            .conn_mut()?
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(storage)?;
        let settled = tx
            .execute(
                sql::SETTLE_PROCEDURE_STEP,
                params![
                    run_id,
                    stored_u64(step.position)?,
                    step.attempt_id,
                    step.result
                ],
            )
            .map_err(storage)?;
        let advanced = tx
            .execute(
                sql::ADVANCE_PROCEDURE_CURSOR,
                params![run_id, stored_u64(run.cursor)?, stored_u64(step.position)?],
            )
            .map_err(storage)?;
        if settled == 0 || advanced == 0 {
            return Err(ProcedureError::StepOutOfOrder {
                run_id: run_id.to_string(),
                position: step.position,
                cursor: run.cursor,
            });
        }
        tx.commit().map_err(storage)?;
        self.procedure_run(run_id)
    }

    /// Completes a run whose cursor reached its last step.
    ///
    /// # Errors
    /// Returns [`ProcedureError::RunNotOpen`] when the run is not running or a
    /// step is still ahead of the cursor, and [`ProcedureError::Store`] when the
    /// write fails.
    pub fn complete_procedure_run(
        &mut self,
        run_id: &str,
    ) -> std::result::Result<ProcedureRun, ProcedureError> {
        let completed = self
            .conn_write()?
            .execute(sql::COMPLETE_PROCEDURE_RUN, params![run_id])
            .map_err(storage)?;
        if completed == 0 {
            let run = self.procedure_run(run_id)?;
            return Err(ProcedureError::RunNotOpen {
                run_id: run_id.to_string(),
                state: run.state.as_str().to_string(),
            });
        }
        self.procedure_run(run_id)
    }

    /// Stops the remainder of a run on the decision that stopped it.
    ///
    /// # Errors
    /// Returns [`ProcedureError::RunNotOpen`] when the run already completed,
    /// and [`ProcedureError::Store`] when the write fails.
    pub fn stop_procedure_run(
        &mut self,
        run_id: &str,
        stop: &StopDecision,
    ) -> std::result::Result<ProcedureRun, ProcedureError> {
        let stopped = self
            .conn_write()?
            .execute(
                sql::STOP_PROCEDURE_RUN,
                params![run_id, stop.trigger.as_str(), stop.detail],
            )
            .map_err(storage)?;
        if stopped == 0 {
            let run = self.procedure_run(run_id)?;
            return Err(ProcedureError::RunNotOpen {
                run_id: run_id.to_string(),
                state: run.state.as_str().to_string(),
            });
        }
        self.procedure_run(run_id)
    }

    /// One run with its snapshot, cursor and stop.
    ///
    /// # Errors
    /// Returns [`ProcedureError::RunMissing`] when no such run is recorded, and
    /// a store refusal when a column cannot be decoded.
    pub fn procedure_run(&self, run_id: &str) -> std::result::Result<ProcedureRun, ProcedureError> {
        let row = self
            .conn()?
            .query_row(sql::PROCEDURE_RUN_ROW, params![run_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, i64>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                    row.get::<_, i64>(4)?,
                    row.get::<_, String>(5)?,
                    row.get::<_, Option<String>>(6)?,
                    row.get::<_, Option<String>>(7)?,
                ))
            })
            .optional()
            .map_err(storage)?;
        let Some((
            procedure_id,
            procedure_version,
            task_id,
            snapshot_json,
            cursor,
            state,
            stop_condition,
            stop_detail,
        )) = row
        else {
            return Err(run_missing(run_id));
        };
        Ok(StoredRun {
            run_id: run_id.to_string(),
            procedure_id,
            procedure_version,
            task_id,
            snapshot_json,
            cursor,
            state,
            stop_condition,
            stop_detail,
        }
        .decode()?)
    }

    /// The steps a run settled, in position order: the executed-step count and
    /// every completed result stay readable after a stop (AC-053).
    ///
    /// # Errors
    /// Returns a store refusal when a column cannot be decoded.
    pub fn procedure_run_steps(
        &self,
        run_id: &str,
    ) -> std::result::Result<Vec<SettledStep>, ProcedureError> {
        let mut statement = self
            .conn()?
            .prepare(sql::PROCEDURE_RUN_STEPS)
            .map_err(storage)?;
        let rows = statement
            .query_map(params![run_id], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, String>(3)?,
                ))
            })
            .map_err(storage)?;
        let mut steps = Vec::new();
        for row in rows {
            let (position, tool, attempt_id, result) = row.map_err(storage)?;
            steps.push(SettledStep {
                position: u64::try_from(position)
                    .map_err(|_negative| corrupt_column("step position", &position.to_string()))?,
                tool,
                attempt_id,
                result,
            });
        }
        Ok(steps)
    }

    /// Re-opens a stopped run so the resumed attempt is running while it runs.
    fn reopen_procedure_run(
        &mut self,
        run: ProcedureRun,
    ) -> std::result::Result<ProcedureRun, ProcedureError> {
        if run.state != RunState::Stopped {
            return Ok(run);
        }
        self.conn_write()?
            .execute(sql::RESUME_PROCEDURE_RUN, params![run.run_id])
            .map_err(storage)?;
        self.procedure_run(&run.run_id)
    }

    /// The newest run of this procedure version that already completed, when
    /// the segment has one: the record a resumed start refuses to replay.
    fn completed_procedure_run(
        &self,
        procedure_id: &str,
        procedure_version: u64,
    ) -> std::result::Result<Option<String>, ProcedureError> {
        let run_id = self
            .conn()?
            .query_row(
                sql::COMPLETED_PROCEDURE_RUN,
                params![procedure_id, stored_u64(procedure_version)?],
                |row| row.get(0),
            )
            .optional()
            .map_err(storage)?;
        Ok(run_id)
    }

    /// The newest run of this procedure version that has not completed: the run
    /// a start resumes instead of re-running steps that already settled.
    fn resumable_procedure_run(
        &self,
        procedure_id: &str,
        procedure_version: u64,
    ) -> std::result::Result<Option<ProcedureRun>, ProcedureError> {
        let row = self
            .conn()?
            .query_row(
                sql::RESUMABLE_PROCEDURE_RUN,
                params![procedure_id, stored_u64(procedure_version)?],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, i64>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, Option<String>>(5)?,
                        row.get::<_, Option<String>>(6)?,
                    ))
                },
            )
            .optional()
            .map_err(storage)?;
        let Some((run_id, task_id, snapshot_json, cursor, state, stop_condition, stop_detail)) =
            row
        else {
            return Ok(None);
        };
        let version = i64::try_from(procedure_version)
            .map_err(|_overflow| corrupt_column("procedure version", procedure_id))?;
        Ok(StoredRun {
            run_id,
            procedure_id: procedure_id.to_string(),
            procedure_version: version,
            task_id,
            snapshot_json,
            cursor,
            state,
            stop_condition,
            stop_detail,
        }
        .decode()?
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{BaseSource, UPDATE_ASSETS, UpdatePhase};
    use crate::state::Connection;

    type ProofResult = Result<(), Box<dyn std::error::Error>>;
    type ProofResult2 = Result<Vec<String>, Box<dyn std::error::Error>>;

    fn base_document(extra: &str) -> String {
        format!(
            "config_version = 1\n\
             [workflow]\n\
             enabled = true\n\
             [decisions]\n\
             mode = \"ask\"\n\
             [context]\n\
             auto_compact = false\n\
             [models.defaults]\n\
             model = {{ mode = \"auto\" }}\n\
             effort = {{ mode = \"auto\" }}\n\
             fallback = {{ mode = \"auto\" }}\n\
             {extra}"
        )
    }

    fn install(root: &std::path::Path, version: u64, text: &str) -> BaseInstall {
        BaseInstall::new(
            BaseSource::new(version, text),
            root.join("config.toml"),
            root,
        )
    }

    /// AC-055: the additive schema expansion preserves every existing column, row
    /// and index, adds only the missing nullable columns, and is idempotent across a
    /// reopen. The legacy shapes read back as legacy, and the invalid ones are
    /// refused instead of being projected.
    #[test]
    fn receipt_metadata_round_trips() -> ProofResult {
        let root = tempfile::TempDir::with_prefix("rivect-base-metadata-")?;
        let db = root.path().join("state.db");

        // A store shaped like one an earlier build wrote: the ledger and the
        // receipt rows exist, the five metadata columns do not. The fixture is the
        // only place a schema is written by hand; the product path always comes
        // through `TaskStore`.
        drop(TaskStore::open(&db)?);
        {
            let conn = Connection::open(&db)?;
            conn.execute_batch(
                "DROP TABLE base_state;
                 CREATE TABLE base_state (
                     base_version INTEGER PRIMARY KEY,
                     digest TEXT NOT NULL,
                     state TEXT NOT NULL
                 ) STRICT;
                 CREATE UNIQUE INDEX idx_base_state_active
                     ON base_state (state) WHERE state = 'active';
                 INSERT INTO base_state (base_version, digest, state)
                     VALUES (1, 'legacy-bytes', 'active');
                 INSERT INTO update_receipts (base_version, asset, location, policy)
                     VALUES (1, 'sqlite_rows', '/legacy/state.db', 'preserve');",
            )?;
        }
        let legacy_columns = |conn: &Connection| -> ProofResult2 {
            let mut statement = conn.prepare("PRAGMA table_info(base_state)")?;
            let columns = statement
                .query_map([], |row| row.get::<_, String>(1))?
                .collect::<std::result::Result<Vec<_>, rusqlite::Error>>()?;
            Ok(columns)
        };
        let before = {
            let conn = Connection::open(&db)?;
            legacy_columns(&conn)?
        };
        assert_eq!(before, ["base_version", "digest", "state"]);

        // The first open expands the ledger in one transaction and leaves the
        // legacy row exactly as it was: it keeps no metadata, so it is the one
        // shape that reads as legacy.
        let store = TaskStore::open(&db)?;
        let legacy = store.update_status()?;
        assert_eq!(legacy.base_version, Some(1));
        let legacy_receipt = legacy.receipt.ok_or("the legacy row keeps its place")?;
        assert_eq!(legacy_receipt.phase, None);
        assert_eq!(legacy_receipt.blockers, None);
        assert_eq!(legacy_receipt.schema_generation, None);
        assert_eq!(legacy_receipt.policy_generation, None);
        assert_eq!(legacy_receipt.state, UpdateState::Active);
        assert_eq!(
            legacy.phase, None,
            "a legacy row is not an activated attempt"
        );
        // A store this build writes: the staged row carries the count and an epoch
        // and no activation metadata; the activated row adds the phase and both
        // generations, and its blocker page is the empty set of that base.
        let fresh = tempfile::TempDir::with_prefix("rivect-base-fresh-")?;
        let mut store = TaskStore::open(&fresh.path().join("state.db"))?;
        let first = install(fresh.path(), 1, &base_document(""));
        let staged = store.stage_base(&first)?;
        assert_eq!(staged.state, UpdateState::Staged);
        assert_eq!(staged.phase, None, "a staged base is not activated");
        assert_eq!(staged.schema_generation, None);
        assert_eq!(staged.policy_generation, None);
        let blockers = staged.blockers.ok_or("a staged base carries its set")?;
        assert!(blockers.items.is_empty(), "an empty set is still a set");
        assert_eq!(blockers.snapshot_generation, 1);
        assert_eq!(
            staged.assets.len(),
            UPDATE_ASSETS.len(),
            "the staged checkpoint classifies every asset"
        );
        let activated = store.commit_base(1)?;
        assert_eq!(activated.state, UpdateState::Active);
        assert_eq!(activated.phase, Some(UpdatePhase::Activated));
        assert_eq!(
            activated.schema_generation,
            Some(KNOWN_SCHEMA_GENERATION),
            "the activated row names the ledger it was published under"
        );
        assert_eq!(
            activated.policy_generation.as_deref(),
            Some(first.policy_generation.as_str()),
            "the activated row names the policy the cutover pinned"
        );

        // A reopen reads the same values back from storage, never from memory.
        drop(store);
        let store = TaskStore::open(&fresh.path().join("state.db"))?;
        let reread = store.update_status()?;
        assert_eq!(reread.phase, Some(UpdatePhase::Activated));
        assert_eq!(reread.schema_generation, Some(KNOWN_SCHEMA_GENERATION));
        assert_eq!(
            reread.policy_generation.as_deref(),
            Some(first.policy_generation.as_str())
        );
        let page = reread.blockers.ok_or("the status serves the set")?;
        assert!(page.items.is_empty());
        assert_eq!(page.snapshot_generation, 1);

        // The invalid shapes: a count without rows, a row without its epoch, and a
        // noncanonical address are all refused, never projected.
        let corrupt = tempfile::TempDir::with_prefix("rivect-base-corrupt-")?;
        let corrupt_db = corrupt.path().join("state.db");
        drop(TaskStore::open(&corrupt_db)?);
        let conn = Connection::open(&corrupt_db)?;
        conn.execute_batch(
            "INSERT INTO base_state
                 (base_version, digest, state, phase, blocker_count, schema_generation,
                  policy_generation, set_epoch)
                 VALUES (1, 'bytes', 'staged', NULL, 2, NULL, NULL, 1);",
        )?;
        drop(conn);
        let store = TaskStore::open(&corrupt_db)?;
        let refusal = store
            .update_status()
            .expect_err("a count without rows is corrupt");
        assert!(
            matches!(refusal, BaseError::Store(StoreError::Storage(_))),
            "{refusal}"
        );
        drop(store);
        Ok(())
    }
}
