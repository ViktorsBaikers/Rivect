//! Single public ingress producer (architecture: `dispatch_runtime_request`
//! is the one dispatcher; `src/api.rs` later only wraps transport). Strict
//! JSON-RPC framing, per-method typed params, fail-closed machine ingress.

use crate::config::{self, EffectiveConfig};
use crate::context::{ContextError, IsolatedCause};
use crate::contracts::{
    AnswerSelection, CommandId, CommandResult, EffectClass, ErrorCode, Lifecycle, LocalCommand,
    LocalCommandResult, OptionId, PAGE_DEFAULT, PAGE_MAX, Page, ProjectInitResult, QuestionId,
    QuestionResult, RetryClass, RpcErrorBody, RpcResponse, SCHEMA_VERSION, SessionId, TaskId,
    WireError,
};
use crate::index::{
    CarryPolicy, Completeness, GenerationState, IndexWatcher, PartialReason, ProjectGraph,
    SnapshotId, StaleCause,
};
use crate::learning::{LearningDefinition, LearningStatus};
use crate::lsp::MAX_INDEX_PARSE_TIME;
use crate::model::{Broker, PendingFallback, RequestManifest};
use crate::owner::{Owner, OwnerError};
use crate::policy::Policy;
use crate::providers::Provider;
use crate::resources::NotificationQueue;
use crate::scheduler::{DEFAULT_MAX_SLOTS, DEFAULT_RESOURCE_CAP, Scheduler};
use crate::state::{ConflictCause, StoreError, TaskStore, denial_class};
use crate::supervisor::{Supervisor, SupervisorPolicy};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::TrySendError;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ingress {
    /// Trusted explicit CLI/TUI input adapter: server-owned human origin.
    TrustedHuman,
    /// Plain SDK/machine JSON: never proves human consent.
    Machine,
}

/// The runtime's closed binding: the owner and the policy are read through
/// accessors and never rebound from outside the crate.
///
/// ```compile_fail
/// use rivect::{commands::Runtime, owner::Owner};
/// fn f(rt: &mut Runtime, owner: Owner) { rt.owner = owner; }
/// ```
///
/// ```
/// use rivect::{commands::Runtime, owner::Owner};
/// fn f(rt: &mut Runtime, owner: Owner) { let _bound: &Owner = rt.owner(); drop(owner); }
/// ```
///
/// ```compile_fail
/// use rivect::{commands::Runtime, owner::Owner};
/// fn f(rt: &mut Runtime, mut owner: Owner) { std::mem::swap(&mut rt.owner, &mut owner); }
/// ```
///
/// ```
/// use rivect::{commands::Runtime, owner::Owner};
/// fn f(rt: &mut Runtime, mut owner: Owner) { let _bound: &Owner = rt.owner(); let _ = &mut owner; }
/// ```
///
/// ```compile_fail
/// use rivect::{commands::Runtime, policy::Policy};
/// fn f(rt: &mut Runtime, policy: Policy) { rt.policy = policy; }
/// ```
///
/// ```
/// use rivect::{commands::Runtime, policy::Policy};
/// fn f(rt: &mut Runtime, policy: Policy) { let _bound: &Policy = rt.policy(); drop(policy); }
/// ```
pub struct Runtime {
    pub(crate) owner: Owner,
    pub(crate) policy: Policy,
    pub broker: Broker,
    /// The one bounded task-tree scheduler (INV-020): slot release on
    /// parent wait, strict-FIFO admission, terminal cancellation.
    pub scheduler: Scheduler,
    /// The sterile-retry supervisor (INV-027): reads the scheduler's
    /// own outcome stream and journals one bounded reaction per
    /// detector firing; never dispatches.
    pub supervisor: Supervisor,
    pub notifications: NotificationQueue,
    /// The applied effective config snapshot. Private: only the owner's
    /// config ingress (boot, [`Runtime::reload_config`], the journaled
    /// config commands) moves it, and every move refreshes the owner
    /// state below. Read it through [`Runtime::effective`].
    effective: EffectiveConfig,
    /// The config owner's live workflow-off view (DEC-048 item 1): the
    /// only source a Custom check handoff can be minted and reconsulted
    /// from. Resolved at open from the runtime's actual effective
    /// snapshot; the admission reconsults this live state at the claim
    /// and before both phases, so a later toggle or edit refuses.
    pub(crate) off_state: Arc<crate::executor::WorkflowOffState>,
    /// Purpose used by the first-task model loop; resolved through the
    /// production config schema, never an allow-default profile.
    pub purpose: String,
    pub scope_root: PathBuf,
    pub scoped_file: PathBuf,
    /// The data root this runtime serves. Operator-controlled retained
    /// artifacts live under it, outside every disposable child tree, so a
    /// cleanup cannot take the evidence with it.
    pub data_root: PathBuf,
    /// Grant id matching the scoped read pair; scheduler nodes freeze it
    /// at answer time and their decision steps re-check it.
    pub scoped_grant: String,
    /// Publication target of the journaled config carrier (AC-095).
    pub config_path: PathBuf,
    pub provider_calls: u64,
    /// The one injected backend seam; defaults to the platform worker
    /// (Linux Landlock/seccomp/netns on Linux, Seatbelt elsewhere).
    pub read_worker: Box<dyn crate::executor::ReadWorker>,
    /// The credential seam an MCP server binding resolves its declared
    /// reference through (INV-011). A surface that owns real material
    /// injects its store; while none is bound a declared reference is
    /// refused instead of resolved from nowhere.
    pub mcp_credentials: Option<Box<dyn crate::providers::CredentialStore>>,
    /// Boot-time publication-recovery verdicts a human must resolve:
    /// collected, sanitized lines with their resolution. Each surface
    /// reports them its own way — headless stderr, TUI transcript — and
    /// receipted rows stay silent.
    pub boot_diagnostics: Vec<String>,
    /// The checkpoint this open's cutover had to abandon (EDGE-006): a
    /// stopped cutover's document that this build cannot resume is
    /// replaced, never a wedge, and the discard is reported instead of
    /// happening silently. `None` when nothing was discarded. Served on
    /// `runtime.status` beside the boot line that names it, because
    /// `doctor` is unbuilt and the base ledger has no command of its own
    /// (DX-I2).
    pub base_recovery: Option<config::BaseDocument>,
    /// Tasks paused on a manual-fallback choice (AC-045): the broker
    /// attempt stays admitted while the served question waits for its
    /// answer — cancellation tombstones the attempt through this map,
    /// and the answered candidate dispatches from its frozen manifest.
    pub paused_attempts: BTreeMap<String, PausedAttempt>,
    /// The one index seam this runtime shares with every action handler:
    /// the pinned project root and the capped worker that parses it
    /// (AC-036c, DEC-031). One root, one worker program, one helper, one
    /// protocol — a request can name neither the project a dispatch
    /// reads nor the program its source is parsed by.
    pub index: IndexSeam,
    /// The project's own filesystem watcher, started by the first
    /// successful `project.init`. Its events are coalesced into one path
    /// set per generation and reported on the loop's own wake channel;
    /// [`Runtime::pump_index`] claims the set and
    /// [`Runtime::reindex_from_watch`] acts on it.
    pub index_watcher: Option<IndexWatcher>,
    /// The off-path owner of the bounded index run (INV-011, D-100). A
    /// tracked spawn, joined in [`Drop`]: never detached.
    pub index_runs: IndexRuns,
    /// The dispatch loop's wake channel. The owner pings it when a run
    /// answers and the watch backend pings it when a batch arrives, so a
    /// loop blocked on input notices both without polling.
    loop_wake: Option<std::sync::mpsc::SyncSender<LoopEvent>>,
    /// The request id whose answer the owner still owes, while a run is
    /// in flight. The loop writes the real response when the owner lands
    /// it, so the id is kept until the answer is rendered with it.
    deferred_index_id: Option<Value>,
    /// Whether *this* dispatch is the one that deferred. A per-dispatch
    /// mark, not the id: a client that reuses a request id while the
    /// first one is still owed must not have its second request reported
    /// as deferred behind the first, or its answer would be dropped.
    deferred_mark: bool,
    /// The generation the in-flight run reserved, sealed when its answer
    /// lands. `None` when no run is in flight.
    index_generation: Option<u64>,
    index_answer_observer: IndexAnswerObserver,
    index_seal_control: IndexSealControl,
    /// The task the in-flight run was started for, so a cancellation it
    /// can observe reaches the child through the owner flag.
    index_run_task: Option<TaskId>,
}

/// The index seam an action handler and the `command.execute`
/// dispatcher read: the pinned project root, and the index worker
/// program and sandbox helper resolved once at Runtime open. The worker
/// paths are never derived from wire or config input, and the routing
/// tests replace the helper to prove no in-process fallback exists.
#[derive(Debug, Clone)]
pub struct IndexSeam {
    pub root: PathBuf,
    pub worker: IndexWorker,
    /// Why the project's own watch is not running, when the backend
    /// refused it. Part of the seam because it is the seam's own
    /// freshness detection: a refused watch means nothing is watching
    /// the tree, and a boundary report that omits that reads as if the
    /// index kept itself current on its own.
    pub watch_refusal: Option<String>,
}

/// The resolved index-worker paths, read at Runtime open.
#[derive(Debug, Clone)]
pub struct IndexWorker {
    pub program: PathBuf,
    pub helper: PathBuf,
}

impl IndexWorker {
    /// The one isolated run a request is bounded by (DEC-028/031): the
    /// worker's own deadline, the caller's, and its cancellation hook.
    pub fn run<'a>(
        &'a self,
        deadline: Option<Instant>,
        cancel: &'a dyn Fn() -> bool,
    ) -> crate::context::IsolatedRun<'a> {
        crate::context::IsolatedRun {
            program: &self.program,
            helper: &self.helper,
            deadline,
            cancel,
            answer_cap: crate::context::WORKER_ANSWER_MAX,
        }
    }
}

// ----- the off-path index owner (INV-011, D-100) -----

/// How many run answers may wait for the dispatch thread. One is the
/// whole policy: at most one run is in flight, so a second answer would
/// mean a run the owner was never asked for.
const INDEX_RUN_CAPACITY: usize = 1;

/// One bounded index run handed to the off-path owner. Everything it
/// needs is owned, so the run crosses the thread boundary without
/// borrowing the runtime: the store stays on the dispatch thread,
/// because there is exactly one writer, and only the child observation
/// — the multi-second part — leaves the input and dispatch path
/// (INV-011).
struct IndexRun {
    request: crate::context::ProjectRequest,
    program: PathBuf,
    helper: PathBuf,
    /// The caller budget narrowed by the clamp, computed on the dispatch
    /// thread (DEC-030 #1) and moved here unchanged.
    deadline: Option<Instant>,
    answer_cap: usize,
}

/// One run answer: what the worker gave back, or the typed branch that
/// ended it without one.
struct IndexRunOutcome {
    outcome: Result<ProjectGraph, ContextError>,
}

/// The off-path owner: one dedicated thread, spawned on first use and
/// joined on shutdown.
///
/// It serves one run at a time, taken by a blocking receive, so it waits
/// for work rather than looking for it — no tick, no cadence, no second
/// plan. It is a tracked spawn, not a detached one: the handle lives
/// here and [`IndexRuns::shutdown`] joins it, so no path leaves a
/// thread running behind a dropped runtime.
pub struct IndexRuns {
    /// The run channel writer, taken and dropped by `shutdown` to close
    /// the owner receive.
    requests: Option<std::sync::mpsc::SyncSender<IndexRun>>,
    /// The answer channel reader, on the dispatch thread. Taken by
    /// `shutdown` *before* the join, so an in-flight send fails instead
    /// of blocking on a bounded channel nobody will read.
    answers: Option<std::sync::mpsc::Receiver<IndexRunOutcome>>,
    /// The owner handle, held so shutdown can join it.
    owner: Option<std::thread::JoinHandle<()>>,
    /// The flag the run stop closure reads. The store is on the
    /// dispatch thread, so this is the only way a cancellation the
    /// dispatch thread observes can reach the child while it runs.
    cancel: Arc<AtomicBool>,
    /// Whether a run is in flight. The contract is one at a time: a
    /// second request is a typed refusal, never a queue.
    busy: bool,
    /// Whether the owner thread ended in a panic. Recorded by
    /// `shutdown` rather than discarded: a panicking owner leaves its
    /// reserved generation exactly where the crash leg says it is —
    /// `stale`/`interrupted`, unsealed — and that verdict is the honest
    /// one, so the only thing to keep is the fact that it happened.
    owner_panicked: bool,
    /// Whether `shutdown` joined a live handle rather than dropping it.
    /// A dropped handle is a detached task, which is the one thing this
    /// owner is not allowed to be — so the fact is recorded and a
    /// surface can read it, instead of the join being an invisible step.
    owner_joined: bool,
    /// Set by the owner's own thread body as it returns, so a caller
    /// that holds this handle can observe that the thread has finished
    /// rather than infer it from an absent join handle. A dropped handle
    /// leaves it unset while the thread is still running — the
    /// difference between a tracked spawn and a detached one, observed
    /// from outside a runtime that is being dropped.
    exited: Arc<AtomicBool>,
    /// The loop wake channel, cloned in when the owner starts.
    wake: Option<std::sync::mpsc::SyncSender<LoopEvent>>,
}

impl std::fmt::Debug for IndexRuns {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IndexRuns")
            .field("spawned", &self.owner.is_some())
            .field("busy", &self.busy)
            .finish_non_exhaustive()
    }
}

impl IndexRuns {
    fn new() -> Self {
        Self {
            requests: None,
            answers: None,
            owner: None,
            cancel: Arc::new(AtomicBool::new(false)),
            exited: Arc::new(AtomicBool::new(false)),
            busy: false,
            wake: None,
            owner_panicked: false,
            owner_joined: false,
        }
    }

    /// The owner thread body: one run at a time, taken by a blocking
    /// receive. It touches nothing but its own arguments — no store, no
    /// runtime, no terminal — so the dispatch thread keeps its single
    /// writer and its input path.
    fn serve(
        requests: std::sync::mpsc::Receiver<IndexRun>,
        answers: std::sync::mpsc::SyncSender<IndexRunOutcome>,
        cancel: Arc<AtomicBool>,
        wake: Option<std::sync::mpsc::SyncSender<LoopEvent>>,
    ) {
        // A closed request channel is the runtime teardown, and a failed
        // answer send is the same: nothing is left to serve.
        while let Ok(run) = requests.recv() {
            let cancelled = || cancel.load(Ordering::Relaxed);
            let isolated = crate::context::IsolatedRun {
                program: &run.program,
                helper: &run.helper,
                deadline: run.deadline,
                cancel: &cancelled,
                answer_cap: run.answer_cap,
            };
            let outcome = crate::context::project_index_isolated(&run.request, &isolated);
            if answers.send(IndexRunOutcome { outcome }).is_err() {
                return;
            }
            // A loop that is blocked on input learns the run is done from
            // this ping, not from a poll. A full channel is the overflow
            // policy — it already holds a wake the loop has not drained
            // — and a disconnected one is the loop's own teardown.
            if let Some(wake) = wake.as_ref()
                && let Err(TrySendError::Disconnected(_)) = wake.try_send(LoopEvent::Index)
            {
                return;
            }
        }
    }

    /// Starts the owner if it is not running, with the loop wake channel
    /// it pings when an answer lands.
    fn ensure_owner(&mut self, wake: Option<&std::sync::mpsc::SyncSender<LoopEvent>>) {
        if self.owner.is_some() {
            if let Some(wake) = wake {
                self.wake = Some(wake.clone());
            }
            return;
        }
        let (request_tx, request_rx) =
            std::sync::mpsc::sync_channel::<IndexRun>(INDEX_RUN_CAPACITY);
        let (answer_tx, answer_rx) =
            std::sync::mpsc::sync_channel::<IndexRunOutcome>(INDEX_RUN_CAPACITY);
        // The spawn is tracked from this line on: the handle lands in
        // `self.owner` and `shutdown` joins it, so this is never a
        // detached task (standards §5, every spawn accounted).
        let cancel = self.cancel.clone();
        let ping = self.wake.clone();
        let exited = Arc::clone(&self.exited);
        self.owner = Some(std::thread::spawn(move || {
            Self::serve(request_rx, answer_tx, cancel, ping);
            exited.store(true, Ordering::SeqCst);
        }));
        self.requests = Some(request_tx);
        self.answers = Some(answer_rx);
        self.wake = wake.cloned();
    }

    /// Hands one run to the owner. `false` when a run is already in
    /// flight: the contract is one in-flight worker per runtime, so a
    /// second request is a typed refusal rather than a queue.
    fn start(&mut self, run: IndexRun) -> bool {
        if self.busy {
            return false;
        }
        let Some(sender) = self.requests.as_ref() else {
            return false;
        };
        match sender.try_send(run) {
            Ok(()) => {
                self.busy = true;
                true
            }
            // The owner is gone, which only happens during teardown; the
            // run is reported as not started rather than half-queued.
            Err(error) => {
                std::hint::black_box(error);
                false
            }
        }
    }

    /// The owner answer, if it has landed. Non-blocking: the caller
    /// turns on its own schedule and this reports only what is ready.
    fn take_answer(&mut self) -> Option<IndexRunOutcome> {
        let answer = self.answers.as_ref()?.try_recv().ok()?;
        self.busy = false;
        Some(answer)
    }

    /// Whether a run is in flight.
    fn busy(&self) -> bool {
        self.busy
    }

    /// Clears the cancellation flag for a run that has not started, so
    /// a shutdown's flag never cancels the next run.
    fn cancel_for_new_run(&self) {
        self.cancel.store(false, Ordering::Relaxed);
    }

    /// Tells the owner a cancellation the dispatch thread observed, and
    /// arms the flag the next run's own pre-flight check reads. The
    /// child stop closure reads the same flag, so a run *in flight* —
    /// not one that has not started — ends cancelled.
    fn cancel(&self) {
        self.cancel.store(true, Ordering::Relaxed);
    }

    /// A handle the owner's own thread sets as it returns. A caller that
    /// drops the runtime cannot read the runtime, so this is how a
    /// shutdown is observed from outside: right after the drop returns,
    /// the flag is set if and only if the handle was joined rather than
    /// dropped.
    pub fn owner_exit_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.exited)
    }

    /// Whether the owner thread has returned.
    pub fn owner_exited(&self) -> bool {
        self.exited.load(Ordering::SeqCst)
    }

    /// Whether the owner thread ended in a panic.
    pub fn owner_panicked(&self) -> bool {
        self.owner_panicked
    }

    /// Whether a live owner was joined rather than its handle dropped. A
    /// surface that must be able to say "nothing outlived this runtime"
    /// reads this instead of inferring it from an absent handle.
    pub fn owner_was_joined(&self) -> bool {
        self.owner_joined
    }

    /// Whether an owner thread is running. `false` after `shutdown`,
    /// which is the observable form of "no detached thread": a handle
    /// that is gone cannot be leaking a thread behind a dropped
    /// runtime.
    pub fn owner_running(&self) -> bool {
        self.owner.is_some()
    }

    /// Joins the owner. The request channel closes first so a waiting
    /// owner returns, the cancel flag is raised so a run in flight ends
    /// rather than outliving the runtime, and the answer channel is
    /// dropped before the join so a bounded send cannot block on a
    /// reader that no longer exists.
    ///
    /// Idempotent: a second call has no handle to join, so a surface
    /// that shuts the owner down and then drops the runtime neither
    /// joins twice nor leaves one behind.
    pub fn shutdown(&mut self) {
        self.cancel();
        drop(self.requests.take());
        drop(self.answers.take());
        if let Some(owner) = self.owner.take() {
            self.owner_panicked = owner.join().is_err();
            self.owner_joined = true;
        }
    }
}

impl Runtime {
    /// Gives the off-path owner the channel a dispatch loop blocks on
    /// (INV-011). The owner pings it when a run answers and the watch
    /// backend pings it when a batch arrives, so the loop waits on one
    /// channel instead of polling either.
    ///
    /// `false` when a channel is already installed: a surface cannot
    /// replace a live wake and orphan the one the owner already holds,
    /// and the refusal keeps the first loop's wake intact.
    pub fn set_loop_wake(&mut self, wake: std::sync::mpsc::SyncSender<LoopEvent>) -> bool {
        if self.loop_wake.is_some() {
            return false;
        }
        self.index_runs.wake = Some(wake.clone());
        self.loop_wake = Some(wake);
        true
    }
}

impl Runtime {
    /// The election owner. Read-only: the binding it carries is never
    /// rebound from outside the crate.
    #[must_use]
    pub fn owner(&self) -> &Owner {
        &self.owner
    }

    /// The grant and deny policy, read-only. Mutation goes through
    /// [`Runtime::policy_writer`].
    #[must_use]
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// The runtime's task store, read-only.
    #[must_use]
    pub fn store(&self) -> &TaskStore {
        self.owner.store()
    }

    /// The one write surface of the runtime's task store.
    pub fn store_writer(&mut self) -> crate::state::StoreWriter<'_> {
        self.owner.store.writer()
    }

    /// Activates one learned delta and installs the definition the store now
    /// composes on this runtime's broker, so the request seam and the selection
    /// seam read one definition inside one process: an activation takes effect
    /// on the next prepare without a restart.
    ///
    /// # Errors
    /// See [`crate::state::TaskStore::activate_learning_delta`].
    pub fn activate_learning_delta(
        &mut self,
        delta_id: &str,
        expected_version: u64,
    ) -> Result<LearningDefinition, StoreError> {
        let definition = self
            .owner
            .store
            .activate_learning_delta(delta_id, expected_version)?;
        self.broker.set_learning_definition(definition.clone());
        Ok(definition)
    }

    /// Withdraws one active learned delta and installs the definition the store
    /// now composes, so a rolled-back body stops riding the very next request
    /// instead of the one after a restart.
    ///
    /// # Errors
    /// See [`crate::state::TaskStore::roll_back_learning_delta`].
    pub fn roll_back_learning_delta(
        &mut self,
        delta_id: &str,
        expected_version: u64,
    ) -> Result<LearningDefinition, StoreError> {
        let definition = self
            .owner
            .store
            .roll_back_learning_delta(delta_id, expected_version)?;
        self.broker.set_learning_definition(definition.clone());
        Ok(definition)
    }

    /// The policy mutators, bound to this runtime's own store.
    pub fn policy_writer(&mut self) -> PolicyWriter<'_> {
        PolicyWriter {
            policy: &mut self.policy,
            store: self.owner.store(),
        }
    }

    /// An executor over this runtime's own policy, store and read worker,
    /// carrying the document's hook declarations so admission consults them at
    /// its one instrumented event.
    pub fn executor(&mut self) -> crate::executor::Executor<'_> {
        let hooks = self.effective.parsed.as_ref().map(|config| &config.hooks);
        crate::executor::Executor::new(
            &mut self.policy,
            &mut self.owner.store,
            self.read_worker.as_mut(),
        )
        .with_hooks(hooks)
    }

    /// An executor over this runtime's policy and store with a caller's
    /// worker: the worker is the public injection seam, never part of
    /// the policy/store binding. The document's hooks still apply.
    pub fn executor_with_worker<'a>(
        &'a mut self,
        worker: &'a mut dyn crate::executor::ReadWorker,
    ) -> crate::executor::Executor<'a> {
        let hooks = self.effective.parsed.as_ref().map(|config| &config.hooks);
        crate::executor::Executor::new(&mut self.policy, &mut self.owner.store, worker)
            .with_hooks(hooks)
    }

    /// An executor that merges identical permitted reads in `flights`.
    pub fn executor_with_flights<'a>(
        &'a mut self,
        flights: &'a mut crate::resources::ReadFlights,
    ) -> crate::executor::Executor<'a> {
        let hooks = self.effective.parsed.as_ref().map(|config| &config.hooks);
        crate::executor::Executor::with_flights(
            &mut self.policy,
            &mut self.owner.store,
            self.read_worker.as_mut(),
            flights,
        )
        .with_hooks(hooks)
    }

    /// The borrowed surfaces an action handler reads, over this runtime's
    /// own store and index seam.
    pub fn action_context<'a>(
        &'a mut self,
        session_id: &'a SessionId,
        config: &'a config::Config,
    ) -> crate::actions::ActionContext<'a> {
        crate::actions::ActionContext::new(&mut self.owner.store, session_id, config, &self.index)
    }
}

/// The policy mutators of one runtime. It splits the runtime's policy and
/// store borrows, so a check admission is only ever issued or released
/// against the store its policy was opened with.
///
/// ```compile_fail
/// use rivect::commands::Runtime;
/// fn f(rt: &mut Runtime) { let pw = rt.policy_writer(); let _policy = pw.policy; }
/// ```
///
/// ```
/// use rivect::commands::Runtime;
/// fn f(rt: &mut Runtime) { let mut pw = rt.policy_writer(); let _id = pw.grant_read(std::path::PathBuf::from("/")); }
/// ```
///
/// ```compile_fail
/// use rivect::commands::Runtime;
/// fn f(rt: &mut Runtime) { let pw = rt.policy_writer(); let _store = pw.store; }
/// ```
///
/// ```
/// use rivect::commands::Runtime;
/// fn f(rt: &mut Runtime) { let pw = rt.policy_writer(); drop(pw); let _store = rt.store(); }
/// ```
pub struct PolicyWriter<'a> {
    policy: &'a mut Policy,
    store: &'a TaskStore,
}

impl std::fmt::Debug for PolicyWriter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyWriter").finish()
    }
}

impl PolicyWriter<'_> {
    /// Grants read access to `scope_root` and returns the grant id.
    pub fn grant_read(&mut self, scope_root: PathBuf) -> String {
        self.policy.grant_read(scope_root)
    }

    /// Grants `classes` on `scope_root` and returns the grant id.
    pub fn grant_classes(&mut self, scope_root: PathBuf, classes: Vec<EffectClass>) -> String {
        self.policy.grant_classes(scope_root, classes)
    }

    /// Revokes one grant; an unknown id changes nothing.
    pub fn revoke(&mut self, grant_id: &str) {
        self.policy.revoke(grant_id);
    }

    /// # Errors
    /// See [`Policy::enroll_deny`].
    pub fn enroll_deny(
        &mut self,
        path: impl AsRef<Path>,
    ) -> Result<(), crate::policy::PolicyError> {
        self.policy.enroll_deny(path)
    }

    /// Enrolls one raw deny target.
    pub fn enroll_deny_target(&mut self, raw: &str) {
        self.policy.enroll_deny_target(raw);
    }

    /// The post-claim consume of the owning dispatch.
    pub fn consume_check_pair(&mut self, admission: &mut crate::executor::CheckAdmission) {
        self.policy.consume_check_pair(admission);
    }

    /// # Errors
    /// See [`Policy::issue_check_dependencies`].
    pub fn issue_check_dependencies(
        &mut self,
        admission: &mut crate::executor::CheckAdmission,
    ) -> Result<(), crate::policy::CheckIssuerError> {
        self.policy.issue_check_dependencies(self.store, admission)
    }

    /// Disposes the issuing pair's allocation for `admission`.
    pub fn release_check_dependencies(&mut self, admission: &mut crate::executor::CheckAdmission) {
        self.policy
            .release_check_dependencies(self.store, admission);
    }
}

/// The owner is tracked, so nothing is ever left running behind a
/// dropped runtime. The request channel closes and the cancellation flag
/// is raised before the join, so a run in flight ends cancelled rather
/// than outliving the `Runtime` that started it — the child dies with
/// its process group and the handle is joined, which is the
/// `JoinSet`/`TaskTracker` discipline the standards require. A panic
/// unwinding through here takes the same path.
impl Drop for Runtime {
    fn drop(&mut self) {
        self.index_runs.shutdown();
    }
}

/// The `rivect` executable re-run as the index worker, resolved once at
/// Runtime open. Never derived from wire or config input: a request
/// cannot name the program its own content is parsed by.
fn worker_program() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("rivect"))
}

impl std::fmt::Debug for Runtime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Credential material lives only behind the store boundary;
        // the runtime's diagnostic surface names its scope and
        // counters, never the effective config's bindings or the
        // injected worker seam.
        f.debug_struct("Runtime")
            .field("purpose", &self.purpose)
            .field("scope_root", &self.scope_root)
            .field("provider_calls", &self.provider_calls)
            .field("config_path", &self.config_path)
            .finish_non_exhaustive()
    }
}

/// The broker-side pause state of one task waiting on a manual
/// fallback answer: the frozen manifest whose dispatch paused, plus
/// the pending choice already consumed for publication — kept so a
/// later answer can name only a served candidate and a cancel can
/// still tombstone the attempt.
#[derive(Debug)]
pub struct PausedAttempt {
    pub manifest: RequestManifest,
    pub choice: Option<PendingFallback>,
    /// The question the choice was served through: only an applied
    /// answer to that very question may dispatch the frozen manifest —
    /// an option id colliding with a candidate on a different fork must
    /// miss. `None` for an error-residue pause that never published a
    /// choice; it can only be tombstoned, never answered into a send.
    pub served_question_id: Option<QuestionId>,
}

impl Runtime {
    pub fn open(data_root: &Path, provider: Box<dyn Provider>) -> Result<Self, OpenError> {
        #[cfg(target_os = "linux")]
        let worker: Box<dyn crate::executor::ReadWorker> =
            Box::new(crate::executor::linux::LinuxWorker);
        #[cfg(not(target_os = "linux"))]
        let worker: Box<dyn crate::executor::ReadWorker> =
            Box::new(crate::executor::macos::MacosReadWorker);
        Self::open_with_worker(data_root, provider, worker)
    }

    pub fn open_with_worker(
        data_root: &Path,
        provider: Box<dyn Provider>,
        read_worker: Box<dyn crate::executor::ReadWorker>,
    ) -> Result<Self, OpenError> {
        // The owner lives inside `open_inner`, so on failure it is already
        // dropped here and its lock release failures are drained once, after
        // the verdicts, on the thread that dropped it.
        Self::open_inner(data_root, provider, read_worker).map_err(|mut failure| {
            failure
                .diagnostics
                .extend(crate::state::take_release_lines());
            // A failed open hands no runtime to any surface, so the
            // collected verdicts still reach stderr before the error does —
            // and ride the error itself, so a caller whose stderr is a dead
            // channel can still hand them to a live one.
            report_boot_diagnostics(&failure.diagnostics);
            failure
        })
    }

    /// The two boot recovery passes, in the one order the contract names: the
    /// publication receipt first, then the check-attempt reconcile. Both write
    /// current-generation rows, so the startup runs them either on a store that
    /// already holds every table they touch (before the generation transaction) or
    /// right after the commit and before the runtime is exposed.
    ///
    /// # Errors
    /// Returns the same typed failures the recovery owners report: a failed
    /// settlement retention fails the open, and a root cleanup failure only
    /// appends a diagnostic.
    fn run_startup_recovery(owner: &mut Owner) -> Result<Vec<String>, OpenError> {
        // A crash between the managed write and its receipt leaves one pending
        // row; receipt exactly the writes attributable to this publisher before
        // any config surface serves (AC-093). Every verdict a human must resolve
        // is collected into the boot diagnostics — each surface reports the lines
        // its own way — while the receipted rows stay silent.
        let diagnostics: Vec<String> = config::recover_publications(&mut owner.store)
            .map_err(OwnerError::from)?
            .iter()
            .filter_map(recovery_diagnostic)
            .collect();
        // DEC-047 check-attempt reconcile before any surface serves: settlement
        // writes `close.unrecovered` for unrecorded interruptions and
        // cleanup-resume removes roots that survived their durable row. A
        // settlement retention failure is a storage fault and fails the open; a
        // root cleanup failure only appends a diagnostic and preserves every
        // approved row.
        let mut diagnostics = diagnostics;
        match reconcile_unrecovered_checks(&mut owner.store) {
            Ok(lines) => diagnostics.extend(lines),
            Err(error) => return Err(OpenError::new(error, diagnostics)),
        }
        Ok(diagnostics)
    }

    /// The one generation this open publishes, through the update owner when a
    /// cutover waits (AC-055): the reference snapshot, the durable attempt
    /// reserve, the validation milestone, the one `IMMEDIATE` generation
    /// transaction, then the terminal record and the snapshot cleanup after the
    /// outcome is proved and the tuple read back.
    ///
    /// An ordinary open — no staged base — publishes exactly the transaction it
    /// always did: no snapshot, no report directory and no record.
    ///
    /// # Errors
    /// The same base-ledger refusals the generation transaction reports, and the
    /// update owner's own refusal, which carries the retained record pointer in
    /// the boot diagnostics so an operator can read the cause it left behind.
    fn publish_startup(
        owner: &mut Owner,
        data_root: &Path,
        install: &config::BaseInstall,
        boot_diagnostics: &[String],
    ) -> Result<Option<config::BaseDocument>, OpenError> {
        let pending = owner
            .store
            .cutover_pending()
            .map_err(|error| open_failure(error.into(), boot_diagnostics))?;
        if !pending {
            return owner
                .store
                .publish_generation(install)
                .map_err(|error| open_failure(base_open_failure(error), boot_diagnostics));
        }
        let evidence = crate::update::EvidenceStore::open(data_root).map_err(|error| {
            // The directory itself refused: no record exists to point at, so the
            // line names the directory.
            update_open_failure(
                error,
                crate::update::EvidencePointer::Directory,
                boot_diagnostics,
            )
        })?;
        // The reserve is durable before the first effect it names, so a kill
        // during the snapshot leaves the boundary the next open classifies.
        let mut attempt = crate::update::UpdateEvidence::fresh(Some(install.version));
        attempt.pending = Some(crate::update::UpdateBoundary::CheckpointCreate);
        // The reserve write failed, so the record the attempt names does not exist:
        // the pointer names the directory that could not hold it.
        evidence.write(&attempt).map_err(|error| {
            update_open_failure(
                error,
                crate::update::EvidencePointer::Directory,
                boot_diagnostics,
            )
        })?;
        let name = match crate::update::snapshot(&owner.store, data_root) {
            Ok(taken) => taken.map(|snapshot| snapshot.name),
            Err(error) => {
                // The cause is retained before the open reports it, so the record
                // carries the seam an operator acts on; when even that write fails
                // the retention refusal is the one worth reporting.
                attempt.note_failure(crate::update::Failure::at(
                    error.boundary(),
                    error.code(),
                    None,
                ));
                attempt.terminal = crate::update::Terminal::Rejected;
                attempt.pending = None;
                let refusal = evidence.write(&attempt).err().unwrap_or(error);
                // The retention write is what decides the pointer: `write` lists, decodes
                // and prunes the records already in the tree before it renames this
                // attempt's file, so a tree that refused, or that holds a record this build
                // will not decode, leaves nothing of this attempt on disk to name.
                let record = format!("{}.json", attempt.attempt_id);
                let pointer = crate::update::refusal_pointer(&refusal, &record);
                return Err(update_open_failure(refusal, pointer, boot_diagnostics));
            }
        };
        let mut abandoned = None;
        let outcome = crate::update::activate(
            &mut owner.store,
            data_root,
            &evidence,
            &mut attempt,
            name.as_deref(),
            |store| crate::update::validate_generation(store, install),
            |store| {
                let published = store.publish_generation(install)?;
                abandoned = published;
                // The commit alone is the publication's answer: the receipt read
                // that follows it is evidence, so a fault there cannot report a
                // landed activation as refused.
                Ok(())
            },
        );
        match outcome {
            Ok(_) => Ok(abandoned),
            // The activation's own milestones landed, so the attempt's record exists
            // and the pointer names it. A terminal-write refusal is the one exception:
            // then no record was made durable and the directory is what an operator
            // can fix.
            Err(error) => {
                let record = format!("{}.json", attempt.attempt_id);
                let pointer = crate::update::refusal_pointer(&error, &record);
                Err(update_open_failure(error, pointer, boot_diagnostics))
            }
        }
    }

    /// The open body: it owns the [`Owner`] until the runtime is built, so
    /// a failure drops the election and the store before the caller drains
    /// their release failures.
    fn open_inner(
        data_root: &Path,
        provider: Box<dyn Provider>,
        read_worker: Box<dyn crate::executor::ReadWorker>,
    ) -> Result<Self, OpenError> {
        // The startup admits the store without publishing the schema: everything
        // this generation writes — the DDL batches, the reaction rebuild, the
        // ledger, the base and the pinned policy — commits in one transaction
        // below, so no surface can observe half a generation (REQ-001).
        // The ownership pre-check of the cutover: a data root another process
        // holds is refused here, before any DDL of this open, with the owner's own
        // typed cause. That refusal is the one cause an operator cannot resolve
        // from the error alone, so its `upd.owner` row — the seam, the lock file
        // the other process holds and the correction — joins the pre-open
        // diagnostics this failed open prints to stderr. The helper answers no line
        // for any other owner failure, so those diagnostics stay exactly as they were.
        let mut owner = Owner::elect_deferred(data_root).map_err(|error| {
            let diagnostics = crate::update::owner_refusal_diagnostics(&error);
            OpenError::new(error, diagnostics)
        })?;
        // A store that already holds the tables the recovery owners write runs
        // them before the generation transaction: their rows describe the old
        // generation, and the commit that follows must not depend on them being
        // written afterwards. A first install or an older generation has nothing
        // for them to reconcile, so they run after the commit — but they still run
        // before any surface serves, and a verdict they collect rides the failed
        // open of a later step.
        let compatible = owner
            .store
            .startup_schema_compatible()
            .map_err(|error| open_failure(error.into(), &[]))?;
        let mut boot_diagnostics = Vec::new();
        if compatible {
            // A refused recovery keeps its verdicts on the error it returns, so the
            // caller still reports what this open already found.
            match Self::run_startup_recovery(&mut owner) {
                Ok(lines) => boot_diagnostics.extend(lines),
                Err(failure) => {
                    let mut failure = failure;
                    failure.diagnostics.splice(0..0, boot_diagnostics);
                    return Err(failure);
                }
            }
        }
        let config_path = data_root.join("config.toml");
        let user_toml = crate::owner::read_user_config(&config_path, CONFIG_MAX_BYTES)
            .map_err(|error| open_failure(error, &boot_diagnostics))?;
        // One bounded read and one resolve: the object validated here is the same
        // object the transaction pins and the runtime serves, so the recorded
        // policy generation names a configuration that really exists.
        let effective = config::resolve_effective(user_toml.as_deref()).map_err(|source| {
            open_failure(
                OwnerError::Config {
                    path: config_path.clone(),
                    source,
                },
                &boot_diagnostics,
            )
        })?;
        let install = config::BaseInstall::new(
            config::BaseSource::SHIPPED,
            config_path.clone(),
            data_root.to_path_buf(),
        )
        .pinning(&effective);
        // The broker — and with it the injected provider, the one seam a model send
        // would cross — exists before the update path runs. The counted provider is
        // therefore live for the whole startup, so a zero measured on it after the
        // open is "the update path sent nothing" rather than "no counter existed
        // yet", which is what it said while the broker was built after the cutover.
        let broker = Broker::new(provider);
        let base_recovery =
            Self::publish_startup(&mut owner, data_root, &install, &boot_diagnostics)?;
        if !compatible {
            match Self::run_startup_recovery(&mut owner) {
                Ok(lines) => boot_diagnostics.extend(lines),
                Err(failure) => {
                    let mut failure = failure;
                    failure.diagnostics.splice(0..0, boot_diagnostics);
                    return Err(failure);
                }
            }
        }
        // The cutover that the one transaction performed may have discarded a
        // checkpoint (EDGE-006); its verdict reaches the boot channel so a surface
        // that only prints boot lines still names the recovery and its resolution
        // (DX-I2).
        if let Some(abandoned) = &base_recovery {
            boot_diagnostics.push(base_recovery_diagnostic(abandoned, install.version));
        }
        let supervisor = Supervisor::new(SupervisorPolicy::default())
            .map_err(|source| open_failure(source.into(), &boot_diagnostics))?;
        let off_state = Arc::new(crate::executor::WorkflowOffState::new(&effective));
        // The learned definition the next request composes comes from the
        // store (AC-051). Installing it on the broker is what makes an
        // activated delta take effect without a per-request call and without
        // a model call; a store that cannot be read this way fails the open,
        // so no runtime serves a request with a definition it did not read.
        let learned = owner
            .store
            .learning_definition()
            .map_err(|error| open_failure(OwnerError::from(error), &boot_diagnostics))?;
        let mut runtime = Self {
            owner,
            policy: Policy::default(),
            broker,
            notifications: NotificationQueue::new(8),
            scheduler: Scheduler::new(DEFAULT_MAX_SLOTS, DEFAULT_RESOURCE_CAP),
            supervisor,
            effective,
            off_state,
            purpose: String::new(),
            scope_root: PathBuf::new(),
            scoped_file: PathBuf::new(),
            data_root: data_root.to_path_buf(),
            scoped_grant: String::new(),
            config_path,
            provider_calls: 0,
            read_worker,
            mcp_credentials: None,
            boot_diagnostics,
            base_recovery,
            paused_attempts: BTreeMap::new(),
            index: IndexSeam {
                root: data_root.to_path_buf(),
                watch_refusal: None,
                worker: IndexWorker {
                    program: worker_program(),
                    // A helper that does not resolve is not an open
                    // failure: the run answers `helper_unavailable`
                    // typed when it is made, and no in-process
                    // fallback stands in for it.
                    helper: crate::executor::helper_path()
                        .unwrap_or_else(|_| data_root.join("rivect-sandbox-helper")),
                },
            },
            index_watcher: None,
            index_runs: IndexRuns::new(),
            loop_wake: None,
            deferred_index_id: None,
            deferred_mark: false,
            index_generation: None,
            index_answer_observer: IndexAnswerObserver::default(),
            index_seal_control: IndexSealControl::default(),
            index_run_task: None,
        };
        // The broker's candidate re-check view tracks the effective
        // config from boot (AC-045b); every admitted config edit
        // re-pushes it through the same seam.
        runtime.broker.set_config(&runtime.config_for_broker());
        runtime.broker.set_learning_definition(learned);
        Ok(runtime)
    }

    /// Ends the runtime and returns its lock release failures.
    ///
    /// The drop joins the index owner, then releases the store, then the
    /// election; a failed unlock still closes its descriptor and is
    /// reported here instead of by a destructor. Each failure is returned
    /// once, as a one-line string like [`Runtime::boot_diagnostics`], for
    /// the surface to report on a channel it owns. A panic unwinding
    /// through an owner has no drain: the panic is the reported failure.
    #[must_use]
    pub fn release(self) -> Vec<String> {
        drop(self);
        crate::state::take_release_lines()
    }

    /// Grants the single scoped read used by the first-task loop and records
    /// the scope root/file pair the loop is confined to.
    pub fn set_read_scope(&mut self, root: PathBuf, file: PathBuf) -> String {
        self.scope_root = root.clone();
        self.scoped_file = file;
        let grant = self.policy.grant_read(root);
        self.scoped_grant = grant.clone();
        grant
    }

    /// Pins the root the next assembly discovers instruction files under
    /// (AC-076): the CLI entry hands the directory the run was started in, so
    /// discovery walks that root's ancestors and a file in a scope above it
    /// still contributes. A run handed none discovers nothing, and a working
    /// directory that cannot be read hands none rather than failing the boot.
    pub fn set_instructions_root(&mut self, root: Option<PathBuf>) {
        self.broker.set_instructions_root(root);
    }

    pub fn config_for_broker(&self) -> config::Config {
        self.effective.composed()
    }

    /// The applied effective config snapshot: a borrowed read of what
    /// the config owner actually applied, never of an assumed publish.
    #[must_use]
    pub fn effective(&self) -> &EffectiveConfig {
        &self.effective
    }

    /// Re-reads the user's config document through the owner's one
    /// bounded ingress and applies it as the effective snapshot: the
    /// owner state is refreshed (a meaningful source or mode change
    /// moves its generation and invalidates pending check authority)
    /// and the broker's candidate re-check view follows. A document
    /// that cannot be read or does not validate changes nothing.
    ///
    /// # Errors
    /// Returns [`OwnerError::ConfigRead`], [`OwnerError::ConfigTooLarge`],
    /// or [`OwnerError::Config`]; the previous snapshot stays applied.
    pub fn reload_config(&mut self) -> Result<(), OwnerError> {
        let user_toml = crate::owner::read_user_config(&self.config_path, CONFIG_MAX_BYTES)?;
        let effective = config::resolve_effective(user_toml.as_deref()).map_err(|source| {
            OwnerError::Config {
                path: self.config_path.clone(),
                source,
            }
        })?;
        self.effective = effective;
        self.off_state.refresh(&self.effective);
        self.broker.set_config(&self.config_for_broker());
        Ok(())
    }

    /// The config owner's Runtime-issued check handoff (DEC-054): binds
    /// the task, this Runtime's Policy/TaskStore identities, and the
    /// owner's CURRENT snapshot — the monotonic generation, the sources
    /// digest, and the actual workflow mode. A Custom admission requires
    /// the bound explicit user workflow-off; a Native admission binds
    /// the same owner context and invalidates on any meaningful
    /// transition. Public callers cannot choose the context — only the
    /// live config owner resolves it.
    pub fn check_handoff(&self, task_id: &TaskId) -> crate::executor::CheckHandoff {
        crate::executor::CheckHandoff::from_owner(
            &self.off_state,
            task_id,
            Arc::clone(self.policy.identity()),
            Arc::clone(self.owner.store.identity()),
        )
    }

    pub fn goal_bytes(&self, task_id: &TaskId) -> Vec<u8> {
        self.owner.store.goal_bytes(task_id).unwrap_or_default()
    }

    /// Tombstones the paused attempt a task still holds (EDGE-004):
    /// the broker admission is cancelled so a late retry or provider
    /// callback never resurrects it. No entry means no outstanding
    /// attempt — nothing to tombstone.
    pub(crate) fn tombstone_paused(&mut self, task: &TaskId) {
        if let Some(paused) = self.paused_attempts.remove(&task.0) {
            self.broker.cancel_attempt(&paused.manifest.attempt_id);
        }
    }

    /// The post-answer resume every answer ingress shares — wire and
    /// card alike: the frozen selection builds the task's runnable
    /// scheduler node through the production path; a task in a settled
    /// or cancelled tree grows nothing runnable — its answer stays
    /// durable (INV-021) and its still-live paused attempt is
    /// tombstoned so it can never dispatch — and an admitted node
    /// drains immediately. The verdict names which arm ran so a surface
    /// never claims "resumed" for a tree that cannot dispatch.
    pub(crate) fn resume_answered(
        &mut self,
        session_id: &SessionId,
        task: &TaskId,
        selection: AnswerSelection,
    ) -> Result<ResumeAdmission, crate::controller::ControllerError> {
        match self
            .scheduler
            .submit_answered(task.clone(), selection, self.scoped_grant.clone())
        {
            Ok(Some(_)) => {
                self.drain_scheduler(session_id)?;
                Ok(ResumeAdmission::Drained)
            }
            Ok(None) => {
                self.tombstone_paused(task);
                // The scheduler answered for a dead tree, so the durable
                // row settles too: the answer commit just wrote
                // `running`, and a snapshot read off it would report
                // live work that can never dispatch. The cancel lands
                // the terminal lifecycle through the same seam as the
                // operator's cancel — superseding any row that
                // outlived the task and journaling `task.cancelled` —
                // but the journal attributes the settle to the state
                // machine that drove it, never to a human who sent none.
                let intent = self.owner.store.snapshot(task)?.intent_revision;
                self.owner.store.cancel_task_with_origin(
                    session_id,
                    task,
                    intent,
                    Some("the task's tree already settled or cancelled"),
                    "state",
                )?;
                Ok(ResumeAdmission::Tombstoned)
            }
            Err(err) => Err(crate::controller::ControllerError::Scheduler(err)),
        }
    }
}

/// What the post-answer resume did with the answered task — surfaces
/// that report a resume must distinguish the arms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResumeAdmission {
    /// The frozen answer built a runnable node and the drain ran.
    Drained,
    /// The task's tree was already settled or cancelled — the answer
    /// stays durable but nothing will ever dispatch for it.
    Tombstoned,
}

/// A failed [`Runtime::open`] still owes the operator the boot verdicts
/// collected before the failure — a failed open hands no runtime to any
/// surface, so they ride the error — followed by the lock release
/// failures of the owner that failed to open. Each surface routes them to
/// the channel it owns: the transcript while the TUI holds the terminal,
/// the propagated error after the guard restores it. `Display` names the
/// failed open and `source()` is the [`OwnerError`] cause, which carries
/// its own context and original failure; the verdicts are a separate
/// channel, not error prose.
#[derive(Debug, thiserror::Error)]
#[error("runtime open failed")]
pub struct OpenError {
    #[source]
    cause: OwnerError,
    diagnostics: Vec<String>,
}

impl OpenError {
    fn new(cause: OwnerError, diagnostics: Vec<String>) -> Self {
        Self { cause, diagnostics }
    }

    /// The boot verdicts collected before the failure — already
    /// sanitized one-line strings like [`Runtime::boot_diagnostics`] —
    /// then the lock release failures of the owner that failed to open,
    /// each reported once. Empty when the failure preceded collection and
    /// released cleanly.
    pub fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }

    /// The base-ledger refusal this open failed on, when it failed on one
    /// (P-001). [`OwnerError`] has no base variant, so the verdict rides the
    /// store's storage slot; the refusal stays typed inside it, so a caller
    /// reads the class the base domain gives it — `conflict` for a recorded
    /// document whose bytes changed — instead of the slot's
    /// `storage_unavailable`, which would report a document conflict as an
    /// unavailable backend.
    ///
    /// A refused update attempt wraps the ledger's refusal one level deeper: the
    /// slot holds [`crate::update::UpdateError::Activation`], which carries the
    /// [`config::BaseError`]. Both carriers are unwrapped here, so the typed base
    /// class survives the pending-cutover path too, and the update boundary stays
    /// in the message and diagnostics this error already carries.
    pub fn base_refusal(&self) -> Option<&config::BaseError> {
        let OwnerError::Store(StoreError::Storage(source)) = &self.cause else {
            return None;
        };
        if let Some(refusal) = source.downcast_ref::<config::BaseError>() {
            return Some(refusal);
        }
        match source.downcast_ref::<crate::update::UpdateError>() {
            Some(crate::update::UpdateError::Activation { refusal, .. }) => Some(refusal),
            _ => None,
        }
    }

    /// The underlying open failure, for callers owning an
    /// [`OwnerError`]-typed surface.
    pub fn into_source(self) -> OwnerError {
        self.cause
    }
}

impl From<OwnerError> for OpenError {
    /// A failure before verdict collection has nothing to carry.
    fn from(source: OwnerError) -> Self {
        Self::new(source, Vec::new())
    }
}

const CONFIG_MAX_BYTES: usize = crate::contracts::REQUEST_MAX_BYTES;

#[derive(Debug, Serialize)]
pub struct StatusResult {
    pub schema_version: u32,
    pub session_id: SessionId,
    pub owner_generation: u64,
    pub state: String,
    pub workflow: config::ConfigEntry,
    /// The pending/active credential-profile pair (AC-047): `active` is
    /// the profile the latest admitted manifest froze at prepare;
    /// `pending` is the profile the next dispatch on that connection
    /// binds under the current config — they diverge only while an
    /// accepted profile edit waits for the next request.
    pub profile: ProfileStatus,
    pub tasks: Page<crate::contracts::TaskStatus>,
    pub todo: Page<crate::contracts::TodoItem>,
    pub scheduler: Page<crate::contracts::SchedulerItem>,
    /// The learned definition's own visibility (DEC-011): the deltas
    /// composing it now, the ones rolled back, and the schema generation the
    /// store reports. Activation and rollback are observable here — there is
    /// no separate command for them.
    pub learning: LearningStatus,
    /// The instruction files' own visibility (AC-076): the typed conflicts the
    /// latest assembly found under the run's instruction root, each naming its
    /// slot, its scope and every source that declared it. A conflict is
    /// observable here — there is no separate command for it — because
    /// instruction files are data the request carries, not a surface of their
    /// own.
    pub instruction_conflicts: Vec<InstructionConflictStatus>,
    /// The base the store serves and the receipt its update wrote (AC-054,
    /// DEC-011). `doctor` is `PlannedUnimplemented` and no settings search
    /// exists yet, so this is the one surface that names the base version and
    /// classifies every persistent asset — the recorded known limit (DX-I2).
    pub update: config::UpdateStatus,
    /// The checkpoint this open's cutover had to abandon (EDGE-006): the
    /// stopped install's document, which this build cannot resume and which no
    /// surface could otherwise clear. Served here beside the boot line that
    /// says the same thing, so a client reading `runtime.status` alone still
    /// sees the recovery. `None` when this open discarded nothing. The one base
    /// refusal this build cannot repair — a recorded base whose bytes changed
    /// under its own version — names its own recovery in its message ("ship the
    /// changed document under a new base version") and closes with the ship
    /// path, not with a command here; the settings-search carrier
    /// (`settings.open`/`config.search`) is still `PlannedUnimplemented`
    /// (DX-I2).
    pub base_recovery: Option<config::BaseDocument>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ProfileStatus {
    pub pending: Option<String>,
    pub active: Option<String>,
}

/// One typed instruction conflict as the status surface serves it (AC-076):
/// the slot, the scope it was declared in, and every distinct source that
/// declared it — canonical first, so neither source is named as the loser.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct InstructionConflictStatus {
    pub slot: String,
    pub scope: String,
    pub sources: Vec<String>,
}

/// The conflicts of the latest assembly (AC-076): recorded where discovery
/// ran, so a status read reports them instead of re-walking a filesystem.
fn instruction_conflicts(rt: &Runtime) -> Vec<InstructionConflictStatus> {
    rt.broker
        .instruction_conflicts()
        .iter()
        .map(|conflict| InstructionConflictStatus {
            slot: conflict.slot.as_str().to_string(),
            scope: conflict.scope.display().to_string(),
            sources: conflict
                .sources
                .iter()
                .map(|source| source.display().to_string())
                .collect(),
        })
        .collect()
}

/// The pending/active profile pair for the status surface (AC-047):
/// `active` names the profile the latest admitted manifest froze;
/// `pending` names the profile the next dispatch on that connection
/// binds under the current config. With no bound connection both are
/// absent.
fn profile_status(rt: &Runtime) -> ProfileStatus {
    let Some(bound) = rt.broker.bound_profile() else {
        return ProfileStatus {
            pending: None,
            active: None,
        };
    };
    let pending = rt
        .effective
        .parsed
        .as_ref()
        .and_then(|config| config.connections.get(&bound.connection))
        .and_then(|connection| connection.profile.clone());
    ProfileStatus {
        pending,
        active: bound.profile,
    }
}

#[derive(Debug, Serialize)]
pub struct ConfigReadResult {
    pub schema_version: u32,
    pub source_digest: String,
    pub entries: Page<config::ConfigEntry>,
}

const METHODS: &[&str] = &[
    "session.open",
    "session.attach",
    "session.close",
    "runtime.status",
    "config.read",
    "task.submit",
    "task.snapshot",
    "question.current",
    "events.read",
    "task.collection",
    "command.describe",
    "command.execute",
    "artifact.read",
];

#[derive(Debug, thiserror::Error)]
enum RequestError {
    #[error("request exceeds the 1 MiB cap")]
    RequestTooLarge,
    #[error("request is not valid JSON")]
    InvalidJson,
    #[error("request id is required")]
    MissingRequestId,
    #[error("notification ids are not accepted")]
    NotificationId,
    #[error("id must be a string of at most 256 bytes or an exact integer")]
    InvalidRequestId,
    #[error("jsonrpc must be \"2.0\"")]
    WrongJsonRpc,
    #[error("method is required")]
    MissingMethod,
    #[error("page must be an object")]
    InvalidPage,
    #[error("page_size must be a positive integer")]
    InvalidPageSize,
    #[error("response serialization failed")]
    Serialization,
    #[error("page cursor must be gen:<generation>:offset:<offset>")]
    InvalidPageCursor,
    #[error("page cursor offset is out of range")]
    PageCursorOffsetOutOfRange,
    #[error("update_blockers must be an object")]
    InvalidUpdateBlockers,
    #[error("update_blockers.page_size must be an integer from 1 to 200")]
    InvalidUpdatePageSize,
    #[error("update_blockers.base must be an integer within the base version range")]
    InvalidUpdateBase,
    #[error("update_blockers.cursor must be a string")]
    InvalidUpdateCursor,
    #[error("after_cursor must be a non-negative integer within the SQLite cursor range")]
    InvalidAfterCursor,
    #[error("params must be an object")]
    ParamsNotObject,
    #[error("unknown method {method}")]
    UnknownMethod { method: String },
    #[error("{field} is required")]
    Required { field: &'static str },
    #[error("unsupported schema_version {version}")]
    UnsupportedVersion { version: u64 },
    #[error("keys must be a non-empty array")]
    KeysNotArray,
    #[error("{field} exceeds {max} items")]
    ArrayTooLarge { field: &'static str, max: usize },
    #[error("{field} must be an array")]
    ArrayNotArray { field: &'static str },
    #[error("{field} items must be strings")]
    ArrayItemNotString { field: &'static str },
    #[error("keys must be a non-empty array")]
    EmptyKeys,
    #[error("keys must be strings")]
    KeysNotStrings,
    #[error("duplicate key {key}")]
    DuplicateKey { key: String },
    #[error("unknown key {key}; known keys: {}", crate::config::read_key_hint())]
    InvalidKey { key: String },
    /// A declaration the document owns (DEC-010): `[hooks]` and
    /// `[mcp.servers.<name>]` answer the file's own status rather than the
    /// unknown-key frame's carrier list.
    #[error("{}", crate::config::document_only_message(key))]
    DocumentOnlyKey { key: String },
    #[error(
        "machine ingress cannot install hook {key}: a hook entry is a program the executor runs"
    )]
    MachineHookDenied { key: String },
    #[error("unknown local command {command}")]
    UnknownLocalCommand { command: String },
    #[error("task {task_id} is running")]
    SessionInFlight { task_id: String },
    #[error("{command} is known but not available in this build")]
    KnownCommandUnavailable { command: String },
    #[error("artifact.read is known but not available in this build")]
    ArtifactReadUnavailable,
    #[error("unknown command kind {kind}")]
    UnknownCommandKind { kind: String },
    #[error("task_id is forbidden on create")]
    TaskIdForbiddenOnCreate,
    #[error("mutation fields are forbidden on a read op")]
    MutationFieldsForbiddenOnRead,
    #[error("unknown decisions.control op {op}; known ops: status, ask, auto, inherit")]
    UnknownDecisionOp { op: String },
    #[error("unknown parameter {name}")]
    UnknownParameter { name: String },
    #[error(
        "expected_source_digest does not match the current sources; re-read config.read for the current digest"
    )]
    SourceDigestMismatch,
    #[error(
        "machine answer without an explicit delegation is denied; the pending question is preserved"
    )]
    MachineAnswerDenied,
    #[error(
        "machine steer without a trusted human ingress is denied; the intent revision is preserved"
    )]
    MachineSteerDenied,
    #[error("revision fields are required")]
    MissingRevisionFields,
    #[error(transparent)]
    Selection(#[from] SelectionError),
    #[error("{method} is not available in this build")]
    MethodUnavailable { method: String },
    #[error("parameter {name} has the wrong type")]
    InvalidParameter { name: &'static str },
    #[error(transparent)]
    ProjectIndex(#[from] ProjectIndexError),
}

impl RequestError {
    fn code(&self) -> ErrorCode {
        match self {
            Self::UnknownMethod { .. } => ErrorCode::UnknownMethod,
            Self::UnsupportedVersion { .. } => ErrorCode::UnsupportedVersion,
            Self::KnownCommandUnavailable { .. }
            | Self::ArtifactReadUnavailable
            | Self::MethodUnavailable { .. } => ErrorCode::CapabilityUnavailable,
            Self::MachineAnswerDenied
            | Self::MachineSteerDenied
            | Self::MachineHookDenied { .. } => ErrorCode::Denied,
            Self::SessionInFlight { .. } => ErrorCode::Conflict,
            Self::SourceDigestMismatch => ErrorCode::Conflict,
            Self::Serialization => ErrorCode::InternalError,
            Self::ProjectIndex(source) => source.code(),
            _ => ErrorCode::InvalidInput,
        }
    }

    fn rpc_code(&self) -> i64 {
        match self {
            Self::InvalidJson => -32700,
            Self::MissingRequestId
            | Self::NotificationId
            | Self::InvalidRequestId
            | Self::WrongJsonRpc
            | Self::MissingMethod => -32600,
            Self::UnknownMethod { .. } => -32601,
            Self::UnsupportedVersion { .. }
            | Self::KnownCommandUnavailable { .. }
            | Self::SessionInFlight { .. }
            | Self::ArtifactReadUnavailable
            | Self::MachineAnswerDenied
            | Self::MachineSteerDenied
            | Self::MachineHookDenied { .. }
            | Self::SourceDigestMismatch
            | Self::MethodUnavailable { .. }
            | Self::ProjectIndex(_)
            | Self::Serialization => -32000,
            _ => -32602,
        }
    }

    fn rpc_message(&self) -> &'static str {
        match self {
            Self::InvalidJson => "parse error",
            _ => self.code().as_str(),
        }
    }
}

pub fn dispatch_runtime_request(
    rt: &mut Runtime,
    ingress: Ingress,
    connection_id: &str,
    request: &str,
) -> String {
    let response = dispatch_inner(rt, ingress, connection_id, request);
    if rt.take_deferral_mark() {
        // `project.init` handed its run to the off-path owner and owes an
        // answer. This entry point is synchronous by contract, so it
        // waits here for the owner's answer and returns *that* — the
        // same response a loop writes when the answer lands, produced
        // once and never synthesised early. The placeholder the handler
        // returned is never written.
        //
        // The debt is matched by request id, not by "a run is in flight":
        // an unrelated request answered while that run is outstanding is
        // answered now, in its own turn, and never dropped on the floor
        // because someone else's run is unfinished.
        if let Some(owed) = rt.pump_index_blocking() {
            return owed;
        }
    }
    encode(&response)
}

/// One response, encoded. The fallback is the same internal-error frame
/// the runtime's own envelope carries, so a response that cannot encode
/// still reaches the surface as valid JSON.
fn encode(response: &RpcResponse) -> String {
    serde_json::to_string(response).unwrap_or_else(|_| {
        "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32000,\"message\":\"internal_error\"}}"
            .to_string()
    })
}

/// One event a dispatch loop turns on.
///
/// A loop's own input source and the index owner are producers of the
/// *same* channel, so a bounded run answering and a request arriving are
/// ordered by arrival rather than by whichever source the loop happens
/// to be blocked on. That single channel is what lets a loop keep
/// serving while a run is in flight (INV-011); polling either one instead
/// is the defect this replaces.
#[derive(Debug)]
pub enum LoopEvent {
    /// A request frame, already bounded and terminator-stripped.
    Frame(String),
    /// The index owner answered a run, or the watch reported a change.
    /// The loop turns and asks the runtime what, if anything, is owed.
    Index,
    /// The loop's input source reached end of input.
    InputClosed,
    /// The loop's input source failed, with the kind it failed with, so
    /// the loop reports the outcome the blocking read always did.
    InputFailed(std::io::ErrorKind),
    /// A frame past the request cap. Its own event, because the loop
    /// reports it as the oversize request it is rather than as a read
    /// failure.
    FrameTooLarge,
}

/// What one dispatch step produced: the response to write now, or a
/// request whose answer the off-path owner still owes.
///
/// `Deferred` is not a synthesised "accepted": a generation that has not
/// been cut has no `SnapshotId` to report, and the answer the caller
/// eventually receives is the owner's real one, produced once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DispatchStep {
    Ready(String),
    Deferred,
}

/// One step of a dispatch loop: route the request, and say whether its
/// answer is ready or owed. Same routing as
/// [`dispatch_runtime_request`] — one dispatch path, one handler — and
/// the difference is only whether the loop may keep serving while a
/// bounded index run finishes (INV-011).
pub fn dispatch_step(
    rt: &mut Runtime,
    ingress: Ingress,
    connection_id: &str,
    request: &str,
) -> DispatchStep {
    let response = dispatch_inner(rt, ingress, connection_id, request);
    // Only the request that started the run is owed an answer. Any other
    // request is answered now, so a second request arriving while a run
    // is in flight is served rather than silently deferred behind
    // someone else's build.
    if rt.take_deferral_mark() {
        DispatchStep::Deferred
    } else {
        DispatchStep::Ready(encode(&response))
    }
}

fn dispatch_inner(
    rt: &mut Runtime,
    ingress: Ingress,
    connection_id: &str,
    request: &str,
) -> RpcResponse {
    if request.len() > crate::contracts::REQUEST_MAX_BYTES {
        return request_error(Value::Null, RequestError::RequestTooLarge);
    }
    let parsed: Value = match serde_json::from_str(request) {
        Ok(value) => value,
        Err(_) => return request_error(Value::Null, RequestError::InvalidJson),
    };
    let Some(id) = parsed.get("id").cloned() else {
        return request_error(Value::Null, RequestError::MissingRequestId);
    };
    if id.is_null() {
        return request_error(id, RequestError::NotificationId);
    }
    match &id {
        Value::String(s) if s.len() <= 256 => {}
        Value::Number(n) if n.is_i64() => {}
        _ => return request_error(id, RequestError::InvalidRequestId),
    }
    if parsed.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return request_error(id, RequestError::WrongJsonRpc);
    }
    if parsed.get("method").and_then(Value::as_str).is_none() {
        return request_error(id, RequestError::MissingMethod);
    }
    if parsed.get("params").map(Value::is_object) != Some(true) {
        return request_error(id, RequestError::ParamsNotObject);
    }
    let method = parsed["method"].as_str().unwrap_or_default().to_string();
    let params = parsed["params"].clone();
    if !METHODS.contains(&method.as_str()) {
        return request_error(id, RequestError::UnknownMethod { method });
    }
    let schema = params.get("schema_version").and_then(Value::as_u64);
    match schema {
        None => {
            return request_error(
                id,
                RequestError::Required {
                    field: "schema_version",
                },
            );
        }
        Some(1) => {}
        Some(version) => {
            return request_error(id, RequestError::UnsupportedVersion { version });
        }
    }
    handle_method(rt, ingress, connection_id, &method, params, id)
}

const RECOVERY_NOT_FOUND: &str = "; read runtime.status to list tasks";
const RECOVERY_CONFLICT: &str = "; re-read the current snapshot before retrying";
const RECOVERY_STALE_INTENT: &str = "; read task.snapshot for current revisions";
const RECOVERY_ALREADY_TERMINAL: &str = "; the historical outcome is preserved";
const RECOVERY_STORAGE: &str = "; retry after checking local storage";
const RECOVERY_UNSUPPORTED_GENERATION: &str =
    "; a newer build wrote this store, open it with that build";
const RECOVERY_LEARNING: &str = "; read runtime.status for the learned definition";

fn envelope_error(id: Value, code: ErrorCode, rpc_code: i64, message: &str) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcErrorBody {
            code: rpc_code,
            message: code.as_str().to_string(),
            data: WireError {
                code,
                message: message.to_string(),
                boundary_id: None,
                retry_class: RetryClass::None,
            },
        }),
    }
}

fn request_error(id: Value, err: RequestError) -> RpcResponse {
    let code = err.code();
    RpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcErrorBody {
            code: err.rpc_code(),
            message: err.rpc_message().to_string(),
            data: WireError::new(code, err.to_string()),
        }),
    }
}

fn store_error(id: Value, err: &StoreError) -> RpcResponse {
    let message = err.to_string();
    envelope_error(
        id,
        err.code(),
        -32000,
        &format!("{message}{}", recovery_hint(err)),
    )
}

/// A base refusal at open is the store's to report: `OwnerError` carries store
/// refusals whole, and a base-ledger verdict rides as that refusal's own cause
/// so the message still names the version that was refused. The verdict stays
/// typed inside the slot, so [`OpenError::base_refusal`] still reads the class
/// the base domain gives it rather than the wrap's.
fn base_open_failure(error: config::BaseError) -> OwnerError {
    match error {
        config::BaseError::Store(source) => OwnerError::from(source),
        other => OwnerError::from(StoreError::Storage(Box::new(other))),
    }
}

/// One refused update attempt and what its evidence really is: the diagnostics name
/// the attempt's record only when that record was durably written, the directory
/// when the directory or a write inside it refused, and the seam alone when the
/// refusal preceded the evidence step. A pointer to a file that does not exist is
/// worse than no pointer: the operator would look for a cause that was never kept.
fn update_open_failure(
    error: crate::update::UpdateError,
    pointer: crate::update::EvidencePointer<'_>,
    diagnostics: &[String],
) -> OpenError {
    let mut lines = diagnostics.to_vec();
    lines.extend(crate::update::refusal_diagnostics(
        pointer,
        error.boundary(),
        error.correction(),
    ));
    open_failure(
        OwnerError::from(StoreError::Storage(Box::new(error))),
        &lines,
    )
}

/// One failed open, carrying the boot verdicts collected so far. The verdicts
/// are cloned at the failure rather than borrowed by a closure, so a step after
/// them can still add its own line — a recovery an earlier step performed is
/// never hidden by a later failure.
fn open_failure(error: OwnerError, diagnostics: &[String]) -> OpenError {
    OpenError::new(error, diagnostics.to_vec())
}

fn base_error(id: Value, err: &config::BaseError) -> RpcResponse {
    match err {
        config::BaseError::Store(source) => store_error(id, source),
        other => envelope_error(id, other.code(), -32000, &other.to_string()),
    }
}

/// The recovery sentence for one store error. A journal-failed denial
/// keeps its own message — the audit gap is named — while the guidance
/// is the denial's, since the denial is what the caller acts on.
fn recovery_hint(err: &StoreError) -> &'static str {
    match err {
        StoreError::NotFound(_) => RECOVERY_NOT_FOUND,
        StoreError::Conflict(_) => RECOVERY_CONFLICT,
        StoreError::StaleIntent { .. } => RECOVERY_STALE_INTENT,
        StoreError::AlreadyTerminal => RECOVERY_ALREADY_TERMINAL,
        StoreError::InvalidInput(_) => "",
        StoreError::ReopenIdentity { .. } => "",
        StoreError::UnsupportedGeneration { .. } => RECOVERY_UNSUPPORTED_GENERATION,
        StoreError::Delta(_) => RECOVERY_LEARNING,
        StoreError::Storage(_) => RECOVERY_STORAGE,
        StoreError::Closed => RECOVERY_STORAGE,
        StoreError::DenialJournalFailed { denial, .. } => recovery_hint(denial),
    }
}

/// Snapshot of the retained config view one edit is applied against: the
/// document plus the entry the read surface serves from it.
struct RetainedView {
    parsed: Option<config::Config>,
    workflow_entry: config::ConfigEntry,
    decisions_entry: config::ConfigEntry,
    context_entry: config::ConfigEntry,
}

fn retained_view(rt: &Runtime) -> RetainedView {
    RetainedView {
        parsed: rt.effective.parsed.clone(),
        workflow_entry: rt.effective.workflow_entry.clone(),
        decisions_entry: rt.effective.decisions_entry.clone(),
        context_entry: rt.effective.context_entry.clone(),
    }
}

/// Puts the pre-edit retained view back: the command was never journaled,
/// so no surface may observe its edit. The config owner's live
/// workflow-off view is re-resolved from the restored snapshot too — a
/// rolled-back edit must not leave stale off authority behind.
fn restore_retained_view(rt: &mut Runtime, before: &RetainedView) {
    rt.effective.parsed = before.parsed.clone();
    rt.effective.workflow_entry = before.workflow_entry.clone();
    rt.effective.decisions_entry = before.decisions_entry.clone();
    rt.effective.context_entry = before.context_entry.clone();
    rt.off_state.advance(&rt.effective);
}

/// Applies one typed edit to the retained config document. `Config::set`
/// and `Config::reset` restore the original document on rejection, so the
/// retained view always mirrors the last accepted edit; the document is
/// put back either way — this carrier never owns a second config.
fn retained_edit(
    rt: &mut Runtime,
    apply: impl FnOnce(&mut config::Config) -> Result<config::ConfigEdit, config::ConfigError>,
) -> Result<config::ConfigEdit, config::ConfigError> {
    let mut retained = std::mem::take(&mut rt.effective.parsed).unwrap_or_default();
    let edit = apply(&mut retained);
    rt.effective.parsed = Some(retained);
    edit
}

fn config_error(id: Value, err: &config::ConfigError) -> RpcResponse {
    envelope_error(id, ErrorCode::InvalidInput, -32602, &err.to_string())
}

/// Journal owner string for the CLI carrier; the file surface admits with
/// its own owner spelling through the same singleflight.
const CONFIG_CARRIER_OWNER: &str = "cli";

/// Admits one accepted edit through the singleflight journal. The read
/// surface is refreshed first, so the retained doc and its served entries
/// move together; a rejected admission restores `before` — the command
/// was never journaled, so no surface may observe its edit. On success
/// the resolved intent returns so each command shapes its own result —
/// `config.set` reports the legacy payload, `decisions.control` the
/// control-shaped one — while the sources digest moves with the landed
/// bytes so a stale precondition always conflicts.
fn admit_config_edit(
    rt: &mut Runtime,
    edit: &config::ConfigEdit,
    before: RetainedView,
    error_id: Value,
) -> Result<config::PublicationIntent, Box<RpcResponse>> {
    rt.effective.refresh_mode_entries(&edit.digest);
    // Every accepted effective-config transition moves the config
    // owner's generation (DEC-054): a toggle, a source replacement, a
    // landed publication error, or a rolled-back edit (the same call in
    // `restore_retained_view`), so a minted admission's reconsult always
    // sees the CURRENT owner context — never the boot-time snapshot —
    // and stale pending authority refuses instead of reading as
    // current, even after a byte-identical return.
    rt.off_state.advance(&rt.effective);
    let intent = match config::admit_publication(
        &mut rt.owner.store,
        CONFIG_CARRIER_OWNER,
        &rt.config_path,
        edit,
    ) {
        // Fresh admission owns the durable publication: the checked-fd
        // write lands the bytes against the staged identity, then the
        // receipt completes the journal row.
        Ok(config::PublicationAdmission::Staged(intent)) => {
            match config::publish_intent(&mut rt.owner.store, &intent, &edit.bytes) {
                Ok(()) => intent,
                Err(err) => {
                    // Fail closed: a write that cannot run leaves the row
                    // pending — the crash-window recovery owns it — and no
                    // surface serves the edit. A receipt that cannot be
                    // recorded after the bytes landed keeps the edit
                    // durable and served; the next boot receipts it.
                    if !matches!(err, config::PublicationError::Journal(_)) {
                        restore_retained_view(rt, &before);
                    } else {
                        // The bytes landed and only the receipt failed:
                        // the row stays pending and the typed error is
                        // returned, but every served surface reflects
                        // the one config now on disk.
                        serve_landed_config(rt, &intent, edit);
                    }
                    return Err(Box::new(publication_error(error_id, &err)));
                }
            }
        }
        // A pending row is never answered from the retained document
        // alone. A foreign winner's write may still be in flight — the
        // replay observes it — while a row this carrier admitted is
        // healed: the bytes already hold and take the receipt, or the
        // retry re-runs the managed write, so no retry reports an edit
        // that is not on disk.
        Ok(config::PublicationAdmission::Pending(pending)) => {
            match config::resolve_pending_publication(
                &mut rt.owner.store,
                CONFIG_CARRIER_OWNER,
                &pending,
                &edit.bytes,
            ) {
                Ok(intent) => intent,
                Err(err) => {
                    // The fresh write's fail-closed contract, word for
                    // word: an unlanded edit is served by no surface,
                    // while landed bytes keep serving as the receipt
                    // waits for the next boot.
                    if !matches!(err, config::PublicationError::Journal(_)) {
                        restore_retained_view(rt, &before);
                    } else {
                        // The pending-heal tail of the same contract:
                        // landed bytes serve while the receipt waits.
                        serve_landed_config(rt, &pending, edit);
                    }
                    return Err(Box::new(publication_error(error_id, &err)));
                }
            }
        }
        // A terminal row already proved its bytes hold; the replay
        // answers the winner's historical outcome.
        Ok(config::PublicationAdmission::Applied(applied)) => applied,
        Err(err) => {
            restore_retained_view(rt, &before);
            return Err(Box::new(publication_error(error_id, &err)));
        }
    };
    // The edit is durable and served: the broker's candidate re-check
    // view moves with the retained document (AC-045b) so the next
    // dispatch — or an in-flight fallback walk — checks against it.
    serve_landed_config(rt, &intent, edit);
    Ok(intent)
}

/// Serves the one config that is actually on disk after the bytes
/// landed: the broker's candidate view, the digest precondition, and
/// the owner/off handoff move together with the retained document. A
/// receipt that failed after the write (DEC-056 item 5) keeps the
/// typed error and the pending row but must not leave a half-applied
/// view — entries, digest, and broker all name the landed config.
fn serve_landed_config(
    rt: &mut Runtime,
    intent: &config::PublicationIntent,
    edit: &config::ConfigEdit,
) {
    let applied = rt.config_for_broker();
    rt.broker.set_config(&applied);
    // The digest preconditions quote the sources this edit landed:
    // only the row whose intended bytes hold advances it — a foreign
    // winner's or a replayed older intent must never make a concurrent
    // edit's stale precondition pass.
    if intent.intended_digest == edit.digest {
        rt.effective.sources_digest = config::sources_digest(&edit.bytes);
        rt.off_state.refresh(&rt.effective);
    }
}

fn admit_config_command(
    rt: &mut Runtime,
    id: Value,
    command: &str,
    key: &str,
    edit: &config::ConfigEdit,
    before: RetainedView,
) -> RpcResponse {
    match admit_config_edit(rt, edit, before, id.clone()) {
        Ok(intent) => RpcResponse::ok(
            id,
            json!({
                "schema_version": SCHEMA_VERSION,
                "command": command,
                "key": key,
                "digest": edit.digest,
                "owner": intent.owner,
                "admission_seq": intent.admission_seq,
            }),
        ),
        Err(response) => *response,
    }
}

/// Wire shape of a publication failure, one code per variant wherever
/// the family surfaces (P-001): journal trouble keeps the store's typed
/// error and its recovery text; the managed write's own failure takes
/// the same code the executor assigns that worker error — a sandbox
/// that cannot start is a capability failure, a denied write a denial —
/// and the target variants split caller-input codes from backend ones
/// instead of collapsing into `internal_error`.
fn publication_error(id: Value, err: &config::PublicationError) -> RpcResponse {
    let (code, rpc_code) = match err {
        config::PublicationError::Journal(store) => return store_error(id, store),
        config::PublicationError::Write(worker) => {
            (crate::executor::worker_error_code(worker), -32000)
        }
        config::PublicationError::TargetAbsent(_) => (ErrorCode::NotFound, -32000),
        config::PublicationError::TargetNotUtf8 => (ErrorCode::InvalidInput, -32602),
        config::PublicationError::Target(_) => (ErrorCode::StorageUnavailable, -32000),
        config::PublicationError::IdentityMissing => (ErrorCode::InternalError, -32000),
    };
    envelope_error(id, code, rpc_code, &err.to_string())
}

/// Boot diagnostics write to stderr through the locked handle, the same
/// pattern the terminal cleanup path uses: a closed stderr loses the
/// line, never panics the open. Reached when an open fails — the
/// collected verdicts, then any lock release failures of the owner that
/// failed to open — and by a surface reporting the release lines of a
/// runtime it dropped. A caller that never receives the runtime finds
/// the same lines on [`OpenError`] instead.
///
/// On a terminal each line starts at column 0 over an erased row: a
/// surface that has just left the alternate screen restores the main
/// screen with its older text intact, and a newline-only write would
/// leave the unwritten tail of a longer old row after the line. Piped or
/// redirected stderr keeps the plain text, no escape bytes.
pub(crate) fn report_boot_diagnostics(lines: &[String]) {
    let mut stderr = std::io::stderr().lock();
    let terminal = stderr.is_terminal();
    for line in lines {
        let written = if terminal {
            crossterm::queue!(
                stderr,
                crossterm::cursor::MoveToColumn(0),
                crossterm::terminal::Clear(crossterm::terminal::ClearType::CurrentLine)
            )
        } else {
            Ok(())
        }
        .and_then(|()| writeln!(stderr, "{line}"));
        if let Err(error) = written {
            std::hint::black_box(error);
        }
    }
}

/// The journey-disposition sites (DEC-047 site map, SLICE-024 owners):
/// an attempt carrying any of these rows is settled — recovery never
/// adds a second disposition.
const JOURNEY_DISPOSITION_SITES: [&str; 11] = [
    "close.phase_closed",
    "close.unexpected_green",
    "close.wrong_cause",
    "close.green_failed",
    "close.setup_failed",
    "close.zero_tests",
    "close.unclassifiable",
    "close.selection_stale",
    "close.inventory_moved",
    "close.cancelled_before_disposition",
    "close.deadline_before_disposition",
];

/// The DEC-047 Runtime-open reconcile over the claimed check attempts.
/// *Settlement* selects attempts with neither a journey disposition,
/// nor a finalised pre-return provider failure (a durable Terminal
/// transport row, an `admit.claim_commit` row, or a ledger rejection
/// that landed), nor an existing `close.unrecovered` row, and writes
/// exactly one `close.unrecovered` row through the existing single
/// writer. The volatile `attempts.state` string is deliberately not
/// consulted: a crash between a terminal transport row and its ledger
/// rejection is finalised by the row, and a moved state with no durable
/// row still settles. *Cleanup-resume* removes the surviving recorded
/// allocation of any claimed attempt whose cleanup authority was not
/// already retired by a durable `cleanup.root` row. The two selections
/// never mix, no verdict is synthesized, no check is replayed, and
/// every pre-existing row is preserved byte-for-byte; only the
/// attempt's own recorded root is removed — anchored by its recorded
/// dev/ino identity under held directory fds, never a path recomputed
/// from the current environment — and a different directory, symlink,
/// or non-directory at the recorded name is refused, so a forged or
/// foreign path is never deleted. Presence is read at both keys — the
/// direct boundary and its terminal twin — so a terminal-only row is
/// never missed.
///
/// # Errors
/// Returns the store's typed error when the durable view or a
/// settlement row cannot be read or written; cleanup failures are
/// returned as diagnostics, never as errors.
fn reconcile_unrecovered_checks(store: &mut TaskStore) -> Result<Vec<String>, OwnerError> {
    let claimed = store.claimed_check_attempts()?;
    let mut diagnostics = Vec::new();
    for attempt in claimed {
        if !attempt_is_settled(store, &attempt)? {
            let cause = "unrecorded interruption: the dispatch ended without a journey disposition or a finalized provider failure";
            let record = crate::verification::RetainedAttempt {
                attempt_id: attempt.clone(),
                boundary_id: crate::state::check_boundary(&attempt, "close.unrecovered"),
                stage: crate::verification::RetainedStage::Terminal,
                cause: cause.to_string(),
                digest: crate::verification::record_digest(&attempt, cause),
                build_attempt: attempt.clone(),
                admitted_attempt_id: Some(attempt.clone()),
            };
            store.retain_attempt(&record)?;
        }
        if !store
            .has_retained_either_key(&crate::state::check_boundary(&attempt, "cleanup.root"))?
        {
            diagnostics.extend(resume_attempt_root_cleanup(store, &attempt)?);
        }
    }
    Ok(diagnostics)
}

/// The settlement selection (DEC-047, stated once): an attempt is
/// settled when a journey disposition, an existing `close.unrecovered`
/// row, an ambiguous-`admit.claim_commit` row, or a finalised
/// pre-return provider failure is already durable. The volatile ledger
/// state string is not part of the predicate. Every presence read
/// names both keys — the direct boundary and its terminal twin — so a
/// terminal-only row is never missed.
fn attempt_is_settled(store: &TaskStore, attempt: &str) -> Result<bool, OwnerError> {
    Ok(store
        .has_retained_either_key(&crate::state::check_boundary(attempt, "close.unrecovered"))?
        || store.has_retained_either_key(&crate::state::check_boundary(
            attempt,
            "admit.claim_commit",
        ))?
        || has_any_retained(store, attempt, &JOURNEY_DISPOSITION_SITES)?
        || has_finalised_provider_failure(store, attempt)?)
}

/// Whether any durable row finalises the attempt as a pre-return
/// provider failure: a Terminal-stage row at any site other than the
/// success-close trio, or at a success-close site carrying the fixed
/// failed-transport marker (DEC-054: a finalized `close.selection`
/// failure is not the successful close observation — the marker is
/// durable evidence, not prose inference, and the site keeps its one
/// owner). A successful `close.result` handoff is not a failed provider
/// result. `admit.claim_commit`, `close.unrecovered`, and the journey
/// dispositions are Terminal too and checked explicitly by the caller;
/// a row outside the attempt's own boundary namespace fails closed.
fn has_finalised_provider_failure(store: &TaskStore, attempt_id: &str) -> Result<bool, OwnerError> {
    let prefix = crate::state::check_boundary(attempt_id, "");
    Ok(store.retained_check_rows(attempt_id)?.iter().any(|record| {
        record.stage == crate::verification::RetainedStage::Terminal
            && match record.boundary_id.strip_prefix(&prefix) {
                None => true,
                Some(site) if crate::executor::SUCCESS_CLOSE_SITES.contains(&site) => record
                    .cause
                    .starts_with(crate::executor::FAILED_CLOSE_TRANSPORT),
                Some(_) => true,
            }
    }))
}

/// Whether any of `sites` already has a retained row for the attempt.
/// Each site's presence is read at both keys — the direct boundary and
/// its terminal twin — so a terminal-only row is never missed.
fn has_any_retained(
    store: &TaskStore,
    attempt_id: &str,
    sites: &[&str],
) -> Result<bool, OwnerError> {
    for &site in sites {
        if store.has_retained_either_key(&crate::state::check_boundary(attempt_id, site))? {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The cleanup-resume half: decides the attempt's own recorded
/// allocation when it survived its durable rows. The locator is the
/// attempt's durable `attempt.root` record — the canonical path
/// (hex-encoded byte for byte) and the dev/ino identity verified at
/// creation — never a path recomputed from the current environment, so
/// a restart under a different temp directory still addresses the
/// original root and never touches a foreign directory that merely
/// holds the recomputed name. An attempt without a locator record (a
/// synthetic or pre-recording claim) owns nothing: no deletion and no
/// diagnostic — a historical pathname or marker alone is never
/// allocation authentication. An absent root retires durably through
/// `cleanup.root`; a present root — identity-verified or not — is
/// refused before any destructive effect (DEC-056 strict protection):
/// the debris survives byte-for-byte, the obligation stays pending for
/// the next reconcile, and one sanitized diagnostic line names the
/// manual resolution without promising a cleanup this build cannot
/// prove safe.
fn resume_attempt_root_cleanup(
    store: &mut TaskStore,
    attempt_id: &str,
) -> Result<Vec<String>, OwnerError> {
    let Some(record_json) =
        store.retained(&crate::state::check_boundary(attempt_id, "attempt.root"))?
    else {
        return Ok(Vec::new());
    };
    let record: crate::verification::RetainedAttempt =
        serde_json::from_str(&record_json).map_err(|source| {
            OwnerError::Store(StoreError::Storage(
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("the attempt root locator of {attempt_id} is corrupt: {source}"),
                )
                .into(),
            ))
        })?;
    let Some((canonical_root, dev, ino)) = crate::executor::parse_attempt_root_cause(&record.cause)
    else {
        return Err(OwnerError::Store(StoreError::Storage(
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!(
                    "the attempt root locator of {attempt_id} does not name an allocation: {}",
                    crate::resources::sanitize_status_cause(&record.cause)
                ),
            )
            .into(),
        )));
    };
    let outcome = crate::executor::remove_recorded_attempt_root(&canonical_root, dev, ino);
    if let Some(cause) = crate::executor::retirement_cause(&outcome) {
        // The absent-root cleanup retires the attempt's cleanup
        // authority durably: the discharge is never represented by the
        // pathname alone.
        crate::executor::retire_cleanup_authority(store, attempt_id, cause)?;
        return Ok(Vec::new());
    }
    match outcome {
        crate::executor::RootRemoval::Refused(reason) => Ok(vec![format!(
            "check recovery: cleanup refused ({reason}) at {}; \
             resolution: inspect the path, then remove it manually if it is debris",
            crate::resources::sanitize_status_cause(&canonical_root.to_string_lossy())
                .replace('\n', "␤")
        )]),
        crate::executor::RootRemoval::Absent => Ok(Vec::new()),
    }
}

/// One diagnostic line for a recovery verdict a human must resolve:
/// the verdict token names what the bytes at the target failed to
/// prove, the sanitized target names where — every control character
/// arrives as inert text and a newline as ␤, so one verdict stays one
/// line — and the resolution names the retry that settles the row. The
/// healed `ExactlyNew` verdict — our own write receipted by the boot —
/// stays silent.
fn recovery_diagnostic(recovery: &config::PublicationRecovery) -> Option<String> {
    let verdict = match recovery.verdict {
        config::PublicationVerdict::ExactlyNew => return None,
        config::PublicationVerdict::Old => "old",
        config::PublicationVerdict::ByteIdenticalThird => "byte_identical_third",
        config::PublicationVerdict::Conflicting => "conflicting",
        config::PublicationVerdict::TornOrUnparseable => "torn_or_unparseable",
        config::PublicationVerdict::Absent => "absent",
        config::PublicationVerdict::Unknown => "unknown",
    };
    Some(format!(
        "publication recovery: {verdict} verdict stays pending at {}; \
         resolution: inspect the target, then re-run the configuration edit that owns the pending publication",
        crate::resources::sanitize_status_cause(&recovery.intent.target).replace('\n', "␤")
    ))
}

/// One diagnostic line for the checkpoint a cutover had to abandon (EDGE-006):
/// the version and bytes that left, then what is left to resolve. The cutover
/// is the recovery itself — the base it installed serves — so the line reports
/// the discard instead of leaving a stopped run's checkpoint as an unexplained
/// disappearance.
fn base_recovery_diagnostic(abandoned: &config::BaseDocument, installed: u64) -> String {
    format!(
        "base recovery: abandoned the checkpoint of base {} with document {}; \
         resolution: the base {installed} now serves, so the stopped cutover has nothing left to resume",
        abandoned.version, abandoned.digest
    )
}

/// Shared tail of the config.set/unset arms: capture the retained view,
/// apply one typed edit, answer a rejection with the typed ConfigError,
/// and admit an accepted edit through the singleflight journal.
fn commit_config_edit(
    rt: &mut Runtime,
    id: Value,
    command: &str,
    key: &str,
    apply: impl FnOnce(&mut config::Config) -> Result<config::ConfigEdit, config::ConfigError>,
) -> RpcResponse {
    let before = retained_view(rt);
    let edit = match retained_edit(rt, apply) {
        Ok(edit) => edit,
        Err(err) => return config_error(id, &err),
    };
    admit_config_command(rt, id, command, key, &edit, before)
}

/// `/new`: an independent conversation on the same connection. The
/// previous session is left exactly as it is — every task, event and
/// attachment stays addressable through `session.attach` — and the fresh
/// session minted here gets its own bootstrap identity, so the receipt
/// key cannot replay the old one.
///
/// A task that is running refuses the switch. Nothing pauses a running
/// task on a session switch in this build, so detaching would leave it
/// with no surface at all while it keeps spending: the refusal names the
/// task and spends nothing instead of doing that silently. Blocked,
/// waiting and paused work is not spending anything and stays addressable
/// through `session.attach`, so it leaves the conversation startable.
fn session_new(rt: &mut Runtime, id: Value, params: &Value, connection_id: &str) -> RpcResponse {
    let Some(session) = session_param(params) else {
        return missing_session(id);
    };
    let running = match running_task(&rt.owner.store, &session) {
        Ok(task) => task,
        Err(err) => return store_error(id, &err),
    };
    if let Some(task_id) = running {
        return request_error(id, RequestError::SessionInFlight { task_id: task_id.0 });
    }
    let bootstrap = format!("new-{}", CommandId::generate().0);
    match rt.owner.store.open_session(&bootstrap, connection_id, None) {
        Ok((session_id, _, _, _)) => RpcResponse::ok(
            id,
            json!({
                "schema_version": SCHEMA_VERSION,
                "kind": "session.new",
                "session_id": session_id.0,
                "previous_session_id": session.0,
            }),
        ),
        Err(err) => store_error(id, &err),
    }
}

/// The task `/new` would detach mid-run: the oldest task of `session_id`
/// still `running`. A session with no live task at all — every task
/// settled — answers in one bounded row read, so a long settled
/// conversation never walks its history here. Live work does need the
/// walk: only the rows carry a lifecycle, and walking the pages is what
/// keeps the answer true for a running task sitting past `PAGE_MAX`.
fn running_task(store: &TaskStore, session: &SessionId) -> Result<Option<TaskId>, StoreError> {
    if store.in_flight_task(session)?.is_none() {
        return Ok(None);
    }
    let mut scanned = None;
    let mut offset = 0_u64;
    loop {
        let page = match store.task_status_page(session, PAGE_MAX, scanned) {
            Ok(page) => page,
            // Task rows moved between two pages. This read is a safety
            // check, not a snapshot: the bounded read still names a live
            // task, so the switch refuses on that rather than failing on a
            // cursor the operator cannot see.
            Err(StoreError::Conflict(ConflictCause::CursorGeneration { .. })) => {
                return store.in_flight_task(session);
            }
            Err(err) => return Err(err),
        };
        if let Some(running) = page
            .items
            .iter()
            .find(|status| status.lifecycle == Lifecycle::Running)
        {
            return Ok(Some(running.task_id.clone()));
        }
        if page.next_cursor.is_none() {
            return Ok(None);
        }
        offset += u64::from(PAGE_MAX);
        scanned = Some((page.snapshot_generation, offset));
    }
}

/// `context.compact`: one forced compaction of a task's episodic history
/// (AC-049) — the continuation the near-full warning offers. The fold is the
/// owner's own, so a history it would not shorten is the owner's typed
/// refusal rather than a silent no-op the surface could report as a success.
fn context_compact(rt: &mut Runtime, id: Value, params: &Value) -> RpcResponse {
    let Some(session) = session_param(params) else {
        return missing_session(id);
    };
    let Some(task) = task_param(params) else {
        return request_error(id, RequestError::Required { field: "task_id" });
    };
    match rt.store_writer().force_compaction(&session, &task) {
        Ok(report) => RpcResponse::ok(
            id,
            json!({
                "schema_version": SCHEMA_VERSION,
                "kind": "context.compact",
                "checkpoint_id": report.checkpoint_id,
                "before_bytes": report.before_bytes,
                "after_bytes": report.after_bytes,
                "folded_records": report.folded_records,
            }),
        ),
        Err(err) => store_error(id, &err),
    }
}

/// The permission mode every `mcp.call` is admitted and re-consulted under.
/// This build has no Settings permission-mode carrier yet (DEC-015), so the
/// documented interim shape is used at both sites: with the mode at
/// `auto`, a `tools/call` is allowed only when the destination is inside its
/// declared bounds — a recorded preapproval — and an unapproved destination
/// lands on `ask`, never on an allow (DEC-014).
const MCP_CALL_MODE: crate::policy::PermissionMode = crate::policy::PermissionMode::Auto;

/// The first-byte re-consult of one `mcp.call`: the executor's own admission
/// inputs, read again immediately before the frame leaves. A grant revoked, an
/// enrolled deny added or a stricter mode landed between the plan and the send
/// refuses here, so a consumptive call never rides an admission that no longer
/// holds. Cancellation has its own owner — the frame write watches the task —
/// so this consult answers only the admission.
struct EgressReconsult<'a> {
    policy: &'a mut Policy,
    grant_id: &'a str,
}

impl crate::mcp::FirstByteGate for EgressReconsult<'_> {
    fn reconsult(
        &mut self,
        store: &TaskStore,
        server: &crate::mcp::McpServer,
    ) -> Result<(), crate::mcp::McpError> {
        let withdrawn = |cause: String| crate::mcp::McpError::AdmissionWithdrawn {
            server: server.name.clone(),
            cause,
        };
        let target = PathBuf::from(&server.origin);
        let grant = self
            .policy
            .admit(self.grant_id, EffectClass::Egress)
            .map_err(|error| withdrawn(error.to_string()))?;
        let ctx = crate::executor::admission_context(
            store,
            MCP_CALL_MODE,
            EffectClass::Egress,
            self.grant_id,
            &grant.scope_root,
            &target,
        )
        .map_err(|error| withdrawn(error.to_string()))?;
        let decision = self.policy.decide(&target, EffectClass::Egress, &ctx);
        if decision != crate::policy::ModeDecision::Allow {
            return Err(withdrawn(format!(
                "the permission mode verdict is {}",
                decision.token()
            )));
        }
        Ok(())
    }
}

/// `mcp.call`: one admitted `tools/call` against a declared server.
///
/// The request names a server and nothing else: the program, its environment
/// and the origin are the operator's `[mcp.servers.<name>]` declaration, so the
/// origin the egress is admitted against is operator data rather than a string
/// the request carried. The executor's egress admission is the gate between the
/// typed call and the first byte — under the delegated mode the destination must
/// be preapproved for this grant — and the same inputs are re-consulted inside
/// [`crate::mcp::run`] immediately before that byte. The logical operation is
/// the attempt ledger's own attempt (INV-004), so a resume continues it instead
/// of creating a second one.
fn mcp_call(rt: &mut Runtime, id: Value, params: &Value) -> RpcResponse {
    let Some(_session) = session_param(params) else {
        return missing_session(id);
    };
    let Some(task) = task_param(params) else {
        return request_error(id, RequestError::Required { field: "task_id" });
    };
    let Some(grant_id) = params.get("grant_id").and_then(Value::as_str) else {
        return request_error(id, RequestError::Required { field: "grant_id" });
    };
    let request = match crate::mcp::McpRequest::from_value(params) {
        Ok(request) => request,
        Err(error) => return mcp_refusal(id, &error),
    };
    // The declaration is the only place a program, an environment or an origin
    // comes from, so a name this installation does not declare is refused
    // before anything is planned (AC-075 credential origin).
    let composed = rt.effective().composed();
    let Some(declaration) = composed.mcp.get(&request.server) else {
        return mcp_refusal(
            id,
            &crate::mcp::McpError::UndeclaredServer {
                server: request.server,
            },
        );
    };
    let call = crate::mcp::McpCall::declared(&request, declaration);
    if let Err(error) = call.validate() {
        return mcp_refusal(id, &error);
    }
    let reports_root = rt.data_root.clone();
    if let Some(operation) = call.operation.as_deref() {
        match crate::mcp::recorded(&rt.owner.store, operation) {
            Ok(Some(settled)) => return mcp_outcome(id, &call, &settled),
            Ok(None) => {}
            Err(error) => return mcp_refusal(id, &error),
        }
    }
    // Cancellation outranks every new byte: a cancelled task starts no
    // effect, and an operation already in flight stays honestly unknown
    // instead of being forgotten.
    match rt.owner.store.task_cancelled(&task) {
        Ok(false) => {}
        Ok(true) => {
            if let Some(settled) = settle_opened(rt, &id, &call, crate::mcp::McpReason::Cancelled) {
                return settled;
            }
            return envelope_error(
                id,
                ErrorCode::Cancelled,
                -32000,
                "task is cancelled; no mcp call is sent",
            );
        }
        Err(error) => return store_error(id, &error),
    }
    let admitted = {
        let mut executor = rt.executor();
        executor.admit(
            &task,
            crate::executor::EffectRequest::Egress {
                grant_id: grant_id.to_string(),
                url: call.server.origin.clone(),
            },
            MCP_CALL_MODE,
        )
    };
    let admitted = match admitted {
        Ok(admitted) => admitted,
        Err(error) => {
            let code = error.error_code();
            // An `ask` verdict on this egress has one cause under the
            // delegated mode: the declared origin has no recorded
            // preapproval for the grant. The executor's own text stays what
            // every other consumer matches, and this surface adds the step
            // the caller is missing.
            let message = if matches!(&error, crate::executor::ExecutorError::ModeAsk) {
                format!(
                    "effect denied: declared origin {} has no recorded preapproval for grant \
                     {grant_id}; {}",
                    call.server.origin,
                    crate::executor::MODE_ASK_REASON
                )
            } else {
                error.to_string()
            };
            if let Some(settled) =
                settle_opened(rt, &id, &call, crate::mcp::McpReason::DestinationRefused)
            {
                return settled;
            }
            return envelope_error(id, code, -32000, &message);
        }
    };
    let ran = {
        let mut gate = EgressReconsult {
            policy: &mut rt.policy,
            grant_id,
        };
        crate::mcp::run(
            &mut rt.owner.store,
            rt.mcp_credentials.as_deref(),
            &reports_root,
            &call,
            &task,
            &admitted.attempt_id,
            &mut gate,
        )
    };
    match ran {
        Ok(outcome) => mcp_outcome(id, &call, &outcome),
        Err(error) => mcp_refusal(id, &error),
    }
}

/// Whether this store opened the operation a request names. Only a claimed
/// operation may be settled, so a caller-chosen id never lands a terminal row;
/// an unreadable claim proves nothing and leaves the settlement off.
fn mcp_opened(rt: &Runtime, operation: &str) -> bool {
    crate::mcp::opened(&rt.owner.store, operation).unwrap_or(false)
}

/// Settles the operation a refused call names and answers with it, when this
/// store opened that operation. A call that names none, or one this store
/// never claimed, falls through to the refusal its own cause spells: a
/// caller-chosen id never lands a terminal row.
fn settle_opened(
    rt: &mut Runtime,
    id: &Value,
    call: &crate::mcp::McpCall,
    reason: crate::mcp::McpReason,
) -> Option<RpcResponse> {
    let operation = call.operation.as_deref()?;
    if !mcp_opened(rt, operation) {
        return None;
    }
    Some(settle_mcp_unresolved(
        rt,
        id.clone(),
        call,
        operation,
        reason,
    ))
}

fn settle_mcp_unresolved(
    rt: &mut Runtime,
    id: Value,
    call: &crate::mcp::McpCall,
    operation: &str,
    reason: crate::mcp::McpReason,
) -> RpcResponse {
    let reports_root = rt.data_root.clone();
    match crate::mcp::settle_unresolved(
        &mut rt.owner.store,
        &reports_root,
        operation,
        &call.server.name,
        reason,
    ) {
        Ok(outcome) => mcp_outcome(id, call, &outcome),
        Err(error) => mcp_refusal(id, &error),
    }
}

fn mcp_outcome(
    id: Value,
    call: &crate::mcp::McpCall,
    outcome: &crate::mcp::McpOutcome,
) -> RpcResponse {
    RpcResponse::ok(id, outcome.wire(&call.server.name))
}

fn mcp_refusal(id: Value, error: &crate::mcp::McpError) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0",
        id,
        result: None,
        error: Some(RpcErrorBody {
            code: -32000,
            message: error.code().as_str().to_string(),
            data: WireError {
                code: error.code(),
                message: error.to_string(),
                boundary_id: error.boundary_id().map(str::to_string),
                retry_class: RetryClass::None,
            },
        }),
    }
}

/// `decisions.control`: one op per call. `status` is a pure read — the
/// key's served entry plus the mode a fork would observe — and rejects
/// mutation fields; `ask`/`auto`/`inherit` write `decisions.mode`
/// through the same journaled publication `config.set` rides, gated by
/// `command_id` plus the `expected_source_digest` precondition so a
/// switch that never lands is never observed. The `command_id` binds
/// the same receipt contract `create_task` rides: a replay answers the
/// recorded result without re-running the edit, and a reused id naming
/// a different intent conflicts. The mode itself never answers a
/// question or grants a right — it only names how the next material
/// fork resolves.
fn decisions_control(rt: &mut Runtime, id: Value, params: &Value, ingress: Ingress) -> RpcResponse {
    const KNOWN_PARAMS: &[&str] = &[
        "schema_version",
        "command",
        "session_id",
        "op",
        "command_id",
        "expected_source_digest",
    ];
    if let Some(unknown) = params.as_object().and_then(|object| {
        object
            .keys()
            .find(|key| !KNOWN_PARAMS.contains(&key.as_str()))
    }) {
        return request_error(
            id,
            RequestError::UnknownParameter {
                name: unknown.clone(),
            },
        );
    }
    let Some(session) = session_param(params) else {
        return missing_session(id);
    };
    let Some(op) = params.get("op").and_then(Value::as_str) else {
        return request_error(
            id,
            RequestError::Required {
                field: "command.op",
            },
        );
    };
    let command_id = params.get("command_id").and_then(Value::as_str);
    let expected = params.get("expected_source_digest").and_then(Value::as_str);
    if op == "status" {
        if command_id.is_some() || expected.is_some() {
            return request_error(id, RequestError::MutationFieldsForbiddenOnRead);
        }
        let result = config::ConfigExplainResult {
            key: config::DECISIONS_MODE_KEY.to_string(),
            entry: rt.effective.decisions_entry.clone(),
            effective: rt.effective.decisions_mode().as_str().to_string(),
            source_digest: rt.effective.sources_digest.clone(),
        };
        return RpcResponse::ok(
            id,
            json!({
                "schema_version": SCHEMA_VERSION,
                "kind": "decisions.control",
                "op": "status",
                "result": serde_json::to_value(result).unwrap_or(Value::Null),
            }),
        );
    }
    if !matches!(op, "ask" | "auto" | "inherit") {
        return request_error(id, RequestError::UnknownDecisionOp { op: op.to_string() });
    }
    let Some(command_id) = command_id.filter(|id| !id.is_empty()) else {
        return request_error(
            id,
            RequestError::Required {
                field: "command_id",
            },
        );
    };
    let Some(expected) = expected else {
        return request_error(
            id,
            RequestError::Required {
                field: "expected_source_digest",
            },
        );
    };
    let principal = match ingress {
        Ingress::TrustedHuman => "local_user",
        Ingress::Machine => "machine",
    };
    // The receipt check precedes the freshness gate: a retry arrives
    // with the digest it was issued against — already stale once the
    // edit landed — and must be answered from the receipt, not refused.
    let params_digest = match serde_json::to_string(&(
        crate::actions::DECISIONS_CONTROL,
        &session.0,
        principal,
        op,
        expected,
    )) {
        Ok(digest) => digest,
        Err(err) => {
            return envelope_error(id, ErrorCode::InternalError, -32000, &err.to_string());
        }
    };
    match rt.owner.store.receipt(command_id) {
        Ok(Some((digest, result_json))) => {
            if digest != params_digest {
                return store_error(
                    id,
                    &StoreError::Conflict(ConflictCause::DuplicateCommand {
                        command_id: command_id.to_string(),
                    }),
                );
            }
            let result: Value = match serde_json::from_str(&result_json) {
                Ok(result) => result,
                Err(err) => {
                    return envelope_error(id, ErrorCode::InternalError, -32000, &err.to_string());
                }
            };
            return RpcResponse::ok(
                id,
                json!({
                    "schema_version": SCHEMA_VERSION,
                    "kind": "decisions.control",
                    "op": op,
                    "result": result,
                }),
            );
        }
        Ok(None) => {}
        Err(err) => return store_error(id, &err),
    }
    if expected != rt.effective.sources_digest {
        return request_error(id, RequestError::SourceDigestMismatch);
    }
    let before = retained_view(rt);
    let edit = match retained_edit(rt, |config| {
        config.set_wire(config::DECISIONS_MODE_KEY, &Value::String(op.to_string()))
    }) {
        Ok(edit) => edit,
        Err(err) => return config_error(id, &err),
    };
    match admit_config_edit(rt, &edit, before, id.clone()) {
        Ok(intent) => {
            let result = config::ConfigMutationResult {
                key: config::DECISIONS_MODE_KEY.to_string(),
                digest: edit.digest,
                owner: intent.owner,
                admission_seq: intent.admission_seq,
            };
            // The edit is durable and served; the receipt binds
            // command_id → this result so the replay never mutates
            // twice. A receipt that cannot be written reports the store
            // failure — the landed edit is never reported as lost.
            let result_json = serde_json::to_string(&result).unwrap_or_default();
            if let Err(err) = rt.owner.store.record_command_receipt(
                command_id,
                &session,
                principal,
                &params_digest,
                &result_json,
            ) {
                return store_error(id, &err);
            }
            RpcResponse::ok(
                id,
                json!({
                    "schema_version": SCHEMA_VERSION,
                    "kind": "decisions.control",
                    "op": op,
                    "result": serde_json::to_value(result).unwrap_or(Value::Null),
                }),
            )
        }
        Err(response) => *response,
    }
}

fn handle_method(
    rt: &mut Runtime,
    ingress: Ingress,
    connection_id: &str,
    method: &str,
    params: Value,
    id: Value,
) -> RpcResponse {
    match method {
        "session.open" | "session.attach" => {
            let bootstrap = params
                .get("bootstrap_id")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if bootstrap.is_empty() {
                return request_error(
                    id,
                    RequestError::Required {
                        field: "bootstrap_id",
                    },
                );
            }
            let attach_to = params
                .get("session_id")
                .and_then(Value::as_str)
                .map(|s| SessionId(s.to_string()));
            match rt
                .owner
                .store
                .open_session(&bootstrap, connection_id, attach_to.as_ref())
            {
                Ok((session_id, attachment_id, generation, _replayed)) => {
                    let revision = 1;
                    RpcResponse::ok(
                        id,
                        json!({
                            "schema_version": SCHEMA_VERSION,
                            "session_id": session_id.0,
                            "owner_generation": generation,
                            "state": "attached",
                            "attachment_id": attachment_id.0,
                            "session_revision": revision,
                        }),
                    )
                }
                Err(err) => store_error(id, &err),
            }
        }
        "session.close" => {
            let Some(session) = session_param(&params) else {
                return missing_session(id);
            };
            RpcResponse::ok(
                id,
                json!({
                    "schema_version": SCHEMA_VERSION,
                    "session_id": session.0,
                    "owner_generation": 1u64,
                    "state": "closed",
                    "attachment_id": params.get("bootstrap_id").and_then(Value::as_str).unwrap_or_default(),
                    "session_revision": 1u64,
                }),
            )
        }
        "runtime.status" => {
            let Some(session) = session_param(&params) else {
                return missing_session(id);
            };
            let (cursor, limit) = match status_page(&params) {
                Ok(page) => page,
                Err(err) => return request_error(id, err),
            };
            let tasks = match rt.owner.store.task_status_page(&session, limit, cursor) {
                Ok(tasks) => tasks,
                Err(err) => return store_error(id, &err),
            };
            let todo = match rt.owner.store.todo_page(&session, limit, cursor) {
                Ok(todo) => todo,
                Err(err) => return store_error(id, &err),
            };
            let scheduler = match rt.owner.store.scheduler_page(&session, limit, cursor) {
                Ok(scheduler) => scheduler,
                Err(err) => return store_error(id, &err),
            };
            let learning = match rt.owner.store.learning_status() {
                Ok(learning) => learning,
                Err(err) => return store_error(id, &err),
            };
            let update_page = match update_blockers_page(&params) {
                Ok(page) => page,
                Err(err) => return request_error(id, err),
            };
            let update = match crate::update::project_status(
                rt.owner.store(),
                &update_page,
                &rt.data_root,
            ) {
                Ok(update) => update,
                Err(err) => return base_error(id, &err),
            };
            let result = StatusResult {
                schema_version: SCHEMA_VERSION,
                session_id: session,
                owner_generation: rt.owner.generation,
                state: "ready".to_string(),
                workflow: rt.effective.workflow_entry.clone(),
                profile: profile_status(rt),
                tasks,
                todo,
                scheduler,
                learning,
                instruction_conflicts: instruction_conflicts(rt),
                update,
                base_recovery: rt.base_recovery.clone(),
            };
            let Ok(payload) = serde_json::to_value(&result) else {
                return request_error(id, RequestError::Serialization);
            };
            RpcResponse::ok(id, payload)
        }
        "config.read" => {
            let Some(_session) = session_param(&params) else {
                return missing_session(id);
            };
            let Some(keys) = params.get("keys").and_then(Value::as_array) else {
                return request_error(id, RequestError::KeysNotArray);
            };
            if keys.is_empty() {
                return request_error(id, RequestError::EmptyKeys);
            }
            let mut seen = std::collections::BTreeSet::new();
            let mut validated: Vec<&str> = Vec::with_capacity(keys.len());
            for key in keys {
                let Some(key) = key.as_str() else {
                    return request_error(id, RequestError::KeysNotStrings);
                };
                if !seen.insert(key.to_string()) {
                    return request_error(
                        id,
                        RequestError::DuplicateKey {
                            key: key.to_string(),
                        },
                    );
                }
                if !config::is_readable_key(key) {
                    // A section the document owns answers its own status:
                    // "unknown key" frames a spelling the schema does not
                    // know, and neither declared section is that.
                    if config::is_document_only_key(key) {
                        return request_error(
                            id,
                            RequestError::DocumentOnlyKey {
                                key: key.to_string(),
                            },
                        );
                    }
                    return request_error(
                        id,
                        RequestError::InvalidKey {
                            key: key.to_string(),
                        },
                    );
                }
                validated.push(key);
            }
            // One entry per requested key, in request order. The keys a base
            // may supply — the workflow flag, the decision mode and the context
            // guard — serve the entry their layer recorded, so a base value is
            // never reported as the user's; the additive profile keys read from
            // the retained document, where an absent field serves null rather
            // than disappearing (AC-054).
            let view = rt.effective.retained();
            let revision = rt
                .effective
                .parsed
                .as_ref()
                .map_or_else(config::shipped_revision, config::Config::revision);
            let source_kind = if rt.effective.parsed.is_some() {
                "user"
            } else {
                "shipped"
            };
            let mut entries = Vec::with_capacity(validated.len());
            for key in validated {
                if key == config::WORKFLOW_KEY {
                    entries.push(rt.effective.workflow_entry.clone());
                    continue;
                }
                if key == config::DECISIONS_MODE_KEY {
                    entries.push(rt.effective.decisions_entry.clone());
                    continue;
                }
                if key == config::CONTEXT_AUTO_COMPACT_KEY {
                    entries.push(rt.effective.context_entry.clone());
                    continue;
                }
                entries.push(config::ConfigEntry {
                    key: key.to_string(),
                    effective: config::ConfigViewValue::Visible {
                        value: view.read_value(key).unwrap_or(Value::Null),
                    },
                    source: config::ConfigSource {
                        kind: source_kind.to_string(),
                        revision: revision.clone(),
                        target: None,
                    },
                });
            }
            let result = ConfigReadResult {
                schema_version: SCHEMA_VERSION,
                source_digest: rt.effective.sources_digest.clone(),
                entries: Page::new(entries, 0),
            };
            RpcResponse::ok(id, serde_json::to_value(result).unwrap_or(Value::Null))
        }
        "task.submit" => submit_task(rt, ingress, params, id),
        "task.snapshot" => {
            let Some(_session) = session_param(&params) else {
                return missing_session(id);
            };
            let Some(task) = task_param(&params) else {
                return request_error(id, RequestError::Required { field: "task_id" });
            };
            match rt.owner.store.snapshot(&task) {
                Ok(snapshot) => {
                    RpcResponse::ok(id, serde_json::to_value(&snapshot).unwrap_or(Value::Null))
                }
                Err(err) => store_error(id, &err),
            }
        }
        "question.current" => {
            let Some(_session) = session_param(&params) else {
                return missing_session(id);
            };
            let Some(task) = task_param(&params) else {
                return request_error(id, RequestError::Required { field: "task_id" });
            };
            match rt.owner.store.current_question(&task) {
                Ok(None) => {
                    let snapshot = match rt.owner.store.snapshot(&task) {
                        Ok(snapshot) => snapshot,
                        Err(err) => return store_error(id, &err),
                    };
                    let result = QuestionResult {
                        schema_version: SCHEMA_VERSION,
                        task_id: task.clone(),
                        task_revision: snapshot.revision,
                        intent_revision: snapshot.intent_revision,
                        question: None,
                    };
                    RpcResponse::ok(id, serde_json::to_value(&result).unwrap_or(Value::Null))
                }
                Ok(Some((question, task_revision))) => {
                    let result = QuestionResult {
                        schema_version: SCHEMA_VERSION,
                        task_id: task.clone(),
                        task_revision,
                        intent_revision: question.intent_revision,
                        question: Some(question),
                    };
                    RpcResponse::ok(id, serde_json::to_value(&result).unwrap_or(Value::Null))
                }
                Err(err) => store_error(id, &err),
            }
        }
        "events.read" => {
            let Some(session) = session_param(&params) else {
                return missing_session(id);
            };
            let after = match after_cursor(&params) {
                Ok(after) => after,
                Err(err) => return request_error(id, err),
            };
            let task = task_param(&params);
            let limit = match page_limit(&params) {
                Ok(limit) => limit,
                Err(err) => return request_error(id, err),
            };
            match rt
                .owner
                .store
                .events_after(&session, task.as_ref(), after, limit)
            {
                Ok(events) => {
                    let items = events
                        .iter()
                        .map(|e| serde_json::to_value(e).unwrap_or(Value::Null))
                        .collect();
                    RpcResponse::ok(
                        id,
                        serde_json::to_value(Page::new(items, after)).unwrap_or(Value::Null),
                    )
                }
                Err(err) => store_error(id, &err),
            }
        }
        "task.collection" => {
            let Some(_session) = session_param(&params) else {
                return missing_session(id);
            };
            let Some(task) = task_param(&params) else {
                return request_error(id, RequestError::Required { field: "task_id" });
            };
            let Some(collection) = params.get("collection").and_then(Value::as_str) else {
                return request_error(
                    id,
                    RequestError::Required {
                        field: "collection",
                    },
                );
            };
            let cursor = match status_cursor(&params) {
                Ok(cursor) => cursor,
                Err(err) => return request_error(id, err),
            };
            let limit = match page_limit(&params) {
                Ok(limit) => limit,
                Err(err) => return request_error(id, err),
            };
            match rt.owner.store.collection(&task, collection, cursor, limit) {
                Ok(page) => RpcResponse::ok(id, serde_json::to_value(&page).unwrap_or(Value::Null)),
                Err(err) => store_error(id, &err),
            }
        }
        "command.describe" => {
            let page = crate::tools::describe();
            RpcResponse::ok(id, serde_json::to_value(&page).unwrap_or(Value::Null))
        }
        "command.execute" => {
            let Some(kind) = params
                .get("command")
                .and_then(|c| c.get("kind"))
                .and_then(Value::as_str)
            else {
                return request_error(
                    id,
                    RequestError::Required {
                        field: "command.kind",
                    },
                );
            };
            match crate::tools::local_command_kind(kind) {
                crate::tools::LocalKind::ConfigSet => {
                    let Some(_session) = session_param(&params) else {
                        return missing_session(id);
                    };
                    let Some(key) = params.get("key").and_then(Value::as_str) else {
                        return request_error(id, RequestError::Required { field: "key" });
                    };
                    // A hook entry is a program the executor runs, so the
                    // machine channel never installs one (I7). The refusal is
                    // typed and names the key before the edit domain is
                    // consulted, so the cause is the guard, not a schema miss.
                    if matches!(ingress, Ingress::Machine) && config::is_hook_key(key) {
                        return request_error(
                            id,
                            RequestError::MachineHookDenied {
                                key: key.to_string(),
                            },
                        );
                    }
                    let Some(value) = params.get("value") else {
                        return request_error(id, RequestError::Required { field: "value" });
                    };
                    commit_config_edit(rt, id, "config.set", key, |config| {
                        config.set_wire(key, value)
                    })
                }
                crate::tools::LocalKind::ConfigUnset => {
                    let Some(_session) = session_param(&params) else {
                        return missing_session(id);
                    };
                    let Some(key) = params.get("key").and_then(Value::as_str) else {
                        return request_error(id, RequestError::Required { field: "key" });
                    };
                    commit_config_edit(rt, id, "config.unset", key, |config| config.reset(key))
                }
                crate::tools::LocalKind::DecisionsControl => {
                    decisions_control(rt, id, &params, ingress)
                }
                crate::tools::LocalKind::ProjectInit => project_init(rt, id, &params),
                crate::tools::LocalKind::SessionNew => session_new(rt, id, &params, connection_id),
                crate::tools::LocalKind::ContextCompact => context_compact(rt, id, &params),
                crate::tools::LocalKind::McpCall => mcp_call(rt, id, &params),
                // The rows belong to the TUI's own projection, so the
                // handler answers the kind it served and no durable
                // effect: the composer clears them on the same answer.
                crate::tools::LocalKind::ViewClear => {
                    let Some(session) = session_param(&params) else {
                        return missing_session(id);
                    };
                    RpcResponse::ok(
                        id,
                        json!({
                            "schema_version": SCHEMA_VERSION,
                            "kind": "view.clear",
                            "session_id": session.0,
                        }),
                    )
                }
                crate::tools::LocalKind::Unknown => request_error(
                    id,
                    RequestError::UnknownLocalCommand {
                        command: kind.to_string(),
                    },
                ),
                crate::tools::LocalKind::PlannedUnimplemented => request_error(
                    id,
                    RequestError::KnownCommandUnavailable {
                        command: kind.to_string(),
                    },
                ),
            }
        }
        "artifact.read" => request_error(id, RequestError::ArtifactReadUnavailable),
        other => request_error(
            id,
            RequestError::UnknownMethod {
                method: other.to_string(),
            },
        ),
    }
}

// ----- project index (SLICE-032) -----

/// Why a project-index build produced no fresh generation. Each arm
/// keeps its own owner's class: the isolated run answers the DEC-033
/// cause's code, the store answers its own, and a root that cannot be
/// used is a caller error.
#[derive(Debug, thiserror::Error)]
pub enum ProjectIndexError {
    #[error(transparent)]
    Context(#[from] ContextError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("index failure could not be sealed")]
    SealFailed {
        #[source]
        primary: Box<ContextError>,
        secondary: StoreError,
    },
    #[error("the pinned project root {path} is not usable: {source}")]
    ProjectRoot {
        path: String,
        #[source]
        source: std::io::Error,
    },
    /// One run is already in flight. The contract is one in-flight
    /// worker per runtime, so a second request is this typed refusal
    /// rather than a queue nobody drains.
    #[error("an index run is already in flight")]
    RunInFlight,
    /// The owner closed its answer channel while a run was in flight,
    /// which only the runtime's own teardown causes.
    #[error("the index run ended without an answer")]
    RunVanished,
}

impl ProjectIndexError {
    /// The wire code one failing build maps to.
    pub fn code(&self) -> ErrorCode {
        match self {
            Self::Context(source) => source.error_code(),
            Self::Store(source) => source.code(),
            Self::SealFailed { .. } => ErrorCode::StorageUnavailable,
            Self::ProjectRoot { .. } => ErrorCode::InvalidInput,
            Self::RunInFlight | Self::RunVanished => ErrorCode::CapabilityUnavailable,
        }
    }
}

/// The edges one cut generation may serve. The bound is the isolated
/// answer cap's row ceiling: a generation bigger than one answer is
/// refused before a worker starts rather than truncated in flight.
const PROJECT_EDGE_LIMIT: usize = crate::lsp::MAX_SYMBOL_ROWS;

/// The deadline one project build is bounded by (DEC-030 #1): the
/// caller's budget, narrowed by [`MAX_INDEX_PARSE_TIME`]. An absent
/// budget, and any budget wider than the bound, is the bound itself — a
/// caller can never widen it. A zero budget is the deadline already
/// passed, which the isolated run answers typed before it spawns.
pub fn index_deadline(budget_ms: Option<u64>) -> Option<Instant> {
    let now = Instant::now();
    let ceiling = now.checked_add(MAX_INDEX_PARSE_TIME).unwrap_or(now);
    Some(match budget_ms {
        None => ceiling,
        Some(millis) => now
            .checked_add(Duration::from_millis(millis))
            .map_or(now, |caller| caller.min(ceiling)),
    })
}

/// The control-byte escape the render boundary applies to every path a
/// caller can shape (DEC-030 #5): a control byte becomes its
/// backslash-`u` hex spelling, so a filename carrying an escape sequence
/// or a cursor move can never reach a terminal or a log as one.
/// Printable bytes, including non-ASCII text, pass through unchanged.
pub fn escape_control(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        if character.is_control() {
            escaped.push_str(&format!("\\u{:04x}", u32::from(character)));
        } else {
            escaped.push(character);
        }
    }
    escaped
}

/// The `project.init` carrier, parsed from the wire params by the type
/// the contract names ([`LocalCommand`]), so the undeclared-field rule
/// the parser enforced is the type's own: a caller-supplied `root` is
/// refused here because the carrier does not declare it, not because a
/// hand-written parser remembered to look. The bounds the wire arrays
/// carry are the ones every other array on this boundary already has.
fn project_init_command(params: &Value) -> Result<LocalCommand, RequestError> {
    // An undeclared name is refused from the params object, before serde
    // is asked to decode anything. The carrier's `deny_unknown_fields` is
    // the guarantee; this is what makes the refusal *name* the field, so
    // no message is parsed back out of a serde error to find it.
    if let Value::Object(fields) = params {
        for name in fields.keys() {
            if !matches!(name.as_str(), "kind" | "task_id" | "budget_ms" | "changed") {
                return Err(RequestError::UnknownParameter { name: name.clone() });
            }
        }
    }
    let command = LocalCommand::from_value(params).map_err(local_command_error)?;
    let LocalCommand::ProjectInit { changed, .. } = &command;
    if changed.len() > crate::contracts::ARRAY_MAX_ITEMS {
        return Err(RequestError::ArrayTooLarge {
            field: "changed",
            max: crate::contracts::ARRAY_MAX_ITEMS,
        });
    }
    // A narrowing names project-relative documents. An absolute or
    // upward path is not one, and the carry's bind list is built from
    // these spellings — so they are checked here rather than trusted.
    for path in changed {
        if path.is_absolute() || relative_path_is_escaping(path) {
            return Err(RequestError::InvalidParameter { name: "changed" });
        }
    }
    Ok(command)
}

/// Whether a project-relative spelling walks above its own root. A
/// lexical collapse, exactly as the derivation places a specifier: no
/// filesystem access, so a symlinked `..` cannot redirect it.
fn relative_path_is_escaping(path: &Path) -> bool {
    let mut depth: i64 = 0;
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return true;
                }
            }
            std::path::Component::Normal(_) => depth += 1,
            std::path::Component::CurDir => {}
            std::path::Component::RootDir | std::path::Component::Prefix(_) => return true,
        }
    }
    false
}

/// A local command's own refusals, mapped onto the request boundary's
/// typed parameter errors. A serde message names the field it choked
/// on, so the caller learns which one it is without a second round.
/// A carrier that decoded no field is a type refusal, and the name is
/// the field serde itself quoted. Every shape this carrier can produce
/// quotes one: `missing field \`kind\`` when the kind is absent,
/// ``invalid type: … expected …`` naming the member whose type is wrong.
/// An undeclared name never reaches here — it is refused from the params
/// object above, where its name is exact.
fn local_command_error(error: serde_json::Error) -> RequestError {
    let text = error.to_string();
    for name in ["task_id", "budget_ms", "changed", "kind"] {
        if text.contains(&format!("`{name}`")) {
            return RequestError::InvalidParameter { name };
        }
    }
    // A shape with no quoted field names the discriminator itself: the
    // request carried no `kind`, which is the only field serde can be
    // missing without quoting.
    RequestError::InvalidParameter { name: "kind" }
}

impl Runtime {
    /// Pins the project root every index query and project build runs
    /// under (AC-036c). The default is the data root; a surface that
    /// knows the user's project narrows it. It is never taken from wire
    /// input, so an untrusted `Query.root` cannot widen what a dispatch
    /// reads. A root that does not resolve is refused by the build with
    /// the same typed cause a query would give.
    pub fn set_project_root(&mut self, root: PathBuf) {
        self.index.root = root.canonicalize().unwrap_or(root);
    }

    /// Cuts one project-index generation: the run happens on the
    /// off-path owner and the caller waits for its answer, so this
    /// entry point stays synchronous and every existing caller is
    /// unchanged. A dispatch loop uses
    /// [`Runtime::start_index_run`] and [`Runtime::pump_index`] instead,
    /// so it keeps serving while the child runs (INV-011).
    ///
    /// `changed` narrows the cut to the documents a coalesced watcher
    /// batch reported; an empty list is a full build or a repair.
    /// `file_set_moved` is the caller's own verdict that the file set
    /// itself moved, which makes any narrowing unsound.
    ///
    /// # Errors
    /// Returns [`ProjectIndexError`] when a run is already in flight,
    /// the worker produced no answer, the store could not seal the
    /// generation, or the pinned root is unusable.
    pub fn build_project_index(
        &mut self,
        task_id: Option<&TaskId>,
        budget_ms: Option<u64>,
        changed: &[PathBuf],
        file_set_moved: bool,
    ) -> Result<ProjectInitResult, ProjectIndexError> {
        self.start_index_run(task_id, budget_ms, changed, file_set_moved)?;
        self.block_on_index_answer()
    }

    /// Prepares one cut and hands the run to the off-path owner. Nothing
    /// here parses: the reservation, the previous file set and the
    /// deadline are all decided on this thread, and the multi-second
    /// part — the child and its observation — leaves the input and
    /// dispatch path.
    ///
    /// The reserved generation is held until
    /// [`Runtime::pump_index`] or `Runtime::block_on_index_answer`
    /// seals it, so the crash window a dying writer leaves is the whole
    /// run and not a gap between a finished run and its reserve.
    ///
    /// # Errors
    /// Returns [`ProjectIndexError`] when a run is already in flight —
    /// the contract is one in-flight worker per runtime, so a second
    /// request is a typed refusal and never a queue — or when the root,
    /// the store or the reservation refuse.
    pub fn start_index_run(
        &mut self,
        task_id: Option<&TaskId>,
        budget_ms: Option<u64>,
        changed: &[PathBuf],
        file_set_moved: bool,
    ) -> Result<(), ProjectIndexError> {
        // A task already cancelled never starts a run: cancellation is
        // the highest-priority verdict, and it is decided here where the
        // store is. A run that starts and is cancelled *later* is
        // `observe_index_cancellation`'s job, which is what makes an
        // in-flight run cancellable at all.
        if let Some(task_id) = task_id
            && !matches!(self.owner.store.task_cancelled(task_id), Ok(false))
        {
            return Err(ProjectIndexError::Context(ContextError::IsolatedRun {
                cause: IsolatedCause::CancelledBeforeSpawn,
                source: None,
            }));
        }
        // The in-flight test comes first, and it is what decides whether
        // this request has any business touching the runtime at all. A
        // refusal must be side-effect-free: reserving a generation, over
        // writing the in-flight run's own generation slot, or clearing
        // the flag its child is reading would each corrupt the run that
        // is already under way — a request that was refused would cancel
        // someone else's build.
        self.index_runs.ensure_owner(self.loop_wake.as_ref());
        if self.index_runs.busy() {
            return Err(ProjectIndexError::RunInFlight);
        }
        let run = self.prepare_index_run(task_id, budget_ms, changed, file_set_moved)?;
        self.index_runs.cancel_for_new_run();
        if !self.index_runs.start(run) {
            return Err(ProjectIndexError::RunInFlight);
        }
        Ok(())
    }

    /// Whether the task the in-flight run was started for is cancelled.
    /// A poll that cannot read the task's state cannot prove the task is
    /// live, and cancellation is the highest-priority verdict, so an
    /// unreadable store reads as cancelled.
    fn index_run_cancelled(&self) -> bool {
        let Some(task_id) = self.index_run_task.as_ref() else {
            return false;
        };
        !matches!(self.owner.store.task_cancelled(task_id), Ok(false))
    }

    /// Everything a run needs, decided on the dispatch thread: the
    /// boundary check, the previous file set, the reservation, the
    /// request and the deadline.
    fn prepare_index_run(
        &mut self,
        task_id: Option<&TaskId>,
        budget_ms: Option<u64>,
        changed: &[PathBuf],
        file_set_moved: bool,
    ) -> Result<IndexRun, ProjectIndexError> {
        let root =
            self.index
                .root
                .canonicalize()
                .map_err(|source| ProjectIndexError::ProjectRoot {
                    path: self.index.root.display().to_string(),
                    source,
                })?;
        if !root.is_dir() {
            return Err(ProjectIndexError::ProjectRoot {
                path: self.index.root.display().to_string(),
                source: std::io::Error::from(std::io::ErrorKind::NotADirectory),
            });
        }
        // The generation this cut replaces is read before the number is
        // reserved, so it is the sealed one and not the reservation this
        // build is about to make. Its indexed file set is the proof a
        // narrowing needs: the worker compares its own enumeration
        // against it, so a file that appeared or vanished outside the
        // narrowing widens the cut even when the backend that saw the
        // change reported nothing usable.
        let previous_documents = match self.owner.store.latest_index_generation()? {
            None => Vec::new(),
            // A read that fails is not an absent generation: proceeding
            // without the proof would let a narrowing run unchecked, so
            // the storage error is the answer.
            Some(previous) => self
                .owner
                .store
                .index_graph(previous)?
                .map_or_else(Vec::new, |previous| previous.graph.documents),
        };
        // The number is reserved *before* the run, so the window a
        // writer that dies leaves behind is the run itself and not the
        // sub-millisecond gap between a finished run and its reserve. A
        // reservation reads `stale`/`interrupted` with no edges and a
        // `partial` coverage stub, which is the honest "a build was
        // begun and never sealed" marker every later read repairs from
        // (INV-007).
        let generation = self.owner.store.reserve_index_generation()?;
        let request = crate::context::ProjectRequest {
            root,
            changed: changed.to_vec(),
            file_set_moved,
            previous_documents,
            limit: PROJECT_EDGE_LIMIT,
        };
        // DEC-030 #1 is decided here, on the dispatch thread, and moved
        // to the owner unchanged: the caller's budget narrowed by the
        // clamp, never widened by the hop.
        let deadline = index_deadline(budget_ms);
        self.index_generation = Some(generation);
        self.index_run_task = task_id.cloned();
        Ok(IndexRun {
            request,
            program: self.index.worker.program.clone(),
            helper: self.index.worker.helper.clone(),
            deadline,
            answer_cap: crate::context::WORKER_ANSWER_MAX,
        })
    }

    /// Seals one finished run and reports it. The carry follows the
    /// answer, not the request: the derivation may have widened a
    /// narrowing it was given, and a cut that re-derived everything
    /// must carry nothing. The seal also supersedes the generation it
    /// replaces in the same commit, so the two can never both read as
    /// current.
    fn seal_index_run(
        &mut self,
        generation: u64,
        outcome: Result<ProjectGraph, ContextError>,
    ) -> Result<ProjectInitResult, ProjectIndexError> {
        match outcome {
            Ok(graph) => {
                let state = if graph.completeness.is_complete() {
                    GenerationState::Fresh
                } else {
                    GenerationState::Stale {
                        cause: StaleCause::PartialCoverage,
                    }
                };
                let policy = if graph.narrowed_to.is_empty() {
                    CarryPolicy::Full
                } else {
                    CarryPolicy::Narrowed {
                        replaced: &graph.narrowed_to,
                    }
                };
                self.owner
                    .store
                    .seal_index_generation(generation, policy, state, &graph)?;
                self.start_project_watch();
                Ok(ProjectInitResult {
                    snapshot: SnapshotId::Generation(generation),
                    state,
                    graph,
                })
            }
            Err(error) => {
                // The failed run still seals its reserved generation,
                // named stale with its cause: the next read repairs
                // instead of reading an older graph as current. Nothing
                // was re-derived, so nothing is replaced — the seal
                // carries what the project already knew.
                let graph = ProjectGraph {
                    edges: Vec::new(),
                    completeness: Completeness::Partial {
                        reasons: vec![PartialReason::EntriesFailed { count: 1 }],
                    },
                    unresolved: Vec::new(),
                    narrowed_to: Vec::new(),
                    documents: Vec::new(),
                };
                let state = GenerationState::Stale {
                    cause: stale_cause_of(&error),
                };
                if let Err(secondary) = self.owner.store.seal_index_generation(
                    generation,
                    CarryPolicy::Nothing,
                    state,
                    &graph,
                ) {
                    return Err(ProjectIndexError::SealFailed {
                        primary: Box::new(error),
                        secondary,
                    });
                }
                Err(ProjectIndexError::Context(error))
            }
        }
    }

    /// Finishes whatever the off-path owner has completed, without
    /// blocking, and returns the response the loop owes for it. `None`
    /// when nothing is ready — which is most turns.
    ///
    /// Three things happen here, in this order, and all of them are
    /// store work on the one writer:
    ///
    /// 1. a run in flight has its cancellation observed — the store is
    ///    here, so this is the actor the `stop` closure never had, and
    ///    the child ends cancelled while it is still running;
    /// 2. a run whose answer landed is sealed, and its response is
    ///    returned if a request is waiting for one. The cancellation is
    ///    re-read here, on the same turn, so a run that finished and was
    ///    cancelled in the same breath is reported cancelled: the
    ///    verdict is the highest-priority one and does not depend on
    ///    which of the two the loop happened to see first;
    /// 3. with no run in flight, a watch batch the backend reported
    ///    starts its repair on the same owner, which is what closes the
    ///    remaining half of INV-007: a project edited and never
    ///    re-initialised is repaired rather than left reading `Fresh`
    ///    over changed bytes.
    pub fn pump_index(&mut self) -> Option<String> {
        // A run still in flight has its cancellation observed before the
        // answer is considered, so the flag reaches the child while it is
        // running. A run that has *already* answered is decided at the
        // seal instead, which reads the same store: that is the ordering
        // the two halves share, and it is why the verdict does not depend
        // on which of the two this turn happened to see.
        if self.index_runs.busy() {
            self.observe_index_cancellation();
        }
        if let Some(answer) = self.index_runs.take_answer() {
            return self
                .seal_index_answer(answer)
                .map(|answer| self.render_index_answer(answer));
        }
        if self.index_runs.busy() {
            return None;
        }
        if self.index_generation.is_none() {
            // A batch the backend reported is a fact about the project
            // that is already true, so the newest generation stops
            // reading current before the repair is even prepared.
            let Ok(repair) = self.take_index_watch_batch() else {
                return None;
            };
            if let Some(batch) = repair {
                let changed = if batch.needs_full_rebuild() {
                    Vec::new()
                } else {
                    batch.paths.iter().cloned().collect()
                };
                if self
                    .start_index_run(None, None, &changed, batch.file_set_moved)
                    .is_err()
                {
                    return None;
                }
            }
        }
        None
    }

    /// Finishes an outstanding run and returns the response it owes,
    /// without starting anything new.
    ///
    /// This is the shutdown turn: a surface that is closing waits for work
    /// it already accepted rather than abandoning it, and it must not
    /// begin a watch repair there — there is no longer a surface to
    /// serve one, and starting it would hold the exit open for a build
    /// nobody is waiting for.
    pub fn pump_index_owed(&mut self) -> Option<String> {
        if !self.index_run_outstanding() {
            return None;
        }
        if self.index_runs.busy() {
            self.observe_index_cancellation();
        }
        // This turn *waits*, which the ordinary pump deliberately does not:
        // a surface that is closing has no other turn coming, and the wait
        // is bounded by the run's own deadline and its cancel flag.
        let answer = self.index_runs.answers.as_ref()?.recv().ok()?;
        self.index_runs.busy = false;
        self.seal_index_answer(answer)
            .map(|answer| self.render_index_answer(answer))
    }

    /// The cancellation the dispatch thread can see: the task the run
    /// was started for is cancelled, so the flag the child's `stop`
    /// closure reads is raised and the run ends now rather than at its
    /// deadline. A poll that cannot read the task's state cannot prove
    /// the task is live, and cancellation is the highest-priority
    /// verdict here.
    fn observe_index_cancellation(&mut self) {
        if self.index_run_cancelled() {
            self.index_runs.cancel();
        }
    }

    /// Seals one finished run and renders the response a deferred
    /// request is owed. A repair nobody asked for has no response to
    /// write — the seal is the whole point of it.
    fn seal_index_answer(
        &mut self,
        answer: IndexRunOutcome,
    ) -> Option<(Value, Result<ProjectInitResult, ProjectIndexError>)> {
        let generation = self.index_generation.take()?;
        self.index_seal_control
            .before_seal(&mut self.owner.store, self.index_run_task.as_ref());
        // The task is read before the slot is cleared: a cancellation
        // recorded while the run was finishing outranks whatever the run
        // itself produced, and the run is sealed with the same cause a
        // pre-spawn refusal would have carried.
        let cancelled = self.index_run_cancelled();
        self.index_run_task = None;
        let sealed =
            self.seal_index_run(generation, cancel_index_outcome(cancelled, answer.outcome));
        let id = self.deferred_index_id.take()?;
        Some((id, sealed))
    }

    fn render_index_answer(
        &mut self,
        answer: (Value, Result<ProjectInitResult, ProjectIndexError>),
    ) -> String {
        self.index_answer_observer.observe(&answer);
        let (id, sealed) = answer;
        encode(&match sealed {
            Ok(result) => RpcResponse::ok(
                id,
                render_command_result(&LocalCommandResult::ProjectInit(Box::new(result))),
            ),
            Err(error) => request_error(id, RequestError::ProjectIndex(error)),
        })
    }

    /// Waits for the run in flight and seals it. This is the
    /// synchronous entry point's half of the cut: the run is on the
    /// owner, and only the *wait* is here. A refusal the run produced —
    /// a missing helper, a deadline, a cancellation — is sealed and
    /// reported, never flattened into a vanished run.
    fn block_on_index_answer(&mut self) -> Result<ProjectInitResult, ProjectIndexError> {
        let Some(receiver) = self.index_runs.answers.as_ref() else {
            return Err(ProjectIndexError::RunVanished);
        };
        // A closed answer channel is the owner being gone, which only
        // the runtime teardown causes and a borrowed runtime cannot:
        // `RecvError` carries no payload, so the typed "vanished"
        // verdict is the whole answer.
        let answer = receiver
            .recv()
            .map_err(|_disconnected| ProjectIndexError::RunVanished)?;
        self.index_runs.busy = false;
        let Some(generation) = self.index_generation.take() else {
            return Err(ProjectIndexError::RunVanished);
        };
        self.index_seal_control
            .before_seal(&mut self.owner.store, self.index_run_task.as_ref());
        // The same unconditional rule as the loop's: a cancellation
        // recorded while the run finished outranks the run's own verdict,
        // and it is read before the slot is cleared.
        let cancelled = self.index_run_cancelled();
        self.index_run_task = None;
        self.seal_index_run(generation, cancel_index_outcome(cancelled, answer.outcome))
    }

    /// Cuts the generation the project's own watcher asks for: a batch
    /// that cannot describe its own change set repairs the whole
    /// project, a narrow one re-derives only its paths. Both go through
    /// the same worker route, so a re-index is never an in-process
    /// parse.
    ///
    /// The previous generation is marked stale first, with the cause the
    /// batch states: a handle a caller already holds therefore reads as
    /// needing a repair the moment the project moves, instead of
    /// answering rows taken from bytes that are no longer there (INV-007).
    /// The seal's own supersession then finds that row already carrying
    /// a cause and leaves it, so the specific `watcher_missed` survives
    /// the weaker "a newer generation exists".
    ///
    /// # Errors
    /// Returns [`ProjectIndexError`] exactly as
    /// [`Runtime::build_project_index`] does.
    pub fn reindex_from_watch(
        &mut self,
        batch: &crate::index::WatchBatch,
    ) -> Result<ProjectInitResult, ProjectIndexError> {
        self.mark_watched_generation(batch)?;
        let changed = if batch.needs_full_rebuild() {
            Vec::new()
        } else {
            batch.paths.iter().cloned().collect()
        };
        self.build_project_index(None, None, &changed, batch.file_set_moved)
    }

    /// The newest generation stops being current as soon as the watch
    /// reports that the project moved. A batch the backend could not
    /// place or could not bound names `watcher_missed` — the repair
    /// trigger, because that batch cannot describe its own change set.
    fn mark_watched_generation(
        &mut self,
        batch: &crate::index::WatchBatch,
    ) -> Result<(), ProjectIndexError> {
        if batch.paths.is_empty() && !batch.missed && !batch.file_set_moved {
            return Ok(());
        }
        let cause = if batch.missed {
            StaleCause::WatcherMissed
        } else {
            StaleCause::SourceChanged
        };
        if let Some(previous) = self.owner.store.latest_index_generation()? {
            self.owner
                .store
                .mark_index_generation_stale(previous, cause)?;
        }
        Ok(())
    }

    /// Claims the project's own watcher's coalesced batch, if one is
    /// waiting. The consumer is the next `project.init`: what the batch
    /// reports is already true of the project, so the newest generation
    /// is marked stale *now* rather than being served as current until
    /// the new cut lands, and the batch's paths narrow the cut when the
    /// caller named none. `None` when no watch is running or nothing has
    /// changed since the last claim.
    ///
    /// # Errors
    /// Returns [`ProjectIndexError`] when the newest generation cannot
    /// be marked stale.
    pub fn take_index_watch_batch(
        &mut self,
    ) -> Result<Option<crate::index::WatchBatch>, ProjectIndexError> {
        let Some(watcher) = self.index_watcher.as_ref() else {
            return Ok(None);
        };
        let batch = watcher.pending_batch();
        if batch.paths.is_empty() && !batch.missed && !batch.file_set_moved {
            return Ok(None);
        }
        self.mark_watched_generation(&batch)?;
        Ok(Some(batch))
    }

    /// Starts the project's own watcher if it is not already running,
    /// and records a refusal instead of discarding one: a watch that
    /// cannot start means nothing is watching the project, which
    /// [`IndexSeam::watch_refusal`] discloses and the boundary
    /// report names. A watch that is already live is left alone: two
    /// backends would double every event and race the single writer for
    /// a generation.
    ///
    /// # Errors
    /// Returns the watcher's typed refusal when the backend cannot watch
    /// the pinned root.
    pub fn start_index_watch(&mut self) -> Result<(), crate::index::WatchError> {
        if self.index_watcher.is_some() {
            return Ok(());
        }
        let root = self
            .index
            .root
            .canonicalize()
            .unwrap_or_else(|_| self.index.root.clone());
        // The backend pings the loop's own channel, so a batch is
        // noticed by a loop that is blocked on input rather than by a
        // poll. Without a loop channel there is nothing to ping, and the
        // batch is claimed by the next `project.init` instead — so the
        // fallback is a private channel nothing reads, whose sender the
        // backend holds until the watch drops.
        let wake = self
            .loop_wake
            .clone()
            .unwrap_or_else(|| std::sync::mpsc::sync_channel::<LoopEvent>(1).0);
        let runtime_dir = self.owner.runtime_dir().to_path_buf();
        self.index_watcher = Some(IndexWatcher::start(&root, Some(&runtime_dir), wake)?);
        Ok(())
    }

    /// Whether *this* dispatch is the one that handed its run to the
    /// off-path owner, consuming the mark. The id is left in place: it
    /// is what the answer is rendered with, and the loop writes that
    /// answer when the owner lands it.
    pub fn take_deferral_mark(&mut self) -> bool {
        std::mem::take(&mut self.deferred_mark)
    }

    /// Whether a run is outstanding at all, owed or in flight. A surface
    /// that must not start a second one asks this.
    pub fn index_run_outstanding(&self) -> bool {
        self.deferred_index_id.is_some() || self.index_runs.busy()
    }

    /// The blocking half of a synchronous dispatch: wait for the
    /// in-flight run and render the response it owes.
    pub fn pump_index_blocking(&mut self) -> Option<String> {
        if self.index_runs.busy() {
            self.observe_index_cancellation();
        }
        let answer = self.index_runs.answers.as_ref()?.recv().ok()?;
        self.index_runs.busy = false;
        self.seal_index_answer(answer)
            .map(|answer| self.render_index_answer(answer))
    }

    /// Starts the project's own watch once a generation has been cut. A
    /// watch that cannot start is not a failed build — the generation is
    /// real — but the refusal is recorded, not discarded, so the
    /// boundary report names the gap in freshness detection instead of
    /// leaving a stale generation to read as current.
    fn start_project_watch(&mut self) {
        if self.index_watcher.is_some() {
            return;
        }
        if let Err(error) = self.start_index_watch() {
            self.record_index_watch_refusal(&error);
        }
    }

    /// Records why the project's own watch is not running, or `None`
    /// when it is. Set by the dispatch that started it, read by the
    /// boundary report — a refused watch is a disclosed gap in freshness
    /// detection, never a silently narrower index.
    pub fn record_index_watch_refusal(&mut self, error: &crate::index::WatchError) {
        self.index.watch_refusal = Some(error.to_string());
    }
}

/// The stale cause a failed isolated run leaves on its generation: the
/// run's own classification, never a default.
fn stale_cause_of(error: &ContextError) -> StaleCause {
    match error {
        ContextError::IsolatedRun {
            cause:
                IsolatedCause::RequestRejected
                | IsolatedCause::WorkerUncapped
                | IsolatedCause::WorkerEnvRejected
                | IsolatedCause::VersionMismatch,
            ..
        } => StaleCause::WorkerRefused,
        ContextError::WorkerRefused { .. } => StaleCause::WorkerRefused,
        _ => StaleCause::IsolatedRun,
    }
}

fn cancel_index_outcome(
    cancelled: bool,
    outcome: Result<ProjectGraph, ContextError>,
) -> Result<ProjectGraph, ContextError> {
    if cancelled {
        Err(ContextError::IsolatedRun {
            cause: IsolatedCause::Cancelled,
            source: outcome
                .err()
                .map(crate::context::IsolatedRunSource::prior)
                .map(Box::new),
        })
    } else {
        outcome
    }
}

fn project_init(rt: &mut Runtime, id: Value, params: &Value) -> RpcResponse {
    if session_param(params).is_none() {
        return missing_session(id);
    }
    // The kind's own arguments are the carrier's own fields, so a
    // caller-supplied `root` — or any other undeclared name — is
    // refused rather than ignored.
    let command = match project_init_command(params.get("command").unwrap_or(&Value::Null)) {
        Ok(command) => command,
        Err(error) => return request_error(id, error),
    };
    let LocalCommand::ProjectInit {
        task_id,
        budget_ms,
        mut changed,
    } = command;
    // The project's own watch is consumed before the build, not after
    // it: what a batch reports is already true of the project, so the
    // newest generation is marked stale now instead of being served as
    // current until the new cut lands (INV-007). A caller naming its
    // own `changed` says more than the batch does, so the batch narrows
    // only when the caller did not.
    let batch = match rt.take_index_watch_batch() {
        Ok(batch) => batch,
        Err(error) => return request_error(id, RequestError::ProjectIndex(error)),
    };
    let file_set_moved = batch.as_ref().is_some_and(|batch| batch.file_set_moved);
    if changed.is_empty() {
        changed = batch.map_or_else(Vec::new, |batch| batch.paths.into_iter().collect());
    }
    match rt.start_index_run(task_id.as_ref(), budget_ms, &changed, file_set_moved) {
        Ok(()) => {
            // The run is on the off-path owner and its answer is owed.
            // Nothing is written for this request now: a generation that
            // is not cut has no `SnapshotId`, and a synthesised
            // "accepted" would be a lie about a build that has not
            // answered. The entry point either waits (synchronous) or
            // tells the loop it is owed.
            rt.deferred_index_id = Some(id.clone());
            rt.deferred_mark = true;
            RpcResponse::ok(id, Value::Null)
        }
        Err(error) => request_error(id, RequestError::ProjectIndex(error)),
    }
}

/// The render boundary for a local command's answer (DEC-030 #5): the
/// answer is the result type's own serialization — so a variant's tag
/// comes from the type rather than from a hand-written string that can
/// drift away from it — and then every path it echoes crosses the
/// boundary with its control bytes escaped, so a caller-supplied file
/// name can never move a cursor in the surface that renders it. A kind
/// with no payload this build serves has no variant to render, so an
/// absent payload can never read as empty success.
fn render_command_result(result: &LocalCommandResult) -> Value {
    let mut wire = serde_json::to_value(result).unwrap_or(Value::Null);
    let Some(body) = wire.as_object_mut() else {
        // `LocalCommandResult` is a flat tagged struct, so this cannot
        // be a non-object; the fallback keeps the boundary total rather
        // than panicking on a shape the type already excludes.
        return wire;
    };
    let Some(graph) = body.get_mut("graph").and_then(Value::as_object_mut) else {
        return wire;
    };
    if let Some(edges) = graph.get_mut("edges").and_then(Value::as_array_mut) {
        for edge in edges.iter_mut() {
            escape_edge_paths(edge);
        }
    }
    // Every path list the graph carries crosses this boundary, not only
    // the two an edge names. `unresolved` is a specifier the source
    // spelled, `documents` is a file name the walk read, and
    // `narrowed_to` is a path the caller named — all three can carry a
    // control byte, and an unescaped one moves a cursor in whatever
    // renders the answer.
    for list in ["unresolved", "documents", "narrowed_to"] {
        escape_path_list(graph, list);
    }
    wire
}

/// One path list of the rendered graph, escaped in place.
fn escape_path_list(graph: &mut serde_json::Map<String, Value>, name: &str) {
    let Some(paths) = graph.get_mut(name).and_then(Value::as_array_mut) else {
        return;
    };
    for path in paths.iter_mut() {
        if let Some(text) = path.as_str() {
            *path = Value::from(escape_control(text));
        }
    }
}

/// The two path coordinates one edge carries. Both are caller-shaped:
/// `from` is a real file name on disk, `to` is a specifier the source
/// text spelled, and either may carry a control byte.
fn escape_edge_paths(edge: &mut Value) {
    for side in ["from", "to"] {
        let Some(path) = edge
            .get_mut(side)
            .and_then(|side| side.as_object_mut())
            .and_then(|side| side.get("path"))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let escaped = Value::from(escape_control(path));
        if let Some(side) = edge.get_mut(side).and_then(Value::as_object_mut) {
            side.insert("path".to_string(), escaped);
        }
    }
}

fn session_param(params: &Value) -> Option<SessionId> {
    params
        .get("session_id")
        .and_then(Value::as_str)
        .map(|s| SessionId(s.to_string()))
}

fn missing_session(id: Value) -> RpcResponse {
    request_error(
        id,
        RequestError::Required {
            field: "session_id",
        },
    )
}

fn task_param(params: &Value) -> Option<TaskId> {
    params
        .get("task_id")
        .and_then(Value::as_str)
        .map(|s| TaskId(s.to_string()))
}

fn after_cursor(params: &Value) -> Result<u64, RequestError> {
    let Some(value) = params.get("after_cursor") else {
        return Ok(0);
    };
    let Some(cursor) = value.as_u64() else {
        return Err(RequestError::InvalidAfterCursor);
    };
    i64::try_from(cursor).map_err(|_conversion| RequestError::InvalidAfterCursor)?;
    Ok(cursor)
}

fn page_limit(params: &Value) -> Result<u32, RequestError> {
    let Some(page) = params.get("page") else {
        return Ok(PAGE_DEFAULT);
    };
    let Some(page) = page.as_object() else {
        return Err(RequestError::InvalidPage);
    };
    let Some(page_size) = page.get("page_size") else {
        return Ok(PAGE_DEFAULT);
    };
    let Some(page_size) = page_size.as_u64() else {
        return Err(RequestError::InvalidPageSize);
    };
    if page_size == 0 {
        return Err(RequestError::InvalidPageSize);
    }
    let bounded = page_size.min(u64::from(PAGE_MAX));
    match u32::try_from(bounded) {
        Ok(limit) => Ok(limit),
        Err(_) => Err(RequestError::InvalidPageSize),
    }
}

/// The `update_blockers` request, a nested object sibling to `page`: the page
/// size (one to [`PAGE_MAX`], refused outside it — unlike `page.page_size`,
/// which clamps, so the two rules stay told apart), the requested base version
/// and the cursor. A malformed value is a caller error, never the store's
/// storage class, and the base is checked against its domain before it reaches
/// the store's `stored_u64`.
fn update_blockers_page(params: &Value) -> Result<config::UpdatePage, RequestError> {
    let Some(request) = params.get("update_blockers") else {
        return Ok(config::UpdatePage::default());
    };
    let Some(request) = request.as_object() else {
        return Err(RequestError::InvalidUpdateBlockers);
    };
    let page_size = match request.get("page_size") {
        None => PAGE_DEFAULT,
        Some(raw) => {
            let Some(size) = raw.as_u64() else {
                return Err(RequestError::InvalidUpdatePageSize);
            };
            let bounded =
                u32::try_from(size).map_err(|_overflow| RequestError::InvalidUpdatePageSize)?;
            if !(1..=PAGE_MAX).contains(&bounded) {
                return Err(RequestError::InvalidUpdatePageSize);
            }
            bounded
        }
    };
    let base = match request.get("base") {
        None => None,
        Some(raw) => {
            let Some(base) = raw.as_u64() else {
                return Err(RequestError::InvalidUpdateBase);
            };
            if base > i64::MAX as u64 {
                return Err(RequestError::InvalidUpdateBase);
            }
            Some(base)
        }
    };
    let cursor = match request.get("cursor") {
        None => None,
        Some(raw) => {
            let Some(cursor) = raw.as_str() else {
                return Err(RequestError::InvalidUpdateCursor);
            };
            Some(cursor.to_string())
        }
    };
    Ok(config::UpdatePage {
        page_size,
        base,
        cursor,
    })
}

fn status_page(params: &Value) -> Result<(Option<(u64, u64)>, u32), RequestError> {
    let limit = page_limit(params)?;
    let cursor = status_cursor(params)?;
    Ok((cursor, limit))
}

fn status_cursor(params: &Value) -> Result<Option<(u64, u64)>, RequestError> {
    let Some(page) = params.get("page") else {
        return Ok(None);
    };
    let Some(page) = page.as_object() else {
        return Err(RequestError::InvalidPage);
    };
    let Some(cursor) = page.get("cursor") else {
        return Ok(None);
    };
    let Some(cursor) = cursor.as_str() else {
        return Err(RequestError::InvalidPageCursor);
    };
    let Some(cursor) = cursor.strip_prefix("gen:") else {
        return Err(RequestError::InvalidPageCursor);
    };
    let Some((generation, offset)) = cursor.split_once(":offset:") else {
        let Ok(generation) = cursor.parse::<u64>() else {
            return Err(RequestError::InvalidPageCursor);
        };
        return Ok(Some((generation, 0)));
    };
    let Ok(generation) = generation.parse::<u64>() else {
        return Err(RequestError::InvalidPageCursor);
    };
    let Ok(offset) = offset.parse::<u64>() else {
        return Err(RequestError::InvalidPageCursor);
    };
    if offset > i64::MAX.unsigned_abs() {
        return Err(RequestError::PageCursorOffsetOutOfRange);
    }
    Ok(Some((generation, offset)))
}

fn submit_task(rt: &mut Runtime, ingress: Ingress, params: Value, id: Value) -> RpcResponse {
    let Some(session) = session_param(&params) else {
        return missing_session(id);
    };
    let command_id = params
        .get("command_id")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if command_id.is_empty() {
        return request_error(
            id,
            RequestError::Required {
                field: "command_id",
            },
        );
    }
    let kind = params
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    if !crate::contracts::TASK_COMMAND_KINDS.contains(&kind.as_str()) {
        return request_error(id, RequestError::UnknownCommandKind { kind });
    }
    let principal = match ingress {
        Ingress::TrustedHuman => "local_user",
        Ingress::Machine => "machine",
    };
    match kind.as_str() {
        "create" => {
            if params.get("task_id").is_some() {
                return request_error(id, RequestError::TaskIdForbiddenOnCreate);
            }
            let Some(goal) = params.get("goal").and_then(Value::as_str) else {
                return request_error(id, RequestError::Required { field: "goal" });
            };
            let contract = params.get("contract").cloned().unwrap_or(Value::Null);
            let criteria = match string_array(&contract, "criteria") {
                Ok(criteria) => criteria,
                Err(err) => return request_error(id, err),
            };
            let constraints = match string_array(&contract, "constraints") {
                Ok(constraints) => constraints,
                Err(err) => return request_error(id, err),
            };
            let parent_task = params
                .get("parent_task_id")
                .and_then(Value::as_str)
                .map(|id| TaskId(id.to_string()));
            if let Some(parent) = &parent_task {
                // Fail closed before any row is written: an unknown
                // parent task must not create an orphan tree linkage.
                if let Err(err) = rt.owner.store.snapshot(parent) {
                    return store_error(id, &err);
                }
            }
            match rt.owner.store.create_task(
                &session,
                &command_id,
                principal,
                goal,
                (&criteria, &constraints),
            ) {
                Ok(result) => {
                    // The scheduler owns the tree shape (INV-020):
                    // parentage recorded at creation links the child's
                    // runnable node under its parent's when the answer
                    // freezes.
                    if let Some(parent) = parent_task {
                        rt.scheduler.adopt(result.task_id.clone(), parent);
                    }
                    RpcResponse::ok(id, serde_json::to_value(&result).unwrap_or(Value::Null))
                }
                Err(err) => store_error(id, &err),
            }
        }
        "answer" => {
            // The attempt's identity parses before anything else: a
            // request that cannot name its task and question has
            // nothing to journal against, so these two required-field
            // returns stay unrecorded.
            let Some(task) = task_param(&params) else {
                return request_error(id, RequestError::Required { field: "task_id" });
            };
            let Some(question_id) = params
                .get("question_id")
                .and_then(Value::as_str)
                .map(|s| QuestionId(s.to_string()))
            else {
                return request_error(
                    id,
                    RequestError::Required {
                        field: "question_id",
                    },
                );
            };
            // Every denial raised past the identity parse journals —
            // the append-only contract is per attempt, not per gate the
            // attempt happened to reach.
            let expected_intent = params
                .get("expected_intent_revision")
                .and_then(Value::as_u64);
            let question_revision = params.get("question_revision").and_then(Value::as_u64);
            let selection_value = params.get("selection");
            if matches!(ingress, Ingress::Machine) {
                // Fail closed: an SDK answer never proves human consent,
                // the pending question is preserved untouched — and the
                // attempt itself is journaled denied.
                if let Err(err) = journal_denied_answer(
                    &mut rt.owner.store,
                    &task,
                    &question_id,
                    question_revision,
                    selection_value,
                    principal,
                    "machine_ingress",
                ) {
                    return request_denial_journal_error(
                        id,
                        &RequestError::MachineAnswerDenied,
                        &err,
                    );
                }
                return request_error(id, RequestError::MachineAnswerDenied);
            }
            let (Some(expected_intent), Some(question_revision)) =
                (expected_intent, question_revision)
            else {
                if let Err(err) = journal_denied_answer(
                    &mut rt.owner.store,
                    &task,
                    &question_id,
                    question_revision,
                    selection_value,
                    "human",
                    "missing_revision_fields",
                ) {
                    return request_denial_journal_error(
                        id,
                        &RequestError::MissingRevisionFields,
                        &err,
                    );
                }
                return request_error(id, RequestError::MissingRevisionFields);
            };
            let Some(selection_value) = selection_value else {
                // A fully pinned answer with no selection is still an
                // attempt: journal the refusal against the named question
                // before refusing — `"null"` is the honest record of an
                // absent field.
                let denial = RequestError::Required { field: "selection" };
                if let Err(journal) = journal_denied_answer(
                    &mut rt.owner.store,
                    &task,
                    &question_id,
                    Some(question_revision),
                    None,
                    "human",
                    "missing_selection",
                ) {
                    return request_denial_journal_error(id, &denial, &journal);
                }
                return request_error(id, denial);
            };
            let selection = match parse_selection(selection_value) {
                Ok(selection) => selection,
                Err(err) => {
                    let denial: RequestError = err.into();
                    if let Err(journal) = journal_denied_answer(
                        &mut rt.owner.store,
                        &task,
                        &question_id,
                        Some(question_revision),
                        Some(selection_value),
                        "human",
                        "invalid_selection",
                    ) {
                        return request_denial_journal_error(id, &denial, &journal);
                    }
                    return request_error(id, denial);
                }
            };
            let snapshot = match rt.owner.store.snapshot(&task) {
                Ok(snapshot) => snapshot,
                Err(err) => {
                    // The journaled class is the store's own taxonomy —
                    // a stale or storage failure must not masquerade as
                    // `not_found`.
                    if let Err(journal) = journal_denied_answer(
                        &mut rt.owner.store,
                        &task,
                        &question_id,
                        Some(question_revision),
                        Some(selection_value),
                        "human",
                        denial_class(&err),
                    ) {
                        return store_error(
                            id,
                            &StoreError::DenialJournalFailed {
                                denial: Box::new(err),
                                journal: Box::new(journal),
                            },
                        );
                    }
                    return store_error(id, &err);
                }
            };
            if snapshot.intent_revision != expected_intent {
                let denial = StoreError::StaleIntent {
                    expected: expected_intent,
                    current: snapshot.intent_revision,
                };
                if let Err(journal) = journal_denied_answer(
                    &mut rt.owner.store,
                    &task,
                    &question_id,
                    Some(question_revision),
                    Some(selection_value),
                    "human",
                    "stale_intent",
                ) {
                    return store_error(
                        id,
                        &StoreError::DenialJournalFailed {
                            denial: Box::new(denial),
                            journal: Box::new(journal),
                        },
                    );
                }
                return store_error(id, &denial);
            }
            match rt.owner.store.answer_question(
                &session,
                &task,
                &question_id,
                question_revision,
                &selection,
                "human",
            ) {
                Ok(result) => {
                    // The frozen answer builds the task's runnable
                    // scheduler node through the production path; a
                    // settled tree grows nothing runnable — the answer
                    // itself stays durable (INV-021).
                    match rt.resume_answered(&session, &task, selection.clone()) {
                        // `result` is the answer-commit snapshot — read
                        // before the resume ran, and either arm can move
                        // the task past it inside this same request: a
                        // tombstoned tree settles the row cancelled, and
                        // a drained node can run the resumed work to
                        // completion. The wire answer re-reads so the
                        // response reports the task it actually left
                        // behind, never the pre-resume `running` row.
                        Ok(_) => match rt.owner.store.snapshot(&task) {
                            Ok(snapshot) => {
                                let settled = CommandResult {
                                    status: result.status.clone(),
                                    task_id: result.task_id.clone(),
                                    task_revision: snapshot.revision,
                                    intent_revision: snapshot.intent_revision,
                                    event_cursor: snapshot.event_cursor,
                                    snapshot,
                                    contract_revision: result.contract_revision,
                                };
                                match serde_json::to_value(&settled) {
                                    Ok(value) => RpcResponse::ok(id, value),
                                    Err(err) => envelope_error(
                                        id,
                                        ErrorCode::InternalError,
                                        -32000,
                                        &err.to_string(),
                                    ),
                                }
                            }
                            Err(err) => store_error(id, &err),
                        },
                        Err(err) => {
                            let message = err.to_string();
                            envelope_error(id, err.error_code(), -32000, &message)
                        }
                    }
                }
                Err(err) => store_error(id, &err),
            }
        }
        "steer" => {
            let Some(task) = task_param(&params) else {
                return request_error(id, RequestError::Required { field: "task_id" });
            };
            if matches!(ingress, Ingress::Machine) {
                // Fail closed before any row moves: an SDK steer never
                // proves human intent, so the intent revision, the pending
                // question and the task revision stay exactly where the
                // caller found them (AC-009, INV-003).
                return request_error(id, RequestError::MachineSteerDenied);
            }
            let (Some(expected_intent), Some(expected_task)) = (
                params
                    .get("expected_intent_revision")
                    .and_then(Value::as_u64),
                params.get("expected_task_revision").and_then(Value::as_u64),
            ) else {
                return request_error(id, RequestError::MissingRevisionFields);
            };
            let Some(instruction) = params.get("instruction").and_then(Value::as_str) else {
                return request_error(
                    id,
                    RequestError::Required {
                        field: "instruction",
                    },
                );
            };
            match rt.owner.store.steer_task(
                &session,
                &task,
                expected_intent,
                expected_task,
                instruction,
            ) {
                Ok(result) => {
                    // The steer supersedes the intent a paused
                    // manual-fallback attempt was pinned under — drain
                    // the pause so the frozen manifest can never
                    // dispatch. The pending question row was superseded
                    // in the same commit — kept for audit, never
                    // answerable again.
                    rt.tombstone_paused(&task);
                    RpcResponse::ok(id, serde_json::to_value(&result).unwrap_or(Value::Null))
                }
                Err(err) => store_error(id, &err),
            }
        }
        "cancel" => {
            let Some(task) = task_param(&params) else {
                return request_error(id, RequestError::Required { field: "task_id" });
            };
            let Some(expected_intent) = params
                .get("expected_intent_revision")
                .and_then(Value::as_u64)
            else {
                return request_error(
                    id,
                    RequestError::Required {
                        field: "expected_intent_revision",
                    },
                );
            };
            let reason = params.get("reason").and_then(Value::as_str);
            match rt
                .owner
                .store
                .cancel_task(&session, &task, expected_intent, reason)
            {
                Ok(result) => {
                    // The tree drains with the store cancellation: the
                    // remaining children of the cancelled task never admit
                    // or dispatch (AC-012).
                    match rt.scheduler.cancel_task_tree(&task) {
                        Ok(_) => {
                            rt.tombstone_paused(&task);
                            RpcResponse::ok(
                                id,
                                serde_json::to_value(&result).unwrap_or(Value::Null),
                            )
                        }
                        Err(err) => {
                            let message = err.to_string();
                            envelope_error(
                                id,
                                crate::controller::ControllerError::Scheduler(err).error_code(),
                                -32000,
                                &message,
                            )
                        }
                    }
                }
                Err(err) => store_error(id, &err),
            }
        }
        other => request_error(
            id,
            RequestError::MethodUnavailable {
                method: other.to_string(),
            },
        ),
    }
}

/// A denied answer attempt that never reaches `answer_question` still
/// journals — the append-only contract counts attempts, not gates.
/// The row records what the request actually carried: the raw selection
/// bytes (`"null"` when the field was absent) and `question_revision` 0
/// when the caller pinned none — live revisions start at 1, so 0 can
/// only mean "unpinned". A journal failure never masks the refusal: the
/// caller wraps it with the denial it protects.
fn journal_denied_answer(
    store: &mut TaskStore,
    task: &TaskId,
    question_id: &QuestionId,
    question_revision: Option<u64>,
    selection: Option<&Value>,
    author: &str,
    denial: &str,
) -> Result<(), StoreError> {
    store.record_denied_attempt(
        task,
        question_id,
        question_revision.unwrap_or(0),
        &selection.map_or_else(|| "null".to_string(), Value::to_string),
        author,
        denial,
    )
}

/// The composite a request-level denial reports when its journal write
/// fails: `DenialJournalFailed`'s shape for denials that are not
/// `StoreError`s — the denial keeps its own code and rpc class, and the
/// audit gap is named rather than masking the refusal.
fn request_denial_journal_error(
    id: Value,
    denial: &RequestError,
    journal: &StoreError,
) -> RpcResponse {
    envelope_error(
        id,
        denial.code(),
        denial.rpc_code(),
        &format!("answer denied: {denial}; the denial journal write failed: {journal}"),
    )
}

#[derive(Debug, thiserror::Error)]
enum SelectionError {
    #[error("selection cannot carry both option_id and text")]
    ConflictingFields,
    #[error("option_id is required")]
    MissingOptionId,
    #[error("custom text exceeds {max} bytes")]
    TextTooLarge { max: usize },
    #[error("custom text is required")]
    MissingText,
    #[error("selection.kind must be option or custom")]
    UnsupportedKind,
}

fn parse_selection(value: &Value) -> Result<AnswerSelection, SelectionError> {
    match value.get("kind").and_then(Value::as_str) {
        Some("option") => {
            if value.get("text").is_some() {
                return Err(SelectionError::ConflictingFields);
            }
            let option_id = value
                .get("option_id")
                .and_then(Value::as_str)
                .filter(|s| !s.is_empty())
                .ok_or(SelectionError::MissingOptionId)?;
            Ok(AnswerSelection::Option {
                option_id: OptionId(option_id.to_string()),
            })
        }
        Some("custom") => {
            if value.get("option_id").is_some() {
                return Err(SelectionError::ConflictingFields);
            }
            let text = value
                .get("text")
                .and_then(Value::as_str)
                .ok_or(SelectionError::MissingText)?;
            if text.len() > crate::contracts::TEXT_MAX_BYTES {
                return Err(SelectionError::TextTooLarge {
                    max: crate::contracts::TEXT_MAX_BYTES,
                });
            }
            Ok(AnswerSelection::Custom {
                text: text.to_string(),
            })
        }
        _ => Err(SelectionError::UnsupportedKind),
    }
}

fn string_array(contract: &Value, field: &'static str) -> Result<Vec<String>, RequestError> {
    let Some(value) = contract.get(field) else {
        return Ok(Vec::new());
    };
    let Some(items) = value.as_array() else {
        return Err(RequestError::ArrayNotArray { field });
    };
    if items.len() > crate::contracts::ARRAY_MAX_ITEMS {
        return Err(RequestError::ArrayTooLarge {
            field,
            max: crate::contracts::ARRAY_MAX_ITEMS,
        });
    }
    items
        .iter()
        .map(|item| {
            item.as_str()
                .map(str::to_string)
                .ok_or(RequestError::ArrayItemNotString { field })
        })
        .collect()
}

#[cfg(not(test))]
#[derive(Default)]
struct IndexAnswerObserver {}

#[cfg(not(test))]
impl IndexAnswerObserver {
    fn observe(&mut self, _answer: &(Value, Result<ProjectInitResult, ProjectIndexError>)) {}
}

#[cfg(not(test))]
#[derive(Default)]
struct IndexSealControl {}

#[cfg(not(test))]
impl IndexSealControl {
    fn before_seal(&mut self, _store: &mut TaskStore, _task: Option<&TaskId>) {}
}

#[cfg(test)]
use tests::{IndexAnswerObserver, IndexSealControl};

#[cfg(test)]
mod tests {
    use super::{publication_error, recovery_diagnostic};

    use crate::config::{self, ConfigValue};
    use crate::contracts::ErrorCode;
    use crate::executor::WorkerError;
    use crate::state::{StoreError, TaskStore};
    use serde_json::Value;

    type TestResult = Result<(), Box<dyn std::error::Error + Send + Sync>>;

    type AnswerObserver = dyn FnMut(
            &(
                Value,
                Result<super::ProjectInitResult, super::ProjectIndexError>,
            ),
        ) + Send;

    #[derive(Default)]
    pub(super) struct IndexAnswerObserver {
        callback: Option<Box<AnswerObserver>>,
    }

    impl IndexAnswerObserver {
        pub(super) fn observe(
            &mut self,
            answer: &(
                Value,
                Result<super::ProjectInitResult, super::ProjectIndexError>,
            ),
        ) {
            if let Some(callback) = &mut self.callback {
                callback(answer);
            }
        }
    }

    type SealControl = dyn FnOnce(&mut TaskStore, Option<&crate::contracts::TaskId>) + Send;

    #[derive(Default)]
    pub(super) struct IndexSealControl {
        callback: Option<Box<SealControl>>,
    }

    impl IndexSealControl {
        pub(super) fn before_seal(
            &mut self,
            store: &mut TaskStore,
            task: Option<&crate::contracts::TaskId>,
        ) {
            if let Some(callback) = self.callback.take() {
                callback(store, task);
            }
        }
    }

    type OwnedIndexFailure = (
        tempfile::TempDir,
        super::Runtime,
        crate::contracts::SessionId,
        crate::contracts::TaskId,
        super::IndexRunOutcome,
    );

    fn owned_index_failure() -> Result<OwnedIndexFailure, Box<dyn std::error::Error + Send + Sync>>
    {
        let (root, mut runtime, session, task) = owned_index_runtime()?;
        runtime.start_index_run(Some(&task), None, &[], false)?;
        let answer = runtime
            .index_runs
            .answers
            .as_ref()
            .expect("the run owns an answer channel")
            .recv_timeout(std::time::Duration::from_secs(5))?;
        assert_original_eacces(answer.outcome.as_ref().expect_err("helper must refuse"));
        Ok((root, runtime, session, task, answer))
    }

    fn owned_index_runtime() -> Result<
        (
            tempfile::TempDir,
            super::Runtime,
            crate::contracts::SessionId,
            crate::contracts::TaskId,
        ),
        Box<dyn std::error::Error + Send + Sync>,
    > {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir()?;
        let helper = root.path().join("nonexecutable-helper");
        std::fs::write(&helper, b"not executable\n")?;
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o600))?;
        let mut runtime = super::Runtime::open_with_worker(
            root.path(),
            Box::new(crate::providers::LoopbackProvider::new()),
            Box::new(RecoveryNoWorker),
        )?;
        runtime.index.worker.helper = helper;
        let (session, _, _, _) = runtime
            .owner
            .store
            .open_session("owned-index", "unit", None)?;
        let task = runtime
            .owner
            .store
            .create_task(&session, "owned-index", "unit", "index source", (&[], &[]))?
            .task_id;
        Ok((root, runtime, session, task))
    }

    fn assert_original_eacces(error: &(dyn std::error::Error + 'static)) {
        let mut next = Some(error);
        let mut worker = false;
        let mut errno = None;
        while let Some(source) = next {
            worker |= source.downcast_ref::<WorkerError>().is_some();
            if let Some(source) = source.downcast_ref::<std::io::Error>() {
                errno = source.raw_os_error();
            }
            next = source.source();
        }
        assert!(worker, "the original worker failure must survive");
        assert_eq!(errno, Some(13), "the original errno must survive");
    }

    #[test]
    fn owned_launch_index_cancel_keeps_primary_in_both_runtime_paths() -> TestResult {
        for blocking in [true, false] {
            let (_root, mut runtime, session, task, answer) = owned_index_failure()?;
            let revision = runtime.owner.store.snapshot(&task)?.intent_revision;
            runtime
                .owner
                .store
                .cancel_task(&session, &task, revision, None)?;
            if blocking {
                let (send, receive) = std::sync::mpsc::sync_channel(1);
                send.send(answer).expect("handoff the actual answer once");
                runtime.index_runs.answers = Some(receive);
                let error = runtime.block_on_index_answer().expect_err("cancelled run");
                assert_eq!(error.code(), ErrorCode::Cancelled);
                assert_original_eacces(&error);
            } else {
                runtime.deferred_index_id = Some(Value::from("owned-index-answer"));
                let answer = runtime.seal_index_answer(answer).expect("owed response");
                assert_original_eacces(answer.1.as_ref().expect_err("cancelled answer"));
                let wire = runtime.render_index_answer(answer);
                let wire: Value = serde_json::from_str(&wire)?;
                assert_eq!(wire["id"], "owned-index-answer");
                assert_eq!(wire["error"]["data"]["code"], "cancelled");
            }
        }
        for pump in 0..3 {
            for cancelled in [false, true] {
                for closed in [false, true] {
                    let (_root, mut runtime, session, task, answer) = owned_index_failure()?;
                    if cancelled {
                        let revision = runtime.owner.store.snapshot(&task)?.intent_revision;
                        runtime
                            .owner
                            .store
                            .cancel_task(&session, &task, revision, None)?;
                    }
                    if closed {
                        runtime.owner.store.close()?;
                    }
                    let observations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                    let observed = std::sync::Arc::clone(&observations);
                    runtime.index_answer_observer.callback = Some(Box::new(move |(id, result)| {
                        assert_eq!(id, "owned-pump-answer");
                        let error = result.as_ref().expect_err("actual helper failure");
                        assert_original_eacces(error);
                        let primary = match error {
                            super::ProjectIndexError::Context(primary) if !closed => Some(primary),
                            super::ProjectIndexError::SealFailed { primary, secondary }
                                if closed =>
                            {
                                assert!(matches!(secondary, StoreError::Closed));
                                Some(primary.as_ref())
                            }
                            _ => None,
                        }
                        .expect("unexpected typed seal result");
                        assert_eq!(
                            primary.error_code(),
                            if cancelled || closed {
                                ErrorCode::Cancelled
                            } else {
                                ErrorCode::CapabilityUnavailable
                            }
                        );
                        assert_eq!(
                            observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                            0
                        );
                    }));
                    let (send, receive) = std::sync::mpsc::sync_channel(1);
                    send.send(answer).expect("handoff the actual answer once");
                    runtime.index_runs.answers = Some(receive);
                    runtime.deferred_index_id = Some(Value::from("owned-pump-answer"));
                    let wire = match pump {
                        0 => runtime.pump_index(),
                        1 => runtime.pump_index_owed(),
                        2 => runtime.pump_index_blocking(),
                        _ => unreachable!("three public adapters"),
                    }
                    .expect("the accepted request is owed one response");
                    let wire: Value = serde_json::from_str(&wire)?;
                    assert_eq!(wire["id"], "owned-pump-answer");
                    assert_eq!(
                        wire["error"]["data"]["code"],
                        if closed {
                            "storage_unavailable"
                        } else if cancelled {
                            "cancelled"
                        } else {
                            "capability_unavailable"
                        }
                    );
                    assert_eq!(observations.load(std::sync::atomic::Ordering::SeqCst), 1);
                    assert!(runtime.index_generation.is_none());
                    assert!(runtime.index_run_task.is_none());
                    assert!(!runtime.index_run_outstanding());
                    assert!(runtime.pump_index_owed().is_none());
                    assert_eq!(observations.load(std::sync::atomic::Ordering::SeqCst), 1);
                }
            }
        }
        for cancelled in [false, true] {
            for closed in [false, true] {
                let (_root, mut runtime, session, task) = owned_index_runtime()?;
                let cancel_session = session.clone();
                runtime.index_seal_control.callback = Some(Box::new(move |store, task| {
                    let task = task.expect("the actual request pins its task");
                    if cancelled {
                        let revision = store
                            .snapshot(task)
                            .expect("read current intent")
                            .intent_revision;
                        store
                            .cancel_task(&cancel_session, task, revision, None)
                            .expect("cancel the real task");
                    }
                    if closed {
                        store
                            .close()
                            .expect("close the actual owner store before seal");
                    }
                }));
                let observations = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
                let observed = std::sync::Arc::clone(&observations);
                runtime.index_answer_observer.callback = Some(Box::new(move |(id, result)| {
                    assert_eq!(id, "owned-sync-answer");
                    let error = result.as_ref().expect_err("actual helper failure");
                    assert_original_eacces(error);
                    let primary = match error {
                        super::ProjectIndexError::Context(primary) if !closed => Some(primary),
                        super::ProjectIndexError::SealFailed { primary, secondary } if closed => {
                            assert!(matches!(secondary, StoreError::Closed));
                            Some(primary.as_ref())
                        }
                        _ => None,
                    }
                    .expect("unexpected typed synchronous result");
                    assert_eq!(
                        primary.error_code(),
                        if cancelled || closed {
                            ErrorCode::Cancelled
                        } else {
                            ErrorCode::CapabilityUnavailable
                        }
                    );
                    assert_eq!(
                        observed.fetch_add(1, std::sync::atomic::Ordering::SeqCst),
                        0
                    );
                }));
                let request = serde_json::json!({
                    "jsonrpc": "2.0", "id": "owned-sync-answer", "method": "command.execute",
                    "params": { "schema_version": 1, "session_id": session.0,
                        "command": { "kind": "project.init", "task_id": task.0 } }
                });
                let wire = super::dispatch_runtime_request(
                    &mut runtime,
                    super::Ingress::Machine,
                    "owned-sync",
                    &request.to_string(),
                );
                let wire: Value = serde_json::from_str(&wire)?;
                assert_eq!(wire["id"], "owned-sync-answer");
                assert_eq!(
                    wire["error"]["data"]["code"],
                    if closed {
                        "storage_unavailable"
                    } else if cancelled {
                        "cancelled"
                    } else {
                        "capability_unavailable"
                    }
                );
                assert_eq!(observations.load(std::sync::atomic::Ordering::SeqCst), 1);
                assert!(runtime.index_seal_control.callback.is_none());
                assert!(runtime.index_generation.is_none());
                assert!(!runtime.index_run_outstanding());
            }
        }
        Ok(())
    }

    #[test]
    fn owned_launch_index_seal_keeps_primary_and_store_failure() -> TestResult {
        let (_root, mut runtime, _session, _task, answer) = owned_index_failure()?;
        let generation = runtime
            .index_generation
            .take()
            .expect("reserved generation");
        runtime.owner.store.close()?;
        let error = runtime
            .seal_index_run(generation, answer.outcome)
            .expect_err("closed store");
        assert_eq!(error.code(), ErrorCode::StorageUnavailable);
        assert_original_eacces(&error);
        assert!(matches!(
            error,
            super::ProjectIndexError::SealFailed {
                secondary: StoreError::Closed,
                ..
            }
        ));
        Ok(())
    }

    const BASE_CONFIG: &str = "config_version = 1\n\
         [connections.primary]\n\
         kind = \"api_key\"\n\
         endpoint = \"https://api.openai.com/v1\"\n\
         credential_ref = \"keyring:primary\"\n\
         [models.defaults]\n\
         model = { mode = \"auto\" }\n\
         effort = { mode = \"auto\" }\n\
         fallback = { mode = \"auto\" }\n";

    fn wire_code(err: &config::PublicationError) -> Option<ErrorCode> {
        publication_error(Value::from(1), err)
            .error
            .map(|error| error.data.code)
    }

    #[test]
    fn publication_error_maps_each_variant_to_its_own_wire_code() {
        assert_eq!(
            wire_code(&config::PublicationError::TargetAbsent(
                "/data/config.toml".to_string()
            )),
            Some(ErrorCode::NotFound),
            "an absent publication target is not_found, not a generic fault"
        );
        assert_eq!(
            wire_code(&config::PublicationError::TargetNotUtf8),
            Some(ErrorCode::InvalidInput)
        );
        assert_eq!(
            wire_code(&config::PublicationError::Target(std::io::Error::other(
                "permission denied"
            ))),
            Some(ErrorCode::StorageUnavailable)
        );
        assert_eq!(
            wire_code(&config::PublicationError::IdentityMissing),
            Some(ErrorCode::InternalError)
        );
        assert_eq!(
            wire_code(&config::PublicationError::Write(
                WorkerError::SandboxSpawnFailed {
                    source: std::io::Error::other("spawn failed")
                }
            )),
            Some(ErrorCode::CapabilityUnavailable),
            "a sandbox that cannot start is a capability failure, not internal"
        );
        assert_eq!(
            wire_code(&config::PublicationError::Write(WorkerError::WriteFailed {
                source: std::io::Error::other("denied")
            })),
            Some(ErrorCode::Denied),
            "a denied managed write surfaces the executor's denied code"
        );
        assert_eq!(
            wire_code(&config::PublicationError::Write(
                WorkerError::WriteMutationFailed {
                    source: std::io::Error::other("mutated then lost")
                }
            )),
            Some(ErrorCode::OutcomeUnknown),
            "a post-mutation write failure reports the unknown outcome"
        );
    }

    #[test]
    fn publication_journal_error_keeps_the_store_code_and_recovery_text() {
        let response = publication_error(
            Value::from(1),
            &config::PublicationError::Journal(StoreError::Storage(
                std::io::Error::other("disk full").into(),
            )),
        );
        let Some(error) = response.error else {
            unreachable!("journal arm must answer an error: {response:?}");
        };
        assert_eq!(error.data.code, ErrorCode::StorageUnavailable);
        assert!(
            error
                .data
                .message
                .contains("retry after checking local storage"),
            "the journal arm keeps the store recovery text: {error:?}"
        );
    }

    fn recovery(verdict: config::PublicationVerdict, target: &str) -> config::PublicationRecovery {
        config::PublicationRecovery {
            intent: config::PublicationIntent {
                owner: "cli".to_string(),
                target: target.to_string(),
                admission_seq: 1,
                intended_digest: "digest".to_string(),
                base_digest: None,
                publish_identity: None,
            },
            verdict,
        }
    }

    #[test]
    fn recovery_diagnostic_names_verdict_and_target_only_when_unhealed() {
        for (verdict, token) in [
            (config::PublicationVerdict::Old, "old"),
            (
                config::PublicationVerdict::ByteIdenticalThird,
                "byte_identical_third",
            ),
            (config::PublicationVerdict::Conflicting, "conflicting"),
            (
                config::PublicationVerdict::TornOrUnparseable,
                "torn_or_unparseable",
            ),
            (config::PublicationVerdict::Absent, "absent"),
            (config::PublicationVerdict::Unknown, "unknown"),
        ] {
            let line = recovery_diagnostic(&recovery(verdict, "/data/config.toml"));
            let Some(text) = line else {
                unreachable!("{verdict:?} must surface a diagnostic");
            };
            assert!(
                text.contains(token),
                "{verdict:?} diagnostic names the verdict: {text}"
            );
            assert!(
                text.contains("/data/config.toml"),
                "{verdict:?} diagnostic names the target: {text}"
            );
            assert!(
                text.contains("resolution:"),
                "{verdict:?} diagnostic names the resolution: {text}"
            );
        }
        assert_eq!(
            recovery_diagnostic(&recovery(
                config::PublicationVerdict::ExactlyNew,
                "/data/config.toml"
            )),
            None,
            "the healed receipted verdict stays silent"
        );
    }

    #[test]
    fn recovery_diagnostic_sanitizes_the_target() {
        let line = recovery_diagnostic(&recovery(
            config::PublicationVerdict::Conflicting,
            "/data/evil\u{7}\u{1b}[2J\n.toml",
        ));
        let Some(text) = line else {
            unreachable!("an unhealed verdict must surface a diagnostic");
        };
        for ch in text.chars() {
            assert!(
                !ch.is_control(),
                "no control character reaches the diagnostic: {text:?}"
            );
        }
        assert!(
            text.contains("^G"),
            "the bell survives as visible, inert data: {text}"
        );
        assert!(
            text.contains('␤'),
            "a newline in the target survives as one inert glyph — the diagnostic stays one line: {text}"
        );
    }

    #[test]
    fn recovery_diagnostics_compose_over_a_seeded_journal() -> TestResult {
        let root = tempfile::TempDir::with_prefix("rivect-recovery-diag-")?;
        let target = root.path().join("config.toml");
        std::fs::write(&target, BASE_CONFIG)?;
        let mut store = TaskStore::open(&root.path().join("state.db"))?;
        let mut parsed = config::Config::parse_validated(BASE_CONFIG)?;
        let edit = parsed.set("workflow.enabled", ConfigValue::Bool(false))?;
        config::stage_publication(&mut store, "cli", &target, &edit)?;

        // The crash window before the write: base bytes still hold, the
        // verdict is Old and surfaces exactly one diagnostic line.
        let lines: Vec<String> = config::recover_publications(&mut store)?
            .iter()
            .filter_map(recovery_diagnostic)
            .collect();
        assert_eq!(lines.len(), 1, "one unresolved verdict, one line");
        assert!(lines[0].contains("old"));
        assert!(lines[0].contains(&*target.to_string_lossy()));

        // The healed crash window — intended bytes under the staged
        // inode — receipts and emits nothing.
        std::fs::write(&target, &edit.bytes)?;
        let silent: Vec<String> = config::recover_publications(&mut store)?
            .iter()
            .filter_map(recovery_diagnostic)
            .collect();
        assert!(
            silent.is_empty(),
            "the receipted verdict emits no diagnostic: {silent:?}"
        );

        Ok(())
    }

    /// A read worker that never reads: the recovery reconcile touches no
    /// file content, so the runtime opens over the refusing worker.
    struct RecoveryNoWorker;

    impl crate::executor::ReadWorker for RecoveryNoWorker {
        fn read_once(
            &mut self,
            _scope_root: &std::path::Path,
            _target: &std::path::Path,
        ) -> Result<crate::executor::ReadObservation, WorkerError> {
            Err(WorkerError::SandboxUnavailable {
                reason: "the recovery tests never read".to_string(),
            })
        }
    }

    /// One real claimed check attempt on the store at `data_root`: an
    /// admitted Exec effect claimed through the production claim call,
    /// so the marker, the running state, and (when armed) the ambiguous
    /// COMMIT row are exactly the durable shapes the reconcile reads.
    fn claimed_check_attempt(
        data_root: &std::path::Path,
        tag: &str,
    ) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let mut owner = crate::owner::Owner::elect(data_root)?;
        let store = &mut owner.store;
        let (session, _, _, _) = store.open_session(&format!("session-{tag}"), "conn", None)?;
        let task = store
            .create_task(
                &session,
                &format!("command-{tag}"),
                "unit",
                "recovery goal",
                (&[], &[]),
            )?
            .task_id;
        store.record_plan_selection(
            &session,
            &task,
            &crate::state::PlanSelectionWrite {
                facts_digest: "recovery-facts",
                request_kind: crate::state::RequestKind::PlanOnly,
                rows: &[],
            },
        )?;
        let mut policy = crate::policy::Policy::default();
        let cargo = std::path::PathBuf::from("/nonexistent/cargo");
        let exec_grant = policy.grant_classes(
            cargo.parent().expect("toolchain dir").to_path_buf(),
            vec![crate::contracts::EffectClass::Exec],
        );
        let project_grant_id = policy.grant_read(std::path::PathBuf::from("/nonexistent/project"));
        let check = crate::executor::ConfinedCheck {
            task_id: task.clone(),
            expected_selection_revision: 1,
            project_grant_id,
            project_root: std::path::PathBuf::from("/nonexistent/project"),
            manifest_rel: std::path::PathBuf::from("Cargo.toml"),
            cargo: cargo.clone(),
            cargo_home: std::path::PathBuf::from("/nonexistent/home"),
            target: crate::executor::CheckTarget::Integration("check".to_string()),
            harness_threads: 1,
            exact_test: "green_passes".to_string(),
            expected_phase: "candidate-review".to_string(),
            expected_assertion_identity: "green_passes".to_string(),
            expected_candidate_digest: "digest".to_string(),
        };
        let owner_state = std::sync::Arc::new(crate::executor::WorkflowOffState::new(
            &config::resolve_effective(None)?,
        ));
        let handoff = crate::executor::CheckHandoff::from_owner(
            &owner_state,
            &task,
            std::sync::Arc::clone(policy.identity()),
            std::sync::Arc::clone(store.identity()),
        );
        let attempt_id = {
            let mut worker = RecoveryNoWorker;
            let mut executor = crate::executor::Executor::new(&mut policy, store, &mut worker);
            let admission = executor.admit_check(
                &task,
                crate::executor::EffectRequest::Exec {
                    grant_id: exec_grant,
                    program: cargo,
                },
                crate::policy::PermissionMode::Yolo,
                &check,
                &handoff,
            )?;
            let claim = admission.claim_binding();
            let outcome = store.claim_check(
                &claim,
                &std::sync::atomic::AtomicBool::new(false),
                std::time::Instant::now() + std::time::Duration::from_secs(300),
            )?;
            assert!(
                matches!(
                    outcome,
                    crate::state::ClaimOutcome::Claimed
                        | crate::state::ClaimOutcome::Refused(crate::state::ClaimRefusal {
                            site: crate::state::ClaimSite::Commit,
                            ..
                        })
                ),
                "the fixture claim must either commit or refuse at the COMMIT site"
            );
            admission.attempt_id().to_string()
        };
        Ok(attempt_id)
    }

    /// One settled-row fixture: the durable row a journey disposition
    /// (SLICE-024) or a pre-return provider finalisation leaves behind.
    fn retained_check_row(
        attempt_id: &str,
        site: &str,
        cause: &str,
    ) -> crate::verification::RetainedAttempt {
        crate::verification::RetainedAttempt {
            attempt_id: attempt_id.to_string(),
            boundary_id: crate::state::check_boundary(attempt_id, site),
            stage: crate::verification::RetainedStage::Terminal,
            cause: cause.to_string(),
            digest: crate::verification::record_digest(attempt_id, cause),
            build_attempt: attempt_id.to_string(),
            admitted_attempt_id: Some(attempt_id.to_string()),
        }
    }

    /// Leaves what a sealed check leaves in a recorded root: a nested
    /// read-only tree.
    fn populate_sealed(root: &std::path::Path) -> TestResult {
        use std::os::unix::fs::PermissionsExt as _;
        let nested = root.join("src/deep");
        std::fs::create_dir_all(&nested)?;
        std::fs::write(nested.join("sealed.txt"), b"sealed")?;
        for sealed in [nested, root.join("src")] {
            std::fs::set_permissions(&sealed, std::fs::Permissions::from_mode(0o555))?;
        }
        Ok(())
    }

    /// The root still holds its sealed debris byte-for-byte: a refused
    /// cleanup removed nothing, unsealed nothing, and kept the name in
    /// place (DEC-056 strict protection).
    fn preserves_sealed_debris(root: &std::path::Path) -> bool {
        std::fs::read(root.join("src/deep/sealed.txt")).is_ok_and(|bytes| bytes == b"sealed")
    }

    /// Unseals and removes a fixture root the product deliberately
    /// cannot clean.
    fn drop_sealed_root(root: &std::path::Path) {
        use std::os::unix::fs::PermissionsExt as _;
        for dir in [root.join("src/deep"), root.join("src")] {
            drop(std::fs::set_permissions(
                &dir,
                std::fs::Permissions::from_mode(0o700),
            ));
        }
        drop(std::fs::remove_dir_all(root));
    }

    #[test]
    fn runtime_recovery_settles_each_crash_window_once_without_replay() -> TestResult {
        let data_root = tempfile::TempDir::with_prefix("rivect-recovery-reconcile-")?;

        // Window 1 — journey disposition: transport success, the
        // disposition row is durable, the crash precedes cleanup.
        let journey = claimed_check_attempt(data_root.path(), "journey")?;
        // Window 2 — pre-return finalisation: the transport row and the
        // ledger rejection are durable, the crash precedes root removal.
        let finalised = claimed_check_attempt(data_root.path(), "finalised")?;
        let finalised_root = crate::executor::attempt_root_of(&finalised);
        // Window 3 — recovery row: the dispatch crashed with no record.
        let unresolved = claimed_check_attempt(data_root.path(), "unresolved")?;
        // Finalized COMMIT failure with a residual R marker: the claim
        // committed durably, then reported failure — marker AND
        // `admit.claim_commit` row both survive.
        crate::state::proof::arm_fault(crate::state::proof::Site::CommitAfterDurable);
        let durable_commit = claimed_check_attempt(data_root.path(), "durable-commit")?;
        // Residual claim_commit row WITHOUT the marker: the transaction
        // rolled back, the ambiguous row alone survives — the attempt
        // never claimed, so the reconcile never sees it.
        crate::state::proof::arm_fault(crate::state::proof::Site::CommitBeforeExec);
        let rolled_back = claimed_check_attempt(data_root.path(), "rolled-back")?;
        // Forged cleanup: a symlink squatting on an unresolved
        // attempt's own root name must be refused, never deleted.
        let squatted = claimed_check_attempt(data_root.path(), "squatted")?;
        let sentinel = data_root.path().join("sentinel-dir");
        std::fs::create_dir_all(&sentinel)?;
        std::fs::write(sentinel.join("kept"), b"sentinel")?;
        std::os::unix::fs::symlink(&sentinel, crate::executor::attempt_root_of(&squatted))?;

        let journey_row = retained_check_row(
            &journey,
            "close.phase_closed",
            "expected phase observed: red failed",
        );
        let finalised_row = retained_check_row(
            &finalised,
            "vendor.spawn",
            "the confined vendor phase refused to spawn",
        );
        let mut owner = crate::owner::Owner::elect(data_root.path())?;
        {
            let store = &mut owner.store;
            store.retain_attempt(&journey_row)?;
            store.retain_attempt(&finalised_row)?;
            store.attempt_rejected(&finalised, "the confined vendor phase refused to spawn")?;
            // The surviving roots are real allocations: created
            // exclusively and durably recorded through the production
            // owner, exactly as a crashed dispatch leaves them.
            for attempt_id in [&journey, &finalised, &unresolved] {
                let allocated = crate::executor::create_recorded_attempt_root(store, attempt_id)?;
                populate_sealed(&allocated.canonical_root)?;
            }
        }
        drop(owner);

        let boundary = |attempt: &str, site: &str| crate::state::check_boundary(attempt, site);
        let open_runtime = || {
            super::Runtime::open_with_worker(
                data_root.path(),
                Box::new(crate::providers::LoopbackProvider::new()),
                Box::new(RecoveryNoWorker),
            )
        };
        let runtime = open_runtime()?;
        {
            let store = &runtime.owner.store;
            // Window 1: cleanup-resume only — the disposition row is
            // byte-identical, no recovery row, and the present root is
            // refused with its debris intact (DEC-056).
            assert_eq!(
                store.retained(&boundary(&journey, "close.phase_closed"))?,
                Some(serde_json::to_string(&journey_row)?),
                "the journey disposition row is preserved byte-for-byte"
            );
            assert!(
                !store.has_retained(&boundary(&journey, "close.unrecovered"))?,
                "a settled disposition never gains close.unrecovered"
            );
            assert!(
                preserves_sealed_debris(&crate::executor::attempt_root_of(&journey)),
                "cleanup-resume refused over the journey window's root"
            );
            assert!(
                !store.has_retained(&boundary(&journey, "cleanup.root"))?,
                "the refused cleanup retired no authority"
            );
            // Window 2: the finalised failure keeps its own row and
            // state, gains no recovery row, and its root is refused the
            // same way.
            assert_eq!(
                store.retained(&boundary(&finalised, "vendor.spawn"))?,
                Some(serde_json::to_string(&finalised_row)?),
                "the finalised transport row is preserved byte-for-byte"
            );
            assert!(
                !store.has_retained(&boundary(&finalised, "close.unrecovered"))?,
                "a finalised pre-return failure is cleanup-resume only"
            );
            assert!(
                preserves_sealed_debris(&finalised_root),
                "cleanup-resume refused over the finalised window's root"
            );
            assert!(
                !store.has_retained(&boundary(&finalised, "cleanup.root"))?,
                "the refused cleanup retired no authority"
            );
            // Window 3: settlement wrote exactly one recovery row, kept
            // the marker, fabricated no COMMIT row, and refused the
            // present root.
            let settled = store.retained(&boundary(&unresolved, "close.unrecovered"))?;
            let Some(settled_json) = settled else {
                unreachable!("an unrecorded interruption must settle on open");
            };
            assert!(
                settled_json.contains("close.unrecovered"),
                "the settlement row names its site: {settled_json}"
            );
            assert!(
                !store.has_retained(&boundary(&unresolved, "admit.claim_commit"))?,
                "recovery never fabricates admit.claim_commit from an absent row"
            );
            assert!(
                store.has_retained(&boundary(&unresolved, "admit.claim"))?,
                "the first-only marker survives settlement"
            );
            assert!(
                preserves_sealed_debris(&crate::executor::attempt_root_of(&unresolved)),
                "settlement refused over the unresolved window's root"
            );
            assert!(
                !store.has_retained(&boundary(&unresolved, "cleanup.root"))?,
                "the refused cleanup retired no authority"
            );
            // Finalized COMMIT failure: the residual marker makes the
            // attempt visible, the claim_commit row makes it settled —
            // cleanup-resume only, both rows byte-identical.
            let commit_json = store.retained(&boundary(&durable_commit, "admit.claim_commit"))?;
            assert!(
                commit_json.is_some(),
                "the durable-then-error COMMIT row is the fixture's own"
            );
            assert!(
                !store.has_retained(&boundary(&durable_commit, "close.unrecovered"))?,
                "a finalized COMMIT failure is never relabelled unresolved"
            );
            assert!(
                store.has_retained(&boundary(&durable_commit, "admit.claim"))?,
                "the residual R marker survived the reopen"
            );
            // Rolled-back claim: no marker, so the reconcile never saw
            // the attempt — no settlement over its ambiguous row.
            assert!(
                !store.has_retained(&boundary(&rolled_back, "admit.claim"))?,
                "the rolled-back claim left no marker"
            );
            assert!(
                !store.has_retained(&boundary(&rolled_back, "close.unrecovered"))?,
                "an unclaimed attempt is invisible to the reconcile"
            );
            assert!(
                store.has_retained(&boundary(&rolled_back, "admit.claim_commit"))?,
                "the ambiguous COMMIT row stays untouched"
            );
            // Forged cleanup: settlement row written, the symlink and
            // its target survive untouched.
            assert!(
                store.has_retained(&boundary(&squatted, "close.unrecovered"))?,
                "the squatted attempt still settles"
            );
            assert!(
                crate::executor::attempt_root_of(&squatted)
                    .symlink_metadata()
                    .is_ok_and(|meta| meta.file_type().is_symlink()),
                "a symlink at the root name is refused, never deleted"
            );
            assert_eq!(
                std::fs::read(sentinel.join("kept"))?,
                b"sentinel",
                "the symlink's target is untouched"
            );
        }
        drop(runtime);

        // Restart idempotency: a second open settles nothing again —
        // every prior row stays byte-identical, no cleanup.root row
        // appears, and the refused debris stays put.
        let runtime = open_runtime()?;
        {
            let store = &runtime.owner.store;
            assert_eq!(
                store.retained(&boundary(&unresolved, "close.unrecovered"))?,
                Some(serde_json::to_string(&retained_check_row(
                    &unresolved,
                    "close.unrecovered",
                    "unrecorded interruption: the dispatch ended without a journey disposition or a finalized provider failure",
                ))?),
                "the second open leaves the settlement row byte-identical"
            );
            for (attempt, site) in [
                (&journey, "close.phase_closed"),
                (&finalised, "vendor.spawn"),
                (&durable_commit, "admit.claim_commit"),
                (&rolled_back, "admit.claim_commit"),
            ] {
                assert!(
                    store.has_retained(&boundary(attempt, site))?,
                    "no durable row disappeared on restart"
                );
            }
            for attempt in [&journey, &unresolved] {
                assert!(
                    !store.has_retained(&boundary(attempt, "cleanup.root"))?,
                    "the still-refused cleanup keeps retiring nothing"
                );
            }
            assert!(
                preserves_sealed_debris(&crate::executor::attempt_root_of(&journey))
                    && preserves_sealed_debris(&crate::executor::attempt_root_of(&unresolved))
                    && preserves_sealed_debris(&finalised_root),
                "the refused debris survives the restart untouched"
            );
        }
        drop(runtime);
        for attempt in [&journey, &finalised, &unresolved] {
            drop_sealed_root(&crate::executor::attempt_root_of(attempt));
        }
        drop(std::fs::remove_file(crate::executor::attempt_root_of(
            &squatted,
        )));

        Ok(())
    }

    #[test]
    fn recovery_cleans_the_recorded_locator_never_a_recomputed_temp_path() -> TestResult {
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::MetadataExt as _;
        let data_root = tempfile::TempDir::with_prefix("rivect-recovery-locator-")?;
        let attempt = claimed_check_attempt(data_root.path(), "locator")?;
        // TMPDIR A: a root whose name carries both locator delimiters and
        // a non-UTF-8 byte, recorded the way the allocation records it.
        let recorded = data_root
            .path()
            .canonicalize()?
            .join(std::ffi::OsStr::from_bytes(
                b"tmp-a \xff dev=7 ino=9 root-hex=",
            ));
        std::fs::create_dir(&recorded)?;
        std::fs::write(recorded.join("debris"), b"attempt bytes")?;
        let metadata = std::fs::metadata(&recorded)?;
        let root = crate::executor::AttemptRoot {
            attempt_id: attempt.clone(),
            canonical_root: recorded.clone(),
            dev: metadata.dev(),
            ino: metadata.ino(),
        };
        let cause = crate::executor::attempt_root_record_cause(&root);
        assert_eq!(
            crate::executor::parse_attempt_root_cause(&cause),
            Some((recorded.clone(), metadata.dev(), metadata.ino())),
            "the locator round-trips losslessly through its durable spelling"
        );
        // TMPDIR B: the recomputed name holds a foreign sentinel the
        // recovery must never touch.
        let foreign = crate::executor::attempt_root_of(&attempt);
        std::fs::create_dir_all(&foreign)?;
        std::fs::write(foreign.join("sentinel"), b"foreign bytes")?;
        let mut owner = crate::owner::Owner::elect(data_root.path())?;
        owner
            .store
            .retain_attempt(&retained_check_row(&attempt, "attempt.root", &cause))?;
        drop(owner);
        let runtime = super::Runtime::open_with_worker(
            data_root.path(),
            Box::new(crate::providers::LoopbackProvider::new()),
            Box::new(RecoveryNoWorker),
        )?;
        assert_eq!(
            std::fs::read(recorded.join("debris"))?,
            b"attempt bytes",
            "the recorded locator's debris survives the refusal byte-for-byte"
        );
        assert!(
            !runtime
                .owner
                .store
                .has_retained(&crate::state::check_boundary(&attempt, "cleanup.root"))?,
            "the refused cleanup retired no authority"
        );
        assert_eq!(
            std::fs::read(foreign.join("sentinel"))?,
            b"foreign bytes",
            "the recomputed temp-path directory is never touched"
        );
        drop(runtime);
        drop(std::fs::remove_dir_all(&foreign));

        Ok(())
    }

    #[test]
    fn runtime_recovery_settlement_reads_durable_rows_not_the_state_string() -> TestResult {
        let data_root = tempfile::TempDir::with_prefix("rivect-recovery-predicate-")?;

        // A finalised pre-return provider failure whose ledger rejection
        // never landed (the crash window between the terminal transport
        // row and `attempt_rejected`): the durable row is the
        // finalisation — settlement must not relabel it unresolved.
        let transport_only = claimed_check_attempt(data_root.path(), "transport-only")?;
        let transport_row = retained_check_row(
            &transport_only,
            "vendor.spawn",
            "the confined vendor phase refused to spawn",
        );
        // A claimed attempt whose volatile state moved with NO durable
        // final row: the state string is not a disposition, so the
        // unrecorded interruption still settles.
        let non_running = claimed_check_attempt(data_root.path(), "non-running")?;
        {
            let mut owner = crate::owner::Owner::elect(data_root.path())?;
            owner.store.retain_attempt(&transport_row)?;
            owner.store.set_attempt_state(
                &non_running,
                "unknown",
                Some("an unrelated volatile writer"),
            )?;
        }

        let runtime = super::Runtime::open_with_worker(
            data_root.path(),
            Box::new(crate::providers::LoopbackProvider::new()),
            Box::new(RecoveryNoWorker),
        )?;
        {
            let store = &runtime.owner.store;
            assert!(
                !store.has_retained(&crate::state::check_boundary(
                    &transport_only,
                    "close.unrecovered"
                ))?,
                "a durable transport failure row finalises even without the ledger rejection"
            );
            assert!(
                store.has_retained(&crate::state::check_boundary(
                    &non_running,
                    "close.unrecovered"
                ))?,
                "a volatile non-running state with no durable row still settles"
            );
        }
        drop(runtime);

        Ok(())
    }

    #[test]
    fn recovery_separates_a_failed_close_transport_from_a_successful_close_observation()
    -> TestResult {
        let data_root = tempfile::TempDir::with_prefix("rivect-recovery-close-")?;
        // A finalized `close.selection` FAILURE: the fixed structured
        // marker (never prose) keeps it a finalised provider failure.
        let failed = claimed_check_attempt(data_root.path(), "close-failed")?;
        let failed_row = retained_check_row(
            &failed,
            "close.selection",
            &format!(
                "{}: close.selection: the task selection is not the check's pinned revision 1 at close",
                crate::executor::FAILED_CLOSE_TRANSPORT
            ),
        );
        // A SUCCESSFUL transport: the three close rows without the
        // marker are an observation of a returned CheckRun, not a
        // failure — with no journey disposition it stays unresolved.
        let observed = claimed_check_attempt(data_root.path(), "close-observed")?;
        {
            let mut owner = crate::owner::Owner::elect(data_root.path())?;
            owner.store.retain_attempt(&failed_row)?;
            for site in crate::executor::SUCCESS_CLOSE_SITES {
                owner.store.retain_attempt(&retained_check_row(
                    &observed,
                    site,
                    "the observation of a returned run",
                ))?;
            }
        }
        let runtime = super::Runtime::open_with_worker(
            data_root.path(),
            Box::new(crate::providers::LoopbackProvider::new()),
            Box::new(RecoveryNoWorker),
        )?;
        {
            let store = &runtime.owner.store;
            assert_eq!(
                store.retained(&crate::state::check_boundary(&failed, "close.selection"))?,
                Some(serde_json::to_string(&failed_row)?),
                "the original terminal failure survives the reopen byte for byte"
            );
            assert!(
                !store.has_retained(&crate::state::check_boundary(&failed, "close.unrecovered"))?,
                "a finalized close failure is never relabelled unresolved"
            );
            assert!(
                store.has_retained(&crate::state::check_boundary(
                    &observed,
                    "close.unrecovered"
                ))?,
                "a successful close observation without a disposition stays unresolved"
            );
        }
        drop(runtime);

        Ok(())
    }

    /// The validated base config the off-ingress test appends its
    /// `[workflow]` override to.
    const OFF_INGRESS_BASE: &str = "config_version = 1\n\
         [connections.primary]\n\
         kind = \"api_key\"\n\
         endpoint = \"https://api.openai.com/v1\"\n\
         credential_ref = \"keyring:primary\"\n\
         [models.defaults]\n\
         model = { mode = \"auto\" }\n\
         effort = { mode = \"auto\" }\n\
         fallback = { mode = \"auto\" }\n";

    #[test]
    fn config_ingress_refreshes_the_off_owner_and_stale_authority_refuses() -> TestResult {
        crate::executor::test_helper::ensure_helper();
        let data_root = tempfile::TempDir::with_prefix("rivect-off-refresh-")?;
        // Boot over a real explicit user workflow-off config.
        std::fs::write(
            data_root.path().join("config.toml"),
            format!("{OFF_INGRESS_BASE}[workflow]\nenabled = false\n"),
        )?;
        let mut runtime = super::Runtime::open_with_worker(
            data_root.path(),
            Box::new(crate::providers::LoopbackProvider::new()),
            Box::new(RecoveryNoWorker),
        )?;

        // A Custom admission over this runtime's own pair.
        let (session, _, _, _) = runtime
            .owner
            .store
            .open_session("off-refresh", "conn", None)?;
        let task = runtime
            .owner
            .store
            .create_task(
                &session,
                "off-refresh-command",
                "unit",
                "custom off goal",
                (&[], &[]),
            )?
            .task_id;
        let handoff = runtime.check_handoff(&task);
        assert!(
            handoff.explicit_off(),
            "the explicit user workflow-off boots as the owner's mode"
        );
        let cargo = std::env::current_exe()?.canonicalize()?;
        std::fs::create_dir_all(data_root.path().join("home/registry/cache"))?;
        std::fs::create_dir_all(data_root.path().join("home/registry/index"))?;
        let exec_grant = runtime.policy.grant_classes(
            cargo
                .parent()
                .ok_or("the toolchain dir is unnamed")?
                .to_path_buf(),
            vec![crate::contracts::EffectClass::Exec],
        );
        let project_grant_id = runtime.policy.grant_read(data_root.path().to_path_buf());
        let check = crate::executor::ConfinedCheck {
            task_id: task.clone(),
            expected_selection_revision: 1,
            project_grant_id,
            project_root: data_root.path().to_path_buf(),
            manifest_rel: std::path::PathBuf::from("Cargo.toml"),
            cargo: cargo.clone(),
            cargo_home: data_root.path().join("home"),
            target: crate::executor::CheckTarget::Integration("check".to_string()),
            harness_threads: 1,
            exact_test: "green_passes".to_string(),
            expected_phase: "candidate-review".to_string(),
            expected_assertion_identity: "green_passes".to_string(),
            expected_candidate_digest: "digest".to_string(),
        };
        let mut admission = {
            let mut worker = RecoveryNoWorker;
            let mut executor = crate::executor::Executor::new(
                &mut runtime.policy,
                &mut runtime.owner.store,
                &mut worker,
            );
            executor.admit_check(
                &task,
                crate::executor::EffectRequest::Exec {
                    grant_id: exec_grant.clone(),
                    program: cargo.clone(),
                },
                crate::policy::PermissionMode::Yolo,
                &check,
                &handoff,
            )?
        };
        // A second admission minted over the same boot-time owner
        // context and never presented until the identical-off return.
        let mut bystander = {
            let mut worker = RecoveryNoWorker;
            let mut executor = crate::executor::Executor::new(
                &mut runtime.policy,
                &mut runtime.owner.store,
                &mut worker,
            );
            executor.admit_check(
                &task,
                crate::executor::EffectRequest::Exec {
                    grant_id: exec_grant.clone(),
                    program: cargo.clone(),
                },
                crate::policy::PermissionMode::Yolo,
                &check,
                &handoff,
            )?
        };

        // The real config ingress toggles the workflow on: the live
        // owner refreshes, no fresh handoff mints, and the still-pending
        // Custom admission refuses at its off reconsult — the attempt
        // stays planned with no root, claim, byte, or spawn.
        let toggled = super::commit_config_edit(
            &mut runtime,
            serde_json::json!(1),
            "config.set",
            "workflow.enabled",
            |config| config.set_wire("workflow.enabled", &serde_json::json!(true)),
        );
        assert!(
            toggled.error.is_none(),
            "the on toggle lands through the real ingress: {:?}",
            toggled.error
        );
        assert!(
            !runtime.check_handoff(&task).explicit_off(),
            "an enabled config binds no explicit off after the refresh"
        );
        {
            let mut worker = RecoveryNoWorker;
            let mut executor = crate::executor::Executor::new(
                &mut runtime.policy,
                &mut runtime.owner.store,
                &mut worker,
            );
            match executor.execute_check(
                &mut admission,
                &check,
                &std::sync::atomic::AtomicBool::new(false),
            ) {
                Err(crate::executor::ExecutorError::Check(
                    crate::executor::CheckError::SelectionMismatch { detail },
                )) => assert!(
                    detail.contains("moved"),
                    "the stale authority refusal names the vanished off context: {detail}"
                ),
                other => unreachable!("the stale off authority must refuse, got {other:?}"),
            }
        }
        assert_eq!(
            runtime
                .owner
                .store
                .attempt_state(admission.bound_attempt_id())?
                .as_deref(),
            Some("planned"),
            "the stale off refusal never claims or settles"
        );
        assert!(
            !crate::executor::attempt_root_of(admission.bound_attempt_id()).exists(),
            "no attempt root exists for the refused presentation"
        );

        // Toggling back off through the same ingress refreshes again: a
        // FRESH handoff mints over the current owner state and a new
        // admission passes the off reconsult (it refuses later, at the
        // pre-claim cancellation).
        let restored = super::commit_config_edit(
            &mut runtime,
            serde_json::json!(2),
            "config.set",
            "workflow.enabled",
            |config| config.set_wire("workflow.enabled", &serde_json::json!(false)),
        );
        assert!(
            restored.error.is_none(),
            "the off toggle lands through the real ingress: {:?}",
            restored.error
        );
        // Returning to identical off bytes never revives a pending
        // admission minted before the toggles: the owner's generation
        // moved twice.
        {
            let mut worker = RecoveryNoWorker;
            let mut executor = crate::executor::Executor::new(
                &mut runtime.policy,
                &mut runtime.owner.store,
                &mut worker,
            );
            match executor.execute_check(
                &mut bystander,
                &check,
                &std::sync::atomic::AtomicBool::new(false),
            ) {
                Err(crate::executor::ExecutorError::Check(
                    crate::executor::CheckError::SelectionMismatch { detail },
                )) => assert!(
                    detail.contains("moved"),
                    "the pending admission stays dead after an identical-off return: {detail}"
                ),
                other => unreachable!("the revived admission must refuse, got {other:?}"),
            }
        }
        let fresh = runtime.check_handoff(&task);
        assert!(
            fresh.explicit_off(),
            "the refreshed owner binds the explicit off again"
        );
        let mut refreshed = {
            let mut worker = RecoveryNoWorker;
            let mut executor = crate::executor::Executor::new(
                &mut runtime.policy,
                &mut runtime.owner.store,
                &mut worker,
            );
            executor.admit_check(
                &task,
                crate::executor::EffectRequest::Exec {
                    grant_id: exec_grant,
                    program: cargo,
                },
                crate::policy::PermissionMode::Yolo,
                &check,
                &fresh,
            )?
        };
        {
            let mut worker = RecoveryNoWorker;
            let mut executor = crate::executor::Executor::new(
                &mut runtime.policy,
                &mut runtime.owner.store,
                &mut worker,
            );
            match executor.execute_check(
                &mut refreshed,
                &check,
                &std::sync::atomic::AtomicBool::new(true),
            ) {
                Err(crate::executor::ExecutorError::Check(
                    crate::executor::CheckError::VendorCancel { .. },
                )) => {}
                other => {
                    unreachable!("the fresh off context admits past its reconsult, got {other:?}")
                }
            }
        }

        drop(runtime);

        Ok(())
    }

    #[test]
    fn a_failed_receipt_after_landed_bytes_serves_one_coherent_config_and_the_retry_only_receipts()
    -> TestResult {
        crate::executor::test_helper::ensure_helper();
        let data_root = tempfile::TempDir::with_prefix("rivect-failed-receipt-")?;
        std::fs::write(
            data_root.path().join("config.toml"),
            format!("{OFF_INGRESS_BASE}[workflow]\nenabled = false\n"),
        )?;
        let mut runtime = super::Runtime::open_with_worker(
            data_root.path(),
            Box::new(crate::providers::LoopbackProvider::new()),
            Box::new(RecoveryNoWorker),
        )?;
        let (boot_generation, boot_mode, boot_digest) = runtime.off_state.current();
        assert_eq!(
            boot_mode,
            crate::executor::WorkflowOwnerMode::ExplicitOff,
            "the boot config carries the explicit off"
        );
        assert_eq!(boot_digest, runtime.effective().sources_digest);

        // The managed write lands; only the receipt fails (DEC-056
        // item 5): the typed Journal error and the pending row are
        // kept, but every served surface must reflect the ONE config
        // now on disk.
        crate::state::proof::arm_fault(crate::state::proof::Site::PublicationReceipt);
        let failed = super::commit_config_edit(
            &mut runtime,
            serde_json::json!(1),
            "config.set",
            "workflow.enabled",
            |config| config.set_wire("workflow.enabled", &serde_json::json!(true)),
        );
        match failed.error.as_ref() {
            Some(error) => assert_eq!(
                error.data.code,
                ErrorCode::StorageUnavailable,
                "the failed receipt surfaces the journal's typed store code: {error:?}"
            ),
            None => unreachable!("the failed receipt returns its typed error"),
        }
        let landed = std::fs::read_to_string(data_root.path().join("config.toml"))?;
        assert!(
            landed.contains("enabled = true"),
            "the managed write landed the bytes: {landed}"
        );
        let landed_digest = config::sources_digest(landed.as_bytes());
        assert_eq!(
            runtime.effective().sources_digest,
            landed_digest,
            "the digest precondition names the landed bytes, not the refused receipt"
        );
        let (generation, mode, digest) = runtime.off_state.current();
        assert_eq!(
            digest, landed_digest,
            "the owner handoff names the landed bytes"
        );
        assert_eq!(
            mode,
            crate::executor::WorkflowOwnerMode::Enabled,
            "the served workflow mode follows the landed config"
        );
        assert!(
            generation > boot_generation,
            "a landed transition moves the owner generation"
        );
        let pending = runtime.owner.store.pending_publications()?;
        assert_eq!(pending.len(), 1, "the failed receipt keeps its pending row");
        assert_eq!(runtime.owner.store.applied_publications()?.len(), 0);
        let admitted_seq = pending[0].admission_seq;

        // The retry heals the pending row: the bytes already hold, so
        // the singleflight answers from the receipt alone — no second
        // write, no second journal row, the same coherent view.
        let retry = super::commit_config_edit(
            &mut runtime,
            serde_json::json!(2),
            "config.set",
            "workflow.enabled",
            |config| config.set_wire("workflow.enabled", &serde_json::json!(true)),
        );
        assert!(
            retry.error.is_none(),
            "the retry receipts the landed bytes: {:?}",
            retry.error
        );
        assert_eq!(
            runtime.effective().sources_digest,
            landed_digest,
            "the retry changes no served view"
        );
        assert_eq!(runtime.owner.store.pending_publications()?.len(), 0);
        let applied = runtime.owner.store.applied_publications()?;
        assert_eq!(
            applied.len(),
            1,
            "exactly one journal row exists for the edit"
        );
        assert_eq!(
            applied[0].admission_seq, admitted_seq,
            "the retry staged no second row behind the receipt"
        );

        drop(runtime);

        Ok(())
    }

    #[test]
    fn open_refusal_exposes_the_original_config_read_io_error() -> TestResult {
        use crate::owner::OwnerError;
        use std::error::Error as _;
        use std::io::Write as _;
        use std::os::unix::fs::PermissionsExt as _;

        let data_root = tempfile::TempDir::with_prefix("rivect-open-eacces-")?;
        let config = data_root.path().join("config.toml");
        std::fs::write(&config, "[workflow]\n")?;
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o000))?;
        // The independent control: the kernel itself must refuse this open
        // with EACCES, or the fixture is not established.
        let Err(control) = std::fs::File::open(&config) else {
            std::io::stderr().write_all(b"NOT_RUN(open-eacces): root bypasses DAC\n")?;
            return Ok(());
        };
        assert_eq!(
            control.kind(),
            std::io::ErrorKind::PermissionDenied,
            "fixture not established: the control open must be a permission refusal"
        );
        assert_eq!(
            control.raw_os_error(),
            Some(13),
            "fixture not established: the control open must be EACCES"
        );

        let Err(refusal) = super::Runtime::open(
            data_root.path(),
            Box::new(crate::providers::LoopbackProvider::new()),
        ) else {
            return Err("an unreadable config must refuse the open".into());
        };

        let owner_hop = refusal
            .source()
            .ok_or("the open refusal must expose the config read failure through source()")?;
        let Some(OwnerError::ConfigRead { path, .. }) = owner_hop.downcast_ref::<OwnerError>()
        else {
            return Err(format!("the source hop must be ConfigRead, found: {owner_hop}").into());
        };
        assert_eq!(path, &config, "the refusal names the config path");
        let original = owner_hop
            .source()
            .ok_or("the config read failure must keep its original io::Error source")?;
        let Some(io_error) = original.downcast_ref::<std::io::Error>() else {
            return Err(
                format!("the original cause must be an io::Error, found: {original}").into(),
            );
        };
        assert_eq!(io_error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(
            io_error.raw_os_error(),
            Some(13),
            "the original errno survives"
        );
        assert!(
            io_error.get_ref().is_none(),
            "the original is the raw os error"
        );
        assert!(
            original.source().is_none(),
            "the original has no further cause"
        );
        assert_eq!(original.to_string(), control.to_string());
        assert_eq!(
            owner_hop.to_string(),
            format!(
                "owner configuration failed: {}: read failed",
                config.display()
            ),
            "the owner hop names its source once, through source()"
        );
        assert_eq!(refusal.to_string(), "runtime open failed");
        assert!(
            refusal.diagnostics().is_empty(),
            "a refusal before verdict collection carries nothing"
        );
        assert_eq!(
            crate::ui::failure_report(owner_hop).to_string(),
            format!("{owner_hop}: {original}"),
            "the report writes the original failure once"
        );

        match refusal.into_source() {
            OwnerError::ConfigRead { source, .. } => {
                assert_eq!(source.raw_os_error(), Some(13));
            }
            other => return Err(format!("into_source must be ConfigRead, found: {other}").into()),
        }
        Ok(())
    }

    const RELEASE_LINES: [&str; 2] = [
        "database writer lock release failed: other error",
        "owner lock release failed: other error",
    ];

    fn release_lines() -> Vec<String> {
        RELEASE_LINES.iter().map(ToString::to_string).collect()
    }

    fn open_refused(
        root: &tempfile::TempDir,
    ) -> Result<super::OpenError, Box<dyn std::error::Error + Send + Sync>> {
        match super::Runtime::open(
            root.path(),
            Box::new(crate::providers::LoopbackProvider::new()),
        ) {
            Ok(_) => Err("the armed fault must refuse the open".into()),
            Err(refusal) => Ok(refusal),
        }
    }

    #[test]
    fn failed_open_carries_release_faults_after_the_primary_error() -> TestResult {
        use crate::owner::OwnerError;
        use crate::state::{proof, take_release_lines};
        use std::error::Error as _;

        assert_eq!(take_release_lines(), Vec::<String>::new());

        // An invalid config: the primary failure first, then the two lines.
        let root = tempfile::TempDir::with_prefix("rivect-open-release-config-")?;
        let config = root.path().join("config.toml");
        std::fs::write(&config, "[workflow\n")?;
        proof::arm_unlock_faults(2);
        let failure = open_refused(&root)?;
        assert_eq!(failure.to_string(), "runtime open failed");
        assert!(
            failure.diagnostics().ends_with(&release_lines()),
            "the release lines end the diagnostics: {:?}",
            failure.diagnostics()
        );
        let hop = failure
            .source()
            .ok_or("the open failure exposes its cause")?;
        let Some(OwnerError::Config { path, .. }) = hop.downcast_ref::<OwnerError>() else {
            return Err(format!("the cause must be Config, found: {hop}").into());
        };
        assert_eq!(path, &config);
        assert_eq!(
            hop.to_string(),
            format!("owner configuration failed: {}", config.display()),
            "the context never holds its source's text"
        );
        let parse = hop.source().ok_or("the config failure keeps its source")?;
        assert_eq!(
            crate::ui::failure_report(hop).to_string(),
            format!("owner configuration failed: {}: {parse}", config.display()),
            "the original failure is written once and nothing past it"
        );
        assert_eq!(take_release_lines(), Vec::<String>::new());

        // A storage failure inside the election: the same lines, same order.
        let root = tempfile::TempDir::with_prefix("rivect-open-release-store-")?;
        proof::arm_bootstrap_fault();
        proof::arm_unlock_faults(2);
        let failure = open_refused(&root)?;
        assert_eq!(failure.diagnostics(), release_lines());
        assert!(
            matches!(failure.into_source(), OwnerError::Store(_)),
            "the bootstrap fault is the storage failure"
        );
        assert_eq!(take_release_lines(), Vec::<String>::new());

        // A healthy runtime releases through `release`.
        let root = tempfile::TempDir::with_prefix("rivect-open-release-healthy-")?;
        let runtime = super::Runtime::open(
            root.path(),
            Box::new(crate::providers::LoopbackProvider::new()),
        )?;
        proof::arm_unlock_faults(2);
        assert_eq!(runtime.release(), release_lines());
        assert_eq!(take_release_lines(), Vec::<String>::new());
        Ok(())
    }

    #[derive(Debug, thiserror::Error)]
    #[error("staged config fault")]
    struct StagedConfigFault {
        nonce: u64,
    }

    #[test]
    fn injected_config_read_failures_keep_the_original_io_error_through_open() -> TestResult {
        use crate::owner::{OwnerError, proof as owner_proof};
        use crate::state::{proof, take_release_lines};
        use std::error::Error as _;

        type Arm = fn(std::io::Error);
        let arms: [(&str, Arm); 2] = [
            ("metadata", owner_proof::arm_config_metadata_fault),
            ("read", owner_proof::arm_config_read_fault),
        ];
        assert_eq!(take_release_lines(), Vec::<String>::new());
        for (label, arm) in arms {
            // Empty diagnostics: the original errno survives untouched.
            let root = tempfile::TempDir::with_prefix("rivect-open-injected-eio-")?;
            std::fs::write(root.path().join("config.toml"), "[workflow]\n")?;
            arm(std::io::Error::from_raw_os_error(5));
            let refusal = open_refused(&root)?;
            assert!(refusal.diagnostics().is_empty(), "{label}: nothing carried");
            let hop = refusal.source().ok_or("the refusal exposes its cause")?;
            assert!(
                matches!(
                    hop.downcast_ref::<OwnerError>(),
                    Some(OwnerError::ConfigRead { .. })
                ),
                "{label}: the cause is ConfigRead"
            );
            let eio = std::io::Error::from_raw_os_error(5);
            let original = hop
                .source()
                .and_then(|source| source.downcast_ref::<std::io::Error>())
                .ok_or("the read failure keeps its io::Error")?;
            assert_eq!(original.raw_os_error(), Some(5), "{label}");
            assert_eq!(original.kind(), eio.kind(), "{label}");
            assert!(original.get_ref().is_none(), "{label}: no payload added");
            assert_eq!(
                crate::ui::failure_report(hop).to_string(),
                format!("{hop}: {eio}"),
                "{label}"
            );
            assert_eq!(take_release_lines(), Vec::<String>::new());

            // Carried diagnostics: the typed payload survives the chain.
            let root = tempfile::TempDir::with_prefix("rivect-open-injected-staged-")?;
            std::fs::write(root.path().join("config.toml"), "[workflow]\n")?;
            arm(std::io::Error::other(StagedConfigFault { nonce: 41 }));
            proof::arm_unlock_faults(2);
            let refusal = open_refused(&root)?;
            assert!(
                refusal.diagnostics().ends_with(&release_lines()),
                "{label}: the release lines end the diagnostics"
            );
            let hop = refusal.source().ok_or("the refusal exposes its cause")?;
            let original = hop
                .source()
                .and_then(|source| source.downcast_ref::<std::io::Error>())
                .ok_or("the read failure keeps its io::Error")?;
            assert_eq!(original.kind(), std::io::ErrorKind::Other, "{label}");
            assert_eq!(original.raw_os_error(), None, "{label}");
            let staged = original
                .get_ref()
                .and_then(|payload| payload.downcast_ref::<StagedConfigFault>())
                .ok_or("the staged payload survives")?;
            assert_eq!(staged.nonce, 41, "{label}");
            assert_eq!(
                crate::ui::failure_report(hop).to_string(),
                format!("{hop}: staged config fault"),
                "{label}"
            );
            assert_eq!(take_release_lines(), Vec::<String>::new());
        }
        Ok(())
    }
}

/// The in-crate twins of the closed-surface doctests: the same
/// expressions over `crate::` paths must compile, so each doctest's
/// failure is attributable to visibility only.
#[cfg(test)]
mod closed_surface_twins {
    use super::{PolicyWriter, Runtime};
    use crate::owner::Owner;
    use crate::policy::Policy;

    fn rebind_owner(rt: &mut Runtime, owner: Owner) {
        rt.owner = owner;
    }

    fn swap_owner(rt: &mut Runtime, mut owner: Owner) {
        std::mem::swap(&mut rt.owner, &mut owner);
    }

    fn rebind_policy(rt: &mut Runtime, policy: Policy) {
        rt.policy = policy;
    }

    fn writer_policy(rt: &mut Runtime) {
        let writer: PolicyWriter<'_> = rt.policy_writer();
        let _policy = writer.policy;
    }

    fn writer_store(rt: &mut Runtime) {
        let writer = rt.policy_writer();
        let _store = writer.store;
    }

    #[test]
    fn the_closed_runtime_items_are_reachable_inside_the_crate() {
        let _: fn(&mut Runtime, Owner) = rebind_owner;
        let _: fn(&mut Runtime, Owner) = swap_owner;
        let _: fn(&mut Runtime, Policy) = rebind_policy;
        let _: fn(&mut Runtime) = writer_policy;
        let _: fn(&mut Runtime) = writer_store;
    }
}
