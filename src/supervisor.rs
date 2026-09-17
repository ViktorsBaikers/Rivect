//! Sterile-retry supervisor: distinguishes progress, useful work and
//! waiting from sterile retry over sliding-window records, and answers
//! every detector firing with exactly one bounded, recorded reaction
//! (INV-027, AC-011). The supervisor never dispatches: it reads
//! scheduler state, produces the diagnostic, and the caller persists
//! the reaction through the task store's reaction journal.

use crate::contracts::TaskId;
use crate::scheduler::{NodeState, Scheduler};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// In-memory reaction history per task; the durable audit trail is the
/// store's supervisor reaction journal.
const REACTION_HISTORY: usize = 8;

/// In-memory watch ceiling: one sliding window per class plus recent
/// reactions per task. Beyond it the least recently observed task
/// drops its watch; its next observation rebuilds the window from
/// zero, and the durable journal keeps the recorded history.
pub const WATCH_LIMIT: usize = 64;

/// Operation classes the detectors know; every class carries its own
/// thresholds — there is no universal limit (INV-027).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationClass {
    Read,
    Test,
    Retrieve,
}

impl std::fmt::Display for OperationClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Read => "read",
            Self::Test => "test",
            Self::Retrieve => "retrieve",
        })
    }
}

/// Detector thresholds for one operation class: every cap counts
/// consecutive sterile observations inside `window`, and `cooldown` is
/// the number of further observations a firing inhibits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassThresholds {
    pub window: usize,
    pub exact_repeat: usize,
    pub fuzzy_repeat: usize,
    pub ping_pong: usize,
    pub no_progress: usize,
    pub cooldown: u32,
}

impl ClassThresholds {
    /// Pins the invariants the detector window depends on: every cap
    /// fits the window (a cap above it is an unreachable detector),
    /// the exact signature cannot fire behind the fuzzy one, a
    /// two-signature cycle needs two samples, and a zero cooldown
    /// would let one firing refire on every next observation.
    fn validate(&self) -> Result<(), PolicyFault> {
        for cap in [
            self.exact_repeat,
            self.fuzzy_repeat,
            self.ping_pong,
            self.no_progress,
        ] {
            if cap > self.window {
                return Err(PolicyFault::WindowBelowCap {
                    window: self.window,
                    cap,
                });
            }
        }
        if self.fuzzy_repeat < self.exact_repeat {
            return Err(PolicyFault::FuzzyBelowExact {
                fuzzy: self.fuzzy_repeat,
                exact: self.exact_repeat,
            });
        }
        if self.ping_pong < 2 {
            return Err(PolicyFault::PingPongBelowPair {
                cap: self.ping_pong,
            });
        }
        if self.cooldown == 0 {
            return Err(PolicyFault::ZeroCooldown {
                cooldown: self.cooldown,
            });
        }
        Ok(())
    }
}

/// Why one class's detector thresholds cannot govern a window.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum PolicyFault {
    #[error("window {window} below cap {cap}")]
    WindowBelowCap { window: usize, cap: usize },
    #[error("fuzzy cap {fuzzy} below exact cap {exact}")]
    FuzzyBelowExact { fuzzy: usize, exact: usize },
    #[error("ping-pong cap {cap} below the two samples a cycle needs")]
    PingPongBelowPair { cap: usize },
    #[error("cooldown {cooldown} lets a firing refire on the next observation")]
    ZeroCooldown { cooldown: u32 },
}

/// Owner-local construction error: a [`SupervisorPolicy`] whose
/// detectors could never fire, or could never stay bounded.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum SupervisorError {
    #[error("invalid {class} detector policy: {fault}")]
    InvalidPolicy {
        class: OperationClass,
        fault: PolicyFault,
    },
}

/// Detector policy: one threshold set per operation class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SupervisorPolicy {
    pub read: ClassThresholds,
    pub test: ClassThresholds,
    pub retrieve: ClassThresholds,
}

impl Default for SupervisorPolicy {
    /// Interim fixed detector thresholds; the config schema owns them
    /// once it gains a supervisor section.
    fn default() -> Self {
        Self {
            read: ClassThresholds {
                window: 8,
                exact_repeat: 3,
                fuzzy_repeat: 4,
                ping_pong: 6,
                no_progress: 8,
                cooldown: 4,
            },
            test: ClassThresholds {
                window: 12,
                exact_repeat: 5,
                fuzzy_repeat: 6,
                ping_pong: 8,
                no_progress: 12,
                cooldown: 6,
            },
            retrieve: ClassThresholds {
                window: 10,
                exact_repeat: 4,
                fuzzy_repeat: 6,
                ping_pong: 8,
                no_progress: 10,
                cooldown: 4,
            },
        }
    }
}

impl SupervisorPolicy {
    fn for_class(&self, class: OperationClass) -> ClassThresholds {
        match class {
            OperationClass::Read => self.read,
            OperationClass::Test => self.test,
            OperationClass::Retrieve => self.retrieve,
        }
    }
}

/// One failed attempt outcome as the detectors compare it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FailureSignature {
    pub tool: String,
    pub args: String,
    pub result: String,
}

impl FailureSignature {
    fn exact_match(&self, other: &Self) -> bool {
        self == other
    }

    fn fuzzy_match(&self, other: &Self) -> bool {
        self.tool == other.tool && self.args == other.args
    }
}

impl std::fmt::Display for FailureSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} -> {}", self.tool, self.args, self.result)
    }
}

/// One completed attempt outcome as the detectors see it. The progress
/// signals — heartbeat since the previous observation, evidence growth,
/// new inputs — each mark the observation useful on their own
/// (PROH-005).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observation {
    pub task: TaskId,
    pub class: OperationClass,
    pub signature: FailureSignature,
    pub heartbeat: bool,
    pub evidence_growth: u64,
    pub new_inputs: bool,
}

impl Observation {
    /// One failed attempt outcome carrying no progress signal yet; the
    /// `with_*` builders add the signals that mark work useful.
    #[must_use]
    pub fn failure(
        task: TaskId,
        class: OperationClass,
        tool: &str,
        args: &str,
        result: &str,
    ) -> Self {
        Self {
            task,
            class,
            signature: FailureSignature {
                tool: tool.to_string(),
                args: args.to_string(),
                result: result.to_string(),
            },
            heartbeat: false,
            evidence_growth: 0,
            new_inputs: false,
        }
    }

    /// A liveness signal since the previous observation: a quiet long
    /// test is useful work (PROH-005).
    #[must_use]
    pub fn with_heartbeat(mut self) -> Self {
        self.heartbeat = true;
        self
    }

    /// Evidence grew by `bytes` since the previous observation:
    /// paginated retrieval is useful work (PROH-005).
    #[must_use]
    pub fn with_evidence_growth(mut self, bytes: u64) -> Self {
        self.evidence_growth = self.evidence_growth.saturating_add(bytes);
        self
    }

    /// New inputs arrived since the previous observation: a RED→GREEN
    /// edit between runs is useful work (PROH-005).
    #[must_use]
    pub fn with_new_inputs(mut self) -> Self {
        self.new_inputs = true;
        self
    }

    fn carries_progress(&self) -> bool {
        self.heartbeat || self.evidence_growth > 0 || self.new_inputs
    }
}

/// Why the detectors fired; the diagnostic that identifies the stall
/// cause (AC-011).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StallCause {
    /// The same tool+args+result failed `repeats` times in a row.
    ExactRepeat {
        signature: FailureSignature,
        repeats: usize,
    },
    /// The same tool+args failed `repeats` times in a row with varying
    /// results.
    FuzzyRepeat {
        signature: FailureSignature,
        repeats: usize,
    },
    /// Two signatures strictly alternated across `alternations`
    /// attempts; `first` is the most recent.
    PingPong {
        first: FailureSignature,
        second: FailureSignature,
        alternations: usize,
    },
    /// `observations` attempts in a row carried no heartbeat, evidence
    /// growth or new inputs.
    NoProgress { observations: usize },
}

impl std::fmt::Display for StallCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ExactRepeat { signature, repeats } => {
                write!(
                    f,
                    "exact repeat of {signature} {repeats} times without progress"
                )
            }
            Self::FuzzyRepeat { signature, repeats } => {
                write!(
                    f,
                    "fuzzy repeat of {signature} {repeats} times without progress"
                )
            }
            Self::PingPong {
                first,
                second,
                alternations,
            } => write!(
                f,
                "ping-pong between {first} and {second} across {alternations} attempts without progress"
            ),
            Self::NoProgress { observations } => write!(
                f,
                "no progress across {observations} attempts without heartbeat, evidence growth or new inputs"
            ),
        }
    }
}

/// The one bounded reaction a detector firing produces: the pause's
/// cause plus the class limits and cooldown in force — never a chain of
/// automatic actions (INV-027).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reaction {
    pub task: TaskId,
    pub class: OperationClass,
    pub cause: StallCause,
    pub thresholds: ClassThresholds,
}

#[derive(Debug, Default)]
struct TaskWatch {
    windows: HashMap<OperationClass, VecDeque<Sample>>,
    cooldown: u32,
    /// Consecutive observations suppressed as waiting-is-progress;
    /// bounded by the class's `no_progress` cap (REQ-010).
    waiting_grace: usize,
    reactions: Vec<Reaction>,
}

#[derive(Debug)]
struct Sample {
    signature: FailureSignature,
    useful: bool,
}

/// Reads sliding-window records and bounds sterile retries; never
/// dispatches (INV-027). The watch set is LRU-bounded at
/// [`WATCH_LIMIT`]; the durable journal in the task store keeps every
/// recorded reaction.
#[derive(Debug)]
pub struct Supervisor {
    policy: SupervisorPolicy,
    watches: HashMap<TaskId, TaskWatch>,
    /// Watch recency, oldest first; mirrors `watches` keys.
    order: VecDeque<TaskId>,
}

impl Supervisor {
    pub fn new(policy: SupervisorPolicy) -> Result<Self, SupervisorError> {
        for (class, thresholds) in [
            (OperationClass::Read, policy.read),
            (OperationClass::Test, policy.test),
            (OperationClass::Retrieve, policy.retrieve),
        ] {
            thresholds
                .validate()
                .map_err(|fault| SupervisorError::InvalidPolicy { class, fault })?;
        }
        Ok(Self {
            policy,
            watches: HashMap::new(),
            order: VecDeque::new(),
        })
    }

    /// Records one completed-attempt outcome and runs the detectors over
    /// the task's sliding window for that class.
    ///
    /// A task whose latest scheduler node is `Waiting` is progressing
    /// by waiting, but only for `no_progress` consecutive observations:
    /// a wait that outlives that grace is itself the stall, so the
    /// suppression is bounded, never absolute (REQ-010). Any progress
    /// signal marks the observation useful the same way. While the
    /// task's cooldown lasts, observations are recorded but no detector
    /// fires — the firing that started the cooldown already produced
    /// its one reaction. A firing returns exactly one [`Reaction`] for
    /// the caller to persist.
    ///
    /// # Examples
    ///
    /// ```
    /// use rivect::contracts::TaskId;
    /// use rivect::scheduler::Scheduler;
    /// use rivect::supervisor::{
    ///     Observation, OperationClass, StallCause, Supervisor, SupervisorPolicy,
    /// };
    ///
    /// let scheduler = Scheduler::new(2, 4);
    /// let mut supervisor = match Supervisor::new(SupervisorPolicy::default()) {
    ///     Ok(supervisor) => supervisor,
    ///     Err(error) => unreachable!("the default policy validates: {error}"),
    /// };
    /// let observation = Observation::failure(
    ///     TaskId("task-loop".to_string()),
    ///     OperationClass::Read,
    ///     "read_file",
    ///     "/scope/allowed.txt",
    ///     "denied: scope",
    /// );
    /// assert_eq!(supervisor.observe(&scheduler, observation.clone()), None);
    /// assert_eq!(supervisor.observe(&scheduler, observation.clone()), None);
    /// assert!(matches!(
    ///     supervisor.observe(&scheduler, observation),
    ///     Some(reaction) if matches!(reaction.cause, StallCause::ExactRepeat { repeats: 3, .. })
    /// ));
    /// ```
    pub fn observe(&mut self, scheduler: &Scheduler, observation: Observation) -> Option<Reaction> {
        let thresholds = self.policy.for_class(observation.class);
        let waiting = scheduler
            .node_of_task(&observation.task)
            .is_some_and(|node| matches!(scheduler.state(node), Ok(NodeState::Waiting)));
        // Watch-set bound: before a first-time task gains its watch,
        // the least recently observed tasks at the ceiling drop theirs
        // — the observed task sits at the order's back, never at the
        // front, so the live sample can never evict itself.
        let watched = self.watches.contains_key(&observation.task);
        self.order.retain(|task| *task != observation.task);
        self.order.push_back(observation.task.clone());
        if !watched {
            while self.watches.len() >= WATCH_LIMIT {
                let Some(evicted) = self.order.pop_front() else {
                    break;
                };
                self.watches.remove(&evicted);
            }
        }
        let watch = self.watches.entry(observation.task.clone()).or_default();
        let window = watch.windows.entry(observation.class).or_default();
        let useful = if waiting {
            if watch.waiting_grace >= thresholds.no_progress {
                false
            } else {
                watch.waiting_grace += 1;
                true
            }
        } else {
            watch.waiting_grace = 0;
            observation.carries_progress()
        };
        window.push_back(Sample {
            useful,
            signature: observation.signature,
        });
        while window.len() > thresholds.window {
            window.pop_front();
        }
        if watch.cooldown > 0 {
            watch.cooldown -= 1;
            return None;
        }
        // INV-027 ordering: the exact signature (tool+args+result) fires
        // before the fuzzy one (tool+args), then ping-pong, then the
        // no-progress catch-all.
        let cause = detect(window, &thresholds)?;
        watch.cooldown = thresholds.cooldown;
        let reaction = Reaction {
            task: observation.task,
            class: observation.class,
            cause,
            thresholds,
        };
        watch.reactions.push(reaction.clone());
        if watch.reactions.len() > REACTION_HISTORY {
            watch.reactions.remove(0);
        }
        Some(reaction)
    }

    /// The task's most recent reactions, oldest first; bounded in
    /// memory, durable through the store's reaction journal.
    pub fn reactions(&self, task: &TaskId) -> &[Reaction] {
        self.watches
            .get(task)
            .map_or(&[], |watch| watch.reactions.as_slice())
    }
}

/// Runs the detectors over the trailing sterile run, newest first;
/// the first detector whose cap is reached wins, so one firing yields
/// exactly one cause.
fn detect(window: &VecDeque<Sample>, thresholds: &ClassThresholds) -> Option<StallCause> {
    let run: Vec<&Sample> = window
        .iter()
        .rev()
        .take_while(|sample| !sample.useful)
        .collect();
    let latest = run.first().copied()?;
    let exact = run
        .iter()
        .take_while(|sample| sample.signature.exact_match(&latest.signature))
        .count();
    if exact >= thresholds.exact_repeat {
        return Some(StallCause::ExactRepeat {
            signature: latest.signature.clone(),
            repeats: exact,
        });
    }
    let fuzzy = run
        .iter()
        .take_while(|sample| sample.signature.fuzzy_match(&latest.signature))
        .count();
    if fuzzy >= thresholds.fuzzy_repeat {
        return Some(StallCause::FuzzyRepeat {
            signature: latest.signature.clone(),
            repeats: fuzzy,
        });
    }
    // Trailing cycle, like the exact and fuzzy runs: only the samples
    // that actually alternate count, so one unmatched sample earlier
    // in the streak never disqualifies the cycle behind it.
    let alternations = trailing_alternations(&run);
    if alternations >= thresholds.ping_pong {
        return Some(StallCause::PingPong {
            first: run[0].signature.clone(),
            second: run[1].signature.clone(),
            alternations,
        });
    }
    if run.len() >= thresholds.no_progress {
        return Some(StallCause::NoProgress {
            observations: run.len(),
        });
    }
    None
}

/// Length of the trailing strict alternation, newest first: even
/// positions repeat the newest signature, odd positions the other one.
fn trailing_alternations(run: &[&Sample]) -> usize {
    let Some(first) = run.first() else {
        return 0;
    };
    let Some(second) = run.get(1) else {
        return 0;
    };
    if first.signature == second.signature {
        return 0;
    }
    run.iter()
        .enumerate()
        .take_while(|(index, sample)| {
            let expected = if index % 2 == 0 {
                &first.signature
            } else {
                &second.signature
            };
            sample.signature == *expected
        })
        .count()
}
