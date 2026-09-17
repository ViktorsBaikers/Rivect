//! Bounded task-tree scheduler: the single owner of tree concurrency
//! (INV-020). A parent that waits on its children releases its execution
//! slot and resource reservation before it waits, so one slot is enough
//! for a parent/child pair (PROH-002); the ready queue is strict FIFO, so
//! a ready independent branch is never parked behind an unrelated running
//! sibling; cancellation drains a whole subtree while completed effects
//! survive it, and a late callback for a cancelled node is counted and
//! dropped — it can never resurrect dispatch (INV-021, AC-012).

use crate::contracts::{AnswerSelection, Event, TaskId};
use std::collections::{HashMap, HashSet, VecDeque};

/// Interim fixed caps for the runtime-owned scheduler; the config schema
/// owns them once it gains a scheduler section.
pub const DEFAULT_MAX_SLOTS: usize = 2;
pub const DEFAULT_RESOURCE_CAP: u32 = 4;

pub type NodeId = usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    Ready,
    Running,
    Waiting,
    Completed,
    /// Run ended without completing — denied, no ready action, an
    /// unknown outcome, or a failed decision step. Terminal: the slot
    /// and reservation are released, and only a fresh intent submits a
    /// fresh node.
    Settled,
    Cancelled,
}

struct Node {
    task: TaskId,
    answer: AnswerSelection,
    grant_id: String,
    parent: Option<NodeId>,
    children: Vec<NodeId>,
    unfinished_children: usize,
    resource_units: u32,
    state: NodeState,
}

/// The step inputs a scheduled task carries into its decision step.
#[derive(Debug, Clone)]
pub struct NodeContext {
    pub task: TaskId,
    pub answer: AnswerSelection,
    pub grant_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitTransition {
    /// Slot and resources were released before waiting; the node requeues
    /// when its last unfinished child settles.
    Released,
    /// Every child already settled; the node never blocked.
    AlreadySatisfied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompleteTransition {
    /// The node settled; `resumed` names a waiting parent that requeued.
    Completed { resumed: Option<NodeId> },
    /// A completion callback for a cancelled node: counted, no state
    /// change, no parent wake (AC-012).
    IgnoredCancelled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliverVerdict {
    /// Delivery observed by live or absent tree nodes.
    Observed,
    /// Delivery for a cancelled node: ignored for admission.
    IgnoredCancelled,
}

#[derive(Debug, thiserror::Error)]
pub enum SchedulerError {
    #[error("unknown scheduler node {node}")]
    UnknownNode { node: NodeId },
    #[error("scheduler node {node} is not running")]
    NotRunning { node: NodeId },
    #[error("scheduler parent {parent} already settled")]
    ParentSettled { parent: NodeId },
    #[error("resource units {units} exceed the resource cap {cap}")]
    UnitsExceedCap { units: u32, cap: u32 },
}

pub struct Scheduler {
    max_slots: usize,
    resource_cap: u32,
    nodes: Vec<Node>,
    /// Strict FIFO of `NodeState::Ready` nodes only; settling and
    /// cancellation keep the invariant.
    ready: VecDeque<NodeId>,
    running: usize,
    held_units: u32,
    ignored_late_deliveries: u64,
    /// Task-tree parentage recorded at task creation; the scheduler is
    /// the single owner of tree shape (INV-020), the store owns tasks.
    parents: HashMap<TaskId, TaskId>,
    /// The same linkage as an insertion-ordered edge list: deterministic
    /// subtree walks without unordered map iteration.
    linkage: Vec<(TaskId, TaskId)>,
    /// Latest node per task: deliveries and ingress-driven tree
    /// cancellation key on the current node, never a historical one.
    by_task: HashMap<TaskId, NodeId>,
    /// Tasks drained by a tree cancellation, membership only — never
    /// iterated. Answer admission fails closed against it, so a
    /// cancelled subtree never grows runnable work again, whichever
    /// ancestors carried nodes (AC-012).
    cancelled_tasks: HashSet<TaskId>,
}

impl Scheduler {
    pub fn new(max_slots: usize, resource_cap: u32) -> Self {
        Self {
            max_slots,
            resource_cap,
            nodes: Vec::new(),
            ready: VecDeque::new(),
            running: 0,
            held_units: 0,
            ignored_late_deliveries: 0,
            parents: HashMap::new(),
            linkage: Vec::new(),
            by_task: HashMap::new(),
            cancelled_tasks: HashSet::new(),
        }
    }

    /// Registers one task-tree node. `resource_units` is the node's share
    /// of the shared resource cap while it runs.
    pub fn submit(
        &mut self,
        parent: Option<NodeId>,
        task: TaskId,
        answer: AnswerSelection,
        grant_id: String,
        resource_units: u32,
    ) -> Result<NodeId, SchedulerError> {
        // A reservation that can never fit is rejected up front: a
        // queue head that can never admit would stall every successor.
        if resource_units > self.resource_cap {
            return Err(SchedulerError::UnitsExceedCap {
                units: resource_units,
                cap: self.resource_cap,
            });
        }
        let node = self.nodes.len();
        if let Some(parent) = parent {
            // A settled parent can never gain children: completion ended
            // its wait, and a cancelled tree must not grow back.
            if matches!(
                self.node_state(parent)?,
                NodeState::Completed | NodeState::Cancelled | NodeState::Settled
            ) {
                return Err(SchedulerError::ParentSettled { parent });
            }
            self.nodes[parent].children.push(node);
            self.nodes[parent].unfinished_children += 1;
        }
        self.nodes.push(Node {
            task: task.clone(),
            answer,
            grant_id,
            parent,
            children: Vec::new(),
            unfinished_children: 0,
            resource_units,
            state: NodeState::Ready,
        });
        self.by_task.insert(task, node);
        self.ready.push_back(node);
        Ok(node)
    }

    /// Records task-tree parentage at task creation. The linkage
    /// outlives node submission, so a child answered later still lands
    /// under its parent's node. Linkage is immutable: the first record
    /// wins, so a replayed create that names a different parent can
    /// never re-adopt the original task.
    pub fn adopt(&mut self, task: TaskId, parent: TaskId) {
        if self.parents.contains_key(&task) {
            return;
        }
        self.parents.insert(task.clone(), parent.clone());
        self.linkage.push((task, parent));
    }

    /// Builds the runnable node for one answered task: the frozen
    /// answer and scoped read grant ride on the node, parentage
    /// resolves to the nearest ancestor that already carries a node,
    /// and a fresh answer retires the task's previous runnable node —
    /// a stale intent must never dispatch. A tree whose linkage is
    /// already settled, or whose task sits in a cancelled subtree,
    /// grows no runnable work: the answer stays durable but nothing
    /// dispatches (INV-021), answered as `None`.
    pub fn submit_answered(
        &mut self,
        task: TaskId,
        answer: AnswerSelection,
        grant_id: String,
    ) -> Result<Option<NodeId>, SchedulerError> {
        // Fail closed before any mutation: a cancelled subtree never
        // grows runnable work again, whichever ancestors carried nodes
        // (AC-012).
        if self.in_cancelled_subtree(&task) {
            return Ok(None);
        }
        if let Some(previous) = self.by_task.get(&task).copied() {
            self.retire(previous);
        }
        let parent = self.runnable_parent(&task);
        match self.submit(parent, task, answer, grant_id, 1) {
            Ok(node) => Ok(Some(node)),
            Err(SchedulerError::ParentSettled { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Cancels the tree of one task — the cancel ingress entry. The
    /// drain follows task linkage, never node linkage alone: a task
    /// that never carried a node still owns its task subtree, and a
    /// descendant whose nearest node-carrying ancestor was missing was
    /// attached as a root or under a farther ancestor. The drained
    /// subtree is recorded, so the cancelled task's remaining children
    /// never admit or dispatch regardless of which ancestors carried
    /// nodes (AC-012).
    pub fn cancel_task_tree(&mut self, task: &TaskId) -> Result<Vec<NodeId>, SchedulerError> {
        let subtree = self.task_subtree(task);
        let mut cancelled = Vec::new();
        for subtree_task in &subtree {
            self.cancelled_tasks.insert(subtree_task.clone());
            if let Some(root) = self.by_task.get(subtree_task).copied() {
                cancelled.extend(self.cancel_tree(root)?);
            }
        }
        Ok(cancelled)
    }

    /// Strict-FIFO admission: the queue head is admitted only while both
    /// caps hold. A head that does not fit blocks its successors —
    /// backpressure without bypass or starvation — and a slot occupied by
    /// a running sibling never blocks an unrelated ready branch that
    /// still fits.
    pub fn admit_next(&mut self) -> Option<NodeId> {
        let node = *self.ready.front()?;
        let units = self.nodes[node].resource_units;
        if self.running == self.max_slots {
            return None;
        }
        // Overflow fails closed: an unrepresentable reservation is a cap.
        let total = self.held_units.checked_add(units)?;
        if total > self.resource_cap {
            return None;
        }
        self.ready.pop_front();
        self.nodes[node].state = NodeState::Running;
        self.running += 1;
        self.held_units = total;
        Some(node)
    }

    /// A running node blocks on its unfinished children. The slot and
    /// resource reservation release inside this transition — before the
    /// wait — so a one-slot tree still admits the children (PROH-002).
    pub fn begin_wait(&mut self, node: NodeId) -> Result<WaitTransition, SchedulerError> {
        if self.node_state(node)? != NodeState::Running {
            return Err(SchedulerError::NotRunning { node });
        }
        if self.nodes[node].unfinished_children == 0 {
            return Ok(WaitTransition::AlreadySatisfied);
        }
        self.nodes[node].state = NodeState::Waiting;
        self.running -= 1;
        self.held_units -= self.nodes[node].resource_units;
        Ok(WaitTransition::Released)
    }

    /// Completes a running node, or counts a late completion callback for
    /// a cancelled one without touching any state (AC-012).
    pub fn complete(&mut self, node: NodeId) -> Result<CompleteTransition, SchedulerError> {
        match self.node_state(node)? {
            NodeState::Running => {
                self.nodes[node].state = NodeState::Completed;
                self.running -= 1;
                self.held_units -= self.nodes[node].resource_units;
                let resumed = self.settle_parent(node);
                Ok(CompleteTransition::Completed { resumed })
            }
            // Counted, never dropped: the late delivery counter is the
            // audit surface for every ignored callback.
            NodeState::Cancelled => {
                self.ignored_late_deliveries += 1;
                Ok(CompleteTransition::IgnoredCancelled)
            }
            _ => Err(SchedulerError::NotRunning { node }),
        }
    }

    /// Settles a running node whose run ended without completing —
    /// denied, no ready action, an unknown outcome, or a failed
    /// decision step. The slot and reservation release and the
    /// parent's wait settles, so one unfinished node can never stall
    /// the tree.
    pub fn settle(&mut self, node: NodeId) -> Result<(), SchedulerError> {
        if self.node_state(node)? != NodeState::Running {
            return Err(SchedulerError::NotRunning { node });
        }
        self.nodes[node].state = NodeState::Settled;
        self.running -= 1;
        self.held_units -= self.nodes[node].resource_units;
        self.settle_parent(node);
        Ok(())
    }

    /// Cancels a whole subtree: every non-terminal node drains, running
    /// slots and reservations release, queued entries disappear. Completed
    /// descendants keep their state — spent cost and landed effects are
    /// preserved. Returns the cancelled node ids in pre-order. A repeated
    /// cancel on a terminal root is a pure no-op: only a newly-cancelled
    /// root settles its own parent, so a re-cancel can never
    /// double-decrement a wait or resurrect the drained tree (AC-012).
    pub fn cancel_tree(&mut self, root: NodeId) -> Result<Vec<NodeId>, SchedulerError> {
        let root_was_live = !matches!(
            self.node_state(root)?,
            NodeState::Completed | NodeState::Cancelled | NodeState::Settled
        );
        let mut stack = vec![root];
        let mut cancelled = Vec::new();
        while let Some(node) = stack.pop() {
            let node_ref = &self.nodes[node];
            if !matches!(
                node_ref.state,
                NodeState::Completed | NodeState::Cancelled | NodeState::Settled
            ) {
                cancelled.push(node);
            }
            // Reversed push pops the leftmost child first: the drained
            // ids come back in pre-order.
            stack.extend(node_ref.children.iter().rev().copied());
        }
        for &node in &cancelled {
            if self.nodes[node].state == NodeState::Running {
                self.running -= 1;
                self.held_units -= self.nodes[node].resource_units;
            }
            self.nodes[node].state = NodeState::Cancelled;
        }
        self.ready
            .retain(|&queued| self.nodes[queued].state == NodeState::Ready);
        if root_was_live {
            // The cancelled root settles its own parent's wait exactly
            // once.
            self.settle_parent(root);
        }
        Ok(cancelled)
    }

    /// Observes one notification delivery. External deliveries never
    /// admit or requeue work — wakeups are internal (child settlement) —
    /// so the only observable verdict is the fail-closed one: a delivery
    /// naming the task's current cancelled node is ignored and counted.
    pub fn deliver(&mut self, event: &Event) -> DeliverVerdict {
        let Some(task) = event.task_id.as_ref() else {
            return DeliverVerdict::Observed;
        };
        // Keyed to the latest node of the task, never a historical one:
        // after a cancel and resubmit, events for the fresh node are
        // observed.
        let names_cancelled = self
            .by_task
            .get(task)
            .is_some_and(|node| self.nodes[*node].state == NodeState::Cancelled);
        if names_cancelled {
            self.ignored_late_deliveries += 1;
            DeliverVerdict::IgnoredCancelled
        } else {
            DeliverVerdict::Observed
        }
    }

    pub fn node_context(&self, node: NodeId) -> Result<NodeContext, SchedulerError> {
        let node_ref = self
            .nodes
            .get(node)
            .ok_or(SchedulerError::UnknownNode { node })?;
        Ok(NodeContext {
            task: node_ref.task.clone(),
            answer: node_ref.answer.clone(),
            grant_id: node_ref.grant_id.clone(),
        })
    }

    pub fn state(&self, node: NodeId) -> Result<NodeState, SchedulerError> {
        self.node_state(node)
    }

    /// The task's latest node, when it carries one: task-keyed callers
    /// (ingress-driven tests, diagnostics) never guess node ids.
    pub fn node_of_task(&self, task: &TaskId) -> Option<NodeId> {
        self.by_task.get(task).copied()
    }

    pub fn running_count(&self) -> usize {
        self.running
    }

    pub fn held_units(&self) -> u32 {
        self.held_units
    }

    pub fn ignored_late_deliveries(&self) -> u64 {
        self.ignored_late_deliveries
    }

    fn node_state(&self, node: NodeId) -> Result<NodeState, SchedulerError> {
        self.nodes
            .get(node)
            .map(|node| node.state)
            .ok_or(SchedulerError::UnknownNode { node })
    }

    /// One child settled: the parent's unfinished count drops, and a
    /// waiting parent whose last child just settled requeues. Cancelled
    /// or settled parents never requeue — cancellation is terminal.
    fn settle_parent(&mut self, child: NodeId) -> Option<NodeId> {
        let parent = self.nodes[child].parent?;
        let node = &mut self.nodes[parent];
        if node.unfinished_children > 0 {
            node.unfinished_children -= 1;
        }
        if node.state == NodeState::Waiting && node.unfinished_children == 0 {
            node.state = NodeState::Ready;
            self.ready.push_back(parent);
            return Some(parent);
        }
        None
    }

    /// Nearest ancestor that already carries a runnable node; ancestors
    /// without nodes yet are skipped, and no ancestor at all means a
    /// root. A settled nearest ancestor is left to `submit` to reject.
    fn runnable_parent(&self, task: &TaskId) -> Option<NodeId> {
        let mut ancestor = self.parents.get(task);
        while let Some(id) = ancestor {
            if let Some(node) = self.by_task.get(id) {
                return Some(*node);
            }
            ancestor = self.parents.get(id);
        }
        None
    }

    /// True when the task or any recorded ancestor was drained by a
    /// tree cancellation: task linkage decides, never node linkage, so
    /// a descendant whose nearest node-carrying ancestor survived the
    /// cancel is still covered — and so is a task adopted under a
    /// cancelled ancestor after the drain (AC-012).
    fn in_cancelled_subtree(&self, task: &TaskId) -> bool {
        let mut ancestor = Some(task);
        while let Some(id) = ancestor {
            if self.cancelled_tasks.contains(id) {
                return true;
            }
            ancestor = self.parents.get(id);
        }
        false
    }

    /// The task plus every task linked under it through recorded
    /// parentage, breadth-first in creation order; membership in the
    /// growing walk keeps it finite even if linkage ever formed a cycle.
    fn task_subtree(&self, task: &TaskId) -> Vec<TaskId> {
        let mut subtree = vec![task.clone()];
        let mut index = 0;
        while index < subtree.len() {
            let current = subtree[index].clone();
            index += 1;
            for (child, parent) in &self.linkage {
                if *parent == current && !subtree.contains(child) {
                    subtree.push(child.clone());
                }
            }
        }
        subtree
    }

    /// Forces one node terminal without running it: a replaced intent's
    /// stale node leaves the ready queue, terminal nodes keep their
    /// recorded outcome, and the parent's wait settles exactly like any
    /// other terminal transition — otherwise the replacement's fresh
    /// node would double-count and the parent would never resume.
    fn retire(&mut self, node: NodeId) {
        if matches!(
            self.nodes[node].state,
            NodeState::Completed | NodeState::Cancelled | NodeState::Settled
        ) {
            return;
        }
        if self.nodes[node].state == NodeState::Running {
            self.running -= 1;
            self.held_units -= self.nodes[node].resource_units;
        }
        if self.nodes[node].state == NodeState::Ready {
            self.ready.retain(|&queued| queued != node);
        }
        self.nodes[node].state = NodeState::Settled;
        self.settle_parent(node);
    }
}
