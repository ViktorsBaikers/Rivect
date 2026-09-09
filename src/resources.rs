//! Resource holders and the bounded notification queue. Overflow never
//! drops obligations silently: the backlog is replaced by one resync marker.

use crate::contracts::Event;
use std::collections::VecDeque;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceHolderStatus {
    Active,
    TerminationUnknown,
    Terminated,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ResourceHolder {
    pub resource_scope: String,
    pub executor_id: String,
    pub owner_generation: u64,
    pub status: ResourceHolderStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Delivery {
    Event(Event),
    ResyncMarker,
}

pub struct NotificationQueue {
    capacity: usize,
    pending: VecDeque<Event>,
    overflowed: bool,
}

impl NotificationQueue {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            pending: VecDeque::new(),
            overflowed: false,
        }
    }

    pub fn push(&mut self, event: Event) {
        if self.pending.len() >= self.capacity {
            self.pending.clear();
            self.overflowed = true;
        }
        self.pending.push_back(event);
    }

    /// Drains at most `limit` deliveries; a pending overflow is reported
    /// first as a single resync marker.
    pub fn drain(&mut self, limit: usize) -> Vec<Delivery> {
        let mut out = Vec::new();
        if self.overflowed {
            self.overflowed = false;
            out.push(Delivery::ResyncMarker);
        }
        while out.len() < limit {
            let Some(event) = self.pending.pop_front() else {
                break;
            };
            out.push(Delivery::Event(event));
        }
        out
    }

    pub fn len(&self) -> usize {
        self.pending.len()
    }

    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }
}
