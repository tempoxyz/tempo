//! Deterministic indexed scheduling helpers.

use std::{
    collections::VecDeque,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering},
    },
};

/// Kind of Block-STM task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockStmTaskKind {
    /// Execute one transaction incarnation.
    Execution,
    /// Validate one finished transaction incarnation.
    Validation,
}

/// Scheduled transaction task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockStmScheduledTask {
    /// Transaction index in the preset serialization order.
    pub tx_index: usize,
    /// Incarnation number for this task.
    pub incarnation: usize,
    /// Task kind.
    pub kind: BlockStmTaskKind,
}

/// Deterministic scheduler for transaction indexes, incarnations, and validations.
#[derive(Debug, Clone)]
pub struct BlockStmScheduler {
    execution: VecDeque<BlockStmScheduledTask>,
    validation: VecDeque<BlockStmScheduledTask>,
    next_incarnation: Vec<usize>,
}

/// Shareable scheduler for worker-owned Block-STM execution and validation tasks.
#[derive(Debug)]
pub struct BlockStmConcurrentScheduler {
    queue: Mutex<VecDeque<BlockStmScheduledTask>>,
    next_incarnation: Vec<AtomicUsize>,
}

impl BlockStmScheduler {
    /// Creates a scheduler for `len` fixed transaction indexes.
    pub fn new(len: usize) -> Self {
        Self {
            execution: (0..len)
                .map(|tx_index| BlockStmScheduledTask {
                    tx_index,
                    incarnation: 0,
                    kind: BlockStmTaskKind::Execution,
                })
                .collect(),
            validation: VecDeque::new(),
            next_incarnation: vec![1; len],
        }
    }

    /// Returns the next task, prioritizing lower-index validation work.
    pub fn next_task(&mut self) -> Option<BlockStmScheduledTask> {
        match (self.validation.front(), self.execution.front()) {
            (Some(validation), Some(execution)) if validation.tx_index <= execution.tx_index => {
                self.validation.pop_front()
            }
            (Some(_), None) => self.validation.pop_front(),
            _ => self.execution.pop_front(),
        }
    }

    /// Compatibility helper returning the next execution index.
    pub fn next_index(&mut self) -> Option<usize> {
        while let Some(task) = self.next_task() {
            if task.kind == BlockStmTaskKind::Execution {
                return Some(task.tx_index);
            }
        }
        None
    }

    /// Schedules validation for a finished incarnation.
    pub fn validate(&mut self, tx_index: usize, incarnation: usize) {
        self.validation.push_back(BlockStmScheduledTask {
            tx_index,
            incarnation,
            kind: BlockStmTaskKind::Validation,
        });
    }

    /// Schedules the next incarnation of an aborted transaction.
    pub fn retry(&mut self, tx_index: usize) -> usize {
        let incarnation = self
            .next_incarnation
            .get_mut(tx_index)
            .expect("retry tx index must be in scheduler range");
        let current = *incarnation;
        *incarnation += 1;
        self.execution.push_back(BlockStmScheduledTask {
            tx_index,
            incarnation: current,
            kind: BlockStmTaskKind::Execution,
        });
        current
    }

    /// Returns true if no indexes remain.
    pub fn is_empty(&self) -> bool {
        self.execution.is_empty() && self.validation.is_empty()
    }
}

impl BlockStmConcurrentScheduler {
    /// Creates a concurrent scheduler for `len` fixed transaction indexes.
    pub fn new(len: usize) -> Self {
        Self {
            queue: Mutex::new(
                (0..len)
                    .map(|tx_index| BlockStmScheduledTask {
                        tx_index,
                        incarnation: 0,
                        kind: BlockStmTaskKind::Execution,
                    })
                    .collect(),
            ),
            next_incarnation: (0..len).map(|_| AtomicUsize::new(1)).collect(),
        }
    }

    /// Returns the next available task.
    pub fn next_task(&self) -> Option<BlockStmScheduledTask> {
        self.queue
            .lock()
            .expect("Block-STM concurrent scheduler poisoned")
            .pop_front()
    }

    /// Schedules validation for a finished incarnation.
    pub fn validate(&self, tx_index: usize, incarnation: usize) {
        self.queue
            .lock()
            .expect("Block-STM concurrent scheduler poisoned")
            .push_back(BlockStmScheduledTask {
                tx_index,
                incarnation,
                kind: BlockStmTaskKind::Validation,
            });
    }

    /// Schedules the next incarnation of an aborted transaction.
    pub fn retry(&self, tx_index: usize) -> usize {
        let incarnation = self.next_incarnation[tx_index].fetch_add(1, Ordering::AcqRel);
        self.queue
            .lock()
            .expect("Block-STM concurrent scheduler poisoned")
            .push_back(BlockStmScheduledTask {
                tx_index,
                incarnation,
                kind: BlockStmTaskKind::Execution,
            });
        incarnation
    }

    /// Returns true when no task is currently queued.
    pub fn is_empty(&self) -> bool {
        self.queue
            .lock()
            .expect("Block-STM concurrent scheduler poisoned")
            .is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blockstm_scheduler_initializes_execution_incarnations() {
        let mut scheduler = BlockStmScheduler::new(2);

        assert_eq!(
            scheduler.next_task(),
            Some(BlockStmScheduledTask {
                tx_index: 0,
                incarnation: 0,
                kind: BlockStmTaskKind::Execution,
            })
        );
        assert_eq!(
            scheduler.next_task(),
            Some(BlockStmScheduledTask {
                tx_index: 1,
                incarnation: 0,
                kind: BlockStmTaskKind::Execution,
            })
        );
        assert!(scheduler.is_empty());
    }

    #[test]
    fn blockstm_scheduler_retries_increment_incarnation() {
        let mut scheduler = BlockStmScheduler::new(1);
        assert_eq!(scheduler.next_index(), Some(0));

        assert_eq!(scheduler.retry(0), 1);
        assert_eq!(scheduler.retry(0), 2);

        assert_eq!(
            scheduler.next_task(),
            Some(BlockStmScheduledTask {
                tx_index: 0,
                incarnation: 1,
                kind: BlockStmTaskKind::Execution,
            })
        );
        assert_eq!(
            scheduler.next_task(),
            Some(BlockStmScheduledTask {
                tx_index: 0,
                incarnation: 2,
                kind: BlockStmTaskKind::Execution,
            })
        );
    }

    #[test]
    fn blockstm_scheduler_prioritizes_lower_validation_task() {
        let mut scheduler = BlockStmScheduler::new(3);
        assert_eq!(scheduler.next_index(), Some(0));
        assert_eq!(scheduler.next_index(), Some(1));
        scheduler.validate(1, 0);

        assert_eq!(
            scheduler.next_task(),
            Some(BlockStmScheduledTask {
                tx_index: 1,
                incarnation: 0,
                kind: BlockStmTaskKind::Validation,
            })
        );
        assert_eq!(scheduler.next_index(), Some(2));
    }

    #[test]
    fn blockstm_concurrent_scheduler_retries_allocate_unique_incarnations() {
        let scheduler = BlockStmConcurrentScheduler::new(1);
        assert_eq!(
            scheduler.next_task(),
            Some(BlockStmScheduledTask {
                tx_index: 0,
                incarnation: 0,
                kind: BlockStmTaskKind::Execution,
            })
        );

        std::thread::scope(|scope| {
            for _ in 0..16 {
                let scheduler = &scheduler;
                scope.spawn(move || {
                    scheduler.retry(0);
                });
            }
        });

        let mut incarnations = Vec::new();
        while let Some(task) = scheduler.next_task() {
            incarnations.push(task.incarnation);
        }
        incarnations.sort_unstable();

        assert_eq!(incarnations, (1..=16).collect::<Vec<_>>());
    }

    #[test]
    fn blockstm_concurrent_scheduler_accepts_validation_tasks() {
        let scheduler = BlockStmConcurrentScheduler::new(0);

        scheduler.validate(7, 2);

        assert_eq!(
            scheduler.next_task(),
            Some(BlockStmScheduledTask {
                tx_index: 7,
                incarnation: 2,
                kind: BlockStmTaskKind::Validation,
            })
        );
        assert!(scheduler.is_empty());
    }
}
