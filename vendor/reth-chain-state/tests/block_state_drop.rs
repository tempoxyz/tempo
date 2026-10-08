use std::sync::{Arc, Barrier};

use reth_chain_state::{BlockState, ExecutedBlock};

const SMALL_STACK: usize = 64 * 1024;
const DEPTH: usize = 100_000;

fn chain(depth: usize, mut parent: Option<Arc<BlockState>>) -> Arc<BlockState> {
    let block = ExecutedBlock::default();
    for _ in 0..depth {
        parent = Some(Arc::new(BlockState::with_parent(block.clone(), parent)));
    }
    parent.expect("nonempty chain")
}

fn small_stack(f: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(SMALL_STACK)
        .spawn(f)
        .unwrap()
        .join()
        .unwrap();
}

#[test]
fn deep_chain_drops_on_small_stack() {
    small_stack(|| {
        let head = chain(DEPTH, None);
        let weak = Arc::downgrade(&head);
        let payload = Arc::downgrade(&head.block_ref().execution_output);
        drop(head);
        assert!(weak.upgrade().is_none());
        assert!(
            payload.upgrade().is_none(),
            "all ancestors must release their payloads"
        );
    });
}

#[test]
fn dropping_branch_preserves_shared_tail() {
    small_stack(|| {
        let tail = chain(DEPTH, None);
        let weak = Arc::downgrade(&tail);
        let head = chain(DEPTH, Some(tail.clone()));
        drop(head);
        assert_eq!(Arc::strong_count(&tail), 1);
        assert_eq!(tail.chain().count(), DEPTH);
        drop(tail);
        assert!(weak.upgrade().is_none());
    });
}

#[test]
fn concurrent_branches_release_shared_tail() {
    let tail = chain(DEPTH, None);
    let weak = Arc::downgrade(&tail);
    let payload = Arc::downgrade(&tail.block_ref().execution_output);
    let barrier = Arc::new(Barrier::new(9));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let head = chain(100, Some(tail.clone()));
            let barrier = barrier.clone();
            std::thread::Builder::new()
                .stack_size(SMALL_STACK)
                .spawn(move || {
                    barrier.wait();
                    drop(head);
                })
                .unwrap()
        })
        .collect();
    drop(tail);
    barrier.wait();
    for handle in handles {
        handle.join().unwrap();
    }
    assert!(weak.upgrade().is_none());
    assert!(payload.upgrade().is_none());
}

#[test]
fn every_payload_is_released_after_its_last_owner() {
    let mut parent: Option<Arc<BlockState>> = None;
    let mut payloads = Vec::new();
    let mut blocks = Vec::new();
    for _ in 0..100 {
        let block = ExecutedBlock::default();
        payloads.push(Arc::downgrade(&block.execution_output));
        blocks.push(Arc::downgrade(&block.recovered_block));
        parent = Some(Arc::new(BlockState::with_parent(block, parent)));
    }
    let shared_head = parent.clone();
    drop(parent);
    assert!(payloads.iter().all(|payload| payload.upgrade().is_some()));
    drop(shared_head);
    assert!(payloads.iter().all(|payload| payload.upgrade().is_none()));
    assert!(blocks.iter().all(|block| block.upgrade().is_none()));
}
