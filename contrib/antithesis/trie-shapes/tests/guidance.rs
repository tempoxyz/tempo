//! Exercises the real SDK logger without mutating the test process's environment.

use alloy_primitives::{b256, Address, B256, U256};
use antithesis_trie_shapes::{Leaves, ShapeTracker};
use serde_json::{json, Value};
use std::{
    env, fs,
    process::Command,
    thread,
    time::{Duration, Instant},
};

fn leaves(keys: &[B256], value: U256) -> Leaves {
    keys.iter().map(|key| (*key, alloy_rlp::encode(value))).collect()
}

#[test]
#[ignore = "run in a child process by records_catalog_and_every_shape"]
fn emit_shapes() {
    antithesis_sdk::antithesis_init();
    let mut tracker = ShapeTracker::default();
    let owner = Some(Address::ZERO);
    tracker.observe(vec![(None, Vec::new()), (owner, Vec::new())]);
    tracker.observe(vec![(owner, leaves(&[B256::ZERO], U256::from(1)))]);
    let a = b256!("0123456789a00000000000000000000000000000000000000000000000000000");
    let b = b256!("0123456789b00000000000000000000000000000000000000000000000000000");
    let c = b256!("f000000000000000000000000000000000000000000000000000000000000000");
    tracker.observe(vec![(None, leaves(&[a, c], U256::from(1)))]);
    for _ in 0..2 {
        tracker.observe(vec![(owner, leaves(&[a, b], U256::from(1)))]);
    }
    tracker.observe(vec![(owner, leaves(&[a, b], U256::MAX))]);
    let fan = (0..16u8)
        .map(|nibble| {
            let mut key = [0u8; 32];
            key[0] = 0x12;
            key[1] = nibble << 4;
            B256::from(key)
        })
        .collect::<Vec<_>>();
    tracker.observe(vec![(owner, leaves(&fan, U256::from(1)))]);
}

#[test]
fn records_catalog_and_every_shape() {
    let directory = env::temp_dir().join(format!("trie-shape-guidance-{}", std::process::id()));
    fs::create_dir(&directory).unwrap();
    let path = directory.join("guidance.jsonl");
    let mut child = Command::new(env::current_exe().unwrap())
        .args(["--ignored", "--exact", "emit_shapes"])
        .env(antithesis_sdk::LOCAL_OUTPUT, &path)
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            let status = child.wait().unwrap();
            panic!("shape guidance child exceeded 30 seconds; killed with {status}");
        }
        thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success(), "shape guidance child failed with {status}");
    let events = fs::read_to_string(&path)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter_map(|event| event.get("antithesis_guidance").cloned())
        .collect::<Vec<_>>();
    fs::remove_dir_all(directory).unwrap();

    for message in [
        "Observed trie root shape",
        "Observed trie branch shape",
        "Observed trie extension shape",
        "Observed trie leaf shape",
    ] {
        let records = events.iter().filter(|event| event["message"] == message).collect::<Vec<_>>();
        let catalog = records.iter().filter(|event| event["hit"] == false).collect::<Vec<_>>();
        assert_eq!(catalog.len(), 1, "{message}");
        assert_eq!(records[0]["hit"], false, "catalog must precede observations: {message}");
        assert_eq!(catalog[0]["guidance_data"], Value::Null);
        assert!(records.iter().any(|event| event["hit"] == true), "{message}");
        for event in &records {
            assert_eq!(event["id"], message);
            assert_eq!(event["guidance_type"], "json");
            assert_eq!(event["maximize"], false);
            assert_eq!(event["location"], catalog[0]["location"]);
            assert!(event["location"]["begin_line"].as_u64().unwrap() > 0);
        }
    }
    let hits = |message| {
        events
            .iter()
            .filter(|event| event["message"] == message && event["hit"] == true)
            .map(|event| event["guidance_data"].clone())
            .collect::<Vec<_>>()
    };
    assert_eq!(
        hits("Observed trie root shape"),
        vec![
            json!({"storage": false, "root": "empty"}),
            json!({"storage": true, "root": "empty"}),
            json!({"storage": true, "root": "leaf"}),
            json!({"storage": false, "root": "branch"}),
            json!({"storage": true, "root": "extension"}),
            json!({"storage": true, "root": "extension"}),
            json!({"storage": true, "root": "extension"}),
            json!({"storage": true, "root": "extension"}),
        ]
    );
    assert_eq!(
        hits("Observed trie branch shape"),
        vec![
            json!({"storage": false, "depth": 0, "root": true, "state_mask": 0x8001}),
            json!({"storage": true, "depth": 10, "root": false, "state_mask": 0x0c00}),
            json!({"storage": true, "depth": 10, "root": false, "state_mask": 0x0c00}),
            json!({"storage": true, "depth": 10, "root": false, "state_mask": 0x0c00}),
            json!({"storage": true, "depth": 2, "root": false, "state_mask": 0xffff}),
        ]
    );
    let extensions = hits("Observed trie extension shape");
    assert_eq!(extensions.len(), 4);
    assert_eq!(
        extensions[..3],
        vec![json!({"storage": true, "depth": 0, "root": true, "length": 10}); 3]
    );
    assert_eq!(extensions[3], json!({"storage": true, "depth": 0, "root": true, "length": 2}));
    let leaves = hits("Observed trie leaf shape");
    assert_eq!(leaves.len(), 25);
    assert_eq!(leaves[0], json!({"storage": true, "depth": 0, "root": true, "embedded": false}));
    assert_eq!(
        leaves[1..3],
        vec![json!({"storage": false, "depth": 1, "root": false, "embedded": null}); 2]
    );
    assert_eq!(
        leaves[3..7],
        vec![json!({"storage": true, "depth": 11, "root": false, "embedded": true}); 4]
    );
    assert_eq!(
        leaves[7..9],
        vec![json!({"storage": true, "depth": 11, "root": false, "embedded": false}); 2]
    );
    assert_eq!(
        leaves[9..],
        vec![json!({"storage": true, "depth": 3, "root": false, "embedded": false}); 16]
    );
}
