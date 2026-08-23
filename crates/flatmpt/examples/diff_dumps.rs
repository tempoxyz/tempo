//! Structurally diff two TEMPO_FLATMPT_DUMP_OPS dumps: parent, claimed root,
//! op counts, and the first differing ops.
//!
//!   cargo run -p tempo-flatmpt --release --example diff_dumps -- <a.bin> <b.bin>

use mpt_flat_poc::{Key, StateOp};

type Dump = (u64, alloy_primitives::B256, Vec<(Key, StateOp)>, alloy_primitives::B256);

fn main() -> anyhow::Result<()> {
    let a_path = std::env::args().nth(1).expect("usage: diff_dumps <a.bin> <b.bin>");
    let b_path = std::env::args().nth(2).expect("usage: diff_dumps <a.bin> <b.bin>");
    let a: Dump = bincode::deserialize(&std::fs::read(&a_path)?)?;
    let b: Dump = bincode::deserialize(&std::fs::read(&b_path)?)?;

    for (name, d) in [("A", &a), ("B", &b)] {
        println!(
            "{name}: block={} parent={} claimed={} ops={}",
            d.0,
            hex::encode(d.1),
            hex::encode(d.3),
            d.2.len()
        );
    }

    // Real update identity: (account key, slot | op-kind). The Key in the
    // dump is the hashed account; SetStorage carries the slot inside the op.
    fn ident(k: &Key, op: &StateOp) -> (Vec<u8>, Vec<u8>) {
        let kb = format!("{k:?}").into_bytes();
        match op {
            StateOp::SetStorage { slot, .. } => (kb, slot.to_vec()),
            other => (kb, format!("kind:{:?}", std::mem::discriminant(other)).into_bytes()),
        }
    }
    use std::collections::BTreeMap;
    let mut afin: BTreeMap<(Vec<u8>, Vec<u8>), &StateOp> = BTreeMap::new();
    for (k, op) in &a.2 { afin.insert(ident(k, op), op); }
    let mut bfin: BTreeMap<(Vec<u8>, Vec<u8>), &StateOp> = BTreeMap::new();
    for (k, op) in &b.2 { bfin.insert(ident(k, op), op); }
    println!("distinct (acct,slot): A={} B={}", afin.len(), bfin.len());
    let mism: Vec<_> = afin.iter().filter(|(k, v)| bfin.get(*k).map(|x| format!("{x:?}")) != Some(format!("{v:?}"))).collect();
    println!("last-write-wins mismatches: {}", mism.len());
    for ((acct, slot), v) in mism.iter().take(6) {
        println!("  acct {} slot {}\n    A-final={:?}\n    B-final={:?}",
            hex::encode(&acct[..acct.len().min(20)]), hex::encode(&slot[..slot.len().min(32)]),
            v, bfin.get(&(acct.clone(), slot.clone())));
    }
    for (name, list) in [("A", &a.2), ("B", &b.2)] {
        let mut seen = std::collections::HashMap::new();
        let mut dups = 0usize; let mut conflict = 0usize;
        for (k, op) in list {
            if let Some(prev) = seen.insert(ident(k, op), format!("{op:?}")) {
                dups += 1;
                if prev != format!("{op:?}") { conflict += 1; }
            }
        }
        println!("{name}: total={} distinct={} dup-writes={} conflicting-dup-writes={}", list.len(), seen.len(), dups, conflict);
    }
    // ORDER PROBE: where do the two sequences first differ, and is either
    // one sorted by (account, slot)?
    let key_of = |k: &Key, op: &StateOp| -> (Vec<u8>, Vec<u8>) {
        let kb = format!("{k:?}").into_bytes();
        match op {
            StateOp::SetStorage { slot, .. } => (kb, slot.to_vec()),
            other => (kb, format!("{:?}", std::mem::discriminant(other)).into_bytes()),
        }
    };
    let first_diff = a.2.iter().zip(b.2.iter()).position(|(x, y)| x != y);
    println!("first differing index: {:?} of {}", first_diff, a.2.len());
    for (name, list) in [("A", &a.2), ("B", &b.2)] {
        let ids: Vec<_> = list.iter().map(|(k, op)| key_of(k, op)).collect();
        let sorted = ids.windows(2).all(|w| w[0] <= w[1]);
        // Count "account runs": contiguous stretches of one account.
        let mut runs = 0; let mut prev: Option<&Vec<u8>> = None;
        for (acct, _) in &ids { if prev != Some(acct) { runs += 1; prev = Some(acct); } }
        println!("{name}: fully-sorted={sorted} account-runs={runs}");
    }
    if let Some(i) = first_diff {
        for d in i.saturating_sub(2)..(i + 4).min(a.2.len()) {
            let (ka, oa) = &a.2[d]; let (kb2, ob) = &b.2[d];
            let fmt = |k: &Key, o: &StateOp| { let (acc, sl) = key_of(k, o); format!("{}..{}", hex::encode(&acc[..8.min(acc.len())]), hex::encode(&sl[..6.min(sl.len())])) };
            println!("  [{d}] A={} B={}{}", fmt(ka, oa), fmt(kb2, ob), if (ka, oa) == (kb2, ob) { "" } else { "   <-- differs" });
        }
    }
    Ok(())
}
