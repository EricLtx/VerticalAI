use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet};
use vk_contracts::storage::MetadataDoc;

#[derive(Debug, Clone)]
struct Write {
    node: u8,
    key: String,
    value: u32,
}

fn write() -> impl Strategy<Value = Write> {
    (0u8..3, "[k-m]", 0u32..5).prop_map(|(node, key, value)| Write { node, key, value })
}

proptest! {
    #[test]
    fn every_write_survives_any_merge_order(
        writes in prop::collection::vec(write(), 0..30),
        order in prop::collection::vec(0usize..3, 0..6)
    ) {
        let mut docs: Vec<MetadataDoc<u32>> = (0..3).map(|_| MetadataDoc::default()).collect();
        for w in &writes {
            docs[w.node as usize].write(&w.key, w.value, &format!("node-{}", w.node));
        }
        // Merge in an arbitrary schedule, then everything into doc 0.
        for &i in &order {
            let other = docs[(i + 1) % 3].clone();
            docs[i].merge(&other);
        }
        let d1 = docs[1].clone();
        docs[0].merge(&d1);
        let d2 = docs[2].clone();
        docs[0].merge(&d2);
        let merged = &docs[0];
        // Every (key, value) ever written is present as the kept value or inside a surfaced conflict.
        let mut present: BTreeSet<(String, u32)> = merged.writes.iter().map(|(k, v)| (k.clone(), *v)).collect();
        for c in &merged.conflicts {
            for (_, v) in &c.values {
                present.insert((c.key.clone(), *v));
            }
        }
        // Last write per (node, key) is what that node holds; earlier same-node overwrites are legitimately replaced.
        let mut last: BTreeMap<(u8, String), u32> = BTreeMap::new();
        for w in &writes {
            last.insert((w.node, w.key.clone()), w.value);
        }
        for ((_, key), value) in last {
            prop_assert!(present.contains(&(key.clone(), value)), "lost write {key}={value}");
        }
    }
}
