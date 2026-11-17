//! Exact anchor chains, work-budget edges and progress polling of the aligner.

use super::super::Control;
use super::*;
use crate::output::Event;
use std::{cell::RefCell, rc::Rc};

fn noise(seed: u64, len: usize) -> Vec<u8> {
    let mut state = seed | 1;
    (0..len)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state >> 24) as u8
        })
        .collect()
}

fn run(a: &[u8], b: &[u8], budget: usize) -> Anchors {
    let control = Control::default();
    let mut progress = Progress {
        control: &control,
        last: None,
    };
    anchors(a, b, budget, &mut progress).unwrap()
}

#[test]
fn identical_inputs_form_one_anchor_and_cost_a_known_budget() {
    let a = noise(1, 200);
    assert_eq!(run(&a, &a, 50_000_000), (vec![(0, 0, 200)], true));
    // 185 indexed windows + 24 sampled windows, 16 bytes each.
    let exact = (185 + 24) * 16;
    assert_eq!(run(&a, &a, exact), (vec![(0, 0, 200)], true));
    let (found, complete) = run(&a, &a, exact - 1);
    assert!(!complete);
    assert!(found.is_empty());
}

#[test]
fn an_insertion_splits_the_chain_without_overlap() {
    let a = noise(2, 300);
    let mut b = a[..100].to_vec();
    // The last inserted byte repeats a[99], so an unguarded backward walk
    // would slide into the first anchor.
    b.extend_from_slice(&[a[99] ^ 0xff, a[98] ^ 0xff, a[99]]);
    b.extend_from_slice(&a[100..]);
    assert_eq!(
        run(&a, &b, 50_000_000).0,
        vec![(0, 0, 100), (100, 103, 200)]
    );
    let flipped = run(&b, &a, 50_000_000).0;
    assert_eq!(flipped, vec![(0, 0, 100), (103, 100, 200)]);
}

#[test]
fn a_block_repeated_on_one_side_keeps_the_later_copy() {
    let w = noise(3, 16);
    let mut a = w.clone();
    a.extend(noise(4, 48));
    a.extend_from_slice(&w);
    a.extend(noise(5, 56));
    let mut b = w.clone();
    b.extend(noise(6, 64));
    assert_eq!(run(&a, &b, 50_000_000).0, vec![(64, 0, 16)]);
}

#[test]
fn short_runs_between_global_anchors_are_realigned_locally() {
    let p1 = noise(7, 64);
    let p2 = noise(8, 64);
    let z = noise(9, 8);
    let mut x = noise(10, 8);
    x.extend_from_slice(&z);
    x.extend(noise(11, 8));
    let mut y = noise(12, 12);
    y.extend_from_slice(&z);
    y.extend(noise(13, 4));
    let join = |mid: &[u8]| [p1.as_slice(), mid, p2.as_slice()].concat();
    assert_eq!(
        run(&join(&x), &join(&y), 50_000_000),
        (vec![(0, 0, 64), (72, 76, 8), (88, 88, 64)], true)
    );
}

#[test]
fn long_matches_publish_progress_at_each_polling_boundary() {
    let a = noise(14, 9000);
    let events = Rc::new(RefCell::new(Vec::new()));
    let sink = events.clone();
    let got = crate::output::capture_events(
        move |event| sink.borrow_mut().push(event),
        || run(&a, &a, 50_000_000),
    );
    assert_eq!(got, (vec![(0, 0, 9000)], true));
    let progress = |label: &str, done, total| Event::Progress {
        label: label.into(),
        done,
        total,
    };
    assert_eq!(
        *events.borrow(),
        vec![
            progress("Indexing content", 0, 9000),
            progress("Matching content", 0, 9000),
            progress("Ordering matches", 0, 1124),
            progress("Extending matches", 4096, 9000),
        ]
    );
}
