use super::*;
use std::sync::{Arc, Mutex};

#[test]
fn captures_both_streams_and_restores_after_panic() {
    let messages = Arc::new(Mutex::new(Vec::new()));
    let received = messages.clone();
    let _ = std::panic::catch_unwind(|| {
        capture(
            move |s| received.lock().unwrap().push(s),
            || {
                println!("information");
                eprintln!("warning");
                panic!("worker failed");
            },
        )
    });
    assert_eq!(*messages.lock().unwrap(), ["information", "warning"]);
    assert!(!captured());
}

#[test]
fn simultaneous_operations_keep_their_output_separate() {
    let workers: Vec<_> = (0..2)
        .map(|n| {
            std::thread::spawn(move || {
                let messages = Arc::new(Mutex::new(Vec::new()));
                let received = messages.clone();
                capture(
                    move |s| received.lock().unwrap().push(s),
                    || println!("job {n}"),
                );
                assert_eq!(*messages.lock().unwrap(), [format!("job {n}")]);
            })
        })
        .collect();
    for worker in workers {
        worker.join().unwrap();
    }
}
