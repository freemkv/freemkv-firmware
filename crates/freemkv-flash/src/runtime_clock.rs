//! Hardware runtime clock, with explicit scoped simulation for unit fixtures.

use std::time::{Duration, Instant};

pub(crate) struct Clock {
    start: Instant,
    #[cfg(test)]
    simulated_start: Option<Duration>,
}

impl Clock {
    pub(crate) fn new() -> Self {
        Self {
            start: Instant::now(),
            #[cfg(test)]
            simulated_start: SIMULATED.with(|time| time.get()),
        }
    }

    pub(crate) fn elapsed(&self) -> Duration {
        #[cfg(test)]
        if let Some(start) = self.simulated_start {
            if let Some(now) = SIMULATED.with(|time| time.get()) {
                return now.saturating_sub(start);
            }
        }
        self.start.elapsed()
    }
}

pub(crate) fn sleep(duration: Duration) {
    #[cfg(test)]
    if SIMULATED.with(|time| match time.get() {
        Some(now) => {
            time.set(Some(now.saturating_add(duration)));
            true
        }
        None => false,
    }) {
        return;
    }
    std::thread::sleep(duration);
}

#[cfg(test)]
thread_local! {
    static SIMULATED: std::cell::Cell<Option<Duration>> = const { std::cell::Cell::new(None) };
}

/// Only in-memory unit fixtures opt in. Real devices and integration/hardware
/// tests retain wall-clock sleeps, including when the library is built for tests.
#[cfg(test)]
pub(crate) fn simulated<T>(op: impl FnOnce() -> T) -> T {
    struct Restore(Option<Duration>);
    impl Drop for Restore {
        fn drop(&mut self) {
            SIMULATED.with(|time| time.set(self.0));
        }
    }
    let _restore = Restore(SIMULATED.with(|time| time.replace(Some(Duration::ZERO))));
    op()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn simulated_waits_advance_each_runtime_from_its_own_start() {
        simulated(|| {
            let first = Clock::new();
            sleep(Duration::from_secs(5));
            let second = Clock::new();
            sleep(Duration::from_secs(2));
            assert_eq!(first.elapsed(), Duration::from_secs(7));
            assert_eq!(second.elapsed(), Duration::from_secs(2));
            // Another test or worker thread must retain the hardware clock.
            std::thread::spawn(|| assert!(SIMULATED.with(|time| time.get().is_none())))
                .join()
                .unwrap();
        });
        assert!(SIMULATED.with(|time| time.get().is_none()));
    }

    #[test]
    fn nested_simulation_restores_the_outer_clock_even_after_a_panic() {
        simulated(|| {
            let clock = Clock::new();
            sleep(Duration::from_secs(3));
            let result = std::panic::catch_unwind(|| {
                simulated(|| {
                    sleep(Duration::from_secs(20));
                    panic!("fixture failure");
                })
            });
            assert!(result.is_err());
            assert_eq!(clock.elapsed(), Duration::from_secs(3));
        });
        assert!(SIMULATED.with(|time| time.get().is_none()));
    }
}
