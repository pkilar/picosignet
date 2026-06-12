//! Wall-clock time derived from the monotonic timer plus a host-supplied epoch.
//!
//! The device has no battery-backed RTC and the signing protocol carries no
//! timestamp, so the bridge pushes the current Unix time via `hsm.setTime`. The
//! device tracks `now = epoch_unix + (monotonic_now - monotonic_at_set)`. Until
//! a time has been set, [`Clock::now_unix`] returns `None` and signing fails
//! closed.

use crate::hal::Monotonic;

/// Tracks wall-clock time as an offset over the monotonic timer.
#[derive(Debug, Clone, Copy, Default)]
pub struct Clock {
    epoch_unix: Option<i64>,
    epoch_mono_us: u64,
}

impl Clock {
    pub fn new() -> Self {
        Clock {
            epoch_unix: None,
            epoch_mono_us: 0,
        }
    }

    /// Set the wall clock to `unix_seconds`, anchored to the current monotonic
    /// reading. Returns whether a time had previously been set.
    pub fn set<M: Monotonic>(&mut self, m: &M, unix_seconds: i64) -> bool {
        let had = self.epoch_unix.is_some();
        self.epoch_unix = Some(unix_seconds);
        self.epoch_mono_us = m.now_micros();
        had
    }

    /// Current Unix time in seconds, or `None` if never set.
    pub fn now_unix<M: Monotonic>(&self, m: &M) -> Option<i64> {
        let epoch = self.epoch_unix?;
        let elapsed_us = m.now_micros().saturating_sub(self.epoch_mono_us);
        Some(epoch + (elapsed_us / 1_000_000) as i64)
    }

    pub fn is_set(&self) -> bool {
        self.epoch_unix.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhal::MockClock;

    #[test]
    fn unset_returns_none() {
        let c = Clock::new();
        let m = MockClock::new();
        assert_eq!(c.now_unix(&m), None);
    }

    #[test]
    fn advances_with_monotonic() {
        let mut c = Clock::new();
        let mut m = MockClock::new();
        assert!(!c.set(&m, 1_000_000));
        assert_eq!(c.now_unix(&m), Some(1_000_000));
        m.advance_secs(42);
        assert_eq!(c.now_unix(&m), Some(1_000_042));
        // Second set reports previousSet = true.
        assert!(c.set(&m, 2_000_000));
    }
}
