//! Wall-clock time derived from the monotonic timer plus a host-supplied epoch.
//!
//! The device has no battery-backed RTC and the signing protocol carries no
//! timestamp, so the bridge pushes the current Unix time via `hsm.setTime`. The
//! device tracks `now = epoch_unix + (monotonic_now - monotonic_at_set)`. Until
//! a time has been set, [`Clock::now_unix`] returns `None` and signing fails
//! closed.
//!
//! `setTime` is intentionally reachable from every state with no PIN — that
//! part is by design (the bridge needs to push time before a signer is even
//! unlocked). But the value feeds `signSshKey`'s `ValidAfter`/`ValidBefore`
//! directly, so an *unbounded* clock would let anything with signing access
//! march the clock arbitrarily far into the future immediately before signing,
//! pre-minting certificates dated long past their true issuance window — which
//! defeats the "short certificate validity bounds the blast radius of host
//! compromise" mitigation the clock exists to support. [`Clock::set`] bounds
//! this: every later resync is checked against an immutable monotonic trust
//! anchor established by the first accepted value in this boot, so repeated
//! individually-small resyncs cannot ratchet time arbitrarily. The dispatcher
//! persists a floor across reboot and requires physical recovery for a large
//! re-anchor.

use crate::hal::Monotonic;

/// Once a time has been set, a later `setTime` may only move the clock within
/// this many seconds of where the monotonic timer says it already is. Chosen
/// well above the bridge's 5-minute periodic resync cadence (`timeSyncEvery`
/// in `host/internal/bridge`) to tolerate scheduling jitter, and far below any
/// drift that would let a certificate's validity window be meaningfully
/// pre-dated.
pub const MAX_DRIFT_SECS: i64 = 900;

/// Sanity floor/ceiling for the very first `setTime` in a boot session, when
/// there is no monotonic-anchored value yet to bound drift against. Rejects
/// obviously-implausible values (negative, epoch-zero, or wildly-future)
/// without needing a trusted time source.
const MIN_PLAUSIBLE_UNIX: i64 = 1_700_000_000; // 2023-11-14, predates this project
const MAX_PLAUSIBLE_UNIX: i64 = MIN_PLAUSIBLE_UNIX + 100 * 365 * 24 * 3600; // +100y

/// `unix_seconds` was implausible on the first `setTime` in a boot session, or
/// drifted too far from the tracked time on a later one. See [`Clock::set`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejected;

/// Tracks wall-clock time as an offset over the monotonic timer.
#[derive(Debug, Clone, Copy, Default)]
pub struct Clock {
    epoch_unix: Option<i64>,
    epoch_mono_us: u64,
    trust_anchor_unix: Option<i64>,
    trust_anchor_mono_us: u64,
}

impl Clock {
    pub fn new() -> Self {
        Clock {
            epoch_unix: None,
            epoch_mono_us: 0,
            trust_anchor_unix: None,
            trust_anchor_mono_us: 0,
        }
    }

    /// Set the wall clock to `unix_seconds`, anchored to the current monotonic
    /// reading. Rejects implausible values on the first call in a boot session
    /// and bounds drift against the monotonic timer on subsequent calls (see
    /// the module docs and [`MAX_DRIFT_SECS`]). On success, returns whether a
    /// time had previously been set.
    pub fn set<M: Monotonic>(&mut self, m: &M, unix_seconds: i64) -> Result<bool, Rejected> {
        match self.trust_anchor_unix {
            None => {
                if !(MIN_PLAUSIBLE_UNIX..=MAX_PLAUSIBLE_UNIX).contains(&unix_seconds) {
                    return Err(Rejected);
                }
            }
            Some(anchor) => {
                let elapsed_us = m.now_micros().saturating_sub(self.trust_anchor_mono_us);
                let expected = anchor.saturating_add((elapsed_us / 1_000_000) as i64);
                let too_far = match unix_seconds.checked_sub(expected) {
                    Some(delta) => delta.unsigned_abs() > MAX_DRIFT_SECS as u64,
                    None => true, // overflow on subtraction: certainly too far
                };
                if too_far {
                    return Err(Rejected);
                }
            }
        }
        let had = self.epoch_unix.is_some();
        if self.trust_anchor_unix.is_none() {
            self.trust_anchor_unix = Some(unix_seconds);
            self.trust_anchor_mono_us = m.now_micros();
        }
        self.epoch_unix = Some(unix_seconds);
        self.epoch_mono_us = m.now_micros();
        Ok(had)
    }

    /// Time derived solely from the immutable boot anchor and monotonic
    /// elapsed time. Later host resyncs cannot alter this value.
    pub fn trusted_now<M: Monotonic>(&self, m: &M) -> Option<i64> {
        let anchor = self.trust_anchor_unix?;
        let elapsed_us = m.now_micros().saturating_sub(self.trust_anchor_mono_us);
        Some(anchor.saturating_add((elapsed_us / 1_000_000) as i64))
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
        assert_eq!(c.set(&m, 1_700_000_000), Ok(false));
        assert_eq!(c.now_unix(&m), Some(1_700_000_000));
        m.advance_secs(42);
        assert_eq!(c.now_unix(&m), Some(1_700_000_042));
        // A small resync within the drift bound reports previousSet = true.
        assert_eq!(c.set(&m, 1_700_000_100), Ok(true));
    }

    #[test]
    fn first_set_rejects_implausible_values() {
        let mut c = Clock::new();
        let m = MockClock::new();
        assert_eq!(c.set(&m, -1), Err(Rejected));
        assert_eq!(c.set(&m, 0), Err(Rejected));
        assert_eq!(c.set(&m, i64::MAX), Err(Rejected));
        assert!(!c.is_set());
        assert_eq!(c.set(&m, 1_700_000_000), Ok(false));
        assert!(c.is_set());
    }

    #[test]
    fn subsequent_set_rejects_large_forward_jump() {
        // A compromised, signing-capable host trying to march the clock a
        // year into the future to pre-mint long-lived-looking certificates
        // must be rejected, not just the far-future first-set case.
        let mut c = Clock::new();
        let m = MockClock::new();
        assert_eq!(c.set(&m, 1_700_000_000), Ok(false));
        let one_year = 365 * 24 * 3600;
        assert_eq!(c.set(&m, 1_700_000_000 + one_year), Err(Rejected));
        // The clock did not move.
        assert_eq!(c.now_unix(&m), Some(1_700_000_000));
    }

    #[test]
    fn subsequent_set_rejects_large_backward_jump() {
        let mut c = Clock::new();
        let m = MockClock::new();
        assert_eq!(c.set(&m, 1_700_100_000), Ok(false));
        assert_eq!(c.set(&m, 1_700_000_000), Err(Rejected));
    }

    #[test]
    fn subsequent_set_allows_small_resync() {
        // Matches the bridge's periodic resync cadence (every 5 minutes).
        let mut c = Clock::new();
        let mut m = MockClock::new();
        assert_eq!(c.set(&m, 1_700_000_000), Ok(false));
        m.advance_secs(300);
        assert_eq!(c.set(&m, 1_700_000_300), Ok(true));
    }

    #[test]
    fn repeated_resyncs_cannot_ratchet_time_forward() {
        let mut c = Clock::new();
        let m = MockClock::new();
        assert_eq!(c.set(&m, 1_700_000_000), Ok(false));
        assert_eq!(c.set(&m, 1_700_000_900), Ok(true));
        assert_eq!(c.set(&m, 1_700_001_800), Err(Rejected));
        assert_eq!(c.trusted_now(&m), Some(1_700_000_000));
    }
}
