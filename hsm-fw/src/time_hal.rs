//! `Monotonic` over Embassy's hardware timer.

use embassy_time::{Duration, Instant};
use hsm_core::hal::Monotonic;

/// Wall-clock-free monotonic source backed by `embassy_time::Instant`.
pub struct EmbassyClock;

impl Monotonic for EmbassyClock {
    fn now_micros(&self) -> u64 {
        Instant::now().as_micros()
    }

    fn delay_ms(&mut self, ms: u32) {
        // The HAL delay is synchronous (it implements PIN-failure backoff, which
        // intentionally stalls the device). We busy-wait against the hardware
        // timer rather than yielding, so the stall is observable as
        // unresponsiveness — exactly the anti-brute-force behavior wanted.
        let until = Instant::now() + Duration::from_millis(ms as u64);
        while Instant::now() < until {
            core::hint::spin_loop();
        }
    }
}
