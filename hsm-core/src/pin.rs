//! PIN attempt counter and failure backoff.
//!
//! The counter lives in the `PinCounter` sector as a bit-clear tick log: the
//! erased sector (all `0xFF`) means zero attempts; each attempt programs the
//! next byte from `0xFF` toward `0x00`. A correct unlock erases the sector. The
//! tick is written *before* the KEK is derived and the AEAD tag checked, so a
//! power glitch during verification always costs an attempt — it cannot be used
//! to brute-force the PIN for free.
//!
//! A byte counts as a used attempt as soon as it leaves the erased `0xFF`
//! state, so even a half-completed tick program is counted (fail-closed). Up to
//! 4096 attempts fit per erase, far above any sane `max_retries`.
//!
//! NOR note: every tick for counts < 256 lands in page 0, which is programmed
//! incrementally (only ever clearing fresh bits). The Pico's W25Q-class flash
//! permits clearing distinct bits of a page across multiple program ops.

use alloc::vec;

use crate::hal::{FlashStore, HalError, Region, PAGE_LEN, SECTOR_LEN};

/// Number of attempts already used (count of non-`0xFF` bytes from the start).
pub fn count<F: FlashStore>(f: &mut F) -> Result<usize, HalError> {
    let mut buf = vec![0xFFu8; SECTOR_LEN];
    f.read(Region::PinCounter, &mut buf)?;
    let mut n = 0;
    while n < buf.len() && buf[n] != 0xFF {
        n += 1;
    }
    Ok(n)
}

/// Record one attempt by clearing the next byte; returns the new attempt count.
/// Must be called and confirmed *before* deriving the KEK.
pub fn tick<F: FlashStore>(f: &mut F) -> Result<usize, HalError> {
    let n = count(f)?;
    if n >= SECTOR_LEN {
        return Ok(n); // saturated; should never happen with sane max_retries
    }
    let page_idx = n / PAGE_LEN;
    let within = n % PAGE_LEN;
    let mut page = [0xFFu8; PAGE_LEN];
    page[within] = 0x00;
    f.program(Region::PinCounter, page_idx * PAGE_LEN, &page)?;
    Ok(n + 1)
}

/// Reset the counter to zero (on a correct unlock).
pub fn reset<F: FlashStore>(f: &mut F) -> Result<(), HalError> {
    f.erase(Region::PinCounter)
}

/// Backoff before answering a failed unlock: `min(250ms · 2^failed, 30s)`.
pub fn backoff_ms(failed_attempts: u32) -> u32 {
    const BASE: u32 = 250;
    const CAP: u32 = 30_000;
    if failed_attempts >= 7 {
        return CAP;
    }
    (BASE << failed_attempts).min(CAP)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhal::MockFlash;

    #[test]
    fn ticks_and_resets() {
        let mut f = MockFlash::new();
        assert_eq!(count(&mut f).unwrap(), 0);
        assert_eq!(tick(&mut f).unwrap(), 1);
        assert_eq!(tick(&mut f).unwrap(), 2);
        assert_eq!(count(&mut f).unwrap(), 2);
        reset(&mut f).unwrap();
        assert_eq!(count(&mut f).unwrap(), 0);
    }

    #[test]
    fn partial_tick_counts_fail_closed() {
        // A half-completed program (byte left at e.g. 0xFE, not 0xFF) still
        // counts as a used attempt.
        let mut f = MockFlash::new();
        f.corrupt(Region::PinCounter, 0, 0xFE);
        assert_eq!(count(&mut f).unwrap(), 1);
    }

    #[test]
    fn backoff_schedule() {
        assert_eq!(backoff_ms(0), 250);
        assert_eq!(backoff_ms(1), 500);
        assert_eq!(backoff_ms(4), 4000);
        assert_eq!(backoff_ms(6), 16000);
        assert_eq!(backoff_ms(7), 30000);
        assert_eq!(backoff_ms(20), 30000);
    }
}
