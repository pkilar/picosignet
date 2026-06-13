//! In-memory HAL implementations for host tests and the simulator.
//!
//! Uses only `core` + `alloc`, so it compiles in the no_std crate (behind the
//! `std` feature for the simulator, and under `cfg(test)` for unit tests). The
//! firmware never includes it.

use zeroize::Zeroizing;

use crate::hal::{EntropySource, FlashStore, HalError, Monotonic, Region, SECTOR_LEN};

/// A RAM-backed flash with the five HSM regions. Models NOR semantics loosely:
/// `erase` sets `0xFF`, `program` overwrites a page (the tests don't rely on
/// bit-clear-only programming except the PIN counter, which only clears bits).
pub struct MockFlash {
    config_a: [u8; SECTOR_LEN],
    config_b: [u8; SECTOR_LEN],
    key_a: [u8; SECTOR_LEN],
    key_b: [u8; SECTOR_LEN],
    pin_counter: [u8; SECTOR_LEN],
    unique_id: [u8; 8],
    device_secret: Result<[u8; 32], HalError>,
}

/// Fixed mock OTP device secret (32 bytes). Deterministic so golden and
/// differential runs stay reproducible; not persisted by `snapshot()` because
/// on hardware the secret lives in OTP, not flash.
pub const MOCK_DEVICE_SECRET: [u8; 32] = *b"usbhsm-mock-otp-secret-32bytes!!";

impl Default for MockFlash {
    fn default() -> Self {
        Self::new()
    }
}

impl MockFlash {
    pub fn new() -> Self {
        MockFlash {
            config_a: [0xFF; SECTOR_LEN],
            config_b: [0xFF; SECTOR_LEN],
            key_a: [0xFF; SECTOR_LEN],
            key_b: [0xFF; SECTOR_LEN],
            pin_counter: [0xFF; SECTOR_LEN],
            unique_id: [0x42; 8],
            device_secret: Ok(MOCK_DEVICE_SECRET),
        }
    }

    pub fn with_unique_id(id: [u8; 8]) -> Self {
        let mut f = Self::new();
        f.unique_id = id;
        f
    }

    /// Test helper: a flash whose device secret differs from the default.
    pub fn with_device_secret(secret: [u8; 32]) -> Self {
        let mut f = Self::new();
        f.device_secret = Ok(secret);
        f
    }

    /// Test helper: a device whose OTP secret is unprovisioned/unreadable —
    /// every KEK operation must fail closed.
    pub fn without_device_secret() -> Self {
        let mut f = Self::new();
        f.device_secret = Err(HalError::Secret);
        f
    }

    fn region(&self, r: Region) -> &[u8; SECTOR_LEN] {
        match r {
            Region::ConfigA => &self.config_a,
            Region::ConfigB => &self.config_b,
            Region::KeyA => &self.key_a,
            Region::KeyB => &self.key_b,
            Region::PinCounter => &self.pin_counter,
        }
    }

    fn region_mut(&mut self, r: Region) -> &mut [u8; SECTOR_LEN] {
        match r {
            Region::ConfigA => &mut self.config_a,
            Region::ConfigB => &mut self.config_b,
            Region::KeyA => &mut self.key_a,
            Region::KeyB => &mut self.key_b,
            Region::PinCounter => &mut self.pin_counter,
        }
    }

    /// Test helper: overwrite a single byte (simulate corruption / a tick).
    pub fn corrupt(&mut self, r: Region, off: usize, val: u8) {
        self.region_mut(r)[off] = val;
    }

    /// Test helper: read one byte.
    pub fn peek(&self, r: Region, off: usize) -> u8 {
        self.region(r)[off]
    }

    /// Serialize the whole flash image (5 sectors + unique id) for the
    /// simulator's `--state-file` persistence.
    pub fn snapshot(&self) -> alloc::vec::Vec<u8> {
        let mut v = alloc::vec::Vec::with_capacity(5 * SECTOR_LEN + 8);
        for r in [
            Region::ConfigA,
            Region::ConfigB,
            Region::KeyA,
            Region::KeyB,
            Region::PinCounter,
        ] {
            v.extend_from_slice(self.region(r));
        }
        v.extend_from_slice(&self.unique_id);
        v
    }

    /// Restore a flash image produced by [`MockFlash::snapshot`]. Returns false
    /// if the data is the wrong length.
    pub fn restore(&mut self, data: &[u8]) -> bool {
        if data.len() != 5 * SECTOR_LEN + 8 {
            return false;
        }
        let regions = [
            Region::ConfigA,
            Region::ConfigB,
            Region::KeyA,
            Region::KeyB,
            Region::PinCounter,
        ];
        for (i, r) in regions.iter().enumerate() {
            let off = i * SECTOR_LEN;
            self.region_mut(*r)
                .copy_from_slice(&data[off..off + SECTOR_LEN]);
        }
        self.unique_id
            .copy_from_slice(&data[5 * SECTOR_LEN..5 * SECTOR_LEN + 8]);
        true
    }
}

impl FlashStore for MockFlash {
    fn read(&mut self, region: Region, buf: &mut [u8]) -> Result<(), HalError> {
        let src = self.region(region);
        if buf.len() < SECTOR_LEN {
            return Err(HalError::OutOfRange);
        }
        buf[..SECTOR_LEN].copy_from_slice(src);
        Ok(())
    }

    fn erase(&mut self, region: Region) -> Result<(), HalError> {
        self.region_mut(region).fill(0xFF);
        Ok(())
    }

    fn program(&mut self, region: Region, offset: usize, page: &[u8]) -> Result<(), HalError> {
        let sector = self.region_mut(region);
        if offset + page.len() > SECTOR_LEN {
            return Err(HalError::OutOfRange);
        }
        // NOR program can only clear bits (AND), matching real hardware. The
        // PIN counter relies on this; record writes erase first so it is moot.
        for (i, &b) in page.iter().enumerate() {
            sector[offset + i] &= b;
        }
        Ok(())
    }

    fn unique_id(&self) -> [u8; 8] {
        self.unique_id
    }

    fn device_secret(&self) -> Result<Zeroizing<[u8; 32]>, HalError> {
        self.device_secret.map(Zeroizing::new)
    }
}

/// A deterministic xorshift entropy source. Output is uniform enough to pass the
/// DRBG health checks; seed it fixed for reproducible (golden/differential)
/// runs.
pub struct MockEntropy {
    state: u64,
}

impl MockEntropy {
    pub fn new(seed: u64) -> Self {
        MockEntropy {
            state: seed | 1, // nonzero
        }
    }

    fn next_byte(&mut self) -> u8 {
        // xorshift64*
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        (x.wrapping_mul(0x2545F4914F6CDD1D) >> 56) as u8
    }
}

impl EntropySource for MockEntropy {
    fn fill_raw(&mut self, buf: &mut [u8]) -> Result<(), HalError> {
        for b in buf.iter_mut() {
            *b = self.next_byte();
        }
        Ok(())
    }
}

/// A controllable monotonic clock. `delay_ms` advances it; tests can also step
/// it manually.
pub struct MockClock {
    micros: u64,
}

impl Default for MockClock {
    fn default() -> Self {
        MockClock::new()
    }
}

impl MockClock {
    pub fn new() -> Self {
        MockClock { micros: 0 }
    }

    /// Advance the clock by `secs` seconds (test helper).
    pub fn advance_secs(&mut self, secs: u64) {
        self.micros += secs * 1_000_000;
    }
}

impl Monotonic for MockClock {
    fn now_micros(&self) -> u64 {
        self.micros
    }

    fn delay_ms(&mut self, ms: u32) {
        self.micros += ms as u64 * 1000;
    }
}
