//! Hardware abstraction layer.
//!
//! `hsm-core` is hardware-agnostic: it talks to the world only through these
//! traits. The firmware implements them over real RP2040 peripherals; the host
//! tests and `hsm-sim` implement them in memory. The split is what makes the
//! security logic testable without a chip.

use core::fmt;

/// Errors a HAL implementation can surface. Kept coarse on purpose — the core
/// maps these onto protocol error codes; fine-grained peripheral detail stays
/// in the firmware logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HalError {
    /// A flash read/erase/program operation failed.
    Flash,
    /// The entropy source could not produce healthy randomness.
    Entropy,
    /// A caller passed an out-of-range region/offset (programming error).
    OutOfRange,
}

impl fmt::Display for HalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HalError::Flash => f.write_str("flash operation failed"),
            HalError::Entropy => f.write_str("entropy source unavailable"),
            HalError::OutOfRange => f.write_str("flash region/offset out of range"),
        }
    }
}

/// Raw, *unconditioned* entropy. The core's DRBG ([`crate::rng`]) is
/// responsible for health-testing and conditioning whatever this returns — an
/// implementation may return biased or low-rate bits (e.g. RP2040 ROSC
/// sampling) and the core will whiten them. Implementations must never block
/// indefinitely; on hardware fault return [`HalError::Entropy`].
pub trait EntropySource {
    /// Fill `buf` with raw entropy bytes. May be slow (the core only calls
    /// this during seeding/reseeding, never per-signature once the DRBG is up).
    fn fill_raw(&mut self, buf: &mut [u8]) -> Result<(), HalError>;
}

/// A monotonic clock that never goes backwards across the device's power-on
/// lifetime. Used to derive wall-clock time (monotonic + a host-supplied
/// offset, see [`crate::clock`]) and to drive PIN-failure backoff.
pub trait Monotonic {
    /// Microseconds since an arbitrary fixed epoch (typically power-on).
    fn now_micros(&self) -> u64;
    /// Busy/sleep for at least `ms` milliseconds. Used for PIN backoff; the
    /// firmware may yield to the async executor, the host mock may no-op.
    fn delay_ms(&mut self, ms: u32);
}

/// Logical flash regions. The firmware maps each to a fixed sector offset (see
/// `docs/FLASH_LAYOUT.md`); the core only ever names them symbolically so the
/// layout can change without touching core logic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Region {
    /// Primary device-config record (mode, Argon2 params, salt, retry policy).
    ConfigA,
    /// Redundant device-config copy (A/B power-fail safety).
    ConfigB,
    /// Primary wrapped CA-key record.
    KeyA,
    /// Redundant wrapped CA-key copy.
    KeyB,
    /// PIN attempt-counter sector (bit-clear tick log).
    PinCounter,
}

/// Block flash access. Every region is exactly [`FlashStore::SECTOR`] bytes and
/// erases as a unit; programming is page-granular.
///
/// On RP2040 these operations run the bootrom flash routines from RAM with
/// interrupts masked, so a call may stall the USB stack for tens to hundreds of
/// milliseconds. The core only writes flash during provisioning/unlock, never
/// concurrently with a signing hot path, so this is acceptable.
pub trait FlashStore {
    /// Erase granularity and the size of every [`Region`]. RP2040 = 4096.
    const SECTOR: usize = 4096;
    /// Program granularity. RP2040 = 256.
    const PAGE: usize = 256;

    /// Read the entire sector backing `region` into `buf` (must be
    /// `>= SECTOR`).
    fn read(&mut self, region: Region, buf: &mut [u8]) -> Result<(), HalError>;
    /// Erase the sector backing `region` to all-`0xFF`.
    fn erase(&mut self, region: Region) -> Result<(), HalError>;
    /// Program one [`FlashStore::PAGE`]-sized page at `offset` within `region`.
    /// `offset` must be page-aligned and within the sector.
    fn program(&mut self, region: Region, offset: usize, page: &[u8]) -> Result<(), HalError>;

    /// The chip's unique 64-bit ID (RP2040 reads it from the QSPI flash). Used
    /// as personalization for entropy and to derive the dev-mode wrapping key.
    /// Stable across reboots and unique per device.
    fn unique_id(&self) -> [u8; 8];
}

/// Convenience: the common sector size as a `usize` constant for buffer sizing
/// in code that is generic over `F: FlashStore` but wants a stack array.
pub const SECTOR_LEN: usize = 4096;
/// Convenience: the common page size.
pub const PAGE_LEN: usize = 256;

// Forwarding impls so a `&mut T` can be used wherever a HAL trait is required
// (e.g. driving an `Hsm` over a borrowed flash image across "reboots" in tests
// and the simulator's `--state-file` mode).
impl<T: EntropySource> EntropySource for &mut T {
    fn fill_raw(&mut self, buf: &mut [u8]) -> Result<(), HalError> {
        (**self).fill_raw(buf)
    }
}

impl<T: Monotonic> Monotonic for &mut T {
    fn now_micros(&self) -> u64 {
        (**self).now_micros()
    }
    fn delay_ms(&mut self, ms: u32) {
        (**self).delay_ms(ms)
    }
}

impl<T: FlashStore> FlashStore for &mut T {
    const SECTOR: usize = T::SECTOR;
    const PAGE: usize = T::PAGE;
    fn read(&mut self, region: Region, buf: &mut [u8]) -> Result<(), HalError> {
        (**self).read(region, buf)
    }
    fn erase(&mut self, region: Region) -> Result<(), HalError> {
        (**self).erase(region)
    }
    fn program(&mut self, region: Region, offset: usize, page: &[u8]) -> Result<(), HalError> {
        (**self).program(region, offset, page)
    }
    fn unique_id(&self) -> [u8; 8] {
        (**self).unique_id()
    }
}
