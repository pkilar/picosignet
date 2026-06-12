//! `EntropySource` over the RP2350's hardware TRNG.
//!
//! The TRNG block samples a dedicated ring oscillator and returns raw 192-bit
//! entropy blocks. We run it with the hardware post-processing (von Neumann
//! balancer, autocorrelation/CRNGT tests) bypassed so `hsm-core`'s own startup
//! health checks (repetition-count + adaptive-proportion) see the *real*
//! source — a stuck or biased oscillator must fail our gates, not be papered
//! over in hardware — and the SHA-512 conditioner + ChaCha20 DRBG remain the
//! trust boundary, exactly as with the RP2040 ROSC design this replaces.
//!
//! Supplementary per-boot entropy from uninitialized SRAM is exposed separately
//! via [`boot_noise`] and folded into the DRBG by the firmware *after* seeding,
//! so it can never mask a TRNG fault.

use core::mem::MaybeUninit;

use embassy_rp::peripherals::TRNG;
use embassy_rp::trng::{Config, Trng};
use hsm_core::hal::{EntropySource, HalError};

/// Hardware TRNG entropy source.
pub struct TrngEntropy<'d> {
    trng: Trng<'d, TRNG>,
}

impl<'d> TrngEntropy<'d> {
    /// Wrap an initialized TRNG driver.
    pub fn new(trng: Trng<'d, TRNG>) -> Self {
        Self { trng }
    }

    /// TRNG configuration: hardware tests stay bypassed (see module docs); the
    /// inter-sample period is doubled from the 25-cycle default for extra
    /// decorrelation headroom — throughput is irrelevant next to Argon2id.
    pub fn config() -> Config {
        let mut cfg = Config::default();
        cfg.sample_count = 50;
        cfg
    }
}

impl EntropySource for TrngEntropy<'_> {
    fn fill_raw(&mut self, buf: &mut [u8]) -> Result<(), HalError> {
        self.trng.blocking_fill_bytes(buf);
        Ok(())
    }
}

/// Size of the SRAM region harvested at boot.
const BOOT_NOISE_LEN: usize = 256;

/// Uninitialized SRAM, left untouched by the cortex-m-rt startup (it neither
/// zeroes `.uninit` nor copies it from flash), so it holds power-on bus/SRAM
/// state. Used as supplementary entropy only.
#[link_section = ".uninit.boot_noise"]
static mut BOOT_NOISE: MaybeUninit<[u8; BOOT_NOISE_LEN]> = MaybeUninit::uninit();

/// Snapshot the boot SRAM noise. Reads are volatile to make the intent (harvest
/// whatever was there at power-on) explicit and avoid the optimizer assuming a
/// fixed value.
pub fn boot_noise() -> [u8; BOOT_NOISE_LEN] {
    let mut out = [0u8; BOOT_NOISE_LEN];
    let base = core::ptr::addr_of!(BOOT_NOISE) as *const u8;
    for (i, b) in out.iter_mut().enumerate() {
        // SAFETY: reading within the BOOT_NOISE static's bytes; value is
        // intentionally indeterminate (entropy harvest).
        *b = unsafe { core::ptr::read_volatile(base.add(i)) };
    }
    out
}
