//! `EntropySource` for the RP2040, which has no hardware TRNG.
//!
//! Raw entropy comes from the ring oscillator's `RANDOMBIT` register, sampled
//! with a small inter-read delay and von Neumann debiased to remove first-order
//! bias. The output is *pure* ROSC so `hsm-core`'s startup health checks (which
//! must see the real source to catch a stuck oscillator) remain meaningful.
//!
//! Supplementary per-boot entropy from uninitialized SRAM is exposed separately
//! via [`boot_noise`] and folded into the DRBG by the firmware *after* seeding,
//! so it can never mask a ROSC fault.

use core::mem::MaybeUninit;

use cortex_m::asm;
use hsm_core::hal::{EntropySource, HalError};

/// RP2040 ROSC `RANDOMBIT` register (ROSC_BASE 0x40060000 + 0x1C). Bit 0 is a
/// free-running random bit. Read via raw MMIO to avoid coupling to embassy-rp's
/// private PAC re-export.
const ROSC_RANDOMBIT: *const u32 = 0x4006_001C as *const u32;

/// Pure ROSC entropy source.
pub struct RoscEntropy;

impl Default for RoscEntropy {
    fn default() -> Self {
        RoscEntropy
    }
}

impl RoscEntropy {
    pub fn new() -> Self {
        RoscEntropy
    }

    /// One raw ROSC random bit.
    #[inline]
    fn raw_bit() -> u8 {
        // SAFETY: ROSC_RANDOMBIT is a valid read-only RP2040 MMIO register.
        (unsafe { core::ptr::read_volatile(ROSC_RANDOMBIT) } & 1) as u8
    }

    /// One sample with a decorrelating delay. The ROSC runs asynchronously to
    /// the core clock; reads too close together are correlated and defeat the
    /// von Neumann debiasing, so we space them ~2 µs apart (≈250 cycles at the
    /// 125 MHz default clock). This keeps the conditioned output passing the
    /// startup health checks on real hardware.
    #[inline]
    fn sample() -> u8 {
        asm::delay(250);
        Self::raw_bit()
    }

    /// One von Neumann-debiased bit: sample pairs until they differ, emit the
    /// first of the differing pair.
    fn debiased_bit() -> u8 {
        loop {
            let a = Self::sample();
            let b = Self::sample();
            if a != b {
                return a;
            }
        }
    }
}

impl EntropySource for RoscEntropy {
    fn fill_raw(&mut self, buf: &mut [u8]) -> Result<(), HalError> {
        for byte in buf.iter_mut() {
            let mut b = 0u8;
            for i in 0..8 {
                b |= Self::debiased_bit() << i;
            }
            *byte = b;
        }
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
