//! RP2350 security hardware: voltage-glitch detectors and boot security
//! status.
//!
//! The glitch detectors watch the core supply for fault-injection transients;
//! when armed, any trigger hard-resets the switched-core power domain (no
//! interrupt, no chance for compromised code to intervene). We arm them at
//! every boot from firmware and lock the configuration until the next reset;
//! production provisioning can additionally force-arm them from boot ROM via
//! `CRIT1.GLITCH_DETECTOR_ENABLE` (see `docs/PROVISIONING.md`), which makes
//! this call redundant-but-harmless.

use rp_pac::glitch_detector::vals::{Arm, Default as SensDefault};
use rp_pac::{GLITCH_DETECTOR, POWMAN};

/// Detector sensitivity, 0..=3 (higher = more sensitive). 0b10 is the
/// second-highest setting; drop to 0b01 if HIL shows spurious resets.
const SENSITIVITY: u8 = 0b10;

/// Arm the glitch detectors with our sensitivity and lock the configuration
/// (ARM/DISARM/SENSITIVITY/LOCK become read-only until reset). Returns whether
/// the detectors report armed. All these registers are Secure-access only; we
/// run as the secure executable.
pub fn arm_glitch_detectors() -> bool {
    GLITCH_DETECTOR.sensitivity().write(|w| {
        w.set_det0(SENSITIVITY);
        w.set_det1(SENSITIVITY);
        w.set_det2(SENSITIVITY);
        w.set_det3(SENSITIVITY);
        // Each field needs its inverse alongside, else the hardware falls
        // back to the OTP default.
        w.set_det0_inv(!SENSITIVITY & 0x3);
        w.set_det1_inv(!SENSITIVITY & 0x3);
        w.set_det2_inv(!SENSITIVITY & 0x3);
        w.set_det3_inv(!SENSITIVITY & 0x3);
        w.set_default(SensDefault::NO);
    });
    GLITCH_DETECTOR.arm().write(|w| w.set_arm(Arm::YES));
    let armed = GLITCH_DETECTOR.arm().read().arm() == Arm::YES;
    GLITCH_DETECTOR.lock().write(|w| w.set_lock(1));
    armed
}

/// Whether the bootrom enforces signed boot: `CRIT1.SECURE_BOOT_ENABLE`
/// (OTP row 0x40 bit 0, burned at production stage P4). The critical rows are
/// 8x redundant and majority-voted by hardware/bootrom; a raw read of the
/// first row is fine for status reporting.
pub fn secure_boot_enabled() -> bool {
    embassy_rp::otp::read_raw_word(0x40)
        .map(|w| w & 1 != 0)
        .unwrap_or(false)
}

/// Whether the last chip reset was caused by a glitch-detector trigger —
/// surfaced in `status` so HIL can distinguish fault-injection (or a too-hot
/// sensitivity) from normal power cycles.
pub fn last_reset_was_glitch() -> bool {
    POWMAN.chip_reset().read().had_glitch_detect()
}
