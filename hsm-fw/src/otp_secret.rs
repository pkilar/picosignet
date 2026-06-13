//! Per-device wrapping secret in on-die OTP.
//!
//! A 32-byte secret, generated on first boot from the health-checked DRBG and
//! burned into a dedicated OTP page, binds both the dev and prod KEKs to this
//! physical chip: a dump of the external QSPI flash alone can never unwrap the
//! CA key. Defense layers:
//!
//! - **Hard page lock** (OTP `PAGEn_LOCK1`, written right after provisioning):
//!   secure firmware may read the page, but the bootloader/picotool (`BL`) and
//!   any non-secure code can never access it, and nobody can write it again.
//! - **Runtime SW_LOCK** ([`lock_slots`], every boot): after the secret is
//!   copied to RAM the page becomes inaccessible even to secure code until the
//!   next reset.
//! - Until `SECURE_BOOT_ENABLE` is burned (production stage, see
//!   `docs/PROVISIONING.md`), any firmware runs as "secure" and could read the
//!   page before locking it — confidentiality against malicious *reflash*
//!   starts at that burn; resistance to flash *chip-off* is immediate.
//!
//! Anti-brick discipline (OTP writes are irreversible): the validity marker is
//! written **last** with read-back verification of every row, so a torn or
//! failed provisioning never presents a half-written secret as valid; a failed
//! slot is voided and the fallback page used. Worst case wastes 2 of 64 pages
//! and the device reports `ERR_INTERNAL` rather than ever using a bad secret.

use embassy_rp::otp;
use hsm_core::hal::{EntropySource, HalError};
use hsm_core::rng::Drbg;
use rand_core::RngCore;
use rp_pac::otp::vals::{SwLockNsec, SwLockSec};
use zeroize::Zeroizing;

/// OTP pages reserved for the secret, tried in order (primary, fallback).
/// High pages, far away from the bootrom's own allocations in pages 0-2.
const SLOT_PAGES: [usize; 2] = [61, 60];
/// ECC rows per page.
const ROWS_PER_PAGE: usize = 64;
/// 16 ECC rows x 16 data bits = the 32-byte secret.
const SECRET_ROWS: usize = 16;
/// Marker row (base+16) value: slot holds a verified secret.
const MARKER_VALID: u16 = 0xA5C3;
/// Void row (base+17) value: slot is abandoned forever (failed verify, dirty
/// state, or degenerate content) — never trust or rewrite it.
const MARKER_VOID: u16 = 0xDEAD;

/// LOCK1 access byte `0x3D` = S: read-only, NS: inaccessible, BL: inaccessible,
/// majority-encoded three times into the 24-bit raw row.
const LOCK1_VALUE: u32 = 0x003D_3D3D;

/// Page-lock rows live in the last OTP pages: `PAGEn_LOCK0` = 0xF80+2n,
/// `PAGEn_LOCK1` = 0xF80+2n+1 (raw rows, 3-byte majority vote).
const fn lock1_row(page: usize) -> usize {
    0xF80 + 2 * page + 1
}

const fn base_row(page: usize) -> usize {
    page * ROWS_PER_PAGE
}

enum SlotState {
    /// Slot holds a verified secret (already re-hard-locked if needed).
    Valid(Zeroizing<[u8; 32]>),
    /// Slot is fully blank and may be provisioned.
    Blank,
    /// Slot is voided, dirty, or unreadable — skip it.
    Unusable,
}

/// Load the device secret, provisioning it on first boot.
///
/// Call once at boot, **before** [`lock_slots`]. Fails closed: any error path
/// yields `HalError::Secret`/`Entropy` and the caller must surface an
/// unusable-KEK state rather than continue with a degenerate secret.
pub fn load_or_provision<E: EntropySource>(
    entropy: &mut E,
) -> Result<Zeroizing<[u8; 32]>, HalError> {
    for &page in &SLOT_PAGES {
        let secret = match try_load(page) {
            SlotState::Valid(secret) => secret,
            SlotState::Blank => match provision(page, entropy) {
                Ok(secret) => secret,
                // Entropy failure is global, not per-slot: don't burn the
                // fallback page on a sick TRNG.
                Err(HalError::Entropy) => return Err(HalError::Entropy),
                Err(_) => continue,
            },
            SlotState::Unusable => continue,
        };
        // Defense in depth: once a valid secret exists, hard-lock BOTH pages
        // (best effort on the inactive one) so nobody can plant a forged
        // fallback slot via picotool while the device awaits its secure-boot
        // burn. Provisioning never runs again, so the spare page is dead
        // weight either way.
        for &p in &SLOT_PAGES {
            if p != page {
                let _ = ensure_hard_lock(p);
            }
        }
        return Ok(secret);
    }
    Err(HalError::Secret)
}

/// Make the secret pages inaccessible (even to secure code) until next reset.
///
/// Call unconditionally after [`load_or_provision`], success or failure, before
/// the USB loop starts. SW_LOCK writes OR into the lock state, so this can only
/// ever tighten.
pub fn lock_slots() {
    for &page in &SLOT_PAGES {
        rp_pac::OTP.sw_lock(page).write(|w| {
            w.set_sec(SwLockSec::INACCESSIBLE);
            w.set_nsec(SwLockNsec::INACCESSIBLE);
        });
    }
}

fn try_load(page: usize) -> SlotState {
    let base = base_row(page);
    let marker = match otp::read_ecc_word(base + SECRET_ROWS) {
        Ok(v) => v,
        Err(_) => return SlotState::Unusable,
    };
    let void = match otp::read_ecc_word(base + SECRET_ROWS + 1) {
        Ok(v) => v,
        Err(_) => return SlotState::Unusable,
    };
    if void != 0 {
        return SlotState::Unusable;
    }

    if marker == MARKER_VALID {
        let mut secret = Zeroizing::new([0u8; 32]);
        for i in 0..SECRET_ROWS {
            match otp::read_ecc_word(base + i) {
                Ok(w) => {
                    secret[2 * i..2 * i + 2].copy_from_slice(&w.to_le_bytes());
                }
                Err(_) => return SlotState::Unusable,
            }
        }
        if degenerate(&secret) {
            void_slot(page);
            return SlotState::Unusable;
        }
        // Heal the (tiny) marker-written-but-not-yet-locked power-loss window:
        // a valid secret must never sit in a page picotool can read.
        if ensure_hard_lock(page).is_err() {
            void_slot(page);
            return SlotState::Unusable;
        }
        return SlotState::Valid(secret);
    }

    if marker != 0 {
        // Unknown marker value: treat as dirty, abandon.
        void_slot(page);
        return SlotState::Unusable;
    }

    // Marker blank: only a fully blank slot is provisionable.
    for i in 0..SECRET_ROWS {
        match otp::read_ecc_word(base + i) {
            Ok(0) => {}
            _ => {
                void_slot(page);
                return SlotState::Unusable;
            }
        }
    }
    SlotState::Blank
}

/// Burn a fresh secret into `page`: rows write-and-verified one by one, the
/// validity marker last, then the permanent page lock.
fn provision<E: EntropySource>(
    page: usize,
    entropy: &mut E,
) -> Result<Zeroizing<[u8; 32]>, HalError> {
    // Health-checked, SHA-512-conditioned randomness — never raw TRNG output.
    let mut drbg = Drbg::new();
    drbg.seed(entropy)?;
    let mut secret = Zeroizing::new([0u8; 32]);
    drbg.fill_bytes(&mut secret[..]);
    if degenerate(&secret) {
        return Err(HalError::Entropy);
    }

    let base = base_row(page);
    for i in 0..SECRET_ROWS {
        let w = u16::from_le_bytes([secret[2 * i], secret[2 * i + 1]]);
        if write_verified(base + i, w).is_err() {
            void_slot(page);
            return Err(HalError::Secret);
        }
    }
    if write_verified(base + SECRET_ROWS, MARKER_VALID).is_err() {
        void_slot(page);
        return Err(HalError::Secret);
    }
    // Without the hard lock the page is picotool-readable, which voids the
    // whole at-rest story — an unlockable slot is an unusable slot.
    if ensure_hard_lock(page).is_err() {
        void_slot(page);
        return Err(HalError::Secret);
    }
    Ok(secret)
}

/// Write one ECC row and read it back.
fn write_verified(row: usize, value: u16) -> Result<(), HalError> {
    otp::write_ecc_word(row, value).map_err(|_| HalError::Secret)?;
    match otp::read_ecc_word(row) {
        Ok(v) if v == value => Ok(()),
        _ => Err(HalError::Secret),
    }
}

/// Set (or confirm) the permanent page lock. OTP bits only ever set, so
/// re-writing an already-locked row is a no-op.
fn ensure_hard_lock(page: usize) -> Result<(), HalError> {
    let row = lock1_row(page);
    let cur = otp::read_raw_word(row).map_err(|_| HalError::Secret)?;
    if cur & LOCK1_VALUE == LOCK1_VALUE {
        return Ok(());
    }
    otp::write_raw_word(row, LOCK1_VALUE).map_err(|_| HalError::Secret)?;
    match otp::read_raw_word(row) {
        Ok(v) if v & LOCK1_VALUE == LOCK1_VALUE => Ok(()),
        _ => Err(HalError::Secret),
    }
}

/// Best-effort: mark a slot permanently abandoned.
fn void_slot(page: usize) {
    let _ = otp::write_ecc_word(base_row(page) + SECRET_ROWS + 1, MARKER_VOID);
}

/// All-equal bytes mean a stuck read path or catastrophic RNG failure.
fn degenerate(secret: &[u8; 32]) -> bool {
    secret.iter().all(|&b| b == 0x00) || secret.iter().all(|&b| b == 0xFF)
}
