//! `FlashStore` over the RP2350's QSPI flash (Embassy blocking driver).
//!
//! The five HSM regions map to fixed offsets in the last sectors of the 4 MiB
//! flash, kept out of the firmware's FLASH region by `memory.x`. Blocking flash
//! ops run the bootrom routines from RAM with interrupts masked; the device
//! processes one request at a time, so a multi-hundred-millisecond erase never
//! races a signing operation.

use embassy_rp::flash::{Blocking, Flash};
use embassy_rp::peripherals::FLASH;
use hsm_core::hal::{FlashStore, HalError, Region, SECTOR_LEN};

/// Total flash size on the Waveshare RP2350-One (4 MiB).
const FLASH_SIZE: usize = 4 * 1024 * 1024;

// Region base offsets from the start of flash. Must match memory.x and
// docs/FLASH_LAYOUT.md.
const CONFIG_A: u32 = 0x3FA000;
const CONFIG_B: u32 = 0x3FB000;
const KEY_A: u32 = 0x3FC000;
const KEY_B: u32 = 0x3FD000;
const PIN_COUNTER: u32 = 0x3FE000;
const SECTOR: u32 = SECTOR_LEN as u32;

/// Embassy-backed flash store.
pub struct EmbassyFlash<'d> {
    flash: Flash<'d, FLASH, Blocking, FLASH_SIZE>,
    unique_id: [u8; 8],
}

impl<'d> EmbassyFlash<'d> {
    /// Take the FLASH peripheral, read the chip id, and wrap it.
    pub fn new(flash: FLASH) -> Self {
        let flash = Flash::<_, Blocking, FLASH_SIZE>::new_blocking(flash);
        // RP2350: the device serial comes from the factory-programmed chip id
        // in OTP (rows 0x000-0x003) — on-die, unlike the RP2040's QSPI-flash
        // UID. A failure leaves it all-zero; the serial degrades gracefully
        // rather than panicking at boot.
        let uid = embassy_rp::otp::get_chipid()
            .map(u64::to_be_bytes)
            .unwrap_or([0u8; 8]);
        EmbassyFlash {
            flash,
            unique_id: uid,
        }
    }

    fn base(region: Region) -> u32 {
        match region {
            Region::ConfigA => CONFIG_A,
            Region::ConfigB => CONFIG_B,
            Region::KeyA => KEY_A,
            Region::KeyB => KEY_B,
            Region::PinCounter => PIN_COUNTER,
        }
    }
}

impl FlashStore for EmbassyFlash<'_> {
    fn read(&mut self, region: Region, buf: &mut [u8]) -> Result<(), HalError> {
        if buf.len() < SECTOR_LEN {
            return Err(HalError::OutOfRange);
        }
        self.flash
            .blocking_read(Self::base(region), &mut buf[..SECTOR_LEN])
            .map_err(|_| HalError::Flash)
    }

    fn erase(&mut self, region: Region) -> Result<(), HalError> {
        let base = Self::base(region);
        self.flash
            .blocking_erase(base, base + SECTOR)
            .map_err(|_| HalError::Flash)
    }

    fn program(&mut self, region: Region, offset: usize, page: &[u8]) -> Result<(), HalError> {
        if offset + page.len() > SECTOR_LEN {
            return Err(HalError::OutOfRange);
        }
        self.flash
            .blocking_write(Self::base(region) + offset as u32, page)
            .map_err(|_| HalError::Flash)
    }

    fn unique_id(&self) -> [u8; 8] {
        self.unique_id
    }

    fn device_secret(&self) -> Result<[u8; 32], HalError> {
        // Fail closed until the OTP secret provisioning lands (next commit).
        Err(HalError::Secret)
    }
}
