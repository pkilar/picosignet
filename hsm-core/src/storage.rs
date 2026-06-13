//! Power-fail-safe flash storage.
//!
//! Two record types — [`DeviceConfig`] and [`KeyBlob`] — each live in an A/B
//! sector pair. A record is `magic | version | seq | len | payload | crc32`;
//! writes always target the *lower-seq* copy with `seq = max+1`, so the most
//! recent valid record survives an interruption mid-write. Reads pick the
//! highest-seq copy whose CRC validates.
//!
//! The PIN attempt counter ([`crate::pin`]) uses the `PinCounter` sector
//! directly with a bit-clear tick scheme and is handled there.

use alloc::vec;
use alloc::vec::Vec;
use crc::{Crc, CRC_32_ISO_HDLC};

use crate::hal::{FlashStore, HalError, Region, PAGE_LEN, SECTOR_LEN};

/// Record magic: ASCII "UHSM".
const MAGIC: [u8; 4] = *b"UHSM";
/// Record schema version. v2 moved the Argon2 salt out of [`DeviceConfig`] and
/// into [`KeyBlob`] so the wrapped seed and the salt that derives its KEK commit
/// as a single atomic record (a v1 split could strand the key on a torn write
/// during PIN rotation). v1 records are rejected by the version check.
const VERSION: u16 = 2;
/// Header bytes preceding the payload: magic(4) + version(2) + seq(4) + len(2).
const HEADER: usize = 12;

const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

/// An A/B sector pair providing atomic, power-fail-safe single-record storage.
#[derive(Clone, Copy)]
pub struct AbPair {
    pub a: Region,
    pub b: Region,
}

impl AbPair {
    pub const fn new(a: Region, b: Region) -> Self {
        AbPair { a, b }
    }

    /// Read the highest-seq valid record across both copies. Returns the
    /// payload bytes, or `None` if neither copy holds a valid record.
    pub fn read_latest<F: FlashStore>(&self, f: &mut F) -> Result<Option<Vec<u8>>, HalError> {
        let ra = read_record(f, self.a)?;
        let rb = read_record(f, self.b)?;
        Ok(match (ra, rb) {
            (None, None) => None,
            (Some((_, p)), None) => Some(p),
            (None, Some((_, p))) => Some(p),
            (Some((sa, pa)), Some((sb, pb))) => {
                if sa >= sb {
                    Some(pa)
                } else {
                    Some(pb)
                }
            }
        })
    }

    /// Write `payload` as a new record with `seq = max(existing)+1`, targeting
    /// the copy with the lower current seq so the newest prior record is
    /// preserved until this write completes.
    pub fn write<F: FlashStore>(&self, f: &mut F, payload: &[u8]) -> Result<(), HalError> {
        let sa = read_record(f, self.a)?.map(|(s, _)| s);
        let sb = read_record(f, self.b)?.map(|(s, _)| s);
        let max_seq = core::cmp::max(sa.unwrap_or(0), sb.unwrap_or(0));
        let new_seq = max_seq.wrapping_add(1);

        // Target the lower-seq (or missing) copy. Missing counts as seq 0.
        let target = if sa.unwrap_or(0) <= sb.unwrap_or(0) {
            self.a
        } else {
            self.b
        };
        write_record(f, target, new_seq, payload)
    }

    /// Erase both copies (factory reset).
    pub fn erase_both<F: FlashStore>(&self, f: &mut F) -> Result<(), HalError> {
        f.erase(self.a)?;
        f.erase(self.b)
    }
}

/// Parse the record in `region`, returning `(seq, payload)` if magic, version,
/// bounds, and CRC all validate.
fn read_record<F: FlashStore>(
    f: &mut F,
    region: Region,
) -> Result<Option<(u32, Vec<u8>)>, HalError> {
    let mut buf = vec![0u8; SECTOR_LEN];
    f.read(region, &mut buf)?;
    Ok(parse_record(&buf))
}

fn parse_record(sector: &[u8]) -> Option<(u32, Vec<u8>)> {
    if sector.len() < HEADER + 4 {
        return None;
    }
    if sector[0..4] != MAGIC {
        return None;
    }
    let version = u16::from_be_bytes([sector[4], sector[5]]);
    if version != VERSION {
        return None;
    }
    let seq = u32::from_be_bytes([sector[6], sector[7], sector[8], sector[9]]);
    let len = u16::from_be_bytes([sector[10], sector[11]]) as usize;
    let end = HEADER + len;
    if end + 4 > sector.len() {
        return None;
    }
    let stored = u32::from_be_bytes([
        sector[end],
        sector[end + 1],
        sector[end + 2],
        sector[end + 3],
    ]);
    if CRC32.checksum(&sector[..end]) != stored {
        return None;
    }
    Some((seq, sector[HEADER..end].to_vec()))
}

fn write_record<F: FlashStore>(
    f: &mut F,
    region: Region,
    seq: u32,
    payload: &[u8],
) -> Result<(), HalError> {
    let total = HEADER + payload.len() + 4;
    if total > SECTOR_LEN {
        return Err(HalError::OutOfRange);
    }
    let mut sector = vec![0xFFu8; SECTOR_LEN];
    sector[0..4].copy_from_slice(&MAGIC);
    sector[4..6].copy_from_slice(&VERSION.to_be_bytes());
    sector[6..10].copy_from_slice(&seq.to_be_bytes());
    sector[10..12].copy_from_slice(&(payload.len() as u16).to_be_bytes());
    sector[HEADER..HEADER + payload.len()].copy_from_slice(payload);
    let crc = CRC32.checksum(&sector[..HEADER + payload.len()]);
    let end = HEADER + payload.len();
    sector[end..end + 4].copy_from_slice(&crc.to_be_bytes());

    f.erase(region)?;
    // Program only the pages spanning the record; the rest stays erased.
    let pages = total.div_ceil(PAGE_LEN);
    for p in 0..pages {
        let off = p * PAGE_LEN;
        f.program(region, off, &sector[off..off + PAGE_LEN])?;
    }
    Ok(())
}

/// Device operating mode, persisted in [`DeviceConfig`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// Fully operational on plug-in; CA key wrapped under a device-ID key
    /// (obfuscation only).
    Dev,
    /// Requires PIN unlock; CA key wrapped under an Argon2id(PIN) key.
    Prod,
}

/// Argon2id work factors, persisted so a device's KDF cost is fixed at init and
/// future firmware can raise it on re-init.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Argon2Params {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Iteration (time) cost.
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub parallelism: u8,
}

/// Persistent device configuration (the `CONFIG_A`/`CONFIG_B` payload).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeviceConfig {
    pub mode: Mode,
    pub argon2: Argon2Params,
    pub max_retries: u8,
    pub wipe_on_lockout: bool,
    pub fw_version: [u8; 3],
}

impl DeviceConfig {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(16);
        v.push(match self.mode {
            Mode::Dev => 0,
            Mode::Prod => 1,
        });
        v.extend_from_slice(&self.argon2.m_cost.to_be_bytes());
        v.extend_from_slice(&self.argon2.t_cost.to_be_bytes());
        v.push(self.argon2.parallelism);
        v.push(self.max_retries);
        v.push(self.wipe_on_lockout as u8);
        v.extend_from_slice(&self.fw_version);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Option<DeviceConfig> {
        // 1 + 4 + 4 + 1 + 1 + 1 + 3 = 15 (the Argon2 salt now lives in KeyBlob)
        if b.len() < 15 {
            return None;
        }
        let mode = match b[0] {
            0 => Mode::Dev,
            1 => Mode::Prod,
            _ => return None,
        };
        let m_cost = u32::from_be_bytes([b[1], b[2], b[3], b[4]]);
        let t_cost = u32::from_be_bytes([b[5], b[6], b[7], b[8]]);
        let parallelism = b[9];
        let max_retries = b[10];
        let wipe_on_lockout = b[11] != 0;
        let fw_version = [b[12], b[13], b[14]];
        Some(DeviceConfig {
            mode,
            argon2: Argon2Params {
                m_cost,
                t_cost,
                parallelism,
            },
            max_retries,
            wipe_on_lockout,
            fw_version,
        })
    }
}

/// How the CA seed in a [`KeyBlob`] is wrapped. Discriminants 1/2 were the v1
/// wraps without the OTP device-secret binding; they are deliberately rejected
/// by [`KeyBlob::from_bytes`] so a v1 blob can never be presented to a v2
/// device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapType {
    /// OTP-secret-derived KEK (dev mode).
    DevKek = 3,
    /// Argon2id(PIN) + OTP-secret KEK (production).
    PinKek = 4,
}

/// The wrapped CA key record (`KEY_A`/`KEY_B` payload). The public key is stored
/// in the clear so `getPublicKey` works while the device is locked. The Argon2
/// `salt` is stored here (not in [`DeviceConfig`]) so the wrapped seed and the
/// salt that derives its KEK form one atomic record — a PIN rotation rewrites a
/// single KEY record and can never leave the seed wrapped under a salt that the
/// active config no longer matches. (`salt` is unused/zero for dev-mode wraps.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyBlob {
    pub wrap_type: WrapType,
    pub aead_nonce: [u8; 12],
    pub pubkey: [u8; 32],
    pub ciphertext: [u8; 32],
    pub tag: [u8; 16],
    pub salt: [u8; 16],
}

impl KeyBlob {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(1 + 12 + 32 + 32 + 16 + 16);
        v.push(self.wrap_type as u8);
        v.extend_from_slice(&self.aead_nonce);
        v.extend_from_slice(&self.pubkey);
        v.extend_from_slice(&self.ciphertext);
        v.extend_from_slice(&self.tag);
        v.extend_from_slice(&self.salt);
        v
    }

    pub fn from_bytes(b: &[u8]) -> Option<KeyBlob> {
        if b.len() < 109 {
            return None;
        }
        let wrap_type = match b[0] {
            3 => WrapType::DevKek,
            4 => WrapType::PinKek,
            _ => return None,
        };
        let mut aead_nonce = [0u8; 12];
        aead_nonce.copy_from_slice(&b[1..13]);
        let mut pubkey = [0u8; 32];
        pubkey.copy_from_slice(&b[13..45]);
        let mut ciphertext = [0u8; 32];
        ciphertext.copy_from_slice(&b[45..77]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&b[77..93]);
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&b[93..109]);
        Some(KeyBlob {
            wrap_type,
            aead_nonce,
            pubkey,
            ciphertext,
            tag,
            salt,
        })
    }
}

/// The config A/B pair.
pub const CONFIG: AbPair = AbPair::new(Region::ConfigA, Region::ConfigB);
/// The key A/B pair.
pub const KEY: AbPair = AbPair::new(Region::KeyA, Region::KeyB);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhal::MockFlash;

    #[test]
    fn config_roundtrip() {
        let cfg = DeviceConfig {
            mode: Mode::Prod,
            argon2: Argon2Params {
                m_cost: 64,
                t_cost: 8,
                parallelism: 1,
            },
            max_retries: 10,
            wipe_on_lockout: true,
            fw_version: [0, 1, 0],
        };
        assert_eq!(DeviceConfig::from_bytes(&cfg.to_bytes()), Some(cfg));
    }

    #[test]
    fn keyblob_roundtrip() {
        let kb = KeyBlob {
            wrap_type: WrapType::PinKek,
            aead_nonce: [1; 12],
            pubkey: [2; 32],
            ciphertext: [3; 32],
            tag: [4; 16],
            salt: [5; 16],
        };
        assert_eq!(KeyBlob::from_bytes(&kb.to_bytes()), Some(kb));
    }

    #[test]
    fn ab_write_read_latest() {
        let mut f = MockFlash::new();
        assert_eq!(CONFIG.read_latest(&mut f).unwrap(), None);
        CONFIG.write(&mut f, b"first").unwrap();
        assert_eq!(
            CONFIG.read_latest(&mut f).unwrap().as_deref(),
            Some(&b"first"[..])
        );
        CONFIG.write(&mut f, b"second").unwrap();
        assert_eq!(
            CONFIG.read_latest(&mut f).unwrap().as_deref(),
            Some(&b"second"[..])
        );
        CONFIG.write(&mut f, b"third").unwrap();
        assert_eq!(
            CONFIG.read_latest(&mut f).unwrap().as_deref(),
            Some(&b"third"[..])
        );
    }

    #[test]
    fn ab_survives_corrupt_newer_copy() {
        // Simulate a torn write: newest copy corrupted, older valid copy remains.
        let mut f = MockFlash::new();
        CONFIG.write(&mut f, b"good-old").unwrap(); // seq1 -> A
        CONFIG.write(&mut f, b"good-new").unwrap(); // seq2 -> B
                                                    // Corrupt B (the higher-seq copy) by flipping a payload byte.
        f.corrupt(Region::ConfigB, HEADER, 0xFF);
        // read_latest must fall back to the valid older A copy.
        assert_eq!(
            CONFIG.read_latest(&mut f).unwrap().as_deref(),
            Some(&b"good-old"[..])
        );
    }

    #[test]
    fn corruption_at_every_offset_never_panics() {
        // Power-fail fuzzing: corrupting any single byte must yield a clean
        // None/older-copy result, never a panic or out-of-bounds.
        for off in 0..(HEADER + 5 + 4) {
            let mut f = MockFlash::new();
            CONFIG.write(&mut f, b"hello").unwrap();
            f.corrupt(Region::ConfigA, off, 0x00);
            f.corrupt(Region::ConfigA, off, 0xFF);
            let _ = CONFIG.read_latest(&mut f).unwrap();
        }
    }
}
