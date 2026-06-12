//! A conditioned DRBG for a chip with no hardware TRNG.
//!
//! Raw entropy from the [`EntropySource`] (RP2040 ROSC sampling, ADC noise,
//! SRAM startup state) is health-checked, then conditioned through SHA-512 into
//! a ChaCha20 DRBG. The DRBG is reseeded before key generation and can mix in
//! host-supplied entropy additively (never as a sole source).
//!
//! The health checks are a pragmatic subset of NIST SP 800-90B's startup tests
//! — a repetition-count test (catches a stuck source) and an adaptive-
//! proportion test (catches gross bias). They gate seeding and key generation;
//! a failure surfaces as `ERR_ENTROPY`.

use rand_chacha::ChaCha20Rng;
use rand_core::{CryptoRng, RngCore, SeedableRng};
use sha2::{Digest, Sha512};
use zeroize::Zeroize;

use crate::hal::{EntropySource, HalError};

/// Raw bytes sampled per (re)seed.
const SEED_SAMPLE: usize = 256;
/// Outputs between recommended reseeds (firmware polls [`Drbg::since_reseed`]).
pub const RESEED_INTERVAL: u64 = 64;
/// Repetition-count cutoff: this many identical consecutive bytes fails.
const RCT_CUTOFF: usize = 24;
/// Adaptive-proportion cutoff: any byte value exceeding this count fails.
const APT_MAX: usize = SEED_SAMPLE / 4;
/// How many fresh samples to draw before declaring the source unhealthy. A
/// physical source (RP2040 ROSC) can produce an occasional sample that trips the
/// startup checks; retrying absorbs that while a genuinely dead/stuck source
/// still fails every attempt.
const MAX_HEALTH_RETRIES: u8 = 16;

/// A health-checked, SHA-512-conditioned ChaCha20 DRBG.
pub struct Drbg {
    rng: ChaCha20Rng,
    seeded: bool,
    since_reseed: u64,
}

impl Default for Drbg {
    fn default() -> Self {
        Self::new()
    }
}

impl Drbg {
    /// Create an unseeded DRBG. [`Drbg::seed`] must be called before use; the
    /// dispatcher does this at boot and fails closed if entropy is unhealthy.
    pub fn new() -> Self {
        Drbg {
            rng: ChaCha20Rng::from_seed([0u8; 32]),
            seeded: false,
            since_reseed: 0,
        }
    }

    pub fn is_seeded(&self) -> bool {
        self.seeded
    }

    pub fn since_reseed(&self) -> u64 {
        self.since_reseed
    }

    /// Seed from raw entropy after health-checking it.
    pub fn seed<E: EntropySource>(&mut self, e: &mut E) -> Result<(), HalError> {
        let mut raw = [0u8; SEED_SAMPLE];
        gather_healthy(e, &mut raw)?;
        self.reinit(b"usbhsm-drbg-seed-v1", None, &raw);
        raw.zeroize();
        self.seeded = true;
        Ok(())
    }

    /// Reseed, folding the current state together with fresh health-checked
    /// entropy. Call before generating the CA key.
    pub fn reseed<E: EntropySource>(&mut self, e: &mut E) -> Result<(), HalError> {
        let mut raw = [0u8; SEED_SAMPLE];
        gather_healthy(e, &mut raw)?;
        let mut cur = [0u8; 32];
        self.rng.fill_bytes(&mut cur);
        self.reinit(b"usbhsm-drbg-reseed-v1", Some(&cur), &raw);
        cur.zeroize();
        raw.zeroize();
        Ok(())
    }

    /// Mix host-supplied entropy into the pool. Additive hardening only — the
    /// host bytes are never the sole source of randomness.
    pub fn mix_host(&mut self, host: &[u8]) {
        let mut cur = [0u8; 32];
        self.rng.fill_bytes(&mut cur);
        self.reinit(b"usbhsm-drbg-mix-host-v1", Some(&cur), host);
        cur.zeroize();
    }

    /// Re-key the ChaCha DRBG from `SHA-512(domain || prev? || material)[..32]`.
    fn reinit(&mut self, domain: &[u8], prev: Option<&[u8]>, material: &[u8]) {
        let mut h = Sha512::new();
        h.update(domain);
        if let Some(p) = prev {
            h.update(p);
        }
        h.update(material);
        let digest = h.finalize();
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&digest[..32]);
        self.rng = ChaCha20Rng::from_seed(seed);
        seed.zeroize();
        self.since_reseed = 0;
    }

    fn bump(&mut self) {
        self.since_reseed = self.since_reseed.saturating_add(1);
    }
}

/// Draw fresh samples until one passes the health checks, up to
/// [`MAX_HEALTH_RETRIES`]. A persistently failing source yields
/// [`HalError::Entropy`].
fn gather_healthy<E: EntropySource>(e: &mut E, out: &mut [u8]) -> Result<(), HalError> {
    for _ in 0..MAX_HEALTH_RETRIES {
        e.fill_raw(out)?;
        if health_check(out).is_ok() {
            return Ok(());
        }
    }
    Err(HalError::Entropy)
}

/// SP 800-90B-style startup health checks on a raw entropy sample.
fn health_check(raw: &[u8]) -> Result<(), HalError> {
    // Repetition-count test: a long run of one value indicates a stuck source.
    let mut run = 1usize;
    let mut max_run = 1usize;
    for i in 1..raw.len() {
        if raw[i] == raw[i - 1] {
            run += 1;
            max_run = max_run.max(run);
        } else {
            run = 1;
        }
    }
    if max_run >= RCT_CUTOFF {
        return Err(HalError::Entropy);
    }

    // Adaptive-proportion test: a value appearing far more than chance
    // indicates gross bias.
    let mut counts = [0usize; 256];
    for &b in raw {
        counts[b as usize] += 1;
    }
    if counts.iter().any(|&c| c > APT_MAX) {
        return Err(HalError::Entropy);
    }
    Ok(())
}

impl RngCore for Drbg {
    fn next_u32(&mut self) -> u32 {
        self.bump();
        self.rng.next_u32()
    }
    fn next_u64(&mut self) -> u64 {
        self.bump();
        self.rng.next_u64()
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.bump();
        self.rng.fill_bytes(dest)
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.bump();
        self.rng.try_fill_bytes(dest)
    }
}

impl CryptoRng for Drbg {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhal::MockEntropy;

    #[test]
    fn seeds_from_healthy_source() {
        let mut e = MockEntropy::new(12345);
        let mut d = Drbg::new();
        assert!(!d.is_seeded());
        d.seed(&mut e).unwrap();
        assert!(d.is_seeded());
    }

    #[test]
    fn same_entropy_gives_same_stream() {
        let mut d1 = Drbg::new();
        let mut d2 = Drbg::new();
        d1.seed(&mut MockEntropy::new(7)).unwrap();
        d2.seed(&mut MockEntropy::new(7)).unwrap();
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        d1.fill_bytes(&mut a);
        d2.fill_bytes(&mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn health_check_rejects_stuck_source() {
        let stuck = [0u8; SEED_SAMPLE];
        assert_eq!(health_check(&stuck), Err(HalError::Entropy));
    }

    #[test]
    fn health_check_rejects_biased_source() {
        // 60% one value — exceeds the 25% adaptive-proportion cutoff.
        let mut biased = [0u8; SEED_SAMPLE];
        for (i, b) in biased.iter_mut().enumerate() {
            *b = if i % 5 == 0 { (i & 0xff) as u8 } else { 0xAA };
        }
        assert_eq!(health_check(&biased), Err(HalError::Entropy));
    }

    #[test]
    fn health_check_accepts_uniform_source() {
        let mut e = MockEntropy::new(99);
        let mut raw = [0u8; SEED_SAMPLE];
        e.fill_raw(&mut raw).unwrap();
        assert_eq!(health_check(&raw), Ok(()));
    }

    #[test]
    fn reseed_changes_stream() {
        let mut d = Drbg::new();
        d.seed(&mut MockEntropy::new(1)).unwrap();
        let mut before = [0u8; 16];
        d.fill_bytes(&mut before);
        d.reseed(&mut MockEntropy::new(2)).unwrap();
        let mut after = [0u8; 16];
        d.fill_bytes(&mut after);
        assert_ne!(before, after);
    }
}
