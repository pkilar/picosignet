//! Cryptographic known-answer tests, surfaced by the `hsm.selfTest` command.
//!
//! Each returns `true` on pass. The Ed25519 and SHA-512 tests check against
//! published vectors (RFC 8032 Test 1, FIPS 180-4 "abc"); the AEAD test is a
//! wrap/unwrap roundtrip with tamper rejection. The host unit tests below run
//! the same checks, so a mis-transcribed vector fails CI rather than a device.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha512};

use crate::keys::CaKey;
use crate::storage::WrapType;
use crate::wrap::{dev_kek, unwrap_seed, wrap_seed};

/// RFC 8032 Ed25519 Test 1 secret seed.
const ED_SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
/// RFC 8032 Ed25519 Test 1 public key (derived from `ED_SEED`).
const ED_PUB: [u8; 32] = [
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
];

/// FIPS 180-4 SHA-512("abc").
const SHA512_ABC: [u8; 64] = [
    0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20, 0x41, 0x31,
    0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6, 0x4b, 0x55, 0xd3, 0x9a,
    0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba, 0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd,
    0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e, 0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f,
];

/// Ed25519 KAT: derive the public key from a known seed (validates the curve
/// arithmetic against a published vector) and verify a fresh signature.
pub fn ed25519_kat() -> bool {
    let ca = CaKey::from_seed(&ED_SEED);
    if ca.public_bytes() != ED_PUB {
        return false;
    }
    let sig = ca.sign(b"usbhsm-selftest");
    let vk = match VerifyingKey::from_bytes(&ca.public_bytes()) {
        Ok(v) => v,
        Err(_) => return false,
    };
    vk.verify(b"usbhsm-selftest", &Signature::from_bytes(&sig))
        .is_ok()
}

/// SHA-512 KAT against the published "abc" digest.
pub fn sha512_kat() -> bool {
    let d = Sha512::digest(b"abc");
    d.as_slice() == SHA512_ABC
}

/// AEAD KAT: a wrap/unwrap roundtrip recovers the seed, and a tampered tag is
/// rejected.
pub fn aead_kat() -> bool {
    let kek = dev_kek(&[0xA5; 8]);
    let seed = [0x33u8; 32];
    let pubkey = [0x44u8; 32];
    let mut blob = wrap_seed(&kek, &seed, &pubkey, WrapType::DevKek, &[0u8; 12]);
    match unwrap_seed(&kek, &blob) {
        Ok(s) if *s == seed => {}
        _ => return false,
    }
    blob.tag[0] ^= 0x01;
    unwrap_seed(&kek, &blob).is_err()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_kats_pass_on_host() {
        assert!(ed25519_kat(), "ed25519 KAT");
        assert!(sha512_kat(), "sha512 KAT");
        assert!(aead_kat(), "aead KAT");
    }
}
