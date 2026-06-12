//! Key-wrapping: derive a key-encryption key (KEK) and AEAD-wrap the 32-byte CA
//! seed for storage. Both KEKs are bound to the per-device secret locked in
//! on-die OTP ([`crate::hal::FlashStore::device_secret`]), so a dump of the
//! external QSPI flash alone can never unwrap the CA key.
//!
//! - **Production**: `KEK = HKDF-SHA256(salt = OTP secret,
//!   ikm = Argon2id(PIN, salt16, params), info = "usbhsm-prod-kek-v2")`. The
//!   memory-hard pass keeps each *online* guess slow; keying the extract step
//!   with the on-die secret means an *offline* brute-force needs the OTP
//!   secret too — i.e. defeating the chip, not just reading the flash. PIN
//!   correctness *is* AEAD tag verification — there is no separate check value
//!   that would give a faster oracle.
//! - **Dev**: `KEK = HKDF-SHA256(OTP secret, info = "usbhsm-dev-kek-v2")`.
//!   At rest this is as strong as the OTP secret; possession of a *running*
//!   device still equals signing, which is dev mode's point (no PIN).
//!
//! The AEAD is ChaCha20-Poly1305 with AAD binding the wrap type and public key,
//! so a blob cannot be presented under a different wrap type or paired with a
//! different public key.

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::storage::{Argon2Params, KeyBlob, WrapType};

/// Errors from wrapping/unwrapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WrapError {
    /// Argon2 failed (bad parameters for the available memory).
    Kdf,
    /// AEAD tag did not verify (wrong PIN, tampered blob, or wrong wrap type).
    Auth,
}

/// Derive the dev-mode KEK from the per-device OTP secret.
pub fn dev_kek(device_secret: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, device_secret);
    let mut out = Zeroizing::new([0u8; 32]);
    // info domain-separates this from any other use of the device secret.
    hk.expand(b"usbhsm-dev-kek-v2", out.as_mut_slice())
        .expect("32 is a valid HKDF-SHA256 output length");
    out
}

/// Derive the production KEK: Argon2id over the PIN, then an HKDF extract
/// keyed by the per-device OTP secret. Cost parameters come from the device
/// config so they are fixed at init time.
pub fn pin_kek(
    pin: &[u8],
    salt: &[u8; 16],
    params: &Argon2Params,
    device_secret: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>, WrapError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let p = Params::new(
        params.m_cost,
        params.t_cost,
        params.parallelism as u32,
        Some(32),
    )
    .map_err(|_| WrapError::Kdf)?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, p);
    let mut stretched = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(pin, salt, stretched.as_mut_slice())
        .map_err(|_| WrapError::Kdf)?;
    let hk = Hkdf::<Sha256>::new(Some(device_secret), stretched.as_slice());
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(b"usbhsm-prod-kek-v2", out.as_mut_slice())
        .expect("32 is a valid HKDF-SHA256 output length");
    Ok(out)
}

/// AAD that binds a wrapped blob to its wrap type and public key.
fn aad(wrap_type: WrapType, pubkey: &[u8; 32]) -> [u8; 33] {
    let mut a = [0u8; 33];
    a[0] = wrap_type as u8;
    a[1..].copy_from_slice(pubkey);
    a
}

/// Wrap `seed` under `kek`, producing a [`KeyBlob`]. `nonce` must be unique per
/// (key, message) — the caller supplies a fresh random nonce from the DRBG.
pub fn wrap_seed(
    kek: &[u8; 32],
    seed: &[u8; 32],
    pubkey: &[u8; 32],
    wrap_type: WrapType,
    nonce: &[u8; 12],
) -> KeyBlob {
    let cipher = ChaCha20Poly1305::new(kek.into());
    let mut buf = *seed;
    let tag = cipher
        .encrypt_in_place_detached(nonce.into(), &aad(wrap_type, pubkey), &mut buf)
        .expect("chacha20poly1305 encryption is infallible for in-RAM buffers");
    KeyBlob {
        wrap_type,
        aead_nonce: *nonce,
        pubkey: *pubkey,
        ciphertext: buf,
        tag: tag.into(),
    }
}

/// Unwrap the seed in `blob` using `kek`. Returns [`WrapError::Auth`] if the tag
/// does not verify — i.e. the wrong PIN, a tampered blob, or a wrong wrap type.
pub fn unwrap_seed(kek: &[u8; 32], blob: &KeyBlob) -> Result<Zeroizing<[u8; 32]>, WrapError> {
    let cipher = ChaCha20Poly1305::new(kek.into());
    let mut buf = Zeroizing::new(blob.ciphertext);
    cipher
        .decrypt_in_place_detached(
            (&blob.aead_nonce).into(),
            &aad(blob.wrap_type, &blob.pubkey),
            buf.as_mut_slice(),
            (&blob.tag).into(),
        )
        .map_err(|_| WrapError::Auth)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: [u8; 32] = [0x5A; 32];

    fn params() -> Argon2Params {
        Argon2Params {
            m_cost: 32,
            t_cost: 2,
            parallelism: 1,
        }
    }

    #[test]
    fn dev_wrap_roundtrip() {
        let kek = dev_kek(&SECRET);
        let seed = [9u8; 32];
        let pubkey = [7u8; 32];
        let blob = wrap_seed(&kek, &seed, &pubkey, WrapType::DevKek, &[0u8; 12]);
        let got = unwrap_seed(&kek, &blob).unwrap();
        assert_eq!(*got, seed);
    }

    #[test]
    fn pin_wrap_roundtrip() {
        let kek = pin_kek(b"correct horse", &[0xAB; 16], &params(), &SECRET).unwrap();
        let seed = [5u8; 32];
        let pubkey = [3u8; 32];
        let blob = wrap_seed(&kek, &seed, &pubkey, WrapType::PinKek, &[1u8; 12]);
        let got = unwrap_seed(&kek, &blob).unwrap();
        assert_eq!(*got, seed);
    }

    #[test]
    fn wrong_pin_fails_auth() {
        let salt = [0x11; 16];
        let kek = pin_kek(b"right-pin", &salt, &params(), &SECRET).unwrap();
        let blob = wrap_seed(&kek, &[5u8; 32], &[3u8; 32], WrapType::PinKek, &[1u8; 12]);
        let wrong = pin_kek(b"wrong-pin", &salt, &params(), &SECRET).unwrap();
        assert_eq!(unwrap_seed(&wrong, &blob), Err(WrapError::Auth));
    }

    #[test]
    fn wrong_device_secret_fails_auth() {
        // The OTP binding: correct PIN + flash dump on a different chip (or
        // off-chip) must not unwrap.
        let salt = [0x11; 16];
        let kek = pin_kek(b"right-pin", &salt, &params(), &SECRET).unwrap();
        let blob = wrap_seed(&kek, &[5u8; 32], &[3u8; 32], WrapType::PinKek, &[1u8; 12]);
        let other = pin_kek(b"right-pin", &salt, &params(), &[0xA5; 32]).unwrap();
        assert_eq!(unwrap_seed(&other, &blob), Err(WrapError::Auth));

        let dev = dev_kek(&SECRET);
        let dev_blob = wrap_seed(&dev, &[5u8; 32], &[3u8; 32], WrapType::DevKek, &[1u8; 12]);
        let dev_other = dev_kek(&[0xA5; 32]);
        assert_eq!(unwrap_seed(&dev_other, &dev_blob), Err(WrapError::Auth));
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let kek = dev_kek(&SECRET);
        let mut blob = wrap_seed(&kek, &[5u8; 32], &[3u8; 32], WrapType::DevKek, &[1u8; 12]);
        blob.ciphertext[0] ^= 0x01;
        assert_eq!(unwrap_seed(&kek, &blob), Err(WrapError::Auth));
    }

    #[test]
    fn swapped_wrap_type_fails_auth() {
        // AAD binds the wrap type; changing it must break authentication.
        let kek = dev_kek(&SECRET);
        let mut blob = wrap_seed(&kek, &[5u8; 32], &[3u8; 32], WrapType::DevKek, &[1u8; 12]);
        blob.wrap_type = WrapType::PinKek;
        assert_eq!(unwrap_seed(&kek, &blob), Err(WrapError::Auth));
    }
}
