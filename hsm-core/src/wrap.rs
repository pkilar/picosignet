//! Key-wrapping: derive a key-encryption key (KEK) and AEAD-wrap the 32-byte CA
//! seed for storage.
//!
//! - **Production**: `KEK = Argon2id(PIN, salt, params)`. The seed is only ever
//!   decrypted into RAM after a correct PIN, and PIN correctness *is* AEAD tag
//!   verification — there is no separate check value that would give a faster
//!   brute-force oracle.
//! - **Dev**: `KEK = HKDF-SHA256(device unique-id)`. This is obfuscation, not
//!   protection: anyone who can read the flash can also read the unique id.
//!   Documented as such in the threat model.
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

/// Derive the dev-mode KEK from the device unique id. Obfuscation only.
pub fn dev_kek(unique_id: &[u8; 8]) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(None, unique_id);
    let mut out = Zeroizing::new([0u8; 32]);
    // info domain-separates this from any other use of the unique id.
    hk.expand(b"usbhsm-dev-kek-v1", out.as_mut_slice())
        .expect("32 is a valid HKDF-SHA256 output length");
    out
}

/// Derive the production KEK from a PIN with Argon2id. Cost parameters come from
/// the device config so they are fixed at init time.
pub fn pin_kek(
    pin: &[u8],
    salt: &[u8; 16],
    params: &Argon2Params,
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
    let mut out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(pin, salt, out.as_mut_slice())
        .map_err(|_| WrapError::Kdf)?;
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

    fn params() -> Argon2Params {
        Argon2Params {
            m_cost: 32,
            t_cost: 2,
            parallelism: 1,
        }
    }

    #[test]
    fn dev_wrap_roundtrip() {
        let kek = dev_kek(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let seed = [9u8; 32];
        let pubkey = [7u8; 32];
        let blob = wrap_seed(&kek, &seed, &pubkey, WrapType::DevKek, &[0u8; 12]);
        let got = unwrap_seed(&kek, &blob).unwrap();
        assert_eq!(*got, seed);
    }

    #[test]
    fn pin_wrap_roundtrip() {
        let kek = pin_kek(b"correct horse", &[0xAB; 16], &params()).unwrap();
        let seed = [5u8; 32];
        let pubkey = [3u8; 32];
        let blob = wrap_seed(&kek, &seed, &pubkey, WrapType::PinKek, &[1u8; 12]);
        let got = unwrap_seed(&kek, &blob).unwrap();
        assert_eq!(*got, seed);
    }

    #[test]
    fn wrong_pin_fails_auth() {
        let salt = [0x11; 16];
        let kek = pin_kek(b"right-pin", &salt, &params()).unwrap();
        let blob = wrap_seed(&kek, &[5u8; 32], &[3u8; 32], WrapType::PinKek, &[1u8; 12]);
        let wrong = pin_kek(b"wrong-pin", &salt, &params()).unwrap();
        assert_eq!(unwrap_seed(&wrong, &blob), Err(WrapError::Auth));
    }

    #[test]
    fn tampered_ciphertext_fails_auth() {
        let kek = dev_kek(&[1; 8]);
        let mut blob = wrap_seed(&kek, &[5u8; 32], &[3u8; 32], WrapType::DevKek, &[1u8; 12]);
        blob.ciphertext[0] ^= 0x01;
        assert_eq!(unwrap_seed(&kek, &blob), Err(WrapError::Auth));
    }

    #[test]
    fn swapped_wrap_type_fails_auth() {
        // AAD binds the wrap type; changing it must break authentication.
        let kek = dev_kek(&[1; 8]);
        let mut blob = wrap_seed(&kek, &[5u8; 32], &[3u8; 32], WrapType::DevKek, &[1u8; 12]);
        blob.wrap_type = WrapType::PinKek;
        assert_eq!(unwrap_seed(&kek, &blob), Err(WrapError::Auth));
    }
}
