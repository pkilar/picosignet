//! The on-device Ed25519 CA key.
//!
//! The 32-byte seed is generated on the device from the conditioned DRBG and
//! never leaves it in the clear: at rest it is AEAD-wrapped ([`crate::wrap`])
//! and stored in flash; in use it lives only as an [`ed25519_dalek::SigningKey`]
//! in RAM, zeroized on lock/disconnect. Only the public key is exportable.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use ed25519_dalek::{Signer, SigningKey};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::sshwire::{b64_encode, put_string};

/// An in-RAM CA signing key. The underlying `SigningKey` zeroizes its secret on
/// drop (ed25519-dalek `zeroize` feature).
pub struct CaKey {
    signing: SigningKey,
}

impl CaKey {
    /// Reconstruct the CA key from its 32-byte seed (e.g. after unwrapping the
    /// stored blob). The seed buffer is the caller's responsibility to zeroize.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        CaKey {
            signing: SigningKey::from_bytes(seed),
        }
    }

    /// Generate a fresh CA key from the DRBG, returning the seed (so the caller
    /// can wrap and persist it) alongside the live key. The returned seed is
    /// held in a `Zeroizing` buffer.
    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> (Zeroizing<[u8; 32]>, Self) {
        let mut seed = Zeroizing::new([0u8; 32]);
        rng.fill_bytes(seed.as_mut_slice());
        let key = CaKey::from_seed(&seed);
        (seed, key)
    }

    /// The raw 32-byte Ed25519 public key.
    pub fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    /// The SSH public-key blob: `string("ssh-ed25519") || string(pub32)`. This
    /// is the `signature key` field embedded in issued certificates.
    pub fn public_blob(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + 11 + 4 + 32);
        put_string(&mut out, b"ssh-ed25519");
        put_string(&mut out, &self.public_bytes());
        out
    }

    /// The CA public key as an `authorized_keys` line:
    /// `ssh-ed25519 <base64-blob> <comment>`.
    pub fn authorized_line(&self, comment: &str) -> String {
        let blob = self.public_blob();
        if comment.is_empty() {
            format!("ssh-ed25519 {}", b64_encode(&blob))
        } else {
            format!("ssh-ed25519 {} {comment}", b64_encode(&blob))
        }
    }

    /// Sign `msg` with Ed25519 (deterministic, RFC 8032). Returns the raw
    /// 64-byte signature.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.signing.sign(msg).to_bytes()
    }

    /// The SSH signature blob for `msg`: `string("ssh-ed25519") || string(sig64)`.
    pub fn signature_blob(&self, msg: &[u8]) -> Vec<u8> {
        let sig = self.sign(msg);
        let mut out = Vec::with_capacity(4 + 11 + 4 + 64);
        put_string(&mut out, b"ssh-ed25519");
        put_string(&mut out, &sig);
        out
    }
}

/// Build the `authorized_keys` line for a raw Ed25519 public key, without a
/// live [`CaKey`]. Used by `getPublicKey` while the device is locked (the
/// public key is stored in the clear).
pub fn authorized_line_from_pubkey(pubkey: &[u8; 32], comment: &str) -> String {
    let mut blob = Vec::with_capacity(4 + 11 + 4 + 32);
    put_string(&mut blob, b"ssh-ed25519");
    put_string(&mut blob, pubkey);
    if comment.is_empty() {
        format!("ssh-ed25519 {}", b64_encode(&blob))
    } else {
        format!("ssh-ed25519 {} {comment}", b64_encode(&blob))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    #[test]
    fn deterministic_pubkey_from_seed() {
        let key = CaKey::from_seed(&[7u8; 32]);
        // Ed25519 public key is deterministic from the seed.
        let key2 = CaKey::from_seed(&[7u8; 32]);
        assert_eq!(key.public_bytes(), key2.public_bytes());
    }

    #[test]
    fn signature_verifies() {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};
        let key = CaKey::from_seed(&[3u8; 32]);
        let msg = b"hello certificate";
        let sig = key.sign(msg);
        let vk = VerifyingKey::from_bytes(&key.public_bytes()).unwrap();
        vk.verify(msg, &Signature::from_bytes(&sig)).unwrap();
    }

    #[test]
    fn generate_is_random() {
        let mut rng = ChaCha20Rng::from_seed([1u8; 32]);
        let (seed_a, _ka) = CaKey::generate(&mut rng);
        let (seed_b, _kb) = CaKey::generate(&mut rng);
        assert_ne!(*seed_a, *seed_b);
    }
}
