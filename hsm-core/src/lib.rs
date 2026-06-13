//! PicoSignet core: the entire protocol state machine, validation, crypto, key
//! wrapping, and flash storage logic for the RP2350 SSH-certificate HSM.
//!
//! Everything hardware-specific lives behind the traits in [`hal`]; the
//! firmware ([`hsm-fw`]) supplies real peripheral implementations while the
//! host test suite and the simulator ([`hsm-sim`]) supply mocks. This keeps
//! the security-critical logic fully unit-testable on a workstation.
//!
//! The single entry point is [`Hsm::process_line`], which takes one
//! newline-delimited JSON request and returns the JSON response bytes —
//! byte-compatible with cerberus `ssh-cert-signer` for the signer-path
//! variants, plus an additive `hsm` management envelope.
#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod hal;

pub mod cert;
pub mod clock;
pub mod goduration;
pub mod keys;
pub mod lineio;
pub mod metrics;
pub mod pin;
pub mod proto;
pub mod rng;
pub mod selftest;
pub mod sshwire;
pub mod storage;
pub mod wrap;

pub mod dispatch;
pub mod state;
pub mod validate;

#[cfg(any(test, feature = "std"))]
pub mod testhal;

/// Firmware version reported in `hsm.status`. Kept in sync with the crate
/// version so a deployed device self-identifies.
pub const FW_VERSION: &str = env!("CARGO_PKG_VERSION");
