//! The device state machine.
//!
//! ```text
//! Uninitialized ──init(dev)──▶ DevReady ──generateKey──▶ DevReady
//!      │                                                   ▲ │ (lock/reset → DevReady)
//!      └──init(prod,pin)──▶ ProdLocked ──unlock(ok)──▶ ProdReady
//!                              │  ▲  └──unlock(bad)─┐      │
//!                              │  └─────────────────┘      │ lock / USB reset / suspend
//!                              ▼ (retries exhausted)       ▼
//!                           LockedOut ◀───────────── (back to ProdLocked)
//!                              │
//!                              └──factoryReset──▶ Uninitialized
//! ```
//!
//! Transition *logic* (loading/unwrapping keys, ticking counters) lives in
//! [`crate::dispatch`]; this type just names the states and the gating
//! predicates.

/// The device's persistent + session state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceState {
    /// No config in flash. Awaits `hsm.init`.
    Uninitialized,
    /// Dev mode, operational. CA key (if present) is loaded under the device
    /// KEK.
    DevReady,
    /// Production mode, CA key present but wrapped; awaits `hsm.unlock`.
    ProdLocked,
    /// Production mode, unlocked: CA key live in RAM.
    ProdReady,
    /// Production mode, retry budget exhausted. Only `factoryReset` escapes.
    LockedOut,
}

impl DeviceState {
    /// The wire string used in `hsm.status` and matching the bridge/CLI.
    pub fn as_str(&self) -> &'static str {
        match self {
            DeviceState::Uninitialized => "uninitialized",
            DeviceState::DevReady => "devReady",
            DeviceState::ProdLocked => "prodLocked",
            DeviceState::ProdReady => "prodReady",
            DeviceState::LockedOut => "lockedOut",
        }
    }

    /// Whether the signer can issue certificates in this state (given a key and
    /// a set clock — those are checked separately).
    pub fn signer_ready(&self) -> bool {
        matches!(self, DeviceState::DevReady | DeviceState::ProdReady)
    }
}
