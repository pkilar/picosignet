//! The request dispatcher and device session — the single entry point
//! [`Hsm::process_line`].
//!
//! `Hsm` owns the HAL, the DRBG, the wall clock, and the in-RAM session
//! (loaded CA key, cached wrapping key, cached config). It parses one
//! newline-delimited JSON request, enforces the exactly-one-variant rule,
//! routes to a handler, and serializes the response. Signer-path failures
//! produce a top-level `{"error": ...}` exactly as cerberus does; management
//! failures stay inside the `hsm` envelope as a structured error.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use rand_core::RngCore;
use zeroize::Zeroizing;

use crate::cert::{build_certificate, CertParams};
use crate::clock::Clock;
use crate::hal::{EntropySource, FlashStore, HalError, Monotonic};
use crate::keys::{authorized_line_from_pubkey, CaKey};
use crate::metrics;
use crate::pin;
use crate::proto::*;
use crate::rng::Drbg;
use crate::state::DeviceState;
use crate::storage::{self, Argon2Params, DeviceConfig, KeyBlob, Mode, WrapType};
use crate::validate::validate;
use crate::wrap::{dev_kek, pin_kek, unwrap_seed, wrap_seed};
use crate::FW_VERSION;

/// Default Argon2id work factors for production init. `m_cost` is in KiB;
/// 256 KiB fits the RP2350's 512 KiB SRAM inside the firmware's 384 KiB heap
/// alongside the JSON buffers — 4x the memory hardness of the earlier 64 KiB
/// setting. `t_cost` = 14 targets ≈1 s of Argon2 compute per guess on the
/// 150 MHz Cortex-M33 (estimate; re-tuned against real unlock timings during
/// HIL bring-up). The value is persisted, so a device's cost is fixed at init
/// time. Note the offline story no longer rests on Argon2 alone: the KEK is
/// also bound to the on-die OTP secret (see `crate::wrap`), so an attacker
/// with only a flash dump has nothing to brute-force against.
const DEFAULT_ARGON: Argon2Params = Argon2Params {
    m_cost: 256,
    t_cost: 14,
    parallelism: 1,
};

const PIN_MIN: usize = 6;
const PIN_MAX: usize = 64;
const MAX_ENTROPY_HEX: usize = 1024;
const CA_COMMENT: &str = "picosignet-ca";

/// The CA seed, the wrapping KEK, and the Argon2 salt (from the key blob)
/// recovered by a successful PIN verification.
type UnlockedSeed = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>, [u8; 16]);

// Management error codes (kept in lockstep with docs/PROTOCOL.md).
const ERR_BAD_REQUEST: &str = "ERR_BAD_REQUEST";
const ERR_ALREADY_INIT: &str = "ERR_ALREADY_INIT";
const ERR_NOT_INIT: &str = "ERR_NOT_INIT";
const ERR_NO_KEY: &str = "ERR_NO_KEY";
const ERR_KEY_EXISTS: &str = "ERR_KEY_EXISTS";
const ERR_LOCKED: &str = "ERR_LOCKED";
const ERR_BAD_PIN: &str = "ERR_BAD_PIN";
const ERR_LOCKED_OUT: &str = "ERR_LOCKED_OUT";
const ERR_BAD_MODE: &str = "ERR_BAD_MODE";
const ERR_ENTROPY: &str = "ERR_ENTROPY";
const ERR_FLASH: &str = "ERR_FLASH";
const ERR_BUSY: &str = "ERR_BUSY";
const ERR_INTERNAL: &str = "ERR_INTERNAL";

/// The device session and dispatcher.
pub struct Hsm<E: EntropySource, M: Monotonic, F: FlashStore> {
    entropy: E,
    mono: M,
    flash: F,
    drbg: Drbg,
    clock: Clock,
    state: DeviceState,
    config: Option<DeviceConfig>,
    /// Live CA key (present in DevReady-with-key and ProdReady).
    ca: Option<CaKey>,
    /// CA public key, cached from the (clear) blob field so `getPublicKey`
    /// works while locked.
    ca_pubkey: Option<[u8; 32]>,
    /// The key-encryption key for wrapping *new* keys: the dev KEK in dev mode,
    /// or the Argon2id(PIN) KEK cached after a successful prod unlock.
    wrap_kek: Option<Zeroizing<[u8; 32]>>,
    /// The Argon2 salt matching `wrap_kek` (prod only), so `generateKey` can
    /// re-wrap a rotated seed into a self-consistent blob without the PIN.
    wrap_salt: Option<[u8; 16]>,
    /// Absolute monotonic deadline for the next PIN attempt. Failures in this
    /// boot set it relative to their actual time; boot reconstructs it from
    /// the persisted counter so a reset cannot skip a pending delay.
    pin_backoff_until_ms: u64,
    /// Cross-reboot lower trust anchor for wall-clock validation.
    trusted_time_floor: Option<i64>,
    /// Set when the persistent trusted-time state could not be read or decoded.
    /// `setTime` fails closed until a clean boot or successful factory reset.
    trusted_time_floor_unavailable: bool,
    /// Physical recovery capability sampled once by firmware during boot.
    physical_recovery_authorized: bool,
    /// Firmware-reported free heap (0 when unknown, e.g. in the simulator).
    heap_free: u64,
    /// Firmware-reported security posture (all false in the simulator):
    /// glitch detectors armed, bootrom secure-boot enforcement, and whether
    /// the last reset was a glitch-detector trigger.
    glitch_armed: bool,
    secure_boot: bool,
    glitch_reset: bool,
    /// Set by `rebootBootloader`; the firmware reboots into BOOTSEL after
    /// flushing the response. Ignored by the simulator.
    reboot_requested: bool,
}

impl<E: EntropySource, M: Monotonic, F: FlashStore> Hsm<E, M, F> {
    /// Boot: seed the DRBG (best effort) and load persisted state from flash.
    /// Boot does not fail on entropy trouble — only operations that need
    /// randomness do, via [`Self::prepare_keygen_entropy`].
    pub fn boot(mut entropy: E, mono: M, flash: F) -> Self {
        let mut drbg = Drbg::new();
        let _ = drbg.seed(&mut entropy); // failure deferred to keygen/sign
        let mut hsm = Hsm {
            entropy,
            mono,
            flash,
            drbg,
            clock: Clock::new(),
            state: DeviceState::Uninitialized,
            config: None,
            ca: None,
            ca_pubkey: None,
            wrap_kek: None,
            wrap_salt: None,
            pin_backoff_until_ms: 0,
            trusted_time_floor: None,
            trusted_time_floor_unavailable: false,
            physical_recovery_authorized: false,
            heap_free: 0,
            glitch_armed: false,
            secure_boot: false,
            glitch_reset: false,
            reboot_requested: false,
        };
        hsm.load_from_flash();
        hsm
    }

    /// Consume a pending reboot-to-bootloader request (firmware calls this after
    /// sending each response; returns true exactly once per request).
    pub fn take_reboot_requested(&mut self) -> bool {
        core::mem::replace(&mut self.reboot_requested, false)
    }

    /// Latch the physical recovery gesture sampled by firmware during boot.
    /// This capability must never be derived from a wire request.
    pub fn set_physical_recovery_authorized(&mut self, authorized: bool) {
        self.physical_recovery_authorized = authorized;
    }

    /// Update the firmware's free-heap figure (surfaced in metrics/status).
    pub fn set_heap_free(&mut self, bytes: u64) {
        self.heap_free = bytes;
    }

    /// Report the firmware's security posture (surfaced in `status`).
    pub fn set_security_flags(
        &mut self,
        glitch_armed: bool,
        secure_boot: bool,
        glitch_reset: bool,
    ) {
        self.glitch_armed = glitch_armed;
        self.secure_boot = secure_boot;
        self.glitch_reset = glitch_reset;
    }

    /// Current state (for tests and firmware status LEDs).
    pub fn state(&self) -> DeviceState {
        self.state
    }

    /// Recommended-reseed hint for the firmware loop.
    pub fn drbg_should_reseed(&self) -> bool {
        self.drbg.since_reseed() >= crate::rng::RESEED_INTERVAL
    }

    /// Reseed the DRBG from hardware entropy (firmware may call periodically).
    pub fn reseed(&mut self) -> Result<(), HalError> {
        self.drbg.reseed(&mut self.entropy)
    }

    /// Fold supplementary entropy (e.g. boot-time SRAM startup noise) into the
    /// DRBG pool. Additive only — never a substitute for the health-checked
    /// hardware source.
    pub fn mix_entropy(&mut self, bytes: &[u8]) {
        self.drbg.mix_host(bytes);
    }

    fn load_from_flash(&mut self) {
        let cfg = storage::CONFIG
            .read_latest(&mut self.flash)
            .ok()
            .flatten()
            .and_then(|b| DeviceConfig::from_bytes(&b));
        let keyblob = storage::KEY
            .read_latest(&mut self.flash)
            .ok()
            .flatten()
            .and_then(|b| KeyBlob::from_bytes(&b));
        match storage::TIME_FLOOR.read_latest_fail_closed(&mut self.flash) {
            Ok(Some(bytes)) => match <[u8; 8]>::try_from(bytes.as_slice()) {
                Ok(encoded) => {
                    self.trusted_time_floor = Some(i64::from_be_bytes(encoded));
                    self.trusted_time_floor_unavailable = false;
                }
                Err(_) => {
                    self.trusted_time_floor = None;
                    self.trusted_time_floor_unavailable = true;
                }
            },
            Ok(None) => {
                self.trusted_time_floor = None;
                self.trusted_time_floor_unavailable = false;
            }
            Err(_) => {
                self.trusted_time_floor = None;
                self.trusted_time_floor_unavailable = true;
            }
        }
        self.ca_pubkey = keyblob.as_ref().map(|kb| kb.pubkey);
        // The salt lives in the key blob (v2); a cached KEK is only meaningful
        // alongside it. Both are re-established below per mode.
        self.wrap_salt = None;

        match cfg {
            None => {
                self.config = None;
                self.state = DeviceState::Uninitialized;
                self.ca = None;
                self.wrap_kek = None;
                self.pin_backoff_until_ms = 0;
            }
            Some(c) => {
                self.config = Some(c);
                match c.mode {
                    Mode::Dev => {
                        self.state = DeviceState::DevReady;
                        self.pin_backoff_until_ms = 0;
                        // No OTP secret => no KEK: the device stays DevReady
                        // for status purposes but cannot load or wrap a key
                        // (fail closed; status reports otpSecret:false).
                        if let Ok(secret) = self.flash.device_secret() {
                            let kek = dev_kek(&secret);
                            if let Some(kb) = keyblob {
                                if let Ok(seed) = unwrap_seed(&kek, &kb) {
                                    self.ca = Some(CaKey::from_seed(&seed));
                                }
                            }
                            self.wrap_kek = Some(kek);
                        }
                    }
                    Mode::Prod => {
                        self.drop_live_secrets();
                        let attempts = pin::count(&mut self.flash).unwrap_or(0);
                        self.pin_backoff_until_ms = if attempts > 0 {
                            (self.mono.now_micros() / 1000)
                                .saturating_add(
                                    pin::backoff_ms(attempts.saturating_sub(1) as u32) as u64
                                )
                        } else {
                            0
                        };
                        if keyblob.is_some() && attempts >= c.max_retries as usize {
                            self.enter_locked_out();
                        } else {
                            self.state = DeviceState::ProdLocked;
                        }
                    }
                }
            }
        }
    }

    /// Process one request line (no trailing newline) and return the response
    /// bytes (also no trailing newline — the transport frames it).
    pub fn process_line(&mut self, line: &[u8]) -> Vec<u8> {
        let resp = self.handle(line);
        serde_json::to_vec(&resp).unwrap_or_else(|_| br#"{"error":"internal error"}"#.to_vec())
    }

    fn handle(&mut self, line: &[u8]) -> Response {
        let req: Request = match serde_json::from_slice(line) {
            Ok(r) => r,
            Err(e) => return Response::error(format!("json.Unmarshal failed: {e}")),
        };

        let n = [
            req.load_key_signer.is_some(),
            req.sign_ssh_key.is_some(),
            req.ping.is_some(),
            req.get_enclave_metrics.is_some(),
            req.hsm.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if n > 1 {
            return Response::error("multiple request variants set; expected exactly one");
        }

        if req.load_key_signer.is_some() {
            self.handle_load_key_signer()
        } else if let Some(s) = req.sign_ssh_key {
            self.handle_sign(s)
        } else if req.ping.is_some() {
            self.handle_ping()
        } else if req.get_enclave_metrics.is_some() {
            self.handle_metrics()
        } else if let Some(h) = req.hsm {
            Response {
                hsm: Some(self.handle_hsm(h)),
                ..Default::default()
            }
        } else {
            Response::error("unexpected command")
        }
    }

    // ---- signer path ------------------------------------------------------

    fn handle_ping(&self) -> Response {
        let signer_loaded = self.state.signer_ready() && self.ca.is_some() && self.clock.is_set();
        Response {
            pong: Some(PingResponse { signer_loaded }),
            ..Default::default()
        }
    }

    fn handle_metrics(&self) -> Response {
        Response {
            enclave_metrics: Some(metrics::build(self.mono.now_micros(), self.heap_free)),
            ..Default::default()
        }
    }

    fn handle_load_key_signer(&self) -> Response {
        if self.state.signer_ready() && self.ca.is_some() {
            Response {
                load_key_signer: Some(LoadKeySignerResponse {
                    success: true,
                    error: String::new(),
                }),
                ..Default::default()
            }
        } else {
            Response::error("CA signer is not initialized; call LoadKeySigner first")
        }
    }

    fn handle_sign(&mut self, req: EnclaveSigningRequest) -> Response {
        if !self.state.signer_ready() || self.ca.is_none() {
            return Response::error("CA signer is not initialized; call LoadKeySigner first");
        }
        let now = match self.clock.now_unix(&self.mono) {
            Some(t) => t,
            None => return Response::error("device clock not set; send hsm.setTime first"),
        };
        let v = match validate(&req) {
            Ok(v) => v,
            Err(msg) => return Response::error(msg),
        };
        // Signing needs a *seeded* CSPRNG, not fresh hardware entropy: the
        // ChaCha20 DRBG (seeded at boot/keygen with health-checked TRNG output)
        // produces unique nonces/serials without reseeding. Reseeding per
        // signature would be slow and would make every signature depend on a
        // fresh TRNG health check. Only seed here if boot seeding never
        // succeeded.
        if self.ensure_seeded().is_err() {
            return Response::error("internal error: entropy unavailable");
        }

        let nonce = self.drbg.random_array::<32>();
        let serial = self.drbg.next_u64();
        let valid_after = (now as u64).wrapping_sub(300);
        let valid_before = (now as u64).wrapping_add((v.duration_ns / 1_000_000_000) as u64);

        let params = CertParams {
            cert_algo: &v.key.cert_algo,
            key_body: &v.key.key_body,
            nonce: &nonce,
            serial,
            key_id: &req.key_id,
            principals: &req.principals,
            valid_after,
            valid_before,
            critical_options: &v.critical_options,
            extensions: &v.extensions,
        };
        let ca = self.ca.as_ref().expect("checked above");
        let line = build_certificate(&params, ca);
        Response {
            sign_ssh_key: Some(SigningResponse {
                signed_key: line,
                error: String::new(),
            }),
            ..Default::default()
        }
    }

    // ---- management path --------------------------------------------------

    fn handle_hsm(&mut self, h: HsmRequest) -> HsmResponse {
        let n = [
            h.init.is_some(),
            h.generate_key.is_some(),
            h.get_public_key.is_some(),
            h.unlock.is_some(),
            h.lock.is_some(),
            h.set_time.is_some(),
            h.status.is_some(),
            h.change_pin.is_some(),
            h.add_entropy.is_some(),
            h.self_test.is_some(),
            h.factory_reset.is_some(),
            h.reboot_bootloader.is_some(),
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if n != 1 {
            return HsmResponse::err(ERR_BAD_REQUEST, "exactly one hsm command expected");
        }

        if let Some(r) = h.init {
            self.hsm_init(r)
        } else if let Some(r) = h.generate_key {
            self.hsm_generate_key(r)
        } else if h.get_public_key.is_some() {
            self.hsm_get_public_key()
        } else if let Some(r) = h.unlock {
            self.hsm_unlock(r)
        } else if h.lock.is_some() {
            self.hsm_lock()
        } else if let Some(r) = h.set_time {
            self.hsm_set_time(r)
        } else if h.status.is_some() {
            self.hsm_status()
        } else if let Some(r) = h.change_pin {
            self.hsm_change_pin(r)
        } else if let Some(r) = h.add_entropy {
            self.hsm_add_entropy(r)
        } else if h.self_test.is_some() {
            self.hsm_self_test()
        } else if let Some(r) = h.factory_reset {
            self.hsm_factory_reset(r)
        } else if let Some(r) = h.reboot_bootloader {
            self.hsm_reboot_bootloader(r)
        } else {
            HsmResponse::err(ERR_BAD_REQUEST, "exactly one hsm command expected")
        }
    }

    /// Request a reboot into the USB mass-storage bootloader after the response
    /// is sent. The actual reset is hardware-specific, so the core only sets a
    /// flag the firmware consumes via [`Self::take_reboot_requested`]; the
    /// simulator simply ignores it.
    ///
    /// Gated the same way as [`Self::hsm_factory_reset`]: free from
    /// `Uninitialized`/`DevReady` (nothing to protect — a fresh board must be
    /// reboot-able before it's ever initialized, and dev mode has no PIN by
    /// design), but a production device requires proof of PIN knowledge or the
    /// boot-latched physical recovery gesture. A locked-out device accepts
    /// only the physical gesture and never another PIN guess.
    fn hsm_reboot_bootloader(&mut self, req: RebootBootloaderReq) -> HsmResponse {
        match self.state {
            DeviceState::ProdLocked | DeviceState::ProdReady => {
                if !self.physical_recovery_authorized {
                    match &req.pin {
                        Some(pin) => {
                            if let Err(resp) = self.verify_pin(pin) {
                                return resp;
                            }
                        }
                        None => {
                            return HsmResponse::err(
                                ERR_BAD_REQUEST,
                                "rebooting into the bootloader requires a PIN or physical recovery held low during reset",
                            )
                        }
                    }
                }
            }
            DeviceState::LockedOut => {
                // Never accept a PIN here — verifying one would reopen a
                // guessing oracle after the retry budget is exhausted.
                if !self.physical_recovery_authorized {
                    return HsmResponse::err(
                        ERR_LOCKED_OUT,
                        "device locked out; hold physical recovery low during reset",
                    );
                }
            }
            DeviceState::Uninitialized | DeviceState::DevReady => {}
        }
        self.reboot_requested = true;
        HsmResponse::with(|r| r.reboot_bootloader = Some(OkResp { ok: true }))
    }

    fn hsm_init(&mut self, req: InitReq) -> HsmResponse {
        if self.config.is_some() {
            return HsmResponse::err(
                ERR_ALREADY_INIT,
                "device already initialized; factory-reset first",
            );
        }
        match req.mode.as_str() {
            "dev" => {
                let secret = match self.flash.device_secret() {
                    Ok(s) => s,
                    Err(_) => return HsmResponse::err(ERR_INTERNAL, "device secret unavailable"),
                };
                let cfg = DeviceConfig {
                    mode: Mode::Dev,
                    argon2: DEFAULT_ARGON,
                    max_retries: 0,
                    wipe_on_lockout: false,
                    fw_version: fw_version_triple(),
                };
                if storage::CONFIG
                    .write(&mut self.flash, &cfg.to_bytes())
                    .is_err()
                {
                    return HsmResponse::err(ERR_FLASH, "failed to write config");
                }
                self.config = Some(cfg);
                self.state = DeviceState::DevReady;
                self.wrap_kek = Some(dev_kek(&secret));
                HsmResponse::with(|r| {
                    r.init = Some(InitResp {
                        ok: true,
                        mode: "dev".to_string(),
                    })
                })
            }
            "prod" => {
                let pin = match &req.pin {
                    Some(p) if (PIN_MIN..=PIN_MAX).contains(&p.len()) => p.clone(),
                    Some(_) => {
                        return HsmResponse::err(
                            ERR_BAD_REQUEST,
                            format!("pin must be {PIN_MIN}..{PIN_MAX} bytes"),
                        )
                    }
                    None => return HsmResponse::err(ERR_BAD_REQUEST, "prod mode requires a pin"),
                };
                if self.prepare_keygen_entropy().is_err() {
                    return HsmResponse::err(ERR_ENTROPY, "entropy source unhealthy");
                }
                let salt = self.drbg.random_array::<16>();
                let max_retries = req.max_retries.unwrap_or(10);
                if max_retries == 0 {
                    return HsmResponse::err(
                        ERR_BAD_REQUEST,
                        "maxRetries must be between 1 and 255",
                    );
                }
                let wipe = req.wipe_on_lockout.unwrap_or(false);

                let secret = match self.flash.device_secret() {
                    Ok(s) => s,
                    Err(_) => return HsmResponse::err(ERR_INTERNAL, "device secret unavailable"),
                };
                let (seed, ca) = CaKey::generate(&mut self.drbg);
                let pubkey = ca.public_bytes();
                let kek = match pin_kek(pin.as_bytes(), &salt, &DEFAULT_ARGON, &secret) {
                    Ok(k) => k,
                    Err(_) => return HsmResponse::err(ERR_INTERNAL, "key derivation failed"),
                };
                let nonce = self.drbg.random_array::<12>();
                let blob = wrap_seed(&kek, &seed, &pubkey, WrapType::PinKek, &salt, &nonce);

                // Write the key first, then config: a config present on boot
                // therefore always implies a key present. The salt rides inside
                // the key blob, so the key record alone is self-unwrapping.
                if storage::KEY
                    .write(&mut self.flash, &blob.to_bytes())
                    .is_err()
                {
                    return HsmResponse::err(ERR_FLASH, "failed to write key");
                }
                let cfg = DeviceConfig {
                    mode: Mode::Prod,
                    argon2: DEFAULT_ARGON,
                    max_retries,
                    wipe_on_lockout: wipe,
                    fw_version: fw_version_triple(),
                };
                if storage::CONFIG
                    .write(&mut self.flash, &cfg.to_bytes())
                    .is_err()
                {
                    return HsmResponse::err(ERR_FLASH, "failed to write config");
                }
                self.reset_pin_counter_best_effort();

                self.config = Some(cfg);
                self.ca_pubkey = Some(pubkey);
                self.ca = None; // locked until unlock
                self.wrap_kek = None;
                self.wrap_salt = None;
                self.pin_backoff_until_ms = 0;
                self.state = DeviceState::ProdLocked;
                HsmResponse::with(|r| {
                    r.init = Some(InitResp {
                        ok: true,
                        mode: "prod".to_string(),
                    })
                })
            }
            _ => HsmResponse::err(ERR_BAD_MODE, "mode must be \"dev\" or \"prod\""),
        }
    }

    fn hsm_generate_key(&mut self, req: GenerateKeyReq) -> HsmResponse {
        match self.state {
            DeviceState::DevReady | DeviceState::ProdReady => {
                if self.ca_pubkey.is_some() && !req.force {
                    return HsmResponse::err(ERR_KEY_EXISTS, "key already exists; pass force=true");
                }
                let wrap_type = match self.config.map(|c| c.mode) {
                    Some(Mode::Dev) => WrapType::DevKek,
                    Some(Mode::Prod) => WrapType::PinKek,
                    None => return HsmResponse::err(ERR_NOT_INIT, "initialize the device first"),
                };
                let kek = match &self.wrap_kek {
                    Some(k) => Zeroizing::new(**k),
                    None => return HsmResponse::err(ERR_LOCKED, "unlock the device first"),
                };
                if self.prepare_keygen_entropy().is_err() {
                    return HsmResponse::err(ERR_ENTROPY, "entropy source unhealthy");
                }
                // The rotated blob must carry the salt that derived the cached
                // KEK (prod); dev wraps use no salt.
                let salt = match wrap_type {
                    WrapType::DevKek => [0u8; 16],
                    WrapType::PinKek => match self.wrap_salt {
                        Some(s) => s,
                        None => return HsmResponse::err(ERR_LOCKED, "unlock the device first"),
                    },
                };
                let (seed, ca) = CaKey::generate(&mut self.drbg);
                let pubkey = ca.public_bytes();
                let nonce = self.drbg.random_array::<12>();
                let blob = wrap_seed(&kek, &seed, &pubkey, wrap_type, &salt, &nonce);
                if storage::KEY
                    .write(&mut self.flash, &blob.to_bytes())
                    .is_err()
                {
                    return HsmResponse::err(ERR_FLASH, "failed to write key");
                }
                let line = ca.authorized_line(CA_COMMENT);
                self.ca = Some(ca);
                self.ca_pubkey = Some(pubkey);
                HsmResponse::with(|r| {
                    r.generate_key = Some(GenerateKeyResp {
                        ok: true,
                        public_key: line,
                    })
                })
            }
            DeviceState::ProdLocked | DeviceState::LockedOut => {
                HsmResponse::err(ERR_LOCKED, "unlock the device first")
            }
            DeviceState::Uninitialized => {
                HsmResponse::err(ERR_NOT_INIT, "initialize the device first")
            }
        }
    }

    fn hsm_get_public_key(&self) -> HsmResponse {
        match self.ca_pubkey {
            Some(pk) => HsmResponse::with(|r| {
                r.get_public_key = Some(PublicKeyResp {
                    public_key: authorized_line_from_pubkey(&pk, CA_COMMENT),
                })
            }),
            None => HsmResponse::err(ERR_NO_KEY, "no CA key present"),
        }
    }

    fn hsm_unlock(&mut self, req: UnlockReq) -> HsmResponse {
        match self.state {
            DeviceState::ProdReady => {
                HsmResponse::with(|r| r.unlock = Some(UnlockResp { ok: true }))
            }
            DeviceState::ProdLocked => match self.verify_pin(&req.pin) {
                Ok((seed, kek, salt)) => {
                    self.ca = Some(CaKey::from_seed(&seed));
                    self.wrap_kek = Some(kek);
                    self.wrap_salt = Some(salt);
                    self.state = DeviceState::ProdReady;
                    HsmResponse::with(|r| r.unlock = Some(UnlockResp { ok: true }))
                }
                Err(resp) => resp,
            },
            DeviceState::LockedOut => {
                HsmResponse::err(ERR_LOCKED_OUT, "device locked out; factory-reset required")
            }
            DeviceState::DevReady => {
                HsmResponse::err(ERR_BAD_MODE, "device is in dev mode; no unlock required")
            }
            DeviceState::Uninitialized => {
                HsmResponse::err(ERR_NOT_INIT, "initialize the device first")
            }
        }
    }

    fn hsm_lock(&mut self) -> HsmResponse {
        match self.state {
            DeviceState::ProdReady => {
                self.drop_live_secrets();
                self.state = DeviceState::ProdLocked;
                HsmResponse::with(|r| r.lock = Some(OkResp { ok: true }))
            }
            DeviceState::ProdLocked | DeviceState::LockedOut => {
                // Defensive cleanup if state and secret presence diverged.
                self.drop_live_secrets();
                HsmResponse::with(|r| r.lock = Some(OkResp { ok: true }))
            }
            DeviceState::DevReady => HsmResponse::err(ERR_BAD_MODE, "dev mode cannot be locked"),
            DeviceState::Uninitialized => {
                HsmResponse::err(ERR_NOT_INIT, "initialize the device first")
            }
        }
    }

    fn hsm_set_time(&mut self, req: SetTimeReq) -> HsmResponse {
        if self.trusted_time_floor_unavailable {
            return HsmResponse::err(
                ERR_FLASH,
                "trusted time state is unavailable; reboot or factory-reset after repairing flash",
            );
        }
        let first_set = !self.clock.is_set();
        if first_set && !self.physical_recovery_authorized {
            if let Some(floor) = self.trusted_time_floor {
                let too_far = match req.unix_seconds.checked_sub(floor) {
                    Some(delta) => delta.unsigned_abs() > crate::clock::MAX_DRIFT_SECS as u64,
                    None => true,
                };
                if too_far {
                    return HsmResponse::err(
                        ERR_BAD_REQUEST,
                        "unixSeconds drifts too far from persisted trusted time; use physical recovery to re-anchor",
                    );
                }
            }
        }

        // Do not update RAM if persisting a changed trust floor fails.
        let mut next_clock = self.clock;
        match next_clock.set(&self.mono, req.unix_seconds) {
            Ok(previous_set) => {
                let old_floor = self.trusted_time_floor;
                let mut next_floor = old_floor;
                if first_set && (old_floor.is_none() || self.physical_recovery_authorized) {
                    next_floor = Some(req.unix_seconds);
                } else if let (Some(floor), Some(trusted_now)) =
                    (old_floor, next_clock.trusted_now(&self.mono))
                {
                    // Persist only monotonic progress, never caller-controlled
                    // resync values, and limit flash wear to hourly updates.
                    if trusted_now.saturating_sub(floor) >= 3600 {
                        next_floor = Some(trusted_now);
                    }
                }
                if next_floor != old_floor
                    && storage::TIME_FLOOR
                        .write(
                            &mut self.flash,
                            &next_floor.expect("changed floor is present").to_be_bytes(),
                        )
                        .is_err()
                {
                    return HsmResponse::err(ERR_FLASH, "failed to persist trusted time floor");
                }
                self.clock = next_clock;
                self.trusted_time_floor = next_floor;
                HsmResponse::with(|r| {
                    r.set_time = Some(SetTimeResp {
                        ok: true,
                        uptime_ms: self.mono.now_micros() / 1000,
                        previous_set,
                    })
                })
            }
            Err(crate::clock::Rejected) => HsmResponse::err(
                ERR_BAD_REQUEST,
                "unixSeconds is implausible or drifts too far from the device's tracked time",
            ),
        }
    }

    fn hsm_status(&mut self) -> HsmResponse {
        let mode = match self.config.map(|c| c.mode) {
            Some(Mode::Dev) => "dev",
            Some(Mode::Prod) => "prod",
            None => "none",
        };
        let retry_remaining = match self.config {
            Some(c) if c.mode == Mode::Prod => {
                let used = pin::count(&mut self.flash).unwrap_or(0);
                Some((c.max_retries as u32).saturating_sub(used as u32))
            }
            _ => None,
        };
        let unix_seconds = self.clock.now_unix(&self.mono);
        let resp = StatusResp {
            state: self.state.as_str().to_string(),
            mode: mode.to_string(),
            key_present: self.ca_pubkey.is_some(),
            unlocked: self.ca.is_some(),
            clock_set: self.clock.is_set(),
            unix_seconds,
            uptime_ms: self.mono.now_micros() / 1000,
            retry_remaining,
            fw_version: FW_VERSION.to_string(),
            serial: hex_encode(&self.flash.unique_id()),
            heap_free_bytes: self.heap_free,
            otp_secret: self.flash.device_secret().is_ok(),
            glitch_armed: self.glitch_armed,
            secure_boot: self.secure_boot,
            glitch_reset: self.glitch_reset,
        };
        HsmResponse::with(|r| r.status = Some(resp))
    }

    fn hsm_change_pin(&mut self, req: ChangePinReq) -> HsmResponse {
        match self.state {
            DeviceState::ProdReady | DeviceState::ProdLocked => {}
            DeviceState::LockedOut => {
                return HsmResponse::err(
                    ERR_LOCKED_OUT,
                    "device locked out; factory-reset required",
                )
            }
            DeviceState::DevReady => return HsmResponse::err(ERR_BAD_MODE, "dev mode has no PIN"),
            DeviceState::Uninitialized => {
                return HsmResponse::err(ERR_NOT_INIT, "initialize the device first")
            }
        }
        if !(PIN_MIN..=PIN_MAX).contains(&req.new_pin.len()) {
            return HsmResponse::err(
                ERR_BAD_REQUEST,
                format!("new pin must be {PIN_MIN}..{PIN_MAX} bytes"),
            );
        }
        let was_ready = self.state == DeviceState::ProdReady;
        let (seed, _old_kek, _old_salt) = match self.verify_pin(&req.current_pin) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        // Re-wrap under a fresh salt and the new PIN.
        if self.prepare_keygen_entropy().is_err() {
            return HsmResponse::err(ERR_ENTROPY, "entropy source unhealthy");
        }
        let new_salt = self.drbg.random_array::<16>();
        let cfg = self.config.expect("prod implies config");
        let secret = match self.flash.device_secret() {
            Ok(s) => s,
            Err(_) => return HsmResponse::err(ERR_INTERNAL, "device secret unavailable"),
        };
        let new_kek = match pin_kek(req.new_pin.as_bytes(), &new_salt, &cfg.argon2, &secret) {
            Ok(k) => k,
            Err(_) => return HsmResponse::err(ERR_INTERNAL, "key derivation failed"),
        };
        let pubkey = match self.ca_pubkey {
            Some(p) => p,
            None => return HsmResponse::err(ERR_NO_KEY, "no CA key present"),
        };
        let nonce = self.drbg.random_array::<12>();
        // The new salt rides inside the key blob, so rotation is a single atomic
        // KEY-record write: there is no separate config write that could tear
        // and strand the seed under a salt the device can no longer reconstruct.
        let blob = wrap_seed(
            &new_kek,
            &seed,
            &pubkey,
            WrapType::PinKek,
            &new_salt,
            &nonce,
        );
        if storage::KEY
            .write(&mut self.flash, &blob.to_bytes())
            .is_err()
        {
            return HsmResponse::err(ERR_FLASH, "failed to write key");
        }
        self.reset_pin_counter_best_effort();
        if was_ready {
            self.ca = Some(CaKey::from_seed(&seed));
            self.wrap_kek = Some(new_kek);
            self.wrap_salt = Some(new_salt);
            self.state = DeviceState::ProdReady;
        } else {
            self.ca = None;
            self.wrap_kek = None;
            self.wrap_salt = None;
            self.state = DeviceState::ProdLocked;
        }
        HsmResponse::with(|r| r.change_pin = Some(OkResp { ok: true }))
    }

    fn hsm_add_entropy(&mut self, req: AddEntropyReq) -> HsmResponse {
        let bytes = match hex_decode(&req.hex) {
            Some(b) if b.len() <= MAX_ENTROPY_HEX => b,
            Some(_) => {
                return HsmResponse::err(ERR_BAD_REQUEST, "too much entropy (max 1024 bytes)")
            }
            None => return HsmResponse::err(ERR_BAD_REQUEST, "hex must be valid hexadecimal"),
        };
        self.drbg.mix_host(&bytes);
        HsmResponse::with(|r| r.add_entropy = Some(OkResp { ok: true }))
    }

    fn hsm_self_test(&mut self) -> HsmResponse {
        let ed = if crate::selftest::ed25519_kat() {
            "pass"
        } else {
            "fail"
        };
        let sha = if crate::selftest::sha512_kat() {
            "pass"
        } else {
            "fail"
        };
        let aead = if crate::selftest::aead_kat() {
            "pass"
        } else {
            "fail"
        };
        let drbg = if self.drbg.is_seeded() {
            "pass"
        } else {
            "fail"
        };
        let flash_ok = storage::CONFIG.read_latest(&mut self.flash).is_ok();
        let flash = if flash_ok { "pass" } else { "fail" };
        let otp = if self.flash.device_secret().is_ok() {
            "pass"
        } else {
            "fail"
        };
        let ok =
            ed == "pass" && sha == "pass" && aead == "pass" && flash == "pass" && otp == "pass";
        HsmResponse::with(|r| {
            r.self_test = Some(SelfTestResp {
                ok,
                tests: SelfTestDetails {
                    ed25519_kat: ed.to_string(),
                    sha2_kat: sha.to_string(),
                    aead_kat: aead.to_string(),
                    drbg_health: drbg.to_string(),
                    flash_crc: flash.to_string(),
                    otp_secret: otp.to_string(),
                },
            })
        })
    }

    /// Erase the CA key and all config. A `prodLocked`/`prodReady` device
    /// requires the current PIN (reusing `verify_pin`'s tick/backoff/lockout
    /// accounting — a wrong guess here counts the same as a wrong `unlock`) or
    /// physical recovery sampled by firmware at boot. Locked-out devices only
    /// accept the physical gesture and never verify another PIN.
    fn hsm_factory_reset(&mut self, req: FactoryResetReq) -> HsmResponse {
        if req.confirm != "ERASE" {
            return HsmResponse::err(ERR_BAD_REQUEST, "confirm must be \"ERASE\"");
        }
        match self.state {
            DeviceState::ProdLocked | DeviceState::ProdReady => {
                if !self.physical_recovery_authorized {
                    match &req.pin {
                        Some(pin) => {
                            if let Err(resp) = self.verify_pin(pin) {
                                return resp;
                            }
                        }
                        None => {
                            return HsmResponse::err(
                                ERR_BAD_REQUEST,
                                "factory-reset requires a PIN or physical recovery held low during reset",
                            )
                        }
                    }
                }
            }
            DeviceState::LockedOut => {
                if !self.physical_recovery_authorized {
                    return HsmResponse::err(
                        ERR_LOCKED_OUT,
                        "device locked out; hold physical recovery low during reset",
                    );
                }
            }
            DeviceState::Uninitialized | DeviceState::DevReady => {}
        }
        // Drop live secrets from RAM first, regardless of the flash outcome.
        self.drop_live_secrets();

        // Erase every persistent region and verify the sensitive records are
        // actually gone; do not claim success while key material may remain.
        let key_gone = self.erase_key_verified();
        let cfg_ok = storage::CONFIG.erase_both(&mut self.flash).is_ok();
        let time_ok = storage::TIME_FLOOR.erase_both(&mut self.flash).is_ok();
        let pin_ok = pin::reset(&mut self.flash).is_ok();
        let cfg_gone = matches!(storage::CONFIG.read_latest(&mut self.flash), Ok(None));
        let time_gone = matches!(storage::TIME_FLOOR.read_latest(&mut self.flash), Ok(None));

        if key_gone && cfg_ok && time_ok && pin_ok && cfg_gone && time_gone {
            self.ca_pubkey = None;
            self.config = None;
            self.trusted_time_floor = None;
            self.trusted_time_floor_unavailable = false;
            self.pin_backoff_until_ms = 0;
            self.state = DeviceState::Uninitialized;
            return HsmResponse::with(|r| r.factory_reset = Some(OkResp { ok: true }));
        }
        // A region failed to erase. Resync RAM from whatever persists so status
        // reflects reality, then report failure so the operator retries.
        self.load_from_flash();
        HsmResponse::err(
            ERR_FLASH,
            "factory reset incomplete; key material may remain — retry",
        )
    }

    // ---- helpers ----------------------------------------------------------

    /// Pre-tick the counter, derive the PIN KEK, and unwrap the seed. On a wrong
    /// PIN, applies backoff and lockout (wiping the key if configured) and
    /// returns the structured error response.
    ///
    /// Backoff is enforced as a non-blocking gate before flash writes or
    /// Argon2id work. It has a real failure-relative deadline in RAM and is
    /// conservatively reconstructed from the persisted counter on boot.
    #[allow(clippy::result_large_err)] // HsmResponse is the natural error payload here
    fn verify_pin(&mut self, pin_str: &str) -> Result<UnlockedSeed, HsmResponse> {
        let cfg = self.config.expect("prod implies config");

        let prior_failures = match pin::count(&mut self.flash) {
            Ok(n) => n,
            Err(_) => return Err(HsmResponse::err(ERR_FLASH, "counter read failed")),
        };
        if prior_failures > 0 {
            let now_ms = self.mono.now_micros() / 1000;
            if now_ms < self.pin_backoff_until_ms {
                let remaining = (cfg.max_retries as u32).saturating_sub(prior_failures as u32);
                return Err(pin_error(
                    ERR_BUSY,
                    "still backing off after a recent failed attempt",
                    remaining,
                    (self.pin_backoff_until_ms - now_ms) as u32,
                ));
            }
        }

        let attempts = match pin::tick(&mut self.flash) {
            Ok(a) => a,
            Err(_) => return Err(HsmResponse::err(ERR_FLASH, "counter write failed")),
        };
        // Read the key blob first: the Argon2 salt that derives the KEK lives in
        // the blob (v2), so we need it before deriving. The pre-tick above
        // already counted this attempt, so doing flash reads here is safe.
        let blob = match storage::KEY.read_latest(&mut self.flash) {
            Ok(Some(b)) => match KeyBlob::from_bytes(&b) {
                Some(kb) => kb,
                None => return Err(HsmResponse::err(ERR_INTERNAL, "corrupt key blob")),
            },
            Ok(None) => return Err(HsmResponse::err(ERR_NO_KEY, "no CA key present")),
            Err(_) => return Err(HsmResponse::err(ERR_FLASH, "key read failed")),
        };
        let secret = match self.flash.device_secret() {
            Ok(s) => s,
            Err(_) => {
                return Err(HsmResponse::err(ERR_INTERNAL, "device secret unavailable"));
            }
        };
        let kek = match pin_kek(pin_str.as_bytes(), &blob.salt, &cfg.argon2, &secret) {
            Ok(k) => k,
            Err(_) => return Err(HsmResponse::err(ERR_INTERNAL, "key derivation failed")),
        };
        match unwrap_seed(&kek, &blob) {
            Ok(seed) => {
                self.reset_pin_counter_best_effort();
                Ok((seed, kek, blob.salt))
            }
            Err(_) => {
                let max = cfg.max_retries as u32;
                let backoff = pin::backoff_ms(attempts.saturating_sub(1) as u32);
                self.pin_backoff_until_ms =
                    (self.mono.now_micros() / 1000).saturating_add(backoff as u64);
                if attempts as u32 >= max {
                    self.enter_locked_out();
                    if cfg.wipe_on_lockout {
                        // Only claim the wipe once both key copies are verified
                        // unreadable; otherwise surface a hard error rather than
                        // pretending the CA key was destroyed.
                        if self.erase_key_verified() {
                            self.ca_pubkey = None;
                        } else {
                            return Err(pin_error(
                                ERR_FLASH,
                                "lockout reached but key wipe failed; key material may remain",
                                0,
                                backoff,
                            ));
                        }
                    }
                    Err(pin_error(
                        ERR_LOCKED_OUT,
                        "too many attempts; device locked out",
                        0,
                        backoff,
                    ))
                } else {
                    let remaining = max.saturating_sub(attempts as u32);
                    Err(pin_error(ERR_BAD_PIN, "incorrect PIN", remaining, backoff))
                }
            }
        }
    }

    /// Erase both copies of the CA key record and confirm no valid record
    /// remains, retrying once. Returns false if key material may still be
    /// readable in flash, so callers can fail closed instead of claiming the
    /// key was destroyed.
    fn erase_key_verified(&mut self) -> bool {
        for _ in 0..2 {
            let _ = storage::KEY.erase_both(&mut self.flash);
            if matches!(storage::KEY.read_latest(&mut self.flash), Ok(None)) {
                return true;
            }
        }
        false
    }

    /// Reset the PIN attempt counter, retrying once on failure (mirrors
    /// [`Self::erase_key_verified`]'s bounded retry). Called after proving PIN
    /// knowledge or committing a fresh config/key — a lingering non-zero
    /// counter here is fail-*closed* (it can only cause a spurious future
    /// lockout, never weaken PIN gating), so this improves reliability
    /// without blocking an otherwise-successful response on a single flash
    /// erase hiccup.
    fn reset_pin_counter_best_effort(&mut self) {
        for _ in 0..2 {
            if pin::reset(&mut self.flash).is_ok() {
                self.pin_backoff_until_ms = 0;
                return;
            }
        }
    }

    /// Drop every production live secret. Safe to call redundantly.
    fn drop_live_secrets(&mut self) {
        self.ca = None;
        self.wrap_kek = None;
        self.wrap_salt = None;
    }

    /// Centralized lockout entry keeps state and secret destruction inseparable.
    fn enter_locked_out(&mut self) {
        self.drop_live_secrets();
        self.state = DeviceState::LockedOut;
    }

    /// Force a production device back to `ProdLocked`, dropping the live CA
    /// key, independent of the `hsm.lock` command. Intended for the firmware
    /// to call on a transport-level disconnect (USB bus reset/suspend) —
    /// `docs/THREAT_MODEL.md` documents production devices as re-locking on
    /// exactly those events. Production state and config are checked
    /// independently so a fault cannot suppress cleanup by desynchronizing
    /// them; genuine dev mode retains its normal no-lock behavior.
    pub fn relock_on_transport_reset(&mut self) {
        let production_state = matches!(
            self.state,
            DeviceState::ProdLocked | DeviceState::ProdReady | DeviceState::LockedOut
        );
        let production_config = self.config.map(|c| c.mode) == Some(Mode::Prod);
        if production_state || production_config {
            self.drop_live_secrets();
            if self.state == DeviceState::ProdReady {
                self.state = DeviceState::ProdLocked;
            }
        }
    }

    /// Ensure the DRBG has been seeded at least once (used on the signing hot
    /// path, which needs a seeded CSPRNG but not fresh hardware entropy).
    fn ensure_seeded(&mut self) -> Result<(), HalError> {
        if !self.drbg.is_seeded() {
            self.drbg.seed(&mut self.entropy)?;
        }
        Ok(())
    }

    /// Ensure the DRBG is seeded, then reseed from fresh hardware entropy. Used
    /// before generating long-lived CA key material (init / generateKey) for
    /// defense in depth. Both steps health-check (with retry); a persistently
    /// unhealthy source returns [`HalError::Entropy`].
    fn prepare_keygen_entropy(&mut self) -> Result<(), HalError> {
        self.ensure_seeded()?;
        self.drbg.reseed(&mut self.entropy)
    }
}

fn pin_error(code: &str, message: &str, remaining: u32, backoff: u32) -> HsmResponse {
    HsmResponse {
        error: Some(HsmError {
            code: code.to_string(),
            message: message.to_string(),
            remaining_attempts: Some(remaining),
            backoff_ms: Some(backoff),
        }),
        ..Default::default()
    }
}

fn fw_version_triple() -> [u8; 3] {
    let mut parts = FW_VERSION.split('.').map(|p| p.parse::<u8>().unwrap_or(0));
    [
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    ]
}

fn hex_encode(b: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len() * 2);
    for &x in b {
        s.push(HEX[(x >> 4) as usize] as char);
        s.push(HEX[(x & 0xf) as usize] as char);
    }
    s
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < b.len() {
        out.push((hexval(b[i])? << 4) | hexval(b[i + 1])?);
        i += 2;
    }
    Some(out)
}

fn hexval(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sshwire::{b64_decode, b64_encode, put_string, Reader};
    use crate::testhal::{MockClock, MockEntropy, MockFlash};
    use alloc::vec;
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use serde_json::Value;

    fn boot() -> Hsm<MockEntropy, MockClock, MockFlash> {
        Hsm::boot(
            MockEntropy::new(0xC0FFEE),
            MockClock::new(),
            MockFlash::new(),
        )
    }

    fn call<F: FlashStore>(hsm: &mut Hsm<MockEntropy, MockClock, F>, json: &str) -> Value {
        let out = hsm.process_line(json.as_bytes());
        serde_json::from_slice(&out).expect("response is valid JSON")
    }

    /// Advance the mock monotonic clock (test helper for the PIN backoff
    /// gate, which is reset-resistant and therefore keyed off `mono`, not a
    /// blocking sleep — see `verify_pin`).
    fn advance<F: FlashStore>(hsm: &mut Hsm<MockEntropy, MockClock, F>, secs: u64) {
        hsm.mono.advance_secs(secs);
    }

    fn user_ed25519_line() -> String {
        let mut blob = Vec::new();
        put_string(&mut blob, b"ssh-ed25519");
        put_string(&mut blob, &[0x11u8; 32]);
        format!("ssh-ed25519 {} user@host", b64_encode(&blob))
    }

    fn ca_pub_from_line(line: &str) -> [u8; 32] {
        let b64 = line.split(' ').nth(1).unwrap();
        let raw = b64_decode(b64).unwrap();
        let mut r = Reader::new(&raw);
        assert_eq!(r.read_string().unwrap(), b"ssh-ed25519");
        let pk = r.read_string().unwrap();
        let mut out = [0u8; 32];
        out.copy_from_slice(pk);
        out
    }

    struct CertFields {
        serial: u64,
        cert_type: u32,
        valid_after: u64,
        valid_before: u64,
        principals: Vec<String>,
    }

    /// Walk an ed25519-user certificate, verify the CA signature, and return the
    /// decoded fields.
    fn verify_and_decode(cert_line: &str, ca_pub: &[u8; 32]) -> CertFields {
        let (algo, b64) = cert_line.split_once(' ').unwrap();
        assert_eq!(algo, "ssh-ed25519-cert-v01@openssh.com");
        let raw = b64_decode(b64).unwrap();
        let mut r = Reader::new(&raw);
        assert_eq!(r.read_string().unwrap(), algo.as_bytes()); // cert algo
        r.read_string().unwrap(); // nonce
        r.read_string().unwrap(); // ed25519 user pubkey body
        let serial = read_u64(&raw, &mut r);
        let cert_type = read_u32(&raw, &mut r);
        let _key_id = r.read_string().unwrap();
        let principals_blob = r.read_string().unwrap().to_vec();
        let valid_after = read_u64(&raw, &mut r);
        let valid_before = read_u64(&raw, &mut r);
        r.read_string().unwrap(); // critical options
        r.read_string().unwrap(); // extensions
        r.read_string().unwrap(); // reserved
        r.read_string().unwrap(); // signature key
        let signed_len = r.position();
        let sig_field = r.read_string().unwrap();
        assert!(r.is_empty(), "no trailing bytes after signature");

        // Verify the CA signature over the bytes-for-signing prefix.
        let mut sr = Reader::new(sig_field);
        assert_eq!(sr.read_string().unwrap(), b"ssh-ed25519");
        let sig = sr.read_string().unwrap();
        let vk = VerifyingKey::from_bytes(ca_pub).unwrap();
        vk.verify(&raw[..signed_len], &Signature::from_slice(sig).unwrap())
            .expect("CA signature verifies");

        // Decode the principals list.
        let mut pr = Reader::new(&principals_blob);
        let mut principals = Vec::new();
        while !pr.is_empty() {
            principals.push(String::from_utf8(pr.read_string().unwrap().to_vec()).unwrap());
        }

        CertFields {
            serial,
            cert_type,
            valid_after,
            valid_before,
            principals,
        }
    }

    fn read_u64(raw: &[u8], r: &mut Reader<'_>) -> u64 {
        let p = r.position();
        r.skip(8).unwrap();
        u64::from_be_bytes(raw[p..p + 8].try_into().unwrap())
    }
    fn read_u32(raw: &[u8], r: &mut Reader<'_>) -> u32 {
        let p = r.position();
        r.skip(4).unwrap();
        u32::from_be_bytes(raw[p..p + 4].try_into().unwrap())
    }

    fn sign_request(validity: &str) -> String {
        format!(
            r#"{{"signSshKey":{{"ssh_key":"{}","key_id":"kid","principals":["alice","bob"],"validity":"{}"}}}}"#,
            user_ed25519_line(),
            validity
        )
    }

    #[test]
    fn dev_lifecycle_and_signature() {
        let mut h = boot();

        // Uninitialized status.
        let s = call(&mut h, r#"{"hsm":{"status":{}}}"#);
        assert_eq!(s["hsm"]["status"]["state"], "uninitialized");

        // init dev.
        let r = call(&mut h, r#"{"hsm":{"init":{"mode":"dev"}}}"#);
        assert_eq!(r["hsm"]["init"]["ok"], true);
        assert_eq!(h.state(), DeviceState::DevReady);

        // generateKey.
        let g = call(&mut h, r#"{"hsm":{"generateKey":{}}}"#);
        assert_eq!(g["hsm"]["generateKey"]["ok"], true);
        let ca_line = g["hsm"]["generateKey"]["publicKey"]
            .as_str()
            .unwrap()
            .to_string();
        let ca_pub = ca_pub_from_line(&ca_line);

        // Ping before time set: signer not loaded (clock unset).
        let p = call(&mut h, r#"{"ping":{}}"#);
        assert_eq!(p["pong"]["signerLoaded"], false);

        // Sign before time set: fails closed.
        let e = call(&mut h, &sign_request("1h"));
        assert_eq!(e["error"], "device clock not set; send hsm.setTime first");

        // Set time, then ping reports loaded.
        call(&mut h, r#"{"hsm":{"setTime":{"unixSeconds":1700000000}}}"#);
        let p = call(&mut h, r#"{"ping":{}}"#);
        assert_eq!(p["pong"]["signerLoaded"], true);

        // Sign and verify the certificate.
        let resp = call(&mut h, &sign_request("1h"));
        let cert = resp["signSshKey"]["signed_key"].as_str().unwrap();
        let f = verify_and_decode(cert, &ca_pub);
        assert_eq!(f.cert_type, 1); // user cert
        assert_eq!(f.valid_after, 1_700_000_000 - 300);
        assert_eq!(f.valid_before, 1_700_000_000 + 3600);
        assert_eq!(f.principals, vec!["alice".to_string(), "bob".to_string()]);
        assert_ne!(f.serial, 0);
    }

    #[test]
    fn invalid_validity_is_top_level_error() {
        let mut h = boot();
        call(&mut h, r#"{"hsm":{"init":{"mode":"dev"}}}"#);
        call(&mut h, r#"{"hsm":{"generateKey":{}}}"#);
        call(&mut h, r#"{"hsm":{"setTime":{"unixSeconds":1700000000}}}"#);
        let e = call(&mut h, &sign_request("25h"));
        assert_eq!(
            e["error"],
            "validity duration 25h0m0s exceeds maximum allowed 24h0m0s"
        );
    }

    #[test]
    fn exactly_one_variant_enforced() {
        let mut h = boot();
        let e = call(&mut h, r#"{"ping":{},"getEnclaveMetrics":{}}"#);
        assert_eq!(
            e["error"],
            "multiple request variants set; expected exactly one"
        );
        let u = call(&mut h, r#"{}"#);
        assert_eq!(u["error"], "unexpected command");
    }

    #[test]
    fn prod_lifecycle_unlock_lock() {
        let mut h = boot();
        let r = call(
            &mut h,
            r#"{"hsm":{"init":{"mode":"prod","pin":"hunter2","maxRetries":3}}}"#,
        );
        assert_eq!(r["hsm"]["init"]["mode"], "prod");
        assert_eq!(h.state(), DeviceState::ProdLocked);

        // getPublicKey works while locked.
        let pk = call(&mut h, r#"{"hsm":{"getPublicKey":{}}}"#);
        let ca_line = pk["hsm"]["getPublicKey"]["publicKey"]
            .as_str()
            .unwrap()
            .to_string();
        let ca_pub = ca_pub_from_line(&ca_line);

        call(&mut h, r#"{"hsm":{"setTime":{"unixSeconds":1700000000}}}"#);

        // Sign while locked: fails.
        let e = call(&mut h, &sign_request("1h"));
        assert_eq!(
            e["error"],
            "CA signer is not initialized; call LoadKeySigner first"
        );

        // Wrong PIN: bad-pin error with remaining attempts.
        let w = call(&mut h, r#"{"hsm":{"unlock":{"pin":"wrongpin"}}}"#);
        assert_eq!(w["hsm"]["error"]["code"], "ERR_BAD_PIN");
        assert_eq!(w["hsm"]["error"]["remainingAttempts"], 2);
        assert_eq!(h.state(), DeviceState::ProdLocked);

        // The next attempt is gated until the reported backoff elapses (see
        // `verify_pin`); advance past it before retrying.
        advance(&mut h, 1);

        // Correct PIN: unlocked.
        let u = call(&mut h, r#"{"hsm":{"unlock":{"pin":"hunter2"}}}"#);
        assert_eq!(u["hsm"]["unlock"]["ok"], true);
        assert_eq!(h.state(), DeviceState::ProdReady);

        // Sign works, signature verifies against the same CA pubkey.
        let resp = call(&mut h, &sign_request("2h"));
        let cert = resp["signSshKey"]["signed_key"].as_str().unwrap();
        let f = verify_and_decode(cert, &ca_pub);
        // +1 for the `advance(&mut h, 1)` paid out above to clear the backoff gate.
        assert_eq!(f.valid_before, 1_700_000_000 + 1 + 7200);

        // Lock: signing fails again.
        call(&mut h, r#"{"hsm":{"lock":{}}}"#);
        assert_eq!(h.state(), DeviceState::ProdLocked);
        let e = call(&mut h, &sign_request("1h"));
        assert_eq!(
            e["error"],
            "CA signer is not initialized; call LoadKeySigner first"
        );
    }

    #[test]
    fn prod_lockout_and_factory_reset() {
        let mut h = boot();
        call(
            &mut h,
            r#"{"hsm":{"init":{"mode":"prod","pin":"hunter2","maxRetries":3,"wipeOnLockout":true}}}"#,
        );
        // Three wrong attempts -> lockout, key wiped. Each attempt is gated
        // behind the previous one's backoff (see `verify_pin`).
        for _ in 0..3 {
            call(&mut h, r#"{"hsm":{"unlock":{"pin":"nope"}}}"#);
            advance(&mut h, 1);
        }
        assert_eq!(h.state(), DeviceState::LockedOut);
        let e = call(&mut h, r#"{"hsm":{"unlock":{"pin":"hunter2"}}}"#);
        assert_eq!(e["hsm"]["error"]["code"], "ERR_LOCKED_OUT");
        // getPublicKey now fails: key was wiped.
        let pk = call(&mut h, r#"{"hsm":{"getPublicKey":{}}}"#);
        assert_eq!(pk["hsm"]["error"]["code"], "ERR_NO_KEY");

        // LockedOut devices never accept another PIN. Recovery requires the
        // boot-latched physical gesture.
        let denied = call(&mut h, r#"{"hsm":{"factoryReset":{"confirm":"ERASE"}}}"#);
        assert_eq!(denied["hsm"]["error"]["code"], "ERR_LOCKED_OUT");
        h.set_physical_recovery_authorized(true);
        let fr = call(&mut h, r#"{"hsm":{"factoryReset":{"confirm":"ERASE"}}}"#);
        assert_eq!(fr["hsm"]["factoryReset"]["ok"], true);
        assert_eq!(h.state(), DeviceState::Uninitialized);
    }

    #[test]
    fn factory_reset_requires_pin_or_physical_recovery_when_locked() {
        // A prodLocked device must not be destroyable by an attacker who only
        // has USB/physical access but not the PIN — the primary regression
        // test for the unauthenticated-factoryReset finding.
        let mut h = boot();
        call(
            &mut h,
            r#"{"hsm":{"init":{"mode":"prod","pin":"hunter2pw"}}}"#,
        );
        assert_eq!(h.state(), DeviceState::ProdLocked);

        // No PIN and no physical recovery: rejected, key intact.
        let denied = call(&mut h, r#"{"hsm":{"factoryReset":{"confirm":"ERASE"}}}"#);
        assert_eq!(denied["hsm"]["error"]["code"], "ERR_BAD_REQUEST");
        assert_eq!(h.state(), DeviceState::ProdLocked);

        // Wrong pin: rejected as a normal bad-PIN attempt (ticks the counter).
        let wrong = call(
            &mut h,
            r#"{"hsm":{"factoryReset":{"confirm":"ERASE","pin":"nope"}}}"#,
        );
        assert_eq!(wrong["hsm"]["error"]["code"], "ERR_BAD_PIN");
        assert_eq!(h.state(), DeviceState::ProdLocked);
        advance(&mut h, 1);

        // Correct pin: erases as before.
        let ok = call(
            &mut h,
            r#"{"hsm":{"factoryReset":{"confirm":"ERASE","pin":"hunter2pw"}}}"#,
        );
        assert_eq!(ok["hsm"]["factoryReset"]["ok"], true);
        assert_eq!(h.state(), DeviceState::Uninitialized);
    }

    #[test]
    fn factory_reset_physical_recovery_bypasses_forgotten_pin() {
        let mut h = boot();
        call(
            &mut h,
            r#"{"hsm":{"init":{"mode":"prod","pin":"hunter2pw"}}}"#,
        );
        // A legacy wire-level force field is ignored and grants no authority.
        let legacy = call(
            &mut h,
            r#"{"hsm":{"factoryReset":{"confirm":"ERASE","force":true}}}"#,
        );
        assert_eq!(legacy["hsm"]["error"]["code"], "ERR_BAD_REQUEST");
        h.set_physical_recovery_authorized(true);
        let r = call(&mut h, r#"{"hsm":{"factoryReset":{"confirm":"ERASE"}}}"#);
        assert_eq!(r["hsm"]["factoryReset"]["ok"], true);
        assert_eq!(h.state(), DeviceState::Uninitialized);
    }

    #[test]
    fn reboot_bootloader_requires_pin_or_physical_recovery_when_locked() {
        // Mirrors the factoryReset gating: a locked device must not let an
        // unauthenticated USB party force it into the bootloader, which (pre
        // secure-boot burn) accepts arbitrary firmware over the same USB link.
        let mut h = boot();
        call(
            &mut h,
            r#"{"hsm":{"init":{"mode":"prod","pin":"hunter2pw"}}}"#,
        );

        let denied = call(&mut h, r#"{"hsm":{"rebootBootloader":{}}}"#);
        assert_eq!(denied["hsm"]["error"]["code"], "ERR_BAD_REQUEST");

        let legacy = call(&mut h, r#"{"hsm":{"rebootBootloader":{"force":true}}}"#);
        assert_eq!(legacy["hsm"]["error"]["code"], "ERR_BAD_REQUEST");

        h.set_physical_recovery_authorized(true);
        let recovered = call(&mut h, r#"{"hsm":{"rebootBootloader":{}}}"#);
        assert_eq!(recovered["hsm"]["rebootBootloader"]["ok"], true);
    }

    #[test]
    fn locked_out_recovery_never_verifies_pin_but_allows_physical_reboot() {
        let mut h = boot();
        call(
            &mut h,
            r#"{"hsm":{"init":{"mode":"prod","pin":"hunter2pw","maxRetries":1}}}"#,
        );
        assert_eq!(
            call(&mut h, r#"{"hsm":{"unlock":{"pin":"wrongpin"}}}"#)["hsm"]["error"]["code"],
            "ERR_LOCKED_OUT"
        );
        let pin = call(
            &mut h,
            r#"{"hsm":{"rebootBootloader":{"pin":"hunter2pw"}}}"#,
        );
        assert_eq!(pin["hsm"]["error"]["code"], "ERR_LOCKED_OUT");
        h.set_physical_recovery_authorized(true);
        let recovered = call(&mut h, r#"{"hsm":{"rebootBootloader":{}}}"#);
        assert_eq!(recovered["hsm"]["rebootBootloader"]["ok"], true);
    }

    #[test]
    fn reboot_bootloader_unrestricted_before_provisioning() {
        // A fresh, never-initialized board must stay reboot-able into the
        // bootloader with no PIN — there is nothing to protect yet, and it
        // must be flashable for the very first time.
        let mut h = boot();
        assert_eq!(h.state(), DeviceState::Uninitialized);
        let r = call(&mut h, r#"{"hsm":{"rebootBootloader":{}}}"#);
        assert_eq!(r["hsm"]["rebootBootloader"]["ok"], true);
    }

    #[test]
    fn pin_backoff_gate_resists_reboot() {
        // The core regression test for the reset-skippable-backoff finding: a
        // failed attempt's backoff must still be paid out even across a real
        // reboot (a fresh `Hsm`/monotonic clock over the same persisted
        // flash), not just within one continuous session.
        let mut flash = MockFlash::new();
        {
            let mut h = Hsm::boot(MockEntropy::new(1), MockClock::new(), &mut flash);
            call(
                &mut h,
                r#"{"hsm":{"init":{"mode":"prod","pin":"hunter2pw","maxRetries":10}}}"#,
            );
            let w = call(&mut h, r#"{"hsm":{"unlock":{"pin":"nope"}}}"#);
            assert_eq!(w["hsm"]["error"]["code"], "ERR_BAD_PIN");
        }
        // "Reboot": fresh Hsm, fresh monotonic clock (starts at 0 again), same
        // flash — the persisted attempt count survives, so the gate must
        // still refuse an immediate retry even with the correct PIN.
        let mut h2 = Hsm::boot(MockEntropy::new(2), MockClock::new(), &mut flash);
        let too_soon = call(&mut h2, r#"{"hsm":{"unlock":{"pin":"hunter2pw"}}}"#);
        assert_eq!(too_soon["hsm"]["error"]["code"], "ERR_BUSY");
        assert_eq!(h2.state(), DeviceState::ProdLocked);

        // Waiting out the reported backoff (from this boot's zero point) lets
        // the correct PIN through.
        advance(&mut h2, 1);
        let ok = call(&mut h2, r#"{"hsm":{"unlock":{"pin":"hunter2pw"}}}"#);
        assert_eq!(ok["hsm"]["unlock"]["ok"], true);
    }

    #[test]
    fn pin_backoff_is_relative_to_the_failure_not_total_uptime() {
        let mut h = boot();
        call(
            &mut h,
            r#"{"hsm":{"init":{"mode":"prod","pin":"hunter2pw","maxRetries":10}}}"#,
        );
        advance(&mut h, 60);
        let wrong = call(&mut h, r#"{"hsm":{"unlock":{"pin":"wrongpin"}}}"#);
        assert_eq!(wrong["hsm"]["error"]["code"], "ERR_BAD_PIN");
        let immediate = call(&mut h, r#"{"hsm":{"unlock":{"pin":"hunter2pw"}}}"#);
        assert_eq!(immediate["hsm"]["error"]["code"], "ERR_BUSY");
    }

    #[test]
    fn prod_init_rejects_zero_retry_budget() {
        let mut h = boot();
        let r = call(
            &mut h,
            r#"{"hsm":{"init":{"mode":"prod","pin":"hunter2pw","maxRetries":0}}}"#,
        );
        assert_eq!(r["hsm"]["error"]["code"], "ERR_BAD_REQUEST");
        assert_eq!(h.state(), DeviceState::Uninitialized);
    }

    #[test]
    fn lockout_drops_live_secrets_and_cannot_sign() {
        let mut h = boot();
        call(
            &mut h,
            r#"{"hsm":{"init":{"mode":"prod","pin":"hunter2pw","maxRetries":1}}}"#,
        );
        call(&mut h, r#"{"hsm":{"unlock":{"pin":"hunter2pw"}}}"#);
        call(&mut h, r#"{"hsm":{"setTime":{"unixSeconds":1700000000}}}"#);
        assert!(call(&mut h, &sign_request("1h"))["signSshKey"].is_object());

        let locked = call(
            &mut h,
            r#"{"hsm":{"changePin":{"currentPin":"wrongpin","newPin":"newpassword"}}}"#,
        );
        assert_eq!(locked["hsm"]["error"]["code"], "ERR_LOCKED_OUT");
        assert_eq!(h.state(), DeviceState::LockedOut);
        assert!(h.ca.is_none());
        assert!(h.wrap_kek.is_none());
        assert!(h.wrap_salt.is_none());
        assert!(call(&mut h, &sign_request("1h"))["error"].is_string());
    }

    #[test]
    fn transport_reset_scrubs_prod_ready_secrets_when_config_is_missing() {
        let mut h = boot();
        call(
            &mut h,
            r#"{"hsm":{"init":{"mode":"prod","pin":"hunter2pw"}}}"#,
        );
        call(&mut h, r#"{"hsm":{"unlock":{"pin":"hunter2pw"}}}"#);
        assert_eq!(h.state(), DeviceState::ProdReady);
        assert!(h.ca.is_some());
        assert!(h.wrap_kek.is_some());
        assert!(h.wrap_salt.is_some());

        // Model a fault that desynchronizes cached config from production
        // state. Transport cleanup must rely on the state independently.
        h.config = None;
        h.relock_on_transport_reset();
        assert_eq!(h.state(), DeviceState::ProdLocked);
        assert!(h.ca.is_none());
        assert!(h.wrap_kek.is_none());
        assert!(h.wrap_salt.is_none());
    }

    #[test]
    fn pin_backoff_gate_does_not_apply_to_first_attempt() {
        // No prior failures means no gate — a freshly initialized device's
        // very first unlock must not be delayed.
        let mut h = boot();
        call(
            &mut h,
            r#"{"hsm":{"init":{"mode":"prod","pin":"hunter2pw"}}}"#,
        );
        let ok = call(&mut h, r#"{"hsm":{"unlock":{"pin":"hunter2pw"}}}"#);
        assert_eq!(ok["hsm"]["unlock"]["ok"], true);
    }

    #[test]
    fn set_time_rejects_implausible_first_value() {
        let mut h = boot();
        let r = call(&mut h, r#"{"hsm":{"setTime":{"unixSeconds":1}}}"#);
        assert_eq!(r["hsm"]["error"]["code"], "ERR_BAD_REQUEST");
        let s = call(&mut h, r#"{"hsm":{"status":{}}}"#);
        assert_eq!(s["hsm"]["status"]["clockSet"], false);
    }

    #[test]
    fn set_time_rejects_large_forward_jump_after_first_set() {
        // The regression test for the unbounded-setTime finding: a
        // signing-capable host must not be able to march the clock a year
        // into the future immediately before signing, to pre-mint
        // certificates dated outside their true issuance window.
        let mut h = boot();
        call(&mut h, r#"{"hsm":{"init":{"mode":"dev"}}}"#);
        call(&mut h, r#"{"hsm":{"generateKey":{}}}"#);
        let ok = call(&mut h, r#"{"hsm":{"setTime":{"unixSeconds":1700000000}}}"#);
        assert_eq!(ok["hsm"]["setTime"]["ok"], true);

        let one_year = 365 * 24 * 3600;
        let jumped = call(
            &mut h,
            &format!(
                r#"{{"hsm":{{"setTime":{{"unixSeconds":{}}}}}}}"#,
                1_700_000_000 + one_year
            ),
        );
        assert_eq!(jumped["hsm"]["error"]["code"], "ERR_BAD_REQUEST");

        // The clock did not move: a cert signed now still gets the original
        // (unjumped) validity window.
        let resp = call(&mut h, &sign_request("1h"));
        let cert = resp["signSshKey"]["signed_key"].as_str().unwrap();
        let ca_line = call(&mut h, r#"{"hsm":{"getPublicKey":{}}}"#)["hsm"]["getPublicKey"]
            ["publicKey"]
            .as_str()
            .unwrap()
            .to_string();
        let ca_pub = ca_pub_from_line(&ca_line);
        let f = verify_and_decode(cert, &ca_pub);
        assert_eq!(f.valid_before, 1_700_000_000 + 3600);
    }

    #[test]
    fn persisted_time_floor_blocks_reboot_reanchor_without_physical_recovery() {
        let mut flash = MockFlash::new();
        {
            let mut h = Hsm::boot(MockEntropy::new(1), MockClock::new(), &mut flash);
            assert_eq!(
                call(&mut h, r#"{"hsm":{"setTime":{"unixSeconds":1700000000}}}"#)["hsm"]["setTime"]
                    ["ok"],
                true
            );
        }
        let mut h = Hsm::boot(MockEntropy::new(2), MockClock::new(), &mut flash);
        let one_year = 365 * 24 * 3600;
        let denied = call(
            &mut h,
            &format!(
                r#"{{"hsm":{{"setTime":{{"unixSeconds":{}}}}}}}"#,
                1_700_000_000 + one_year
            ),
        );
        assert_eq!(denied["hsm"]["error"]["code"], "ERR_BAD_REQUEST");
        h.set_physical_recovery_authorized(true);
        let recovered = call(
            &mut h,
            &format!(
                r#"{{"hsm":{{"setTime":{{"unixSeconds":{}}}}}}}"#,
                1_700_000_000 + one_year
            ),
        );
        assert_eq!(recovered["hsm"]["setTime"]["ok"], true);
    }

    #[test]
    fn trusted_time_floor_read_error_fails_closed() {
        for region in [crate::hal::Region::TimeA, crate::hal::Region::TimeB] {
            let mut flash = MockFlash::new();
            storage::TIME_FLOOR
                .write(&mut flash, &1_700_000_000i64.to_be_bytes())
                .unwrap();
            flash.set_read_fault(Some(region));

            let mut h = Hsm::boot(MockEntropy::new(1), MockClock::new(), &mut flash);
            // Physical recovery authorizes a deliberate large re-anchor, but
            // never bypasses unavailable trusted-time storage.
            h.set_physical_recovery_authorized(true);
            let r = call(&mut h, r#"{"hsm":{"setTime":{"unixSeconds":1731536000}}}"#);
            assert_eq!(r["hsm"]["error"]["code"], "ERR_FLASH");
            assert!(!h.clock.is_set());

            // The boot's failure remains latched even if the transient fault
            // clears. A clean reboot re-reads the persisted floor safely.
            h.flash.set_read_fault(None);
            let retry = call(&mut h, r#"{"hsm":{"setTime":{"unixSeconds":1700000000}}}"#);
            assert_eq!(retry["hsm"]["error"]["code"], "ERR_FLASH");
            drop(h);

            let mut rebooted = Hsm::boot(MockEntropy::new(2), MockClock::new(), &mut flash);
            let recovered = call(
                &mut rebooted,
                r#"{"hsm":{"setTime":{"unixSeconds":1700000000}}}"#,
            );
            assert_eq!(recovered["hsm"]["setTime"]["ok"], true);
        }
    }

    #[test]
    fn malformed_trusted_time_floor_fails_closed() {
        let mut flash = MockFlash::new();
        storage::TIME_FLOOR.write(&mut flash, b"short").unwrap();

        let mut h = Hsm::boot(MockEntropy::new(1), MockClock::new(), &mut flash);
        let r = call(&mut h, r#"{"hsm":{"setTime":{"unixSeconds":1700000000}}}"#);
        assert_eq!(r["hsm"]["error"]["code"], "ERR_FLASH");
        assert!(!h.clock.is_set());
    }

    #[test]
    fn factory_reset_erases_persisted_time_floor() {
        let mut flash = MockFlash::new();
        {
            let mut h = Hsm::boot(MockEntropy::new(1), MockClock::new(), &mut flash);
            call(&mut h, r#"{"hsm":{"init":{"mode":"dev"}}}"#);
            call(&mut h, r#"{"hsm":{"setTime":{"unixSeconds":1700000000}}}"#);
            assert_eq!(
                call(&mut h, r#"{"hsm":{"factoryReset":{"confirm":"ERASE"}}}"#)["hsm"]
                    ["factoryReset"]["ok"],
                true
            );
        }
        let mut h = Hsm::boot(MockEntropy::new(2), MockClock::new(), &mut flash);
        let one_year = 365 * 24 * 3600;
        let resync = call(
            &mut h,
            &format!(
                r#"{{"hsm":{{"setTime":{{"unixSeconds":{}}}}}}}"#,
                1_700_000_000 + one_year
            ),
        );
        assert_eq!(resync["hsm"]["setTime"]["ok"], true);
    }

    #[test]
    fn persistence_across_reboot() {
        // Build a flash image with dev mode + key, then "reboot" into a new Hsm
        // over the same flash and confirm the key reloads.
        let mut flash = MockFlash::new();
        {
            let mut h = Hsm::boot(MockEntropy::new(1), MockClock::new(), &mut flash);
            call(&mut h, r#"{"hsm":{"init":{"mode":"dev"}}}"#);
            call(&mut h, r#"{"hsm":{"generateKey":{}}}"#);
            assert!(h.state() == DeviceState::DevReady);
        }
        // Reboot.
        let mut h2 = Hsm::boot(MockEntropy::new(2), MockClock::new(), &mut flash);
        assert_eq!(h2.state(), DeviceState::DevReady);
        let s = call(&mut h2, r#"{"hsm":{"status":{}}}"#);
        assert_eq!(s["hsm"]["status"]["keyPresent"], true);
        assert_eq!(s["hsm"]["status"]["unlocked"], true); // dev key auto-loads
    }

    #[test]
    fn prod_persists_locked_across_reboot() {
        let mut flash = MockFlash::new();
        {
            let mut h = Hsm::boot(MockEntropy::new(1), MockClock::new(), &mut flash);
            call(
                &mut h,
                r#"{"hsm":{"init":{"mode":"prod","pin":"hunter2"}}}"#,
            );
        }
        let h2 = Hsm::boot(MockEntropy::new(2), MockClock::new(), &mut flash);
        assert_eq!(h2.state(), DeviceState::ProdLocked);
    }

    #[test]
    fn self_test_passes() {
        let mut h = boot();
        let r = call(&mut h, r#"{"hsm":{"selfTest":{}}}"#);
        assert_eq!(r["hsm"]["selfTest"]["ok"], true);
        assert_eq!(r["hsm"]["selfTest"]["tests"]["ed25519Kat"], "pass");
    }

    #[test]
    fn missing_device_secret_fails_closed() {
        // A device whose OTP secret is unprovisioned/unreadable must refuse
        // every KEK operation (init in either mode) with ERR_INTERNAL, while
        // status stays reachable.
        let mut h = Hsm::boot(
            MockEntropy::new(1),
            MockClock::new(),
            MockFlash::without_device_secret(),
        );
        let r = call(&mut h, r#"{"hsm":{"init":{"mode":"dev"}}}"#);
        assert_eq!(r["hsm"]["error"]["code"], "ERR_INTERNAL");
        let r = call(
            &mut h,
            r#"{"hsm":{"init":{"mode":"prod","pin":"hunter2"}}}"#,
        );
        assert_eq!(r["hsm"]["error"]["code"], "ERR_INTERNAL");
        let s = call(&mut h, r#"{"hsm":{"status":{}}}"#);
        assert_eq!(s["hsm"]["status"]["state"], "uninitialized");
    }

    #[test]
    fn dev_key_does_not_load_without_device_secret() {
        // Provision normally, then "move" the flash image to a device whose
        // OTP secret is gone: the key must not load and signing must refuse.
        let mut flash = MockFlash::new();
        {
            let mut h = Hsm::boot(MockEntropy::new(1), MockClock::new(), &mut flash);
            call(&mut h, r#"{"hsm":{"init":{"mode":"dev"}}}"#);
            call(&mut h, r#"{"hsm":{"generateKey":{}}}"#);
        }
        let snapshot = flash.snapshot();
        let mut moved = MockFlash::without_device_secret();
        assert!(moved.restore(&snapshot));
        let mut h2 = Hsm::boot(MockEntropy::new(2), MockClock::new(), moved);
        let s = call(&mut h2, r#"{"hsm":{"status":{}}}"#);
        assert_eq!(s["hsm"]["status"]["keyPresent"], true);
        assert_eq!(s["hsm"]["status"]["unlocked"], false); // KEK never derived
    }

    #[test]
    fn wrong_device_secret_does_not_unwrap_dev_key() {
        // Same flash image, different chip (different OTP secret): the AEAD
        // tag must fail and the key must not load.
        let mut flash = MockFlash::new();
        {
            let mut h = Hsm::boot(MockEntropy::new(1), MockClock::new(), &mut flash);
            call(&mut h, r#"{"hsm":{"init":{"mode":"dev"}}}"#);
            call(&mut h, r#"{"hsm":{"generateKey":{}}}"#);
        }
        let snapshot = flash.snapshot();
        let mut other_chip = MockFlash::with_device_secret([0xEE; 32]);
        assert!(other_chip.restore(&snapshot));
        let mut h2 = Hsm::boot(MockEntropy::new(2), MockClock::new(), other_chip);
        let s = call(&mut h2, r#"{"hsm":{"status":{}}}"#);
        assert_eq!(s["hsm"]["status"]["unlocked"], false);
    }

    #[test]
    fn change_pin_writes_only_the_key_record_and_rotates_salt() {
        // Regression: the Argon2 salt lives in the key blob, so PIN rotation is
        // a single atomic KEY-record write — it must not touch the config
        // record, and the new PIN must unwrap the seed after a reboot while the
        // old PIN must not. (A split key/config write could otherwise strand
        // the CA key on a torn write.)
        let mut flash = MockFlash::new();
        {
            let mut h = Hsm::boot(MockEntropy::new(1), MockClock::new(), &mut flash);
            call(
                &mut h,
                r#"{"hsm":{"init":{"mode":"prod","pin":"oldpassword"}}}"#,
            );
        }
        let cfg_before = storage::CONFIG.read_latest(&mut flash).unwrap();
        {
            let mut h = Hsm::boot(MockEntropy::new(2), MockClock::new(), &mut flash);
            assert_eq!(
                call(&mut h, r#"{"hsm":{"unlock":{"pin":"oldpassword"}}}"#)["hsm"]["unlock"]["ok"],
                true
            );
            assert_eq!(
                call(
                    &mut h,
                    r#"{"hsm":{"changePin":{"currentPin":"oldpassword","newPin":"newpassword"}}}"#
                )["hsm"]["changePin"]["ok"],
                true
            );
        }
        let cfg_after = storage::CONFIG.read_latest(&mut flash).unwrap();
        assert_eq!(
            cfg_before, cfg_after,
            "change_pin must not rewrite the config record"
        );
        // Old PIN rejected, new PIN unlocks — the rotated salt persisted with the key.
        {
            let mut h = Hsm::boot(MockEntropy::new(3), MockClock::new(), &mut flash);
            assert_eq!(h.state(), DeviceState::ProdLocked);
            let bad = call(&mut h, r#"{"hsm":{"unlock":{"pin":"oldpassword"}}}"#);
            assert_eq!(bad["hsm"]["error"]["code"], "ERR_BAD_PIN");
        }
        {
            let mut h = Hsm::boot(MockEntropy::new(4), MockClock::new(), &mut flash);
            // The previous block's rejected old-PIN attempt persisted a
            // failure to flash; a fresh boot's monotonic clock restarts at
            // zero, so the backoff gate must be waited out again here too
            // (this is precisely the reset-resistance `verify_pin` provides).
            advance(&mut h, 1);
            assert_eq!(
                call(&mut h, r#"{"hsm":{"unlock":{"pin":"newpassword"}}}"#)["hsm"]["unlock"]["ok"],
                true
            );
        }
    }

    #[test]
    fn factory_reset_fails_closed_when_erase_fails() {
        // A failed erase must not be reported as a successful reset.
        let mut flash = MockFlash::new();
        {
            let mut h = Hsm::boot(MockEntropy::new(1), MockClock::new(), &mut flash);
            call(
                &mut h,
                r#"{"hsm":{"init":{"mode":"prod","pin":"hunter2pw"}}}"#,
            );
        }
        flash.set_erase_fault(true);
        let mut h = Hsm::boot(MockEntropy::new(2), MockClock::new(), &mut flash);
        h.set_physical_recovery_authorized(true);
        let r = call(&mut h, r#"{"hsm":{"factoryReset":{"confirm":"ERASE"}}}"#);
        assert_eq!(r["hsm"]["error"]["code"], "ERR_FLASH");
        // State must reflect reality: the key record is still present.
        let s = call(&mut h, r#"{"hsm":{"status":{}}}"#);
        assert_eq!(s["hsm"]["status"]["keyPresent"], true);
        assert_eq!(s["hsm"]["status"]["state"], "prodLocked");
    }

    #[test]
    fn lockout_wipe_fails_closed_when_erase_fails() {
        // wipe-on-lockout must verify the erase; if the key cannot be destroyed,
        // surface ERR_FLASH rather than claiming the key was wiped.
        let mut flash = MockFlash::new();
        {
            let mut h = Hsm::boot(MockEntropy::new(1), MockClock::new(), &mut flash);
            call(
                &mut h,
                r#"{"hsm":{"init":{"mode":"prod","pin":"hunter2pw","maxRetries":1,"wipeOnLockout":true}}}"#,
            );
        }
        flash.set_erase_fault(true);
        let mut h = Hsm::boot(MockEntropy::new(2), MockClock::new(), &mut flash);
        // First wrong attempt reaches maxRetries=1 → lockout → wipe → erase fails.
        let r = call(&mut h, r#"{"hsm":{"unlock":{"pin":"wrongpwxx"}}}"#);
        assert_eq!(r["hsm"]["error"]["code"], "ERR_FLASH");
        // The key must still be reported present (the wipe did not happen).
        let s = call(&mut h, r#"{"hsm":{"status":{}}}"#);
        assert_eq!(s["hsm"]["status"]["keyPresent"], true);
        assert_eq!(s["hsm"]["status"]["state"], "lockedOut");
    }
}
