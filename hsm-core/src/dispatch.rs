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
/// alongside the JSON buffers — 4x the memory hardness of the old RP2040
/// build. `t_cost` = 14 targets ≈1 s of Argon2 compute per guess on the
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
const CA_COMMENT: &str = "usbhsm-ca";

/// The CA seed and the wrapping KEK recovered by a successful PIN verification.
type UnlockedSeed = (Zeroizing<[u8; 32]>, Zeroizing<[u8; 32]>);

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
        self.ca_pubkey = keyblob.as_ref().map(|kb| kb.pubkey);

        match cfg {
            None => {
                self.config = None;
                self.state = DeviceState::Uninitialized;
                self.ca = None;
                self.wrap_kek = None;
            }
            Some(c) => {
                self.config = Some(c);
                match c.mode {
                    Mode::Dev => {
                        self.state = DeviceState::DevReady;
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
                        self.ca = None;
                        self.wrap_kek = None;
                        let attempts = pin::count(&mut self.flash).unwrap_or(0);
                        if keyblob.is_some() && attempts >= c.max_retries as usize {
                            self.state = DeviceState::LockedOut;
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
        if self.ca.is_some() {
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
        if self.ca.is_none() {
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

        let mut nonce = [0u8; 32];
        self.drbg.fill_bytes(&mut nonce);
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
        } else if h.reboot_bootloader.is_some() {
            self.hsm_reboot_bootloader()
        } else {
            HsmResponse::err(ERR_BAD_REQUEST, "exactly one hsm command expected")
        }
    }

    /// Request a reboot into the USB mass-storage bootloader after the response
    /// is sent. The actual reset is hardware-specific, so the core only sets a
    /// flag the firmware consumes via [`Self::take_reboot_requested`]; the
    /// simulator simply ignores it.
    fn hsm_reboot_bootloader(&mut self) -> HsmResponse {
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
                    salt: [0u8; 16],
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
                let mut salt = [0u8; 16];
                self.drbg.fill_bytes(&mut salt);
                let max_retries = req.max_retries.unwrap_or(10);
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
                let mut nonce = [0u8; 12];
                self.drbg.fill_bytes(&mut nonce);
                let blob = wrap_seed(&kek, &seed, &pubkey, WrapType::PinKek, &nonce);

                // Write the key first, then config: a config present on boot
                // therefore always implies a key present.
                if storage::KEY
                    .write(&mut self.flash, &blob.to_bytes())
                    .is_err()
                {
                    return HsmResponse::err(ERR_FLASH, "failed to write key");
                }
                let cfg = DeviceConfig {
                    mode: Mode::Prod,
                    argon2: DEFAULT_ARGON,
                    salt,
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
                let _ = pin::reset(&mut self.flash);

                self.config = Some(cfg);
                self.ca_pubkey = Some(pubkey);
                self.ca = None; // locked until unlock
                self.wrap_kek = None;
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
                let (seed, ca) = CaKey::generate(&mut self.drbg);
                let pubkey = ca.public_bytes();
                let mut nonce = [0u8; 12];
                self.drbg.fill_bytes(&mut nonce);
                let blob = wrap_seed(&kek, &seed, &pubkey, wrap_type, &nonce);
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
                Ok((seed, kek)) => {
                    self.ca = Some(CaKey::from_seed(&seed));
                    self.wrap_kek = Some(kek);
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
                self.ca = None; // CaKey zeroizes on drop
                self.wrap_kek = None; // Zeroizing
                self.state = DeviceState::ProdLocked;
                HsmResponse::with(|r| r.lock = Some(OkResp { ok: true }))
            }
            DeviceState::ProdLocked | DeviceState::LockedOut => {
                HsmResponse::with(|r| r.lock = Some(OkResp { ok: true }))
            }
            DeviceState::DevReady => HsmResponse::err(ERR_BAD_MODE, "dev mode cannot be locked"),
            DeviceState::Uninitialized => {
                HsmResponse::err(ERR_NOT_INIT, "initialize the device first")
            }
        }
    }

    fn hsm_set_time(&mut self, req: SetTimeReq) -> HsmResponse {
        let previous = self.clock.set(&self.mono, req.unix_seconds);
        HsmResponse::with(|r| {
            r.set_time = Some(SetTimeResp {
                ok: true,
                uptime_ms: self.mono.now_micros() / 1000,
                previous_set: previous,
            })
        })
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
        let (seed, _old_kek) = match self.verify_pin(&req.current_pin) {
            Ok(v) => v,
            Err(resp) => return resp,
        };
        // Re-wrap under a fresh salt and the new PIN.
        if self.prepare_keygen_entropy().is_err() {
            return HsmResponse::err(ERR_ENTROPY, "entropy source unhealthy");
        }
        let mut new_salt = [0u8; 16];
        self.drbg.fill_bytes(&mut new_salt);
        let mut cfg = self.config.expect("prod implies config");
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
        let mut nonce = [0u8; 12];
        self.drbg.fill_bytes(&mut nonce);
        let blob = wrap_seed(&new_kek, &seed, &pubkey, WrapType::PinKek, &nonce);
        if storage::KEY
            .write(&mut self.flash, &blob.to_bytes())
            .is_err()
        {
            return HsmResponse::err(ERR_FLASH, "failed to write key");
        }
        cfg.salt = new_salt;
        if storage::CONFIG
            .write(&mut self.flash, &cfg.to_bytes())
            .is_err()
        {
            return HsmResponse::err(ERR_FLASH, "failed to write config");
        }
        self.config = Some(cfg);
        let _ = pin::reset(&mut self.flash);
        if was_ready {
            self.ca = Some(CaKey::from_seed(&seed));
            self.wrap_kek = Some(new_kek);
            self.state = DeviceState::ProdReady;
        } else {
            self.ca = None;
            self.wrap_kek = None;
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

    fn hsm_factory_reset(&mut self, req: FactoryResetReq) -> HsmResponse {
        if req.confirm != "ERASE" {
            return HsmResponse::err(ERR_BAD_REQUEST, "confirm must be \"ERASE\"");
        }
        let _ = storage::KEY.erase_both(&mut self.flash);
        let _ = storage::CONFIG.erase_both(&mut self.flash);
        let _ = pin::reset(&mut self.flash);
        self.ca = None;
        self.wrap_kek = None;
        self.ca_pubkey = None;
        self.config = None;
        self.state = DeviceState::Uninitialized;
        HsmResponse::with(|r| r.factory_reset = Some(OkResp { ok: true }))
    }

    // ---- helpers ----------------------------------------------------------

    /// Pre-tick the counter, derive the PIN KEK, and unwrap the seed. On a wrong
    /// PIN, applies backoff and lockout (wiping the key if configured) and
    /// returns the structured error response.
    #[allow(clippy::result_large_err)] // HsmResponse is the natural error payload here
    fn verify_pin(&mut self, pin_str: &str) -> Result<UnlockedSeed, HsmResponse> {
        let cfg = self.config.expect("prod implies config");
        let attempts = match pin::tick(&mut self.flash) {
            Ok(a) => a,
            Err(_) => return Err(HsmResponse::err(ERR_FLASH, "counter write failed")),
        };
        let secret = match self.flash.device_secret() {
            Ok(s) => s,
            Err(_) => {
                return Err(HsmResponse::err(ERR_INTERNAL, "device secret unavailable"));
            }
        };
        let kek = match pin_kek(pin_str.as_bytes(), &cfg.salt, &cfg.argon2, &secret) {
            Ok(k) => k,
            Err(_) => return Err(HsmResponse::err(ERR_INTERNAL, "key derivation failed")),
        };
        let blob = match storage::KEY.read_latest(&mut self.flash) {
            Ok(Some(b)) => match KeyBlob::from_bytes(&b) {
                Some(kb) => kb,
                None => return Err(HsmResponse::err(ERR_INTERNAL, "corrupt key blob")),
            },
            Ok(None) => return Err(HsmResponse::err(ERR_NO_KEY, "no CA key present")),
            Err(_) => return Err(HsmResponse::err(ERR_FLASH, "key read failed")),
        };
        match unwrap_seed(&kek, &blob) {
            Ok(seed) => {
                let _ = pin::reset(&mut self.flash);
                Ok((seed, kek))
            }
            Err(_) => {
                let max = cfg.max_retries as u32;
                let backoff = pin::backoff_ms(attempts.saturating_sub(1) as u32);
                self.mono.delay_ms(backoff);
                if attempts as u32 >= max {
                    if cfg.wipe_on_lockout {
                        let _ = storage::KEY.erase_both(&mut self.flash);
                        self.ca_pubkey = None;
                    }
                    self.state = DeviceState::LockedOut;
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

        // Correct PIN: unlocked.
        let u = call(&mut h, r#"{"hsm":{"unlock":{"pin":"hunter2"}}}"#);
        assert_eq!(u["hsm"]["unlock"]["ok"], true);
        assert_eq!(h.state(), DeviceState::ProdReady);

        // Sign works, signature verifies against the same CA pubkey.
        let resp = call(&mut h, &sign_request("2h"));
        let cert = resp["signSshKey"]["signed_key"].as_str().unwrap();
        let f = verify_and_decode(cert, &ca_pub);
        assert_eq!(f.valid_before, 1_700_000_000 + 7200);

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
        // Three wrong attempts -> lockout, key wiped.
        for _ in 0..3 {
            call(&mut h, r#"{"hsm":{"unlock":{"pin":"nope"}}}"#);
        }
        assert_eq!(h.state(), DeviceState::LockedOut);
        let e = call(&mut h, r#"{"hsm":{"unlock":{"pin":"hunter2"}}}"#);
        assert_eq!(e["hsm"]["error"]["code"], "ERR_LOCKED_OUT");
        // getPublicKey now fails: key was wiped.
        let pk = call(&mut h, r#"{"hsm":{"getPublicKey":{}}}"#);
        assert_eq!(pk["hsm"]["error"]["code"], "ERR_NO_KEY");

        // factoryReset escapes lockout.
        let fr = call(&mut h, r#"{"hsm":{"factoryReset":{"confirm":"ERASE"}}}"#);
        assert_eq!(fr["hsm"]["factoryReset"]["ok"], true);
        assert_eq!(h.state(), DeviceState::Uninitialized);
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
}
