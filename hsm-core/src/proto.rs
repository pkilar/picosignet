//! The JSON wire protocol.
//!
//! The signer-path types ([`Request`]'s `load_key_signer`/`sign_ssh_key`/
//! `ping`/`get_enclave_metrics` and their responses) mirror cerberus
//! `messages` field-for-field, including JSON key names and `omitempty`
//! semantics. An additive `hsm` variant carries device management. Unknown
//! fields are ignored on input (matching Go's `encoding/json`), which is what
//! lets the `hsm` field ride alongside the cerberus envelope safely.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

// ===========================================================================
// Top-level request envelope
// ===========================================================================

/// One request. Exactly one variant must be set (enforced in dispatch).
#[derive(Debug, Default, Deserialize)]
pub struct Request {
    #[serde(rename = "loadKeySigner", default)]
    pub load_key_signer: Option<LoadKeySignerRequest>,
    #[serde(rename = "signSshKey", default)]
    pub sign_ssh_key: Option<EnclaveSigningRequest>,
    #[serde(default)]
    pub ping: Option<PingRequest>,
    #[serde(rename = "getEnclaveMetrics", default)]
    pub get_enclave_metrics: Option<GetEnclaveMetricsRequest>,
    #[serde(default)]
    pub hsm: Option<HsmRequest>,
}

/// AWS credentials in cerberus; ignored by the HSM (all fields optional).
#[derive(Debug, Default, Deserialize)]
pub struct LoadKeySignerRequest {}

/// `ping` is an empty object.
#[derive(Debug, Default, Deserialize)]
pub struct PingRequest {}

/// `getEnclaveMetrics` is an empty object.
#[derive(Debug, Default, Deserialize)]
pub struct GetEnclaveMetricsRequest {}

/// The signing request — mirrors cerberus `EnclaveSigningRequest`. All fields
/// default so a missing field behaves like Go's zero value and is caught by
/// validation with the right message (rather than a JSON parse error).
#[derive(Debug, Default, Deserialize)]
pub struct EnclaveSigningRequest {
    #[serde(default)]
    pub ssh_key: String,
    #[serde(default)]
    pub key_id: String,
    #[serde(default)]
    pub principals: Vec<String>,
    #[serde(default)]
    pub validity: String,
    #[serde(default)]
    pub permissions: BTreeMap<String, String>,
    #[serde(default)]
    pub custom_attributes: BTreeMap<String, String>,
    #[serde(default)]
    pub critical_options: BTreeMap<String, String>,
}

// ===========================================================================
// Top-level response envelope
// ===========================================================================

/// One response. Only the set variant is serialized (`omitempty` semantics),
/// matching cerberus.
#[derive(Debug, Default, Serialize)]
pub struct Response {
    #[serde(rename = "loadKeySigner", skip_serializing_if = "Option::is_none")]
    pub load_key_signer: Option<LoadKeySignerResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(rename = "signSshKey", skip_serializing_if = "Option::is_none")]
    pub sign_ssh_key: Option<SigningResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pong: Option<PingResponse>,
    #[serde(rename = "enclaveMetrics", skip_serializing_if = "Option::is_none")]
    pub enclave_metrics: Option<EnclaveMetricsResponse>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hsm: Option<HsmResponse>,
}

impl Response {
    /// A top-level `{"error": "..."}` response (every signer-path failure).
    pub fn error(msg: impl Into<String>) -> Self {
        Response {
            error: Some(msg.into()),
            ..Default::default()
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct LoadKeySignerResponse {
    #[serde(skip_serializing_if = "core::ops::Not::not")]
    pub success: bool,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Default, Serialize)]
pub struct SigningResponse {
    #[serde(rename = "signed_key", skip_serializing_if = "String::is_empty")]
    pub signed_key: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub error: String,
}

#[derive(Debug, Default, Serialize)]
pub struct PingResponse {
    #[serde(rename = "signerLoaded")]
    pub signer_loaded: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct EnclaveMetricsResponse {
    pub cpu: EnclaveCpuTimes,
    pub memory: EnclaveMemoryStats,
}

#[derive(Debug, Default, Serialize)]
pub struct EnclaveCpuTimes {
    pub user: f64,
    pub nice: f64,
    pub system: f64,
    pub idle: f64,
    pub iowait: f64,
    pub irq: f64,
    pub softirq: f64,
}

#[derive(Debug, Default, Serialize)]
pub struct EnclaveMemoryStats {
    #[serde(rename = "totalBytes")]
    pub total_bytes: u64,
    #[serde(rename = "availableBytes")]
    pub available_bytes: u64,
    #[serde(rename = "freeBytes")]
    pub free_bytes: u64,
    #[serde(rename = "buffersBytes")]
    pub buffers_bytes: u64,
    #[serde(rename = "cachedBytes")]
    pub cached_bytes: u64,
}

// ===========================================================================
// HSM management sub-envelope
// ===========================================================================

/// Management request. Exactly one command must be set (enforced in dispatch).
#[derive(Debug, Default, Deserialize)]
pub struct HsmRequest {
    #[serde(default)]
    pub init: Option<InitReq>,
    #[serde(rename = "generateKey", default)]
    pub generate_key: Option<GenerateKeyReq>,
    #[serde(rename = "getPublicKey", default)]
    pub get_public_key: Option<EmptyReq>,
    #[serde(default)]
    pub unlock: Option<UnlockReq>,
    #[serde(default)]
    pub lock: Option<EmptyReq>,
    #[serde(rename = "setTime", default)]
    pub set_time: Option<SetTimeReq>,
    #[serde(default)]
    pub status: Option<EmptyReq>,
    #[serde(rename = "changePin", default)]
    pub change_pin: Option<ChangePinReq>,
    #[serde(rename = "addEntropy", default)]
    pub add_entropy: Option<AddEntropyReq>,
    #[serde(rename = "selfTest", default)]
    pub self_test: Option<EmptyReq>,
    #[serde(rename = "factoryReset", default)]
    pub factory_reset: Option<FactoryResetReq>,
    #[serde(rename = "rebootBootloader", default)]
    pub reboot_bootloader: Option<EmptyReq>,
}

/// An empty-object command (`getPublicKey`, `lock`, `status`, `selfTest`).
#[derive(Debug, Default, Deserialize)]
pub struct EmptyReq {}

#[derive(Debug, Default, Deserialize)]
pub struct InitReq {
    #[serde(default)]
    pub mode: String,
    #[serde(default)]
    pub pin: Option<String>,
    #[serde(rename = "maxRetries", default)]
    pub max_retries: Option<u8>,
    #[serde(rename = "wipeOnLockout", default)]
    pub wipe_on_lockout: Option<bool>,
}

#[derive(Debug, Default, Deserialize)]
pub struct GenerateKeyReq {
    #[serde(default)]
    pub force: bool,
}

#[derive(Debug, Default, Deserialize)]
pub struct UnlockReq {
    #[serde(default)]
    pub pin: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct SetTimeReq {
    #[serde(rename = "unixSeconds", default)]
    pub unix_seconds: i64,
}

#[derive(Debug, Default, Deserialize)]
pub struct ChangePinReq {
    #[serde(rename = "currentPin", default)]
    pub current_pin: String,
    #[serde(rename = "newPin", default)]
    pub new_pin: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct AddEntropyReq {
    #[serde(default)]
    pub hex: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct FactoryResetReq {
    #[serde(default)]
    pub confirm: String,
}

/// Management response. Like [`Response`], only the set variant is serialized;
/// `error` carries a structured [`HsmError`] (management errors stay inside the
/// `hsm` envelope, unlike signer-path errors which are top-level).
#[derive(Debug, Default, Serialize)]
pub struct HsmResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<HsmError>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init: Option<InitResp>,
    #[serde(rename = "generateKey", skip_serializing_if = "Option::is_none")]
    pub generate_key: Option<GenerateKeyResp>,
    #[serde(rename = "getPublicKey", skip_serializing_if = "Option::is_none")]
    pub get_public_key: Option<PublicKeyResp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlock: Option<UnlockResp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock: Option<OkResp>,
    #[serde(rename = "setTime", skip_serializing_if = "Option::is_none")]
    pub set_time: Option<SetTimeResp>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<StatusResp>,
    #[serde(rename = "changePin", skip_serializing_if = "Option::is_none")]
    pub change_pin: Option<OkResp>,
    #[serde(rename = "addEntropy", skip_serializing_if = "Option::is_none")]
    pub add_entropy: Option<OkResp>,
    #[serde(rename = "selfTest", skip_serializing_if = "Option::is_none")]
    pub self_test: Option<SelfTestResp>,
    #[serde(rename = "factoryReset", skip_serializing_if = "Option::is_none")]
    pub factory_reset: Option<OkResp>,
    #[serde(rename = "rebootBootloader", skip_serializing_if = "Option::is_none")]
    pub reboot_bootloader: Option<OkResp>,
}

impl HsmResponse {
    /// Wrap a single command response (helper for the dispatcher).
    pub fn with(f: impl FnOnce(&mut HsmResponse)) -> Self {
        let mut r = HsmResponse::default();
        f(&mut r);
        r
    }

    /// A management error response.
    pub fn err(code: &str, message: impl Into<String>) -> Self {
        HsmResponse {
            error: Some(HsmError {
                code: code.into(),
                message: message.into(),
                remaining_attempts: None,
                backoff_ms: None,
            }),
            ..Default::default()
        }
    }
}

#[derive(Debug, Default, Serialize)]
pub struct HsmError {
    pub code: String,
    pub message: String,
    #[serde(rename = "remainingAttempts", skip_serializing_if = "Option::is_none")]
    pub remaining_attempts: Option<u32>,
    #[serde(rename = "backoffMs", skip_serializing_if = "Option::is_none")]
    pub backoff_ms: Option<u32>,
}

#[derive(Debug, Default, Serialize)]
pub struct InitResp {
    pub ok: bool,
    pub mode: String,
}

#[derive(Debug, Default, Serialize)]
pub struct GenerateKeyResp {
    pub ok: bool,
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

#[derive(Debug, Default, Serialize)]
pub struct PublicKeyResp {
    #[serde(rename = "publicKey")]
    pub public_key: String,
}

#[derive(Debug, Default, Serialize)]
pub struct UnlockResp {
    pub ok: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct OkResp {
    pub ok: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct SetTimeResp {
    pub ok: bool,
    #[serde(rename = "uptimeMs")]
    pub uptime_ms: u64,
    #[serde(rename = "previousSet")]
    pub previous_set: bool,
}

#[derive(Debug, Default, Serialize)]
pub struct StatusResp {
    pub state: String,
    pub mode: String,
    #[serde(rename = "keyPresent")]
    pub key_present: bool,
    pub unlocked: bool,
    #[serde(rename = "clockSet")]
    pub clock_set: bool,
    #[serde(rename = "unixSeconds", skip_serializing_if = "Option::is_none")]
    pub unix_seconds: Option<i64>,
    #[serde(rename = "uptimeMs")]
    pub uptime_ms: u64,
    #[serde(rename = "retryRemaining", skip_serializing_if = "Option::is_none")]
    pub retry_remaining: Option<u32>,
    #[serde(rename = "fwVersion")]
    pub fw_version: String,
    pub serial: String,
    #[serde(rename = "heapFreeBytes")]
    pub heap_free_bytes: u64,
}

#[derive(Debug, Default, Serialize)]
pub struct SelfTestResp {
    pub ok: bool,
    pub tests: SelfTestDetails,
}

#[derive(Debug, Default, Serialize)]
pub struct SelfTestDetails {
    #[serde(rename = "ed25519Kat")]
    pub ed25519_kat: String,
    #[serde(rename = "sha2Kat")]
    pub sha2_kat: String,
    #[serde(rename = "aeadKat")]
    pub aead_kat: String,
    #[serde(rename = "drbgHealth")]
    pub drbg_health: String,
    #[serde(rename = "flashCrc")]
    pub flash_crc: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_sign_request() {
        let j = r#"{"signSshKey":{"ssh_key":"ssh-ed25519 AAAA","key_id":"k","principals":["a"],"validity":"1h"}}"#;
        let r: Request = serde_json::from_str(j).unwrap();
        let s = r.sign_ssh_key.unwrap();
        assert_eq!(s.ssh_key, "ssh-ed25519 AAAA");
        assert_eq!(s.key_id, "k");
        assert_eq!(s.principals, ["a"]);
        assert_eq!(s.validity, "1h");
        assert!(s.permissions.is_empty());
    }

    #[test]
    fn parses_hsm_request_alongside_unknown_fields() {
        // Unknown top-level fields are ignored (Go-compatible).
        let j = r#"{"hsm":{"setTime":{"unixSeconds":1700000000}},"extra":42}"#;
        let r: Request = serde_json::from_str(j).unwrap();
        let h = r.hsm.unwrap();
        assert_eq!(h.set_time.unwrap().unix_seconds, 1_700_000_000);
    }

    #[test]
    fn error_response_is_top_level() {
        let r = Response::error("boom");
        assert_eq!(serde_json::to_string(&r).unwrap(), r#"{"error":"boom"}"#);
    }

    #[test]
    fn pong_serializes_signer_loaded() {
        let r = Response {
            pong: Some(PingResponse {
                signer_loaded: true,
            }),
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"pong":{"signerLoaded":true}}"#
        );
    }

    #[test]
    fn missing_fields_default_like_go() {
        // No principals / validity: parses fine (validation catches it later).
        let j = r#"{"signSshKey":{"ssh_key":"x","key_id":"k"}}"#;
        let r: Request = serde_json::from_str(j).unwrap();
        let s = r.sign_ssh_key.unwrap();
        assert!(s.principals.is_empty());
        assert_eq!(s.validity, "");
    }
}
