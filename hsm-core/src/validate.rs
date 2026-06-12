//! Signing-request validation, reproducing cerberus `ssh-cert-signer`'s rules
//! and — where practical — its exact top-level error strings.
//!
//! The check order matches `SignPublicKey`/`validateSigningRequest`:
//! field-presence → `ParseDuration` → principals → permissions∩custom_attrs →
//! key parse → key algorithm/size → duration sign → duration max. The
//! `invalid request: `, `failed to parse public key: `, and `rejected public
//! key: ` prefixes mirror the Go wrapping so a rejection reads identically.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::{String, ToString};

use crate::goduration::{format_duration, parse_duration};
use crate::proto::EnclaveSigningRequest;
use crate::sshwire::{parse_authorized_key, KeyError, KeyKind, ParsedKey};

/// Maximum principals per request (cerberus `messages.MaxPrincipals`).
pub const MAX_PRINCIPALS: usize = 100;
/// Maximum certificate validity in nanoseconds (cerberus `messages.MaxValidity`
/// = 24h).
pub const MAX_VALIDITY_NS: i64 = 24 * 3600 * 1_000_000_000;
const MIN_RSA_BITS: u32 = 2048;
const MAX_RSA_BITS: u32 = 8192;

/// The validated, ready-to-sign request data.
pub struct Validated {
    pub key: ParsedKey,
    pub duration_ns: i64,
    /// `permissions ∪ custom_attributes`, sorted (becomes cert Extensions).
    pub extensions: BTreeMap<String, String>,
    /// Cert critical options, sorted.
    pub critical_options: BTreeMap<String, String>,
}

/// Validate `req`, returning the validated data or the exact top-level error
/// message string to place in `{"error": ...}`.
pub fn validate(req: &EnclaveSigningRequest) -> Result<Validated, String> {
    // 1. Field presence, duration parse, principals, map-collision.
    let duration_ns = validate_request(req)?;

    // 2. Parse the public key.
    let key = parse_authorized_key(&req.ssh_key).map_err(map_key_error)?;

    // 3. Algorithm / size policy.
    validate_public_key(&key.kind)?;

    // 4. Duration sign and bound (post key checks, matching Go's order).
    if duration_ns <= 0 {
        return Err(format!(
            "validity duration must be positive (got {})",
            format_duration(duration_ns)
        ));
    }
    if duration_ns > MAX_VALIDITY_NS {
        return Err(format!(
            "validity duration {} exceeds maximum allowed {}",
            format_duration(duration_ns),
            format_duration(MAX_VALIDITY_NS)
        ));
    }

    // 5. Merge extensions (collision already rejected) and copy critical options.
    let mut extensions = BTreeMap::new();
    for (k, v) in &req.permissions {
        extensions.insert(k.clone(), v.clone());
    }
    for (k, v) in &req.custom_attributes {
        extensions.insert(k.clone(), v.clone());
    }
    let critical_options = req.critical_options.clone();

    Ok(Validated {
        key,
        duration_ns,
        extensions,
        critical_options,
    })
}

fn map_key_error(e: KeyError) -> String {
    match e {
        // Go emits the underlying x/crypto parse error here; we can't reproduce
        // its exact text, but the class (a parse rejection) matches.
        KeyError::Parse => "failed to parse public key: invalid authorized key".to_string(),
        KeyError::Options => "public key must not carry SSH options".to_string(),
        KeyError::Trailing => "public key must not carry trailing data".to_string(),
        KeyError::Rejected(r) => format!("rejected public key: {r}"),
    }
}

fn validate_request(req: &EnclaveSigningRequest) -> Result<i64, String> {
    if req.ssh_key.trim().is_empty() {
        return Err("invalid request: SSH key cannot be empty".to_string());
    }
    if req.key_id.trim().is_empty() {
        return Err("invalid request: KeyID cannot be empty".to_string());
    }
    if req.validity.trim().is_empty() {
        return Err("invalid request: validity duration cannot be empty".to_string());
    }
    let duration = parse_duration(&req.validity)
        .map_err(|e| format!("invalid request: invalid validity duration format: {e}"))?;

    if req.principals.is_empty() {
        return Err("invalid request: principals cannot be empty".to_string());
    }
    if req.principals.len() > MAX_PRINCIPALS {
        return Err(format!(
            "invalid request: too many principals: {} (maximum: {})",
            req.principals.len(),
            MAX_PRINCIPALS
        ));
    }
    for (i, p) in req.principals.iter().enumerate() {
        if p.trim().is_empty() {
            return Err(format!(
                "invalid request: principal at index {i} cannot be empty"
            ));
        }
    }
    for k in req.custom_attributes.keys() {
        if req.permissions.contains_key(k) {
            return Err(format!(
                "invalid request: key {} present in both permissions and custom_attributes",
                go_quote(k)
            ));
        }
    }
    Ok(duration)
}

fn validate_public_key(kind: &KeyKind) -> Result<(), String> {
    match kind {
        KeyKind::Rsa { bits } => {
            if *bits < MIN_RSA_BITS {
                return Err(format!(
                    "rejected public key: RSA key too small: {bits} bits (minimum {MIN_RSA_BITS})"
                ));
            }
            if *bits > MAX_RSA_BITS {
                // cerberus rejects this at parse time ("ssh: rsa modulus too
                // large"); we reject here. Same accept/reject decision.
                return Err(format!(
                    "rejected public key: RSA key too large: {bits} bits (maximum {MAX_RSA_BITS})"
                ));
            }
        }
        KeyKind::EcdsaP256 | KeyKind::EcdsaP384 | KeyKind::EcdsaP521 | KeyKind::Ed25519 => {}
    }
    Ok(())
}

/// A minimal Go `%q` (strconv.Quote) for identifier-like keys.
fn go_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            _ => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::sshwire::{b64_encode, put_string};

    fn ed25519_line() -> String {
        let mut blob = Vec::new();
        put_string(&mut blob, b"ssh-ed25519");
        put_string(&mut blob, &[0u8; 32]);
        format!("ssh-ed25519 {}", b64_encode(&blob))
    }

    fn rsa_line(bits: u32) -> String {
        // Build an ssh-rsa blob with a modulus of the requested bit length.
        let mut blob = Vec::new();
        put_string(&mut blob, b"ssh-rsa");
        put_string(&mut blob, &[1, 0, 1]); // e = 65537
        let nbytes = (bits as usize).div_ceil(8);
        let mut n = vec![0u8; nbytes];
        n[0] = 0x80; // set top bit so bit length is exactly `bits`
                     // mpint with high bit set needs a 0x00 pad to stay positive.
        let mut mpint = vec![0x00];
        mpint.extend_from_slice(&n);
        put_string(&mut blob, &mpint);
        format!("ssh-rsa {}", b64_encode(&blob))
    }

    fn base_req() -> EnclaveSigningRequest {
        EnclaveSigningRequest {
            ssh_key: ed25519_line(),
            key_id: "kid".to_string(),
            principals: vec!["alice".to_string()],
            validity: "1h".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn accepts_valid_request() {
        let v = validate(&base_req()).unwrap();
        assert_eq!(v.duration_ns, 3_600_000_000_000);
    }

    #[test]
    fn error_messages_match_cerberus() {
        let cases: Vec<(EnclaveSigningRequest, &str)> = vec![
            (
                EnclaveSigningRequest {
                    ssh_key: "  ".to_string(),
                    ..base_req()
                },
                "invalid request: SSH key cannot be empty",
            ),
            (
                EnclaveSigningRequest {
                    key_id: "".to_string(),
                    ..base_req()
                },
                "invalid request: KeyID cannot be empty",
            ),
            (
                EnclaveSigningRequest {
                    validity: "".to_string(),
                    ..base_req()
                },
                "invalid request: validity duration cannot be empty",
            ),
            (
                EnclaveSigningRequest {
                    validity: "5x".to_string(),
                    ..base_req()
                },
                "invalid request: invalid validity duration format: time: unknown unit \"x\" in duration \"5x\"",
            ),
            (
                EnclaveSigningRequest {
                    principals: vec![],
                    ..base_req()
                },
                "invalid request: principals cannot be empty",
            ),
            (
                EnclaveSigningRequest {
                    principals: vec!["a".to_string(), "  ".to_string()],
                    ..base_req()
                },
                "invalid request: principal at index 1 cannot be empty",
            ),
            (
                EnclaveSigningRequest {
                    validity: "25h".to_string(),
                    ..base_req()
                },
                "validity duration 25h0m0s exceeds maximum allowed 24h0m0s",
            ),
        ];
        for (req, want) in cases {
            assert_eq!(validate(&req).err().as_deref(), Some(want));
        }
    }

    #[test]
    fn too_many_principals() {
        let req = EnclaveSigningRequest {
            principals: (0..101).map(|i| format!("p{i}")).collect(),
            ..base_req()
        };
        assert_eq!(
            validate(&req).err().as_deref(),
            Some("invalid request: too many principals: 101 (maximum: 100)")
        );
    }

    #[test]
    fn permissions_custom_collision() {
        let mut req = base_req();
        req.permissions
            .insert("permit-pty".to_string(), String::new());
        req.custom_attributes
            .insert("permit-pty".to_string(), "x".to_string());
        assert_eq!(
            validate(&req).err().as_deref(),
            Some("invalid request: key \"permit-pty\" present in both permissions and custom_attributes")
        );
    }

    #[test]
    fn rsa_size_policy() {
        let small = EnclaveSigningRequest {
            ssh_key: rsa_line(1024),
            ..base_req()
        };
        assert_eq!(
            validate(&small).err().as_deref(),
            Some("rejected public key: RSA key too small: 1024 bits (minimum 2048)")
        );

        let ok = EnclaveSigningRequest {
            ssh_key: rsa_line(2048),
            ..base_req()
        };
        assert!(validate(&ok).is_ok());

        let big = EnclaveSigningRequest {
            ssh_key: rsa_line(16384),
            ..base_req()
        };
        assert!(validate(&big)
            .err()
            .unwrap()
            .starts_with("rejected public key: RSA key too large"));
    }

    #[test]
    fn options_and_trailing_rejected() {
        let mut blob = Vec::new();
        put_string(&mut blob, b"ssh-ed25519");
        put_string(&mut blob, &[0u8; 32]);
        let b = b64_encode(&blob);

        let opt = EnclaveSigningRequest {
            ssh_key: format!("no-pty ssh-ed25519 {b}"),
            ..base_req()
        };
        assert_eq!(
            validate(&opt).err().as_deref(),
            Some("public key must not carry SSH options")
        );

        let trail = EnclaveSigningRequest {
            ssh_key: format!("ssh-ed25519 {b}\nssh-ed25519 {b}"),
            ..base_req()
        };
        assert_eq!(
            validate(&trail).err().as_deref(),
            Some("public key must not carry trailing data")
        );
    }
}
