//! OpenSSH certificate assembly.
//!
//! Builds the exact byte sequence that `golang.org/x/crypto/ssh`
//! `Certificate.Marshal` produces, so a cert issued here is indistinguishable
//! from one issued by cerberus `ssh-cert-signer`. The construction is linear:
//! everything up to and including the signature key is the "bytes for signing";
//! we sign that with the CA key and append the signature blob.
//!
//! Field order and the two-length-prefix encoding of non-empty option values
//! are pinned against `x/crypto/ssh/certs.go` and verified byte-for-byte by the
//! differential test suite.

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::keys::CaKey;
use crate::sshwire::{b64_encode, put_string, put_u32, put_u64};

/// Certificate type: always a user certificate (`SSH2_CERT_TYPE_USER`).
pub const CERT_TYPE_USER: u32 = 1;

/// Inputs to a certificate. Maps are `BTreeMap` so iteration is already in the
/// lexical key order OpenSSH requires for critical options and extensions.
pub struct CertParams<'a> {
    pub cert_algo: &'a str,
    pub key_body: &'a [u8],
    pub nonce: &'a [u8; 32],
    pub serial: u64,
    pub key_id: &'a str,
    pub principals: &'a [String],
    pub valid_after: u64,
    pub valid_before: u64,
    pub critical_options: &'a BTreeMap<String, String>,
    pub extensions: &'a BTreeMap<String, String>,
}

/// Encode a principals list: the concatenation of `string(p)` for each
/// principal. The result is itself wrapped as one `string` by the caller.
fn marshal_principals(principals: &[String], out: &mut Vec<u8>) {
    for p in principals {
        put_string(out, p.as_bytes());
    }
}

/// Encode a critical-options or extensions map per `PROTOCOL.certkeys`:
/// keys in lexical order, each as `string(name) || string(value_field)` where
/// the value field is empty for flag options and `string(value)` (a second
/// length prefix) for options that carry a value.
fn marshal_tuples(map: &BTreeMap<String, String>, out: &mut Vec<u8>) {
    for (k, v) in map {
        put_string(out, k.as_bytes());
        if v.is_empty() {
            put_string(out, &[]); // u32(0)
        } else {
            let mut inner = Vec::with_capacity(4 + v.len());
            put_string(&mut inner, v.as_bytes());
            put_string(out, &inner); // string(string(value))
        }
    }
}

/// Build a signed certificate and return it as a single-line
/// `authorized_keys` string: `<cert-algo> <base64>` (no trailing newline,
/// matching cerberus's `TrimSpace`'d output).
pub fn build_certificate(p: &CertParams<'_>, ca: &CaKey) -> String {
    let mut blob = Vec::with_capacity(512);

    // prefix: string(cert-algo) || string(nonce) || key_body(raw)
    put_string(&mut blob, p.cert_algo.as_bytes());
    put_string(&mut blob, p.nonce);
    blob.extend_from_slice(p.key_body);

    // generic fields up to and including the signature key.
    put_u64(&mut blob, p.serial);
    put_u32(&mut blob, CERT_TYPE_USER);
    put_string(&mut blob, p.key_id.as_bytes());

    let mut principals_blob = Vec::new();
    marshal_principals(p.principals, &mut principals_blob);
    put_string(&mut blob, &principals_blob);

    put_u64(&mut blob, p.valid_after);
    put_u64(&mut blob, p.valid_before);

    let mut crit = Vec::new();
    marshal_tuples(p.critical_options, &mut crit);
    put_string(&mut blob, &crit);

    let mut ext = Vec::new();
    marshal_tuples(p.extensions, &mut ext);
    put_string(&mut blob, &ext);

    put_string(&mut blob, &[]); // reserved (empty string)

    let ca_pub = ca.public_blob();
    put_string(&mut blob, &ca_pub);

    // `blob` is now exactly the bytes Go signs (full Marshal with nil signature
    // minus its trailing 4-byte length). Sign and append the signature blob.
    let sig_blob = ca.signature_blob(&blob);
    put_string(&mut blob, &sig_blob);

    format!("{} {}", p.cert_algo, b64_encode(&blob))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::CaKey;
    use crate::sshwire::{put_string as ps, Reader};
    use alloc::string::ToString;
    use alloc::vec;

    fn ed25519_key_body() -> Vec<u8> {
        // string(pub32) — the type-specific body for an ed25519 user key.
        let mut b = Vec::new();
        ps(&mut b, &[0x11u8; 32]);
        b
    }

    #[test]
    fn certificate_structure_roundtrips() {
        let ca = CaKey::from_seed(&[9u8; 32]);
        let key_body = ed25519_key_body();
        let principals = vec!["alice".to_string(), "bob".to_string()];
        let mut exts = BTreeMap::new();
        exts.insert("permit-pty".to_string(), String::new());
        let mut crit = BTreeMap::new();
        crit.insert("force-command".to_string(), "/bin/true".to_string());

        let params = CertParams {
            cert_algo: "ssh-ed25519-cert-v01@openssh.com",
            key_body: &key_body,
            nonce: &[0xAA; 32],
            serial: 0x0102030405060708,
            key_id: "test-key",
            principals: &principals,
            valid_after: 1000,
            valid_before: 2000,
            critical_options: &crit,
            extensions: &exts,
        };
        let line = build_certificate(&params, &ca);

        // Decode and walk the top-level fields to confirm structure.
        let (algo, b64) = line.split_once(' ').unwrap();
        assert_eq!(algo, "ssh-ed25519-cert-v01@openssh.com");
        let raw = crate::sshwire::b64_decode(b64).unwrap();
        let mut r = Reader::new(&raw);
        assert_eq!(r.read_string().unwrap(), algo.as_bytes()); // cert algo
        assert_eq!(r.read_string().unwrap().len(), 32); // nonce
        assert_eq!(r.read_string().unwrap(), &[0x11u8; 32]); // ed25519 pubkey
                                                             // serial(8) + type(4)
                                                             // The remaining structural correctness (serial, type, principals,
                                                             // options, signature) is asserted byte-for-byte against x/crypto/ssh in
                                                             // tests/differential.
    }

    #[test]
    fn empty_maps_produce_empty_blobs() {
        let empty: BTreeMap<String, String> = BTreeMap::new();
        let mut out = Vec::new();
        marshal_tuples(&empty, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn flag_extension_is_single_empty_value() {
        let mut m = BTreeMap::new();
        m.insert("permit-X11-forwarding".to_string(), String::new());
        let mut out = Vec::new();
        marshal_tuples(&m, &mut out);
        // string("permit-X11-forwarding") || u32(0)
        let mut expect = Vec::new();
        ps(&mut expect, b"permit-X11-forwarding");
        expect.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(out, expect);
    }

    #[test]
    fn valued_option_has_double_length_prefix() {
        let mut m = BTreeMap::new();
        m.insert("force-command".to_string(), "ls".to_string());
        let mut out = Vec::new();
        marshal_tuples(&m, &mut out);
        // string("force-command") || string( string("ls") )
        let mut expect = Vec::new();
        ps(&mut expect, b"force-command");
        let mut inner = Vec::new();
        ps(&mut inner, b"ls");
        ps(&mut expect, &inner);
        assert_eq!(out, expect);
    }
}
