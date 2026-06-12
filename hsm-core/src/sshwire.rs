//! SSH wire-format primitives and `authorized_keys` public-key parsing.
//!
//! This is the byte-exact foundation for certificate encoding. The formats
//! here mirror `golang.org/x/crypto/ssh` (which cerberus `ssh-cert-signer`
//! uses) so issued certificates are indistinguishable on the wire. The
//! differential test suite (`tests/differential`) pins this parity field by
//! field.
//!
//! References: RFC 4251 §5 (SSH data types), OpenSSH `PROTOCOL.certkeys`.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

/// Append a `uint32` in SSH (big-endian) order.
pub fn put_u32(out: &mut Vec<u8>, v: u32) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Append a `uint64` in SSH (big-endian) order.
pub fn put_u64(out: &mut Vec<u8>, v: u64) {
    out.extend_from_slice(&v.to_be_bytes());
}

/// Append an SSH `string`: a `uint32` length prefix followed by the raw bytes.
pub fn put_string(out: &mut Vec<u8>, s: &[u8]) {
    put_u32(out, s.len() as u32);
    out.extend_from_slice(s);
}

/// Standard-alphabet base64 with padding (OpenSSH `authorized_keys` encoding).
pub fn b64_encode(data: &[u8]) -> String {
    B64.encode(data)
}

/// Decode standard-alphabet base64.
pub fn b64_decode(s: &str) -> Result<Vec<u8>, KeyError> {
    B64.decode(s.as_bytes()).map_err(|_| KeyError::Parse)
}

/// A cursor over SSH wire bytes for parsing length-prefixed fields.
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    /// Read an SSH `string` (length-prefixed byte slice).
    pub fn read_string(&mut self) -> Result<&'a [u8], KeyError> {
        if self.buf.len() < self.pos + 4 {
            return Err(KeyError::Parse);
        }
        let len = u32::from_be_bytes([
            self.buf[self.pos],
            self.buf[self.pos + 1],
            self.buf[self.pos + 2],
            self.buf[self.pos + 3],
        ]) as usize;
        self.pos += 4;
        if self.buf.len() < self.pos + len {
            return Err(KeyError::Parse);
        }
        let s = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(s)
    }

    /// True once all bytes have been consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Current byte offset (e.g. to slice out the bytes-for-signing prefix).
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Advance past `n` fixed-size bytes (uint32/uint64 fields).
    pub fn skip(&mut self, n: usize) -> Result<(), KeyError> {
        if self.buf.len() < self.pos + n {
            return Err(KeyError::Parse);
        }
        self.pos += n;
        Ok(())
    }
}

/// Errors from parsing a submitted public key. The variants map onto the
/// cerberus error classes so the dispatcher can reproduce the right top-level
/// message (`failed to parse public key`, `public key must not carry SSH
/// options`/`trailing data`, `rejected public key`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyError {
    /// Could not parse the key at all (malformed base64, bad blob, unknown
    /// leading token). Mirrors `failed to parse public key`.
    Parse,
    /// The line carried `authorized_keys` options before the key type.
    Options,
    /// Extra data followed the single key (e.g. a second line).
    Trailing,
    /// Parsed fine but the algorithm/curve/size is not certifiable. Carries the
    /// reason text appended after `rejected public key: `.
    Rejected(String),
}

/// The algorithm family of a parsed public key, with the data needed for
/// size/curve validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyKind {
    Ed25519,
    Rsa { bits: u32 },
    EcdsaP256,
    EcdsaP384,
    EcdsaP521,
}

/// A successfully parsed `authorized_keys` public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedKey {
    /// The SSH algorithm name, e.g. `ssh-ed25519`, `ssh-rsa`,
    /// `ecdsa-sha2-nistp256`.
    pub algo: String,
    /// The certificate algorithm name, e.g.
    /// `ssh-ed25519-cert-v01@openssh.com`.
    pub cert_algo: String,
    /// The type-specific key fields: the full public-key blob with the leading
    /// `string(algo)` removed. These bytes splice directly into the certificate
    /// after the nonce (see `x/crypto/ssh` `Certificate.Marshal`).
    pub key_body: Vec<u8>,
    /// Algorithm family and parameters for validation.
    pub kind: KeyKind,
}

/// The set of certifiable key-type names and their cert-type counterparts.
fn cert_algo_for(algo: &str) -> Option<&'static str> {
    match algo {
        "ssh-ed25519" => Some("ssh-ed25519-cert-v01@openssh.com"),
        "ssh-rsa" => Some("ssh-rsa-cert-v01@openssh.com"),
        "ecdsa-sha2-nistp256" => Some("ecdsa-sha2-nistp256-cert-v01@openssh.com"),
        "ecdsa-sha2-nistp384" => Some("ecdsa-sha2-nistp384-cert-v01@openssh.com"),
        "ecdsa-sha2-nistp521" => Some("ecdsa-sha2-nistp521-cert-v01@openssh.com"),
        _ => None,
    }
}

/// Key-type names we recognize but refuse to certify, so they produce a
/// `rejected public key` error (matching cerberus) rather than a bare parse
/// failure.
fn is_known_unsupported(tok: &str) -> bool {
    matches!(
        tok,
        "ssh-dss"
            | "sk-ssh-ed25519@openssh.com"
            | "sk-ecdsa-sha2-nistp256@openssh.com"
            | "ssh-rsa-sha2-256"
            | "ssh-rsa-sha2-512"
    )
}

/// Parse a single bare `authorized_keys` line into a [`ParsedKey`].
///
/// Enforces cerberus semantics: a bare key with no options and no trailing
/// data. A trailing comment after the base64 blob is allowed (it is dropped, as
/// in OpenSSH).
pub fn parse_authorized_key(input: &str) -> Result<ParsedKey, KeyError> {
    // Reject trailing data: more than one non-empty line means a second key or
    // junk followed the first (cerberus: ParseAuthorizedKey leaves it in `rest`).
    let nonempty_lines = input.lines().filter(|l| !l.trim().is_empty()).count();
    if nonempty_lines > 1 {
        return Err(KeyError::Trailing);
    }

    let line = input.trim();
    if line.is_empty() {
        return Err(KeyError::Parse);
    }
    let tokens: Vec<&str> = line.split_whitespace().collect();

    // Locate the key-type token. A bare key has it first; options before it are
    // rejected. An explicitly unsupported type is rejected with a reason.
    let mut type_idx: Option<usize> = None;
    for (i, t) in tokens.iter().enumerate() {
        if cert_algo_for(t).is_some() {
            type_idx = Some(i);
            break;
        }
        if is_known_unsupported(t) {
            return Err(KeyError::Rejected(format!(
                "unsupported public key type: {t}"
            )));
        }
    }
    let idx = type_idx.ok_or(KeyError::Parse)?;
    if idx > 0 {
        // Tokens precede the key type: these are authorized_keys options.
        return Err(KeyError::Options);
    }

    let algo = tokens[idx];
    let blob_b64 = tokens.get(idx + 1).ok_or(KeyError::Parse)?;
    let blob = b64_decode(blob_b64)?;

    // Verify the embedded algorithm name matches the declared one.
    let mut r = Reader::new(&blob);
    let inner_algo = r.read_string()?;
    if inner_algo != algo.as_bytes() {
        return Err(KeyError::Parse);
    }
    // key_body = blob minus the leading string(algo): everything after the
    // first SSH string. This is what splices into the certificate.
    let header_len = 4 + inner_algo.len();
    let key_body = blob[header_len..].to_vec();

    let kind = parse_key_kind(algo, &mut r)?;
    let cert_algo = cert_algo_for(algo).expect("checked above").to_string();

    Ok(ParsedKey {
        algo: algo.to_string(),
        cert_algo,
        key_body,
        kind,
    })
}

/// Parse the type-specific fields to extract validation parameters. `r` is
/// positioned just after the algorithm name.
fn parse_key_kind(algo: &str, r: &mut Reader<'_>) -> Result<KeyKind, KeyError> {
    match algo {
        "ssh-ed25519" => {
            let pk = r.read_string()?;
            if pk.len() != 32 {
                return Err(KeyError::Rejected("malformed ed25519 key".to_string()));
            }
            Ok(KeyKind::Ed25519)
        }
        "ssh-rsa" => {
            let _e = r.read_string()?; // public exponent
            let n = r.read_string()?; // modulus (mpint, big-endian, signed)
            let bits = mpint_bit_len(n);
            Ok(KeyKind::Rsa { bits })
        }
        "ecdsa-sha2-nistp256" | "ecdsa-sha2-nistp384" | "ecdsa-sha2-nistp521" => {
            let curve = r.read_string()?;
            let _q = r.read_string()?; // EC point
            match curve {
                b"nistp256" => Ok(KeyKind::EcdsaP256),
                b"nistp384" => Ok(KeyKind::EcdsaP384),
                b"nistp521" => Ok(KeyKind::EcdsaP521),
                _ => Err(KeyError::Rejected("mismatched ECDSA curve".to_string())),
            }
        }
        _ => Err(KeyError::Parse),
    }
}

/// Bit length of an SSH `mpint` (two's-complement big-endian). RSA moduli are
/// positive, so a leading `0x00` pad byte (present when the high bit is set) is
/// skipped before counting.
fn mpint_bit_len(bytes: &[u8]) -> u32 {
    // Strip leading zero bytes (sign padding and any incidental zeros).
    let mut i = 0;
    while i < bytes.len() && bytes[i] == 0 {
        i += 1;
    }
    let mag = &bytes[i..];
    if mag.is_empty() {
        return 0;
    }
    let top = mag[0];
    let top_bits = 8 - top.leading_zeros(); // 1..=8
    (mag.len() as u32 - 1) * 8 + top_bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn put_string_frames_length() {
        let mut out = Vec::new();
        put_string(&mut out, b"abc");
        assert_eq!(out, [0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn mpint_bit_len_handles_padding() {
        // 0x00 0xFF -> 8 bits (leading pad stripped).
        assert_eq!(mpint_bit_len(&[0x00, 0xFF]), 8);
        // 0x01 0x00 -> 9 bits.
        assert_eq!(mpint_bit_len(&[0x01, 0x00]), 9);
        // empty / zero -> 0.
        assert_eq!(mpint_bit_len(&[0x00]), 0);
    }

    #[test]
    fn parse_ed25519_roundtrip() {
        // Build a minimal ssh-ed25519 blob: string("ssh-ed25519") || string(32 zero bytes).
        let mut blob = Vec::new();
        put_string(&mut blob, b"ssh-ed25519");
        put_string(&mut blob, &[0u8; 32]);
        let line = format!("ssh-ed25519 {} comment@host", b64_encode(&blob));
        let pk = parse_authorized_key(&line).unwrap();
        assert_eq!(pk.algo, "ssh-ed25519");
        assert_eq!(pk.cert_algo, "ssh-ed25519-cert-v01@openssh.com");
        assert_eq!(pk.kind, KeyKind::Ed25519);
        // key_body should be string(32 zero bytes) = 4 + 32 bytes.
        assert_eq!(pk.key_body.len(), 36);
    }

    #[test]
    fn options_prefix_rejected() {
        let mut blob = Vec::new();
        put_string(&mut blob, b"ssh-ed25519");
        put_string(&mut blob, &[0u8; 32]);
        let line = format!("no-pty ssh-ed25519 {}", b64_encode(&blob));
        assert_eq!(parse_authorized_key(&line), Err(KeyError::Options));
    }

    #[test]
    fn trailing_line_rejected() {
        let mut blob = Vec::new();
        put_string(&mut blob, b"ssh-ed25519");
        put_string(&mut blob, &[0u8; 32]);
        let b = b64_encode(&blob);
        let line = format!("ssh-ed25519 {b}\nssh-ed25519 {b}");
        assert_eq!(parse_authorized_key(&line), Err(KeyError::Trailing));
    }

    #[test]
    fn dsa_rejected_not_parse_error() {
        let line = "ssh-dss AAAAB3NzaC1kc3M=";
        assert!(matches!(
            parse_authorized_key(line),
            Err(KeyError::Rejected(_))
        ));
    }
}
