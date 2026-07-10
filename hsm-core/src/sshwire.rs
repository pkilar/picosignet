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
use p256::PublicKey as P256PublicKey;
use p384::PublicKey as P384PublicKey;
use p521::PublicKey as P521PublicKey;

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
///
/// Every arm must fully consume `r`: the blob's type-specific tail becomes
/// [`ParsedKey::key_body`], which splices *raw* into the certificate we sign
/// (see `cert::build_certificate`). Without this check, a blob with a
/// well-formed key followed by arbitrary extra bytes would be accepted and
/// those extra bytes spliced into a CA-signed structure — where
/// `x/crypto/ssh.ParsePublicKey` (what cerberus uses) explicitly rejects
/// trailing junk. Checked once, uniformly, after the match, so every key kind
/// gets the same guarantee.
fn parse_key_kind(algo: &str, r: &mut Reader<'_>) -> Result<KeyKind, KeyError> {
    let kind = match algo {
        "ssh-ed25519" => {
            let pk = r.read_string()?;
            if pk.len() != 32 {
                return Err(KeyError::Rejected("malformed ed25519 key".to_string()));
            }
            KeyKind::Ed25519
        }
        "ssh-rsa" => {
            let e = positive_mpint_u64(r.read_string()?)
                .ok_or_else(|| KeyError::Rejected("malformed RSA public exponent".to_string()))?;
            if e < 3 || e % 2 == 0 {
                return Err(KeyError::Rejected(
                    "RSA public exponent must be an odd integer >= 3".to_string(),
                ));
            }
            let bits = positive_mpint_bit_len(r.read_string()?)
                .ok_or_else(|| KeyError::Rejected("malformed RSA modulus".to_string()))?;
            KeyKind::Rsa { bits }
        }
        "ecdsa-sha2-nistp256" => {
            let curve = r.read_string()?;
            let q = r.read_string()?;
            if curve != b"nistp256" {
                return Err(KeyError::Rejected("mismatched ECDSA curve".to_string()));
            }
            require_uncompressed_sec1(q, 65)?;
            P256PublicKey::from_sec1_bytes(q)
                .map_err(|_| KeyError::Rejected("invalid ECDSA public point".to_string()))?;
            KeyKind::EcdsaP256
        }
        "ecdsa-sha2-nistp384" => {
            let curve = r.read_string()?;
            let q = r.read_string()?;
            if curve != b"nistp384" {
                return Err(KeyError::Rejected("mismatched ECDSA curve".to_string()));
            }
            require_uncompressed_sec1(q, 97)?;
            P384PublicKey::from_sec1_bytes(q)
                .map_err(|_| KeyError::Rejected("invalid ECDSA public point".to_string()))?;
            KeyKind::EcdsaP384
        }
        "ecdsa-sha2-nistp521" => {
            let curve = r.read_string()?;
            let q = r.read_string()?;
            if curve != b"nistp521" {
                return Err(KeyError::Rejected("mismatched ECDSA curve".to_string()));
            }
            require_uncompressed_sec1(q, 133)?;
            P521PublicKey::from_sec1_bytes(q)
                .map_err(|_| KeyError::Rejected("invalid ECDSA public point".to_string()))?;
            KeyKind::EcdsaP521
        }
        _ => return Err(KeyError::Parse),
    };
    if !r.is_empty() {
        return Err(KeyError::Trailing);
    }
    Ok(kind)
}

/// SSH ECDSA keys carry an uncompressed SEC1 point. Curve decoders also accept
/// compressed points, but preserving one in a signed certificate would produce
/// an encoding OpenSSH and x/crypto/ssh reject.
fn require_uncompressed_sec1(q: &[u8], expected_len: usize) -> Result<(), KeyError> {
    if q.len() != expected_len || q.first() != Some(&0x04) {
        return Err(KeyError::Rejected(
            "ECDSA public point must use uncompressed SEC1 encoding".to_string(),
        ));
    }
    Ok(())
}

/// Return a canonical positive SSH `mpint` magnitude. RSA parameters are
/// positive signed values, so only one leading zero is permitted, and only as
/// required sign padding for a magnitude whose high bit is set.
fn positive_mpint_magnitude(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.is_empty() || bytes[0] & 0x80 != 0 {
        return None;
    }
    if bytes[0] == 0 {
        if bytes.len() == 1 || bytes[1] & 0x80 == 0 {
            return None;
        }
        return Some(&bytes[1..]);
    }
    Some(bytes)
}

fn positive_mpint_u64(bytes: &[u8]) -> Option<u64> {
    let magnitude = positive_mpint_magnitude(bytes)?;
    if magnitude.len() > 8 {
        return None;
    }
    Some(
        magnitude
            .iter()
            .fold(0u64, |value, &byte| (value << 8) | byte as u64),
    )
}

fn positive_mpint_bit_len(bytes: &[u8]) -> Option<u32> {
    let magnitude = positive_mpint_magnitude(bytes)?;
    let top_bits = 8 - magnitude[0].leading_zeros();
    Some((magnitude.len() as u32 - 1) * 8 + top_bits)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    #[test]
    fn put_string_frames_length() {
        let mut out = Vec::new();
        put_string(&mut out, b"abc");
        assert_eq!(out, [0, 0, 0, 3, b'a', b'b', b'c']);
    }

    #[test]
    fn positive_mpint_validation_rejects_noncanonical_values() {
        assert_eq!(positive_mpint_bit_len(&[0x00, 0xFF]), Some(8));
        assert_eq!(positive_mpint_bit_len(&[0x01, 0x00]), Some(9));
        assert_eq!(positive_mpint_bit_len(&[]), None);
        assert_eq!(positive_mpint_bit_len(&[0x00]), None);
        assert_eq!(positive_mpint_bit_len(&[0x00, 0x7F]), None);
        assert_eq!(positive_mpint_bit_len(&[0x80]), None);
    }

    fn rsa_line(exponent: &[u8]) -> String {
        let mut blob = Vec::new();
        put_string(&mut blob, b"ssh-rsa");
        put_string(&mut blob, exponent);
        put_string(&mut blob, &[1, 0, 1]);
        format!("ssh-rsa {}", b64_encode(&blob))
    }

    fn ecdsa_line(algo: &str, curve: &[u8], point: &[u8]) -> String {
        let mut blob = Vec::new();
        put_string(&mut blob, algo.as_bytes());
        put_string(&mut blob, curve);
        put_string(&mut blob, point);
        format!("{algo} {}", b64_encode(&blob))
    }

    #[test]
    fn rsa_rejects_invalid_public_exponents() {
        for exponent in [
            &[][..],
            &[0][..],
            &[1][..],
            &[4][..],
            &[0x80][..],
            &[0, 3][..],
        ] {
            assert!(matches!(
                parse_authorized_key(&rsa_line(exponent)),
                Err(KeyError::Rejected(_))
            ));
        }
        assert!(parse_authorized_key(&rsa_line(&[1, 0, 1])).is_ok());
    }

    #[test]
    fn ecdsa_rejects_curve_mismatch_and_invalid_point() {
        let mut mismatch = Vec::new();
        put_string(&mut mismatch, b"ecdsa-sha2-nistp256");
        put_string(&mut mismatch, b"nistp384");
        put_string(&mut mismatch, &[4; 65]);
        assert!(matches!(
            parse_authorized_key(&format!("ecdsa-sha2-nistp256 {}", b64_encode(&mismatch))),
            Err(KeyError::Rejected(_))
        ));

        let mut invalid = Vec::new();
        put_string(&mut invalid, b"ecdsa-sha2-nistp256");
        put_string(&mut invalid, b"nistp256");
        put_string(&mut invalid, &[4; 65]);
        assert!(matches!(
            parse_authorized_key(&format!("ecdsa-sha2-nistp256 {}", b64_encode(&invalid))),
            Err(KeyError::Rejected(_))
        ));
    }

    #[test]
    fn ecdsa_rejects_compressed_sec1_points() {
        let mut p256_scalar = [0u8; 32];
        p256_scalar[31] = 1;
        let p256_point = p256::SecretKey::from_slice(&p256_scalar)
            .unwrap()
            .public_key()
            .to_encoded_point(true);
        let mut p384_scalar = [0u8; 48];
        p384_scalar[47] = 1;
        let p384_point = p384::SecretKey::from_slice(&p384_scalar)
            .unwrap()
            .public_key()
            .to_encoded_point(true);
        let mut p521_scalar = [0u8; 66];
        p521_scalar[65] = 1;
        let p521_point = p521::SecretKey::from_slice(&p521_scalar)
            .unwrap()
            .public_key()
            .to_encoded_point(true);

        for line in [
            ecdsa_line("ecdsa-sha2-nistp256", b"nistp256", p256_point.as_bytes()),
            ecdsa_line("ecdsa-sha2-nistp384", b"nistp384", p384_point.as_bytes()),
            ecdsa_line("ecdsa-sha2-nistp521", b"nistp521", p521_point.as_bytes()),
        ] {
            assert!(matches!(
                parse_authorized_key(&line),
                Err(KeyError::Rejected(_))
            ));
        }
    }

    #[test]
    fn valid_supported_ecdsa_keys_parse() {
        // SEC1 uncompressed encoding of the NIST P-256 generator.
        let point = [
            4, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4,
            0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45,
            0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7,
            0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce,
            0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ];
        let mut p256_scalar = [0u8; 32];
        p256_scalar[31] = 1;
        let p256_point = p256::SecretKey::from_slice(&p256_scalar)
            .unwrap()
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        assert_eq!(p256_point.as_slice(), &point);
        let mut p384_scalar = [0u8; 48];
        p384_scalar[47] = 1;
        let p384_point = p384::SecretKey::from_slice(&p384_scalar)
            .unwrap()
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let mut p521_scalar = [0u8; 66];
        p521_scalar[65] = 1;
        let p521_point = p521::SecretKey::from_slice(&p521_scalar)
            .unwrap()
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();

        for (algo, curve, point) in [
            ("ecdsa-sha2-nistp256", b"nistp256".as_slice(), p256_point),
            ("ecdsa-sha2-nistp384", b"nistp384".as_slice(), p384_point),
            ("ecdsa-sha2-nistp521", b"nistp521".as_slice(), p521_point),
        ] {
            assert!(parse_authorized_key(&ecdsa_line(algo, curve, &point)).is_ok());
        }
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
    fn trailing_bytes_inside_blob_rejected() {
        // A well-formed ed25519 key followed by extra bytes *within the same
        // base64 blob* (not a second line) must be rejected — matching
        // x/crypto/ssh.ParsePublicKey's "trailing junk" check — rather than
        // silently splicing the extra bytes into a signed certificate.
        let mut blob = Vec::new();
        put_string(&mut blob, b"ssh-ed25519");
        put_string(&mut blob, &[0u8; 32]);
        blob.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);
        let line = format!("ssh-ed25519 {}", b64_encode(&blob));
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
