//! A faithful port of Go's `time.ParseDuration` and `Duration.String`.
//!
//! cerberus parses the request's `validity` with `time.ParseDuration` and
//! formats duration values in its bound-check errors with `Duration.String`.
//! To make the HSM's rejections byte-identical, this reproduces both exactly,
//! including the overflow handling and the `time: …` error strings (with Go's
//! `quote`). Test vectors are lifted from Go's `time/time_test.go`.
//!
//! Durations are represented as `i64` nanoseconds, matching `time.Duration`.

use alloc::format;
use alloc::string::{String, ToString};

const NANOSECOND: u64 = 1;
const MICROSECOND: u64 = 1_000;
const MILLISECOND: u64 = 1_000_000;
const SECOND: u64 = 1_000_000_000;
const MINUTE: u64 = 60 * SECOND;
const HOUR: u64 = 3600 * SECOND;

const TWO_63: u64 = 1u64 << 63;

fn unit_map(u: &str) -> Option<u64> {
    Some(match u {
        "ns" => NANOSECOND,
        "us" => MICROSECOND,
        "\u{00b5}s" => MICROSECOND, // U+00B5 MICRO SIGN
        "\u{03bc}s" => MICROSECOND, // U+03BC GREEK SMALL LETTER MU
        "ms" => MILLISECOND,
        "s" => SECOND,
        "m" => MINUTE,
        "h" => HOUR,
        _ => return None,
    })
}

/// Go's `time.quote`: a double-quoted rendering with `"`/`\` escaped and any
/// byte outside `0x20..=0x7f` emitted as `\xHH`.
fn quote(s: &str) -> String {
    let mut buf = String::with_capacity(s.len() + 2);
    buf.push('"');
    for &b in s.as_bytes() {
        if b == b'"' || b == b'\\' {
            buf.push('\\');
            buf.push(b as char);
        } else if (0x20..=0x7f).contains(&b) {
            buf.push(b as char);
        } else {
            const HEX: &[u8; 16] = b"0123456789abcdef";
            buf.push('\\');
            buf.push('x');
            buf.push(HEX[(b >> 4) as usize] as char);
            buf.push(HEX[(b & 0xf) as usize] as char);
        }
    }
    buf.push('"');
    buf
}

fn err_invalid(orig: &str) -> String {
    format!("time: invalid duration {}", quote(orig))
}
fn err_missing_unit(orig: &str) -> String {
    format!("time: missing unit in duration {}", quote(orig))
}
fn err_unknown_unit(u: &str, orig: &str) -> String {
    format!(
        "time: unknown unit {} in duration {}",
        quote(u),
        quote(orig)
    )
}

/// Port of Go `leadingInt`: consume `[0-9]*`, returning the value, the number
/// of bytes consumed, and whether it overflowed `1<<63`.
fn leading_int(s: &[u8]) -> (u64, usize, bool) {
    let mut x: u64 = 0;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if !c.is_ascii_digit() {
            break;
        }
        if x > TWO_63 / 10 {
            return (0, i, true);
        }
        x = x * 10 + (c - b'0') as u64;
        if x > TWO_63 {
            return (0, i, true);
        }
        i += 1;
    }
    (x, i, false)
}

/// Port of Go `leadingFraction`: consume `[0-9]*` after a decimal point,
/// returning the accumulated value, the power-of-ten scale, and bytes consumed.
fn leading_fraction(s: &[u8]) -> (u64, f64, usize) {
    let mut x: u64 = 0;
    let mut scale: f64 = 1.0;
    let mut overflow = false;
    let mut i = 0;
    while i < s.len() {
        let c = s[i];
        if !c.is_ascii_digit() {
            break;
        }
        if !overflow {
            if x > (TWO_63 - 1) / 10 {
                overflow = true;
            } else {
                let y = x * 10 + (c - b'0') as u64;
                if y > TWO_63 {
                    overflow = true;
                } else {
                    x = y;
                    scale *= 10.0;
                }
            }
        }
        i += 1;
    }
    (x, scale, i)
}

/// Parse a Go duration string into nanoseconds. On error returns the exact
/// `time: …` message Go would produce.
pub fn parse_duration(orig: &str) -> Result<i64, String> {
    let mut s = orig;
    let mut d: u64 = 0;
    let mut neg = false;

    // Optional leading sign.
    if let Some(&c) = s.as_bytes().first() {
        if c == b'-' || c == b'+' {
            neg = c == b'-';
            s = &s[1..];
        }
    }
    // Special case: "0" (after an optional sign) is zero.
    if s == "0" {
        return Ok(0);
    }
    if s.is_empty() {
        return Err(err_invalid(orig));
    }

    while !s.is_empty() {
        // The next character must be [0-9.].
        let b0 = s.as_bytes()[0];
        if !(b0 == b'.' || b0.is_ascii_digit()) {
            return Err(err_invalid(orig));
        }

        // Integer part.
        let pl = s.len();
        let (mut v, consumed, overflow) = leading_int(s.as_bytes());
        if overflow {
            return Err(err_invalid(orig));
        }
        s = &s[consumed..];
        let pre = pl != s.len();

        // Optional fractional part.
        let mut f: u64 = 0;
        let mut scale: f64 = 1.0;
        let mut post = false;
        if !s.is_empty() && s.as_bytes()[0] == b'.' {
            s = &s[1..];
            let pl2 = s.len();
            let (ff, sc, c2) = leading_fraction(s.as_bytes());
            f = ff;
            scale = sc;
            s = &s[c2..];
            post = pl2 != s.len();
        }
        if !pre && !post {
            // No digits at all (e.g. ".s").
            return Err(err_invalid(orig));
        }

        // Unit: run of bytes up to the next '.' or digit.
        let sb = s.as_bytes();
        let mut i = 0;
        while i < sb.len() {
            let c = sb[i];
            if c == b'.' || c.is_ascii_digit() {
                break;
            }
            i += 1;
        }
        if i == 0 {
            return Err(err_missing_unit(orig));
        }
        let u = &s[..i];
        s = &s[i..];
        let unit = match unit_map(u) {
            Some(x) => x,
            None => return Err(err_unknown_unit(u, orig)),
        };

        if v > TWO_63 / unit {
            return Err(err_invalid(orig));
        }
        v *= unit;
        if f > 0 {
            // float64 is needed to be nanosecond-accurate for fractions of hours.
            v = v.wrapping_add((f as f64 * (unit as f64 / scale)) as u64);
            if v > TWO_63 {
                return Err(err_invalid(orig));
            }
        }
        d = d.wrapping_add(v);
        if d > TWO_63 {
            return Err(err_invalid(orig));
        }
    }

    if neg {
        // For d == 1<<63 this yields i64::MIN, matching Go's -Duration(1<<63).
        return Ok((d as i64).wrapping_neg());
    }
    if d > TWO_63 - 1 {
        return Err(err_invalid(orig));
    }
    Ok(d as i64)
}

fn fmt_int(buf: &mut [u8], mut w: usize, mut v: u64) -> usize {
    if v == 0 {
        w -= 1;
        buf[w] = b'0';
    } else {
        while v > 0 {
            w -= 1;
            buf[w] = b'0' + (v % 10) as u8;
            v /= 10;
        }
    }
    w
}

fn fmt_frac(buf: &mut [u8], mut w: usize, mut v: u64, prec: usize) -> (usize, u64) {
    let mut print = false;
    for _ in 0..prec {
        let digit = v % 10;
        print = print || digit != 0;
        if print {
            w -= 1;
            buf[w] = b'0' + digit as u8;
        }
        v /= 10;
    }
    if print {
        w -= 1;
        buf[w] = b'.';
    }
    (w, v)
}

/// Port of Go `Duration.String`: e.g. `0s`, `1.5s`, `24h0m0s`, `-1h0m0s`,
/// `1µs`. Used in cerberus's validity bound-check error messages.
pub fn format_duration(d: i64) -> String {
    let mut buf = [0u8; 32];
    let mut w = buf.len();
    let neg = d < 0;
    let mut u = d.unsigned_abs();

    if u < SECOND {
        // Sub-second: pick the largest fitting unit.
        w -= 1;
        buf[w] = b's';
        w -= 1;
        let prec;
        if u == 0 {
            return "0s".to_string();
        } else if u < MICROSECOND {
            prec = 0;
            buf[w] = b'n';
        } else if u < MILLISECOND {
            prec = 3;
            // 'µ' (U+00B5) is two UTF-8 bytes 0xC2 0xB5.
            w -= 1;
            buf[w] = 0xC2;
            buf[w + 1] = 0xB5;
        } else {
            prec = 6;
            buf[w] = b'm';
        }
        let (nw, nu) = fmt_frac(&mut buf, w, u, prec);
        w = nw;
        u = nu;
        w = fmt_int(&mut buf, w, u);
    } else {
        w -= 1;
        buf[w] = b's';
        let (nw, nu) = fmt_frac(&mut buf, w, u, 9);
        w = nw;
        u = nu;

        // Integer seconds.
        w = fmt_int(&mut buf, w, u % 60);
        u /= 60;

        // Integer minutes.
        if u > 0 {
            w -= 1;
            buf[w] = b'm';
            w = fmt_int(&mut buf, w, u % 60);
            u /= 60;

            // Integer hours (stop here; days vary in length).
            if u > 0 {
                w -= 1;
                buf[w] = b'h';
                w = fmt_int(&mut buf, w, u);
            }
        }
    }

    if neg {
        w -= 1;
        buf[w] = b'-';
    }
    // buf[w..] is valid UTF-8 (ASCII plus the 'µ' bytes).
    String::from_utf8_lossy(&buf[w..]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_test_vectors() {
        let cases: &[(&str, i64)] = &[
            ("0", 0),
            ("5s", 5_000_000_000),
            ("30s", 30_000_000_000),
            ("1478s", 1_478_000_000_000),
            ("-5s", -5_000_000_000),
            ("+5s", 5_000_000_000),
            ("-0", 0),
            ("+0", 0),
            ("5.0s", 5_000_000_000),
            ("5.6s", 5_600_000_000),
            ("5.s", 5_000_000_000),
            (".5s", 500_000_000),
            ("1.0s", 1_000_000_000),
            ("1.004s", 1_004_000_000),
            ("100.00100s", 100_001_000_000),
            ("10ns", 10),
            ("11us", 11_000),
            ("12\u{00b5}s", 12_000),
            ("12\u{03bc}s", 12_000),
            ("13ms", 13_000_000),
            ("14s", 14_000_000_000),
            ("15m", 900_000_000_000),
            ("16h", 57_600_000_000_000),
            ("3h30m", 3 * 3_600_000_000_000 + 30 * 60_000_000_000),
            ("10.5s4m", 4 * 60_000_000_000 + 10_500_000_000),
            ("-2m3.4s", -(2 * 60_000_000_000 + 3_400_000_000)),
            (
                "1h2m3s4ms5us6ns",
                3_600_000_000_000 + 2 * 60_000_000_000 + 3_000_000_000 + 4_000_000 + 5_000 + 6,
            ),
            (
                "39h9m14.425s",
                39 * 3_600_000_000_000 + 9 * 60_000_000_000 + 14_425_000_000,
            ),
            ("52763797000ns", 52_763_797_000),
            ("0.3333333333333333333h", 20 * 60_000_000_000),
            ("9223372036854775807ns", 9_223_372_036_854_775_807),
            ("9223372036854775.807us", 9_223_372_036_854_775_807),
            ("-9223372036854775808ns", -9_223_372_036_854_775_808),
            ("-9223372036854775.808us", -9_223_372_036_854_775_808),
        ];
        for (s, want) in cases {
            assert_eq!(parse_duration(s), Ok(*want), "parsing {s:?}");
        }
    }

    #[test]
    fn rejects_with_exact_go_messages() {
        let cases: &[(&str, &str)] = &[
            ("", "time: invalid duration \"\""),
            ("3", "time: missing unit in duration \"3\""),
            ("-", "time: invalid duration \"-\""),
            ("s", "time: invalid duration \"s\""),
            (".", "time: invalid duration \".\""),
            ("-.", "time: invalid duration \"-.\""),
            (".s", "time: invalid duration \".s\""),
            ("+.s", "time: invalid duration \"+.s\""),
            ("1d", "time: unknown unit \"d\" in duration \"1d\""),
            ("5x", "time: unknown unit \"x\" in duration \"5x\""),
            ("3000000h", "time: invalid duration \"3000000h\""), // overflow
        ];
        for (s, want) in cases {
            assert_eq!(
                parse_duration(s),
                Err((*want).to_string()),
                "rejecting {s:?}"
            );
        }
    }

    #[test]
    fn formats_like_go() {
        assert_eq!(format_duration(0), "0s");
        assert_eq!(format_duration(SECOND as i64), "1s");
        assert_eq!(format_duration(1_500_000_000), "1.5s");
        assert_eq!(format_duration(HOUR as i64), "1h0m0s");
        assert_eq!(format_duration(24 * HOUR as i64), "24h0m0s");
        assert_eq!(format_duration(25 * HOUR as i64), "25h0m0s");
        assert_eq!(format_duration(-(HOUR as i64)), "-1h0m0s");
        assert_eq!(format_duration(90 * MINUTE as i64), "1h30m0s");
        assert_eq!(format_duration(1), "1ns");
        assert_eq!(format_duration(1_000), "1\u{00b5}s");
        assert_eq!(format_duration(1_000_000), "1ms");
    }
}
