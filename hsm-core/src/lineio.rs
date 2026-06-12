//! Newline-delimited line reassembly from USB packets, with an on-device size
//! cap.
//!
//! USB CDC-ACM delivers arbitrary 64-byte chunks; requests are framed by `\n`.
//! The device caps a line at 16 KiB (vs the enclave's 256 KiB — the largest
//! legitimate request, an RSA-8192 key with 100 principals, is ~6 KiB). An
//! oversize line is drained to the next newline and reported as an error.

use alloc::vec::Vec;

/// Maximum accepted request line length.
pub const MAX_LINE: usize = 16 * 1024;

/// A completed event from the assembler.
pub enum Event {
    /// A full request line (newline stripped).
    Line(Vec<u8>),
    /// The line exceeded [`MAX_LINE`] and was discarded.
    TooLong,
}

/// Accumulates bytes into newline-delimited lines.
#[derive(Default)]
pub struct LineAssembler {
    buf: Vec<u8>,
    overflowed: bool,
}

impl LineAssembler {
    pub fn new() -> Self {
        LineAssembler::default()
    }

    /// Feed one byte. Returns an [`Event`] when a line terminates.
    pub fn push(&mut self, b: u8) -> Option<Event> {
        if b == b'\n' {
            if self.overflowed {
                self.overflowed = false;
                self.buf.clear();
                return Some(Event::TooLong);
            }
            // Tolerate CRLF by trimming a trailing CR.
            if self.buf.last() == Some(&b'\r') {
                self.buf.pop();
            }
            return Some(Event::Line(core::mem::take(&mut self.buf)));
        }
        if self.overflowed {
            return None; // draining until newline
        }
        if self.buf.len() >= MAX_LINE {
            self.overflowed = true;
            self.buf.clear();
            return None;
        }
        self.buf.push(b);
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn drive(a: &mut LineAssembler, data: &[u8]) -> Vec<Event> {
        let mut out = Vec::new();
        for &b in data {
            if let Some(e) = a.push(b) {
                out.push(e);
            }
        }
        out
    }

    #[test]
    fn splits_lines_and_trims_cr() {
        let mut a = LineAssembler::new();
        let events = drive(&mut a, b"hello\r\nworld\n");
        assert_eq!(events.len(), 2);
        match &events[0] {
            Event::Line(v) => assert_eq!(v, b"hello"),
            _ => panic!(),
        }
        match &events[1] {
            Event::Line(v) => assert_eq!(v, b"world"),
            _ => panic!(),
        }
    }

    #[test]
    fn reports_oversize() {
        let mut a = LineAssembler::new();
        let big = vec![b'x'; MAX_LINE + 100];
        let mut events = drive(&mut a, &big);
        assert!(events.is_empty());
        events = drive(&mut a, b"\n");
        assert!(matches!(events.as_slice(), [Event::TooLong]));
        // Recovers for the next line.
        let after = drive(&mut a, b"ok\n");
        assert!(matches!(after.as_slice(), [Event::Line(_)]));
    }
}
