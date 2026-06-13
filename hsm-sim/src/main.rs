//! Host simulator for PicoSignet.
//!
//! Wires `hsm-core` to the in-memory mock HAL and pumps newline-delimited JSON
//! between stdin and stdout, exactly as the firmware does over USB CDC-ACM.
//! Used by the differential test suite and for local protocol experiments.
//!
//! Flags:
//!   --deterministic-rng <hex>   seed the entropy source for reproducible runs
//!   --fixed-time <unix-seconds> pre-set the clock (skip an explicit hsm.setTime)
//!   --state-file <path>         load the flash image at start, save it at exit

use std::io::{self, BufRead, Write};
use std::process::ExitCode;

use hsm_core::dispatch::Hsm;
use hsm_core::testhal::{MockClock, MockEntropy, MockFlash};

/// Default entropy seed so the simulator is reproducible unless overridden.
const DEFAULT_SEED: u64 = 0x7573_6268_736d_0042;

struct Args {
    seed: u64,
    fixed_time: Option<i64>,
    state_file: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut seed = DEFAULT_SEED;
    let mut fixed_time = None;
    let mut state_file = None;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--deterministic-rng" => {
                let hex = it.next().ok_or("--deterministic-rng needs a value")?;
                seed = fold_hex_seed(&hex);
            }
            "--fixed-time" => {
                let v = it.next().ok_or("--fixed-time needs a value")?;
                fixed_time = Some(v.parse().map_err(|_| "invalid --fixed-time")?);
            }
            "--state-file" => {
                state_file = Some(it.next().ok_or("--state-file needs a value")?);
            }
            other => return Err(format!("unknown flag: {other}")),
        }
    }
    Ok(Args {
        seed,
        fixed_time,
        state_file,
    })
}

/// Fold an arbitrary-length hex string into a u64 seed for the mock entropy.
fn fold_hex_seed(hex: &str) -> u64 {
    let mut acc: u64 = 0xcbf29ce484222325; // FNV-1a offset basis
    for b in hex.bytes() {
        acc ^= b as u64;
        acc = acc.wrapping_mul(0x100000001b3);
    }
    acc
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("hsm-sim: {e}");
            return ExitCode::from(2);
        }
    };

    let mut flash = MockFlash::new();
    if let Some(path) = &args.state_file {
        if let Ok(data) = std::fs::read(path) {
            flash.restore(&data);
        }
    }

    // Drive the device over a borrowed flash so we can snapshot it after the
    // Hsm is dropped (the `&mut T: FlashStore` impl makes this work).
    {
        let mut hsm = Hsm::boot(MockEntropy::new(args.seed), MockClock::new(), &mut flash);

        if let Some(t) = args.fixed_time {
            let line = format!(r#"{{"hsm":{{"setTime":{{"unixSeconds":{t}}}}}}}"#);
            let _ = hsm.process_line(line.as_bytes());
        }

        let stdin = io::stdin();
        let stdout = io::stdout();
        let mut out = stdout.lock();
        for line in stdin.lock().lines() {
            let line = match line {
                Ok(l) => l,
                Err(_) => break,
            };
            if line.trim().is_empty() {
                continue;
            }
            let resp = hsm.process_line(line.as_bytes());
            if out
                .write_all(&resp)
                .and_then(|_| out.write_all(b"\n"))
                .and_then(|_| out.flush())
                .is_err()
            {
                break;
            }
        }
    }

    if let Some(path) = &args.state_file {
        let _ = std::fs::write(path, flash.snapshot());
    }

    ExitCode::SUCCESS
}
