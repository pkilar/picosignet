//! Device-meaningful values for the `getEnclaveMetrics` compatibility response.
//!
//! cerberus's enclave reports `/proc/stat` and `/proc/meminfo`. The HSM has
//! neither, so it fills the same JSON shape with what it does have: total SRAM
//! and the current free-heap estimate the firmware reports. CPU fields carry
//! the device uptime in the `user` slot (counter semantics) and zero elsewhere.
//! The host only uses these for coarse health dashboards.

use crate::proto::{EnclaveCpuTimes, EnclaveMemoryStats, EnclaveMetricsResponse};

/// RP2040 has 264 KiB of SRAM.
const TOTAL_SRAM_BYTES: u64 = 264 * 1024;

/// Build a metrics snapshot. `uptime_us` is the monotonic uptime; `heap_free`
/// is the firmware's current free-heap estimate (0 if unknown, e.g. in the
/// simulator).
pub fn build(uptime_us: u64, heap_free: u64) -> EnclaveMetricsResponse {
    EnclaveMetricsResponse {
        cpu: EnclaveCpuTimes {
            user: uptime_us as f64 / 1_000_000.0,
            nice: 0.0,
            system: 0.0,
            idle: 0.0,
            iowait: 0.0,
            irq: 0.0,
            softirq: 0.0,
        },
        memory: EnclaveMemoryStats {
            total_bytes: TOTAL_SRAM_BYTES,
            available_bytes: heap_free,
            free_bytes: heap_free,
            buffers_bytes: 0,
            cached_bytes: 0,
        },
    }
}
