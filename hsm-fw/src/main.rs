//! usbhsm firmware entry point (RP2040).
//!
//! Initializes the heap and Embassy, then runs the USB CDC-ACM transport that
//! pumps newline-delimited JSON to `hsm-core`'s dispatcher. The HAL trait impls
//! (flash, entropy, time) live in the sibling modules.
#![no_std]
#![no_main]

extern crate alloc;

mod entropy_hal;
mod flash_hal;
mod time_hal;
mod usb;

use core::mem::MaybeUninit;

use embassy_executor::Spawner;
use embedded_alloc::LlffHeap as Heap;
use panic_halt as _;

/// Global heap backing `alloc` in `hsm-core`. 128 KiB leaves headroom on the
/// RP2040's 264 KiB SRAM for stacks, USB buffers, and the Argon2 working set.
#[global_allocator]
static HEAP: Heap = Heap::empty();

const HEAP_SIZE: usize = 128 * 1024;

// The second-stage bootloader (`.boot2`) is provided by embassy-rp, which
// embeds the W25Q080 loader by default.

#[embassy_executor::main]
async fn main(spawner: Spawner) {
    // Initialize the global allocator before any `alloc` use.
    {
        static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
        // SAFETY: touched exactly once, here, before anything allocates.
        unsafe { HEAP.init(core::ptr::addr_of_mut!(HEAP_MEM) as usize, HEAP_SIZE) }
    }

    let p = embassy_rp::init(Default::default());
    usb::run(spawner, p).await;
}
