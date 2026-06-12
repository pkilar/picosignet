//! usbhsm firmware entry point (RP2350).
//!
//! Initializes the heap and Embassy, then runs the USB CDC-ACM transport that
//! pumps newline-delimited JSON to `hsm-core`'s dispatcher. The HAL trait impls
//! (flash, entropy, time) live in the sibling modules.
#![no_std]
#![no_main]

extern crate alloc;

mod entropy_hal;
mod flash_hal;
mod led;
mod otp_secret;
mod security;
mod time_hal;
mod usb;

use core::mem::MaybeUninit;

use embassy_executor::Spawner;
use embedded_alloc::LlffHeap as Heap;
use panic_halt as _;

/// Global heap backing `alloc` in `hsm-core`. 384 KiB of the RP2350's 512 KiB
/// main SRAM: the Argon2id working set (m_cost = 256 KiB) lives here, with
/// headroom for the protocol buffers; the remaining 128 KiB covers stacks,
/// statics, and USB buffers.
#[global_allocator]
static HEAP: Heap = Heap::empty();

const HEAP_SIZE: usize = 384 * 1024;

/// RP2350 boot block: the bootrom scans the first 4 KiB of flash for this
/// IMAGE_DEF (placed by memory.x right after the vector table) to identify a
/// bootable Arm Secure executable. `picotool seal --sign` extends the block
/// with a signature for secure-boot provisioned devices.
#[link_section = ".start_block"]
#[used]
pub static IMAGE_DEF: embassy_rp::block::ImageDef = embassy_rp::block::ImageDef::secure_exe();

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
