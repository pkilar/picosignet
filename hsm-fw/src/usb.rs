//! USB CDC-ACM transport: enumerate as a serial port and pump
//! newline-delimited JSON to the `hsm-core` dispatcher, while driving the
//! on-board WS2812 status LED from the device state.

use core::sync::atomic::{AtomicBool, Ordering};

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_rp::bind_interrupts;
use embassy_rp::peripherals::{PIO0, TRNG, USB};
use embassy_rp::pio::{InterruptHandler as PioInterruptHandler, Pio};
use embassy_rp::pio_programs::ws2812::{PioWs2812, PioWs2812Program};
use embassy_rp::trng::{InterruptHandler as TrngInterruptHandler, Trng};
use embassy_rp::usb::{Driver, InterruptHandler as UsbInterruptHandler};
use embassy_rp::Peripherals;
use embassy_time::Timer;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::driver::EndpointError;
use embassy_usb::{Builder, Config};
use static_cell::StaticCell;

use hsm_core::dispatch::Hsm;
use hsm_core::lineio::{Event, LineAssembler};

use crate::entropy_hal::{boot_noise, TrngEntropy};
use crate::flash_hal::EmbassyFlash;
use crate::led::StatusLed;
use crate::time_hal::EmbassyClock;

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => UsbInterruptHandler<USB>;
    PIO0_IRQ_0 => PioInterruptHandler<PIO0>;
    TRNG_IRQ => TrngInterruptHandler<TRNG>;
});

const PACKET: usize = 64;

/// Set by [`ResetHandler`] on a USB bus reset or suspend. The protocol loop
/// polls and clears it, re-locking a production device rather than relying
/// only on `session()`'s own `Result` return — a suspend need not error a
/// pending endpoint read the way a physical unplug or bus reset typically
/// does, so a device left plugged into a suspended host could otherwise stay
/// `ProdReady` indefinitely. `docs/THREAT_MODEL.md` and the state-machine
/// diagram in `hsm_core::state` both document "lock / USB reset / suspend" as
/// a re-lock trigger; this is what actually implements it.
static RELOCK_REQUESTED: AtomicBool = AtomicBool::new(false);

/// `embassy_usb::Handler` that only observes bus-level reset/suspend events
/// to flip [`RELOCK_REQUESTED`]. Registered with the `Builder` in [`run`].
struct ResetHandler;

impl embassy_usb::Handler for ResetHandler {
    fn reset(&mut self) {
        RELOCK_REQUESTED.store(true, Ordering::Relaxed);
    }
    fn suspended(&mut self, suspended: bool) {
        if suspended {
            RELOCK_REQUESTED.store(true, Ordering::Relaxed);
        }
    }
}

/// Build the USB device + status LED and run them with the protocol loop.
pub async fn run(_spawner: Spawner, p: Peripherals) {
    // Arm the voltage-glitch detectors before anything touches key material;
    // the config locks until next reset.
    let glitch_armed = crate::security::arm_glitch_detectors();

    let driver = Driver::new(p.USB, Irqs);

    let mut config = Config::new(0x1209, 0x000A);
    config.manufacturer = Some("PicoSignet");
    config.product = Some("PicoSignet");
    config.serial_number = Some("picosignet-0");
    config.max_power = 100;
    config.max_packet_size_0 = PACKET as u8;
    config.device_class = 0xEF;
    config.device_sub_class = 0x02;
    config.device_protocol = 0x01;
    config.composite_with_iads = true;

    static CONFIG_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static BOS_DESC: StaticCell<[u8; 256]> = StaticCell::new();
    static MSOS_DESC: StaticCell<[u8; 128]> = StaticCell::new();
    static CONTROL_BUF: StaticCell<[u8; 128]> = StaticCell::new();
    static STATE: StaticCell<State> = StaticCell::new();

    let mut builder = Builder::new(
        driver,
        config,
        CONFIG_DESC.init([0; 256]),
        BOS_DESC.init([0; 256]),
        MSOS_DESC.init([0; 128]),
        CONTROL_BUF.init([0; 128]),
    );

    let mut class = CdcAcmClass::new(&mut builder, STATE.init(State::new()), PACKET as u16);

    static RESET_HANDLER: StaticCell<ResetHandler> = StaticCell::new();
    builder.handler(RESET_HANDLER.init(ResetHandler));

    let mut usb = builder.build();

    // Status LED: WS2812 on GPIO16 (PIO0/SM0, DMA0) — Waveshare RP2350-One.
    let Pio {
        mut common, sm0, ..
    } = Pio::new(p.PIO0, Irqs);
    let ws_program = PioWs2812Program::new(&mut common);
    let mut led = StatusLed::new(PioWs2812::new(
        &mut common,
        sm0,
        p.DMA_CH0,
        p.PIN_16,
        &ws_program,
    ));

    let usb_fut = usb.run();

    let proto_fut = async {
        let mut entropy = TrngEntropy::new(Trng::new(p.TRNG, Irqs, TrngEntropy::config()));
        // First boot burns the per-device OTP secret; every boot loads it,
        // then the runtime SW_LOCK makes its pages unreadable (even to us)
        // until the next reset. On failure the device still boots — status
        // stays reachable — but every KEK operation fails closed.
        let device_secret = crate::otp_secret::load_or_provision(&mut entropy);
        crate::otp_secret::lock_slots();
        let flash = EmbassyFlash::new(p.FLASH, device_secret);
        let mut hsm = Hsm::boot(entropy, EmbassyClock, flash);
        hsm.set_security_flags(
            glitch_armed,
            crate::security::secure_boot_enabled(),
            crate::security::last_reset_was_glitch(),
        );
        // Fold boot SRAM noise into the DRBG (additive; the TRNG stays the
        // primary, health-checked source).
        hsm.mix_entropy(&boot_noise());
        led.set_state(hsm.state()).await;

        loop {
            class.wait_connection().await;
            let _ = session(&mut class, &mut hsm, &mut led).await;
            // The connection just dropped for some reason (unplug, bus reset,
            // an I/O error) — a production device must not stay unlocked once
            // the host that unlocked it is gone. Also clear the flag so a
            // suspend that fires without ever erroring `session` (handled
            // inline inside it) doesn't leave a stale relock pending forever.
            RELOCK_REQUESTED.store(false, Ordering::Relaxed);
            hsm.relock_on_transport_reset();
            led.set_state(hsm.state()).await;
        }
    };

    join(usb_fut, proto_fut).await;
}

async fn session<'c, 't, 'f, 'l>(
    class: &mut CdcAcmClass<'c, Driver<'c, USB>>,
    hsm: &mut Hsm<TrngEntropy<'t>, EmbassyClock, EmbassyFlash<'f>>,
    led: &mut StatusLed<'l>,
) -> Result<(), EndpointError> {
    let mut asm = LineAssembler::new();
    let mut packet = [0u8; PACKET];
    loop {
        let n = class.read_packet(&mut packet).await?;
        for &b in &packet[..n] {
            match asm.push(b) {
                Some(Event::Line(line)) => {
                    // A suspend need not error the endpoint the way a reset or
                    // unplug typically does, so this session might still be
                    // "connected" per `wait_connection` — catch it here too,
                    // before honoring the next request, rather than only
                    // after the connection eventually drops.
                    if RELOCK_REQUESTED.swap(false, Ordering::Relaxed) {
                        hsm.relock_on_transport_reset();
                    }
                    led.busy().await;
                    let resp = hsm.process_line(&line);
                    led.set_state(hsm.state()).await;
                    write_framed(class, &resp).await?;
                    if hsm.take_reboot_requested() {
                        // Let the ack drain to the host, then reset to BOOTSEL.
                        Timer::after_millis(80).await;
                        // RP2350 bootrom reboot (datasheet §5.4.8.24):
                        // REBOOT_TYPE_BOOTSEL (0x0002) | NO_RETURN_ON_SUCCESS (0x0100).
                        embassy_rp::rom_data::reboot(0x0102, 100, 0, 0);
                    }
                }
                Some(Event::TooLong) => {
                    write_framed(class, br#"{"error":"request too large (max 16384 bytes)"}"#)
                        .await?;
                }
                None => {}
            }
        }
    }
}

/// Write `resp` followed by a newline, in <=64-byte USB packets.
async fn write_framed<'d>(
    class: &mut CdcAcmClass<'d, Driver<'d, USB>>,
    resp: &[u8],
) -> Result<(), EndpointError> {
    let mut buf = [0u8; PACKET];
    let mut idx = 0;
    for &b in resp.iter().chain(core::iter::once(&b'\n')) {
        buf[idx] = b;
        idx += 1;
        if idx == PACKET {
            class.write_packet(&buf).await?;
            idx = 0;
        }
    }
    if idx > 0 {
        class.write_packet(&buf[..idx]).await?;
    }
    Ok(())
}
