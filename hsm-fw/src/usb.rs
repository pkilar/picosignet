//! USB CDC-ACM transport: enumerate as a serial port and pump
//! newline-delimited JSON to the `hsm-core` dispatcher, while driving the
//! on-board WS2812 status LED from the device state.

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

/// Build the USB device + status LED and run them with the protocol loop.
pub async fn run(_spawner: Spawner, p: Peripherals) {
    let driver = Driver::new(p.USB, Irqs);

    let mut config = Config::new(0x1209, 0x000A);
    config.manufacturer = Some("usbhsm");
    config.product = Some("usbhsm");
    config.serial_number = Some("usbhsm-0");
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
        // Fold boot SRAM noise into the DRBG (additive; the TRNG stays the
        // primary, health-checked source).
        hsm.mix_entropy(&boot_noise());
        led.set_state(hsm.state()).await;

        loop {
            class.wait_connection().await;
            let _ = session(&mut class, &mut hsm, &mut led).await;
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
