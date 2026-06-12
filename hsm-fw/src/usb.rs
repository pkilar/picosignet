//! USB CDC-ACM transport: enumerate as a serial port and pump
//! newline-delimited JSON to the `hsm-core` dispatcher.

use embassy_executor::Spawner;
use embassy_futures::join::join;
use embassy_rp::bind_interrupts;
use embassy_rp::peripherals::USB;
use embassy_rp::usb::{Driver, InterruptHandler};
use embassy_rp::Peripherals;
use embassy_usb::class::cdc_acm::{CdcAcmClass, State};
use embassy_usb::driver::EndpointError;
use embassy_usb::{Builder, Config};
use static_cell::StaticCell;

use hsm_core::dispatch::Hsm;

use hsm_core::lineio::{Event, LineAssembler};

use crate::entropy_hal::{boot_noise, RoscEntropy};
use crate::flash_hal::EmbassyFlash;
use crate::time_hal::EmbassyClock;

bind_interrupts!(struct Irqs {
    USBCTRL_IRQ => InterruptHandler<USB>;
});

const PACKET: usize = 64;

/// Build the USB device and run it concurrently with the protocol loop.
pub async fn run(_spawner: Spawner, p: Peripherals) {
    let driver = Driver::new(p.USB, Irqs);

    let mut config = Config::new(0x1209, 0x000A);
    config.manufacturer = Some("usbhsm");
    config.product = Some("usbhsm");
    config.serial_number = Some("usbhsm-0");
    config.max_power = 100;
    config.max_packet_size_0 = PACKET as u8;
    // CDC composite device class triple (IAD), for clean enumeration.
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

    let usb_fut = usb.run();

    let proto_fut = async {
        let flash = EmbassyFlash::new(p.FLASH);
        let mut hsm = Hsm::boot(RoscEntropy::new(), EmbassyClock, flash);
        // Fold boot SRAM noise into the DRBG (additive; ROSC stays the primary,
        // health-checked source).
        hsm.mix_entropy(&boot_noise());

        loop {
            class.wait_connection().await;
            // A session ends when the host disconnects; loop to wait again.
            let _ = session(&mut class, &mut hsm).await;
        }
    };

    join(usb_fut, proto_fut).await;
}

async fn session<'d>(
    class: &mut CdcAcmClass<'d, Driver<'d, USB>>,
    hsm: &mut Hsm<RoscEntropy, EmbassyClock, EmbassyFlash<'d>>,
) -> Result<(), EndpointError> {
    let mut asm = LineAssembler::new();
    let mut packet = [0u8; PACKET];
    loop {
        let n = class.read_packet(&mut packet).await?;
        for &b in &packet[..n] {
            match asm.push(b) {
                Some(Event::Line(line)) => {
                    let resp = hsm.process_line(&line);
                    write_framed(class, &resp).await?;
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
