//! WS2812 (NeoPixel) status LED.
//!
//! Wiring is for the Adafruit Trinkey QT2040: a single WS2812 on GPIO27, powered
//! directly (no enable pin). The data line is driven by PIO0/SM0 via embassy-rp's
//! WS2812 program (DMA-backed). The colors map the device state machine so the
//! key is glanceable without a host:
//!
//! | State          | Color  |
//! |----------------|--------|
//! | Uninitialized  | blue   |
//! | DevReady       | green  |
//! | ProdLocked     | amber  |
//! | ProdReady      | green  |
//! | LockedOut      | red    |
//! | (processing)   | white  |  — shown while a request is handled, so a slow
//!                              Argon2id unlock visibly holds white for ~1.4 s.

use embassy_rp::peripherals::PIO0;
use embassy_rp::pio_programs::ws2812::PioWs2812;
use smart_leds::RGB8;

use hsm_core::state::DeviceState;

const fn rgb(r: u8, g: u8, b: u8) -> RGB8 {
    RGB8 { r, g, b }
}

// Low brightness — a status indicator, not a flashlight.
const BLUE: RGB8 = rgb(0, 0, 60);
const GREEN: RGB8 = rgb(0, 60, 0);
const AMBER: RGB8 = rgb(70, 28, 0);
const RED: RGB8 = rgb(80, 0, 0);
const BUSY: RGB8 = rgb(40, 40, 40);

/// Map a device state to its indicator color.
fn color_for(state: DeviceState) -> RGB8 {
    match state {
        DeviceState::Uninitialized => BLUE,
        DeviceState::DevReady | DeviceState::ProdReady => GREEN,
        DeviceState::ProdLocked => AMBER,
        DeviceState::LockedOut => RED,
    }
}

/// The on-board status LED, wrapping the WS2812 driver.
pub struct StatusLed<'d> {
    ws: PioWs2812<'d, PIO0, 0, 1>,
}

impl<'d> StatusLed<'d> {
    pub fn new(ws: PioWs2812<'d, PIO0, 0, 1>) -> Self {
        Self { ws }
    }

    /// Show the color for `state`.
    pub async fn set_state(&mut self, state: DeviceState) {
        self.ws.write(&[color_for(state)]).await;
    }

    /// Show the "processing" color (held for the duration of a slow request).
    pub async fn busy(&mut self) {
        self.ws.write(&[BUSY]).await;
    }
}
