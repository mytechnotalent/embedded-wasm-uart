//! SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2026 Kevin Thomas
//!
//! # WASM UART Echo Firmware for RP2350 (Pico 2)
//!
//! This firmware runs a WebAssembly Component Model runtime on the RP2350
//! bare-metal using wasmtime with the Pulley interpreter. A precompiled WASM
//! component reads characters from UART0 and echoes them back, including
//! backspace handling, through typed WIT interfaces (`embedded:platform/uart`).

#![no_std]
#![no_main]

// Enable the global allocator for heap-backed collections.
extern crate alloc;

/// WIT host-import implementations for UART.
mod platform;
/// UART peripheral setup and I/O helpers.
mod uart;

use core::panic::PanicInfo; // Panic handler signature type.
use embedded_alloc::LlffHeap as Heap; // Linked-list first-fit heap allocator.
use rp235x_hal as hal; // RP2350 HAL shorthand.
use wasmtime::component::{Component, HasSelf}; // Component Model loader and linker traits.
use wasmtime::{Config, Engine, Store}; // Wasmtime runtime core types.

// Generate host-side bindings for the `uart-echo` WIT world.
wasmtime::component::bindgen!({
    world: "uart-echo",
    path: "wit",
});

/// Global heap allocator backed by a statically allocated memory region.
///
/// Uses the linked-list first-fit allocation strategy from `embedded-alloc`.
#[global_allocator]
static HEAP: Heap = Heap::empty();

/// External crystal oscillator frequency in Hz.
const XOSC_CRYSTAL_FREQ: u32 = 12_000_000;

/// Heap size in bytes (256 KiB of the available 512 KiB RAM).
const HEAP_SIZE: usize = 262_144;

/// Precompiled Pulley bytecode for the WASM UART echo component, embedded at build time.
const WASM_BINARY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/uart_echo.cwasm"));

/// RP2350 boot metadata placed in the `.start_block` section for the Boot ROM.
#[unsafe(link_section = ".start_block")]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();

/// Host state providing WIT interface implementations via the wasmtime store.
///
/// All hardware access goes through the global UART state (`uart.rs`), so the
/// host state carries no fields. The WIT `Host` trait is implemented
/// directly on this struct.
struct HostState;

impl embedded::platform::uart::Host for HostState {
    /// Reads a single byte from UART0 (blocking).
    ///
    /// # Returns
    ///
    /// The byte read from UART0.
    fn read_byte(&mut self) -> u8 {
        uart::read_byte()
    }

    /// Writes a single byte to UART0.
    ///
    /// # Arguments
    ///
    /// * `byte` - The byte to transmit over UART0.
    fn write_byte(&mut self, byte: u8) {
        uart::write_byte(byte);
    }
}

/// Panic handler that outputs a diagnostic message over UART0.
///
/// Initializes UART0 via direct register writes (in case HAL is not yet
/// configured), then writes "PANIC" followed by the panic info.
///
/// # Arguments
///
/// * `info` - Panic information containing the location and message.
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    uart::panic_init();
    uart::panic_write(b"\n!!! PANIC !!!\n");
    if let Some(location) = info.location() {
        uart::panic_write(b"Location: ");
        uart::panic_write(location.file().as_bytes());
        uart::panic_write(b"\n");
    }
    if let Some(msg) = info.message().as_str() {
        uart::panic_write(b"Message: ");
        uart::panic_write(msg.as_bytes());
        uart::panic_write(b"\n");
    }
    loop {
        cortex_m::asm::wfe();
    }
}

/// Initializes the global heap allocator from a static memory region.
///
/// # Safety
///
/// Must be called exactly once before any heap allocations occur.
/// Uses `unsafe` to initialize the allocator with a raw pointer to static memory.
fn init_heap() {
    use core::mem::MaybeUninit;
    /// Static memory region backing the global heap allocator.
    static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    unsafe { HEAP.init(&raw mut HEAP_MEM as usize, HEAP_SIZE) }
}

/// Initializes system clocks and PLLs from the external crystal oscillator.
///
/// # Arguments
///
/// * `xosc` - External oscillator peripheral.
/// * `clocks` - Clocks peripheral.
/// * `pll_sys` - System PLL peripheral.
/// * `pll_usb` - USB PLL peripheral.
/// * `resets` - Resets peripheral for subsystem reset control.
/// * `watchdog` - Watchdog timer used as the clock reference.
///
/// # Returns
///
/// The configured clocks manager for peripheral clock access.
///
/// # Panics
///
/// Panics if clock initialization fails.
fn init_clocks(
    xosc: hal::pac::XOSC,
    clocks: hal::pac::CLOCKS,
    pll_sys: hal::pac::PLL_SYS,
    pll_usb: hal::pac::PLL_USB,
    resets: &mut hal::pac::RESETS,
    watchdog: &mut hal::Watchdog,
) -> hal::clocks::ClocksManager {
    hal::clocks::init_clocks_and_plls(
        XOSC_CRYSTAL_FREQ,
        xosc,
        clocks,
        pll_sys,
        pll_usb,
        resets,
        watchdog,
    )
    .ok()
    .unwrap()
}

/// Initializes all RP2350 hardware peripherals.
///
/// Sets up the watchdog, clocks, SIO, and GPIO pins. Passes only GPIO0
/// (TX) and GPIO1 (RX) to `uart::init()`, keeping all other pins under
/// `main.rs` control.
///
/// # Panics
///
/// Panics if the hardware peripherals have already been taken.
fn init_hardware() {
    let mut pac = hal::pac::Peripherals::take().unwrap();
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);
    let clocks = init_clocks(
        pac.XOSC,
        pac.CLOCKS,
        pac.PLL_SYS,
        pac.PLL_USB,
        &mut pac.RESETS,
        &mut watchdog,
    );
    let sio = hal::Sio::new(pac.SIO);
    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0,
        pac.PADS_BANK0,
        sio.gpio_bank0,
        &mut pac.RESETS,
    );
    let uart_dev = uart::init(pac.UART0, &mut pac.RESETS, &clocks, pins.gpio0, pins.gpio1);
    uart::store_global(uart_dev);
}

/// Creates a wasmtime engine configured for Pulley on bare-metal.
///
/// Explicitly targets `pulley32` to match the AOT cross-compilation in
/// `build.rs`. All settings must be identical between build-time and
/// runtime engines or `Component::deserialize` will fail. OS-dependent
/// features are disabled and memory limits are tuned for the RP2350's
/// 512 KiB RAM.
///
/// # Returns
///
/// A configured wasmtime `Engine` targeting the Pulley 32-bit interpreter.
///
/// # Panics
///
/// Panics if the engine configuration fails.
fn create_engine() -> Engine {
    let mut config = Config::new();
    config.target("pulley32").expect("set pulley32 target");
    config.signals_based_traps(false);
    config.memory_init_cow(false);
    config.memory_reservation(0);
    config.memory_guard_size(0);
    config.memory_reservation_for_growth(0);
    config.guard_before_linear_memory(false);
    config.max_wasm_stack(16384);
    Engine::new(&config).expect("create Pulley engine")
}

/// Deserializes the precompiled Pulley component from embedded bytes.
///
/// # Safety
///
/// Uses `unsafe` to call `Component::deserialize` which requires that the
/// embedded bytes are a valid serialized wasmtime component. This invariant
/// is upheld because the bytes are produced by our build script.
///
/// # Arguments
///
/// * `engine` - Engine with matching Pulley configuration.
///
/// # Returns
///
/// The deserialized wasmtime `Component`.
///
/// # Panics
///
/// Panics if the embedded Pulley bytecode is invalid.
fn create_component(engine: &Engine) -> Component {
    unsafe { Component::deserialize(engine, WASM_BINARY) }.expect("valid Pulley component")
}

/// Builds the component linker with all WIT interface bindings registered.
///
/// Uses the `bindgen!`-generated `UartEcho::add_to_linker` to register
/// host implementations for `embedded:platform/uart`.
///
/// # Arguments
///
/// * `engine` - WASM engine that the linker is associated with.
///
/// # Returns
///
/// A configured component `Linker` with all WIT interfaces registered.
///
/// # Panics
///
/// Panics if any interface fails to register.
fn build_linker(engine: &Engine) -> wasmtime::component::Linker<HostState> {
    let mut linker = wasmtime::component::Linker::new(engine);
    UartEcho::add_to_linker::<HostState, HasSelf<HostState>>(
        &mut linker,
        |state: &mut HostState| state,
    )
    .expect("register WIT interfaces");
    linker
}

/// Instantiates the WASM component and executes the exported `run` function.
///
/// # Arguments
///
/// * `store` - WASM store holding the host state.
/// * `linker` - Component linker with WIT interfaces registered.
/// * `component` - Precompiled WASM component to instantiate.
///
/// # Panics
///
/// Panics if instantiation fails or the `run` export is not found.
fn execute_wasm(
    store: &mut Store<HostState>,
    linker: &wasmtime::component::Linker<HostState>,
    component: &Component,
) {
    let uart_echo =
        UartEcho::instantiate(&mut *store, component, linker).expect("instantiate component");
    uart_echo.call_run(&mut *store).expect("execute run");
}

/// Loads and runs the WASM UART echo component.
fn run_wasm() -> ! {
    let engine = create_engine();
    let component = create_component(&engine);
    let mut store = Store::new(&engine, HostState);
    let linker = build_linker(&engine);
    execute_wasm(&mut store, &linker, &component);
    loop {
        cortex_m::asm::wfe();
    }
}

/// Firmware entry point that initializes hardware and runs the WASM UART echo.
#[hal::entry]
fn main() -> ! {
    init_heap();
    init_hardware();
    run_wasm()
}
