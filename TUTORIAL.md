# Tutorial: Embedded WASM UART Echo — A Complete Code Walkthrough

This tutorial is a line-by-line, function-by-function guide through every Rust source file in the **embedded-wasm-uart** project. By the end, you will understand how a WebAssembly component is compiled, deployed, and executed on an RP2350 microcontroller to echo UART characters — entirely in bare-metal Rust with no operating system.

The walkthrough follows this order:

1. [WIT Interface Definition](#1-wit-interface-definition-witworldwit) — the contract between guest and host
2. [Platform Glue](#2-platform-glue-srcplatformrs) — thread-local storage stubs for Wasmtime
3. [UART Driver](#3-uart-driver-srcuartrs) — serial initialization and I/O
4. [Firmware Entry Point](#4-firmware-entry-point-srcmainrs) — hardware init, WASM runtime, panic handler
5. [Build Script](#5-build-script-buildrs) — AOT compilation pipeline
6. [WASM Guest Application](#6-wasm-guest-application-wasm-appsrclibrs) — the UART echo component itself

---

## 1. WIT Interface Definition (`wit/world.wit`)

Before any Rust code, the project defines a **WIT (WebAssembly Interface Type)** file. WIT is a language-neutral interface description that the WebAssembly Component Model uses to type-check function calls between a host (the firmware) and a guest (the WASM module).

```wit
package embedded:platform;
```

This declares a WIT package named `embedded:platform`. Package names use a namespace:name convention. This one lives in the `embedded` namespace and provides `platform`-level hardware abstractions.

```wit
interface uart {
    read-byte: func() -> u8;
    write-byte: func(byte: u8);
}
```

The `uart` interface defines two functions. The `read-byte` blocks until a byte is available on the UART receive line and returns it. The `write-byte` takes a byte and transmits it over the UART. These are **imports** — the guest calls them, and the host provides the implementations backed by real hardware.

Unlike the blinky project's `gpio` and `timing` interfaces, the UART interface is bidirectional — the guest can both read and write. This enables interactive applications like the echo loop.

```wit
world uart-echo {
    import uart;
    export run: func();
}
```

A **world** is a complete contract. The `uart-echo` world says: "I need `uart` from the host, and I will provide a `run` function." The host instantiates the component, calls `run`, and the WASM code takes over — reading characters from UART and echoing them back through the host-provided `uart` interface.

---

## 2. Platform Glue (`src/platform.rs`)

Wasmtime was originally built for desktop operating systems that provide thread-local storage (TLS) through the OS. On a bare-metal microcontroller, there is no OS, so we must provide TLS ourselves. This file is the simplest in the project — two functions and one static variable.

### Imports

```rust
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
```

The `ptr` provides `null_mut()` for initializing the TLS value. `AtomicPtr` is an atomic pointer type that can be read and written from any context without data races. On a single-core Cortex-M33, atomics are not strictly necessary, but they satisfy Rust's type system and make the code correct by construction.

### The TLS Variable

```rust
static TLS_VALUE: AtomicPtr<u8> = AtomicPtr::new(ptr::null_mut());
```

This is the entire TLS implementation. Wasmtime's runtime stores a single pointer per thread. Since the RP2350 runs a single thread, one global atomic pointer is sufficient. It starts as null and gets set by Wasmtime during component execution.

### `wasmtime_tls_get`

```rust
#[unsafe(no_mangle)]
pub extern "C" fn wasmtime_tls_get() -> *mut u8 {
    TLS_VALUE.load(Ordering::Relaxed)
}
```

Wasmtime calls this symbol by name to retrieve the current thread's TLS pointer. The `#[unsafe(no_mangle)]` attribute (Rust 2024 syntax) prevents the compiler from mangling the function name, so Wasmtime's linker can find it. The `extern "C"` uses the C calling convention. `Ordering::Relaxed` is sufficient because there is only one thread — no ordering guarantees are needed relative to other threads.

### `wasmtime_tls_set`

```rust
#[unsafe(no_mangle)]
pub extern "C" fn wasmtime_tls_set(ptr: *mut u8) {
    TLS_VALUE.store(ptr, Ordering::Relaxed);
}
```

This is the setter counterpart. Wasmtime calls it to store its runtime context pointer before executing WASM code, and clears it (stores null) when execution completes. Together, these two functions are the minimum platform glue that Wasmtime requires to run on bare metal.

---

## 3. UART Driver (`src/uart.rs`)

The UART driver provides serial I/O over GPIO0 (TX) and GPIO1 (RX) at 115200 baud. In this project, UART is the primary interface — not just for diagnostics, but for the application itself. The WASM guest reads and writes characters through this module. It is designed as a **shared plug-and-play** driver — it can be dropped into any RP2350 project without modification.

### Module Header

```rust
#![allow(dead_code)]
```

Because this module is shared across multiple projects, not every project uses every function. For example, the blinky project never calls `read_byte`, while this project uses it heavily. This attribute suppresses warnings for unused functions.

### Imports

```rust
use core::cell::RefCell;
use critical_section::Mutex;
use fugit::HertzU32;
use hal::Clock;
use nb::block;
use rp235x_hal as hal;
```

`RefCell` provides interior mutability — the ability to borrow the UART peripheral mutably at runtime even though it lives in a static. `Mutex` from the `critical_section` crate is a bare-metal mutex that disables interrupts to prevent data races. `HertzU32` is a typed frequency value that prevents unit confusion. `Clock` is a trait for reading peripheral clock frequencies. The `nb::block` import brings the `block!` macro into scope, which converts non-blocking operations into blocking ones by spinning. The `hal` alias maps to the RP2350 hardware abstraction layer.

### Constants

```rust
const UART0_BASE: u32 = 0x4007_0000;
```

The UART0 peripheral's base address in the RP2350's memory map. This is used only by the panic handler's raw register access functions — the normal HAL-based functions do not need it.

### The UART Type Alias

```rust
pub type Uart0 = hal::uart::UartPeripheral<
    hal::uart::Enabled,
    hal::pac::UART0,
    (
        hal::gpio::Pin<hal::gpio::bank0::Gpio0, hal::gpio::FunctionUart, hal::gpio::PullNone>,
        hal::gpio::Pin<hal::gpio::bank0::Gpio1, hal::gpio::FunctionUart, hal::gpio::PullNone>,
    ),
>;
```

This type alias captures the fully configured UART peripheral type. The HAL uses Rust's type system to encode the peripheral's state: it is `Enabled`, it is `UART0` (not UART1), and its TX/RX pins are GPIO0 and GPIO1 configured for the UART function with no pull resistors. This type-level encoding prevents runtime errors — you cannot accidentally pass an unconfigured UART to a function that expects a configured one.

### Global UART Storage

```rust
static UART: Mutex<RefCell<Option<Uart0>>> = Mutex::new(RefCell::new(None));
```

The UART peripheral is stored in a global static behind a critical-section mutex. The `Option` starts as `None` and is set to `Some(uart)` during initialization. This pattern — `Mutex<RefCell<Option<T>>>` — is the standard safe way to store peripherals globally in embedded Rust, avoiding all `unsafe` and raw pointers.

### `init`

```rust
pub fn init(
    uart0: hal::pac::UART0,
    resets: &mut hal::pac::RESETS,
    clocks: &hal::clocks::ClocksManager,
    tx_pin: hal::gpio::Pin<hal::gpio::bank0::Gpio0, hal::gpio::FunctionNull, hal::gpio::PullDown>,
    rx_pin: hal::gpio::Pin<hal::gpio::bank0::Gpio1, hal::gpio::FunctionNull, hal::gpio::PullDown>,
) -> Uart0 {
```

This function accepts the raw UART0 peripheral, the resets controller, the clocks manager, and **only** the two GPIO pins it needs. This is a deliberate design decision: the function does not accept the entire `Pins` struct. The caller (`main.rs`) owns all the pins and passes only GPIO0 and GPIO1 to the UART. This means adding a new GPIO pin to the project never requires changing this module.

The pins arrive in their default state (`FunctionNull`, `PullDown`) and are reconfigured inside:

```rust
    let uart_pins = (
        tx_pin.reconfigure::<hal::gpio::FunctionUart, hal::gpio::PullNone>(),
        rx_pin.reconfigure::<hal::gpio::FunctionUart, hal::gpio::PullNone>(),
    );
```

The `reconfigure` is a zero-cost type-level state transition. It configures the hardware registers and returns a new type that proves the pin is now in UART mode.

```rust
    hal::uart::UartPeripheral::new(uart0, uart_pins, resets)
        .enable(
            hal::uart::UartConfig::new(
                HertzU32::from_raw(115_200),
                hal::uart::DataBits::Eight,
                None,
                hal::uart::StopBits::One,
            ),
            clocks.peripheral_clock.freq(),
        )
        .expect("configure UART0")
}
```

The UART peripheral is created, configured for 115200 baud with 8N1 framing (8 data bits, no parity, 1 stop bit), and enabled. The `.expect()` call panics with a descriptive message if configuration fails — which would only happen if the hardware is in an unexpected state.

### `store_global`

```rust
pub fn store_global(uart: Uart0) {
    critical_section::with(|cs| {
        UART.borrow(cs).replace(Some(uart));
    });
}
```

After `init` returns the configured UART, the caller stores it in the global mutex so that any code can read from and write to UART0. The `critical_section::with` disables interrupts for the duration of the closure, acquires the mutex, and calls `replace(Some(uart))` to store the peripheral.

### `write_msg`

```rust
pub fn write_msg(msg: &[u8]) {
    critical_section::with(|cs| {
        let cell = UART.borrow(cs);
        let uart = cell.borrow();
        let uart = uart.as_ref().unwrap();
        for &b in msg {
            if b == b'\n' {
                uart.write_full_blocking(b"\r");
            }
            uart.write_full_blocking(&[b]);
        }
    });
}
```

This function writes a byte slice to UART0 using the HAL. It acquires the global mutex, borrows the UART peripheral, and writes each byte. The `\n` to `\r\n` conversion ensures proper line endings on serial terminals, which expect a carriage return before each line feed.

### `read_byte`

```rust
pub fn read_byte() -> u8 {
    critical_section::with(|cs| {
        let cell = UART.borrow(cs);
        let mut uart = cell.borrow_mut();
        let uart = uart.as_mut().unwrap();
        let mut buf = [0u8; 1];
        let _ = block!(uart.read_raw(&mut buf));
        buf[0]
    })
}
```

This function blocks until a byte arrives on the UART RX line. The `block!` macro from the `nb` crate spins on the non-blocking `read_raw` call until it returns `Ok`. In this project, `read_byte` is the primary input mechanism — the WASM guest calls it through the WIT `uart` interface to receive characters from the serial terminal. Note it uses `borrow_mut` because `read_raw` requires a mutable reference to the UART peripheral (reading modifies the RX FIFO state).

### `write_byte`

```rust
pub fn write_byte(byte: u8) {
    critical_section::with(|cs| {
        let cell = UART.borrow(cs);
        let uart = cell.borrow();
        uart.as_ref().unwrap().write_full_blocking(&[byte]);
    });
}
```

Writes a single byte to UART0. This is the echo path — the WASM guest reads a character with `read_byte`, then sends it back with `write_byte`. Unlike `read_byte`, writing only needs an immutable borrow because `write_full_blocking` does not modify the UART's internal state.

### `panic_init`

```rust
pub fn panic_init() {
    const RESETS_BASE: u32 = 0x4002_0000;
    const RESET_CLR: *mut u32 = (RESETS_BASE + 0x3000) as *mut u32;
    const RESET_DONE: *const u32 = (RESETS_BASE + 0x0008) as *const u32;
    const IO_BANK0_BASE: u32 = 0x4002_8000;
    const GPIO0_CTRL: *mut u32 = (IO_BANK0_BASE + 0x004) as *mut u32;
    const GPIO1_CTRL: *mut u32 = (IO_BANK0_BASE + 0x00C) as *mut u32;
    const UARTIBRD: *mut u32 = (UART0_BASE + 0x024) as *mut u32;
    const UARTFBRD: *mut u32 = (UART0_BASE + 0x028) as *mut u32;
    const UARTLCR_H: *mut u32 = (UART0_BASE + 0x02C) as *mut u32;
    const UARTCR: *mut u32 = (UART0_BASE + 0x030) as *mut u32;
```

This function re-initializes UART0 from scratch using **raw register writes** — no HAL. Why? During a panic, the HAL may be in an unknown state. The UART global might never have been initialized. The allocator might be corrupted. The only safe thing to do is talk directly to the hardware.

Each constant is a pointer to a specific hardware register. `RESET_CLR` deasserts peripheral resets. `RESET_DONE` reports when a peripheral is out of reset. `GPIO0_CTRL` and `GPIO1_CTRL` select the pin function (UART). The `UART*` registers configure baud rate, data format, and enable the peripheral.

```rust
    unsafe {
        core::ptr::write_volatile(RESET_CLR, (1 << 26) | (1 << 6));
        while core::ptr::read_volatile(RESET_DONE) & (1 << 26) == 0 {}
        while core::ptr::read_volatile(RESET_DONE) & (1 << 6) == 0 {}
        core::ptr::write_volatile(GPIO0_CTRL, 2);
        core::ptr::write_volatile(GPIO1_CTRL, 2);
        core::ptr::write_volatile(UARTIBRD, 81);
        core::ptr::write_volatile(UARTFBRD, 24);
        core::ptr::write_volatile(UARTLCR_H, (0b11 << 5) | (1 << 4));
        core::ptr::write_volatile(UARTCR, (1 << 0) | (1 << 8) | (1 << 9));
    }
```

The sequence: first, deassert the resets for IO_BANK0 (bit 6) and UART0 (bit 26) by writing to the atomic-clear register. Then spin until both peripherals report they are out of reset. Next, set GPIO0 and GPIO1 to function 2 (UART). Finally, configure the UART for 115200 baud at the default 150 MHz peripheral clock. The integer baud rate divisor (81) and fractional divisor (24) are calculated from: `150_000_000 / (16 * 115200) = 81.380`, fractional part `0.380 * 64 = 24.3 ≈ 24`. The line control register sets 8 data bits and enables the FIFO. The control register enables the UART, transmitter, and receiver.

### `panic_write_byte`

```rust
pub fn panic_write_byte(byte: u8) {
    const UARTDR: *mut u32 = UART0_BASE as *mut u32;
    const UARTFR: *const u32 = (UART0_BASE + 0x018) as *const u32;
    unsafe {
        while core::ptr::read_volatile(UARTFR) & (1 << 5) != 0 {}
        core::ptr::write_volatile(UARTDR, byte as u32);
    }
}
```

Writes a single byte by spinning until the TX FIFO has space (flag register bit 5 is the "TX FIFO full" flag), then writing to the data register. This is the panic handler's equivalent of `write_byte`, using raw registers instead of the HAL.

### `panic_write`

```rust
pub fn panic_write(msg: &[u8]) {
    for &b in msg {
        if b == b'\n' {
            panic_write_byte(b'\r');
        }
        panic_write_byte(b);
    }
}
```

Iterates over a byte slice, writing each byte with `\n` to `\r\n` conversion, using the raw register path. This is what the panic handler calls to output the panic message.

---

## 4. Firmware Entry Point (`src/main.rs`)

This is the largest file and the heart of the firmware. It initializes hardware, sets up the WASM runtime, and bridges the WIT `uart` interface to real hardware. Unlike the blinky project, there is no LED driver — this project is purely UART-driven.

### Crate Attributes and Module Declarations

```rust
#![no_std]
#![no_main]
```

The `no_std` means no standard library — only `core` and `alloc`. The `no_main` means there is no standard `fn main()` — the entry point is provided by `cortex-m-rt` via the `#[hal::entry]` attribute.

```rust
extern crate alloc;
```

Enables the `alloc` crate, which provides `Vec`, `Box`, `String`, and other heap types. The heap is backed by the `embedded-alloc` allocator initialized in `init_heap`.

```rust
mod platform;
mod uart;
```

These declarations bring the two modules into scope. Note there is no `led` module — this project does not control any GPIO output pins.

### Imports

```rust
use core::panic::PanicInfo;
use embedded_alloc::LlffHeap as Heap;
use rp235x_hal as hal;
use wasmtime::component::{Component, HasSelf};
use wasmtime::{Config, Engine, Store};
```

`PanicInfo` is the type passed to the panic handler. `LlffHeap` is a linked-list first-fit heap allocator designed for embedded systems. The `hal` is the RP2350 hardware abstraction layer. The Wasmtime imports bring in the Component Model's core types: `Component` (a precompiled WASM module), `Engine` (the execution environment), `Store` (per-instance state), and `HasSelf` (a marker type used for linker registration).

### WIT Bindings Generation

```rust
wasmtime::component::bindgen!({
    world: "uart-echo",
    path: "wit",
});
```

This macro reads the WIT file at compile time and generates Rust types and traits for the `uart-echo` world. It produces:
- A `UartEcho` struct with methods to instantiate the component and call exports
- An `embedded::platform::uart::Host` trait that the firmware must implement
- A `Guest` interface representing the component's exports

### Global Allocator

```rust
#[global_allocator]
static HEAP: Heap = Heap::empty();
```

Declares the heap allocator as a global static. It starts empty and is initialized by `init_heap` with a 256 KiB memory region. Wasmtime uses the heap extensively — for the `Store`, `Component` metadata, and WASM linear memory.

### Constants

```rust
const XOSC_CRYSTAL_FREQ: u32 = 12_000_000;
const HEAP_SIZE: usize = 262_144;
const WASM_BINARY: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/uart_echo.cwasm"));
```

`XOSC_CRYSTAL_FREQ` is the external crystal frequency (12 MHz) used to configure the PLL. `HEAP_SIZE` is 256 KiB — half of the RP2350's 512 KiB RAM, leaving the other half for the stack and Wasmtime's internal structures. `WASM_BINARY` embeds the precompiled Pulley bytecode directly into the firmware binary at compile time using `include_bytes!`. The `.cwasm` file is produced by `build.rs` and is named `uart_echo.cwasm` to distinguish it from the blinky component.

### Boot Metadata

```rust
#[unsafe(link_section = ".start_block")]
#[used]
pub static IMAGE_DEF: hal::block::ImageDef = hal::block::ImageDef::secure_exe();
```

The RP2350's boot ROM looks for metadata in a special `.start_block` section to determine how to boot. The `secure_exe()` tells the boot ROM this is a secure ARM executable. The `#[used]` attribute prevents the linker from stripping this symbol even though nothing references it in code. `#[unsafe(link_section)]` is the Rust 2024 syntax for placing data in a specific linker section.

### Host State and WIT Implementation

```rust
struct HostState;
```

The host state is the Rust type that Wasmtime's `Store` carries. The WIT host trait is implemented on this struct. It has no fields because all hardware access goes through the global UART static.

```rust
impl embedded::platform::uart::Host for HostState {
    fn read_byte(&mut self) -> u8 {
        uart::read_byte()
    }

    fn write_byte(&mut self, byte: u8) {
        uart::write_byte(byte);
    }
}
```

These are the host-side implementations of the WIT `uart` interface. When the WASM guest calls `uart::read_byte()`, Wasmtime routes it here, which delegates to the UART driver's `read_byte` function to block until a character arrives. When the guest calls `uart::write_byte(b)`, Wasmtime routes it to `uart::write_byte`, which sends the byte over the serial line. The Pulley interpreter pauses during each host call and resumes when it returns.

### Panic Handler

```rust
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
```

When any code panics (via `.unwrap()`, `.expect()`, `panic!`, etc.), this handler runs. It re-initializes UART0 from scratch using raw register writes (the HAL might be in an unknown state), then outputs the panic location and message. Finally, it enters an infinite loop using `wfe` (Wait For Event), which puts the CPU into a low-power state. This is critical for debugging — without a visible panic output, crashes on embedded targets are invisible.

### `init_heap`

```rust
fn init_heap() {
    use core::mem::MaybeUninit;
    static mut HEAP_MEM: [MaybeUninit<u8>; HEAP_SIZE] = [MaybeUninit::uninit(); HEAP_SIZE];
    unsafe { HEAP.init(&raw mut HEAP_MEM as usize, HEAP_SIZE) }
}
```

Allocates a 256 KiB region of uninitialized memory and passes it to the heap allocator. `MaybeUninit` tells the compiler this memory does not need to be zeroed — saving boot time. The `unsafe` block is required because `HEAP.init` takes a raw pointer; this is one of the few unavoidable uses of `unsafe` in the project.

### `init_clocks`

```rust
fn init_clocks(
    xosc: hal::pac::XOSC,
    clocks: hal::pac::CLOCKS,
    pll_sys: hal::pac::PLL_SYS,
    pll_usb: hal::pac::PLL_USB,
    resets: &mut hal::pac::RESETS,
    watchdog: &mut hal::Watchdog,
) -> hal::clocks::ClocksManager {
    hal::clocks::init_clocks_and_plls(
        XOSC_CRYSTAL_FREQ, xosc, clocks, pll_sys, pll_usb, resets, watchdog,
    )
    .ok()
    .unwrap()
}
```

Initializes the RP2350's clock tree. The external 12 MHz crystal drives two PLLs: the system PLL (configured to 150 MHz for the CPU) and the USB PLL (48 MHz for USB peripherals, though USB is not used here). The function returns a `ClocksManager` that provides clock frequency information to other peripherals — critically, the UART's baud rate calculation depends on knowing the peripheral clock frequency.

### `init_hardware`

```rust
fn init_hardware() {
    let mut pac = hal::pac::Peripherals::take().unwrap();
    let mut watchdog = hal::Watchdog::new(pac.WATCHDOG);
    let clocks = init_clocks(
        pac.XOSC, pac.CLOCKS, pac.PLL_SYS, pac.PLL_USB,
        &mut pac.RESETS, &mut watchdog,
    );
    let sio = hal::Sio::new(pac.SIO);
    let pins = hal::gpio::Pins::new(
        pac.IO_BANK0, pac.PADS_BANK0, sio.gpio_bank0, &mut pac.RESETS,
    );
    let uart_dev = uart::init(pac.UART0, &mut pac.RESETS, &clocks, pins.gpio0, pins.gpio1);
    uart::store_global(uart_dev);
}
```

This function initializes all hardware. `Peripherals::take()` is a singleton — it can only be called once, preventing multiple drivers from accessing the same hardware. The function creates the watchdog (required by the clock init), configures clocks, initializes the SIO (Single-cycle IO) for GPIO access, and creates the pin struct.

Pin allocation happens here and only here. GPIO0 and GPIO1 go to the UART — and that is all this project needs. Unlike the blinky project, there is no `led::store_pin` call because there are no output pins to register. If you wanted to add an LED on GPIO25, you would add `led::store_pin(25, pins.gpio25.into_push_pull_output())` here and introduce the `led` module.

### `create_engine`

```rust
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
```

Creates the Wasmtime execution engine. Every setting here is critical and must match the build-time engine in `build.rs` exactly:

- `target("pulley32")` — targets the Pulley 32-bit software interpreter instead of native code generation. Pulley is Wasmtime's portable bytecode interpreter that runs on any architecture.
- `signals_based_traps(false)` — disables OS signal handlers for traps. There is no OS to send signals.
- `memory_init_cow(false)` — disables copy-on-write memory initialization. There is no virtual memory system.
- `memory_reservation(0)` — disables virtual memory reservation. The RP2350 has only physical memory.
- `memory_guard_size(0)` — disables guard pages. No virtual memory means no guard pages.
- `memory_reservation_for_growth(0)` — no pre-reserved growth space.
- `guard_before_linear_memory(false)` — no guard page before linear memory.
- `max_wasm_stack(16384)` — limits the WASM stack to 16 KiB to fit in the constrained RAM.

### `create_component`

```rust
fn create_component(engine: &Engine) -> Component {
    unsafe { Component::deserialize(engine, WASM_BINARY) }.expect("valid Pulley component")
}
```

Deserializes the precompiled Pulley bytecode that was embedded by `include_bytes!`. The `unsafe` is required because `Component::deserialize` trusts that the bytes are a valid Wasmtime serialized component — this is guaranteed because our `build.rs` produced them.

### `build_linker`

```rust
fn build_linker(engine: &Engine) -> wasmtime::component::Linker<HostState> {
    let mut linker = wasmtime::component::Linker::new(engine);
    UartEcho::add_to_linker::<HostState, HasSelf<HostState>>(
        &mut linker,
        |state: &mut HostState| state,
    )
    .expect("register WIT interfaces");
    linker
}
```

Creates a component linker and registers all WIT interface implementations. `UartEcho::add_to_linker` was generated by `bindgen!` and connects the `uart::Host` trait implementation on `HostState` to the linker. The `HasSelf<HostState>` type parameter is a phantom type used internally by Wasmtime — the closure simply returns `state` unchanged.

### `execute_wasm`

```rust
fn execute_wasm(
    store: &mut Store<HostState>,
    linker: &wasmtime::component::Linker<HostState>,
    component: &Component,
) {
    let uart_echo =
        UartEcho::instantiate(&mut *store, component, linker).expect("instantiate component");
    uart_echo.call_run(&mut *store).expect("execute run");
}
```

Instantiates the WASM component and calls the exported `run` function. `UartEcho::instantiate` creates a live instance of the component with all imports resolved. The `call_run` invokes the guest's `run` function, which enters the infinite echo loop. This function only returns if the WASM guest's `run` function returns — which in this project it never does.

### `run_wasm`

```rust
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
```

Orchestrates the WASM runtime startup. Creates the engine, deserializes the component, creates a store with the host state, builds the linker, and executes the WASM component. The trailing `loop` is a safety net — `execute_wasm` should never return because the guest's `run` function loops forever.

### `main`

```rust
#[hal::entry]
fn main() -> ! {
    init_heap();
    init_hardware();
    run_wasm()
}
```

The firmware entry point. `#[hal::entry]` is the RP2350 HAL's entry point attribute (built on `cortex-m-rt`). It sets up the stack pointer and vector table, then calls this function. The boot sequence is: initialize the heap allocator, initialize all hardware peripherals, then start the WASM runtime. The `-> !` return type means this function never returns — the WASM guest's echo loop runs forever.

---

## 5. Build Script (`build.rs`)

The build script runs on the **host machine** (your development computer) during `cargo build`. It compiles the WASM guest application and AOT-compiles it to Pulley bytecode so the device does not need a WASM compiler.

### Imports

```rust
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use wasmtime::{Config, Engine};
use wit_component::ComponentEncoder;
```

Unlike the firmware code, the build script uses the full standard library (`std`). It needs file I/O, process spawning, and the host-side Wasmtime with Cranelift code generation.

### `setup_output_dir`

```rust
fn setup_output_dir() -> PathBuf {
    let out = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    println!("cargo:rustc-link-search={}", out.display());
    out
}
```

Gets the build output directory from the `OUT_DIR` environment variable (set by cargo) and registers it as a linker search path. The linker script (`memory.x`) and the compiled Pulley bytecode (`uart_echo.cwasm`) will be placed here.

### `write_linker_script`

```rust
fn write_linker_script(out: &Path) {
    let memory_x = include_bytes!("rp2350.x");
    let mut f = File::create(out.join("memory.x")).unwrap();
    f.write_all(memory_x).unwrap();
}
```

Copies the RP2350 memory layout linker script (`rp2350.x`) into the output directory as `memory.x`. The linker script defines the Flash (2 MiB) and RAM (512 KiB) regions and tells the linker where to place code, data, and the stack. The `cortex-m-rt` crate's `link.x` script includes `memory.x` automatically.

### `compile_wasm_app`

```rust
fn compile_wasm_app() {
    let status = Command::new("cargo")
        .args(["build", "--release", "--target", "wasm32-unknown-unknown"])
        .current_dir("wasm-app")
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .status()
        .expect("failed to build WASM app");
    assert!(status.success(), "WASM app compilation failed");
}
```

Spawns a child `cargo build` process to compile the WASM guest application. Key details:

- `--target wasm32-unknown-unknown` compiles to WebAssembly instead of the host architecture.
- `.current_dir("wasm-app")` runs the build in the WASM sub-crate's directory.
- `.env_remove("CARGO_ENCODED_RUSTFLAGS")` is critical — without this, the parent build's RUSTFLAGS (which contain ARM linker flags like `--nmagic` and `-Tlink.x`) leak into the child build and cause WASM linker errors.

The output is a core WASM module at `wasm-app/target/wasm32-unknown-unknown/release/wasm_app.wasm`.

### `create_pulley_engine`

```rust
fn create_pulley_engine() -> Engine {
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
```

Creates a Wasmtime engine for AOT cross-compilation. Every setting **must be identical** to `create_engine` in `src/main.rs`. When Wasmtime serializes a component, it embeds all configuration values in the `.cwasm` header. When the device deserializes it, it compares every value against the runtime engine. Any mismatch causes `Component::deserialize` to fail with a cryptic error.

### `compile_wasm_to_pulley`

```rust
fn compile_wasm_to_pulley(out: &Path) {
    let wasm_path = "wasm-app/target/wasm32-unknown-unknown/release/wasm_app.wasm";
    let wasm_bytes = std::fs::read(wasm_path).expect("read WASM binary");
    let component_bytes = ComponentEncoder::default()
        .module(&wasm_bytes)
        .expect("set core module")
        .validate(true)
        .encode()
        .expect("encode component");
    let engine = create_pulley_engine();
    let serialized = engine
        .precompile_component(&component_bytes)
        .expect("precompile component");
    std::fs::write(out.join("uart_echo.cwasm"), &serialized).expect("write Pulley bytecode");
}
```

This is the core of the AOT compilation pipeline and the most important function in the build script. It performs three transformations:

1. **Read the core WASM module** — the raw `.wasm` file produced by `cargo build` in the previous step.
2. **Encode as a component** — `ComponentEncoder` reads the type metadata that `wit-bindgen` embedded in the core module and wraps it as a proper WASM component with typed imports and exports.
3. **AOT-compile to Pulley bytecode** — `precompile_component` runs Cranelift (a code generator) targeting the `pulley32` architecture, producing serialized bytecode that the Pulley interpreter can execute without any compilation on the device.

The result is written to `uart_echo.cwasm`, which the firmware includes via `include_bytes!`.

### `print_rerun_triggers`

```rust
fn print_rerun_triggers() {
    println!("cargo:rerun-if-changed=rp2350.x");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=wasm-app/src/lib.rs");
    println!("cargo:rerun-if-changed=wasm-app/Cargo.toml");
    println!("cargo:rerun-if-changed=wit/world.wit");
}
```

Tells cargo which files should trigger a rebuild of the build script. Without these, cargo might cache the build script output and miss changes to the WASM guest code or WIT definitions.

### `main`

```rust
fn main() {
    let out = setup_output_dir();
    write_linker_script(&out);
    compile_wasm_app();
    compile_wasm_to_pulley(&out);
    print_rerun_triggers();
}
```

The build script entry point. The sequence is: set up the output directory, write the linker script, compile the WASM guest to a core module, transform and AOT-compile it to Pulley bytecode, and register file change triggers.

---

## 6. WASM Guest Application (`wasm-app/src/lib.rs`)

This is the WebAssembly component that runs **inside** the Wasmtime runtime on the RP2350. It has no access to hardware — only to the WIT `uart` interface the host provides. Unlike the blinky guest (which just loops set-high/delay/set-low), the UART echo guest performs interactive I/O with terminal-aware character handling.

### Crate Attributes

```rust
#![no_std]
```

The WASM guest is `no_std` because the `wasm32-unknown-unknown` target has no operating system. It uses `core` for language primitives and `alloc` for the heap.

```rust
extern crate alloc;
```

Enables heap allocation. The canonical ABI (the calling convention between host and guest) requires a `cabi_realloc` function for the host to allocate memory in the guest's linear memory. The `wit-bindgen` crate generates this function, and it needs a working allocator to call.

### Global Allocator

```rust
#[global_allocator]
static ALLOC: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;
```

The `dlmalloc` is a port of Doug Lea's malloc to Rust. It is the only allocator that works with `wasm32-unknown-unknown` in `no_std` because it implements its own `sbrk` by growing the WASM linear memory. The `global` feature flag makes it a `#[global_allocator]`.

### Imports and Bindings

```rust
use embedded::platform::uart;
```

This import comes from the bindings generated by `wit_bindgen::generate!`. It provides `uart::read_byte` and `uart::write_byte` — the functions defined in `world.wit` and implemented by the host firmware.

```rust
wit_bindgen::generate!({
    world: "uart-echo",
    path: "../wit",
});
```

This macro reads `wit/world.wit` at compile time and generates guest-side bindings. It creates the `embedded::platform::uart` module with functions that call into the host, and a `Guest` trait that the component must implement.

### The Guest Implementation

```rust
struct UartEchoApp;

export!(UartEchoApp);
```

`UartEchoApp` is the struct that implements the guest side of the `uart-echo` world. The `export!` macro (generated by `wit_bindgen`) registers it as the component's implementation, wiring up the exported `run` function.

```rust
impl Guest for UartEchoApp {
    fn run() {
        loop {
            echo_char(read_byte());
        }
    }
}
```

The `run` function is the entire application loop. It reads one byte from UART, passes it to `echo_char` for processing, and repeats forever. Each call to `read_byte` crosses the WASM boundary — the Pulley interpreter pauses, Wasmtime dispatches the call to `HostState::read_byte`, which blocks in the UART driver until a character arrives, then returns control to the interpreter.

### `read_byte`

```rust
fn read_byte() -> u8 {
    uart::read_byte()
}
```

A thin wrapper around the WIT-generated `uart::read_byte`. This delegates directly to the host function, which blocks until a byte arrives on UART0. The wrapper exists to keep the code readable and maintain the helper-above-caller ordering convention.

### `write_byte`

```rust
fn write_byte(b: u8) {
    uart::write_byte(b);
}
```

A thin wrapper around the WIT-generated `uart::write_byte`. Sends a single byte across the WASM boundary to the host, which transmits it over UART0.

### `handle_backspace`

```rust
fn handle_backspace() {
    write_byte(0x08);
    write_byte(b' ');
    write_byte(0x08);
}
```

Handles backspace and delete key presses with the standard terminal backspace sequence: move cursor left (`0x08` = BS), overwrite the character with a space, then move cursor left again. This ensures the previous character is visually erased from the terminal display. Without this three-byte sequence, a backspace would just move the cursor without clearing the character.

### `handle_newline`

```rust
fn handle_newline() {
    write_byte(b'\r');
    write_byte(b'\n');
}
```

Converts any newline input (CR or LF) into a proper CR+LF sequence. Serial terminals expect both characters to start a new line — CR moves the cursor to column 0, and LF moves it down one row. Sending only one would result in either overwriting the current line or stepping down without returning to column 0.

### `echo_char`

```rust
fn echo_char(b: u8) {
    match b {
        0x08 | 0x7F => handle_backspace(),
        b'\r' | b'\n' => handle_newline(),
        _ => write_byte(b),
    }
}
```

The character dispatch function. It takes a byte and routes it to the appropriate handler based on its value. Backspace (`0x08`) and delete (`0x7F`) trigger the erase sequence. Carriage return (`\r`) and line feed (`\n`) trigger the newline sequence. All other characters are echoed verbatim. This `match` is the heart of the echo application — it turns a simple byte-in/byte-out loop into a usable terminal experience.

### Panic Handler

```rust
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
```

The WASM guest's panic handler. Unlike the firmware's panic handler, it cannot write to a UART — it has no direct hardware access. It simply enters an infinite loop using `spin_loop()` (a hint to the CPU to reduce power consumption while spinning). In practice, a panic in the WASM guest would cause Wasmtime to trap, which would be caught by the firmware's panic handler.

---

## Summary: The Complete Execution Flow

1. The RP2350 powers on and the boot ROM reads `IMAGE_DEF` from `.start_block`
2. `main()` calls `init_heap()` to set up the 256 KiB heap
3. `init_hardware()` configures clocks (150 MHz) and UART0 (115200 baud on GPIO0/GPIO1)
4. `run_wasm()` creates the Pulley engine and deserializes the precompiled WASM component
5. `execute_wasm()` instantiates the component and calls `run`
6. The guest's `run()` enters an infinite loop: `read_byte()` -> `echo_char()` -> back to `read_byte()`
7. Each `read_byte` call crosses the WASM boundary into the host, which blocks until a character arrives on UART0
8. Each `write_byte` call crosses the boundary and transmits a byte over UART0
9. Special characters (backspace, newline) are handled by the guest's dispatch logic
10. Characters echo. Forever.

## License

MIT
