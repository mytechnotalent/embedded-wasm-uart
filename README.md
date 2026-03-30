# Embedded WASM UART Echo
## WebAssembly UART Echo on RP2350 Pico 2

> Part of the [embedded-wasm](https://github.com/mytechnotalent/embedded-wasm) collection — a set of repos that runs a WebAssembly Component Model runtime (Wasmtime + Pulley interpreter) directly on the RP2350 bare-metal with hardware capabilities exposed through WIT.

A pure Embedded Rust project that runs a **WebAssembly Component Model runtime** (Wasmtime + Pulley interpreter) directly on the RP2350 (Raspberry Pi Pico 2) bare-metal. A WASM component is AOT-compiled to Pulley bytecode on the host and executed on the device to echo UART characters through typed WIT interfaces (`embedded:platform/uart`) — no operating system and no standard library.

<br>

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Project Structure](#project-structure)
- [Source Files](#source-files)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Flashing](#flashing)
- [Usage](#usage)
- [Testing](#testing)
- [How It Works](#how-it-works)
- [WIT Interface Contract](#wit-interface-contract)
- [Memory Layout](#memory-layout)
- [Extending the Project](#extending-the-project)
- [Troubleshooting](#troubleshooting)
- [Tutorial](#tutorial)
- [License](#license)

<br>

## Overview

This project demonstrates that WebAssembly is not just for browsers — it can run on a microcontroller with 512 KB of RAM. The firmware uses [Wasmtime](https://github.com/bytecodealliance/Wasmtime) with the **Pulley interpreter** (a portable, `no_std`-compatible WebAssembly runtime) and executes a precompiled WASM component that reads characters from UART0 and echoes them back with terminal-friendly backspace handling through typed WIT interfaces.

**Key properties:**

- **Pure Rust** — zero C code, zero C bindings, zero FFI
- **Component Model** — typed WIT interfaces (`embedded:platform/uart`), not raw `extern "C"` imports
- **Minimal unsafe** — only unavoidable sites (heap init, boot metadata, component deserialize, panic handler UART)
- **Tiny WASM component** — minimal footprint for the echo module
- **AOT compilation** — WASM is compiled to Pulley bytecode on the host, no compilation on device
- **Industry-standard runtime** — Wasmtime is the reference WebAssembly implementation
- **Terminal-friendly** — handles backspace/DEL, CR/LF for proper serial terminal interaction

## Architecture

```
┌───────────────────────────────────────────────────────┐
│                 RP2350 (Pico 2)                       │
│                                                       │
│  ┌───────────────────────────────────────────────┐    │
│  │            Firmware (src/main.rs)             │    │
│  │                                               │    │
│  │  ┌─────────┐  ┌────────┐  ┌───────────┐       │    │
│  │  │  Heap   │  │Wasmtime│  │ WIT Host  │       │    │
│  │  │ 256 KiB │  │ Pulley │  │ Trait Impl│       │    │
│  │  └─────────┘  └───┬────┘  └─────┬─────┘       │    │
│  │                   │             │             │    │
│  │  ┌────────┐  ┌────┴─────────────┴──────────┐  │    │
│  │  │uart.rs │  │ Component (.cwasm)          │  │    │
│  │  └────────┘  │                             │  │    │
│  │              │  imports:                   │  │    │
│  │              │    embedded:platform/uart   │  │    │
│  │              │      read-byte() -> u8      │  │    │
│  │              │      write-byte(byte: u8)   │  │    │
│  │              │                             │  │    │
│  │              │  exports:                   │  │    │
│  │              │    run()                    │  │    │
│  │              └─────────────────────────────┘  │    │
│  └───────────────────────────────────────────────┘    │
│                                                       │
│  GPIO0 (UART0 TX) -> Serial Out                       │
│  GPIO1 (UART0 RX) <- Serial In                        │
└───────────────────────────────────────────────────────┘
```

## Project Structure

```
embedded-wasm-uart/
├── .cargo/
│   └── config.toml        # ARM Cortex-M33 target, linker flags, picotool runner
├── .vscode/
│   ├── extensions.json    # Recommended VS Code extensions
│   └── settings.json      # Rust-analyzer target configuration
├── wit/                   # WIT interface definitions (Component Model)
│   └── world.wit          # uart-echo world: import uart, export run
├── wasm-app/              # WASM UART echo component (compiled to .wasm)
│   ├── .cargo/
│   │   └── config.toml    # WASM linker flags (minimal memory)
│   ├── Cargo.toml
│   └── src/
│       └── lib.rs         # Echo logic: wit-bindgen generated uart interface, exports run()
├── wasm-tests/            # Integration tests for the WASM component
│   ├── Cargo.toml
│   ├── build.rs           # Encodes core WASM as component via ComponentEncoder
│   └── tests/
│       └── integration.rs # 9 tests: loading, imports, echo, backspace, CR/LF
├── src/
│   ├── main.rs            # Firmware: hardware init, Wasmtime component runtime, WIT host traits
│   ├── uart.rs            # UART0 driver (shared plug-and-play module)
│   └── platform.rs        # Platform TLS glue for Wasmtime no_std
├── build.rs               # Compiles WASM app, encodes as component, AOT-compiles to Pulley
├── Cargo.toml             # Firmware dependencies
├── rp2350.x               # RP2350 memory layout linker script
├── SKILLS.md              # Project conventions and lessons learned
└── README.md              # This file
```

## Source Files

### `wit/world.wit` — WIT Interface Definitions

Defines the `embedded:platform` package with the `uart` interface and the `uart-echo` world. This is the contract between guest and host — the guest calls `uart.read-byte()` and `uart.write-byte(byte)` without knowing anything about the hardware. The host maps those calls to real UART registers.

### `wasm-app/src/lib.rs` — WASM Guest Component

The WASM component compiled to `wasm32-unknown-unknown`. Uses `wit_bindgen::generate!()` to generate typed bindings from the `uart-echo` WIT world. Implements the `Guest` trait with a `run()` function that reads characters in an infinite loop and echoes them back via the `embedded:platform/uart` interface. Helper functions handle backspace/DEL (BS+Space+BS) and CR/LF newline conversion. Uses `dlmalloc` as the global allocator for the canonical ABI's `cabi_realloc`.

### `src/main.rs` — Firmware Entry Point

Orchestrates everything: initializes the heap (256 KiB), clocks, and hardware peripherals, then boots the Wasmtime Pulley engine. Uses `wasmtime::component::bindgen!()` to generate host-side types and implements `embedded::platform::uart::Host` on `HostState` to bridge WIT imports to the `uart` driver module. Deserializes the embedded `.cwasm` component bytecode via `Component::deserialize` and calls the WASM `run()` export via `UartEcho::instantiate()`. The panic handler uses `uart::panic_init()` and `uart::panic_write()` to output diagnostics over UART0 via raw register writes.

### `src/uart.rs` — UART0 Driver (Shared Module)

Provides both HAL-based and raw-register UART0 access. The `uart::init()` accepts only the GPIO0 (TX) and GPIO1 (RX) pins and configures UART0 at 115200 baud, returning just the UART peripheral. Callers retain ownership of all other pins. The `uart::store_global()` stores the UART in a `critical_section::Mutex`. HAL functions: `write_msg()`, `read_byte()`, `write_byte()`. Panic functions (raw registers, no HAL): `panic_init()`, `panic_write()`. Marked `#![allow(dead_code)]` — shared module, identical across repos.

### `src/platform.rs` — Wasmtime TLS Glue

Implements `wasmtime_tls_get()` and `wasmtime_tls_set()` using a global `AtomicPtr`. Required by Wasmtime on `no_std` platforms. On this single-threaded MCU, TLS is just a single atomic pointer.

### `build.rs` — AOT Build Script

Copies the linker script (`rp2350.x` → `memory.x`), spawns a child `cargo build` to compile `wasm-app/` to a core `.wasm` binary, encodes it as a WASM component via `ComponentEncoder` (using the `wit-bindgen` metadata embedded in the binary), then AOT-compiles the component to Pulley bytecode via Cranelift. Strips `CARGO_ENCODED_RUSTFLAGS` from the child build to prevent ARM linker flags from leaking into the WASM compilation.

## Prerequisites

### Toolchain

```bash
# Rust (stable)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Required compilation targets
rustup target add thumbv8m.main-none-eabihf # RP2350 ARM Cortex-M33
rustup target add wasm32-unknown-unknown    # WebAssembly
```

### Flashing Tool

```bash
# macOS
brew install picotool

# Linux (build from source)
# See https://github.com/raspberrypi/picotool
```

### Serial Terminal

```bash
# macOS — use screen or minicom
screen /dev/tty.usbserial* 115200

# Linux
minicom -D /dev/ttyACM0 -b 115200

# Or use any serial terminal (PuTTY, CoolTerm, etc.)
```

### Optional (Debugging)

```bash
cargo install probe-rs-tools
```

## Building

```bash
cargo build --release
```

This single command does everything:

1. `build.rs` compiles `wasm-app/` to `wasm32-unknown-unknown` → produces `wasm_app.wasm` (core module with `wit-bindgen` metadata)
2. `build.rs` encodes the core module as a WASM component via `ComponentEncoder`
3. `build.rs` AOT-compiles the component to Pulley bytecode via Cranelift → produces `uart_echo.cwasm`
4. The firmware compiles for `thumbv8m.main-none-eabihf`, embedding the Pulley bytecode via `include_bytes!`
5. The result is an ELF at `target/thumbv8m.main-none-eabihf/release/embedded-wasm-uart`

## Flashing

```bash
cargo run --release
```

This builds the firmware and flashes it to the Pico 2 via `picotool` (configured as the cargo runner in `.cargo/config.toml`).

> **Note:** Hold the **BOOTSEL** button on the Pico 2 while plugging in the USB cable to enter bootloader mode. Release once connected.

## Usage

After flashing, connect to the Pico 2's UART0 via a USB-to-serial adapter:

- **GPIO0** → TX (connect to adapter's RX)
- **GPIO1** → RX (connect to adapter's TX)
- **GND** → GND

Open a serial terminal at **115200 baud, 8N1**:

```bash
screen /dev/tty.usbserial* 115200
```

Type characters — they will be echoed back immediately. Backspace/DEL erases the previous character. Enter sends CR+LF for a proper newline.

## Debugging (VS Code + probe-rs)

### Prerequisites

- [probe-rs](https://probe.rs/) installed
- [probe-rs VS Code extension](https://marketplace.visualstudio.com/items?itemName=probe-rs.probe-rs-debugger) installed
- Debug probe connected to the Pico 2 SWD pins (SWCLK, SWDIO, GND)

### Usage

1. Open the project in VS Code
2. Set breakpoints in `src/main.rs` (or any source file)
3. Press **F5** or select **Run -> Start Debugging**
4. The `debuggable` profile builds with `release` optimizations + full debug symbols (`debug = 2`)
5. probe-rs flashes the ELF and halts at your first breakpoint

The pre-launch task runs:

```bash
cargo build --profile debuggable
```

This produces an ELF at `target/thumbv8m.main-none-eabihf/debuggable/embedded-wasm-uart.elf`.

### Variables Panel

> **Warning:** Do **NOT** expand the **Static** dropdown in the Variables panel. It attempts to enumerate every static variable in the binary — including thousands from Wasmtime internals — over the SWD link, causing an infinite spin. Use the **Locals** and **Registers** dropdowns instead.

## Testing

```bash
cd wasm-tests && cargo test
```

Runs 9 integration tests validating:
- Component loading and compilation
- Export contract (`run` function exists)
- Import contract (`embedded:platform/uart` interface)
- All imports from `embedded:platform` package
- Normal character echo
- Backspace handling (BS → BS+Space+BS)
- DEL handling (0x7F → BS+Space+BS)
- Carriage return handling (CR → CR+LF)
- Full mixed sequence (char + DEL + char + CR)

## How It Works

### 1. The WIT Interface (`wit/world.wit`)

Defines the contract between guest and host:

```wit
package embedded:platform;

interface uart {
    read-byte: func() -> u8;
    write-byte: func(byte: u8);
}

world uart-echo {
    import uart;
    export run: func();
}
```

The guest calls `uart.read-byte()` and `uart.write-byte(byte)` without knowing anything about the hardware. The host maps those calls to real UART registers.

### 2. The WASM Guest (`wasm-app/src/lib.rs`)

The WASM component is a `#![no_std]` Rust library compiled to `wasm32-unknown-unknown`. It uses `wit-bindgen` to generate typed bindings from the `uart-echo` WIT world and implements the `Guest` trait:

```rust
wit_bindgen::generate!({
    world: "uart-echo",
    path: "../wit",
});

struct UartEchoApp;
export!(UartEchoApp);

impl Guest for UartEchoApp {
    fn run() {
        loop {
            echo_char(uart::read_byte());
        }
    }
}
```

No `unsafe`, no register addresses, no HAL — just typed function calls.

The echo logic handles three cases:
- **Backspace/DEL** (0x08 or 0x7F): sends BS + Space + BS to erase the previous character
- **CR/LF** (0x0D or 0x0A): sends CR+LF for proper terminal newline
- **Normal characters**: echoed back as-is

### 3. The Firmware Runtime (`src/main.rs`)

The firmware boots in this sequence:

1. **`init_heap()`** — 256 KiB heap for Wasmtime via `embedded-alloc`.
2. **`init_hardware()`** — Clocks, SIO, GPIO, UART0:
   - `uart::init(gpio0, gpio1)` → configures UART0 at 115200 baud (takes only TX/RX pins)
   - `uart::store_global()` → stores UART in mutex
3. **`run_wasm()`** — Boots the WASM Component Model runtime:
   ```
   create_engine()    → Config::target("pulley32"), bare-metal settings
   create_component() → Component::deserialize(embedded .cwasm bytes)
   Store::new()       → Holds HostState (unit struct, no closures)
   build_linker()     → UartEcho::add_to_linker (WIT trait auto-registration)
   execute_wasm()     → UartEcho::instantiate() → call_run()
   ```

### 4. The Call Chain

```
WASM run()
  → uart::read_byte()                   [WIT import: embedded:platform/uart]
    → Host::read_byte(&mut self)        [trait impl on HostState]
      → uart::read_byte()               [uart.rs — HAL nb::block!(uart.read_raw())]
  ← returns byte as u8

  → echo_char(byte)                     [WASM internal logic]
    → match on backspace/CR/normal

  → uart::write_byte(byte)              [WIT import: embedded:platform/uart]
    → Host::write_byte(&mut self, byte) [trait impl on HostState]
      → uart::write_byte(b)             [uart.rs — HAL uart.write_full_blocking()]
```

### 5. The Build Pipeline (`build.rs`)

```
cargo build --release
       │
       ▼
   build.rs runs:
       │
       ├── 1. Copy rp2350.x → OUT_DIR/memory.x (linker script)
       │
       ├── 2. Spawn: cargo build --release --target wasm32-unknown-unknown
       │         └── wasm-app/ compiles → wasm_app.wasm (core module)
       │
       ├── 3. ComponentEncoder encodes core module as WASM component
       │         └── Uses wit-bindgen metadata embedded in the binary
       │
       ├── 4. AOT-compile component to Pulley bytecode via Cranelift:
       │         └── engine.precompile_component(&component) → uart_echo.cwasm
       │
       └── 5. Main firmware compiles:
               └── include_bytes!("uart_echo.cwasm") embeds the Pulley bytecode
               └── Links against memory.x for RP2350 memory layout
```

Critical detail: `CARGO_ENCODED_RUSTFLAGS` (ARM flags like `--nmagic`, `-Tlink.x`) must be stripped from the child WASM build via `.env_remove("CARGO_ENCODED_RUSTFLAGS")`.

### 6. Creating a New Project from This Template

1. Copy the repo and rename it.
2. Drop in `uart.rs` and `platform.rs` unchanged — they are plug-and-play.
3. Edit `wit/world.wit`:
   - Define your WIT interfaces (imports for the hardware your guest needs)
   - Define your world with `import` and `export run: func()`
4. Edit `wasm-app/src/lib.rs`:
   - `wit_bindgen::generate!()` pointing at your WIT world
   - Implement the `Guest` trait with your logic in `fn run()`
5. Edit `src/main.rs`:
   - `wasmtime::component::bindgen!()` pointing at your WIT world
   - Implement `Host` traits on `HostState` to bridge WIT to hardware
   - Pass only UART pins to `uart::init(gpio0, gpio1)` in `init_hardware()`
6. `build.rs` needs no changes unless you rename the `.cwasm` output.
7. `cargo build --release` → `cargo run --release` to flash.

## WIT Interface Contract

```wit
package embedded:platform;

interface uart {
    read-byte: func() -> u8;
    write-byte: func(byte: u8);
}

world uart-echo {
    import uart;
    export run: func();
}
```

| Interface                | Function     | Signature        | Description                               |
| ------------------------ | ------------ | ---------------- | ----------------------------------------- |
| `embedded:platform/uart` | `read-byte`  | `func() -> u8`   | Blocking read of a single byte from UART0 |
| `embedded:platform/uart` | `write-byte` | `func(byte: u8)` | Writes a single byte to UART0             |

## Memory Layout

| Region             | Address      | Size            | Usage                                                 |
| ------------------ | ------------ | --------------- | ----------------------------------------------------- |
| Flash              | `0x10000000` | 2 MiB           | Firmware code + embedded WASM component               |
| RAM (striped)      | `0x20000000` | 512 KiB         | Stack + heap + data                                   |
| Heap (allocated)   | —            | 256 KiB         | Wasmtime engine, store, component, WASM linear memory |
| WASM linear memory | —            | 64 KiB (1 page) | WASM component's addressable memory                   |
| WASM stack         | —            | 4 KiB           | WASM call stack                                       |

> **Important:** The default WASM linker allocates 1 MB of linear memory (16 pages). This exceeds the RP2350's total RAM. The `wasm-app/.cargo/config.toml` explicitly sets `--initial-memory=65536` (1 page) and `stack-size=4096`.

## Extending the Project

### Adding New WIT Interfaces

1. Add the interface in `wit/world.wit`:
   ```wit
   interface gpio {
       set-high: func(pin: u32);
       set-low: func(pin: u32);
   }
   ```

2. Import it in the world:
   ```wit
   world uart-echo {
       import uart;
       import gpio;
       export run: func();
   }
   ```

3. Implement the `Host` trait in `src/main.rs`:
   ```rust
   impl embedded::platform::gpio::Host for HostState {
       fn set_high(&mut self, pin: u32) {
           led::set_high(pin as u8);
       }
       fn set_low(&mut self, pin: u32) {
           led::set_low(pin as u8);
       }
   }
   ```

4. The guest can immediately use `gpio::set_high(25)` — no linker registration needed, `UartEcho::add_to_linker()` picks up all WIT traits automatically.

### Changing Echo Behavior

Edit the `echo_char()` function in `wasm-app/src/lib.rs`:

```rust
fn echo_char(b: u8) {
    match b {
        0x08 | 0x7F => handle_backspace(),
        b'\r' | b'\n' => handle_newline(),
        b'a'..=b'z' => write_byte(b - 32), // echo uppercase
        _ => write_byte(b),
    }
}
```

Rebuild and reflash — only the WASM component changes.

## Troubleshooting

| Symptom                                         | Cause                                  | Fix                                                                              |
| ----------------------------------------------- | -------------------------------------- | -------------------------------------------------------------------------------- |
| No echo from UART                               | WASM linear memory too large for heap  | Ensure `wasm-app/.cargo/config.toml` has `--initial-memory=65536`                |
| No echo from UART                               | Wiring wrong                           | GPIO0=TX→adapter RX, GPIO1=RX→adapter TX, GND→GND                                |
| `Component::deserialize` panics                 | Config mismatch build vs device        | Both engines must have identical `Config` settings                               |
| `Component::deserialize` panics                 | `default-features` mismatch            | Both `[dependencies]` and `[build-dependencies]` need `default-features = false` |
| Build fails with `unknown argument: --nmagic`   | Parent rustflags leaking to WASM build | Ensure `build.rs` has `.env_remove("CARGO_ENCODED_RUSTFLAGS")`                   |
| Build fails with `extern blocks must be unsafe` | Rust 2024 edition                      | Use `unsafe extern { ... }` with `safe fn` declarations                          |
| `picotool` can't find device                    | Not in bootloader mode                 | Hold BOOTSEL while plugging in USB                                               |
| `cargo build` doesn't pick up WASM changes      | Cached build artifacts                 | Run `cargo clean && cargo build --release`                                       |
| ComponentEncoder fails                          | wit-bindgen metadata missing           | Ensure wasm-app uses `wit-bindgen` with `macros` + `realloc` features            |
| Garbled characters in terminal                  | Baud rate mismatch                     | Ensure terminal is set to 115200 baud, 8N1                                       |

## Tutorial

For a comprehensive, line-by-line walkthrough of every source file and function in this project, see [TUTORIAL.md](TUTORIAL.md).

<br>

## License

- [MIT License](LICENSE)
