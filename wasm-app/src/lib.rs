//! SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2026 Kevin Thomas
//!
//! # WASM UART Echo Component
//!
//! A minimal WebAssembly component that reads characters from UART and echoes
//! them back, including backspace handling for terminal interaction. Uses
//! typed WIT interfaces (`embedded:platform/uart`) instead of raw imports.

#![no_std]

// Enable the global allocator for heap-backed collections.
extern crate alloc;

use core::panic::PanicInfo; // Panic handler signature type.

/// Global heap allocator required by the canonical ABI's `cabi_realloc`.
#[global_allocator]
static ALLOC: dlmalloc::GlobalDlmalloc = dlmalloc::GlobalDlmalloc;

use embedded::platform::uart; // Host-provided UART import.

// Generate guest-side bindings for the `uart-echo` WIT world.
wit_bindgen::generate!({
    world: "uart-echo",
    path: "../wit",
});

/// WASM guest component implementing the `uart-echo` world.
struct UartEchoApp;

// Register `UartEchoApp` as the component's exported implementation.
export!(UartEchoApp);

impl Guest for UartEchoApp {
    /// Echoes UART characters indefinitely with special handling.
    ///
    /// Reads one byte at a time from UART and echoes it back, with special
    /// handling for backspace (BS/DEL) and newline (CR/LF) characters.
    fn run() {
        loop {
            echo_char(read_byte());
        }
    }
}

/// Reads a single byte from UART via the host function.
///
/// # Returns
///
/// The byte read from UART.
fn read_byte() -> u8 {
    uart::read_byte()
}

/// Writes a single byte to UART via the host function.
///
/// # Arguments
///
/// * `b` - The byte to transmit over UART.
fn write_byte(b: u8) {
    uart::write_byte(b);
}

/// Handles a backspace character by erasing the previous character.
///
/// Sends the sequence: backspace, space, backspace to overwrite the
/// previous character on the terminal display.
fn handle_backspace() {
    write_byte(0x08);
    write_byte(b' ');
    write_byte(0x08);
}

/// Handles a carriage return by sending CR+LF for proper newline.
fn handle_newline() {
    write_byte(b'\r');
    write_byte(b'\n');
}

/// Echoes a single character back based on its type.
///
/// # Arguments
///
/// * `b` - The byte to echo.
fn echo_char(b: u8) {
    match b {
        0x08 | 0x7F => handle_backspace(),
        b'\r' | b'\n' => handle_newline(),
        _ => write_byte(b),
    }
}

/// Panic handler for the WASM environment that halts in an infinite loop.
///
/// # Arguments
///
/// * `_info` - Panic information (unused in the WASM environment).
#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {
        core::hint::spin_loop();
    }
}
