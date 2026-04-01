# Reverse Engineering: embedded-wasm-uart

## Table of Contents

1. [Binary Overview](#1-binary-overview)
2. [ELF Header](#2-elf-header)
3. [Section Layout](#3-section-layout)
4. [Memory Map & Segments](#4-memory-map--segments)
5. [Boot Sequence](#5-boot-sequence)
6. [Vector Table](#6-vector-table)
7. [Firmware Function Map](#7-firmware-function-map)
8. [Hardware Register Access](#8-hardware-register-access)
9. [Pulley Interpreter Deep Dive](#9-pulley-interpreter-deep-dive)
10. [Embedded cwasm Blob](#10-embedded-cwasm-blob)
11. [Host-Guest Call Flow](#11-host-guest-call-flow)
12. [RE Observations](#12-re-observations)
13. [Pulley Instruction Set Architecture](#13-pulley-instruction-set-architecture)
14. [Pulley Bytecode Disassembly](#14-pulley-bytecode-disassembly)
15. [Ghidra Analysis Walkthrough](#15-ghidra-analysis-walkthrough)

---

## 1. Binary Overview

| Property       | Value                                    |
| -------------- | ---------------------------------------- |
| File           | `embedded-wasm-uart`                     |
| Size on disk   | 1,168,560 bytes (1.11 MiB)               |
| Format         | ELF32 ARM little-endian                  |
| ABI            | EABI5, hard-float                        |
| Target         | ARMv8-M Mainline (Cortex-M33)            |
| MCU            | RP2350 (Raspberry Pi Pico 2)             |
| Stripped       | No (symbol table + string table present) |
| Text functions | 2,375                                    |

The binary is a bare-metal `no_std` Rust firmware that hosts a Wasmtime
Component Model runtime with the Pulley bytecode interpreter. A
precompiled Wasm component reads characters from UART0 and echoes them
back with line editing (backspace handling and newline echo). The only
WIT interface is `embedded:platform/uart` with `read-byte` and
`write-byte` — no GPIO is used.

---

## 2. ELF Header

```
Magic:   7f 45 4c 46 01 01 01 03 00 00 00 00 00 00 00 00
Class:                             ELF32
Data:                              2's complement, little endian
Version:                           1 (current)
OS/ABI:                            UNIX - GNU
Type:                              EXEC (Executable file)
Machine:                           ARM
Entry point address:               0x1000010d
Flags:                             0x5000400, Version5 EABI, hard-float ABI
Program headers:                   6 (at offset 52)
Section headers:                   16 (at offset 1,167,920)
```

**Entry Point**: `0x1000010d` — the `Reset` handler in `.text`. The LSB is
set (0x0D vs 0x0C) to indicate Thumb mode, required by ARMv8-M. The actual
code starts at `0x1000010c`.

---

## 3. Section Layout

```
Nr  Name            Type        Addr        Size      Flags  Description
 1  .vector_table   PROGBITS    0x10000000  0x000f8   A      ARM exception + interrupt vectors
 2  .start_block    PROGBITS    0x100000f8  0x00014   AR     RP2350 IMAGE_DEF boot metadata
 3  .text           PROGBITS    0x1000010c  0x83a28   AX     All executable code (527 KiB)
 4  .bi_entries     PROGBITS    0x10083b34  0x00000   A      Binary info entries (empty)
 5  .rodata         PROGBITS    0x10083b38  0x1db38   AMSR   Read-only data (119 KiB)
 6  .data           PROGBITS    0x20000000  0x00028   WA     Initialized globals (40 bytes)
 7  .gnu.sgstubs    PROGBITS    0x100a1690  0x00000   A      Secure gateway stubs (empty)
 8  .bss            NOBITS      0x20000028  0x40094   WA     Zero-init data (256 KiB)
 9  .uninit         NOBITS      0x200400bc  0x00000   WA     Uninitialized memory (empty)
10  .end_block      PROGBITS    0x100a1690  0x00000   WA     Block end marker (empty)
13  .symtab         SYMTAB      file only   0x1d200          Symbol table (7,530 entries)
15  .strtab         STRTAB      file only   0x5fb3c          String table (385 KiB)
```

### Size Breakdown

| Region         | Section         | Size          | % of 4 MiB Flash     |
| -------------- | --------------- | ------------- | -------------------- |
| Code           | `.text`         | 539,176 B     | 12.9%                |
| Constants      | `.rodata`       | 121,656 B     | 2.9%                 |
| Vectors        | `.vector_table` | 248 B         | <0.1%                |
| Boot meta      | `.start_block`  | 20 B          | <0.1%                |
| Init data      | `.data`         | 40 B          | <0.1%                |
| **Flash used** |                 | **661,140 B** | **15.8%**            |
| **Flash free** |                 | 3,533,164 B   | 84.2%                |
| BSS (RAM)      | `.bss`          | 262,292 B     | 51.2% of 512 KiB RAM |

This is the smallest of the four embedded-wasm variants because it has
no GPIO module — only UART read/write host bindings.

### .data Section Note

The UART variant has 40 bytes of `.data` (vs 36 bytes for blinky/button/c2).
The extra 4 bytes are due to the UART peripheral handle being stored in
`.data` with an 8-byte representation (Mutex + RefCell overhead) rather than
a simpler 4-byte BSS slot.

---

## 4. Memory Map & Segments

```
Segment  VirtAddr     PhysAddr     MemSiz   Flags  Contents
  0      0x10000000   0x10000000   0x0010c  R      .vector_table + .start_block
  1      0x1000010c   0x1000010c   0x83a28  R E    .text (executable code)
  2      0x10083b34   0x10083b34   0x1db3c  R      .rodata (constants + cwasm blob)
  3      0x20000000   0x100a1668   0x00028  RW     .data (LMA in flash, VMA in RAM)
  4      0x20000028   0x20000028   0x40094  RW     .bss (zero-filled at boot)
  5      0x00000000   0x00000000   0x00000  RW     GNU_STACK (zero-size)
```

### Physical Address Space

```
Flash (XIP):  0x10000000 - 0x100a168f  (661 KiB used of 4 MiB)
              +-- 0x10000000  Vector table (248 B)
              +-- 0x100000f8  IMAGE_DEF boot block (20 B)
              +-- 0x1000010c  .text starts (Reset handler)
              +-- 0x10083b38  .rodata starts
              +-- 0x10088578  Embedded cwasm (Pulley ELF, ~24 KiB)
              +-- 0x100a1668  .data initializers (40 B, copied to RAM)

RAM (SRAM):   0x20000000 - 0x200400bb  (256 KiB used of 512 KiB)
              +-- 0x20000000  .data (40 B: UART handle + TLS value)
              +-- 0x20000028  TLS_VALUE (4 B)
              +-- 0x2000002c  HEAP_MEM (262,144 B = 256 KiB)
              +-- 0x2004002c  HEAP allocator struct (32 B)

Stack:        0x20080000  Initial SP (top of 512 KiB SRAM, grows down)
```

---

## 5. Boot Sequence

### 5.1 RP2350 Boot ROM -> IMAGE_DEF

The RP2350 Boot ROM scans flash for a valid image definition block. Our
`.start_block` section at `0x100000f8` contains:

```
d3deffff 42012110 ff010000 00000000 793512ab
```

This is `hal::block::ImageDef::secure_exe()` — it tells the Boot ROM
this is a secure ARM executable.

### 5.2 Vector Table -> Reset Handler

```
Word 0: 0x20080000  <- Initial Stack Pointer
Word 1: 0x1000010d  <- Reset vector (Thumb-mode)
```

### 5.3 Reset Handler (0x1000010c)

```armasm
Reset:
    bl      DefaultPreInit          ; No-op
    ; --- Zero .bss (0x20000028 -> 0x200400bc) ---
    ; --- Copy .data from flash (0x100a1668) to RAM (0x20000000) ---
    ; --- Enable FPU ---
    bl      main
    udf     #0
```

### 5.4 `main()` (0x10008014)

```armasm
main:
    bl      __cortex_m_rt_main      ; at 0x1000736c
```

### 5.5 `__cortex_m_rt_main` (0x1000736c)

```
    ; Enable FPU
    bl      init_heap               ; Initialize 256 KiB heap
    bl      init_hardware           ; Clocks, UART0 (GPIO0 TX + GPIO1 RX)
    bl      run_wasm                ; Run the Wasm UART echo component (never returns)
```

Note: Unlike blinky/button which enable SIO GPIO outputs, this variant
has no GPIO output setup — only UART0 is configured.

---

## 6. Vector Table

The vector table at `0x10000000` is 248 bytes (62 entries):

```
Offset  Vector              Handler          Address
0x0000  Initial SP          —                0x20080000
0x0004  Reset               Reset            0x1000010d
0x0008  NMI                 DefaultHandler   0x1007b5a5
0x000c  HardFault           HardFault_       0x10083b2d
0x0040+ IRQ0-IRQ51          DefaultHandler   0x1007b5a5
```

All exception/IRQ vectors point to `DefaultHandler` (infinite loop)
except HardFault (also infinite loop). No peripheral interrupts are used.

---

## 7. Firmware Function Map

### 7.1 Application Functions

| Address      | Size  | Symbol                          | Purpose                                     |
| ------------ | ----- | ------------------------------- | ------------------------------------------- |
| `0x1000010c` | 0x3e  | `Reset`                         | BSS zero, .data copy, FPU enable, call main |
| `0x100071e8` | 0x184 | `init_hardware`                 | Clocks, UART0 (GPIO0 TX, GPIO1 RX)          |
| `0x1000736c` | 0x6c  | `__cortex_m_rt_main`            | FPU, init_heap, init_hardware, run_wasm     |
| `0x100073d8` | 0x742 | `run_wasm`                      | Create engine, deserialize cwasm, run guest |
| `0x10007b1c` | 0x20  | `init_heap`                     | Initialize 256 KiB linked-list heap         |
| `0x1000801c` | 0xbc  | `platform::uart::add_to_linker` | Register read-byte/write-byte WIT bindings  |
| `0x10008014` | 0x8   | `main`                          | Thin #[entry] wrapper                       |
| `0x1007b5a4` | 0x6   | `DefaultHandler`                | Infinite loop (unhandled exception)         |
| `0x1007b5ac` | 0x6   | `DefaultPreInit`                | No-op (returns immediately)                 |
| `0x10083b2c` | 0x6   | `HardFault`                     | Infinite loop (hard fault)                  |

### 7.2 UART Host Bindings

The UART variant has no separate `led.rs` or `button.rs` modules. All
host bindings go through `platform::uart::add_to_linker` which registers
two WIT imports:

- **`read-byte`**: Calls `uart::read_byte()` — blocking read from UART0
  RX FIFO. Implemented via `nb::block!` on the HAL `read_full` method.

- **`write-byte`**: Calls `uart::write_byte(byte)` — blocking write to
  UART0 TX FIFO. Implemented via `nb::block!` on the HAL `write_full`
  method.

Note: `uart::read_byte`, `uart::write_byte`, and `uart::store_global`
are inlined by the compiler into `run_wasm` and `init_hardware`. They
do not appear as separate symbols in the binary.

### 7.3 Wasmtime Runtime (Top by Size)

| Address      | Size     | Demangled Name                     |
| ------------ | -------- | ---------------------------------- |
| `0x10031a50` | 16,464 B | `OperatorCost::deserialize`        |
| `0x10066fc8` | 16,456 B | `decode_one_extended`              |
| `0x10063cac` | 12,518 B | `Interpreter::run` (dispatch loop) |
| `0x1002d1f4` | 8,696 B  | `Metadata::check_cost`             |
| `0x1000c570` | 2,304 B  | `InterpreterRef::call`             |

### 7.4 BSS / Data Layout

| Address      | Size      | Section | Symbol       | Purpose                         |
| ------------ | --------- | ------- | ------------ | ------------------------------- |
| `0x20000000` | 8 B       | .data   | `uart::UART` | Mutex<RefCell<Option<Uart0>>>   |
| `0x20000028` | 4 B       | .bss    | `TLS_VALUE`  | Wasmtime TLS shim (platform.rs) |
| `0x2000002c` | 262,144 B | .bss    | `HEAP_MEM`   | Raw heap backing memory         |
| `0x2004002c` | 32 B      | .bss    | `HEAP`       | Linked-list allocator state     |

Note: No `led::PINS` or `button::PINS` — this variant has no GPIO
module.

---

## 8. Hardware Register Access

### 8.1 Peripheral Base Addresses

| Base Address | Peripheral | Usage in Firmware       |
| ------------ | ---------- | ----------------------- |
| `0x40020000` | RESETS     | Subsystem reset control |
| `0x40028000` | IO_BANK0   | GPIO function selection |
| `0x40030000` | PADS_BANK0 | Pad configuration       |
| `0x40040000` | XOSC       | Crystal oscillator      |
| `0x40048000` | PLL_SYS    | System PLL (150 MHz)    |
| `0x4004c000` | PLL_USB    | USB PLL (48 MHz)        |
| `0x40050000` | CLOCKS     | Clock generators        |
| `0x40070000` | UART0      | Serial I/O (TX + RX)    |
| `0xe000ed88` | CPACR      | FPU access control      |

### 8.2 UART0 Registers

UART0 is the only peripheral actively used at runtime:

```
0x40070000  UARTDR    Data register (TX/RX)
0x40070018  UARTFR    Flag register
                       Bit 4: RXFE (RX FIFO Empty)
                       Bit 5: TXFF (TX FIFO Full)
0x40070024  UARTIBRD  Integer baud rate divisor
0x40070028  UARTFBRD  Fractional baud rate divisor
0x4007002c  UARTLCR_H Line control (8N1 config)
0x40070030  UARTCR    Control register (enable)
```

### 8.3 GPIO Usage

Only two GPIO pins are configured, both for UART0:

- **GPIO0**: UART0 TX (Function: UART)
- **GPIO1**: UART0 RX (Function: UART)

No SIO GPIO output/input registers are used at runtime (no `0xd0000014`
SET or `0xd0000004` IN accesses). This is the only embedded-wasm variant
with no SIO GPIO runtime access.

---

## 9. Pulley Interpreter Deep Dive

### 9.1 Interpreter Entry (`InterpreterRef::call`)

```
Location:  0x1000c570  (2,304 bytes)
```

Call sequence:

```
run_wasm()
  -> UartEcho::instantiate()
    -> UartEcho::call_run()
      -> InterpreterRef::call()     <-- native-to-Pulley boundary
        -> Vm::call_start()         ; Set up Pulley register file
        -> Vm::call_run()           ; Enter interpreter loop
          -> Interpreter::run()     ; Main dispatch loop
```

### 9.2 Main Dispatch Loop

```
Location:  0x10063cac  (12,518 bytes)
```

Same two-level dispatch scheme as all embedded-wasm repos: primary
opcodes (0x00-0xDB) handled by a jump table in `Interpreter::run`,
extended opcodes (0xDC prefix + 2-byte opcode) handled by
`decode_one_extended`.

---

## 10. Embedded cwasm Blob

### 10.1 Location and Format

The precompiled Pulley bytecode is embedded in `.rodata` at
`0x10088578`. It is **24,456 bytes** (0x5f88).

| Field  | Value                          |
| ------ | ------------------------------ |
| Magic  | `\x7fELF`                      |
| Class  | ELF64 (byte `02` at offset 4)  |
| Data   | Little-endian                  |
| Target | `pulley32-unknown-unknown-elf` |

This is the smallest cwasm among the four embedded-wasm variants because
the guest only has two host imports (`read-byte`, `write-byte`) and simple
sequential logic without branching.

### 10.2 Guest Code Logic

```
fn run() {
    loop {
        let byte = call_import uart::read_byte()
        match byte {
            0x08 | 0x7f => {            // Backspace or DEL
                call_import uart::write_byte(0x08)  // BS
                call_import uart::write_byte(0x20)  // Space
                call_import uart::write_byte(0x08)  // BS
            }
            0x0d => {                   // Carriage Return
                call_import uart::write_byte(0x0d)  // CR
                call_import uart::write_byte(0x0a)  // LF
            }
            _ => {
                call_import uart::write_byte(byte)  // Echo
            }
        }
    }
}
```

The guest implements a simple terminal echo with destructive backspace
(overwriting the character with a space) and CR-to-CRLF translation.

---

## 11. Host-Guest Call Flow

### 11.1 Character Echo

```
[Pulley VM]  Bytecode: call_indirect_host -> read_byte()
    |
    v
[ARM Native]  uart::read_byte (inlined into run_wasm)
    |
    v
[Hardware]  UART0 UARTDR @ 0x40070000 -> read byte from RX FIFO

[Pulley VM]  Return to guest with byte value in x0
    |
    v
[Pulley VM]  Match: regular character -> call_indirect_host -> write_byte(byte)
    |
    v
[ARM Native]  uart::write_byte (inlined into run_wasm)
    |
    v
[Hardware]  UART0 UARTDR @ 0x40070000 -> write byte to TX FIFO
```

### 11.2 Backspace Handling

```
[Pulley VM]  read_byte() returns 0x08 (BS) or 0x7f (DEL)
    |
    v
[Pulley VM]  Match: backspace -> three consecutive write_byte calls
    |
    +-- call_indirect_host -> write_byte(0x08)    ; Move cursor back
    +-- call_indirect_host -> write_byte(0x20)    ; Overwrite with space
    +-- call_indirect_host -> write_byte(0x08)    ; Move cursor back again
    |
    v
[Hardware]  Three UART TX writes: BS, SPACE, BS
```

---

## 12. RE Observations

### 12.1 Binary Composition

| Component                 | Approx Size | % of .text |
| ------------------------- | ----------- | ---------- |
| Wasmtime runtime          | ~533 KiB    | 98.9%      |
| Pulley interpreter (run)  | 12.2 KiB    | 2.3%       |
| Pulley decoder (extended) | 16.1 KiB    | 3.0%       |
| Application (uart+main)   | ~6 KiB      | 1.1%       |

This is the leanest embedded-wasm variant. The application code is
minimal because `uart::read_byte` and `uart::write_byte` are inlined
into `run_wasm`, and no GPIO module is linked.

### 12.2 Comparison Across Variants

| Aspect          | Blinky      | Button      | UART      | C2          |
| --------------- | ----------- | ----------- | --------- | ----------- |
| .text size      | 544,880 B   | 548,680 B   | 539,176 B | 556,712 B   |
| .data size      | 36 B        | 36 B        | 40 B      | 36 B        |
| .bss size       | 262,308 B   | 262,324 B   | 262,292 B | 262,316 B   |
| cwasm size      | 24,680 B    | 25,384 B    | 24,456 B  | 24,704 B    |
| Functions       | 2,375       | 2,392       | 2,375     | 2,501       |
| WIT interfaces  | gpio,timing | gpio,btn,tm | uart      | gpio,timing |
| GPIO pins used  | 1 output    | 1 in, 1 out | 0 (UART)  | 27 outputs  |
| SIO GPIO access | Yes         | Yes         | **No**    | Yes         |

### 12.3 Key Addresses Quick Reference

| Address      | What                                          |
| ------------ | --------------------------------------------- |
| `0x10000000` | Vector table (initial SP + exception vectors) |
| `0x100000f8` | RP2350 IMAGE_DEF boot block                   |
| `0x1000010c` | Reset handler (entry point)                   |
| `0x100071e8` | init_hardware                                 |
| `0x1000736c` | __cortex_m_rt_main                            |
| `0x100073d8` | run_wasm                                      |
| `0x10007b1c` | init_heap                                     |
| `0x1000801c` | platform::uart::add_to_linker                 |
| `0x10008014` | main (thin wrapper)                           |
| `0x10063cac` | Pulley Interpreter::run (dispatch loop)       |
| `0x10066fc8` | Pulley decode_one_extended                    |
| `0x1000c570` | InterpreterRef::call (native->Pulley bridge)  |
| `0x10088578` | Embedded cwasm blob (Pulley ELF)              |
| `0x1007b5a4` | DefaultHandler (infinite loop)                |
| `0x10083b2c` | HardFault (infinite loop)                     |
| `0x40070000` | UART0 base (UARTDR data register)             |
| `0x40070018` | UART0 UARTFR (flags register)                 |
| `0x20000000` | uart::UART handle (.data, 8 B)                |
| `0x2000002c` | HEAP_MEM (256 KiB)                            |
| `0x20080000` | Initial stack pointer                         |

---

## 13. Pulley Instruction Set Architecture

### 13.1 Overview

Pulley is Wasmtime's portable bytecode interpreter (wasmtime 43.0.0,
`pulley-interpreter` crate v43.0.0). It defines a register-based ISA
with variable-length instructions, designed for efficient interpretation
rather than native execution.

### 13.2 Encoding Format

**Primary opcodes** use a 1-byte opcode followed by operands:

```
[opcode:1] [operands:0-9]
```

There are **220 primary opcodes** (0x00-0xDB). Opcode `0xDC` is the
**ExtendedOp** sentinel — when the interpreter encounters it, it reads
a 2-byte extended opcode:

```
[0xDC] [ext_opcode:2] [operands:0-N]
```

There are **310 extended opcodes** (0x0000-0x0135) for SIMD, float
conversions, and complex operations.

### 13.3 Key Instructions

See the [embedded-wasm-servo-rp2350 RE.md](https://github.com/mytechnotalent/embedded-wasm-servo-rp2350)
§13 for the complete Pulley ISA reference. The UART guest uses the same
instruction subset as the base blinky with the addition of comparison
and conditional branch instructions for the `match` statement.

---

## 14. Pulley Bytecode Disassembly

### 14.1 Guest::run() — UART Echo Loop

```
; function[N]: Guest::run()

push_frame_save <frame>, <callee-saved regs>

; Load VMContext and function pointers
xload32le_o32 x_heap, x0, 28          ; heap_base
xmov x_vmctx, x0                      ; save VMContext

; Load host function pointers
xload32le_o32 x_read_fn, x_vmctx, ...
xload32le_o32 x_write_fn, x_vmctx, ...

; Load constants for comparison
xconst8 x_bs, 0x08                    ; Backspace
xconst8 x_del, 0x7f                   ; DEL
xconst8 x_cr, 0x0d                    ; Carriage Return
xconst8 x_lf, 0x0a                    ; Line Feed
xconst8 x_space, 0x20                 ; Space

.loop:
    ; --- uart::read_byte() ---
    call_indirect x_read_fn            ; -> ARM: blocking UART RX
    xmov x_byte, x0                   ; Save received byte

    ; --- Check for backspace (0x08) ---
    br_if_xeq32 x_byte, x_bs, .backspace

    ; --- Check for DEL (0x7f) ---
    br_if_xeq32 x_byte, x_del, .backspace

    ; --- Check for CR (0x0d) ---
    br_if_xeq32 x_byte, x_cr, .newline

    ; --- Default: echo the character ---
    xmov x2, x_byte
    call_indirect x_write_fn
    jump .loop

.backspace:
    xmov x2, x_bs                     ; BS
    call_indirect x_write_fn
    xmov x2, x_space                  ; Space (overwrite)
    call_indirect x_write_fn
    xmov x2, x_bs                     ; BS (back again)
    call_indirect x_write_fn
    jump .loop

.newline:
    xmov x2, x_cr                     ; CR
    call_indirect x_write_fn
    xmov x2, x_lf                     ; LF
    call_indirect x_write_fn
    jump .loop
```

---

## 15. Ghidra Analysis Walkthrough

### 15.1 Import and Initial Analysis

1. **File -> Import File**: Select the ELF. Ghidra auto-detects
   `ARM:LE:32:v8T` (ARMv8 Thumb). Accept the defaults.

2. **Auto-analysis**: Ghidra identifies 2,375 functions from the symbol
   table.

3. **Analysis time**: ~30 seconds for this 1.11 MiB binary.

### 15.2 Symbol Tree Navigation

```
Functions/ (2,375 total)
+-- Reset                              0x1000010c
+-- main                               0x10008014
+-- __cortex_m_rt_main                 0x1000736c
+-- embedded_wasm_uart::run_wasm       0x100073d8
+-- embedded_wasm_uart::init_hardware  0x100071e8
+-- platform::uart::add_to_linker      0x1000801c
+-- pulley_interpreter::interp::Interpreter::run  0x10063cac
+-- pulley_interpreter::decode::decode_one_extended  0x10066fc8
+-- InterpreterRef::call               0x1000c570
+-- ... (2,366 more)
```

### 15.3 Finding and Extracting the cwasm Blob

1. Navigate to `0x10088578` in the Listing view
2. Ghidra shows the `7f 45 4c 46` (ELF magic) bytes
3. Right-click -> **Select Bytes** -> enter length 24456 (0x5f88)
4. **File -> Export Selection** -> Binary format -> save as `uart-echo.cwasm`

### 15.4 Ghidra + G-Pulley: Full-Stack Analysis

With the [G-Pulley](https://github.com/mytechnotalent/G-Pulley) extension
installed, Ghidra can analyze **both** the ARM host firmware and the
Pulley guest bytecode:

| Aspect                  | ARM Host Code             | Pulley Guest Code (G-Pulley)        |
| ----------------------- | ------------------------- | ----------------------------------- |
| Disassembly             | Full ARM Thumb-2          | Full Pulley ISA mnemonics           |
| Function identification | Automatic from symbols    | Automatic (cwasm loader + analyzer) |
| Cross-references        | Full xref graph           | Function calls and branches         |
| Control flow            | CFG with switch detection | Branch and jump targets resolved    |
| Host call boundary      | `InterpreterRef::call`    | `call_indirect_host` instructions   |

**G-Pulley provides**:

- Custom ELF loader that extracts the `.cwasm` blob from the firmware
- SLEIGH processor spec for Pulley 32-bit and 64-bit ISA (Wasmtime v43.0.0)
- Post-load analyzer that discovers functions, trampolines, and host calls
- Full opcode decoding for all 220 primary + 310 extended Pulley opcodes

### 15.5 Recommended Ghidra Workflow

1. **Install G-Pulley**: Download from
   [G-Pulley releases](https://github.com/mytechnotalent/G-Pulley/releases).
   In Ghidra: **File -> Install Extensions -> + -> select zip**. Restart.

2. **Analyze the ARM firmware**: Import the ELF. Run auto-analysis.
   Follow Reset -> main -> `__cortex_m_rt_main` -> `run_wasm`.

3. **Examine UART bindings**: Navigate to `platform::uart::add_to_linker`
   (0x1000801c) to see how `read-byte` and `write-byte` are registered.
   The actual UART I/O is inlined into `run_wasm` (0x100073d8).

4. **Trace the interpreter**: Start at `InterpreterRef::call` (0x1000c570),
   follow into `Interpreter::run` (0x10063cac) to see the Pulley dispatch
   loop.

5. **Analyze the Pulley bytecode**: Import the firmware ELF again using
   G-Pulley's cwasm loader (select "Pulley cwasm" format). G-Pulley
   extracts the embedded cwasm blob, disassembles all Pulley opcodes,
   and identifies guest functions including the echo loop with its
   backspace and newline handling branches.
