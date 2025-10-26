# Payload System

## Overview

The shellcode payload has been refactored from an inline C byte array to an external NASM assembly file. This provides several benefits:

1. **Maintainability**: Assembly code is easier to read, understand, and modify than raw bytes
2. **Documentation**: Assembly instructions can be commented clearly
3. **Correctness**: The assembler ensures proper instruction encoding
4. **Flexibility**: Easy to update the payload without manually calculating byte offsets

## Files

- `sources/payload.s` - NASM assembly source for the shellcode payload
- `generate_payload.sh` - Script that compiles the assembly and generates a C header
- `sources/payload_data.h` - Auto-generated C header (not in git, regenerated on build)

## Build Process

1. `make` triggers the generation of `sources/payload_data.h` from `sources/payload.s`
2. The `generate_payload.sh` script:
   - Compiles `payload.s` using NASM to `objects/payload.o`
   - Extracts the `.text` section as raw binary to `objects/payload.bin`
   - Converts the binary to a C array in `sources/payload_data.h`
3. `sources/main.c` includes `payload_data.h` to get the `code[]` array

## Payload Structure

The payload performs the following operations:

1. Saves all callee-saved registers (rax, rcx, rdx, rbx, rsi, rdi, rbp, r8-r11)
2. Calls `write(1, "hello world from pt_load\n", 26)` using syscall
3. Restores all registers
4. Calculates the original entry point address (PIE-compatible)
5. Jumps to the original entry point

## Modifying the Payload

To modify the shellcode:

1. Edit `sources/payload.s` 
2. Run `make clean && make` to rebuild
3. The new payload will be automatically incorporated

## Technical Details

The payload uses position-independent code (PIC) techniques:
- `lea rsi, [rel message]` - Relative addressing for the message string
- Manual encoding of `movabs` instructions for address patching placeholders
- Runtime calculation of the base address to support PIE executables
