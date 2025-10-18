# Simple PT_NOTE to PT_LOAD Test

This directory demonstrates the PT_NOTE to PT_LOAD segment conversion technique for ELF binary infection.

## Test Files

- `sample64` - Original PIE (Position Independent Executable) test binary - **NOT COMPATIBLE**
- `sample64_nopie` - Non-PIE statically linked test binary - **WORKS**
- `woody_woodpacker` - The packer executable (from parent directory)

## Usage

```bash
# Test with non-PIE binary (works correctly)
./woody_woodpacker sample64_nopie
./output_woody

# Expected output:
# ..WOODY..
# Hello, World!
```

## Important Limitation

⚠️ **PIE (Position Independent Executables) are not supported**

The PT_LOAD injection technique used here does not work with PIE binaries because:
- PIE binaries use position-independent code with relative addressing
- The entry point address (e.g., 0x1060) is an offset, not an absolute address
- At runtime, the kernel loads the binary at a random base address
- Jumping to the stored entry point address causes a segfault

### Solution

Use non-PIE, statically-linked binaries:
```bash
gcc -no-pie -static -o output source.c
```

This limitation exists in the reference implementation (`ia_ptload`) as well.

## How It Works

1. Finds PT_NOTE segment in the ELF binary
2. Converts PT_NOTE to PT_LOAD with executable permissions
3. Injects shellcode at end of file that:
   - Saves all registers
   - Prints "..WOODY..\n"
   - Restores registers
   - Jumps to original entry point
4. Updates entry point to injected code
5. Original program executes normally after payload
