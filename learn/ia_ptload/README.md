# PT_LOAD Segment Injection with XOR-Stream Encryption

This directory contains an implementation of the PT_LOAD segment injection technique described in https://tmpout.sh/1/2.html, with enhanced support for Position Independent Executables (PIE), plus XOR-stream encryption/decryption tools.

## Features

- **PT_LOAD Injection**: Inject code into ELF binaries by repurposing PT_NOTE segments
- **PIE Support**: Works with both PIE and non-PIE executables
- **XOR-Stream Encryption**: Encrypt and decrypt output files using a tiny Xorshift32 PRNG

## What it does

The program takes an ELF64 executable as input and creates a modified version that:
1. First prints "hello world from pt_load"
2. Then executes the original program (which prints "hello normal world")

This works with both:
- **Non-PIE executables** (ET_EXEC): Traditional executables with fixed load addresses
- **PIE executables** (ET_DYN): Position Independent Executables that use ASLR (Address Space Layout Randomization)

## How it works

The PT_LOAD injection technique is a method to inject code into an ELF binary by repurposing an existing segment:

### Step 1: Find PT_NOTE Segment
The program scans the ELF program headers to find a PT_NOTE segment, which typically contains build information but is not required for execution.

### Step 2: Convert PT_NOTE to PT_LOAD
The PT_NOTE segment header is modified:
- Type: Changed from `PT_NOTE` (4) to `PT_LOAD` (1)
- Flags: Set to `PF_R | PF_X` (readable and executable)
- Virtual address: Set to a high address (0xc000000 + file_size)
- File offset: Points to the end of the file where shellcode will be added
- Size: Set to the size of the injected shellcode

### Step 3: Inject Shellcode
Custom x86_64 assembly code is appended to the end of the file. The shellcode:
- Saves all registers to preserve program state
- Makes a syscall to write the message to stdout
- Restores all registers
- Jumps to the original entry point (using different strategies for PIE vs non-PIE)

### Step 4: Modify Entry Point
The ELF header's entry point (`e_entry`) is changed to point to the virtual address of the injected code.

### Step 5: Patch the Jump Address
The shellcode contains placeholders that are patched with the actual values needed to return control to the original program.

## PIE Compatibility

### The Challenge

Position Independent Executables (PIE) present unique challenges for code injection:

1. **Dynamic Load Addresses**: PIE executables are loaded at a random base address each time they run (ASLR). The entry point in the ELF header is a relative offset, not an absolute address.

2. **Address Calculation**: To jump back to the original entry point, we need to:
   - Calculate the base address where the executable was loaded at runtime
   - Add the original entry offset to this base address

### The Solution

We use two different shellcode variants:

#### Non-PIE Shellcode (ET_EXEC)
```asm
; ... save registers and print message ...
movabs rax, <absolute_entry_address>  ; Patch with original e_entry
jmp rax
```

For non-PIE executables, the entry point is an absolute address (e.g., 0x401050), so we can directly jump to it.

#### PIE Shellcode (ET_DYN)
```asm
; ... save registers and print message ...
lea rax, [rip]           ; Get current instruction pointer
movabs rbx, <rip_value>  ; Patch with expected RIP value (injection_vaddr + offset)
sub rax, rbx             ; Calculate: base = actual_rip - expected_rip
movabs rbx, <entry_offset>  ; Patch with original e_entry (relative offset)
add rax, rbx             ; Calculate: actual_entry = base + entry_offset
jmp rax
```

For PIE executables:
1. **Get current position**: `lea rax, [rip]` loads the current instruction pointer into rax
2. **Calculate base address**: By subtracting the expected RIP value (where we know the shellcode is mapped), we get the actual base address where the executable was loaded
3. **Add entry offset**: Add the original entry point offset to get the absolute address of the real entry point
4. **Jump**: Transfer control to the original entry point

### Key Technical Details

**RIP-relative addressing**: The x86_64 instruction `lea rax, [rip]` loads the address of the *next* instruction into rax. This allows us to determine our current position in memory without hardcoding any addresses.

**Base address calculation**: 
```
base_address = current_rip - expected_rip
actual_entry = base_address + entry_offset
```

**Example with PIE**:
- Shellcode injected at virtual address: 0xc003e60
- At runtime, PIE loaded at base: 0x555555554000
- Entry offset in ELF: 0x1060
- When `lea rax, [rip]` at offset 54 executes:
  - Expected RIP: 0xc003e9d (injection_vaddr + 61)
  - Actual RIP: 0xc003e9d (because loader maps our injected segment as requested)
  - Base calculation: rax = 0xc003e9d - 0xc003e9d = 0x0
  - For PIE loaded at random address, the base would be that random address
  - Actual entry: 0x555555554000 + 0x1060 = 0x555555555060

### Why This Works

The injected PT_LOAD segment is loaded at the address we specify (0xc000000 + file_size), which is not subject to ASLR. However, the original executable segments *are* subject to ASLR if it's a PIE binary. By calculating the base address dynamically, we can jump to the correct location regardless of where the original code was loaded.

## Technical Details

### Shellcode Structure (PIE version)
```
Offset 0-14:   Register preservation (push all registers)
Offset 15-38:  System call to write message
Offset 39-53:  Register restoration (pop all registers)
Offset 54-60:  lea rax, [rip] - Get current position
Offset 61-70:  movabs rbx, <rip_value> - Expected RIP (patched)
Offset 71-73:  sub rax, rbx - Calculate base address
Offset 74-83:  movabs rbx, <entry_offset> - Original entry (patched)
Offset 84-86:  add rax, rbx - Calculate actual entry
Offset 87-88:  jmp rax - Jump to original entry
Offset 89+:    Message string
```

### Shellcode Structure (Non-PIE version)
```
Offset 0-14:   Register preservation (push all registers)
Offset 15-38:  System call to write message
Offset 39-53:  Register restoration (pop all registers)
Offset 54-65:  movabs rax, <absolute_address> - Original entry (patched)
Offset 66-67:  jmp rax - Jump to original entry
Offset 68+:    Message string
```

### Memory Layout
```
Original File:
  [ELF Header]
  [Program Headers] <- PT_NOTE modified to PT_LOAD
  [Segments]
  [Sections]

Infected File:
  [ELF Header] <- e_entry points to injected code
  [Program Headers] <- PT_LOAD points to end of file
  [Segments]
  [Sections]
  [Injected Shellcode] <- Executes first, then jumps to original entry
```

### Detection of PIE vs Non-PIE

The injector automatically detects the executable type by examining the ELF header:
- `e_type == ET_EXEC` (2): Non-PIE executable
- `e_type == ET_DYN` (3): PIE executable or shared library

## Files

- `pt_load_injector.c` - Main injector program that performs the PT_LOAD injection
- `encrypt_decrypt.c` - XOR-stream encryption/decryption tool using Xorshift32 PRNG
- `test_hello.c` - Test program that prints "hello normal world"
- `Makefile` - Build configuration with test targets for both PIE and non-PIE
- `README.md` - This file
- `ENCRYPTION.md` - Detailed documentation about the encryption feature

## Usage

```bash
# Build everything (both PIE and non-PIE test executables plus tools)
make

# Run the automated test (tests both PIE and non-PIE plus encryption)
make test

# Or manually:
# 1. Create infected binary
./pt_load_injector test_hello infected_hello
./infected_hello

# 2. Encrypt the infected binary
./encrypt_decrypt infected_hello encrypted_infected_hello

# 3. Decrypt it back
./encrypt_decrypt encrypted_infected_hello decrypted_infected_hello

# 4. Verify it still works
./decrypted_infected_hello

# PIE version:
./pt_load_injector test_hello_pie infected_hello_pie
./infected_hello_pie
./encrypt_decrypt infected_hello_pie encrypted_infected_hello_pie
./encrypt_decrypt encrypted_infected_hello_pie decrypted_infected_hello_pie
./decrypted_infected_hello_pie
```

## Expected Output

When running the tests, you should see:

### Infected Binary
```
./infected_hello
hello world from pt_load
 hello normal world
```

### Encryption/Decryption
```
./encrypt_decrypt infected_hello encrypted_infected_hello
Successfully processed file: infected_hello -> encrypted_infected_hello
File size: 15964 bytes
XOR-stream encryption/decryption applied with PRNG seed: 0xDEADBEEF

./encrypted_infected_hello
bash: ./encrypted_infected_hello: cannot execute binary file: Exec format error

./encrypt_decrypt encrypted_infected_hello decrypted_infected_hello
Successfully processed file: encrypted_infected_hello -> decrypted_infected_hello
File size: 15964 bytes
XOR-stream encryption/decryption applied with PRNG seed: 0xDEADBEEF

./decrypted_infected_hello
hello world from pt_load
 hello normal world
```

This demonstrates:
1. PT_LOAD injection works and executes the payload
2. Files can be encrypted (rendering them unexecutable)
3. Files can be decrypted (restoring full functionality)
4. The encryption/decryption process is reversible and lossless

This works identically for both PIE and non-PIE executables, demonstrating successful injection, encryption, and decryption.

## Building PIE vs Non-PIE Executables

```bash
# Build a non-PIE executable
gcc -no-pie -o my_program my_program.c

# Build a PIE executable (default on most modern systems)
gcc -o my_program my_program.c
# or explicitly:
gcc -pie -fPIE -o my_program my_program.c
```

## Security Implications

This technique demonstrates:
1. **Code injection**: How code can be added to executables without source code
2. **Execution flow hijacking**: How to redirect program execution
3. **ASLR considerations**: PIE executables use ASLR, but injected segments can be placed at fixed addresses
4. **Register preservation**: Importance of maintaining program state when injecting code

## Limitations

1. Requires a PT_NOTE segment (present in most modern ELF files)
2. Assumes standard x86_64 calling conventions
3. The injected code runs in the same security context as the original program
4. Does not handle dynamically linked libraries that might be loaded at the original entry point

## References

- [tmpout.sh Article on PT_LOAD Injection](https://tmpout.sh/1/2.html)
- [ELF Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [Linux x86_64 Syscall Reference](https://filippo.io/linux-syscall-table/)
- [Position Independent Executables (PIE)](https://en.wikipedia.org/wiki/Position-independent_code)
- [Address Space Layout Randomization (ASLR)](https://en.wikipedia.org/wiki/Address_space_layout_randomization)
