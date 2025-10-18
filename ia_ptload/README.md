# PT_LOAD Segment Injection

This directory contains an implementation of the PT_LOAD segment injection technique described in https://tmpout.sh/1/2.html.

## What it does

The program takes an ELF64 executable as input and creates a modified version that:
1. First prints "hello world from pt_load"
2. Then executes the original program (which prints "hello normal world")

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
- Jumps to the original entry point

### Step 4: Modify Entry Point
The ELF header's entry point (`e_entry`) is changed to point to the virtual address of the injected code.

### Step 5: Patch the Jump Address
The shellcode contains a placeholder for the original entry point address, which is patched with the actual value from the original ELF header.

## Technical Details

### Shellcode Structure
```
- Register preservation (push all registers)
- System call to write message
- Register restoration (pop all registers)
- Jump to original entry point (using movabs + jmp)
- Message string
```

### Why Static Linking?
The test program is compiled with `-static` to create a self-contained executable. This ensures that the program doesn't require dynamic linking, which simplifies the injection process. The original entry point (`_start`) expects a specific stack layout that is preserved through register save/restore.

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

## Files

- `pt_load_injector.c` - Main injector program that performs the PT_LOAD injection
- `test_hello.c` - Test program that prints "hello normal world"
- `Makefile` - Build configuration with test target

## Usage

```bash
# Build everything
make

# Run the automated test
make test

# Or manually:
./pt_load_injector test_hello infected_hello
./infected_hello
```

## Expected Output

When running `./infected_hello`, you should see:
```
hello world from pt_load
 hello normal world
```

The original program runs successfully after the injected code executes.

## References

- [tmpout.sh Article on PT_LOAD Injection](https://tmpout.sh/1/2.html)
- [ELF Specification](https://refspecs.linuxfoundation.org/elf/elf.pdf)
- [Linux x86_64 Syscall Reference](https://filippo.io/linux-syscall-table/)
