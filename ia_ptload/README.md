# PT_LOAD Segment Injection

This directory contains an implementation of the PT_LOAD segment injection technique described in https://tmpout.sh/1/2.html.

## What it does

The program takes an ELF64 executable as input and creates a modified version that:
1. First prints "hello world from pt_load"
2. Then executes the original program (which prints "hello normal world")

## How it works

The technique involves:
1. Finding a PT_NOTE segment in the ELF program headers
2. Converting it to a PT_LOAD segment with execute permissions
3. Injecting shellcode at the end of the file
4. Modifying the entry point to execute the injected code first
5. The injected code jumps back to the original entry point after execution

## Files

- `pt_load_injector.c` - Main injector program
- `test_hello.c` - Test program that prints "hello normal world"
- `Makefile` - Build configuration

## Usage

```bash
# Build everything
make

# Run the test
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
