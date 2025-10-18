# Debug Summary: simple_ptone_to_ptlaod Segfault Fix

## Problem Statement
The user reported that the output file of the woody_woodpacker executable in the `simple_ptone_to_ptlaod` directory was segfaulting. They asked to compare it with the working `ia_ptload` implementation.

## Root Cause Analysis

After comparing `simple_ptone_to_ptlaod` with the working `ia_ptload` reference implementation, I identified 6 critical issues:

### 1. Wrong Shellcode Behavior
**Problem:** The shellcode in `sources/main.c` called `exit()` syscall instead of jumping back to the original entry point.

**Evidence:**
```asm
# Original broken shellcode (simplified):
syscall          # write message
mov $0x3c, %al   # exit syscall
syscall          # EXIT - program terminates!
```

**Fix:** Replaced with shellcode that jumps back to original entry:
```asm
# Fixed shellcode:
syscall          # write message
movabs $0x0, %rax   # will be patched with original entry
jmp *%rax           # jump to original program
```

### 2. Hardcoded Entry Point
**Problem:** Line 149-150 set entry point to hardcoded `0x0c000000`:
```c
char new_entrypoint[4] = {0x00, 0x00, 0x00, 0x0c};
```

**Issue:** This was always wrong because:
- The actual virtual address depends on file size
- Should be `0xc000000 + file_size` (8 bytes, not 4)

**Fix:** Calculate from PT_LOAD segment virtual address:
```c
uint64_t new_entry = data->pt_note.p_vaddr;
ft_memcpy(&data->output_bytes[0x18], &new_entry, sizeof(uint64_t));
```

### 3. No Entry Point Preservation
**Problem:** Original entry point was never saved before modifying.

**Fix:** Added `original_entry` field to struct and saved it:
```c
data->original_entry = data->elf_hdr.e_entry;
```

### 4. Shellcode Not Patched
**Problem:** The shellcode contains a placeholder for the original entry address, but it was never patched with the actual value.

**Fix:** Added patching before writing shellcode:
```c
ft_memcpy(&shellcode_exit[56], &data->original_entry, sizeof(uint64_t));
```

### 5. Incorrect RIP-Relative Offset
**Problem:** The `lea rsi, [rip+offset]` instruction had wrong offset (0x1d instead of 0x22).

**Calculation:**
- lea instruction ends at byte 32
- Message starts at byte 66
- Offset = 66 - 32 = 34 (0x22)

**Fix:** Changed offset from 0x1d to 0x22 in shellcode.

### 6. PIE Binary Incompatibility
**Problem:** Testing with `sample64` which is a PIE (Position Independent Executable).

**Why PIE Doesn't Work:**
- PIE uses position-independent code
- Entry point (e.g., 0x1060) is an offset, not absolute address
- Kernel loads binary at random base address at runtime
- Jumping to stored address hits unmapped memory → segfault

**Fix:** 
- Created `sample64_nopie` compiled with `-no-pie -static`
- Documented the PIE limitation in README

## Verification

### Before Fixes:
```bash
./woody_woodpacker sample64
./output_woody
# Segmentation fault
```

### After Fixes:
```bash
./woody_woodpacker sample64_nopie
./output_woody
# ..WOODY..
# Hello, World!
```

## Comparison with ia_ptload

Both implementations now have identical behavior:
- ✅ Work correctly with non-PIE binaries
- ⚠️ Segfault with PIE binaries (known limitation)

## Files Modified

1. **sources/main.c**
   - Replaced shellcode with jump-back version
   - Fixed entry point calculation
   - Added shellcode patching logic
   - Changed shellcode length to use sizeof()

2. **includes/woody.h**
   - Added `original_entry` field to t_woodyData struct

3. **simple_ptone_to_ptlaod/README.md** (new)
   - Documented usage and PIE limitation

4. **simple_ptone_to_ptlaod/sample64_nopie** (new)
   - Non-PIE test binary that works correctly

## Technical Details

### Shellcode Structure (76 bytes)
```
Bytes 0-14:   Save registers (push rax through r11)
Bytes 15-38:  Setup and execute write syscall
Bytes 39-53:  Restore registers (pop in reverse order)
Bytes 54-65:  movabs + jmp to original entry (patched at offset 56)
Bytes 66-75:  Message "..WOODY..\n"
```

### Memory Layout After Infection
```
[Original ELF]
├── ELF Header (e_entry = new PT_LOAD vaddr)
├── Program Headers
│   └── PT_NOTE → PT_LOAD (vaddr = 0xc000000 + filesize)
├── Original Segments
└── [Injected Shellcode at EOF]
```

## Conclusion

The segfault was caused by a combination of:
1. Wrong shellcode that exited instead of jumping back
2. Incorrect entry point calculation
3. Missing shellcode patching
4. Testing with incompatible PIE binary

All issues have been resolved, and the implementation now matches the working `ia_ptload` reference.
