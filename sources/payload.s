; Payload shellcode for woody_woodpacker
; This is the code that gets injected into the ELF binary

[BITS 64]

section .text
global payload_start
global payload_end

payload_start:
    ; Save all callee-saved registers
    push rax
    push rcx
    push rdx
    push rbx
    push rsi
    push rdi
    push rbp
    push r8
    push r9
    push r10
    push r11

    ; write(1, message, message_len)
    mov eax, 1              ; sys_write
    mov edi, 1              ; stdout
    lea rsi, [rel message]  ; message (position-independent)
    mov edx, 26             ; message length
    syscall

    ; Restore all registers
    pop r11
    pop r10
    pop r9
    pop r8
    pop rbp
    pop rdi
    pop rsi
    pop rbx
    pop rdx
    pop rcx
    pop rax

    ; For PIE: Calculate base address and add original entry offset
    ; Get current RIP into rax
    ; Using explicit encoding to get lea rax, [rip+0]
    db 0x48, 0x8d, 0x05, 0x00, 0x00, 0x00, 0x00  ; lea rax, [rip]

    ; Load injection_vaddr into rbx (will be patched)
    ; Using explicit encoding to get 10-byte instruction
    db 0x48, 0xbb           ; movabs rbx prefix
    dq 0x0000000000000000   ; 8-byte immediate (will be patched)

    ; Calculate base: base = current_rip - injection_vaddr
    sub rax, rbx

    ; Load original entry offset into rbx (will be patched)
    ; Using explicit encoding to get 10-byte instruction  
    db 0x48, 0xbb           ; movabs rbx prefix
    dq 0x0000000000000000   ; 8-byte immediate (will be patched)

    ; Calculate actual entry: actual_entry = base + original_entry
    add rax, rbx

    ; Jump to the calculated address
    jmp rax

message:
    db 'hello world from pt_load', 0x0a, 0x00

payload_end:
