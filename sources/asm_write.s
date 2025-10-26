global asm_write

section .text

asm_write:
    mov rax, 1      ; write syscall nb
    mov rdx, rsi    ; len dans 3e arg de write 
    mov rsi, rdi    ; str dans 2e arg 
    mov rdi, 1      ; fd 1

    syscall
    ret

section .note.GNU-stack noalloc noexec nowrite progbits
