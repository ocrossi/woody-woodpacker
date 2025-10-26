global syscall_random
section .text

syscall_random:
    push rbp
    mov rbp, rsp
    mov rax, 318        ; syscall number for getrandom
    ; rdi already contains buf (first parameter)
    ; rsi already contains size (second parameter)
    mov rdx, 0          ; flags = 0
    syscall 
    cmp rax, 0
    jl .err
    mov rax, rdi        ; return buf
    pop rbp
    ret
.err:
    xor rax, rax        ; return NULL (or set errno appropriately)
    pop rbp
    ret
