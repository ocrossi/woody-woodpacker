global syscall_random
section .text

syscall_random:
    push rbp
    mov rsp, rbp
    mov rax, 318
    mov rbx, 0
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
