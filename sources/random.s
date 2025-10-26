; BITS 64
section .data

section .text
    global syscall_random

syscall_random:
    push rbp
    mov rsp, rbp
    mov rax, 318
    syscall
    leave 
    ret
