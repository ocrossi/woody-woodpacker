global syscall_random
section .text

syscall_random:
    push rbp
    mov rbp, rsp
    mov rax, 318
    mov rdx, 0
    syscall 
    pop rbp
    ret

segment .note.GNU-stack
