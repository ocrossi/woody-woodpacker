global _start

section .text 

_start:
    mov rax, 1 ; write 
    mov rdi, 1 ; fd = 1
    mov rsi, message 
    mov rdx, len
    syscall 
    mov rax, 60 ; exit
    mov rdi, 0  ; 0
    syscall

section .data 
    message: db "Hello future shellcodes",0xa ;17 len
    len: equ $-message ; store len 
