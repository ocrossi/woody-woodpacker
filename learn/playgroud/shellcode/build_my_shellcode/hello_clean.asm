global _start

section .text 

_start:
    xor rax, rax ; rax = 0
    add rax, 1 ; rax = 1 with no bull bytes
    xor rdi, rdi 
    add rdi, 1 ; fd = 1
    lea rsi, [rel message] 
    xor rdx, rdx
    add rdx, len
    syscall 
    xor rax, rax ; rax = 0
    add rax, 60 ; exit
    xor rdi, rdi  ; 0
    syscall

section .data 
    message: db "Hello future shellcodes",0xa ;17 len
    len: equ $-message ; store len 
