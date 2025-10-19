global _start
_start:
    jmp short string

code:
    pop rsi
    xor rax, rax
    mov al, 1
    mov rdi, rax
    mov rdx, rdi
    add rdx, 14
    syscall

    xor rax, rax
    add rax, 60
    xor rdi, rdi
    syscall

string:
call code
db  'Hello, world!',0x0A
