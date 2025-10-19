BITS 64 ; Define target architecture bits

section .data ; Data segment
msg db "Hello, world!", 0x0a; String with new line char

section .text ; Text segment
global _start; Default entry point for ELF linking

_start:

; write
mov rax, 1 ; Specify write syscall
mov rbx, 1 ; Specify stdout by putting 1 into rbx
mov rsi, msg ; Put the address of the string into rsi
mov rdx, 14 ; Put the length of the string into rdx
syscall ; Execute the system call

; exit
mov rax, 60 ; Specify exit syscall
mov rbx, 0 ; Exit with success
syscall ; Execute the system call
