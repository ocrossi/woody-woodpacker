bits 64 ; on s assure que ca va run en 64bits 
default rel ; addresses in relative 
global _start

;     rdi   rsi    rdx
;      v     v      v
;write(fd,   msg,   len);

_start:
        xor     eax, eax
        cdq
        mov     dl, 10         ;3eme argument (rdx)
        inc     eax            ;eax = 1 (syscall)
        mov     edi, eax       ;1er argument rdi = 1
        lea     rsi, [msg] ;2eme arg
        syscall

msg     db "..WOODY..",10
