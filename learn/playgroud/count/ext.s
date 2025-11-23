global addNumbers 

section .text 

addNumbers:
    add rdi, rsi 
    mov rax, rdi 
    ret
; section .note.GNU-stack noalloc noexec nowrite progbits
