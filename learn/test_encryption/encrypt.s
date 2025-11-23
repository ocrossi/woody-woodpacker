global encrypt

encrypt:
    mov r11, rdi ; save base address key
    mov cl, [rdi]
    loop_text:
        mov al, [rsi]
        mov bl, [rdi]
        dec rdx
        cmp rdx, 0 ; end of text 
        je exit 
        cmp bl, 0 ; end of key 
        je reset_key 
        xor al, bl
        mov [rsi], al
        inc rsi
        inc rdi
    reset_key:
        mov rdi, r11
        jmp loop_text
    exit:
        ret
        

; write:
;     call len
;     ; mov edx, 0x12
;     mov edx, ecx
;     mov rax, 1
;     syscall
;     ret
;
; len:
;     xor rcx, rcx ; compteur a 0
;     mov rax, rsi
;     loop:
;         mov bl, [rax]
;         cmp bl, 0
;         je exit_len
;         inc rcx 
;         inc rax 
;         jmp loop
;     exit_len:
;         ret

    
; https://app.x64.halb.it/ cool site for asm
