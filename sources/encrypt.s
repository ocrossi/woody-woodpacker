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
    
; https://app.x64.halb.it/ cool site for asm
