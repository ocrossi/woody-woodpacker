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
    
    test:
      lea r11, [ rel $ + 35] ; nasm pas de rip mais rel $
      lea rdi, [rel $  + 36]
      lea rdx, [rel $  + 45]
      lea rdx, [rel $  + 45]
      jmp $ + 10
      mov rdi, r11
; https://app.x64.halb.it/ cool site for asm

    // look for placeholder key, offset & size in rdi, rsi, rdx 
    // lea placeholder key in r11 
    // lea placeholder .text offset in rsi
    // lea placeholder .text size in rsi
