section .data
    prompt_msg db "Enter something: ", 0     ; Prompt message to display
    output_msg db "You entered: ", 0         ; Output prefix message

section .bss
    user_input resb 20                       ; Reserve 20 bytes for user input

section .text
    global _start                            ; Entry point for the program

_start:
    ; Step 1: Display the prompt message
    mov eax, 4                               ; System call number for sys_write
    mov ebx, 1                               ; File descriptor 1 (stdout)
    mov ecx, prompt_msg                      ; Address of prompt message
    mov edx, 17                              ; Length of prompt message
    int 0x80                                 ; Call the kernel to write

    ; Step 2: Read user input
    mov eax, 3                               ; System call number for sys_read
    mov ebx, 0                               ; File descriptor 0 (stdin)
    mov ecx, user_input                      ; Address to store user input
    mov edx, 20                              ; Max number of bytes to read
    int 0x80                                 ; Call the kernel to read

    ; Step 3: Display "You entered: " message
    mov eax, 4                               ; System call number for sys_write
    mov ebx, 1                               ; File descriptor 1 (stdout)
    mov ecx, output_msg                      ; Address of output message
    mov edx, 13                              ; Length of output message
    int 0x80                                 ; Call the kernel to write

    ; Step 4: Display the user's input
    mov eax, 4                               ; System call number for sys_write
    mov ebx, 1                               ; File descriptor 1 (stdout)
    mov ecx, user_input                      ; Address of user input
    mov edx, 20                              ; Length of user input to display
    int 0x80                                 ; Call the kernel to write

    ; Exit program
    mov eax, 1                               ; System call number for sys_exit
    xor ebx, ebx                             ; Exit code 0
    int 0x80                                 ; Call the kernel to exit
