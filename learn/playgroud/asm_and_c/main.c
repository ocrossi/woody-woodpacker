#include <stdio.h>
#include <string.h>

// Declare the external assembly function
extern void asm_write(const char *str, size_t len);

int main() {
    const char *msg = "Hello from asm_write hehe!\n";
    const char *hello_msg = "Hello asm!\n";
    size_t len = strlen(msg);
    asm_write(msg, len);
    return 0;
}

// nasm -f elf64 asm_write.asm && gcc -c main.c && gcc *.o && ./a.out 
