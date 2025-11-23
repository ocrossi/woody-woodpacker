#include <stdio.h>

extern int addNumbers(int a, int b);

int main() {
    printf("res = %d\n", addNumbers(1, 2));
    return 0;
}
// nasm -f elf64 ext.s && gcc -c main.c && gcc *.o && ./a.out 
