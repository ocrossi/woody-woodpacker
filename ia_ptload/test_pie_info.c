#include <stdio.h>

extern char _start;

int main() {
    printf("main is at: %p\n", (void*)main);
    printf("_start is at: %p\n", (void*)&_start);
    printf("hello normal world\n");
    return 0;
}
