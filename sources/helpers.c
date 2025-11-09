#include "../includes/woody.h"

void print_bytes(const void *data, size_t size) {
    const unsigned char *bytes = (const unsigned char *)data;
    
    for (size_t i = 0; i < size; i++) {
        printf("%02x ", bytes[i]);
        if ((i + 1) % 16 == 0) printf("\n");
    }
    if (size % 16 != 0) printf("\n");
}
