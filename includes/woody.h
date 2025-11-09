#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>

#define KEY_SIZE 8

typedef struct s_woodyData {
    int fd;
    size_t file_size;
    int fd_out;
    size_t output_size;
    char* output_bytes; 

    uint64_t new_entrypoint;
    uint64_t old_entrypoint;
    char key[KEY_SIZE];

    Elf64_Phdr pt_load; // transforme pour infection
    Elf64_Ehdr elf_hdr;
    Elf64_Phdr *prgm_hdrs;
} t_woodyData;

extern char* syscall_random(void *buf, int size);

extern void encrypt(const char *key, const char *text, size_t len);
extern void decrypt(const char *key, const char *text, size_t len);

void print_hex(const char* buffer, size_t n);
