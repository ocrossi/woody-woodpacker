#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>

#define KEY_SIZE 8

typedef struct s_woodyData {
    size_t file_size;
    size_t offset_ptnote; // how many bytes starting at the beginning of the file

    void *new_entrypoint;
    char key[KEY_SIZE];

    char* output_bytes; 
    int payload_size;
    uint64_t injection_addr;

    int fd;
    int fd_out;

    Elf64_Phdr pt_note; // lu tel quel dans le fichier
    Elf64_Phdr pt_load; // transforme pour infection
    Elf64_Ehdr elf_hdr;
    Elf64_Phdr *prgm_hdrs;
} t_woodyData;

extern char* syscall_random(void *buf, int size);

extern void encrypt(const char *key, const char *text, size_t len);
extern void decrypt(const char *key, const char *text, size_t len);

void print_hex(const char* buffer, size_t n);
