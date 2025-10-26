#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <elf.h>
#include <fcntl.h>

typedef struct s_woodyData {
    size_t file_size;
    size_t offset_ptnote; // how many bytes starting at the beginning of the file

    void *new_entrypoint;

    int payload_size;
    uint64_t injection_addr;

    int fd;

    Elf64_Phdr pt_note; // lu tel quel dans le fichier
    Elf64_Phdr pt_load; // transforme pour infection
    Elf64_Ehdr elf_hdr;
    Elf64_Phdr *prgm_hdrs;
} t_woodyData;

extern ssize_t syscall_random(void *buf, int size);
void print_hex(const char* buffer, size_t n);

#define KEY_SIZE 64
